package ttlwatch_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/quota"
	"github.com/sanskarpan/Ghostlight/internal/ttlwatch"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func env(id string, expiresAt time.Time) ttlwatch.Environment {
	return ttlwatch.Environment{
		ID: id, Repository: "repo/acme/app", Actor: "actor-1", Profile: "postgres-standard",
		Desired: "present", ExpiresAt: expiresAt, ReservationID: "res-" + id,
	}
}

// store is the watchdog's persistence.
type store struct {
	items []ttlwatch.Environment

	expiredErr  error
	markErr     error
	markAbsent  map[string]time.Time
	listedLimit int
}

func (s *store) Expired(_ context.Context, limit int) ([]ttlwatch.Environment, error) {
	if s.expiredErr != nil {
		return nil, s.expiredErr
	}
	s.listedLimit = limit
	out := append([]ttlwatch.Environment(nil), s.items...)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *store) MarkAbsent(_ context.Context, id string, at time.Time) error {
	if s.markErr != nil {
		return s.markErr
	}
	if s.markAbsent == nil {
		s.markAbsent = map[string]time.Time{}
	}
	s.markAbsent[id] = at
	return nil
}

// ledger records releases.
type ledger struct {
	err      error
	released []string
}

func (l *ledger) Release(_ context.Context, id string) error {
	if l.err != nil {
		return l.err
	}
	l.released = append(l.released, id)
	return nil
}

func newWatchdog(t *testing.T, s *store, l *ledger) *ttlwatch.Watchdog {
	t.Helper()
	w, err := ttlwatch.New(s, l, ttlwatch.Config{
		Maxima:             quota.DefaultMaxima(),
		Now:                func() time.Time { return now },
		RequireReservation: true,
	})
	if err != nil {
		t.Fatalf("new watchdog: %v", err)
	}
	return w
}

// TestWatchdogNeedsItsOwnStore is the independence requirement as a test: expiry must
// not be a branch inside the controller, or a stuck controller decides that an
// environment lives forever.
func TestWatchdogNeedsItsOwnStore(t *testing.T) {
	if _, err := ttlwatch.New(nil, nil, ttlwatch.Config{}); err == nil {
		t.Fatal("a watchdog must not be constructible without its own store")
	}
}

// TestExpiredEnvironmentIsMarkedAbsent is the base path.
func TestExpiredEnvironmentIsMarkedAbsent(t *testing.T) {
	s := &store{items: []ttlwatch.Environment{env("a", now.Add(-time.Minute))}}
	l := &ledger{}

	res, err := newWatchdog(t, s, l).Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Expired != 1 {
		t.Fatalf("expected one expiry, got %+v", res)
	}
	if _, ok := s.markAbsent["a"]; !ok {
		t.Fatal("the expired environment was not marked absent")
	}
	if len(l.released) != 1 || l.released[0] != "res-a" {
		t.Fatalf("capacity must be released on expiry, got %v", l.released)
	}
}

// TestUnexpiredEnvironmentIsLeftAlone: a watchdog that expires early destroys work
// someone is paying for.
func TestUnexpiredEnvironmentIsLeftAlone(t *testing.T) {
	s := &store{items: []ttlwatch.Environment{env("a", now.Add(time.Hour))}}
	l := &ledger{}

	res, err := newWatchdog(t, s, l).Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Expired != 0 || len(l.released) != 0 {
		t.Fatalf("an unexpired environment must be untouched, got %+v", res)
	}
	if len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0].Reason, "not yet past") {
		t.Fatalf("the skip must explain itself, got %+v", res.Skipped)
	}
}

// TestExpiryDoesNotWaitForTheGate is the rule that stops a stuck gate becoming a
// permanent environment.
func TestExpiryDoesNotWaitForTheGate(t *testing.T) {
	s := &store{items: []ttlwatch.Environment{env("a", now.Add(-time.Hour))}}
	l := &ledger{}

	res, err := newWatchdog(t, s, l).Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Expired != 1 {
		t.Fatalf("expiry must not depend on gate results, got %+v", res)
	}
}

// TestAbsentEnvironmentIsNotExpiredTwice keeps the watchdog idempotent under the
// re-read it does after a partial failure.
func TestAbsentEnvironmentIsNotExpiredTwice(t *testing.T) {
	s := &store{items: []ttlwatch.Environment{{
		ID: "a", Desired: ttlwatch.DesiredAbsent, ExpiresAt: now.Add(-time.Hour), ReservationID: "res-a",
	}}}
	l := &ledger{}

	res, err := newWatchdog(t, s, l).Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Expired != 0 || len(l.released) != 0 {
		t.Fatalf("an already-absent environment must not be expired or released again, got %+v", res)
	}
}

// TestMissingTTLIsNotTreatedAsInfinite: a zero expiry is a data bug, and both obvious
// readings of it are harmful.
func TestMissingTTLIsNotTreatedAsInfinite(t *testing.T) {
	s := &store{items: []ttlwatch.Environment{{ID: "a", Desired: "present", ReservationID: "res-a"}}}
	l := &ledger{}

	res, err := newWatchdog(t, s, l).Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Expired != 0 {
		t.Fatal("an environment with no TTL must not be silently destroyed")
	}
}

// TestCapacityIsNotReleasedWhenMarkingFails is the ordering rule. Releasing first
// would free a slot the still-present environment occupies, letting a replacement
// oversubscribe the fleet.
func TestCapacityIsNotReleasedWhenMarkingFails(t *testing.T) {
	s := &store{
		items:   []ttlwatch.Environment{env("a", now.Add(-time.Hour))},
		markErr: errors.New("database unavailable"),
	}
	l := &ledger{}

	res, err := newWatchdog(t, s, l).Run(context.Background(), 100)
	if err == nil {
		t.Fatal("a failure to mark absent must surface")
	}
	if len(l.released) != 0 {
		t.Fatalf("capacity must not be released while the environment is still present, got %v", l.released)
	}
	if res.Expired != 0 {
		t.Fatal("nothing was expired, so nothing may be reported as expired")
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Err == nil {
		t.Fatalf("the failure must be attributable to one environment, got %+v", res.Skipped)
	}
}

// TestReleaseFailureIsReportedSeparately: the environment is gone but its slot is
// leaked, which is a distinct and retryable problem.
func TestReleaseFailureIsReportedSeparately(t *testing.T) {
	s := &store{items: []ttlwatch.Environment{env("a", now.Add(-time.Hour))}}
	l := &ledger{err: errors.New("ledger unavailable")}

	res, err := newWatchdog(t, s, l).Run(context.Background(), 100)
	if err == nil {
		t.Fatal("a leaked reservation must surface")
	}
	if res.Expired != 1 {
		t.Fatal("the environment did expire, and that must be reported")
	}
	if res.Released != 0 {
		t.Fatal("nothing was released")
	}
	if !strings.Contains(err.Error(), "release capacity") {
		t.Fatalf("the error must name the leak, got %q", err)
	}
}

// TestEnvironmentWithoutAReservationIsSkipped guards the case where releasing nothing
// would leave a slot consumed with no environment to account for it.
func TestEnvironmentWithoutAReservationIsSkipped(t *testing.T) {
	s := &store{items: []ttlwatch.Environment{{
		ID: "a", Desired: "present", ExpiresAt: now.Add(-time.Hour),
	}}}
	l := &ledger{}

	res, err := newWatchdog(t, s, l).Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Expired != 0 {
		t.Fatal("an environment holding no reservation must be escalated, not expired blindly")
	}
	if !strings.Contains(res.Skipped[0].Reason, "no capacity reservation") {
		t.Fatalf("the skip must explain the missing reservation, got %+v", res.Skipped)
	}
}

// TestListingFailureSurfaces: a watchdog that cannot see due environments must not
// report a clean pass.
func TestListingFailureSurfaces(t *testing.T) {
	s := &store{expiredErr: errors.New("database unavailable")}
	_, err := newWatchdog(t, s, &ledger{}).Run(context.Background(), 100)
	if err == nil || !strings.Contains(err.Error(), "list expired") {
		t.Fatalf("a failed listing must surface, got %v", err)
	}
}

// TestBoundIsPassedThrough keeps one backlog from monopolising the watchdog.
func TestBoundIsPassedThrough(t *testing.T) {
	s := &store{items: []ttlwatch.Environment{env("a", now.Add(-time.Hour))}}
	newWatchdog(t, s, &ledger{}).Run(context.Background(), 25)
	if s.listedLimit != 25 {
		t.Fatalf("the bound must reach the store, got %d", s.listedLimit)
	}
}

// failingStore fails MarkAbsent for one specific environment, modelling a transient
// conflict on a single row rather than an outage.
type failingStore struct {
	*store
	failFor string
}

func (f *failingStore) MarkAbsent(ctx context.Context, id string, at time.Time) error {
	if id == f.failFor {
		return errors.New("could not serialize access to row")
	}
	return f.store.MarkAbsent(ctx, id, at)
}

// TestPartialFailureDoesNotStopTheRemainder: one unmarkable environment must not
// prevent every other expired environment from being reclaimed. If it did, a single
// stuck row would pin the whole fleet at capacity until someone noticed.
func TestPartialFailureDoesNotStopTheRemainder(t *testing.T) {
	l := &ledger{}
	fs := &failingStore{
		store:   &store{items: []ttlwatch.Environment{env("bad", now.Add(-time.Hour)), env("good", now.Add(-time.Hour))}},
		failFor: "bad",
	}

	w, err := ttlwatch.New(fs, l, ttlwatch.Config{
		Maxima:             quota.DefaultMaxima(),
		Now:                func() time.Time { return now },
		RequireReservation: true,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	res, runErr := w.Run(context.Background(), 100)
	if runErr == nil {
		t.Fatal("the failed environment must surface")
	}
	if res.Expired != 1 {
		t.Fatalf("the healthy environment must still be reclaimed, got %+v", res)
	}
	if _, ok := fs.markAbsent["good"]; !ok {
		t.Fatal("the healthy environment was not marked absent")
	}
	if len(l.released) != 1 || l.released[0] != "res-good" {
		t.Fatalf("only the reclaimed environment may release capacity, got %v", l.released)
	}
}

// TestGraceMustBeBounded: grace is bounded precisely so it can lapse. Unbounded grace
// would make this unanswerable.
func TestGraceMustBeBounded(t *testing.T) {
	w := newWatchdog(t, &store{}, &ledger{})

	lapsed, err := w.GraceLapsed(quota.Grace{Duration: time.Hour, ExpiresAt: now.Add(-time.Minute), Reason: "incident"}, now)
	if err != nil {
		t.Fatalf("a bounded grace must evaluate: %v", err)
	}
	if !lapsed {
		t.Fatal("grace that has passed must be reported as lapsed")
	}

	lapsed, err = w.GraceLapsed(quota.Grace{Duration: time.Hour, ExpiresAt: now.Add(time.Hour), Reason: "incident"}, now)
	if err != nil || lapsed {
		t.Fatalf("grace still in force must not lapse, got %v (%v)", lapsed, err)
	}

	if _, err := w.GraceLapsed(quota.Grace{Duration: time.Hour, Reason: "incident"}, now); !errors.Is(err, ttlwatch.ErrRefused) {
		t.Fatalf("grace without an expiry must be refused, got %v", err)
	}
	if _, err := w.GraceLapsed(quota.Grace{Duration: 500 * time.Hour, ExpiresAt: now, Reason: "x"}, now); err == nil {
		t.Fatal("grace beyond the cap must be refused")
	}
}

// TestExtensionCountIsBoundedAtTheWatchdog checks the bound is enforced where the
// answer is explained, not only where it is granted.
func TestExtensionCountIsBoundedAtTheWatchdog(t *testing.T) {
	w := newWatchdog(t, &store{}, &ledger{})
	m := quota.DefaultMaxima()

	e := env("a", now.Add(time.Hour))
	for i := 0; i < m.MaxExtensions; i++ {
		e.Extensions = i
		if err := w.Extendable(e); err != nil {
			t.Fatalf("extension %d must be available: %v", i+1, err)
		}
	}
	e.Extensions = m.MaxExtensions
	err := w.Extendable(e)
	if !errors.Is(err, ttlwatch.ErrRefused) {
		t.Fatalf("the %dth extension must be refused", m.MaxExtensions+1)
	}
	if !strings.Contains(err.Error(), "audited capacity revision") {
		t.Fatalf("the refusal must direct an operator, got %q", err)
	}
}

// TestExpiryAndReleaseAreBothDurableAcrossAWatchdogRestart: a restarted watchdog
// re-reads the same rows, so it must not double-release.
func TestExpiryAndReleaseAreBothDurableAcrossAWatchdogRestart(t *testing.T) {
	s := &store{items: []ttlwatch.Environment{env("a", now.Add(-time.Hour))}}
	l := &ledger{}
	w := newWatchdog(t, s, l)

	if _, err := w.Run(context.Background(), 100); err != nil {
		t.Fatalf("first run: %v", err)
	}
	// The row is now absent, so a re-read must not release again.
	s.items[0].Desired = ttlwatch.DesiredAbsent
	res, err := w.Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if res.Released != 0 || len(l.released) != 1 {
		t.Fatalf("capacity must be released exactly once, got %v", l.released)
	}
}
