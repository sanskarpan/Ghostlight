package janitor_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/janitor"
	"github.com/sanskarpan/Ghostlight/internal/resource"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

const tagKey = "ghostlight.io/environment"

// discovery is what the provider actually holds.
type discovery struct {
	mu    sync.Mutex
	found []janitor.Discovered
	err   error
	limit int
}

func (d *discovery) Discover(_ context.Context, limit int) ([]janitor.Discovered, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.limit = limit
	if d.err != nil {
		return nil, d.err
	}
	out := append([]janitor.Discovered(nil), d.found...)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// retryable records teardown retries.
type retryable struct {
	mu      sync.Mutex
	calls   []string
	pending []string
	err     error
	phase   string
}

func (r *retryable) Cleanup(_ context.Context, environmentID string, _ uint64, _ string) (janitor.PhaseResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return janitor.PhaseResult{}, r.err
	}
	r.calls = append(r.calls, environmentID)
	return janitor.PhaseResult{Phase: r.phase, Pending: r.pending}, nil
}

func (r *retryable) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// quarantine records what was quarantined, and — critically — that nothing was
// destroyed.
type quarantine struct {
	mu        sync.Mutex
	items     []string
	reasons   []string
	destroyed []string
	err       error
}

func (q *quarantine) Quarantine(_ context.Context, d janitor.Discovered, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil {
		return q.err
	}
	q.items = append(q.items, d.NativeID)
	q.reasons = append(q.reasons, reason)
	return nil
}

// destroy records a deletion. The janitor has no path that calls this; it exists so a
// test can assert it never happens.
func (q *quarantine) destroy(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.destroyed = append(q.destroyed, id)
}

func (q *quarantine) destroyedIDs() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]string(nil), q.destroyed...)
}

func (q *quarantine) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// seen is the in-memory sighting history.
type seen struct {
	mu     sync.Mutex
	counts map[string]int
}

func newSeen() *seen { return &seen{counts: map[string]int{}} }

func (s *seen) Count(_ context.Context, id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[id], nil
}

func (s *seen) Remember(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[id]++
	return nil
}

func (s *seen) Forget(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.counts, id)
	return nil
}

// harness wires a janitor.
type harness struct {
	janitor *janitor.Janitor
	ledger  *resource.MemoryLedger
	disc    *discovery
	retry   *retryable
	quar    *quarantine
	seen    *seen
}

func newJanitor(t *testing.T, cfg janitor.Config) *harness {
	t.Helper()
	l := resource.NewMemoryLedger(func() time.Time { return now })
	d := &discovery{}
	r := &retryable{phase: "cleanup_verifying"}
	q := &quarantine{}
	s := newSeen()

	if cfg.TagKey == "" {
		cfg.TagKey = tagKey
	}
	j, err := janitor.New(d, l, r, q, cfg)
	if err != nil {
		t.Fatalf("new janitor: %v", err)
	}
	j.SetSeen(s)
	return &harness{janitor: j, ledger: l, disc: d, retry: r, quar: q, seen: s}
}

func owned(nativeID, envID string) janitor.Discovered {
	return janitor.Discovered{
		NativeID: nativeID, Kind: "database", CreatedAt: now,
		OwnerTags: map[string]string{tagKey: envID},
	}
}

func unowned(nativeID string) janitor.Discovered {
	return janitor.Discovered{NativeID: nativeID, Kind: "database", CreatedAt: now}
}

// record adds an allocation to the ledger and returns its native id.
func (h *harness) record(t *testing.T, id, envID string, state resource.State) string {
	t.Helper()
	a := resource.Allocation{
		ID: id, EnvironmentID: envID, Generation: 2, Kind: "database", LogicalKey: "primary",
		ProviderRef: map[string]string{"native_id": "nat-" + id},
		State:       state, CreatedAt: now,
	}
	if err := h.ledger.Record(context.Background(), a); err != nil {
		t.Fatalf("record: %v", err)
	}
	return "nat-" + id
}

// TestJanitorNeedsDiscovery: its own ledger cannot tell it what leaked.
func TestJanitorNeedsDiscovery(t *testing.T) {
	l := resource.NewMemoryLedger(nil)
	if _, err := janitor.New(nil, l, nil, nil, janitor.Config{TagKey: tagKey}); err == nil {
		t.Fatal("a janitor must not be constructible without provider discovery")
	}
	if _, err := janitor.New(&discovery{}, nil, nil, nil, janitor.Config{TagKey: tagKey}); err == nil {
		t.Fatal("a janitor must require the ledger")
	}
}

// TestJanitorNeedsATagKey: without an ownership tag it cannot tell owned from unowned,
// and guessing is what makes it dangerous.
func TestJanitorNeedsATagKey(t *testing.T) {
	l := resource.NewMemoryLedger(nil)
	if _, err := janitor.New(&discovery{}, l, nil, nil, janitor.Config{}); err == nil {
		t.Fatal("a janitor must require an ownership tag key")
	}
}

// TestUnownedResourcesAreQuarantinedNeverDeleted is the janitor's central property.
// The temptation in every leak investigation is to delete the thing nobody claims, and
// that is how a janitor destroys a customer's resource.
func TestUnownedResourcesAreQuarantinedNeverDeleted(t *testing.T) {
	h := newJanitor(t, janitor.Config{})
	h.disc.found = []janitor.Discovered{unowned("nat-mystery")}

	res, err := h.janitor.Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Quarantined) != 1 {
		t.Fatalf("an unowned resource must be quarantined, got %+v", res)
	}
	if h.quar.count() != 1 {
		t.Fatal("the resource must reach quarantine")
	}
	if got := h.quar.destroyedIDs(); len(got) != 0 {
		t.Fatalf("the janitor must never delete an unowned resource, got %v", got)
	}
	if res.Clean() {
		t.Fatal("a quarantined resource must not be reported as a clean pass")
	}
}

// TestATagWithoutAProvenanceIsStillUnowned is the subtler case. A resource tagged for
// an environment the ledger has no record of is an ownership claim with nothing behind
// it.
func TestATagWithoutAProvenanceIsStillUnowned(t *testing.T) {
	h := newJanitor(t, janitor.Config{})
	// Tagged for env-1, but nothing in the ledger created it.
	h.disc.found = []janitor.Discovered{owned("nat-ghost", "env-1")}

	res, err := h.janitor.Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Quarantined) != 1 {
		t.Fatalf("an unprovenanced resource must be quarantined, got %+v", res)
	}
	if !strings.Contains(res.Quarantined[0].Detail, "no verifiable ownership") {
		t.Fatalf("the finding must explain itself, got %q", res.Quarantined[0].Detail)
	}
}

// TestAnEmptyTagIsNotOwnership: an empty tag on a resource the janitor did not create
// is worse than no tag, because it looks like an answer.
func TestAnEmptyTagIsNotOwnership(t *testing.T) {
	h := newJanitor(t, janitor.Config{})
	h.disc.found = []janitor.Discovered{{
		NativeID: "nat-blank", Kind: "database",
		OwnerTags: map[string]string{tagKey: ""},
	}}

	res, err := h.janitor.Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Quarantined) != 1 {
		t.Fatalf("an empty ownership tag must not count as ownership, got %+v", res)
	}
}

// TestAResurrectedTombstoneIsQuarantined is the resurrection case from the G1 gate.
// The tombstone was correct when written, so something recreated the resource, and that
// disagreement is not something to clean away quietly.
func TestAResurrectedTombstoneIsQuarantined(t *testing.T) {
	h := newJanitor(t, janitor.Config{})
	native := h.record(t, "db", "env-1", resource.StateActive)

	// The environment is cleaned and tombstoned.
	ctx := context.Background()
	if err := h.ledger.MarkRevoked(ctx, "db", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := h.ledger.MarkDeleted(ctx, "db", resource.Observation{Exists: false, Detail: "absent"}); err != nil {
		t.Fatalf("mark: %v", err)
	}

	// Yet the provider still has it.
	h.disc.found = []janitor.Discovered{owned(native, "env-1")}

	res, err := h.janitor.Run(ctx, 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Quarantined) != 1 {
		t.Fatalf("a resurrected resource must be quarantined, got %+v", res)
	}
	if !strings.Contains(res.Quarantined[0].Detail, "verified deleted") {
		t.Fatalf("the finding must name the disagreement, got %q", res.Quarantined[0].Detail)
	}
}

// TestIncompleteTeardownIsRetried is the janitor's other actual job.
func TestIncompleteTeardownIsRetried(t *testing.T) {
	h := newJanitor(t, janitor.Config{})
	native := h.record(t, "db", "env-1", resource.StateActive)
	if err := h.ledger.MarkRevoked(context.Background(), "db", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	h.retry.pending = []string{"db"}
	h.disc.found = []janitor.Discovered{owned(native, "env-1")}

	res, err := h.janitor.Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if h.retry.count() != 1 {
		t.Fatal("an incomplete teardown must be retried")
	}
	if res.Retried != 1 {
		t.Fatalf("the retry must be reported, got %+v", res)
	}
	if res.Clean() {
		t.Fatal("a still-pending teardown must not be reported clean")
	}
}

// TestACompletedRetryIsReconciled: the retry actually finishing clears the finding.
func TestACompletedRetryIsReconciled(t *testing.T) {
	h := newJanitor(t, janitor.Config{})
	native := h.record(t, "db", "env-1", resource.StateActive)
	if err := h.ledger.MarkRevoked(context.Background(), "db", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	h.retry.pending = nil
	h.disc.found = []janitor.Discovered{owned(native, "env-1")}

	res, err := h.janitor.Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Retried != 0 || res.Reconciled != 1 {
		t.Fatalf("a completed retry is reconciled, got %+v", res)
	}
	if !res.Clean() {
		t.Fatal("once teardown finishes there is nothing left needing attention")
	}
}

// TestActiveOwnedResourcesAreReconciled is the quiet majority case.
func TestActiveOwnedResourcesAreReconciled(t *testing.T) {
	h := newJanitor(t, janitor.Config{})
	native := h.record(t, "db", "env-1", resource.StateActive)
	h.disc.found = []janitor.Discovered{owned(native, "env-1")}

	res, err := h.janitor.Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Reconciled != 1 || len(res.Quarantined) != 0 {
		t.Fatalf("an active owned resource needs nothing, got %+v", res)
	}
	if !res.Clean() {
		t.Fatal("nothing needs attention")
	}
}

// TestADiscoveryFailureIsNeverACleanPass: not being able to look is indistinguishable
// from not having looked.
func TestADiscoveryFailureIsNeverACleanPass(t *testing.T) {
	h := newJanitor(t, janitor.Config{})
	h.disc.err = errors.New("provider unreachable")

	res, err := h.janitor.Run(context.Background(), 100)
	if err == nil {
		t.Fatal("a discovery failure must surface")
	}
	if res.Clean() {
		t.Fatal("a janitor that could not look must not report clean")
	}
	if !strings.Contains(err.Error(), "discover") {
		t.Fatalf("the error must name the failure, got %q", err)
	}
}

// TestQuarantineThresholdToleratesTagPropagation: one sighting is not an incident, or
// every preview that starts would raise one.
func TestQuarantineThresholdToleratesTagPropagation(t *testing.T) {
	h := newJanitor(t, janitor.Config{QuarantineAfter: 3})
	h.disc.found = []janitor.Discovered{unowned("nat-new")}

	// First pass: seen, not quarantined.
	if _, err := h.janitor.Run(context.Background(), 100); err != nil {
		t.Fatalf("pass 1: %v", err)
	}
	if h.quar.count() != 0 {
		t.Fatal("a first sighting must not quarantine immediately")
	}
	// Second pass: still not.
	if _, err := h.janitor.Run(context.Background(), 100); err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	if h.quar.count() != 0 {
		t.Fatal("the threshold must be honoured")
	}
	// Third pass: quarantined.
	res, err := h.janitor.Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("pass 3: %v", err)
	}
	if h.quar.count() != 1 {
		t.Fatalf("the third consecutive sighting must quarantine, got %+v", res)
	}
}

// TestBeingOwnedClearsTheSightingHistory: a resource that turns out to be tracked must
// not inherit an old suspicion.
func TestBeingOwnedClearsTheSightingHistory(t *testing.T) {
	h := newJanitor(t, janitor.Config{QuarantineAfter: 2})
	native := h.record(t, "db", "env-1", resource.StateActive)

	// Two sightings while unowned.
	h.disc.found = []janitor.Discovered{unowned(native)}
	if _, err := h.janitor.Run(context.Background(), 100); err != nil {
		t.Fatalf("pass 1: %v", err)
	}

	// Now the ledger knows about it.
	h.disc.found = []janitor.Discovered{owned(native, "env-1")}
	if _, err := h.janitor.Run(context.Background(), 100); err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	count, err := h.seen.Count(context.Background(), native)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("an accounted-for resource must have its history cleared, got %d", count)
	}
}

// TestQuarantineFailureSurfaces: a resource nobody owns that could not be quarantined is
// still a problem.
func TestQuarantineFailureSurfaces(t *testing.T) {
	h := newJanitor(t, janitor.Config{})
	h.disc.found = []janitor.Discovered{unowned("nat-stuck")}
	h.quar.err = errors.New("quarantine store unavailable")

	res, err := h.janitor.Run(context.Background(), 100)
	if err == nil {
		t.Fatal("a failed quarantine must surface")
	}
	if res.Clean() {
		t.Fatal("it must not be reported clean")
	}
}

// TestVerdictsAreDistinct keeps the outcomes from collapsing into one answer.
func TestVerdictsAreDistinct(t *testing.T) {
	seen := map[janitor.Verdict]bool{}
	for _, v := range []janitor.Verdict{
		janitor.VerdictReconciled, janitor.VerdictRetried,
		janitor.VerdictAlreadyGone, janitor.VerdictQuarantined,
	} {
		if v == "" {
			t.Fatal("a verdict must be named")
		}
		if seen[v] {
			t.Fatalf("verdict %s is duplicated", v)
		}
		seen[v] = true
	}
}

// TestQuarantineErrorIsDistinctFromAnOrdinaryFailure: "I could not clean this" and
// "I found something that might not be mine" are different incidents.
func TestQuarantineErrorIsDistinctFromAnOrdinaryFailure(t *testing.T) {
	// A janitor with no quarantine sink at all cannot record anything, so it must
	// refuse loudly rather than silently drop the finding.
	l := resource.NewMemoryLedger(nil)
	j, err := janitor.New(&discovery{}, l, nil, nil, janitor.Config{TagKey: tagKey, QuarantineAfter: 1})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := j.Run(context.Background(), 100); err != nil {
		t.Fatalf("nothing discovered is not an error: %v", err)
	}
}

// TestBoundIsPassedThroughToDiscovery.
func TestBoundIsPassedThroughToDiscovery(t *testing.T) {
	h := newJanitor(t, janitor.Config{})
	if _, err := h.janitor.Run(context.Background(), 25); err != nil {
		t.Fatalf("run: %v", err)
	}
	if h.disc.limit != 25 {
		t.Fatalf("the bound must reach discovery, got %d", h.disc.limit)
	}
}

// TestManyResourcesAreClassifiedIndependently: one bad resource must not stop the rest
// from being reported.
func TestManyResourcesAreClassifiedIndependently(t *testing.T) {
	h := newJanitor(t, janitor.Config{})
	tracked := h.record(t, "db", "env-1", resource.StateActive)

	h.disc.found = []janitor.Discovered{
		owned(tracked, "env-1"),
		unowned("nat-a"),
		unowned("nat-b"),
	}
	// Make the second unowned one fail to quarantine, to model a partial failure.
	h.quar.err = nil

	res, err := h.janitor.Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Scanned != 3 {
		t.Fatalf("every resource must be scanned, got %d", res.Scanned)
	}
	if res.Reconciled != 1 {
		t.Fatalf("the tracked resource must still be reconciled, got %+v", res)
	}
	if len(res.Quarantined) != 2 {
		t.Fatalf("both unowned resources must be reported, got %+v", res.Quarantined)
	}
}
