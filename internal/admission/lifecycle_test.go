package admission_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/admission"
	"github.com/sanskarpan/Ghostlight/internal/quota"
	"github.com/sanskarpan/Ghostlight/internal/ttlwatch"
)

// These tests cross package boundaries on purpose. Each of quota, admission and
// ttlwatch passes its own tests, and that is exactly when a lifecycle bug hides: in the
// wiring. The property that matters is not "quota refuses when exhausted" but "a
// preview that was admitted, then expired, returns its capacity and cannot oversubscribe
// the fleet".

// watchdogStore adapts the admission ledger to the watchdog's store interface.
//
// It is mutex-guarded because the concurrent expiry test drives one store from several
// watchdog goroutines. A real store is concurrency-safe for the same reason: several
// controllers share it.
type watchdogStore struct {
	mu   sync.Mutex
	envs []ttlwatch.Environment
	// marked records ids marked absent.
	marked map[string]bool
}

func (s *watchdogStore) Expired(_ context.Context, limit int) ([]ttlwatch.Environment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]ttlwatch.Environment(nil), s.envs...)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *watchdogStore) MarkAbsent(_ context.Context, id string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.marked == nil {
		s.marked = map[string]bool{}
	}
	s.marked[id] = true
	for i := range s.envs {
		if s.envs[i].ID == id {
			s.envs[i].Desired = ttlwatch.DesiredAbsent
		}
	}
	return nil
}

// TestExpiryReturnsCapacityAndTheSlotIsReusable is the whole point of tying these
// three packages together.
func TestExpiryReturnsCapacityAndTheSlotIsReusable(t *testing.T) {
	l := quota.NewMemoryLedger(grants(1), func() time.Time { return now })
	g, err := admission.New(l, quota.DefaultMaxima(), func() time.Time { return now })
	if err != nil {
		t.Fatalf("new gate: %v", err)
	}

	// Admit the only environment the fleet can hold.
	d, err := g.Admit(context.Background(), request("env-1"))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}

	// The fleet is now full, so a second preview is refused.
	if _, err := g.Admit(context.Background(), request("env-2")); !errors.Is(err, admission.ErrRefused) {
		t.Fatalf("the fleet must be full, got %v", err)
	}

	// Expire the first. The watchdog releases the capacity it was holding.
	ws := &watchdogStore{envs: []ttlwatch.Environment{{
		ID: "env-1", Desired: "present", ExpiresAt: now.Add(-time.Minute), ReservationID: d.ReservationID,
	}}}
	w, err := ttlwatch.New(ws, releaseAdapter{g}, ttlwatch.Config{
		Maxima: quota.DefaultMaxima(), Now: func() time.Time { return now }, RequireReservation: true,
	})
	if err != nil {
		t.Fatalf("new watchdog: %v", err)
	}
	res, runErr := w.Run(context.Background(), 100)
	if runErr != nil {
		t.Fatalf("watchdog: %v", runErr)
	}
	if res.Expired != 1 || res.Released != 1 {
		t.Fatalf("expiry must both mark and release, got %+v", res)
	}

	// The slot is reusable, which is what stops the platform leaking capacity.
	if _, err := g.Admit(context.Background(), request("env-3")); err != nil {
		t.Fatalf("a reclaimed slot must admit a new environment: %v", err)
	}
}

// releaseAdapter lets the watchdog return capacity through the admission gate, so the
// release path exercised is the real one.
type releaseAdapter struct{ g *admission.Gate }

func (r releaseAdapter) Release(ctx context.Context, id string) error {
	return r.g.Release(ctx, id)
}

// TestExpiryNeverOversubscribesUnderConcurrency is the property that matters most:
// repeated expiry under concurrent load must not free a slot twice.
func TestExpiryNeverOversubscribesUnderConcurrency(t *testing.T) {
	const capacity = 5
	l := quota.NewMemoryLedger(grants(capacity), func() time.Time { return now })
	g, err := admission.New(l, quota.DefaultMaxima(), func() time.Time { return now })
	if err != nil {
		t.Fatalf("new gate: %v", err)
	}

	// Fill the fleet.
	var admitted []admission.Decision
	for i := 0; i < capacity; i++ {
		d, err := g.Admit(context.Background(), request("env-"+string(rune('a'+i))))
		if err != nil {
			t.Fatalf("admit %d: %v", i, err)
		}
		admitted = append(admitted, d)
	}

	ws := &watchdogStore{}
	for _, d := range admitted {
		ws.envs = append(ws.envs, ttlwatch.Environment{
			ID: d.Scopes[0].Ref, Desired: "present", ExpiresAt: now.Add(-time.Minute), ReservationID: d.ReservationID,
		})
	}

	w, err := ttlwatch.New(ws, releaseAdapter{g}, ttlwatch.Config{
		Maxima: quota.DefaultMaxima(), Now: func() time.Time { return now }, RequireReservation: true,
	})
	if err != nil {
		t.Fatalf("new watchdog: %v", err)
	}

	// Expire concurrently. The ledger must remain exactly consistent.
	var wg sync.WaitGroup
	var mu sync.Mutex
	var res ttlwatch.Result
	var errs []error
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := w.Run(context.Background(), 100)
			mu.Lock()
			res.Expired += r.Expired
			res.Released += r.Released
			if e != nil {
				errs = append(errs, e)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	// A reservation released twice would invent capacity nobody paid for, so the
	// total releases must never exceed the number of reservations held.
	if res.Released > len(admitted) {
		t.Fatalf("capacity released %d times for %d reservations; the ledger invented capacity",
			res.Released, len(admitted))
	}

	rem, err := l.Remaining(context.Background(),
		quota.ScopeRef{Scope: quota.ScopeFleet, Ref: "global"}, now)
	if err != nil {
		t.Fatalf("remaining: %v", err)
	}
	if rem.Concurrency > capacity {
		t.Fatalf("remaining concurrency %d exceeds the fleet capacity %d", rem.Concurrency, capacity)
	}
}

// TestExhaustionOrderIsEnforcedBeforeAnyEnvironmentIsAdmitted ties the ordering rule
// to the admission gate: once admission stops, no new environment appears.
func TestExhaustionOrderIsEnforcedBeforeAnyEnvironmentIsAdmitted(t *testing.T) {
	order := quota.DefaultExhaustionOrder()
	if err := quota.ValidateExhaustionOrder(order); err != nil {
		t.Fatalf("the default exhaustion order must be valid: %v", err)
	}

	// Stopping admission is stage one, so by the time anything is destroyed no new
	// environment can take the capacity being freed.
	first := order[0]
	if first != quota.StageStopAdmission {
		t.Fatalf("exhaustion must stop admission first, got %s", first)
	}

	l := quota.NewMemoryLedger(grants(0), func() time.Time { return now })
	g, err := admission.New(l, quota.DefaultMaxima(), func() time.Time { return now })
	if err != nil {
		t.Fatalf("new gate: %v", err)
	}
	if _, err := g.Admit(context.Background(), request("env-1")); !errors.Is(err, admission.ErrRefused) {
		t.Fatalf("with admission stopped nothing may be admitted, got %v", err)
	}
}

// TestTheFullLifecycleOfOnePreview walks admit → extend (refused) → expire → release.
func TestTheFullLifecycleOfOnePreview(t *testing.T) {
	l := quota.NewMemoryLedger(grants(2), func() time.Time { return now })
	g, err := admission.New(l, quota.DefaultMaxima(), func() time.Time { return now })
	if err != nil {
		t.Fatalf("new gate: %v", err)
	}
	ctx := context.Background()

	// Admit.
	d, err := g.Admit(ctx, request("env-1"))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if d.ExpiresAt != now.Add(quota.DefaultTTL) {
		t.Fatalf("default TTL must be 24h from admission, got %v", d.ExpiresAt)
	}

	// Extend without an audit record: refused.
	if _, err := g.Extend(ctx, quota.Extension{EnvironmentID: "env-1", Actor: "actor-1", Now: now}, nil); err == nil {
		t.Fatal("an unaudited extension must be refused")
	}
	// Extend with one, using the last remaining slot, is allowed: an extension keeps
	// an existing environment alive rather than admitting a new one.
	dec, err := g.Extend(ctx, quota.Extension{EnvironmentID: "env-1", Actor: "actor-1", Now: now},
		[]quota.AuditEntry{{Actor: "ops-1", Operation: "rev", Revision: "rev-7"}})
	if err != nil {
		t.Fatalf("an audited extension must succeed while a slot remains: %v", err)
	}
	if dec.NewExpiry != now.Add(dec.Granted) {
		t.Fatalf("the extension must set a new expiry, got %v", dec.NewExpiry)
	}

	// Destroy needs a reason.
	if err := g.AuthorizeDestroy(ctx, "env-1", "actor-1", ""); err == nil {
		t.Fatal("an unexplained destroy must be refused")
	}
	if err := g.AuthorizeDestroy(ctx, "env-1", "actor-1", "PR closed"); err != nil {
		t.Fatalf("an authorized destroy must pass: %v", err)
	}

	// Expire and release.
	ws := &watchdogStore{envs: []ttlwatch.Environment{{
		ID: "env-1", Desired: "present", ExpiresAt: now.Add(-time.Minute), ReservationID: d.ReservationID,
	}}}
	w, err := ttlwatch.New(ws, releaseAdapter{g}, ttlwatch.Config{
		Maxima: quota.DefaultMaxima(), Now: func() time.Time { return now }, RequireReservation: true,
	})
	if err != nil {
		t.Fatalf("new watchdog: %v", err)
	}
	if _, err := w.Run(ctx, 100); err != nil {
		t.Fatalf("watchdog: %v", err)
	}

	rem, _ := l.Remaining(ctx, quota.ScopeRef{Scope: quota.ScopeFleet, Ref: "global"}, now)
	if rem.Concurrency != 2 {
		t.Fatalf("the preview's capacity must be fully returned, got %v", rem)
	}
}

// TestGraceIsBoundedAcrossTheWholeStack: grace is capped at every layer it touches.
func TestGraceIsBoundedAcrossTheWholeStack(t *testing.T) {
	m := quota.DefaultMaxima()
	if m.MaxGrace <= 0 {
		t.Fatal("the profile must declare a grace maximum")
	}

	// The watchdog refuses to evaluate unbounded grace.
	ws := &watchdogStore{}
	l := quota.NewMemoryLedger(grants(1), func() time.Time { return now })
	g, _ := admission.New(l, m, func() time.Time { return now })
	w, err := ttlwatch.New(ws, releaseAdapter{g}, ttlwatch.Config{Maxima: m, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("new watchdog: %v", err)
	}

	if _, err := w.GraceLapsed(quota.Grace{Duration: time.Hour, Reason: "incident"}, now); err == nil {
		t.Fatal("grace without an expiry must never be evaluable")
	}
	if _, err := w.GraceLapsed(quota.Grace{
		Duration: m.MaxGrace + time.Second, ExpiresAt: now, Reason: "incident",
	}, now); !errors.Is(err, ttlwatch.ErrRefused) {
		t.Fatal("grace beyond the profile maximum must be refused")
	}
}

// TestACustomerCanAlwaysBeToldWhyTheyWereRefused checks refusals are presentable,
// because a refusal nobody can act on becomes support load.
func TestACustomerCanAlwaysBeToldWhyTheyWereRefused(t *testing.T) {
	l := quota.NewMemoryLedger(grants(1), func() time.Time { return now })
	g, _ := admission.New(l, quota.DefaultMaxima(), func() time.Time { return now })

	_, err := g.Admit(context.Background(), request("env-1"))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	_, err = g.Admit(context.Background(), request("env-2"))
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	for _, want := range []string{"repository:repo/acme/app", "short", "limit"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the refusal must mention %q so it is actionable, got %q", want, msg)
		}
	}
}
