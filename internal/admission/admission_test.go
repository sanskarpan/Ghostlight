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
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func grants(concurrency int) []quota.Grant {
	s, e := now.Add(-time.Hour), now.Add(30*24*time.Hour)
	var out []quota.Grant
	for _, sc := range quota.Scopes(quota.Request{Repository: "repo/acme/app", Actor: "actor-1", Profile: "postgres-standard"}) {
		out = append(out, quota.Grant{
			Scope: sc.Scope, Ref: sc.Ref, WindowStart: s, WindowEnd: e,
			MaxConcurrency: concurrency, MaxCPUMillicores: 8000, MaxStorageGiB: 100,
			AllowanceMinor: 500_000, Currency: "USD",
		})
	}
	return out
}

func newGate(t *testing.T, concurrency int) (*admission.Gate, *quota.MemoryLedger) {
	t.Helper()
	l := quota.NewMemoryLedger(grants(concurrency), func() time.Time { return now })
	g, err := admission.New(l, quota.DefaultMaxima(), func() time.Time { return now })
	if err != nil {
		t.Fatalf("new gate: %v", err)
	}
	return g, l
}

func request(id string) admission.Request {
	return admission.Request{
		EnvironmentID: id, Actor: "actor-1", Repository: "repo/acme/app", Profile: "postgres-standard",
		Demanded:     quota.Demand{Concurrency: 1, CPUMillicores: 500, StorageGiB: 5, AllowanceMinor: 1_000},
		RequestedTTL: quota.DefaultTTL, Now: now,
	}
}

// TestGateRequiresALedger is the invariant as a test: admitting without a reservation
// is how an environment comes to exist with nothing accounting for it.
func TestGateRequiresALedger(t *testing.T) {
	if _, err := admission.New(nil, quota.DefaultMaxima(), nil); err == nil {
		t.Fatal("a gate must not be constructible without a ledger")
	}
}

// TestAdmissionReservesCapacity is the base path.
func TestAdmissionReservesCapacity(t *testing.T) {
	g, l := newGate(t, 5)

	d, err := g.Admit(context.Background(), request("env-1"))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if !d.Granted() {
		t.Fatal("a granted admission must carry a reservation")
	}
	if d.ExpiresAt != now.Add(quota.DefaultTTL) {
		t.Fatalf("the decision must set a real expiry, got %v", d.ExpiresAt)
	}
	if d.Clamped {
		t.Fatal("a TTL inside policy is not clamped")
	}
	if len(d.Scopes) != 4 {
		t.Fatalf("capacity must be held against all four scopes, got %d", len(d.Scopes))
	}

	rem, err := l.Remaining(context.Background(), quota.ScopeRef{Scope: quota.ScopeFleet, Ref: "global"}, now)
	if err != nil {
		t.Fatalf("remaining: %v", err)
	}
	if rem.Concurrency != 4 {
		t.Fatalf("admission must consume a slot, got %v", rem)
	}
}

// TestAdmissionRefusesWhenCapacityIsGone is the property that keeps the fleet from
// oversubscribing itself.
func TestAdmissionRefusesWhenCapacityIsGone(t *testing.T) {
	g, _ := newGate(t, 1)

	if _, err := g.Admit(context.Background(), request("env-1")); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := g.Admit(context.Background(), request("env-2"))
	if !errors.Is(err, admission.ErrRefused) {
		t.Fatalf("an exhausted fleet must refuse admission, got %v", err)
	}
	// The refusal must be presentable to a customer, which means naming the binding
	// scope rather than reporting a generic error. Every scope is capped at one here,
	// and repository binds first, so the name must be the repository.
	if !strings.Contains(err.Error(), "repository:repo/acme/app") {
		t.Fatalf("the refusal must name the binding scope, got %q", err)
	}
	if !strings.Contains(err.Error(), "concurrent preview limit") {
		t.Fatalf("the refusal must give a remedy, got %q", err)
	}
}

// TestRefusedAdmissionConsumesNothing: a request that fails a precondition must not
// leave a partial hold for a rollback to clean up.
func TestRefusedAdmissionConsumesNothing(t *testing.T) {
	g, l := newGate(t, 1)

	// Beyond the profile maximum, so the demand check refuses before reserving.
	tooMuch := request("env-1")
	tooMuch.Demanded.CPUMillicores = 999_999
	if _, err := g.Admit(context.Background(), tooMuch); !errors.Is(err, admission.ErrRefused) {
		t.Fatalf("an impossible demand must be refused, got %v", err)
	}

	// The single slot must still be available.
	if _, err := g.Admit(context.Background(), request("env-2")); err != nil {
		t.Fatalf("a refused admission must consume nothing: %v", err)
	}
	if len(l.Active()) != 1 {
		t.Fatalf("exactly one reservation should exist, got %d", len(l.Active()))
	}
}

// TestTTLIsClampedAtAdmission, not silently honoured.
func TestTTLIsClampedAtAdmission(t *testing.T) {
	g, _ := newGate(t, 5)

	req := request("env-1")
	req.RequestedTTL = 30 * 24 * time.Hour
	d, err := g.Admit(context.Background(), req)
	if err != nil {
		t.Fatalf("an over-long TTL must clamp rather than fail: %v", err)
	}
	if !d.Clamped {
		t.Fatal("a clamped grant must say so")
	}
	if d.GrantedTTL != 72*time.Hour {
		t.Fatalf("clamped to the 72h maximum, got %v", d.GrantedTTL)
	}
}

// TestAdmissionIdentifiesWhatItConsumes: capacity consumed by nothing is a leak.
func TestAdmissionIdentifiesWhatItConsumes(t *testing.T) {
	g, _ := newGate(t, 5)

	base := request("env-1")
	for name, mutate := range map[string]func(*admission.Request){
		"no environment": func(r *admission.Request) { r.EnvironmentID = "" },
		"no repository":  func(r *admission.Request) { r.Repository = "" },
		"no actor":       func(r *admission.Request) { r.Actor = "" },
	} {
		req := base
		mutate(&req)
		if _, err := g.Admit(context.Background(), req); !errors.Is(err, admission.ErrRefused) {
			t.Fatalf("%s must be refused, got %v", name, err)
		}
	}
}

// TestReleaseReturnsCapacity is the teardown path.
func TestReleaseReturnsCapacity(t *testing.T) {
	g, l := newGate(t, 1)

	d, err := g.Admit(context.Background(), request("env-1"))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if err := g.Release(context.Background(), d.ReservationID); err != nil {
		t.Fatalf("release: %v", err)
	}
	rem, _ := l.Remaining(context.Background(), quota.ScopeRef{Scope: quota.ScopeFleet, Ref: "global"}, now)
	if rem.Concurrency != 1 {
		t.Fatalf("release must return the slot, got %v", rem)
	}
}

// TestReleasingNothingHeldIsNotAnError: a cleanup path must not fail forever over a
// state that is already correct.
func TestReleasingNothingHeldIsNotAnError(t *testing.T) {
	g, _ := newGate(t, 5)
	if err := g.Release(context.Background(), ""); err != nil {
		t.Fatalf("releasing an empty reservation must be a no-op, got %v", err)
	}
}

// TestExtensionRequiresAllThreeThings walks SPEC.md's requirement one at a time.
func TestExtensionRequiresAllThreeThings(t *testing.T) {
	g, _ := newGate(t, 5)
	audited := []quota.AuditEntry{{Actor: "ops-1", Operation: "raise_fleet_limit", Revision: "rev-7"}}

	// No actor.
	if _, err := g.Extend(context.Background(), quota.Extension{EnvironmentID: "env-1", Now: now}, audited); !errors.Is(err, admission.ErrRefused) {
		t.Fatal("an unidentified actor must be refused")
	}
	// No audit record.
	if _, err := g.Extend(context.Background(), quota.Extension{EnvironmentID: "env-1", Actor: "actor-1", Now: now}, nil); !errors.Is(err, admission.ErrRefused) {
		t.Fatal("an unaudited extension must be refused")
	}
	// All three present.
	dec, err := g.Extend(context.Background(), quota.Extension{EnvironmentID: "env-1", Actor: "actor-1", Now: now}, audited)
	if err != nil {
		t.Fatalf("a fully authorized extension must succeed: %v", err)
	}
	if dec.Audit.Actor != "actor-1" {
		t.Fatalf("the grant must carry an audit entry, got %+v", dec.Audit)
	}
}

// TestExtensionRefusedWhenTheFleetIsFull: remaining allowance is one of the three
// requirements, and it is read from the ledger rather than assumed.
func TestExtensionRefusedWhenTheFleetIsFull(t *testing.T) {
	g, _ := newGate(t, 1)
	audited := []quota.AuditEntry{{Actor: "ops-1", Operation: "rev", Revision: "rev-7"}}

	if _, err := g.Admit(context.Background(), request("env-1")); err != nil {
		t.Fatalf("admit: %v", err)
	}
	_, err := g.Extend(context.Background(), quota.Extension{EnvironmentID: "env-1", Actor: "actor-1", Now: now}, audited)
	if !errors.Is(err, admission.ErrRefused) {
		t.Fatalf("an extension with no remaining fleet capacity must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "no fleet concurrency") {
		t.Fatalf("the refusal must name the exhausted dimension, got %q", err)
	}
}

// TestExtensionCountIsBounded.
func TestExtensionCountIsBounded(t *testing.T) {
	g, _ := newGate(t, 50)
	audited := []quota.AuditEntry{{Actor: "ops-1", Operation: "rev", Revision: "rev-7"}}
	m := quota.DefaultMaxima()

	_, err := g.Extend(context.Background(),
		quota.Extension{EnvironmentID: "env-1", Actor: "actor-1", ExtensionsSoFar: m.MaxExtensions, Now: now}, audited)
	if !errors.Is(err, admission.ErrRefused) {
		t.Fatalf("the %dth extension must be refused, got %v", m.MaxExtensions+1, err)
	}
}

// TestDestroyAuthorization is the other privileged operation.
func TestDestroyAuthorization(t *testing.T) {
	g, _ := newGate(t, 5)

	if err := g.AuthorizeDestroy(context.Background(), "env-1", "actor-1", "PR closed"); err != nil {
		t.Fatalf("an authorized destroy must be allowed: %v", err)
	}
	if err := g.AuthorizeDestroy(context.Background(), "", "actor-1", "PR closed"); !errors.Is(err, admission.ErrRefused) {
		t.Fatal("a destroy must name the environment")
	}
	if err := g.AuthorizeDestroy(context.Background(), "env-1", "", "PR closed"); !errors.Is(err, admission.ErrRefused) {
		t.Fatal("a destroy requires an identified actor")
	}
	if err := g.AuthorizeDestroy(context.Background(), "env-1", "actor-1", ""); !errors.Is(err, admission.ErrRefused) {
		t.Fatal("a destroy requires a reason; an unexplained one gives the customer nothing to appeal")
	}
}

// TestConcurrentAdmissionsNeverOversubscribe is the property, tested concurrently. If
// it fails, the fleet is running more environments than it paid for.
func TestConcurrentAdmissionsNeverOversubscribe(t *testing.T) {
	const capacity = 3
	const attempts = 30
	g, l := newGate(t, capacity)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var admitted []string

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "env-" + string(rune('a'+i))
			if d, err := g.Admit(context.Background(), request(id)); err == nil && d.Granted() {
				mu.Lock()
				admitted = append(admitted, id)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if len(admitted) != capacity {
		t.Fatalf("admitted %d environments against capacity %d: %v", len(admitted), capacity, admitted)
	}
	if len(l.Active()) != capacity {
		t.Fatalf("the ledger holds %d reservations, capacity is %d", len(l.Active()), capacity)
	}
}
