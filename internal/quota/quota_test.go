package quota_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/quota"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func window() (time.Time, time.Time) {
	return now.Add(-time.Hour), now.Add(30 * 24 * time.Hour)
}

func standardGrants(fleet, repo, actor, profile int) []quota.Grant {
	s, e := window()
	return []quota.Grant{
		{Scope: quota.ScopeFleet, Ref: "global", WindowStart: s, WindowEnd: e, MaxConcurrency: fleet,
			MaxCPUMillicores: 8000, MaxStorageGiB: 100, AllowanceMinor: 500_000, Currency: "USD"},
		{Scope: quota.ScopeRepository, Ref: "repo/acme/app", WindowStart: s, WindowEnd: e, MaxConcurrency: repo,
			MaxCPUMillicores: 4000, MaxStorageGiB: 50, AllowanceMinor: 100_000, Currency: "USD"},
		{Scope: quota.ScopeActor, Ref: "actor-1", WindowStart: s, WindowEnd: e, MaxConcurrency: actor,
			MaxCPUMillicores: 4000, MaxStorageGiB: 50, AllowanceMinor: 100_000, Currency: "USD"},
		{Scope: quota.ScopeProfile, Ref: "postgres-standard", WindowStart: s, WindowEnd: e, MaxConcurrency: profile,
			MaxCPUMillicores: 8000, MaxStorageGiB: 100, AllowanceMinor: 500_000, Currency: "USD"},
	}
}

func request(env string, demand quota.Demand) quota.Request {
	return quota.Request{
		EnvironmentID: env,
		Actor:         "actor-1",
		Repository:    "repo/acme/app",
		Profile:       "postgres-standard",
		Demanded:      demand,
		Now:           now,
	}
}

func mustErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

var oneSlot = quota.Demand{Concurrency: 1, CPUMillicores: 500, StorageGiB: 5, AllowanceMinor: 1_000}

// TestEveryScopeApplies checks all four levels bind. Reserving against a subset is how
// one repository ends up consuming the entire fleet.
func TestEveryScopeApplies(t *testing.T) {
	l := quota.NewMemoryLedger(standardGrants(10, 1, 1, 10), func() time.Time { return now })

	// Fleet has room, but the repository is capped at one.
	_, err := l.Reserve(context.Background(), request("env-1", oneSlot), quota.Scopes(request("env-1", oneSlot)))
	if err != nil {
		t.Fatalf("first reservation: %v", err)
	}
	_, err = l.Reserve(context.Background(), request("env-2", oneSlot), quota.Scopes(request("env-2", oneSlot)))
	if !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("the repository cap must bind even with fleet room, got %v", err)
	}
	if !strings.Contains(err.Error(), "repository") {
		t.Fatalf("the denial must name the binding scope, got %q", err)
	}
}

// TestTheBindingConstraintIsNamed matters operationally: an operator who is told the
// fleet is full when the repository is full will raise the wrong limit.
func TestTheBindingConstraintIsNamed(t *testing.T) {
	l := quota.NewMemoryLedger(standardGrants(10, 1, 5, 10), func() time.Time { return now })
	scopes := quota.Scopes(request("env-1", oneSlot))

	if _, err := l.Reserve(context.Background(), request("env-1", oneSlot), scopes); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := l.Reserve(context.Background(), request("env-2", oneSlot), scopes)
	if !strings.Contains(err.Error(), "repository:repo/acme/app") {
		t.Fatalf("the denial must identify the repository, got %q", err)
	}
	if !strings.Contains(err.Error(), "at its concurrent preview limit") {
		t.Fatalf("the denial must give a remedy, got %q", err)
	}
}

// TestFleetCapBindsWhenOthersHaveRoom is the mirror case.
func TestFleetCapBindsWhenOthersHaveRoom(t *testing.T) {
	l := quota.NewMemoryLedger(standardGrants(1, 10, 10, 10), func() time.Time { return now })

	for i := 1; i <= 1; i++ {
		req := request(fmt.Sprintf("env-%d", i), oneSlot)
		if _, err := l.Reserve(context.Background(), req, quota.Scopes(req)); err != nil {
			t.Fatalf("reservation %d: %v", i, err)
		}
	}
	req := request("env-2", oneSlot)
	_, err := l.Reserve(context.Background(), req, quota.Scopes(req))
	if !errors.Is(err, quota.ErrExhausted) || !strings.Contains(err.Error(), "fleet") {
		t.Fatalf("the fleet cap must bind, got %v", err)
	}
	if !strings.Contains(err.Error(), "a retry will not help") {
		t.Fatalf("a fleet denial must say retrying is pointless, got %q", err)
	}
}

// TestOnlyOneControllerGetsTheLastSlot is the race SPEC.md warns about, tested the
// only way it can be: with real concurrency and no test-side locking.
func TestOnlyOneControllerGetsTheLastSlot(t *testing.T) {
	const controllers = 24
	l := quota.NewMemoryLedger(standardGrants(1, 1, 1, 1), func() time.Time { return now })

	var wg sync.WaitGroup
	var mu sync.Mutex
	var granted []string

	for i := 0; i < controllers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := request(fmt.Sprintf("env-%02d", i), oneSlot)
			if _, err := l.Reserve(context.Background(), req, quota.Scopes(req)); err == nil {
				mu.Lock()
				granted = append(granted, req.EnvironmentID)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if len(granted) != 1 {
		t.Fatalf("%d controllers consumed the single remaining slot: %v", len(granted), granted)
	}
}

// TestPartialReservationNeverLeaks is the second half of atomicity: a reservation
// refused at any scope must consume nothing at any scope. A partial hold leaks
// capacity with no environment to account for it.
func TestPartialReservationNeverLeaks(t *testing.T) {
	// Every scope is wide except the profile, which has exactly one slot.
	l := quota.NewMemoryLedger(standardGrants(10, 10, 10, 1), func() time.Time { return now })

	// Fill the profile.
	fill := request("filler", oneSlot)
	if _, err := l.Reserve(context.Background(), fill, quota.Scopes(fill)); err != nil {
		t.Fatalf("filler: %v", err)
	}

	fleet := quota.ScopeRef{Scope: quota.ScopeFleet, Ref: "global"}
	before, err := l.Remaining(context.Background(), fleet, now)
	if err != nil {
		t.Fatalf("remaining: %v", err)
	}

	req := request("env-1", oneSlot)
	if _, err := l.Reserve(context.Background(), req, quota.Scopes(req)); !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("the full profile must refuse, got %v", err)
	}

	after, err := l.Remaining(context.Background(), fleet, now)
	if err != nil {
		t.Fatalf("remaining: %v", err)
	}
	if after != before {
		t.Fatalf("a refused reservation consumed capacity anyway: %v then %v", before, after)
	}
	if len(l.Active()) != 1 {
		t.Fatalf("a refused reservation must not be recorded, have %d", len(l.Active()))
	}
}

// TestReleaseIsIdempotent: cleanup is retried, so a double release must not invent
// capacity that was never bought.
func TestReleaseIsIdempotent(t *testing.T) {
	l := quota.NewMemoryLedger(standardGrants(3, 3, 3, 3), func() time.Time { return now })
	req := request("env-1", oneSlot)
	res, err := l.Reserve(context.Background(), req, quota.Scopes(req))
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}

	fleet := quota.ScopeRef{Scope: quota.ScopeFleet, Ref: "global"}
	full, _ := l.Remaining(context.Background(), fleet, now)

	if err := l.Release(context.Background(), res.ID); err != nil {
		t.Fatalf("first release: %v", err)
	}
	// A retried cleanup must be safe.
	err = l.Release(context.Background(), res.ID)
	if !errors.Is(err, quota.ErrNoReservation) {
		t.Fatalf("a repeated release must report the reservation is gone, got %v", err)
	}

	restored, _ := l.Remaining(context.Background(), fleet, now)
	if restored.Concurrency != full.Concurrency+1 {
		t.Fatalf("release must restore exactly one slot: had %d, want %d",
			full.Concurrency, restored.Concurrency+1)
	}
}

// TestReleaseRestoresEveryScope, since a reservation holds four.
func TestReleaseRestoresEveryScope(t *testing.T) {
	l := quota.NewMemoryLedger(standardGrants(5, 5, 5, 5), func() time.Time { return now })
	req := request("env-1", oneSlot)
	res, err := l.Reserve(context.Background(), req, quota.Scopes(req))
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}

	for _, s := range quota.Scopes(req) {
		before, _ := l.Remaining(context.Background(), s, now)
		if before.Concurrency != 4 {
			t.Fatalf("%s did not lose a slot: %v", quota.ShortestRef(s), before)
		}
		if before.CPUMillicores == 0 || before.StorageGiB == 0 {
			t.Fatalf("%s reported resource headroom that was never checked: %v", quota.ShortestRef(s), before)
		}
	}
	if err := l.Release(context.Background(), res.ID); err != nil {
		t.Fatalf("release: %v", err)
	}
	for _, s := range quota.Scopes(req) {
		after, _ := l.Remaining(context.Background(), s, now)
		if after.Concurrency != 5 {
			t.Fatalf("%s was not restored: %v", quota.ShortestRef(s), after)
		}
	}
}

// TestReservationRequiresAnEnvironment: capacity consumed by nothing is a leak by
// definition.
func TestReservationRequiresAnEnvironment(t *testing.T) {
	l := quota.NewMemoryLedger(standardGrants(5, 5, 5, 5), func() time.Time { return now })
	req := quota.Request{Actor: "actor-1", Repository: "repo/acme/app", Profile: "postgres-standard", Demanded: oneSlot, Now: now}
	if _, err := l.Reserve(context.Background(), req, quota.Scopes(req)); err == nil {
		t.Fatal("a reservation must name the environment consuming it")
	}
}

// TestUnknownScopeRefused: a scope with no grant has no ceiling, which would be
// unlimited capacity.
func TestUnknownScopeRefused(t *testing.T) {
	l := quota.NewMemoryLedger(nil, func() time.Time { return now })
	req := request("env-1", oneSlot)
	if _, err := l.Reserve(context.Background(), req, quota.Scopes(req)); !errors.Is(err, quota.ErrNotAuthorized) {
		t.Fatalf("a scope with no grant must be refused, got %v", err)
	}
}

// TestReservationOutsideTheWindowRefused: an expired window is not a standing
// allowance.
func TestReservationOutsideTheWindowRefused(t *testing.T) {
	past := []quota.Grant{
		{Scope: quota.ScopeFleet, Ref: "global",
			WindowStart: now.Add(-48 * time.Hour), WindowEnd: now.Add(-time.Hour), MaxConcurrency: 100},
	}
	l := quota.NewMemoryLedger(past, func() time.Time { return now })
	req := request("env-1", oneSlot)
	if _, err := l.Reserve(context.Background(), req, quota.Scopes(req)); !errors.Is(err, quota.ErrNotAuthorized) {
		t.Fatalf("an elapsed window must refuse reservations, got %v", err)
	}
}

// TestRemainingOutsideTheWindowIsZero stops a report claiming headroom that is not
// running.
func TestRemainingOutsideTheWindowIsZero(t *testing.T) {
	past := []quota.Grant{
		{Scope: quota.ScopeFleet, Ref: "global",
			WindowStart: now.Add(-48 * time.Hour), WindowEnd: now.Add(-time.Hour), MaxConcurrency: 100},
	}
	l := quota.NewMemoryLedger(past, func() time.Time { return now })
	rem, err := l.Remaining(context.Background(), quota.ScopeRef{Scope: quota.ScopeFleet, Ref: "global"}, now)
	if err != nil {
		t.Fatalf("remaining: %v", err)
	}
	if rem.Concurrency != 0 {
		t.Fatalf("outside its window a grant offers nothing, got %v", rem)
	}
}

// TestUnconstrainedDimensionsDoNotRefuse: a profile with no storage ceiling must not
// reject every environment that attaches some storage.
func TestUnconstrainedDimensionsDoNotRefuse(t *testing.T) {
	s, e := window()
	// Every scope is granted, and none of them constrains cpu, storage or money.
	var grants []quota.Grant
	for _, sc := range quota.Scopes(quota.Request{Repository: "r", Actor: "a", Profile: "p"}) {
		grants = append(grants, quota.Grant{
			Scope: sc.Scope, Ref: sc.Ref, WindowStart: s, WindowEnd: e, MaxConcurrency: 10,
		})
	}
	l := quota.NewMemoryLedger(grants, func() time.Time { return now })

	req := quota.Request{EnvironmentID: "env-1", Actor: "a", Repository: "r", Profile: "p", Now: now,
		Demanded: quota.Demand{Concurrency: 1, CPUMillicores: 999, StorageGiB: 999, AllowanceMinor: 999}}
	if _, err := l.Reserve(context.Background(), req, quota.Scopes(req)); err != nil {
		t.Fatalf("unconstrained dimensions must not refuse: %v", err)
	}
}

// TestAllowanceIsEnforced: money is a real dimension, not metadata.
func TestAllowanceIsEnforced(t *testing.T) {
	// Every scope granted, but the fleet's money allowance is only enough for one.
	l := quota.NewMemoryLedger(moneyCappedGrants(1_500), func() time.Time { return now })

	req := request("env-1", quota.Demand{Concurrency: 1, AllowanceMinor: 1_000})
	if _, err := l.Reserve(context.Background(), req, quota.Scopes(req)); err != nil {
		t.Fatalf("first: %v", err)
	}
	req = request("env-2", quota.Demand{Concurrency: 1, AllowanceMinor: 1_000})
	_, err := l.Reserve(context.Background(), req, quota.Scopes(req))
	if !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("the allowance must bind, got %v", err)
	}
	if !strings.Contains(err.Error(), "allowance") {
		t.Fatalf("the denial must name the shortfall dimension, got %q", err)
	}
}

// moneyCappedGrants grants every scope with a fleet allowance of the given total.
func moneyCappedGrants(allowance int64) []quota.Grant {
	s, e := window()
	var grants []quota.Grant
	for _, sc := range quota.Scopes(quota.Request{Repository: "repo/acme/app", Actor: "actor-1", Profile: "postgres-standard"}) {
		a := int64(0)
		if sc.Scope == quota.ScopeFleet {
			a = allowance
		}
		grants = append(grants, quota.Grant{
			Scope: sc.Scope, Ref: sc.Ref, WindowStart: s, WindowEnd: e,
			MaxConcurrency: 10, AllowanceMinor: a, Currency: "USD",
		})
	}
	return grants
}

// TestDemandMustSatisfyTheProfile: an impossible request never reaches the ledger.
func TestDemandMustSatisfyTheProfile(t *testing.T) {
	m := quota.DefaultMaxima()
	if err := quota.CheckDemand(quota.Demand{Concurrency: 1, CPUMillicores: 100}, m); err != nil {
		t.Fatalf("a modest demand must be admitted: %v", err)
	}
	if err := quota.CheckDemand(quota.Demand{Concurrency: 0}, m); err == nil {
		t.Fatal("a reservation must consume at least one slot")
	}
	if err := quota.CheckDemand(quota.Demand{Concurrency: 1, CPUMillicores: 999_999}, m); !errors.Is(err, quota.ErrBeyondMaximum) {
		t.Fatal("compute beyond the profile maximum must be refused")
	}
	if err := quota.CheckDemand(quota.Demand{Concurrency: 1, StorageGiB: 5_000}, m); !errors.Is(err, quota.ErrBeyondMaximum) {
		t.Fatal("storage beyond the profile maximum must be refused")
	}
}

// TestTTLIsClampedNotRefused: a caller asking for too long gets the policy maximum,
// which is the point. It must not get the extra time.
func TestTTLIsClampedNotRefused(t *testing.T) {
	m := quota.DefaultMaxima()

	got, err := quota.TTLBounds(0, m)
	if err != nil || got != quota.DefaultTTL {
		t.Fatalf("an unspecified TTL must default to 24h, got %v (%v)", got, err)
	}
	got, err = quota.TTLBounds(48*time.Hour, m)
	if err != nil || got != 48*time.Hour {
		t.Fatalf("a TTL inside the maximum must be honoured, got %v (%v)", got, err)
	}
	got, err = quota.TTLBounds(30*24*time.Hour, m)
	if err != nil {
		t.Fatalf("an over-long TTL clamps rather than failing: %v", err)
	}
	if got != 72*time.Hour {
		t.Fatalf("an over-long TTL must clamp to the 72h maximum, got %v", got)
	}
}

// TestExtensionRequiresAnAuthorizedActor is the first of the three requirements.
func TestExtensionRequiresAnAuthorizedActor(t *testing.T) {
	g := quota.NewGate(quota.DefaultMaxima(), true, func() time.Time { return now })
	_, err := g.EvaluateExtension(quota.Extension{EnvironmentID: "env-1", Now: now}, nil, quota.Demand{Concurrency: 1})
	if !errors.Is(err, quota.ErrNotAuthorized) {
		t.Fatalf("an unidentified actor must be refused, got %v", err)
	}
}

// TestExtensionRequiresRemainingAllowance is the second. It is checked before the
// grant is audited, because there is no point auditing a grant that cannot be made.
func TestExtensionRequiresRemainingAllowance(t *testing.T) {
	g := quota.NewGate(quota.DefaultMaxima(), true, func() time.Time { return now })
	_, err := g.EvaluateExtension(
		quota.Extension{EnvironmentID: "env-1", Actor: "actor-1", Now: now}, nil, quota.Demand{Concurrency: 0})
	if !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("an extension with no remaining concurrency must be refused, got %v", err)
	}
}

// TestExtensionRequiresAnAuditRecord is the third.
func TestExtensionRequiresAnAuditRecord(t *testing.T) {
	g := quota.NewGate(quota.DefaultMaxima(), true, func() time.Time { return now })
	_, err := g.EvaluateExtension(
		quota.Extension{EnvironmentID: "env-1", Actor: "actor-1", Now: now}, nil, quota.Demand{Concurrency: 1})
	if !errors.Is(err, quota.ErrNotAuthorized) {
		t.Fatalf("an unaudited extension must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "capacity revision") {
		t.Fatalf("the refusal must point at the audited revision, got %q", err)
	}

	audited := []quota.AuditEntry{{Actor: "ops-1", Operation: "raise_fleet_limit", Revision: "rev-7"}}
	dec, err := g.EvaluateExtension(
		quota.Extension{EnvironmentID: "env-1", Actor: "actor-1", Now: now}, audited, quota.Demand{Concurrency: 1})
	if err != nil {
		t.Fatalf("a fully authorized extension must succeed: %v", err)
	}
	if dec.Audit.Actor != "actor-1" || dec.Audit.Operation != "extend_ttl" {
		t.Fatalf("the grant must carry its own audit entry, got %+v", dec.Audit)
	}
	if dec.NewExpiry != now.Add(quota.DefaultTTL) {
		t.Fatalf("the grant must set a real expiry, got %v", dec.NewExpiry)
	}
}

// TestExtensionIsClampedToTheMaximum: an extension is still subject to policy.
func TestExtensionIsClampedToTheMaximum(t *testing.T) {
	g := quota.NewGate(quota.DefaultMaxima(), true, func() time.Time { return now })
	dec, err := g.EvaluateExtension(
		quota.Extension{EnvironmentID: "env-1", Actor: "actor-1", Requested: 90 * 24 * time.Hour, Now: now},
		[]quota.AuditEntry{{Actor: "ops", Operation: "rev", Revision: "r1"}},
		quota.Demand{Concurrency: 1})
	if err != nil {
		t.Fatalf("over-long extension clamps rather than failing: %v", err)
	}
	if !dec.Clamped {
		t.Fatal("a clamped grant must say so")
	}
	if dec.Granted != 72*time.Hour {
		t.Fatalf("clamped to 72h, got %v", dec.Granted)
	}
}

// TestExtensionCountIsBounded is the guard against turning a preview into a permanent
// environment by retrying.
func TestExtensionCountIsBounded(t *testing.T) {
	m := quota.DefaultMaxima()
	g := quota.NewGate(m, true, func() time.Time { return now })
	audited := []quota.AuditEntry{{Actor: "ops", Operation: "rev", Revision: "r1"}}

	for i := 0; i < m.MaxExtensions; i++ {
		if _, err := g.EvaluateExtension(
			quota.Extension{EnvironmentID: "env-1", Actor: "a", ExtensionsSoFar: i, Now: now},
			audited, quota.Demand{Concurrency: 1}); err != nil {
			t.Fatalf("extension %d must be allowed: %v", i, err)
		}
	}
	_, err := g.EvaluateExtension(
		quota.Extension{EnvironmentID: "env-1", Actor: "a", ExtensionsSoFar: m.MaxExtensions, Now: now},
		audited, quota.Demand{Concurrency: 1})
	if !errors.Is(err, quota.ErrNotAuthorized) {
		t.Fatalf("the %dth extension must be refused", m.MaxExtensions+1)
	}
	if !strings.Contains(err.Error(), "capacity revision") {
		t.Fatalf("exceeding the cap must direct an operator to a revision, got %q", err)
	}
}

// TestGraceMustHaveAnExplicitCapAndExpiry is SPEC.md's rule, enforced.
func TestGraceMustHaveAnExplicitCapAndExpiry(t *testing.T) {
	m := quota.DefaultMaxima()

	if err := quota.ValidateGrace(quota.Grace{}, m); !errors.Is(err, quota.ErrGraceUnbounded) {
		t.Fatalf("a zero grace is not a grace period, got %v", err)
	}
	if err := quota.ValidateGrace(quota.Grace{Duration: time.Hour, Reason: "incident"}, m); !errors.Is(err, quota.ErrGraceUnbounded) {
		t.Fatalf("grace without an expiry must be refused, got %v", err)
	}
	if err := quota.ValidateGrace(quota.Grace{Duration: time.Hour, ExpiresAt: now}, m); err == nil {
		t.Fatal("grace without a reason must be refused; it is indistinguishable from a leak")
	}
	if err := quota.ValidateGrace(quota.Grace{Duration: 100 * time.Hour, ExpiresAt: now, Reason: "incident"}, m); !errors.Is(err, quota.ErrBeyondMaximum) {
		t.Fatalf("grace beyond the cap must be refused, got %v", err)
	}
	if err := quota.ValidateGrace(quota.Grace{Duration: time.Hour, ExpiresAt: now, Reason: "incident 42"}, m); err != nil {
		t.Fatalf("bounded, expiring, explained grace must be allowed: %v", err)
	}
}

// TestExhaustionOrderStopsAdmissionBeforeDestroying is the rule the spec fixes, and
// the one whose violation burns money rather than leaking it.
func TestExhaustionOrderStopsAdmissionBeforeDestroying(t *testing.T) {
	if err := quota.ValidateExhaustionOrder(quota.DefaultExhaustionOrder()); err != nil {
		t.Fatalf("the default order must be valid: %v", err)
	}

	bad := []quota.Stage{quota.StageDestroy, quota.StageStopAdmission, quota.StageDrain}
	if err := quota.ValidateExhaustionOrder(bad); err == nil {
		t.Fatal("destroy before stop-admission must be refused")
	}
	if !strings.Contains(mustErr(quota.ValidateExhaustionOrder(bad)), "emptied and refilled") {
		t.Fatal("the refusal must explain why the order is refused")
	}

	if err := quota.ValidateExhaustionOrder([]quota.Stage{quota.StageDrain}); err == nil {
		t.Fatal("an order that never stops admission must be refused")
	}
	if err := quota.ValidateExhaustionOrder([]quota.Stage{quota.StageStopAdmission}); err == nil {
		t.Fatal("an order with no destroy stage must be refused")
	}
	if err := quota.ValidateExhaustionOrder([]quota.Stage{quota.StageStopAdmission, quota.StageStopAdmission}); err == nil {
		t.Fatal("a duplicated stage must be refused")
	}
}

// TestDefaultExhaustionOrderFollowsTheSpec pins the sequence itself, since the
// validation above only checks a few orderings.
func TestDefaultExhaustionOrderFollowsTheSpec(t *testing.T) {
	order := quota.DefaultExhaustionOrder()
	want := []quota.Stage{
		quota.StageStopAdmission,
		quota.StageStopLiveProviders,
		quota.StageStopExperiments,
		quota.StageDrain,
		quota.StageDestroy,
	}
	if len(order) != len(want) {
		t.Fatalf("the order has %d stages, want %d", len(order), len(want))
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("stage %d is %s, want %s", i, order[i], want[i])
		}
	}
}

// TestReportIdentifiesTheBindingConstraint: the operator needs to know which limit to
// change, and stability means comparing two reports does not require guessing.
func TestReportIdentifiesTheBindingConstraint(t *testing.T) {
	l := quota.NewMemoryLedger(standardGrants(10, 1, 5, 10), func() time.Time { return now })
	req := request("env-1", oneSlot)
	if _, err := l.Reserve(context.Background(), req, quota.Scopes(req)); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	reports, err := l.Report(context.Background(), quota.Scopes(req), now)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if len(reports) != 4 {
		t.Fatalf("a report must cover every scope, got %d", len(reports))
	}
	// Sorted by scope name, so consecutive runs agree.
	if reports[0].Ref.Scope != quota.ScopeActor {
		t.Fatalf("reports must be stably ordered, first is %s", reports[0].Ref.Scope)
	}
	for _, r := range reports {
		if r.Ref.Scope == quota.ScopeRepository && !r.Exhausted {
			t.Fatal("the full repository must be reported as exhausted")
		}
		if r.Ref.Scope == quota.ScopeFleet && r.Exhausted {
			t.Fatal("the fleet has room and must not be reported exhausted")
		}
	}
}

// TestScopesAreDeterministic: an unstable order would make two reports incomparable.
func TestScopesAreDeterministic(t *testing.T) {
	req := request("env-1", oneSlot)
	first := quota.Bindings(quota.Scopes(req))
	for i := 0; i < 5; i++ {
		again := quota.Bindings(quota.Scopes(req))
		for j := range first {
			if first[j] != again[j] {
				t.Fatalf("scope order is unstable at %d: %v vs %v", j, first, again)
			}
		}
	}
}

// TestReservationIsRecordedAgainstEveryScope keeps the release path honest.
func TestReservationIsRecordedAgainstEveryScope(t *testing.T) {
	l := quota.NewMemoryLedger(standardGrants(5, 5, 5, 5), func() time.Time { return now })
	req := request("env-1", oneSlot)
	res, err := l.Reserve(context.Background(), req, quota.Scopes(req))
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if len(res.ScopeRefs) != 4 {
		t.Fatalf("a reservation must record all four scopes, got %d", len(res.ScopeRefs))
	}
	if res.EnvironmentID != "env-1" || res.ID == "" {
		t.Fatalf("a reservation must identify itself, got %+v", res)
	}
	if res.ExpiresAt.IsZero() {
		t.Fatal("a reservation must expire, or capacity is held forever")
	}
	if !strings.Contains(res.ID, "res-") {
		t.Fatalf("reservation ids must be greppable in logs, got %q", res.ID)
	}
}

// TestGraceDoesNotExtendTheReservation checks the two clocks stay separate.
func TestGraceDoesNotExtendTheReservation(t *testing.T) {
	l := quota.NewMemoryLedger(standardGrants(1, 1, 1, 1), func() time.Time { return now })
	req := request("env-1", oneSlot)
	res, err := l.Reserve(context.Background(), req, quota.Scopes(req))
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if !res.ExpiresAt.Equal(now.Add(quota.DefaultTTL)) {
		t.Fatalf("the reservation must carry the default TTL, got %v", res.ExpiresAt)
	}
}
