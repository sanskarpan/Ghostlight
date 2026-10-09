package foundation_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/foundation"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func registry(t *testing.T) *foundation.MemoryRegistry {
	t.Helper()
	return foundation.NewMemoryRegistry(func() time.Time { return now })
}

// qualified publishes an output and its passing evidence.
func qualified(t *testing.T, r *foundation.MemoryRegistry, o foundation.Output) {
	t.Helper()
	if err := r.Publish(o); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := r.Qualify(foundation.Qualification{
		Output: o, QualifiedBy: "platform-bootstrap", QualifiedAt: now,
		Checks: foundation.PassingChecks(o.Kind),
	}); err != nil {
		t.Fatalf("qualify: %v", err)
	}
}

func depender(t *testing.T, r foundation.Registry) *foundation.Depender {
	t.Helper()
	d, err := foundation.New(r, foundation.Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("new depender: %v", err)
	}
	return d
}

// TestDependerRequiresARegistry: without one, every dependency is unqualified by
// omission.
func TestDependerRequiresARegistry(t *testing.T) {
	if _, err := foundation.New(nil, foundation.Config{}); err == nil {
		t.Fatal("a depender must not be constructible without the foundation registry")
	}
}

// TestQualifiedOutputIsUsable is the ordinary path.
func TestQualifiedOutputIsUsable(t *testing.T) {
	r := registry(t)
	qualified(t, r, foundation.NetworkOutput())
	d := depender(t, r)

	out, err := d.Require(context.Background(), foundation.KindNetwork, "primary")
	if err != nil {
		t.Fatalf("require: %v", err)
	}
	if out.Value != "vpc-0123abc" {
		t.Fatalf("the dependency must carry its value, got %q", out.Value)
	}
	if !foundation.PlatformOwned(out) {
		t.Fatal("a foundation output must be platform-owned")
	}
}

// TestAnUnqualifiedOutputIsRefused is the package's central property.
//
// The reason it matters: an unqualified network does not error when used. It simply
// isolates badly. A missing output fails visibly at wiring time; an unqualified one is
// used and the problem surfaces later, as a preview that can reach something it should
// not.
func TestAnUnqualifiedOutputIsRefused(t *testing.T) {
	r := registry(t)
	net := foundation.NetworkOutput()
	if err := r.Publish(net); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// Published but never qualified.
	_, err := depender(t, r).Require(context.Background(), foundation.KindNetwork, "primary")
	if !errors.Is(err, foundation.ErrUnqualified) {
		t.Fatalf("an unqualified output must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "refusing to assume") {
		t.Fatalf("the refusal must state what it declined to do, got %q", err)
	}
}

// TestAFailedCheckRefusesTheOutput: presence is not qualification.
func TestAFailedCheckRefusesTheOutput(t *testing.T) {
	r := registry(t)
	net := foundation.NetworkOutput()
	if err := r.Publish(net); err != nil {
		t.Fatalf("publish: %v", err)
	}
	checks := foundation.PassingChecks(net.Kind)
	// egress_default_deny failed.
	for i := range checks {
		if checks[i].Name == "egress_default_deny" {
			checks[i].Passed = false
			checks[i].Detail = "egress allowed to 0.0.0.0/0"
		}
	}
	if err := r.Qualify(foundation.Qualification{
		Output: net, QualifiedBy: "platform-bootstrap", QualifiedAt: now, Checks: checks,
	}); err != nil {
		t.Fatalf("qualify: %v", err)
	}

	_, err := depender(t, r).Require(context.Background(), foundation.KindNetwork, "primary")
	if !errors.Is(err, foundation.ErrUnqualified) {
		t.Fatalf("a failed check must refuse, got %v", err)
	}
	// The refusal must name which check, or it is not diagnosable.
	if !strings.Contains(err.Error(), "egress_default_deny") {
		t.Fatalf("the refusal must name the failed check, got %q", err)
	}
}

// TestAnAbsentCheckIsNotAPassedCheck is the subtler half of the same rule.
//
// The most likely bug is forgetting to run a check, not a check failing. An evidence
// record that simply omits a required check must be refused, not treated as compliant.
func TestAnAbsentCheckIsNotAPassedCheck(t *testing.T) {
	r := registry(t)
	net := foundation.NetworkOutput()
	if err := r.Publish(net); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// Only one of the two required checks was run.
	if err := r.Qualify(foundation.Qualification{
		Output: net, QualifiedBy: "platform-bootstrap", QualifiedAt: now,
		Checks: []foundation.Check{{Name: "isolated_from_shared", Passed: true}},
	}); err != nil {
		t.Fatalf("qualify: %v", err)
	}

	_, err := depender(t, r).Require(context.Background(), foundation.KindNetwork, "primary")
	if !errors.Is(err, foundation.ErrUnqualified) {
		t.Fatalf("an absent check must not count as passing, got %v", err)
	}
	if !strings.Contains(err.Error(), "egress_default_deny") {
		t.Fatalf("the refusal must name the missing check, got %q", err)
	}
}

// TestQualificationByNobodyIsNotQualification.
func TestQualificationByNobodyIsNotQualification(t *testing.T) {
	r := registry(t)
	if err := r.Publish(foundation.NetworkOutput()); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := r.Qualify(foundation.Qualification{
		Output: foundation.NetworkOutput(), QualifiedAt: now,
		Checks: foundation.PassingChecks(foundation.KindNetwork),
	}); err == nil {
		t.Fatal("qualification requires someone to have established it")
	}
}

// TestExpiredQualificationIsRefused: evidence goes stale.
func TestExpiredQualificationIsRefused(t *testing.T) {
	r := registry(t)
	net := foundation.NetworkOutput()
	if err := r.Publish(net); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := r.Qualify(foundation.Qualification{
		Output: net, QualifiedBy: "platform-bootstrap", QualifiedAt: now,
		ExpiresAt: now.Add(time.Hour), Checks: foundation.PassingChecks(net.Kind),
	}); err != nil {
		t.Fatalf("qualify: %v", err)
	}

	// Before expiry it is usable.
	if _, err := depender(t, r).Require(context.Background(), foundation.KindNetwork, "primary"); err != nil {
		t.Fatalf("before expiry it must be usable: %v", err)
	}

	// After expiry it is not.
	later := now.Add(2 * time.Hour)
	d, err := foundation.New(r, foundation.Config{Now: func() time.Time { return later }})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_, err = d.Require(context.Background(), foundation.KindNetwork, "primary")
	if !errors.Is(err, foundation.ErrExpired) {
		t.Fatalf("lapsed qualification must be refused, got %v", err)
	}
}

// TestUnknownOutputIsRefusedDistinctly: absent is a different problem from unqualified,
// and the two have different fixes.
func TestUnknownOutputIsRefusedDistinctly(t *testing.T) {
	r := registry(t)
	_, err := depender(t, r).Require(context.Background(), foundation.KindNetwork, "primary")
	if !errors.Is(err, foundation.ErrUnknownOutput) {
		t.Fatalf("an absent output must be reported as unknown, got %v", err)
	}
}

// TestAnEmptyValueIsRefused: a published output with no value is not a dependency.
func TestAnEmptyValueIsRefused(t *testing.T) {
	r := registry(t)
	empty := foundation.Output{
		Kind: foundation.KindNetwork, Name: "primary", Value: "",
		Ownership: foundation.OwnershipPlatform,
	}
	if err := r.Publish(empty); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := r.Qualify(foundation.Qualification{
		Output: empty, QualifiedBy: "ops", QualifiedAt: now,
		Checks: foundation.PassingChecks(empty.Kind),
	}); err != nil {
		t.Fatalf("qualify: %v", err)
	}
	if _, err := depender(t, r).Require(context.Background(), foundation.KindNetwork, "primary"); !errors.Is(err, foundation.ErrUnqualified) {
		t.Fatalf("an empty value must be refused, got %v", err)
	}
}

// TestAFoundationOutputCannotBeEnvironmentOwned stops a mislabelled output from ever
// being depended upon.
func TestAFoundationOutputCannotBeEnvironmentOwned(t *testing.T) {
	r := registry(t)
	mislabelled := foundation.Output{
		Kind: foundation.KindNetwork, Name: "primary", Value: "vpc-1",
		Ownership: foundation.OwnershipEnvironment,
	}
	if err := r.Publish(mislabelled); err == nil {
		t.Fatal("a foundation resource cannot be published as environment-owned")
	}
}

// TestUnknownKindsAreNotConsumable: fail closed on anything unrecognised.
func TestUnknownKindsAreNotConsumable(t *testing.T) {
	if foundation.Kind("secret_beans").Consumable() {
		t.Fatal("an unrecognised kind must not be consumable")
	}
	for _, k := range []foundation.Kind{
		foundation.KindAccount, foundation.KindRegion, foundation.KindNetwork,
		foundation.KindRole, foundation.KindStateBucket, foundation.KindLogging, foundation.KindCluster,
	} {
		if !k.Consumable() {
			t.Fatalf("%s should be consumable", k)
		}
	}
}

// TestEveryFoundationOutputIsPlatformOwned: the invariant that keeps a preview teardown
// from reaching the foundation, checked across every kind.
func TestEveryFoundationOutputIsPlatformOwned(t *testing.T) {
	r := registry(t)
	d := depender(t, r)
	for _, o := range []foundation.Output{
		foundation.NetworkOutput(), foundation.RoleOutput(), foundation.StateOutput(),
	} {
		qualified(t, r, o)
		got, err := d.Require(context.Background(), o.Kind, o.Name)
		if err != nil {
			t.Fatalf("require %s: %v", o.Kind, err)
		}
		if !foundation.PlatformOwned(got) {
			t.Fatalf("%s was not platform-owned", o.Kind)
		}
	}
}

// ---------------------------------------------------------------------------
// Destroy scope
// ---------------------------------------------------------------------------

// TestFoundationIsNeverInAnEnvironmentDestroyScope is the property G2.1 exists for.
func TestFoundationIsNeverInAnEnvironmentDestroyScope(t *testing.T) {
	platform := foundation.NetworkOutput()
	ours := foundation.Output{
		Kind: foundation.KindNetwork, Name: "preview-db", Value: "nat-preview-db-1",
		Ownership: foundation.OwnershipEnvironment,
	}

	plan, err := foundation.BuildDestroyPlan([]foundation.Output{platform, ours}, []string{"nat-preview-db-1"})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.EnvironmentOwned) != 1 || plan.EnvironmentOwned[0].Value != "nat-preview-db-1" {
		t.Fatalf("only the environment's own resource may be destroyed, got %+v", plan.EnvironmentOwned)
	}
	if len(plan.Excluded) != 1 || plan.Excluded[0].Output.Value != "vpc-0123abc" {
		t.Fatalf("the foundation must be excluded, got %+v", plan.Excluded)
	}
	if !strings.Contains(plan.Excluded[0].Reason, "platform-owned") {
		t.Fatalf("the exclusion must say why, got %q", plan.Excluded[0].Reason)
	}
}

// TestDestroyScopeIsDerivedByExclusion: a new foundation output is excluded by default.
// An allowlist would make every new output destroyable until someone noticed.
func TestDestroyScopeIsDerivedByExclusion(t *testing.T) {
	future := foundation.Output{
		Kind: foundation.KindCluster, Name: "new-future-pool", Value: "pool-1",
		Ownership: foundation.OwnershipPlatform,
	}
	plan, err := foundation.BuildDestroyPlan([]foundation.Output{future}, nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.EnvironmentOwned) != 0 {
		t.Fatalf("an unfamiliar platform-owned output must be excluded by default, got %+v", plan.EnvironmentOwned)
	}
	if len(plan.Excluded) != 1 {
		t.Fatalf("it must appear as an explicit exclusion, got %+v", plan.Excluded)
	}
}

// TestAnUnknownResourceIsNotOurs: not platform-owned and not on our list is refused,
// the same reasoning the resource ledger applies.
func TestAnUnknownResourceIsNotOurs(t *testing.T) {
	unknown := foundation.Output{
		Kind: foundation.KindNetwork, Name: "mystery", Value: "nat-someone-elses",
		Ownership: foundation.OwnershipEnvironment,
	}
	plan, err := foundation.BuildDestroyPlan([]foundation.Output{unknown}, nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.EnvironmentOwned) != 0 {
		t.Fatalf("a resource we cannot claim must not be destroyed, got %+v", plan.EnvironmentOwned)
	}
	if !strings.Contains(plan.Excluded[0].Reason, "not among") {
		t.Fatalf("the exclusion must say why, got %q", plan.Excluded[0].Reason)
	}
}

// TestDestroyPlanIsStablyOrdered: the plan is an audit artifact, so two runs must produce
// the same one.
func TestDestroyPlanIsStablyOrdered(t *testing.T) {
	outputs := []foundation.Output{
		{Kind: foundation.KindRole, Name: "b", Value: "nat-b", Ownership: foundation.OwnershipEnvironment},
		{Kind: foundation.KindNetwork, Name: "a", Value: "nat-a", Ownership: foundation.OwnershipEnvironment},
		{Kind: foundation.KindCluster, Name: "z", Value: "nat-z", Ownership: foundation.OwnershipEnvironment},
	}
	ids := []string{"nat-a", "nat-b", "nat-z"}
	first, err := foundation.BuildDestroyPlan(outputs, ids)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, _ := foundation.BuildDestroyPlan(outputs, ids)
		for j := range first.EnvironmentOwned {
			if first.EnvironmentOwned[j].Value != again.EnvironmentOwned[j].Value {
				t.Fatalf("the plan is unstable: %+v vs %+v", first.EnvironmentOwned, again.EnvironmentOwned)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// State locations
// ---------------------------------------------------------------------------

// TestStateLocationIsDerivedFromTheEnvironmentID.
func TestStateLocationIsDerivedFromTheEnvironmentID(t *testing.T) {
	loc, err := foundation.BuildStateLocation("ghostlight-tfstate", "env-01HQ")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if loc.Bucket != "ghostlight-tfstate" {
		t.Fatalf("bucket: %s", loc.Bucket)
	}
	if loc.Prefix != "environments/env-01HQ/terraform/" {
		t.Fatalf("prefix: %s", loc.Prefix)
	}
	if loc.LockName != "ghostlight-tfstate-env-01HQ" {
		t.Fatalf("lock name: %s", loc.LockName)
	}
}

// TestStatePrefixIsPerEnvironment: two previews must never share a state prefix, or
// applying one destroys the other's state.
func TestStatePrefixIsPerEnvironment(t *testing.T) {
	a, err := foundation.BuildStateLocation("b", "env-1")
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	c, err := foundation.BuildStateLocation("b", "env-2")
	if err != nil {
		t.Fatalf("c: %v", err)
	}
	if a.Prefix == c.Prefix {
		t.Fatal("two environments must not share a state prefix")
	}
	if a.LockName == c.LockName {
		t.Fatal("two environments must not share a state lock")
	}
}

// TestStateLocationCannotBeEscaped: the prefix is a path into the platform's own bucket,
// so an id that could traverse is refused even though the id should be platform-issued.
func TestStateLocationCannotBeEscaped(t *testing.T) {
	for _, id := range []string{"", "..", ".", "../../other", "a/b", `a\b`, "a\x00b"} {
		if _, err := foundation.StatePrefix(id); err == nil {
			t.Fatalf("id %q must be refused as a prefix segment", id)
		}
	}
	for _, b := range []string{"", "a/b", `a\b`, "a.b", "a\x00b"} {
		if _, err := foundation.BuildStateLocation(b, "env-1"); err == nil {
			t.Fatalf("bucket %q must be refused", b)
		}
	}
}

// TestFailedChecksAreReportedInAStableOrder, so a refusal reads the same way twice.
func TestFailedChecksAreReportedInAStableOrder(t *testing.T) {
	q := foundation.Qualification{Checks: []foundation.Check{
		{Name: "zebra", Passed: false},
		{Name: "alpha", Passed: false},
		{Name: "middle", Passed: true},
	}}
	got := q.FailedChecks()
	if len(got) != 2 || got[0] != "alpha" || got[1] != "zebra" {
		t.Fatalf("failed checks must be sorted, got %v", got)
	}
	if q.Valid() {
		t.Fatal("a qualification with a failed check is not valid")
	}
}

// TestQualificationWithNoChecksIsNotValid: empty evidence is not evidence.
func TestQualificationWithNoChecksIsNotValid(t *testing.T) {
	q := foundation.Qualification{}
	if q.Valid() {
		t.Fatal("an empty check list is not a qualification")
	}
}

// TestQualificationWithNoExpiryNeverLapses: correct for a value that cannot change.
func TestQualificationWithNoExpiryNeverLapses(t *testing.T) {
	q := foundation.Qualification{}
	if q.Expired(now.Add(1000 * time.Hour)) {
		t.Fatal("a qualification with no expiry never lapses")
	}
	q.ExpiresAt = now
	if !q.Expired(now) {
		t.Fatal("a qualification lapses at its expiry")
	}
}
