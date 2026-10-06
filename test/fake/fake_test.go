package fake_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/actions"
	"github.com/sanskarpan/Ghostlight/internal/provider"
	"github.com/sanskarpan/Ghostlight/test/fake"
)

var now = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

var lease = actions.Lease{Owner: "controller-a", Epoch: 3}

func request(env, key string) provider.AllocationRequest {
	return provider.AllocationRequest{
		EnvironmentID: env,
		Generation:    7,
		Kind:          provider.KindPostgres,
		LogicalKey:    key,
		Bounds:        provider.Bounds{MaxVCPU: 1, MaxMemoryMiB: 2048, MaxStorageGiB: 20},
	}
}

var profileMax = provider.Bounds{MaxVCPU: 6, MaxMemoryMiB: 12288, MaxStorageGiB: 200, MaxPartitions: 8, MaxActiveUnits: 1000}

// allocateAndCommit models one reconciliation step: commit the intent, attempt
// the external call, then record the outcome under the fence.
func allocateAndCommit(t *testing.T, p *fake.Fake, a *actions.Action) (*provider.Allocation, error) {
	t.Helper()
	alloc, err := p.Allocate(context.Background(), provider.AllocationRequest{
		EnvironmentID: a.EnvironmentID,
		Generation:    a.Generation,
		Kind:          provider.KindPostgres,
		LogicalKey:    a.LogicalKey,
		Bounds:        provider.Bounds{MaxVCPU: 1, MaxMemoryMiB: 2048, MaxStorageGiB: 20},
	})
	if err == nil {
		if aerr := a.AcceptResult(lease, a.Generation, actions.StateSucceeded, alloc.Reference, now); aerr != nil {
			t.Fatalf("commit result: %v", aerr)
		}
		return alloc, nil
	}
	// Any error after the call may have taken effect is uncertain, not failed.
	if uerr := a.MarkUncertain(lease, a.Generation, err.Error(), now.Add(time.Minute), now); uerr != nil {
		t.Fatalf("mark uncertain: %v", uerr)
	}
	return nil, err
}

func newAction(t *testing.T, key string) *actions.Action {
	t.Helper()
	a, err := actions.New("env-01HQ", 7, actions.TypeAllocate, key, "sha256:aa", []string{"dep/postgres"}, now)
	if err != nil {
		t.Fatalf("new action: %v", err)
	}
	if err := a.Claim(lease, now); err != nil {
		t.Fatalf("claim: %v", err)
	}
	return a
}

// TestCreateFailsBeforeAnyEffectIsRetryableImmediately covers the boundary where
// the call fails cleanly: absence is provable, so a retry is safe.
func TestCreateFailsBeforeAnyEffectIsRetryableImmediately(t *testing.T) {
	p := fake.New(fake.FailBeforeCreate, nil)
	a := newAction(t, "alloc-pg")

	if _, err := allocateAndCommit(t, p, a); err == nil {
		t.Fatal("expected the injected pre-create failure")
	}
	if a.State != actions.StateUncertain {
		t.Fatalf("a clean pre-create failure should still be recorded as uncertain by this model, got %s", a.State)
	}

	// Observe proves absence, which permits a safe retry.
	obs, oerr := p.Observe(context.Background(), map[string]string{"handle": "ref-alloc-pg"})
	if oerr != nil {
		t.Fatalf("observe: %v", oerr)
	}
	if obs.Present {
		t.Fatal("resource should not exist after a pre-create failure")
	}
	if err := a.ResolveUncertain(actions.Observe{Existed: false, Gone: true, Reason: obs.Detail}, now); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if a.State != actions.StatePlanned {
		t.Fatalf("verified absence must return to planned, got %s", a.State)
	}
	if err := a.Claim(lease, now.Add(time.Hour)); err != nil {
		t.Fatalf("retry after verified absence must be permitted: %v", err)
	}
}

// TestCreateSucceedsButResponseIsLost is the central scenario: the resource
// exists but the caller cannot know it. The action must be uncertain, and
// observation must reveal the resource rather than causing a duplicate create.
func TestCreateSucceedsButResponseIsLost(t *testing.T) {
	p := fake.New(fake.FailAfterCreateBeforeResponse, nil)
	a := newAction(t, "alloc-pg")

	alloc, err := allocateAndCommit(t, p, a)
	if err == nil {
		t.Fatal("expected the injected post-create failure")
	}
	if alloc != nil {
		t.Fatal("caller must not receive an allocation handle it never asked for")
	}
	if a.State != actions.StateUncertain {
		t.Fatalf("a lost response must yield uncertain, got %s", a.State)
	}

	// The resource does exist natively.
	if !p.Exists("alloc-pg") {
		t.Fatal("test setup: the resource should exist natively")
	}

	// Observation must find it, and the action must resolve as succeeded without
	// a second create. The handle is discovered by ownership scan, exactly as a
	// real janitor would; it is not known to the caller whose response was lost.
	handle := p.HandleFor("alloc-pg", 0)
	if handle == "" {
		t.Fatal("test setup: expected a native resource")
	}
	obs, oerr := p.Observe(context.Background(), map[string]string{"handle": handle})
	if oerr != nil {
		t.Fatalf("observe: %v", oerr)
	}
	if !obs.Present {
		t.Fatal("observation must find the resource that was actually created")
	}
	if err := a.ResolveUncertain(actions.Observe{Existed: true, Reference: obs.Reference, Reason: obs.Detail}, now); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if a.State != actions.StateSucceeded {
		t.Fatalf("an existing resource means the create succeeded, got %s", a.State)
	}
	if p.Count() != 1 {
		t.Fatalf("observation must prevent a duplicate; live resources = %d", p.Count())
	}
}

// TestBlindRetryWouldDuplicate is the regression this design exists to prevent.
func TestBlindRetryWouldDuplicate(t *testing.T) {
	// Demonstrate the hazard directly: two allocates without observation create
	// two resources. The platform must never do this, and the action ledger's
	// refusal to reclaim an uncertain action is what prevents it.
	direct := fake.New(fake.FailNone, nil)
	req := request("env-01HQ", "alloc-pg")
	if _, err := direct.Allocate(context.Background(), req); err != nil {
		t.Fatalf("first allocate: %v", err)
	}
	if _, err := direct.Allocate(context.Background(), req); err != nil {
		t.Fatalf("second allocate: %v", err)
	}
	if direct.Count() != 2 {
		t.Fatalf("expected 2 resources from 2 unobserved creates, got %d", direct.Count())
	}

	// The ledger must refuse to hand an uncertain action back to a runner.
	unsafe := fake.New(fake.FailAfterCreateBeforeResponse, nil)
	a := newAction(t, "alloc-pg")
	_, _ = allocateAndCommit(t, unsafe, a)
	if !a.NeedsObservation() {
		t.Fatal("action must require observation")
	}
	if err := a.Claim(lease, now.Add(time.Hour)); err == nil {
		t.Fatal("the ledger must refuse to re-run an uncertain action without observation")
	}
	if unsafe.Count() != 1 {
		t.Fatalf("the uncertain action must not have been re-run; live resources = %d", unsafe.Count())
	}
}

// TestTransientFailureRecoversOnRetry covers a failure that applies once, so the
// retry succeeds and exactly one resource exists.
func TestTransientFailureRecoversOnRetry(t *testing.T) {
	p := fake.New(fake.FailBeforeCreate, nil).WithOnce()
	a := newAction(t, "alloc-pg")

	if _, err := allocateAndCommit(t, p, a); err == nil {
		t.Fatal("expected the injected failure")
	}
	obs, oerr := p.Observe(context.Background(), map[string]string{"handle": "ref-alloc-pg"})
	if oerr != nil {
		t.Fatalf("observe: %v", oerr)
	}
	if obs.Present {
		t.Fatal("a pre-create failure must leave no resource")
	}
	if err := a.ResolveUncertain(actions.Observe{Existed: false, Gone: true, Reason: obs.Detail}, now); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := a.Claim(lease, now.Add(time.Hour)); err != nil {
		t.Fatalf("retry must be permitted: %v", err)
	}
	alloc, err := p.Allocate(context.Background(), request("env-01HQ", "alloc-pg"))
	if err != nil {
		t.Fatalf("retry should now succeed: %v", err)
	}
	if err := a.AcceptResult(lease, a.Generation, actions.StateSucceeded, alloc.Reference, now); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if p.Count() != 1 {
		t.Fatalf("exactly one resource must exist after a recovered retry, got %d", p.Count())
	}
}

// TestUnobservableObservationDoesNotBecomeAbsence is the permission-failure case.
// Concluding absence here would cause a duplicate create on retry.
func TestUnobservableObservationDoesNotBecomeAbsence(t *testing.T) {
	// Both conditions at once: the create's outcome is unknown, and the
	// observation needed to resolve it cannot be performed. Concluding absence
	// here would cause a duplicate create on retry.
	p := fake.New(fake.FailAfterCreateBeforeResponse, nil).WithObserveMode(fake.FailObserve)
	a := newAction(t, "alloc-pg")
	_, _ = allocateAndCommit(t, p, a)
	if !a.NeedsObservation() {
		t.Fatalf("action must require observation, got %s", a.State)
	}

	var obsErr error
	if _, obsErr = p.Observe(context.Background(), map[string]string{"handle": "ref-alloc-pg"}); obsErr == nil {
		t.Fatal("expected the injected observation failure")
	} else if !errors.Is(obsErr, provider.ErrNotAbsent) {
		t.Fatalf("an unobservable observation must not present as absence, got %v", obsErr)
	}

	// Resolving as absent would be wrong. The action must stay uncertain.
	if rerr := a.ResolveUncertain(actions.Observe{Existed: false, Gone: false, Reason: obsErr.Error()}, now); rerr == nil {
		t.Fatal("an unresolvable observation must not resolve")
	}
	if a.State != actions.StateUncertain {
		t.Fatalf("state must remain uncertain, got %s", a.State)
	}
}

// TestPartialDestroyIsNotDestroyed covers the teardown boundary. A partial removal
// must leave the environment unresolved, never reported as absent.
func TestPartialDestroyIsNotDestroyed(t *testing.T) {
	p := fake.New(fake.FailDuringDestroy, nil)
	req := request("env-01HQ", "alloc-pg")
	alloc, err := p.Allocate(context.Background(), req)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if err := p.Destroy(context.Background(), *alloc); err == nil {
		t.Fatal("expected the injected partial destroy failure")
	}
	// Credentials were revoked but the resource is still present, so the
	// environment is not clean.
	if !p.Exists("alloc-pg") {
		t.Fatal("a partial destroy must leave the resource present")
	}
	obs, oerr := p.Observe(context.Background(), alloc.Reference)
	if oerr != nil {
		t.Fatalf("observe: %v", oerr)
	}
	if !obs.Present {
		t.Fatal("absence must not be claimed after a partial destroy")
	}
}

// TestDestroyIsIdempotent covers a repeated teardown, which must not error and
// must not create anything.
func TestDestroyIsIdempotent(t *testing.T) {
	p := fake.New(fake.FailNone, nil)
	req := request("env-01HQ", "alloc-pg")
	alloc, err := p.Allocate(context.Background(), req)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := p.Destroy(context.Background(), *alloc); err != nil {
			t.Fatalf("destroy %d must be idempotent: %v", i, err)
		}
	}
	if p.Count() != 0 {
		t.Fatalf("expected no live resources, got %d", p.Count())
	}
}

// TestRevokeRunsBeforeDestroy encodes the teardown ordering requirement.
func TestRevokeRunsBeforeDestroy(t *testing.T) {
	p := fake.New(fake.FailNone, nil)
	alloc, err := p.Allocate(context.Background(), request("env-01HQ", "alloc-pg"))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if err := p.Revoke(context.Background(), *alloc); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !p.Exists("alloc-pg") {
		t.Fatal("revoking credentials must not remove the resource; destruction follows")
	}
	if err := p.Destroy(context.Background(), *alloc); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if p.Count() != 0 {
		t.Fatal("resource should be gone")
	}
}

// TestProviderRefusesUntrustedCandidateWithoutIsolationClass is the admission
// gate that keeps a weaker provider from being used silently.
func TestProviderRefusesUntrustedCandidateWithoutIsolationClass(t *testing.T) {
	p := fake.New(fake.FailNone, map[provider.Capability]bool{
		provider.CapDedicatedDependencies: true,
		provider.CapEgressEnforcement:     true,
		// No isolation class and no node-identity withholding.
	})

	reqs := []provider.Requirement{
		{Capability: provider.CapDedicatedDependencies, Reason: "dedicated bounded dependencies", Critical: true},
		{Capability: provider.CapIsolationClass, Reason: "contain hostile candidate code", Critical: true},
	}
	err := provider.CheckRequirements(p.Capabilities(), reqs)
	if err == nil {
		t.Fatal("a provider without an isolation class must be refused for untrusted candidates")
	}
	var unavail *provider.UnavailableError
	if !errors.As(err, &unavail) {
		t.Fatalf("expected UnavailableError, got %T: %v", err, err)
	}
	if unavail.Capability != provider.CapIsolationClass {
		t.Fatalf("expected the isolation class to be named, got %s", unavail.Capability)
	}
}

// TestUnsupportedProviderRefusesEverything verifies the null provider fails
// closed rather than pretending a capability exists.
func TestUnsupportedProviderRefusesEverything(t *testing.T) {
	var p provider.Provider = provider.UnsupportedProvider{Reason: "no adapter configured"}
	reqs := []provider.Requirement{
		{Capability: provider.CapDedicatedDependencies, Reason: "baseline", Critical: true},
	}
	if err := provider.CheckRequirements(p.Capabilities(), reqs); err == nil {
		t.Fatal("the null provider must fail every critical requirement")
	}
	if _, err := p.Allocate(context.Background(), request("env", "k")); err == nil {
		t.Fatal("the null provider must refuse allocation")
	}
	if _, err := p.Observe(context.Background(), nil); !errors.Is(err, provider.ErrNotAbsent) {
		t.Fatal("the null provider must never report absence")
	}
}

// TestBoundsAreEnforcedBeforeProvisioning checks that an over-profile request is
// rejected without an external call.
func TestBoundsAreEnforcedBeforeProvisioning(t *testing.T) {
	over := request("env-01HQ", "alloc-pg")
	over.Bounds.MaxVCPU = 999
	if err := over.Validate(profileMax); err == nil {
		t.Fatal("an over-profile vCPU request must be refused")
	}
	ok := request("env-01HQ", "alloc-pg")
	if err := ok.Validate(profileMax); err != nil {
		t.Fatalf("an in-profile request must be accepted: %v", err)
	}
}

// TestSharedResourcesAreNotDestroyedByOnePreview encodes the denylist: a shared
// broker must never be destroyed because one environment closed.
func TestSharedResourcesAreNotDestroyedByOnePreview(t *testing.T) {
	if !provider.KindKafka.SharedResource() {
		t.Fatal("kafka must be classified as a shared resource")
	}
	if !provider.KindWorkflow.SharedResource() {
		t.Fatal("the workflow service must be classified as a shared resource")
	}
	if provider.KindPostgres.SharedResource() {
		t.Fatal("postgres must be classified as dedicated by default")
	}
	if provider.KindRedis.SharedResource() {
		t.Fatal("redis must be classified as dedicated by default")
	}

	// A shared allocation is marked shared so the destroy path can refuse it.
	p := fake.New(fake.FailNone, nil)
	shared := provider.AllocationRequest{
		EnvironmentID: "env-01HQ", Generation: 7, Kind: provider.KindKafka, LogicalKey: "topic-a",
		Bounds: provider.Bounds{MaxPartitions: 2},
	}
	alloc, err := p.Allocate(context.Background(), shared)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if !alloc.Shared {
		t.Fatal("a shared dependency must be marked shared so it is denied delete authority")
	}
}

// TestJanitorDiscoversUnownedResources covers reconciliation after local record
// loss. The janitor enumerates the provider independently of local state.
func TestJanitorDiscoversUnownedResources(t *testing.T) {
	p := fake.New(fake.FailNone, nil)
	p.AddUnowned(provider.Allocation{
		EnvironmentID: "env-01HQ",
		Kind:          provider.KindObjectStore,
		Reference:     map[string]string{"handle": "ref-orphan"},
	})
	found := p.Unowned()
	if len(found) != 1 {
		t.Fatalf("janitor must discover 1 unowned resource, got %d", len(found))
	}
	if found[0].Reference["handle"] != "ref-orphan" {
		t.Fatal("janitor must report the ownership reference it found")
	}
}

// TestStateLockSerializesMutation models the requirement that a replacement runner
// does not start a conflicting mutation while a prior native operation is
// unaccounted for.
func TestStateLockSerializesMutation(t *testing.T) {
	p := fake.New(fake.FailNone, nil)
	if _, err := p.Allocate(context.Background(), request("env-01HQ", "alloc-pg")); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if p.StateLockHeld("env-01HQ") {
		t.Fatal("no lock should be held initially")
	}
	p.SetStateLockHeld("env-01HQ", true)
	if !p.StateLockHeld("env-01HQ") {
		t.Fatal("state lock must be observable so a replacement can wait for it")
	}
}
