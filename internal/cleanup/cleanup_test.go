package cleanup_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/cleanup"
	"github.com/sanskarpan/Ghostlight/internal/resource"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// fakeProvider is a dependency that records what was done to it.
type fakeProvider struct {
	mu sync.Mutex

	revoked   []string
	destroyed []string
	// seq is a global ordering log, so two providers can be compared against each
	// other. Teardown correctness is a question about interleaving between kinds, not
	// about each one in isolation.
	seq *seqLog
	// revokeErr fails revocation.
	revokeErr error
	// destroyErr fails destruction, leaving the outcome uncertain.
	destroyErr error
	// stillPresent leaves the resource existing after a successful destroy, modelling
	// a provider that accepted the call but did not apply it.
	stillPresent bool
}

// seqLog is a shared ordering log.
type seqLog struct {
	mu sync.Mutex
	// entries is "id:op" in the order they happened.
	entries []string
}

func (s *seqLog) add(e string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
}

func (s *seqLog) indexOf(entry string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.entries {
		if e == entry {
			return i
		}
	}
	return -1
}

func (f *fakeProvider) Revoke(_ context.Context, a resource.Allocation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revoked = append(f.revoked, a.ID)
	f.seq.add("revoke:" + a.ID)
	return nil
}

func (f *fakeProvider) Destroy(_ context.Context, a resource.Allocation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.destroyErr != nil {
		return f.destroyErr
	}
	f.destroyed = append(f.destroyed, a.ID)
	f.seq.add("destroy:" + a.ID)
	return nil
}

func (f *fakeProvider) snapshot() ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...), append([]string(nil), f.destroyed...)
}

// revokedAt is the position of this provider's revocation in the shared log, or -1.
func (f *fakeProvider) revokedAt(id string) int { return f.seq.indexOf("revoke:" + id) }

// destroyedAt is the position of this provider's destruction in the shared log, or -1.
func (f *fakeProvider) destroyedAt(id string) int { return f.seq.indexOf("destroy:" + id) }

// harness wires a ledger, an authority issuer and a driver together.
type harness struct {
	ledger *resource.MemoryLedger
	issuer *resource.AuthorityIssuer
	driver *cleanup.Driver
	seq    *seqLog
	// mu guards pages, which several concurrent cleanup goroutines append to.
	mu    sync.Mutex
	pages []string
}

func newHarness(t *testing.T, providers map[string]cleanup.Depender, present map[string]bool) *harness {
	t.Helper()
	l := resource.NewMemoryLedger(func() time.Time { return now })
	i, err := resource.NewAuthorityIssuer(l, resource.NewDenylist("nat-foundation-001"), func() time.Time { return now })
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	// The observer reports absence for anything not in the present set.
	i.SetObserver(func(_ context.Context, ref map[string]string) (resource.Observation, error) {
		id := ref["native_id"]
		if present[id] {
			return resource.Observation{Exists: true, Detail: "still present"}, nil
		}
		return resource.Observation{Exists: false, Detail: "provider reports absent"}, nil
	})
	h := &harness{ledger: l, issuer: i, seq: &seqLog{}}
	d, err := cleanup.NewDriver(l, i, providers, func() time.Time { return now })
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	h.driver = d
	// Every provider shares one ordering log.
	for _, dep := range providers {
		if p, ok := dep.(*fakeProvider); ok {
			p.seq = h.seq
		}
	}
	d.SetPage(func(env, reason string) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.pages = append(h.pages, env+": "+reason)
	})
	return h
}

// pageCount is the number of escalations, read safely.
func (h *harness) pageCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.pages)
}

func alloc(id, env, kind, key string, shared bool) resource.Allocation {
	return resource.Allocation{
		ID: id, EnvironmentID: env, Generation: 3, Kind: kind, LogicalKey: key,
		ProviderRef: map[string]string{"native_id": "nat-" + id},
		IsShared:    shared, State: resource.StateActive, CreatedAt: now,
	}
}

// TestDriverRequiresTheLedgerAndIssuer: bypassing the issuer means deleting on trust.
func TestDriverRequiresTheLedgerAndIssuer(t *testing.T) {
	if _, err := cleanup.NewDriver(nil, nil, nil, nil); err == nil {
		t.Fatal("a driver must require the ledger")
	}
	if _, err := cleanup.NewDriver(resource.NewMemoryLedger(nil), nil, nil, nil); err == nil {
		t.Fatal("a driver must require the authority issuer")
	}
}

// TestFullCleanupVerifiesAbsence is the happy path, and the point of it is the final
// verification rather than the destroy call.
func TestFullCleanupVerifiesAbsence(t *testing.T) {
	p := &fakeProvider{}
	h := newHarness(t, map[string]cleanup.Depender{"database": p}, map[string]bool{})
	ctx := context.Background()
	if err := h.ledger.Record(ctx, alloc("db", "env-1", "database", "primary", false)); err != nil {
		t.Fatalf("record: %v", err)
	}

	res, err := h.driver.Cleanup(ctx, "env-1", 3, "cleanup")
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Phase != cleanup.PhaseDestroyed {
		t.Fatalf("cleanup must complete, got %+v", res)
	}
	if res.Revoked != 1 || res.Destroyed != 1 || res.Verified != 1 {
		t.Fatalf("every stage must run, got %+v", res)
	}

	got, err := h.ledger.ByID(ctx, "db")
	if err != nil {
		t.Fatalf("by id: %v", err)
	}
	if got.State != resource.StateVerifiedDeleted {
		t.Fatalf("the allocation must be tombstoned, got %s", got.State)
	}
	if got.DeletionProof == "" {
		t.Fatal("a verified deletion must carry proof of absence")
	}
}

// TestRevocationHappensBeforeDestruction is the ordering rule: credentials outlive the
// data they grant access to.
func TestRevocationHappensBeforeDestruction(t *testing.T) {
	p := &fakeProvider{}
	h := newHarness(t, map[string]cleanup.Depender{"database": p}, nil)
	ctx := context.Background()
	if err := h.ledger.Record(ctx, alloc("db", "env-1", "database", "primary", false)); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, err := h.driver.Cleanup(ctx, "env-1", 3, "cleanup"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	revoked, destroyed := p.snapshot()
	if len(revoked) != 1 || len(destroyed) != 1 {
		t.Fatalf("both stages must run, got %v / %v", revoked, destroyed)
	}
}

// TestDestructionIsRefusedWhenRevocationFailed is the failure that matters: destroying
// data whose access is still live is exactly what the ordering prevents.
func TestDestructionIsRefusedWhenRevocationFailed(t *testing.T) {
	p := &fakeProvider{revokeErr: errors.New("credential api unavailable")}
	h := newHarness(t, map[string]cleanup.Depender{"database": p}, nil)
	ctx := context.Background()
	if err := h.ledger.Record(ctx, alloc("db", "env-1", "database", "primary", false)); err != nil {
		t.Fatalf("record: %v", err)
	}

	res, err := h.driver.Cleanup(ctx, "env-1", 3, "cleanup")
	if err != nil {
		t.Fatalf("cleanup must surface the failure: %v", err)
	}
	if res.Revoked != 0 {
		t.Fatal("revocation did not succeed")
	}
	_, destroyed := p.snapshot()
	if len(destroyed) != 0 {
		t.Fatalf("nothing may be destroyed while its access is live, got %v", destroyed)
	}
	if res.Phase == cleanup.PhaseDestroyed {
		t.Fatal("a failed revocation must not be reported as destroyed")
	}
	if len(res.Pending) != 1 {
		t.Fatalf("the allocation must stay pending, got %+v", res.Pending)
	}
}

// TestASuccessfulDestroyIsNotProof is the core of verified cleanup: the provider can
// accept a call and not apply it.
func TestASuccessfulDestroyIsNotProof(t *testing.T) {
	p := &fakeProvider{}
	// The provider returns success but the resource is still there.
	h := newHarness(t, map[string]cleanup.Depender{"database": p}, map[string]bool{"nat-db": true})
	ctx := context.Background()
	if err := h.ledger.Record(ctx, alloc("db", "env-1", "database", "primary", false)); err != nil {
		t.Fatalf("record: %v", err)
	}

	res, err := h.driver.Cleanup(ctx, "env-1", 3, "cleanup")
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Destroyed != 1 {
		t.Fatal("the destroy call itself succeeded")
	}
	if res.Verified != 0 {
		t.Fatal("a resource that still exists may not be verified deleted")
	}
	if res.Phase != cleanup.PhaseVerifying {
		t.Fatalf("cleanup must remain verifying, got %s", res.Phase)
	}
	if len(res.Pending) != 1 || res.Pending[0] != "db" {
		t.Fatalf("the allocation must stay pending for re-verification, got %+v", res.Pending)
	}

	got, _ := h.ledger.ByID(ctx, "db")
	if got.State == resource.StateVerifiedDeleted {
		t.Fatal("the ledger must not tombstone an unverified deletion")
	}
}

// TestUncertainDestroyIsNotRetriedBlindly: the outcome is verified next pass rather
// than re-issued, because re-destroying a resource that already succeeded is how a
// shared resource is destroyed twice.
func TestUncertainDestroyIsNotRetriedBlindly(t *testing.T) {
	p := &fakeProvider{destroyErr: errors.New("gateway timeout after apply")}
	h := newHarness(t, map[string]cleanup.Depender{"database": p}, nil)
	ctx := context.Background()
	if err := h.ledger.Record(ctx, alloc("db", "env-1", "database", "primary", false)); err != nil {
		t.Fatalf("record: %v", err)
	}

	res, err := h.driver.Cleanup(ctx, "env-1", 3, "cleanup")
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(res.Pending) != 1 {
		t.Fatalf("an uncertain destroy must stay pending, got %+v", res)
	}
	if res.Skipped[0].Reason != cleanup.SkipDestroyUncertain {
		t.Fatalf("the skip must be classified as uncertain, got %q", res.Skipped[0].Reason)
	}
}

// TestSharedResourcesAreSkippedNotDestroyed: the driver must not even attempt them,
// and must record the exclusion so "destroyed" never means "we did not look".
func TestSharedResourcesAreSkippedNotDestroyed(t *testing.T) {
	p := &fakeProvider{}
	h := newHarness(t, map[string]cleanup.Depender{"database": p}, nil)
	ctx := context.Background()
	if err := h.ledger.Record(ctx, alloc("shared", "env-1", "database", "shared-primary", true)); err != nil {
		t.Fatalf("record: %v", err)
	}

	res, err := h.driver.Cleanup(ctx, "env-1", 3, "cleanup")
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, destroyed := p.snapshot(); len(destroyed) != 0 {
		t.Fatalf("a shared resource must never be destroyed, got %v", destroyed)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("the exclusion must be recorded, got %+v", res.Skipped)
	}
	if res.Skipped[0].Reason != cleanup.SkipShared {
		t.Fatalf("the skip must be classified as an intentional exclusion, got %q", res.Skipped[0].Reason)
	}
	if res.Skipped[0].Pageable() {
		t.Fatal("an intentional exclusion must not page an operator")
	}
	// Nothing this environment was responsible for remains, so it is clean. The shared
	// resource outliving it is correct: it was never this environment's to remove.
	if res.Phase != cleanup.PhaseDestroyed {
		t.Fatalf("a shared-only environment is fully cleaned, got %s", res.Phase)
	}
	if n := h.pageCount(); n != 0 {
		t.Fatalf("skipping a shared resource is not pageable, got %d pages", n)
	}
}

// TestFoundationResourceIsRefusedEvenWhenUnflagged ties the two layers together.
func TestFoundationResourceIsRefusedEvenWhenUnflagged(t *testing.T) {
	p := &fakeProvider{}
	h := newHarness(t, map[string]cleanup.Depender{"database": p}, nil)
	ctx := context.Background()

	a := alloc("db", "env-1", "database", "primary", false)
	a.ProviderRef = map[string]string{"native_id": "nat-foundation-001"}
	if err := h.ledger.Record(ctx, a); err != nil {
		t.Fatalf("record: %v", err)
	}

	res, err := h.driver.Cleanup(ctx, "env-1", 3, "cleanup")
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, destroyed := p.snapshot(); len(destroyed) != 0 {
		t.Fatalf("a denylisted foundation resource must not be destroyed, got %v", destroyed)
	}
	if len(res.Pending) != 1 {
		t.Fatalf("it must remain pending and visible, got %+v", res)
	}
}

// TestGenerationMismatchStopsDestruction.
func TestGenerationMismatchStopsDestruction(t *testing.T) {
	p := &fakeProvider{}
	h := newHarness(t, map[string]cleanup.Depender{"database": p}, nil)
	ctx := context.Background()
	if err := h.ledger.Record(ctx, alloc("db", "env-1", "database", "primary", false)); err != nil {
		t.Fatalf("record: %v", err)
	}
	// Cleanup is for generation 2, but the allocation belongs to generation 3.
	res, err := h.driver.Cleanup(ctx, "env-1", 2, "cleanup")
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, destroyed := p.snapshot(); len(destroyed) != 0 {
		t.Fatalf("a stale generation must not destroy, got %v", destroyed)
	}
	if len(res.Pending) != 1 {
		t.Fatalf("the allocation must stay pending, got %+v", res)
	}
}

// TestUnknownKindIsNotSilentlySkipped: no provider means nothing can remove it, which
// must be visible rather than counted as success.
func TestUnknownKindIsNotSilentlySkipped(t *testing.T) {
	p := &fakeProvider{}
	h := newHarness(t, map[string]cleanup.Depender{"database": p}, nil)
	ctx := context.Background()
	if err := h.ledger.Record(ctx, alloc("x", "env-1", "quantum_queue", "main", false)); err != nil {
		t.Fatalf("record: %v", err)
	}

	res, err := h.driver.Cleanup(ctx, "env-1", 3, "cleanup")
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Phase == cleanup.PhaseDestroyed {
		t.Fatal("an unremovable resource must not be reported as destroyed")
	}
	if len(res.Pending) != 1 {
		t.Fatalf("it must remain pending, got %+v", res)
	}
	if res.Skipped[0].Reason != cleanup.SkipRevokeFailed {
		t.Fatalf("a kind nothing can remove must surface at revocation, got %q", res.Skipped[0].Reason)
	}
	// The classification is what decides whether to page, so it must be a real gap
	// rather than an intentional exclusion.
	if !res.Skipped[0].Pageable() {
		t.Fatalf("a missing provider is a real gap and must be pageable, got %+v", res.Skipped[0])
	}
	if !strings.Contains(res.Skipped[0].Detail, "no provider is registered") {
		t.Fatalf("the detail must explain the gap, got %q", res.Skipped[0].Detail)
	}
	if h.pageCount() == 0 {
		t.Fatal("a kind nothing can remove must page an operator")
	}
}

// TestAnEnvironmentWithNothingAllocatedIsAlreadyClean avoids a pointless verification
// loop.
func TestAnEnvironmentWithNothingAllocatedIsAlreadyClean(t *testing.T) {
	h := newHarness(t, map[string]cleanup.Depender{}, nil)
	res, err := h.driver.Cleanup(context.Background(), "env-empty", 1, "cleanup")
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Phase != cleanup.PhaseDestroyed || !res.Clean() {
		t.Fatalf("nothing to remove is already destroyed, got %+v", res)
	}
}

// TestDestroyOrderIsDependencySafe pins the sequence the spec fixes: workload access
// before data, and bindings before the namespace disappears.
func TestDestroyOrderIsDependencySafe(t *testing.T) {
	workload := &fakeProvider{}
	binding := &fakeProvider{}
	providers := map[string]cleanup.Depender{"identity": binding, "database": workload}
	h := newHarness(t, providers, nil)
	ctx := context.Background()

	// Record deliberately out of order; the driver must impose the correct one.
	for _, a := range []resource.Allocation{
		alloc("db", "env-1", "database", "primary", false),
		alloc("id", "env-1", "identity", "workload", false),
	} {
		if err := h.ledger.Record(ctx, a); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	if _, err := h.driver.Cleanup(ctx, "env-1", 3, "cleanup"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	// Identities are destroyed after the databases they grant access to, because
	// removing the identity first would break the very access the destruction needs.
	if binding.destroyedAt("id") < 0 || workload.destroyedAt("db") < 0 {
		t.Fatal("both kinds must be destroyed")
	}
	if workload.destroyedAt("db") > binding.destroyedAt("id") {
		t.Fatalf("the database must be destroyed before the identity binding; seq was %+v", h.seq.entries)
	}
}

// TestRevocationOrderRemovesAccessBeforeData is the other half of the ordering rule.
func TestRevocationOrderRemovesAccessBeforeData(t *testing.T) {
	workload := &fakeProvider{}
	binding := &fakeProvider{}
	h := newHarness(t, map[string]cleanup.Depender{"identity": binding, "database": workload}, nil)
	ctx := context.Background()

	for _, a := range []resource.Allocation{
		alloc("db", "env-1", "database", "primary", false),
		alloc("id", "env-1", "identity", "workload", false),
	} {
		if err := h.ledger.Record(ctx, a); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	if _, err := h.driver.Cleanup(ctx, "env-1", 3, "cleanup"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	// Workload identity access is revoked before the data it reaches is revoked, so
	// the workload loses access first.
	if binding.revokedAt("id") < 0 || workload.revokedAt("db") < 0 {
		t.Fatal("both credentials must be revoked")
	}
	if binding.revokedAt("id") > workload.revokedAt("db") {
		t.Fatalf("identity access must be revoked before the database it reaches; seq was %+v", h.seq.entries)
	}
}

// TestOneStuckResourceDoesNotBlockTheOthers: a single pending allocation must not
// prevent every other resource from being reclaimed.
func TestOneStuckResourceDoesNotBlockTheOthers(t *testing.T) {
	db := &fakeProvider{}
	stuck := &fakeProvider{stillPresent: true}
	h := newHarness(t, map[string]cleanup.Depender{
		"database": db, "quantum_queue": stuck,
	}, map[string]bool{"nat-stuck": true})
	ctx := context.Background()

	for _, a := range []resource.Allocation{
		alloc("db", "env-1", "database", "primary", false),
		alloc("stuck", "env-1", "quantum_queue", "main", false),
	} {
		if err := h.ledger.Record(ctx, a); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	res, err := h.driver.Cleanup(ctx, "env-1", 3, "cleanup")
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Verified != 1 {
		t.Fatalf("the healthy resource must still be verified, got %+v", res)
	}
	if len(res.Pending) != 1 || res.Pending[0] != "stuck" {
		t.Fatalf("only the stuck resource may remain pending, got %+v", res.Pending)
	}
	if res.Phase != cleanup.PhaseVerifying {
		t.Fatalf("the environment must remain verifying, got %s", res.Phase)
	}
}

// TestConcurrentCleanupRunsAreConsistent: several controllers must not double-destroy.
func TestConcurrentCleanupRunsAreConsistent(t *testing.T) {
	p := &fakeProvider{}
	h := newHarness(t, map[string]cleanup.Depender{"database": p}, nil)
	ctx := context.Background()
	if err := h.ledger.Record(ctx, alloc("db", "env-1", "database", "primary", false)); err != nil {
		t.Fatalf("record: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.driver.Cleanup(ctx, "env-1", 3, "cleanup")
		}()
	}
	wg.Wait()

	got, err := h.ledger.ByID(ctx, "db")
	if err != nil {
		t.Fatalf("by id: %v", err)
	}
	if got.State != resource.StateVerifiedDeleted {
		t.Fatalf("the allocation must end tombstoned, got %s", got.State)
	}
}

// TestBackoffIsBounded keeps a failed verification from hammering the provider.
func TestBackoffIsBounded(t *testing.T) {
	if d := cleanup.NextVerification(0); d != 0 {
		t.Fatalf("a first attempt should be immediate, got %v", d)
	}
	if cleanup.NextVerification(1) <= 0 || cleanup.NextVerification(2) <= 0 {
		t.Fatal("retries must back off")
	}
	if cleanup.NextVerification(99) > 15*time.Minute {
		t.Fatal("backoff must be bounded, or a stuck resource is polled forever")
	}
	if cleanup.NextVerification(5) <= cleanup.NextVerification(1) {
		t.Fatal("backoff must increase")
	}
}

// TestPhasesAreDistinct keeps the honest answer distinguishable from a finished one.
func TestPhasesAreDistinct(t *testing.T) {
	seen := map[cleanup.Phase]bool{}
	for _, p := range []cleanup.Phase{
		cleanup.PhaseRunning, cleanup.PhaseRevoking, cleanup.PhaseDestroying,
		cleanup.PhaseVerifying, cleanup.PhaseDestroyed, cleanup.PhasePreserved,
	} {
		if p == "" {
			t.Fatal("a phase must be named")
		}
		if seen[p] {
			t.Fatalf("phase %s is duplicated", p)
		}
		seen[p] = true
	}
	if (cleanup.Result{Phase: cleanup.PhaseVerifying}).Clean() {
		t.Fatal("verifying is not clean")
	}
	if !(cleanup.Result{Phase: cleanup.PhaseDestroyed}).Clean() {
		t.Fatal("destroyed is clean")
	}
	if (cleanup.Result{Phase: cleanup.PhasePreserved}).Clean() {
		t.Fatal("preserved is not clean; state still exists")
	}
}

// TestPreservedStateIsNeverReportedDestroyed is SPEC.md's failure-table rule: "preserve
// state/inventory and page; do not report destroyed." A resource that could not be
// removed must escalate, and the environment must not be called clean.
func TestPreservedStateIsNeverReportedDestroyed(t *testing.T) {
	// A foundation resource recorded as unshared is denied by the denylist, so it can
	// never be removed: state must be preserved and a person paged.
	p := &fakeProvider{}
	h := newHarness(t, map[string]cleanup.Depender{"database": p}, nil)
	ctx := context.Background()

	a := alloc("f", "env-1", "database", "primary", false)
	a.ProviderRef = map[string]string{"native_id": "nat-foundation-001"}
	if err := h.ledger.Record(ctx, a); err != nil {
		t.Fatalf("record: %v", err)
	}

	res, err := h.driver.Cleanup(ctx, "env-1", 3, "cleanup")
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Clean() {
		t.Fatalf("state that could not be removed must not be reported destroyed: %+v", res)
	}
	if res.Phase != cleanup.PhaseVerifying {
		t.Fatalf("it must remain verifying, got %s", res.Phase)
	}
	if h.pageCount() == 0 {
		t.Fatal("an unremovable resource must page an operator rather than wait to be noticed")
	}
}
