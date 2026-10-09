package gate_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/cleanup"
	"github.com/sanskarpan/Ghostlight/internal/janitor"
	"github.com/sanskarpan/Ghostlight/internal/provider"
	"github.com/sanskarpan/Ghostlight/internal/resource"

	"github.com/sanskarpan/Ghostlight/test/fake"
	"github.com/sanskarpan/Ghostlight/test/gate"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// world is a full platform slice: a faked provider, a resource ledger, a cleanup driver
// and a janitor, all wired the way production wires them.
type world struct {
	t *testing.T

	provider *fake.Fake
	ledger   *resource.MemoryLedger
	issuer   *resource.AuthorityIssuer
	driver   *cleanup.Driver
	janitor  *janitor.Janitor

	// dependers adapts the fake provider to the cleanup driver.
	dependers  map[string]cleanup.Depender
	quarantine *quarantineSink
	seen       *seenStore
	mu         sync.Mutex
}

// quarantineSink records what the janitor refused to delete.
type quarantineSink struct {
	mu  sync.Mutex
	ids []string
}

func (q *quarantineSink) Quarantine(_ context.Context, d janitor.Discovered, _ string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.ids = append(q.ids, envKeyOf(d.NativeID))
	return nil
}

func (q *quarantineSink) list() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]string(nil), q.ids...)
}

// seenStore persists sighting history for the janitor.
type seenStore struct {
	mu     sync.Mutex
	counts map[string]int
}

func (s *seenStore) Count(_ context.Context, id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[id], nil
}

func (s *seenStore) Remember(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[id]++
	return nil
}

func (s *seenStore) Forget(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.counts, id)
	return nil
}

// envKeyOf turns a fake handle into "<environment>/<logicalKey>".
func envKeyOf(handle string) string {
	if i := indexOfSlash(handle); i >= 0 {
		return handle[i+1:]
	}
	return handle
}

func indexOfSlash(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}

// fakeDepender adapts the faked provider to the cleanup driver's Depender.
type fakeDepender struct {
	p    *fake.Fake
	kind string
}

func (d fakeDepender) Revoke(ctx context.Context, a resource.Allocation) error {
	return d.p.Revoke(ctx, provider.Allocation{
		EnvironmentID: a.EnvironmentID, Kind: provider.DependencyKind(d.kind),
		Reference: a.ProviderRef, CredentialRef: a.CredentialRef,
	})
}

func (d fakeDepender) Destroy(ctx context.Context, a resource.Allocation) error {
	return d.p.Destroy(ctx, provider.Allocation{
		EnvironmentID: a.EnvironmentID, Kind: provider.DependencyKind(d.kind),
		Reference: a.ProviderRef,
	})
}

// newWorld builds a consistent platform slice.
func newWorld(t *testing.T, mode fake.FailureMode) *world {
	t.Helper()
	w := &world{t: t, seen: &seenStore{counts: map[string]int{}}, quarantine: &quarantineSink{}}

	w.provider = fake.New(mode, map[provider.Capability]bool{
		provider.CapOwnershipTags: true,
	})
	w.ledger = resource.NewMemoryLedger(func() time.Time { return now })

	issuer, err := resource.NewAuthorityIssuer(w.ledger, resource.NewDenylist(), func() time.Time { return now })
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	w.issuer = issuer
	// Observe through the faked provider, which is the only source of truth about what
	// actually exists.
	issuer.SetObserver(func(ctx context.Context, ref map[string]string) (resource.Observation, error) {
		obs, err := w.provider.Observe(ctx, ref)
		if err != nil {
			return resource.Observation{}, err
		}
		detail := "provider reports absent"
		if obs.Present {
			detail = "provider reports present"
		}
		return resource.Observation{Exists: obs.Present, Detail: detail}, nil
	})

	w.dependers = map[string]cleanup.Depender{"database": fakeDepender{p: w.provider, kind: "database"}}
	driver, err := cleanup.NewDriver(w.ledger, issuer, w.dependers, func() time.Time { return now })
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	w.driver = driver

	// The janitor drives teardown through a function seam rather than importing the
	// cleanup package, so neither package depends on the other's result type. This is
	// the documented integration point.
	retry := janitor.RetryableFunc(func(ctx context.Context, envID string, gen uint64, actor string) (janitor.PhaseResult, error) {
		res, err := driver.Cleanup(ctx, envID, gen, actor)
		if err != nil {
			return janitor.PhaseResult{}, err
		}
		return janitor.PhaseResult{Phase: string(res.Phase), Pending: res.Pending}, nil
	})
	j, err := janitor.New(w, w.ledger, retry, w.quarantine, janitor.Config{
		TagKey: "ghostlight.io/environment", QuarantineAfter: 1, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("janitor: %v", err)
	}
	j.SetSeen(w.seen)
	w.janitor = j
	return w
}

// Discover implements the janitor's Discovery over the faked provider.
func (w *world) Discover(_ context.Context, limit int) ([]janitor.Discovered, error) {
	var out []janitor.Discovered
	for _, a := range w.provider.Unowned() {
		env, ok := a.Reference["environment_id"]
		if !ok || env == "" {
			env = "env-orphan"
		}
		out = append(out, janitor.Discovered{
			NativeID:  a.Reference["native_id"],
			Kind:      string(a.Kind),
			OwnerTags: map[string]string{"ghostlight.io/environment": env},
			CreatedAt: now,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NativeID < out[j].NativeID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// allocate creates a provider resource and records it, the way the reconcile loop does.
func (w *world) allocate(envID, logicalKey string) (resource.Allocation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	a, err := w.provider.Allocate(context.Background(), provider.AllocationRequest{
		EnvironmentID: envID, Kind: "database", LogicalKey: logicalKey,
	})
	if err != nil {
		return resource.Allocation{}, err
	}
	rec := resource.Allocation{
		ID:                    "alloc-" + envID + "-" + logicalKey,
		EnvironmentID:         envID,
		Generation:            2,
		Kind:                  string(a.Kind),
		LogicalKey:            logicalKey,
		ProviderRef:           map[string]string{"handle": a.Reference["handle"], "environment_id": envID},
		CredentialRef:         a.CredentialRef,
		SupportsOwnershipTags: a.SupportsOwnershipTags,
		State:                 resource.StateActive,
		CreatedAt:             now,
	}
	if err := w.ledger.Record(context.Background(), rec); err != nil {
		return resource.Allocation{}, err
	}
	return rec, nil
}

// state reads everything back for the gate's comparison.
func (w *world) state() gate.State {
	w.mu.Lock()
	defer w.mu.Unlock()

	st := gate.State{
		ProviderResources: w.provider.Live(),
		Quarantined:       w.quarantine.list(),
	}
	for _, a := range w.ledger.All() {
		st.LedgerAllocs = append(st.LedgerAllocs, a)
	}
	sort.Slice(st.LedgerAllocs, func(i, j int) bool { return st.LedgerAllocs[i].ID < st.LedgerAllocs[j].ID })
	return st
}

// assertClean is the gate's own assertion.
func (w *world) assertClean(t *testing.T, ref *gate.Reference, scenario string) {
	t.Helper()
	if err := gate.CheckAll(ref, w.state()); err != nil {
		t.Fatalf("%s:\n%v", scenario, err)
	}
}

// ---------------------------------------------------------------------------
// Scenario: duplicate
// ---------------------------------------------------------------------------

// TestDuplicateDeliveryCreatesOneResource is the duplicate half of the gate.
//
// A webhook redelivered must not create a second database. It also must not be
// swallowed: the second delivery has to be recognized as the same event.
func TestDuplicateDeliveryCreatesOneResource(t *testing.T) {
	w := newWorld(t, fake.FailNone)
	ref := gate.NewReference()
	ref.Expect("primary")

	first, err := w.allocate("env-1", "primary")
	if err != nil {
		t.Fatalf("first allocation: %v", err)
	}

	// The duplicate delivery arrives. Recording it again must be rejected by the
	// ledger's uniqueness constraint rather than creating a second resource.
	dup := resource.Allocation{
		ID: "alloc-env-1-primary-dup", EnvironmentID: "env-1", Generation: 2,
		Kind: "database", LogicalKey: "primary",
		ProviderRef: map[string]string{"native_id": "different", "environment_id": "env-1"},
		State:       resource.StateActive, CreatedAt: now,
	}
	if err := w.ledger.Record(context.Background(), dup); err == nil {
		t.Fatal("a duplicate logical key must be refused by the ledger")
	}
	// And the provider must still hold exactly one.
	if w.provider.Count() != 1 {
		t.Fatalf("a duplicate delivery created %d resources, want 1", w.provider.Count())
	}
	_ = first
	w.assertClean(t, ref, "duplicate delivery")
}

// TestConcurrentDuplicateDeliveriesCreateOneResource is the same property under
// concurrency, which is where a read-then-write uniqueness check would fail.
func TestConcurrentDuplicateDeliveriesCreateOneResource(t *testing.T) {
	w := newWorld(t, fake.FailNone)
	ref := gate.NewReference()
	ref.Expect("primary")

	if _, err := w.allocate("env-1", "primary"); err != nil {
		t.Fatalf("first: %v", err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var accepted int
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			dup := resource.Allocation{
				ID: fmt.Sprintf("dup-%d", i), EnvironmentID: "env-1", Generation: 2,
				Kind: "database", LogicalKey: "primary",
				ProviderRef: map[string]string{"native_id": fmt.Sprintf("other-%d", i), "environment_id": "env-1"},
				State:       resource.StateActive, CreatedAt: now,
			}
			if err := w.ledger.Record(context.Background(), dup); err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if accepted != 0 {
		t.Fatalf("%d concurrent duplicates were accepted", accepted)
	}
	w.assertClean(t, ref, "concurrent duplicate deliveries")
}

// ---------------------------------------------------------------------------
// Scenario: reorder
// ---------------------------------------------------------------------------

// TestReorderedEventsConvergeOnTheSameState checks that arriving out of order does not
// leave the platform disagreeing with reality.
func TestReorderedEventsConvergeOnTheSameState(t *testing.T) {
	w := newWorld(t, fake.FailNone)
	ref := gate.NewReference()
	ref.Expect("primary")

	if _, err := w.allocate("env-1", "primary"); err != nil {
		t.Fatalf("allocate: %v", err)
	}

	// An older generation's event arrives after a newer one. The ledger must refuse it
	// rather than rolling the record back: the newer generation owns the resource, and
	// accepting the older one would let a delayed webhook authorize cleanup of
	// something a later generation replaced.
	stale := resource.Allocation{
		ID: "alloc-env-1-primary", EnvironmentID: "env-1", Generation: 1,
		Kind: "database", LogicalKey: "primary",
		ProviderRef: map[string]string{"native_id": "nat-stale", "environment_id": "env-1"},
		State:       resource.StateActive, CreatedAt: now,
	}
	err := w.ledger.Record(context.Background(), stale)
	if !errors.Is(err, resource.ErrGenerationMismatch) {
		t.Fatalf("an out-of-order event must be refused, got %v", err)
	}
	got, err := w.ledger.ByID(context.Background(), "alloc-env-1-primary")
	if err != nil {
		t.Fatalf("by id: %v", err)
	}
	if got.Generation != 2 {
		t.Fatalf("a reordered event moved the generation back to %d", got.Generation)
	}
	w.assertClean(t, ref, "reordered events")
}

// TestGenerationFenceBlocksStaleCleanup: a teardown authorized for an older generation
// must not remove what a newer one created.
func TestGenerationFenceBlocksStaleCleanup(t *testing.T) {
	w := newWorld(t, fake.FailNone)
	ref := gate.NewReference()
	ref.Expect("primary")

	if _, err := w.allocate("env-1", "primary"); err != nil {
		t.Fatalf("allocate: %v", err)
	}

	// An old cleanup pass runs against generation 1 while the allocation is generation 2.
	res, err := w.driver.Cleanup(context.Background(), "env-1", 1, "stale-cleanup")
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Clean() {
		t.Fatal("a stale generation must not report a clean cleanup")
	}
	if w.provider.Count() != 1 {
		t.Fatalf("a stale cleanup removed a resource: %d left", w.provider.Count())
	}
	w.assertClean(t, ref, "stale generation cleanup")
}

// ---------------------------------------------------------------------------
// Scenario: crash
// ---------------------------------------------------------------------------

// TestCrashBeforeLedgerWriteIsQuarantinedNotDeleted is the crash half of the gate, and
// the most important test in this file.
//
// The provider created the resource, then the process died before the ledger recorded
// it. The resource is real and it is a genuine leak. The tempting response is to delete
// it, because it is unowned and untracked. Deleting it would be exactly the wrong move:
// nothing proves it is ours, and the ledger cannot produce delete authority for it.
func TestCrashBeforeLedgerWriteIsQuarantinedNotDeleted(t *testing.T) {
	w := newWorld(t, fake.FailNone)
	ref := gate.NewReference()

	// The provider created it. Nothing in the ledger knows.
	orphan := provider.Allocation{
		EnvironmentID: "env-1", Kind: "database",
		Reference:     map[string]string{"native_id": "nat-orphan", "environment_id": "env-1"},
		CredentialRef: "secret://orphan",
	}
	w.provider.AddUnowned(orphan)
	before := w.provider.Count()

	res, err := w.janitor.Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("janitor: %v", err)
	}
	if len(res.Quarantined) != 1 {
		t.Fatalf("the orphan must be quarantined, got %+v", res)
	}
	if res.Clean() {
		t.Fatal("a pass that quarantined a resource is not clean")
	}
	if w.provider.Count() != before {
		t.Fatalf("the janitor deleted an unowned resource: %d -> %d", before, w.provider.Count())
	}
	// The model expects nothing, and the resource is tracked by quarantine, so this
	// satisfies the gate: nothing is silently unaccounted for.
	w.assertClean(t, ref, "crash before ledger write")
}

// TestCrashAfterDestroyBeforeVerificationLeavesNoResurrection: the resource is gone, the
// tombstone is written, and a later pass must not recreate it.
func TestCrashAfterDestroyBeforeVerificationLeavesNoResurrection(t *testing.T) {
	w := newWorld(t, fake.FailNone)
	ref := gate.NewReference()

	a, err := w.allocate("env-1", "primary")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	ref.Destroy("primary")

	// Cleanup runs, but the provider's observe is unavailable, so deletion cannot be
	// verified. The environment must stay verifying.
	w.provider.WithObserveMode(fake.FailObserve)
	res, err := w.driver.Cleanup(context.Background(), "env-1", 2, "cleanup")
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Clean() {
		t.Fatal("unverifiable deletion must not be reported as clean")
	}

	// A later pass, once observation works again, completes the tombstone.
	w.provider = fake.New(fake.FailNone, map[provider.Capability]bool{provider.CapOwnershipTags: true})
	// The provider was reset, so the resource no longer exists.
	obs, err := w.issuer.Observe(context.Background(), resource.Authority{
		EnvironmentID: a.EnvironmentID, Generation: a.Generation,
		AllocationID: a.ID, ProviderRef: a.ProviderRef,
	})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if obs.Exists {
		t.Fatal("the resource should be absent after teardown")
	}
	if err := w.ledger.MarkDeleted(context.Background(), a.ID, obs); err != nil {
		t.Fatalf("mark deleted: %v", err)
	}

	// The janitor runs again. The provider holds nothing, so nothing resurrects.
	jres, err := w.janitor.Run(context.Background(), 100)
	if err != nil {
		t.Fatalf("janitor: %v", err)
	}
	if len(jres.Quarantined) != 0 {
		t.Fatalf("nothing should need quarantining, got %+v", jres.Quarantined)
	}
	w.assertClean(t, ref, "crash after destroy")
}

// TestATombstonedResourceCannotBeRecreated is the resurrection property directly.
func TestATombstonedResourceCannotBeRecreated(t *testing.T) {
	w := newWorld(t, fake.FailNone)
	ref := gate.NewReference()

	a, err := w.allocate("env-1", "primary")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	ctx := context.Background()
	// Teardown genuinely removes it from the provider, then the tombstone is written.
	// Tombstoning without removing would be a lie the gate is right to reject.
	if err := w.provider.Revoke(ctx, provider.Allocation{
		EnvironmentID: "env-1", Kind: "database", Reference: a.ProviderRef,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := w.provider.Destroy(ctx, provider.Allocation{
		EnvironmentID: "env-1", Kind: "database", Reference: a.ProviderRef,
	}); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if err := w.ledger.MarkRevoked(ctx, a.ID, "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := w.ledger.MarkDeleted(ctx, a.ID, resource.Observation{Exists: false, Detail: "absent"}); err != nil {
		t.Fatalf("mark: %v", err)
	}
	ref.Destroy("primary")

	// A late delivery recreates the same logical key.
	late := resource.Allocation{
		ID: a.ID, EnvironmentID: "env-1", Generation: 3,
		Kind: "database", LogicalKey: "primary",
		ProviderRef: map[string]string{"native_id": "nat-again", "environment_id": "env-1"},
		State:       resource.StateActive, CreatedAt: now,
	}
	err = w.ledger.Record(ctx, late)
	if !errors.Is(err, resource.ErrAlreadyDeleted) {
		t.Fatalf("a tombstoned allocation must not be recreated, got %v", err)
	}
	w.assertClean(t, ref, "tombstone resurrection")
}

// ---------------------------------------------------------------------------
// Scenario: timeout
// ---------------------------------------------------------------------------

// TestTimeoutAfterCreateIsResolvedByObservationNotRecreation is the timeout half.
//
// SPEC.md: "A timeout after possible external success becomes uncertain and triggers
// observation by stable ownership/name, not unconditional recreation." Recreating on a
// timeout is how a preview ends up with two databases.
func TestTimeoutAfterCreateIsResolvedByObservationNotRecreation(t *testing.T) {
	w := newWorld(t, fake.FailNone)
	ref := gate.NewReference()
	ref.Expect("primary")

	// The create actually applied, then the response was lost.
	w.provider = fake.New(fake.FailAfterCreateBeforeResponse, map[provider.Capability]bool{
		provider.CapOwnershipTags: true,
	})
	w.issuer.SetObserver(func(ctx context.Context, ref map[string]string) (resource.Observation, error) {
		obs, err := w.provider.Observe(ctx, ref)
		if err != nil {
			return resource.Observation{}, err
		}
		detail := "provider reports absent"
		if obs.Present {
			detail = "provider reports present"
		}
		return resource.Observation{Exists: obs.Present, Detail: detail}, nil
	})

	if _, err := w.allocate("env-1", "primary"); err == nil {
		t.Fatal("the allocation must report the timeout as an error")
	}

	// The resource does exist despite the error, and the model expects exactly one.
	if w.provider.Count() != 1 {
		t.Fatalf("expected the create to have applied, provider holds %d", w.provider.Count())
	}

	// The reconcile loop records the allocation row before observing, then adopts the
	// existing resource rather than creating a second one.
	handle := w.provider.HandleFor("primary", 0)
	if handle == "" {
		t.Fatal("the create produced no handle, so the timeout scenario is not modelled")
	}
	if err := w.ledger.Record(context.Background(), resource.Allocation{
		ID: "alloc-env-1-primary", EnvironmentID: "env-1", Generation: 2,
		Kind: "database", LogicalKey: "primary",
		ProviderRef: map[string]string{"handle": handle, "environment_id": "env-1"},
		State:       resource.StateActive, CreatedAt: now,
	}); err != nil {
		t.Fatalf("record the allocation row: %v", err)
	}

	// Observation resolves it. Critically, no recreation happens, so still one.
	res, err := w.issuer.Observe(context.Background(), resource.Authority{
		EnvironmentID: "env-1", Generation: 2, AllocationID: "alloc-env-1-primary",
		ProviderRef: map[string]string{"handle": handle, "environment_id": "env-1"},
	})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if !res.Exists {
		t.Fatal("observation must find the resource that the timeout hid")
	}
	// Still exactly one: the timeout did not lead to a second create.
	if w.provider.Count() != 1 {
		t.Fatalf("a timeout led to recreation: %d resources", w.provider.Count())
	}
	w.assertClean(t, ref, "timeout after create")
}

// TestPermissionFailureIsNotAbsence: SPEC.md is explicit, and mistaking one for the
// other is how a live resource gets "cleaned".
func TestPermissionFailureIsNotAbsence(t *testing.T) {
	w := newWorld(t, fake.FailNone)
	ref := gate.NewReference()
	ref.Expect("primary")

	if _, err := w.allocate("env-1", "primary"); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	// The provider refuses to be observed.
	w.provider.WithObserveMode(fake.FailObserve)

	_, err := w.issuer.Observe(context.Background(), resource.Authority{
		EnvironmentID: "env-1", Generation: 2, AllocationID: "alloc-env-1-primary",
		ProviderRef: map[string]string{"native_id": "nat-primary", "environment_id": "env-1"},
	})
	if err == nil {
		t.Fatal("a permission failure must not be reported as absence")
	}
	if !errors.Is(err, provider.ErrNotAbsent) {
		t.Fatalf("the error must be the provider's explicit not-absent, got %v", err)
	}
	// The resource still exists, and the model expects it, so the gate holds.
	if w.provider.Count() != 1 {
		t.Fatal("a permission failure must not remove anything")
	}
	w.assertClean(t, ref, "permission failure")
}

// ---------------------------------------------------------------------------
// Combined
// ---------------------------------------------------------------------------

// TestASequenceOfEveryFailureModeLeavesNoLeakAndNoResurrection is the gate's headline
// claim, run as one continuous history rather than as isolated cases.
//
// Isolated tests prove each property separately. What they cannot prove is that the
// properties hold together — that the crash does not undermine the duplicate rule, that
// the timeout does not undermine the tombstone. Running them as one history is what
// makes the gate a gate.
func TestASequenceOfEveryFailureModeLeavesNoLeakAndNoResurrection(t *testing.T) {
	w := newWorld(t, fake.FailNone)
	ref := gate.NewReference()
	ctx := context.Background()

	// 1. A normal environment comes up.
	ref.Expect("primary")
	a, err := w.allocate("env-1", "primary")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	w.assertClean(t, w.refExpecting(t, "primary"), "1. normal provisioning")

	// 2. Duplicate delivery for the same key.
	dup := resource.Allocation{
		ID: "dup", EnvironmentID: "env-1", Generation: 2, Kind: "database", LogicalKey: "primary",
		ProviderRef: map[string]string{"native_id": "nat-dup", "environment_id": "env-1"},
		State:       resource.StateActive, CreatedAt: now,
	}
	if err := w.ledger.Record(ctx, dup); err == nil {
		t.Fatal("a duplicate must be refused")
	}
	w.assertClean(t, w.refExpecting(t, "primary"), "2. after duplicate")

	// 3. A crash leaves an orphan the ledger never learned about.
	w.provider.AddUnowned(provider.Allocation{
		EnvironmentID: "env-1", Kind: "database",
		Reference: map[string]string{"native_id": "nat-orphan", "environment_id": "env-1"},
	})
	orphansBefore := w.provider.Count()
	jres, err := w.janitor.Run(ctx, 100)
	if err != nil {
		t.Fatalf("janitor: %v", err)
	}
	if len(jres.Quarantined) != 1 {
		t.Fatalf("the orphan must be quarantined, got %+v", jres)
	}
	if w.provider.Count() != orphansBefore {
		t.Fatal("the janitor deleted the orphan; that is the failure this gate exists to prevent")
	}

	// 4. A reordered event from an older generation must not roll state back.
	stale := resource.Allocation{
		ID: a.ID, EnvironmentID: "env-1", Generation: 1, Kind: "database", LogicalKey: "primary",
		ProviderRef: a.ProviderRef, State: resource.StateActive, CreatedAt: now,
	}
	if err := w.ledger.Record(ctx, stale); !errors.Is(err, resource.ErrGenerationMismatch) {
		t.Fatalf("an out-of-order event must be refused, got %v", err)
	}
	got, err := w.ledger.ByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("by id: %v", err)
	}
	if got.Generation != 2 {
		t.Fatalf("a reordered event rolled the generation to %d", got.Generation)
	}

	// 5. Real teardown runs: revoke, destroy, verify, tombstone.
	ref.Destroy("primary")
	cres, err := w.driver.Cleanup(ctx, "env-1", a.Generation, "cleanup")
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if !cres.Clean() {
		t.Fatalf("a clean teardown must report clean, got %+v", cres)
	}
	if w.provider.Count() != 0 {
		t.Fatalf("teardown left %d resources in the provider", w.provider.Count())
	}

	// 6. A late delivery tries to resurrect it.
	late := resource.Allocation{
		ID: a.ID, EnvironmentID: "env-1", Generation: 3, Kind: "database", LogicalKey: "primary",
		ProviderRef: map[string]string{"native_id": "nat-again", "environment_id": "env-1"},
		State:       resource.StateActive, CreatedAt: now,
	}
	if err := w.ledger.Record(ctx, late); !errors.Is(err, resource.ErrAlreadyDeleted) {
		t.Fatalf("a tombstoned id must not be recreated, got %v", err)
	}

	// The whole history, checked in one go against a model that expects nothing left.
	w.assertClean(t, ref, "full failure-mode sequence")
}

// refExpecting is a small helper for the intermediate assertions.
func (w *world) refExpecting(t *testing.T, key string) *gate.Reference {
	t.Helper()
	r := gate.NewReference()
	r.Expect(key)
	return r
}

// TestTheGateItselfDetectsViolations is the negative control.
//
// A gate that cannot fail is not a gate. Each of these deliberately breaks an invariant
// and requires the checker to notice.
func TestTheGateItselfDetectsViolations(t *testing.T) {
	cases := []struct {
		name  string
		ref   func() *gate.Reference
		state gate.State
		want  gate.Invariant
	}{
		{
			name: "unexpected untracked survivor",
			ref:  gate.NewReference,
			state: gate.State{
				ProviderResources: []string{"env-1/rogue"},
			},
			want: gate.InvNoUnownedSurvivor,
		},
		{
			name: "resurrected tombstone",
			ref: func() *gate.Reference {
				r := gate.NewReference()
				r.Destroy("primary")
				return r
			},
			state: gate.State{ProviderResources: []string{"env-1/primary"}},
			want:  gate.InvNoResurrection,
		},
		{
			name: "duplicate create",
			ref: func() *gate.Reference {
				r := gate.NewReference()
				r.Expect("primary")
				return r
			},
			state: gate.State{ProviderResources: []string{"env-1/primary", "env-2/primary"}},
			want:  gate.InvNoDuplicateCreate,
		},
		{
			name: "missing expected resource",
			ref: func() *gate.Reference {
				r := gate.NewReference()
				r.Expect("primary")
				return r
			},
			state: gate.State{},
			want:  gate.InvNoUnownedSurvivor,
		},
		{
			name: "wrongful deletion",
			ref: func() *gate.Reference {
				r := gate.NewReference()
				r.Expect("primary")
				return r
			},
			state: gate.State{
				ProviderResources: []string{"env-1/primary"},
				Deleted:           []string{"env-1/primary"},
			},
			want: gate.InvNoWrongfulDeletion,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			violations := gate.Check(tc.ref(), tc.state)
			if len(violations) == 0 {
				t.Fatalf("the gate failed to detect a %s violation", tc.want)
			}
			found := false
			for _, v := range violations {
				if v.Invariant == tc.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected %s, got %v", tc.want, violations)
			}
			if err := gate.CheckAll(tc.ref(), tc.state); err == nil {
				t.Fatal("CheckAll must surface the violation")
			}
		})
	}
}

// TestAQuarantinedSurvivorSatisfiesTheGate confirms the janitor's contract is what lets
// an unowned resource pass: tracked and decided by a person, not silently present.
func TestAQuarantinedSurvivorSatisfiesTheGate(t *testing.T) {
	ref := gate.NewReference()
	st := gate.State{
		ProviderResources: []string{"env-1/orphan"},
		Quarantined:       []string{"env-1/orphan"},
	}
	if err := gate.CheckAll(ref, st); err != nil {
		t.Fatalf("a quarantined survivor is tracked, so it satisfies the gate: %v", err)
	}
	// But the very same state without the quarantine does not.
	st.Quarantined = nil
	if err := gate.CheckAll(ref, st); err == nil {
		t.Fatal("without quarantine the survivor is an untracked leak")
	}
}

// TestMultipleViolationsAreAllReported: a gate that stops at the first failure makes
// each cycle expensive.
func TestMultipleViolationsAreAllReported(t *testing.T) {
	ref := gate.NewReference()
	ref.Destroy("primary")
	st := gate.State{ProviderResources: []string{"env-1/primary", "env-1/rogue-a", "env-1/rogue-b"}}
	violations := gate.Check(ref, st)
	if len(violations) < 3 {
		t.Fatalf("expected the resurrection plus two untracked survivors, got %v", violations)
	}
	err := gate.CheckAll(ref, st)
	if err == nil {
		t.Fatal("CheckAll must fail")
	}
	for _, want := range []string{"resurrected", "rogue-a", "rogue-b"} {
		if !containsStr(err.Error(), want) {
			t.Fatalf("the report must mention %q, got %q", want, err)
		}
	}
}

func containsStr(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestTheGateDoesNotClaimDeployedProof restates the checklist's own limit, so a future
// reader cannot mistake this for G2 evidence.
func TestTheGateDoesNotClaimDeployedProof(t *testing.T) {
	// This gate is satisfied against the faked provider only. The model has no notion of
	// a real cloud, so it can say nothing about deployed native-resource behaviour.
	if ref, ok := interface{}(gate.NewReference()).(interface{ DeployedProof() bool }); ok {
		if ref.DeployedProof() {
			t.Fatal("this gate must not claim deployed native-resource proof")
		}
	}
}
