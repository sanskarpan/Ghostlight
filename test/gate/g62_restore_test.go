package gate_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/janitor"
	"github.com/sanskarpan/Ghostlight/internal/resource"
)

// This file is the G6.2 restore gate: what a database restore gets wrong and
// how the platform rights it.
//
// A restore returns the ledger to a cut point. Everything the ledger learned
// after the cut — new allocations, revocations, verified deletions — is gone,
// while the provider still holds the world as it was. Reconciling means
// replaying the beyond-cut ledger log in order (re-record, revoke, delete)
// and then letting the janitor compare the provider's truth against the
// replayed ledger: owned-and-accounted-for reconciles, a verified-deleted
// record stays dead even if re-recorded, and a provider-side resource with
// no ledger provenance quarantines — it is never deleted.
//
// Every test drives the real memory ledger with the real janitor, because the
// property lives at their seam: replay order, tombstone-wins, the denylist,
// and quarantine-on-no-provenance. What this suite may not claim: executing a
// real managed-database restore (pg_basebackup / point-in-time recovery).
// That needs the fleet's database, which is not here. What it does claim is
// the reconciliation half — the proof that a restore to a cut plus an
// ordered replay converges to the pre-restore ledger, and that nothing
// beyond the cut can manufacture delete authority.

var g62Now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

const g62Tag = "ghostlight.io/env"

// g62Alloc builds a ledger allocation for one native resource.
func g62Alloc(id, env, kind, key, native string) resource.Allocation {
	return resource.Allocation{
		ID:            id,
		EnvironmentID: env,
		Generation:    6,
		Kind:          kind,
		LogicalKey:    key,
		ProviderRef:   map[string]string{"native_id": native},
		CredentialRef: "creds/" + id,
		// Ownership tags are the post-restore handle: without them the
		// janitor cannot find the resource again.
		SupportsOwnershipTags: true,
		CreatedAt:             g62Now,
	}
}

// g62Seed returns a ledger holding the pre-cut world: a database and a cache,
// both active.
func g62Seed(t *testing.T) *resource.MemoryLedger {
	t.Helper()
	l := resource.NewMemoryLedger(func() time.Time { return g62Now })
	ctx := context.Background()
	for _, a := range []resource.Allocation{
		g62Alloc("alloc-db-1", "env-1", "postgres", "primary", "nat-db-1"),
		g62Alloc("alloc-cache-1", "env-1", "valkey", "session", "nat-cache-1"),
	} {
		if err := l.Record(ctx, a); err != nil {
			t.Fatalf("seed %s: %v", a.ID, err)
		}
	}
	return l
}

// g62Snapshot copies the ledger as of the cut. A real snapshot is bytes on
// disk; a copy of every allocation is the same promise: the state at the cut
// and nothing after it.
func g62Snapshot(l *resource.MemoryLedger) []resource.Allocation {
	return l.All()
}

// g62Restore builds the post-restore ledger from the snapshot alone. This is
// what a restore without reconciliation gives back: the cut, exactly.
func g62Restore(t *testing.T, snap []resource.Allocation) *resource.MemoryLedger {
	t.Helper()
	l := resource.NewMemoryLedger(func() time.Time { return g62Now })
	ctx := context.Background()
	for _, a := range snap {
		if err := l.Record(ctx, a); err != nil {
			t.Fatalf("restore %s: %v", a.ID, err)
		}
	}
	return l
}

// A restore without reconciliation lies: the database reads active while the
// provider world moved on — the beyond-cut allocation is missing and the
// beyond-cut deletion is forgotten. This test establishes the hole the later
// tests close.
func TestG62RestoreAloneLosesBeyondCutWrites(t *testing.T) {
	live := g62Seed(t)
	ctx := context.Background()
	snap := g62Snapshot(live)

	// Beyond the cut: a new queue is recorded, the database is revoked and
	// verified deleted.
	if err := live.Record(ctx, g62Alloc("alloc-queue-1", "env-1", "kafka", "jobs", "nat-queue-1")); err != nil {
		t.Fatalf("beyond-cut record: %v", err)
	}
	if err := live.MarkRevoked(ctx, "alloc-db-1", "operator", "rotated before destroy"); err != nil {
		t.Fatalf("beyond-cut revoke: %v", err)
	}
	if err := live.MarkDeleted(ctx, "alloc-db-1", resource.Observation{
		At: g62Now, Exists: false, Detail: "provider confirms nat-db-1 absent",
	}); err != nil {
		t.Fatalf("beyond-cut delete: %v", err)
	}

	restored := g62Restore(t, snap)
	if _, err := restored.ByID(ctx, "alloc-queue-1"); !errors.Is(err, resource.ErrUnknownResource) {
		t.Fatalf("restored ledger knows the beyond-cut queue: %v", err)
	}
	db, err := restored.ByID(ctx, "alloc-db-1")
	if err != nil {
		t.Fatalf("restored ledger lost the database: %v", err)
	}
	if db.State != resource.StateActive {
		t.Fatalf("restored database reads %s; a restore without replay resurrects the deleted", db.State)
	}
}

// An ordered replay of the beyond-cut log converges: the queue reappears,
// the database is revoked then tombstoned again, and the ledger matches the
// pre-restore world.
func TestG62OrderedReplayConvergesToPreRestore(t *testing.T) {
	live := g62Seed(t)
	ctx := context.Background()
	snap := g62Snapshot(live)
	if err := live.Record(ctx, g62Alloc("alloc-queue-1", "env-1", "kafka", "jobs", "nat-queue-1")); err != nil {
		t.Fatalf("beyond-cut record: %v", err)
	}
	if err := live.MarkRevoked(ctx, "alloc-db-1", "operator", "rotated before destroy"); err != nil {
		t.Fatalf("beyond-cut revoke: %v", err)
	}
	if err := live.MarkDeleted(ctx, "alloc-db-1", resource.Observation{
		At: g62Now, Exists: false, Detail: "provider confirms nat-db-1 absent",
	}); err != nil {
		t.Fatalf("beyond-cut delete: %v", err)
	}
	want := live.All()

	restored := g62Restore(t, snap)
	// The write-ahead log, in order: record, revoke, verify-delete.
	if err := restored.Record(ctx, g62Alloc("alloc-queue-1", "env-1", "kafka", "jobs", "nat-queue-1")); err != nil {
		t.Fatalf("replay record: %v", err)
	}
	if err := restored.MarkRevoked(ctx, "alloc-db-1", "operator", "rotated before destroy"); err != nil {
		t.Fatalf("replay revoke: %v", err)
	}
	if err := restored.MarkDeleted(ctx, "alloc-db-1", resource.Observation{
		At: g62Now, Exists: false, Detail: "provider confirms nat-db-1 absent",
	}); err != nil {
		t.Fatalf("replay delete: %v", err)
	}

	got := restored.All()
	if len(got) != len(want) {
		t.Fatalf("replayed ledger holds %d allocations, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i].ID || got[i].State != want[i].State {
			t.Errorf("allocation %d: got %s/%s, want %s/%s",
				i, got[i].ID, got[i].State, want[i].ID, want[i].State)
		}
	}
}

// The tombstone wins over a re-record: once verified-deleted, no replay —
// ordered or stale — may resurrect the allocation. A restore that replays a
// creation event dated after a deletion it has not replayed yet must refuse
// rather than resurrect.
func TestG62TombstoneWinsOverReRecord(t *testing.T) {
	l := g62Seed(t)
	ctx := context.Background()
	if err := l.MarkRevoked(ctx, "alloc-db-1", "operator", "rotated before destroy"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := l.MarkDeleted(ctx, "alloc-db-1", resource.Observation{
		At: g62Now, Exists: false, Detail: "provider confirms nat-db-1 absent",
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	fresh := g62Alloc("alloc-db-1", "env-1", "postgres", "primary", "nat-db-1")
	fresh.Generation = 7 // even a newer generation must not resurrect
	if err := l.Record(ctx, fresh); !errors.Is(err, resource.ErrAlreadyDeleted) {
		t.Fatalf("re-record of a tombstone: error = %v, want refusal", err)
	}
	issuer, err := resource.NewAuthorityIssuer(l, resource.NewDenylist("nat-foundation-1"), func() time.Time { return g62Now })
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	if _, err := issuer.Authorize(ctx, "alloc-db-1", 6, "operator"); !errors.Is(err, resource.ErrAlreadyDeleted) {
		t.Fatalf("authority for a tombstone: error = %v, want refusal", err)
	}
}

// The denylist survives the restore: a foundation native ID smuggled into a
// beyond-cut allocation can never receive delete authority, before or after
// the cut.
func TestG62DenylistSurvivesRestore(t *testing.T) {
	live := g62Seed(t)
	ctx := context.Background()
	snap := g62Snapshot(live)

	smuggled := g62Alloc("alloc-smuggle-1", "env-1", "postgres", "analytics", "nat-foundation-1")
	if err := live.Record(ctx, smuggled); err != nil {
		t.Fatalf("record smuggled: %v", err)
	}
	if err := live.MarkRevoked(ctx, "alloc-smuggle-1", "operator", "revoked"); err != nil {
		t.Fatalf("revoke smuggled: %v", err)
	}

	restored := g62Restore(t, snap)
	if err := restored.Record(ctx, smuggled); err != nil {
		t.Fatalf("replay smuggled: %v", err)
	}
	if err := restored.MarkRevoked(ctx, "alloc-smuggle-1", "operator", "revoked"); err != nil {
		t.Fatalf("replay revoke: %v", err)
	}
	issuer, err := resource.NewAuthorityIssuer(restored, resource.NewDenylist("nat-foundation-1"), func() time.Time { return g62Now })
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	if _, err := issuer.Authorize(ctx, "alloc-smuggle-1", 6, "operator"); !errors.Is(err, resource.ErrSharedResource) {
		t.Fatalf("authority for a denylisted native ID: error = %v, want refusal", err)
	}
}

// g62Discovery is the provider's truth after the cut: the queue and cache
// exist with ownership tags, the database is gone, and an orphan created
// beyond the cut (crash between provider create and ledger record) exists
// with a tag but no ledger provenance.
type g62Discovery struct {
	found []janitor.Discovered
}

func (d *g62Discovery) Discover(_ context.Context, _ int) ([]janitor.Discovered, error) {
	return d.found, nil
}

// g62Quarantine records what the janitor refuses to touch. It never deletes:
// the only assertion that matters is that nothing here ever does.
type g62Quarantine struct {
	mu      sync.Mutex
	calls   []janitor.Discovered
	deleted []string
}

func (q *g62Quarantine) Quarantine(_ context.Context, d janitor.Discovered, _ string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.calls = append(q.calls, d)
	return nil
}

func g62Janitor(t *testing.T, ledger *resource.MemoryLedger, provider []janitor.Discovered) (*janitor.Janitor, *g62Quarantine) {
	t.Helper()
	q := &g62Quarantine{}
	j, err := janitor.New(&g62Discovery{found: provider}, ledger, nil, q, janitor.Config{
		TagKey: g62Tag, QuarantineAfter: 1,
		Now: func() time.Time { return g62Now },
	})
	if err != nil {
		t.Fatalf("janitor: %v", err)
	}
	return j, q
}

func g62Tagged(native, env string) janitor.Discovered {
	return janitor.Discovered{
		NativeID: native, Kind: "postgres",
		OwnerTags: map[string]string{g62Tag: env}, CreatedAt: g62Now,
	}
}

// The beyond-cut orphan — tagged but with no ledger provenance — quarantines.
// It is never deleted, and the pass never reads clean while it is pending.
func TestG62OrphanBeyondTheCutQuarantinesAndSurvives(t *testing.T) {
	restored := g62Restore(t, g62Snapshot(g62Seed(t)))
	ctx := context.Background()

	provider := []janitor.Discovered{
		g62Tagged("nat-cache-1", "env-1"),
		g62Tagged("nat-orphan-9", "env-1"), // created beyond the cut, never recorded
	}
	j, q := g62Janitor(t, restored, provider)
	res, err := j.Run(ctx, 100)
	if err != nil {
		t.Fatalf("janitor with a quarantine sink: %v", err)
	}
	if res.Clean() {
		t.Error("a pass with a quarantined orphan reads clean: it would be believed")
	}
	if len(res.Quarantined) != 1 || res.Quarantined[0].NativeID != "nat-orphan-9" {
		t.Errorf("quarantined findings = %+v, want exactly the orphan", res.Quarantined)
	}
	if len(q.calls) != 1 || q.calls[0].NativeID != "nat-orphan-9" {
		t.Errorf("quarantined = %+v, want exactly the orphan", q.calls)
	}
	if len(q.deleted) != 0 {
		t.Errorf("quarantine deleted %v: the janitor never deletes what it cannot prove", q.deleted)
	}
	if _, err := restored.ByID(ctx, "nat-orphan-9"); err == nil {
		t.Error("orphan entered the ledger through the janitor")
	}
}

// After replay, the janitor reconciles the replayed world: the queue and the
// cache are accounted for and still active, the tombstoned database is simply
// absent from the provider, and the only finding is the quarantined orphan.
func TestG62ReplayedWorldReconcilesExceptTheOrphan(t *testing.T) {
	live := g62Seed(t)
	ctx := context.Background()
	snap := g62Snapshot(live)
	if err := live.Record(ctx, g62Alloc("alloc-queue-1", "env-1", "kafka", "jobs", "nat-queue-1")); err != nil {
		t.Fatalf("beyond-cut record: %v", err)
	}
	if err := live.MarkRevoked(ctx, "alloc-db-1", "operator", "rotated before destroy"); err != nil {
		t.Fatalf("beyond-cut revoke: %v", err)
	}
	if err := live.MarkDeleted(ctx, "alloc-db-1", resource.Observation{
		At: g62Now, Exists: false, Detail: "provider confirms nat-db-1 absent",
	}); err != nil {
		t.Fatalf("beyond-cut delete: %v", err)
	}

	restored := g62Restore(t, snap)
	if err := restored.Record(ctx, g62Alloc("alloc-queue-1", "env-1", "kafka", "jobs", "nat-queue-1")); err != nil {
		t.Fatalf("replay record: %v", err)
	}
	if err := restored.MarkRevoked(ctx, "alloc-db-1", "operator", "rotated before destroy"); err != nil {
		t.Fatalf("replay revoke: %v", err)
	}
	if err := restored.MarkDeleted(ctx, "alloc-db-1", resource.Observation{
		At: g62Now, Exists: false, Detail: "provider confirms nat-db-1 absent",
	}); err != nil {
		t.Fatalf("replay delete: %v", err)
	}

	provider := []janitor.Discovered{
		{NativeID: "nat-queue-1", Kind: "kafka", OwnerTags: map[string]string{g62Tag: "env-1"}, CreatedAt: g62Now},
		g62Tagged("nat-cache-1", "env-1"),
		g62Tagged("nat-orphan-9", "env-1"),
		// nat-db-1 is absent: verified deleted, and the provider agrees.
	}
	j, q := g62Janitor(t, restored, provider)
	res, err := j.Run(ctx, 100)
	if err != nil {
		t.Fatalf("janitor with a quarantine sink: %v", err)
	}
	if res.Reconciled != 2 {
		t.Errorf("reconciled = %d, want the queue and the cache", res.Reconciled)
	}
	if len(q.calls) != 1 || q.calls[0].NativeID != "nat-orphan-9" {
		t.Errorf("quarantined = %+v, want exactly the orphan", q.calls)
	}
	if res.Clean() {
		t.Error("a pass with a quarantined orphan reads clean: it would be believed")
	}
	// The tombstone held through everything: no authority, no resurrection.
	issuer, err := resource.NewAuthorityIssuer(restored, resource.NewDenylist("nat-foundation-1"), func() time.Time { return g62Now })
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	if _, err := issuer.Authorize(ctx, "alloc-db-1", 6, "operator"); !errors.Is(err, resource.ErrAlreadyDeleted) {
		t.Fatalf("authority for the replayed tombstone: error = %v", err)
	}
}

// Replay order is load-bearing: a stale record for an older generation must
// not roll the replayed row back. A log applied out of order refuses rather
// than rewinding.
func TestG62OutOfOrderReplayCannotRollBack(t *testing.T) {
	l := g62Seed(t)
	ctx := context.Background()
	if err := l.MarkRevoked(ctx, "alloc-cache-1", "operator", "revoked"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	stale := g62Alloc("alloc-cache-1", "env-1", "valkey", "session", "nat-cache-1")
	stale.Generation = 5 // older than the recorded 6
	if err := l.Record(ctx, stale); !errors.Is(err, resource.ErrGenerationMismatch) {
		t.Fatalf("stale replay: error = %v, want a generation refusal", err)
	}
	cur, err := l.ByID(ctx, "alloc-cache-1")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if cur.Generation != 6 || cur.State != resource.StateRevoked {
		t.Errorf("stale replay moved the row: %+v", cur)
	}
}
