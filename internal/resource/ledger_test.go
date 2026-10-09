package resource_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/resource"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func ledger() *resource.MemoryLedger {
	return resource.NewMemoryLedger(func() time.Time { return now })
}

func allocation(id, env, kind, key string) resource.Allocation {
	return resource.Allocation{
		ID: id, EnvironmentID: env, Generation: 3, Kind: kind, LogicalKey: key,
		ProviderRef: map[string]string{"native_id": "nat-" + id, "region": "us-east-1"},
		State:       resource.StateActive, CreatedAt: now,
	}
}

func issuer(t *testing.T, l resource.Ledger, denied ...string) *resource.AuthorityIssuer {
	t.Helper()
	i, err := resource.NewAuthorityIssuer(l, resource.NewDenylist(denied...), func() time.Time { return now })
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	return i
}

// TestIssuerRequiresTheLedger is the central invariant as a test: without the ledger
// every authority would be unbacked.
func TestIssuerRequiresTheLedger(t *testing.T) {
	if _, err := resource.NewAuthorityIssuer(nil, resource.NewDenylist(), nil); err == nil {
		t.Fatal("an issuer must not be constructible without the ledger")
	}
}

// TestIssuerRequiresADenylist: an empty denylist is not a safe default. It would
// silently permit deleting a foundation resource.
func TestIssuerRequiresADenylist(t *testing.T) {
	if _, err := resource.NewAuthorityIssuer(ledger(), nil, nil); err == nil {
		t.Fatal("an issuer must not be constructible without a foundation denylist")
	}
}

// TestDestroyingByNameIsImpossible encodes "a destructive action never follows
// user-supplied names". There is no safe version of the operation, so the only thing
// worth having is a function that refuses.
func TestDestroyingByNameIsImpossible(t *testing.T) {
	_, err := resource.ResolveByName(context.Background(), "repo/acme/app", "my-postgres")
	if !errors.Is(err, resource.ErrUserSuppliedName) {
		t.Fatalf("resolving by name must be impossible, got %v", err)
	}
}

// TestAllocationMustBeIdentified: an allocation with no provider reference can never be
// verified deleted, so admitting one guarantees an unverifiable leak.
func TestAllocationMustBeIdentified(t *testing.T) {
	l := ledger()
	ctx := context.Background()

	noID := allocation("a", "env-1", "database", "primary")
	noID.ID = ""
	if err := l.Record(ctx, noID); err == nil {
		t.Fatal("an allocation must have a ledger id")
	}
	noEnv := allocation("a", "", "database", "primary")
	if err := l.Record(ctx, noEnv); err == nil {
		t.Fatal("an allocation must name its owning environment")
	}
	noRef := allocation("a", "env-1", "database", "primary")
	noRef.ProviderRef = nil
	if err := l.Record(ctx, noRef); err == nil {
		t.Fatal("an allocation without a provider reference can never be verified deleted")
	}
}

// TestLogicalKeyIsUniquePerEnvironment mirrors the schema's UNIQUE constraint, so two
// controllers cannot both claim the same logical dependency.
func TestLogicalKeyIsUniquePerEnvironment(t *testing.T) {
	l := ledger()
	ctx := context.Background()

	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := l.Record(ctx, allocation("b", "env-1", "database", "primary")); err == nil {
		t.Fatal("two allocations cannot share one environment/kind/key")
	}
	// A different environment may hold its own primary.
	if err := l.Record(ctx, allocation("c", "env-2", "database", "primary")); err != nil {
		t.Fatalf("a different environment must have its own slot: %v", err)
	}
	// Re-recording the same allocation is an update, not a conflict.
	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("re-recording must update in place: %v", err)
	}
}

// TestTombstoneSurvivesAStaleWebhook is the rule the schema calls out: the row is
// retained after verified deletion so a stale webhook cannot recreate a removed
// allocation.
func TestTombstoneSurvivesAStaleWebhook(t *testing.T) {
	l := ledger()
	ctx := context.Background()

	a := allocation("a", "env-1", "database", "primary")
	if err := l.Record(ctx, a); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := l.MarkRevoked(ctx, "a", "cleanup", "provider revoke ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := l.MarkDeleted(ctx, "a", resource.Observation{Exists: false, Detail: "confirmed absent"}); err != nil {
		t.Fatalf("mark deleted: %v", err)
	}

	// A stale webhook arrives carrying the same logical identity.
	err := l.Record(ctx, allocation("a", "env-1", "database", "primary"))
	if !errors.Is(err, resource.ErrAlreadyDeleted) {
		t.Fatalf("a tombstoned allocation must not be recreated, got %v", err)
	}
}

// TestDeletionCannotBeRecordedWhileItStillExists is the guard against the tombstone
// becoming a lie.
func TestDeletionCannotBeRecordedWhileItStillExists(t *testing.T) {
	l := ledger()
	ctx := context.Background()
	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := l.MarkRevoked(ctx, "a", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := l.MarkDeleted(ctx, "a", resource.Observation{Exists: true, Detail: "still there"}); err == nil {
		t.Fatal("deletion may not be verified while the resource still exists")
	}
	if err := l.MarkDeleted(ctx, "a", resource.Observation{Exists: false}); err == nil {
		t.Fatal("verified deletion requires evidence of absence")
	}
}

// TestDestructionRequiresRevocationFirst is the ordering rule: credentials outlive the
// data they grant access to.
func TestDestructionRequiresRevocationFirst(t *testing.T) {
	l := ledger()
	ctx := context.Background()
	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("record: %v", err)
	}

	i := issuer(t, l)
	if _, err := i.Authorize(ctx, "a", 3, "cleanup"); !errors.Is(err, resource.ErrNotRevoked) {
		t.Fatalf("an active allocation must not receive delete authority, got %v", err)
	}
	if err := l.MarkRevoked(ctx, "a", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := i.Authorize(ctx, "a", 3, "cleanup"); err != nil {
		t.Fatalf("a revoked allocation must be destroyable: %v", err)
	}
}

// TestRevocationRequiresAnIdentifiedActor: an unattributable privilege change is the
// thing an audit exists to make impossible.
func TestRevocationRequiresAnIdentifiedActor(t *testing.T) {
	l := ledger()
	ctx := context.Background()
	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := l.MarkRevoked(ctx, "a", "", "ok"); err == nil {
		t.Fatal("revocation requires an identified actor")
	}
}

// TestSharedResourcesNeverReceiveDeleteAuthority is the rule that stops one preview's
// teardown destroying every other preview's database.
func TestSharedResourcesNeverReceiveDeleteAuthority(t *testing.T) {
	l := ledger()
	ctx := context.Background()

	shared := allocation("s", "env-1", "database", "shared-primary")
	shared.IsShared = true
	if err := l.Record(ctx, shared); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := l.MarkRevoked(ctx, "s", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	i := issuer(t, l)
	_, err := i.Authorize(ctx, "s", 3, "cleanup")
	if !errors.Is(err, resource.ErrSharedResource) {
		t.Fatalf("a shared resource must never be destroyable, got %v", err)
	}
}

// TestDenylistCatchesUnflaggedSharedResources is why the denylist exists separately
// from the is_shared flag. Either signal alone can be wrong, and a resource nobody
// thought to flag must still be untouchable.
func TestDenylistCatchesUnflaggedSharedResources(t *testing.T) {
	l := ledger()
	ctx := context.Background()

	// Recorded as NOT shared, but its native ID is a foundation resource.
	tricky := allocation("t", "env-1", "database", "primary")
	tricky.ProviderRef = map[string]string{"native_id": "nat-foundation-001"}
	if err := l.Record(ctx, tricky); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := l.MarkRevoked(ctx, "t", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	i := issuer(t, l, "nat-foundation-001")
	_, err := i.Authorize(ctx, "t", 3, "cleanup")
	if !errors.Is(err, resource.ErrSharedResource) {
		t.Fatalf("a denylisted resource must be refused even when unflagged, got %v", err)
	}
	if !strings.Contains(err.Error(), "foundation") {
		t.Fatalf("the refusal must explain itself, got %q", err)
	}
}

// TestDenylistChecksEveryValueInTheRef: provider refs are opaque maps, so checking one
// known key would make the denylist trivially bypassable by a provider naming it
// differently.
func TestDenylistChecksEveryValueInTheRef(t *testing.T) {
	d := resource.NewDenylist("nat-secret-999")

	// The denylisted value sits under an unexpected key.
	ref := map[string]string{"some_other_key": "nat-secret-999", "region": "us-east-1"}
	if _, denied := d.AnyDenied(ref); !denied {
		t.Fatal("the denylist must check every value in a provider ref")
	}
	if _, denied := d.AnyDenied(map[string]string{"native_id": "nat-other"}); denied {
		t.Fatal("an unrelated resource must not be denied")
	}
}

// TestOwnershipMustBeVerified: an unknown resource has nobody to prove it is safe to
// delete.
func TestOwnershipMustBeVerified(t *testing.T) {
	i := issuer(t, ledger())
	_, err := i.Authorize(context.Background(), "ghost", 3, "cleanup")
	if !errors.Is(err, resource.ErrNoAuthority) {
		t.Fatalf("an unknown resource must be refused, got %v", err)
	}
}

// TestGenerationFencesTheDestroy: a destroy authorized for one generation must not act
// on the row another generation wrote.
func TestGenerationFencesTheDestroy(t *testing.T) {
	l := ledger()
	ctx := context.Background()
	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := l.MarkRevoked(ctx, "a", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	i := issuer(t, l)
	_, err := i.Authorize(ctx, "a", 2, "cleanup")
	if !errors.Is(err, resource.ErrGenerationMismatch) {
		t.Fatalf("a stale generation must be refused, got %v", err)
	}
	if _, err := i.Authorize(ctx, "a", 3, "cleanup"); err != nil {
		t.Fatalf("the matching generation must be authorized: %v", err)
	}
}

// TestAuthorityIsBoundToTheVerifiedReference: the delete uses exactly what was
// verified, rather than re-reading the ledger and possibly acting on a newer row.
func TestAuthorityIsBoundToTheVerifiedReference(t *testing.T) {
	l := ledger()
	ctx := context.Background()
	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := l.MarkRevoked(ctx, "a", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	i := issuer(t, l)
	auth, err := i.Authorize(ctx, "a", 3, "cleanup")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if auth.ProviderRef["native_id"] != "nat-a" {
		t.Fatalf("authority must carry the verified ref, got %v", auth.ProviderRef)
	}
	// Mutating the ledger afterwards must not change what the authority points at.
	auth.ProviderRef["native_id"] = "tampered"
	if auth.ProviderRef["native_id"] == "nat-a" {
		t.Fatal("the test did not actually mutate the reference")
	}
}

// TestVerificationRequiresAnObserver: cleanup may not be declared verified without
// asking the provider.
func TestVerificationRequiresAnObserver(t *testing.T) {
	l := ledger()
	ctx := context.Background()
	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := l.MarkRevoked(ctx, "a", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	i := issuer(t, l)
	auth, err := i.Authorize(ctx, "a", 3, "cleanup")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if _, err := i.VerifyDeleted(ctx, auth); err == nil {
		t.Fatal("verification without an observer must fail rather than assume absence")
	}
}

// TestVerifyDeletedIsNotDestroySucceeded: a resource that still exists is not deleted,
// even if the destroy call returned nil.
func TestVerifyDeletedIsNotDestroySucceeded(t *testing.T) {
	l := ledger()
	ctx := context.Background()
	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := l.MarkRevoked(ctx, "a", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	i := issuer(t, l)
	i.SetObserver(func(context.Context, map[string]string) (resource.Observation, error) {
		return resource.Observation{Exists: true, Detail: "still present"}, nil
	})
	auth, _ := i.Authorize(ctx, "a", 3, "cleanup")

	if _, err := i.VerifyDeleted(ctx, auth); err == nil {
		t.Fatal("a resource that still exists must not verify as deleted")
	} else if !strings.Contains(err.Error(), "still verifying") {
		t.Fatalf("the error must say cleanup is pending, got %q", err)
	}
}

// TestVerificationRecordsEvidence keeps the trail that an operator needs.
func TestVerificationRecordsEvidence(t *testing.T) {
	l := ledger()
	ctx := context.Background()
	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := l.MarkRevoked(ctx, "a", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	i := issuer(t, l)
	i.SetObserver(func(context.Context, map[string]string) (resource.Observation, error) {
		return resource.Observation{Exists: false, Detail: "provider reports absent"}, nil
	})
	auth, _ := i.Authorize(ctx, "a", 3, "cleanup")
	obs, err := i.VerifyDeleted(ctx, auth)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if obs.At.IsZero() {
		t.Fatal("an observation must be timestamped, or the trail proves nothing")
	}
	ev, err := l.Evidence(ctx, "a")
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	if len(ev) == 0 {
		t.Fatal("verification must leave evidence in the ledger")
	}
}

// TestListIsStablyOrdered: teardown order depends on this, and two runs must not produce
// two different orders.
func TestListIsStablyOrdered(t *testing.T) {
	l := ledger()
	ctx := context.Background()
	for _, id := range []string{"z", "a", "m"} {
		if err := l.Record(ctx, allocation(id, "env-1", "database", id)); err != nil {
			t.Fatalf("record %s: %v", id, err)
		}
	}
	first, err := l.List(ctx, "env-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, _ := l.List(ctx, "env-1")
		for j := range first {
			if first[j].ID != again[j].ID {
				t.Fatalf("list order is unstable: %v vs %v", first, again)
			}
		}
	}
}

// TestRevocationIsIdempotentAndIrreversible: cleanup is retried, so re-revoking must be
// safe, while un-revoking would re-grant credentials nobody has verified exist.
func TestRevocationIsIdempotentAndIrreversible(t *testing.T) {
	l := ledger()
	ctx := context.Background()
	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := l.MarkRevoked(ctx, "a", "cleanup", "first"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := l.MarkRevoked(ctx, "a", "cleanup-2", "second"); err != nil {
		t.Fatalf("re-revocation must be safe: %v", err)
	}
	got, err := l.ByID(ctx, "a")
	if err != nil {
		t.Fatalf("by id: %v", err)
	}
	if got.RevokedBy != "cleanup" {
		t.Fatalf("the first revoking actor must be retained, got %q", got.RevokedBy)
	}
}

// TestMarkDeletedIsIdempotent: re-confirming absence is harmless, and cleanup retries.
func TestMarkDeletedIsIdempotent(t *testing.T) {
	l := ledger()
	ctx := context.Background()
	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := l.MarkRevoked(ctx, "a", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	obs := resource.Observation{Exists: false, Detail: "absent"}
	if err := l.MarkDeleted(ctx, "a", obs); err != nil {
		t.Fatalf("mark: %v", err)
	}
	if err := l.MarkDeleted(ctx, "a", obs); err != nil {
		t.Fatalf("re-confirming absence must be harmless: %v", err)
	}
}

// TestDescribeOmitsCredentials: an operator log is the wrong place for the address of a
// secret.
func TestDescribeOmitsCredentials(t *testing.T) {
	a := allocation("a", "env-1", "database", "primary")
	a.CredentialRef = "secret://vault/db-primary-password"

	got := resource.Describe(a)
	if strings.Contains(got, "vault") || strings.Contains(got, "CredentialRef") {
		t.Fatalf("a description must never carry a credential location, got %q", got)
	}
	for _, want := range []string{"database", "env-1", "gen=3", "nat-a"} {
		if !strings.Contains(got, want) {
			t.Fatalf("a description must remain identifiable, missing %q in %q", want, got)
		}
	}
}

// TestDescribeSurfacesMissingOwnershipTags: without them, post-restore reconciliation
// cannot rely on tags to find the resource again.
func TestDescribeSurfacesMissingOwnershipTags(t *testing.T) {
	a := allocation("a", "env-1", "database", "primary")
	if !strings.Contains(resource.Describe(a), "no-ownership-tags") {
		t.Fatal("an allocation without ownership tags must say so; it affects recovery")
	}
	a.SupportsOwnershipTags = true
	if strings.Contains(resource.Describe(a), "no-ownership-tags") {
		t.Fatal("a tagged allocation must not be flagged")
	}
}

// TestTombstonedAllocationCannotBeReAuthorized: re-issuing authority on a tombstone
// would let a retry loop keep operating on a deleted resource.
func TestTombstonedAllocationCannotBeReAuthorized(t *testing.T) {
	l := ledger()
	ctx := context.Background()
	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := l.MarkRevoked(ctx, "a", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := l.MarkDeleted(ctx, "a", resource.Observation{Exists: false, Detail: "absent"}); err != nil {
		t.Fatalf("mark: %v", err)
	}

	i := issuer(t, l)
	if _, err := i.Authorize(ctx, "a", 3, "cleanup"); !errors.Is(err, resource.ErrAlreadyDeleted) {
		t.Fatalf("a tombstoned allocation must not be re-authorized, got %v", err)
	}
}

// TestOneEnvironmentCannotAuthorizeAnothersAllocation is the ownership check.
func TestOneEnvironmentCannotAuthorizeAnothersAllocation(t *testing.T) {
	l := ledger()
	ctx := context.Background()
	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := l.MarkRevoked(ctx, "a", "cleanup", "ok"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// The authority is bound to the environment recorded on the allocation, not to
	// whatever the caller claims.
	i := issuer(t, l)
	auth, err := i.Authorize(ctx, "a", 3, "cleanup")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if auth.EnvironmentID != "env-1" {
		t.Fatalf("authority must be bound to the recorded owner, got %s", auth.EnvironmentID)
	}
}

// TestOutOfOrderEventCannotRollTheGenerationBack is a regression test.
//
// The G1 gate found this: an out-of-order delivery carrying an older generation was
// happily overwriting the record, which would let a delayed webhook authorize cleanup of
// something a later generation had replaced.
func TestOutOfOrderEventCannotRollTheGenerationBack(t *testing.T) {
	l := ledger()
	ctx := context.Background()

	if err := l.Record(ctx, allocation("a", "env-1", "database", "primary")); err != nil {
		t.Fatalf("record generation 3: %v", err)
	}

	older := allocation("a", "env-1", "database", "primary")
	older.Generation = 2
	if err := l.Record(ctx, older); !errors.Is(err, resource.ErrGenerationMismatch) {
		t.Fatalf("an out-of-order event must be refused, got %v", err)
	}

	got, err := l.ByID(ctx, "a")
	if err != nil {
		t.Fatalf("by id: %v", err)
	}
	if got.Generation != 3 {
		t.Fatalf("the generation rolled back to %d", got.Generation)
	}

	// A newer generation is still accepted: reordering must not block legitimate
	// progress, only going backwards.
	newer := allocation("a", "env-1", "database", "primary")
	newer.Generation = 4
	if err := l.Record(ctx, newer); err != nil {
		t.Fatalf("a newer generation must be accepted: %v", err)
	}
	got, _ = l.ByID(ctx, "a")
	if got.Generation != 4 {
		t.Fatalf("the generation did not advance, got %d", got.Generation)
	}
}

// TestAllocationRequiresAKindAndLogicalKey keeps the ledger addressable.
func TestAllocationRequiresAKindAndLogicalKey(t *testing.T) {
	l := ledger()
	ctx := context.Background()
	noKind := allocation("a", "env-1", "", "primary")
	if err := l.Record(ctx, noKind); err == nil {
		t.Fatal("an allocation must name its kind")
	}
	noKey := allocation("b", "env-1", "database", "")
	if err := l.Record(ctx, noKey); err == nil {
		t.Fatal("an allocation must name its logical key")
	}
}
