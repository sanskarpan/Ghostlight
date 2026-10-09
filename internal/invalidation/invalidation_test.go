package invalidation_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/invalidation"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func tracker() *invalidation.Tracker {
	return invalidation.NewTracker(func() time.Time { return now })
}

func keeper(t *testing.T) *invalidation.Keeper {
	t.Helper()
	k, err := invalidation.NewKeeper([]byte("attestation-test-key"), "test-keeper")
	if err != nil {
		t.Fatalf("keeper: %v", err)
	}
	return k
}

// TestSourceUpdateCancelsAndInvalidates: both halves, because half a response is not a
// response.
func TestSourceUpdateCancelsAndInvalidates(t *testing.T) {
	tr := tracker()

	running := tr.Start("env-1", 142, "abc123", 2, "smoke")
	finished := tr.Start("env-1", 142, "abc123", 2, "isolation")
	if err := tr.Complete(finished.ID, "pass"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	other := tr.Start("env-9", 999, "zzz", 1, "smoke")

	canceled, invalidated := tr.Invalidate(142, "", invalidation.CauseSourceUpdate)

	if len(canceled) != 1 || canceled[0].ID != running.ID {
		t.Fatalf("the running gate must be canceled, got %+v", canceled)
	}
	if canceled[0].CanceledBy != invalidation.CauseSourceUpdate {
		t.Fatalf("the cancellation must name its cause, got %s", canceled[0].CanceledBy)
	}
	if len(invalidated) != 1 || invalidated[0].RunID != finished.ID {
		t.Fatalf("the completed pass must be invalidated, got %+v", invalidated)
	}
	if tr.Qualifies(finished.ID) {
		t.Fatal("an invalidated pass must no longer qualify")
	}
	if len(tr.Active()) != 1 || tr.Active()[0].ID != other.ID {
		t.Fatal("a different PR must be untouched")
	}
}

// TestLateVerdictOnACanceledRunDoesNotLand: a slow harness must not outlive the
// invalidation that stopped it.
func TestLateVerdictOnACanceledRunDoesNotLand(t *testing.T) {
	tr := tracker()

	r := tr.Start("env-1", 142, "abc123", 2, "smoke")
	tr.Invalidate(142, "", invalidation.CausePRClosed)
	if err := tr.Complete(r.ID, "pass"); err == nil {
		t.Fatal("a verdict for a canceled run must be refused")
	}
	if tr.Qualifies(r.ID) {
		t.Fatal("a refused verdict must never qualify")
	}
}

// TestVerdictsLandOnce.
func TestVerdictsLandOnce(t *testing.T) {
	tr := tracker()

	r := tr.Start("env-1", 142, "abc123", 2, "smoke")
	if err := tr.Complete(r.ID, "pass"); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := tr.Complete(r.ID, "pass"); err == nil {
		t.Fatal("a second verdict must be refused")
	}
	if err := tr.Complete("gate-999999", "pass"); !errors.Is(err, invalidation.ErrUnknownRun) {
		t.Fatalf("an unknown run must be reported, got %v", err)
	}
}

// TestOnlyPassesAreInvalidated: a fail never qualified anything, so there is nothing
// to take away — and recording an invalidation for one would imply it once counted.
func TestOnlyPassesAreInvalidated(t *testing.T) {
	tr := tracker()

	failed := tr.Start("env-1", 142, "abc123", 2, "smoke")
	if err := tr.Complete(failed.ID, "fail"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	passed := tr.Start("env-1", 142, "abc123", 2, "isolation")
	if err := tr.Complete(passed.ID, "pass"); err != nil {
		t.Fatalf("complete: %v", err)
	}

	_, invalidated := tr.Invalidate(142, "", invalidation.CauseExpired)
	if len(invalidated) != 1 || invalidated[0].RunID != passed.ID {
		t.Fatalf("only the pass must be invalidated, got %+v", invalidated)
	}
	if len(tr.Invalidated()) != 1 {
		t.Fatal("the fail must leave no invalidation record")
	}
}

// TestScopeNarrowsToOneEnvironment: a single preview's update must not cancel its
// sibling's gates.
func TestScopeNarrowsToOneEnvironment(t *testing.T) {
	tr := tracker()

	a := tr.Start("env-a", 142, "abc123", 2, "smoke")
	b := tr.Start("env-b", 142, "abc123", 2, "smoke")

	canceled, _ := tr.Invalidate(142, "env-a", invalidation.CauseSourceUpdate)
	if len(canceled) != 1 || canceled[0].ID != a.ID {
		t.Fatalf("only env-a must cancel, got %+v", canceled)
	}
	if len(tr.Active()) != 1 || tr.Active()[0].ID != b.ID {
		t.Fatal("env-b must keep running")
	}
}

// TestExpiryInvalidates.
func TestExpiryInvalidates(t *testing.T) {
	tr := tracker()

	r := tr.Start("env-1", 142, "abc123", 2, "smoke")
	if err := tr.Complete(r.ID, "pass"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	_, invalidated := tr.Invalidate(142, "", invalidation.CauseExpired)
	if len(invalidated) != 1 {
		t.Fatalf("expiry must invalidate the pass, got %+v", invalidated)
	}
	if invalidated[0].Cause != invalidation.CauseExpired {
		t.Fatalf("the record must name expiry, got %s", invalidated[0].Cause)
	}
}

// TestPRCloseEndsEveryPreview: one close, all questions moot.
func TestPRCloseEndsEveryPreview(t *testing.T) {
	tr := tracker()

	a := tr.Start("env-a", 142, "abc123", 2, "smoke")
	b := tr.Start("env-b", 142, "abc123", 3, "isolation")
	if err := tr.Complete(b.ID, "pass"); err != nil {
		t.Fatalf("complete: %v", err)
	}

	canceled, invalidated := tr.Invalidate(142, "", invalidation.CausePRClosed)
	if len(canceled) != 1 || canceled[0].ID != a.ID {
		t.Fatalf("the running gate must cancel, got %+v", canceled)
	}
	if len(invalidated) != 1 || invalidated[0].RunID != b.ID {
		t.Fatalf("the pass must invalidate, got %+v", invalidated)
	}
	if len(tr.Active()) != 0 {
		t.Fatal("nothing may still be running for a closed PR")
	}
}

// TestQualifiesRequiresAPass: running, canceled, failed, and unknown runs qualify
// nothing.
func TestQualifiesRequiresAPass(t *testing.T) {
	tr := tracker()

	running := tr.Start("env-1", 142, "abc123", 2, "smoke")
	if tr.Qualifies(running.ID) {
		t.Fatal("a running gate qualifies nothing")
	}
	if tr.Qualifies("gate-999999") {
		t.Fatal("an unknown run qualifies nothing")
	}
	failed := tr.Start("env-1", 142, "abc123", 2, "isolation")
	if err := tr.Complete(failed.ID, "fail"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if tr.Qualifies(failed.ID) {
		t.Fatal("a fail qualifies nothing")
	}
	passed := tr.Start("env-1", 142, "abc123", 2, "load")
	if err := tr.Complete(passed.ID, "pass"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !tr.Qualifies(passed.ID) {
		t.Fatal("an uninvalidated pass must qualify")
	}
}

// TestConcurrentInvalidationIsConsistent.
func TestConcurrentInvalidationIsConsistent(t *testing.T) {
	tr := tracker()
	for i := 0; i < 10; i++ {
		tr.Start("env-1", 142, "abc123", 2, "smoke")
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr.Invalidate(142, "", invalidation.CauseSourceUpdate)
		}()
	}
	wg.Wait()

	if len(tr.Active()) != 0 {
		t.Fatalf("every run must be canceled exactly once semantics aside, %d still active", len(tr.Active()))
	}
}

// ---------------------------------------------------------------------------
// Attestation integrity
// ---------------------------------------------------------------------------

func attestation() invalidation.Attestation {
	return invalidation.Attestation{
		RunID: "gate-000001", Verdict: "pass", SourceSHA: "abc123", Generation: 2,
		SealedAt: now,
	}
}

// TestSealedAttestationVerifies is the ordinary path.
func TestSealedAttestationVerifies(t *testing.T) {
	k := keeper(t)
	a, err := k.Seal(attestation())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if a.Signature == "" {
		t.Fatal("a sealed attestation must carry a signature")
	}
	if err := k.Verify(a); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestKeeperRefusesAnEmptyKey: it would sign edits.
func TestKeeperRefusesAnEmptyKey(t *testing.T) {
	if _, err := invalidation.NewKeeper(nil, "k"); err == nil {
		t.Fatal("an empty key must be refused")
	}
	if _, err := invalidation.NewKeeper([]byte("k"), ""); err == nil {
		t.Fatal("a keeper id is required")
	}
}

// TestEditedAttestationIsRefused: a review that can be rewritten is not a review.
// The attack is upgrading a fail to a pass after signing.
func TestEditedAttestationIsRefused(t *testing.T) {
	k := keeper(t)
	a, err := k.Seal(invalidation.Attestation{
		RunID: "gate-000001", Verdict: "fail", SourceSHA: "abc123", Generation: 2, SealedAt: now,
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	a.Verdict = "pass"
	if err := k.Verify(a); !errors.Is(err, invalidation.ErrTampered) {
		t.Fatalf("an edited attestation must be refused, got %v", err)
	}
}

// TestUnsignedAttestationIsRefused.
func TestUnsignedAttestationIsRefused(t *testing.T) {
	k := keeper(t)
	if err := k.Verify(attestation()); !errors.Is(err, invalidation.ErrUnsigned) {
		t.Fatalf("an unsigned attestation must be refused, got %v", err)
	}
}

// TestSealRequiresIdentity.
func TestSealRequiresIdentity(t *testing.T) {
	k := keeper(t)
	if _, err := k.Seal(invalidation.Attestation{}); err == nil {
		t.Fatal("an anonymous attestation must be refused")
	}
}

// TestUseRequiresBothHalves: a valid signature over an untracked run is a forgery with
// good cryptography; a tracked run with a broken signature cannot be trusted.
func TestUseRequiresBothHalves(t *testing.T) {
	tr := tracker()
	k := keeper(t)
	ctx := context.Background()

	r := tr.Start("env-1", 142, "abc123", 2, "smoke")
	if err := tr.Complete(r.ID, "pass"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	a, err := k.Seal(invalidation.Attestation{
		RunID: r.ID, Verdict: "pass", SourceSHA: "abc123", Generation: 2, SealedAt: now,
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := invalidation.Use(ctx, tr, k, a); err != nil {
		t.Fatalf("a valid attestation for a qualifying run must be usable: %v", err)
	}

	// Forgery with good cryptography: signed, but the tracker never saw the run.
	forged, err := k.Seal(invalidation.Attestation{
		RunID: "gate-999999", Verdict: "pass", SourceSHA: "abc123", Generation: 2, SealedAt: now,
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := invalidation.Use(ctx, tr, k, forged); err == nil {
		t.Fatal("a signed attestation for an untracked run must be refused")
	}

	// Tracked run, broken signature.
	broken := a
	broken.Signature = "tampered"
	if err := invalidation.Use(ctx, tr, k, broken); !errors.Is(err, invalidation.ErrTampered) {
		t.Fatalf("a tampered attestation must be refused, got %v", err)
	}

	// Valid signature, invalidated run.
	tr.Invalidate(142, "", invalidation.CauseSourceUpdate)
	if err := invalidation.Use(ctx, tr, k, a); err == nil {
		t.Fatal("an attestation for an invalidated run must be refused")
	}
}
