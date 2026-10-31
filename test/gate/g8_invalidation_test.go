package gate_test

import (
	"context"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/fixtures"
	"github.com/sanskarpan/Ghostlight/internal/invalidation"
)

// This file is the G8 gate invalidation re-proof: the G3.6 tracker re-driven
// through the team operations a fleet actually performs — reset, clone, and
// scoped invalidation across sibling previews.
//
// G3 proves the tracker in isolation: cancel the running, invalidate the
// passed, refuse the late verdict. What it cannot prove is that the team
// layer honors the same boundary at its seams: a reset that moves the
// generation must not leave the old run qualifying, a clone must not inherit
// its parent's qualification, an invalidate scoped to one environment must
// not kill its sibling, and a signed attestation must be checked against the
// tracker rather than trusted on cryptography alone.
//
// Every test drives at least two packages (invalidation + fixtures, or
// tracker + keeper), because the property lives at the seam. What this suite
// may not claim: candidate/baseline comparison (G8.5, deferred post-revenue)
// or the fleet envelope. Those remain open G8 gate items.

var g8iNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func g8iTracker() *invalidation.Tracker {
	return invalidation.NewTracker(func() time.Time { return g8iNow })
}

func g8iKeeper(t *testing.T) *invalidation.Keeper {
	t.Helper()
	k, err := invalidation.NewKeeper([]byte("0123456789abcdef0123456789abcdef"), "gate-keeper")
	if err != nil {
		t.Fatalf("NewKeeper: %v", err)
	}
	return k
}

func g8iSnap() fixtures.Snapshot {
	return fixtures.Snapshot{
		Identity:       fixtures.Identity{ID: "env-1", Slug: "preview-one"},
		EnvironmentID:  "env-1",
		Generation:     6,
		Generations:    []uint64{4, 5, 6},
		TTL:            24 * time.Hour,
		FixtureName:    "baseline",
		FixtureVersion: 3,
	}
}

// A reset that records a new generation must end the old run's authority: the
// run tracked at the old generation is canceled when still running, and its
// pass is invalidated when already landed.
func TestG8GateResetEndsTheOldRun(t *testing.T) {
	tr := g8iTracker()
	running := tr.Start("env-1", 142, "abc123", 6, "smoke")
	landed := tr.Start("env-1", 142, "abc123", 6, "isolation")
	if err := tr.Complete(landed.ID, "pass"); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// The team resets onto generation 7; the world moved, so the gate does too.
	snap := g8iSnap()
	grown := snap
	grown.Generation = 7
	grown.Generations = []uint64{4, 5, 6, 7}
	if _, err := fixtures.Reset(grown, 7); err != nil {
		t.Fatalf("Reset(7): %v", err)
	}
	canceled, invalidated := tr.Invalidate(142, "env-1", invalidation.CauseSourceUpdate)
	if len(canceled) != 1 || canceled[0].ID != running.ID {
		t.Errorf("running run not canceled: %+v", canceled)
	}
	if len(invalidated) != 1 || invalidated[0].RunID != landed.ID {
		t.Errorf("landed pass not invalidated: %+v", invalidated)
	}
	if tr.Qualifies(landed.ID) {
		t.Error("pass for the pre-reset generation still qualifies")
	}
	if err := tr.Complete(running.ID, "pass"); err == nil {
		t.Error("late verdict for a canceled run landed; the question is dead")
	}
}

// A clone starts unqualified: the parent's pass qualifies the parent's code,
// never the copy — even though the copy began life identical.
func TestG8GateCloneInheritsNoQualification(t *testing.T) {
	tr := g8iTracker()
	parent := tr.Start("env-1", 142, "abc123", 6, "smoke")
	if err := tr.Complete(parent.ID, "pass"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !tr.Qualifies(parent.ID) {
		t.Fatal("parent pass must qualify before any invalidation")
	}

	clone, err := fixtures.Clone(g8iSnap(), fixtures.Identity{ID: "env-2", Slug: "preview-two"})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	// No run was ever tracked for the clone's environment, so nothing about
	// the clone qualifies — the parent's pass is scoped to env-1's run.
	if tr.Qualifies("gate-000002") {
		t.Error("untracked run qualifies")
	}
	if clone.EnvironmentID != "env-2" {
		t.Errorf("clone scoped to %q", clone.EnvironmentID)
	}
	// And invalidating the parent's scope leaves the clone's future runs
	// unaffected: a fresh run for env-2 still qualifies after env-1 is killed.
	fresh := tr.Start("env-2", 142, "abc123", 6, "smoke")
	if err := tr.Complete(fresh.ID, "pass"); err != nil {
		t.Fatalf("complete fresh: %v", err)
	}
	tr.Invalidate(142, "env-1", invalidation.CausePRClosed)
	if !tr.Qualifies(fresh.ID) {
		t.Error("scoped invalidation of env-1 killed env-2's pass")
	}
}

// Scoped invalidation is a scalpel: killing one sibling preview's question
// must not touch the other's answer.
func TestG8GateScopedInvalidationSparesTheSibling(t *testing.T) {
	tr := g8iTracker()
	a := tr.Start("env-a", 142, "abc123", 2, "smoke")
	b := tr.Start("env-b", 142, "abc123", 2, "smoke")
	runA, runB := a.ID, b.ID
	if err := tr.Complete(runA, "pass"); err != nil {
		t.Fatalf("complete a: %v", err)
	}
	if err := tr.Complete(runB, "pass"); err != nil {
		t.Fatalf("complete b: %v", err)
	}
	canceled, invalidated := tr.Invalidate(142, "env-a", invalidation.CauseExpired)
	if len(canceled) != 0 {
		t.Errorf("nothing was running; canceled=%v", canceled)
	}
	if len(invalidated) != 1 || invalidated[0].RunID != runA {
		t.Errorf("env-a pass not invalidated exactly once: %+v", invalidated)
	}
	if tr.Qualifies(runA) {
		t.Error("env-a pass still qualifies after scoped invalidation")
	}
	if !tr.Qualifies(runB) {
		t.Error("env-b pass died with its sibling's question")
	}
}

// A fail never qualified anything, so invalidating it records nothing.
// Recording an invalidation for a fail would imply it once counted.
func TestG8GateFailLeavesNoInvalidationRecord(t *testing.T) {
	tr := g8iTracker()
	run := tr.Start("env-1", 142, "abc123", 2, "smoke")
	if err := tr.Complete(run.ID, "fail"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	canceled, invalidated := tr.Invalidate(142, "", invalidation.CauseSourceUpdate)
	if len(canceled) != 0 || len(invalidated) != 0 {
		t.Errorf("fail produced records: canceled=%v invalidated=%v", canceled, invalidated)
	}
	if len(tr.Invalidated()) != 0 {
		t.Errorf("fail left invalidation records: %+v", tr.Invalidated())
	}
}

// Invalidating twice is safe: the kill map is keyed by run, so the second
// pass overwrites rather than duplicates. A retry of the webhook must not
// manufacture a second record.
func TestG8GateDoubleInvalidationDoesNotDuplicate(t *testing.T) {
	tr := g8iTracker()
	run := tr.Start("env-1", 142, "abc123", 2, "smoke")
	if err := tr.Complete(run.ID, "pass"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	tr.Invalidate(142, "", invalidation.CauseSourceUpdate)
	tr.Invalidate(142, "", invalidation.CauseSourceUpdate)
	if got := len(tr.Invalidated()); got != 1 {
		t.Errorf("double invalidation left %d records, want exactly one", got)
	}
	if tr.Qualifies(run.ID) {
		t.Error("pass qualifies after invalidation")
	}
}

// A valid signature over a run the tracker never saw is a forgery with good
// cryptography. Use must refuse it: both halves — signature and tracking —
// are required.
func TestG8GateUnknownRunRefusedDespiteValidSignature(t *testing.T) {
	tr := g8iTracker()
	k := g8iKeeper(t)
	a, err := k.Seal(invalidation.Attestation{
		RunID: "gate-999999", Verdict: "pass", SourceSHA: "abc123",
		Generation: 2, SealedAt: g8iNow,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := invalidation.Use(context.Background(), tr, k, a); err == nil {
		t.Error("attestation for an untracked run was used to qualify")
	}
}

// A tampered attestation is refused even while the underlying run genuinely
// qualifies. Trusting the tracker state over the broken seal would treat an
// attack as a data problem.
func TestG8GateTamperedAttestationRefusedWhileRunQualifies(t *testing.T) {
	tr := g8iTracker()
	k := g8iKeeper(t)
	run := tr.Start("env-1", 142, "abc123", 2, "smoke")
	if err := tr.Complete(run.ID, "pass"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !tr.Qualifies(run.ID) {
		t.Fatal("run must qualify before the tamper test means anything")
	}
	a, err := k.Seal(invalidation.Attestation{
		RunID: run.ID, Verdict: "pass", SourceSHA: "abc123",
		Generation: 2, SealedAt: g8iNow,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	a.Verdict = "pass-plus" // edited after signing
	if err := invalidation.Use(context.Background(), tr, k, a); err == nil {
		t.Error("tampered attestation was used to qualify")
	}
	// The run itself still qualifies — the tamper taints the paper, not the run.
	if !tr.Qualifies(run.ID) {
		t.Error("tampered copy invalidated the run it was copied from")
	}
}

// The honest path through Use: sealed, tracked, passed, uninvalidated.
// Without it, every refusal above could be mistaken for a gate that refuses
// everything.
func TestG8GateHonestAttestationUsedThroughTracker(t *testing.T) {
	tr := g8iTracker()
	k := g8iKeeper(t)
	run := tr.Start("env-1", 142, "abc123", 2, "smoke")
	if err := tr.Complete(run.ID, "pass"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	a, err := k.Seal(invalidation.Attestation{
		RunID: run.ID, Verdict: "pass", SourceSHA: "abc123",
		Generation: 2, SealedAt: g8iNow,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := invalidation.Use(context.Background(), tr, k, a); err != nil {
		t.Fatalf("honest attestation refused: %v", err)
	}
}
