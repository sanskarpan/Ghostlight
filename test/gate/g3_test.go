package gate_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/confidence"
	"github.com/sanskarpan/Ghostlight/internal/evidence"
	"github.com/sanskarpan/Ghostlight/internal/evidencestore"
	"github.com/sanskarpan/Ghostlight/internal/harness"
	"github.com/sanskarpan/Ghostlight/internal/invalidation"
)

// This file is the G3 gate: "candidate cannot fake a pass and stale results cannot
// qualify new code/config."
//
// Each test is an attack by the candidate against the qualification system, and each
// asserts the layer that stops it. The attacks are ordered from the most naive to the
// most sophisticated, because a gate that stops only naive attacks is decoration.

var g3now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func g3binding(gen uint64) evidence.Binding {
	return evidence.Binding{
		SourceSHA: "abc123", BaseSHA: "def456", ArtifactDigest: "sha256:aaa",
		ConfigDigest: "sha256:bbb", RecipeDigest: "sha256:ccc",
		SchemaDigest: "sha256:ddd", PolicyDigest: "sha256:eee", Generation: gen,
	}
}

func g3keeper(t *testing.T) *evidence.HMACKeeper {
	t.Helper()
	k, err := evidence.NewHMACKeeper([]byte("g3-gate-key"), "g3")
	if err != nil {
		t.Fatalf("keeper: %v", err)
	}
	return k
}

func g3verifier(t *testing.T) *evidence.Verifier {
	t.Helper()
	v, err := evidence.NewVerifier(g3keeper(t), func() time.Time { return g3now })
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return v
}

func g3sealed(t *testing.T, outcome string, b evidence.Binding) *evidence.Result {
	t.Helper()
	r, err := evidence.Seal(g3keeper(t), "smoke", outcome, b, g3now, g3now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return r
}

func g3expectation(gen uint64) evidence.Expectation {
	b := g3binding(gen)
	return evidence.Expectation{Binding: b}
}

// TestCandidateCannotWriteItsOwnEvidence: the most naive attack is also the most
// important to stop, because everything else assumes the evidence store is honest.
func TestCandidateCannotWriteItsOwnEvidence(t *testing.T) {
	s := evidencestore.NewStore(func() time.Time { return g3now })

	for _, role := range []evidencestore.WriterRole{"workload", "candidate", "runtime"} {
		_, err := s.Append(context.Background(), evidencestore.Write{
			ByRole: role, Harness: "smoke", EnvironmentID: "env-1",
			Generation: 2, Outcome: "pass", Body: "trust me",
		})
		if !errors.Is(err, evidencestore.ErrForbiddenWriter) {
			t.Fatalf("a candidate writing %q must be refused, got %v", role, err)
		}
	}
}

// TestCandidateCannotReplayAnothersPass: a pass bound to env-A's digests does not
// qualify env-B, even if every other field matches.
func TestCandidateCannotReplayAnothersPass(t *testing.T) {
	r := g3sealed(t, "pass", g3binding(2))
	// env-B presents env-A's pass as its own. The binding names env-A's source, so it
	// cannot match env-B's expectation — but the deeper point is that the gate
	// compares digests rather than trusting the presenter.
	exp := g3expectation(2)
	exp.Binding.SourceSHA = "different-source"
	if err := g3verifier(t).Verify(context.Background(), r, exp); !errors.Is(err, evidence.ErrDigestMismatch) {
		t.Fatalf("a replayed pass must mismatch, got %v", err)
	}
}

// TestCandidateCannotEditAPass: upgrading a fail to a pass after sealing breaks the
// signature, and the broken signature refuses rather than re-examines.
func TestCandidateCannotEditAPass(t *testing.T) {
	r := g3sealed(t, "fail", g3binding(2))
	r.Outcome = "pass"
	if err := g3verifier(t).Verify(context.Background(), r, g3expectation(2)); !errors.Is(err, evidence.ErrBadSignature) {
		t.Fatalf("an edited result must fail signature verification, got %v", err)
	}
}

// TestCandidateCannotPassOnThreeProbes: a harness run with a tiny sample is
// inconclusive, and inconclusive never qualifies — no matter what the harness said.
func TestCandidateCannotPassOnThreeProbes(t *testing.T) {
	// Three passing probes across the required dimensions.
	obs := []confidence.Observation{
		{Dimension: "smoke", Passed: true},
		{Dimension: "isolation", Passed: true},
		{Dimension: "smoke", Passed: true},
	}
	req := confidence.Requirement{
		MinObservations: 30, Dimensions: []string{"smoke", "isolation"},
		MinLowerBound: 0.95, MaxFailureRate: 0.05,
	}
	a := confidence.Assess(obs, req)
	if a.Verdict != confidence.VerdictInconclusive {
		t.Fatalf("three probes must be inconclusive, got %+v", a)
	}
	if confidence.Qualifies(a) {
		t.Fatal("inconclusive must never qualify")
	}
}

// TestStalePassCannotQualifyNewCode is the gate's second clause.
//
// A pass sealed for generation 2, presented after the candidate moved to generation
// 3, must be refused even though every digest still matches. The candidate moved on;
// the evidence did not.
func TestStalePassCannotQualifyNewCode(t *testing.T) {
	r := g3sealed(t, "pass", g3binding(2))
	if err := g3verifier(t).Verify(context.Background(), r, g3expectation(3)); !errors.Is(err, evidence.ErrStaleResult) {
		t.Fatalf("a pass for an older generation must be stale, got %v", err)
	}
}

// TestUpdatedSourceInvalidatesThePass: a source update cancels the question, and the
// old pass dies with it.
func TestUpdatedSourceInvalidatesThePass(t *testing.T) {
	tr := invalidation.NewTracker(func() time.Time { return g3now })

	run := tr.Start("env-1", 142, "abc123", 2, "smoke")
	if err := tr.Complete(run.ID, "pass"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !tr.Qualifies(run.ID) {
		t.Fatal("an uninvalidated pass must qualify")
	}

	// New code arrives.
	tr.Invalidate(142, "", invalidation.CauseSourceUpdate)
	if tr.Qualifies(run.ID) {
		t.Fatal("a pass for superseded code must no longer qualify")
	}
}

// TestExpiredPassCannotQualify: time, not code, moved — same refusal.
func TestExpiredPassCannotQualify(t *testing.T) {
	r, err := evidence.Seal(g3keeper(t), "smoke", "pass", g3binding(2), g3now.Add(-48*time.Hour), g3now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := g3verifier(t).Verify(context.Background(), r, g3expectation(2)); !errors.Is(err, evidence.ErrExpiredEvidence) {
		t.Fatalf("expired evidence must not qualify, got %v", err)
	}
}

// TestClosedPRKillsEveryPass: the question is moot, so every answer dies.
func TestClosedPRKillsEveryPass(t *testing.T) {
	tr := invalidation.NewTracker(func() time.Time { return g3now })

	a := tr.Start("env-a", 142, "abc123", 2, "smoke")
	b := tr.Start("env-b", 142, "abc123", 2, "isolation")
	if err := tr.Complete(a.ID, "pass"); err != nil {
		t.Fatalf("complete a: %v", err)
	}
	if err := tr.Complete(b.ID, "pass"); err != nil {
		t.Fatalf("complete b: %v", err)
	}

	tr.Invalidate(142, "", invalidation.CausePRClosed)
	if tr.Qualifies(a.ID) || tr.Qualifies(b.ID) {
		t.Fatal("no pass may survive its PR closing")
	}
}

// TestFullQualificationPathBindsEverything: the honest path, end to end — harness
// passes, evidence sealed and bound, confidence sufficient, run uninvalidated.
func TestFullQualificationPathBindsEverything(t *testing.T) {
	ctx := context.Background()

	// 1. The platform-owned harness passes.
	runner := harness.NewRunner(func() time.Time { return g3now })
	ev, err := runner.Run(ctx, harness.Scenario{
		Kind: harness.KindSmoke,
		Identity: harness.Identity{
			SourceSHA: "abc123", BaseSHA: "def456", ArtifactDigest: "sha256:aaa",
			ConfigDigest: "sha256:bbb", RecipeDigest: "sha256:ccc", PolicyDigest: "sha256:ddd",
			Generation: 2,
		},
		Timeout: time.Minute,
	}, harness.NewMockTarget(), nil)
	if err != nil {
		t.Fatalf("harness: %v", err)
	}
	if ev.Outcome != harness.OutcomePass {
		t.Fatalf("harness must pass, got %+v", ev)
	}

	// 2. The pass is sealed bound to the exact candidate.
	r := g3sealed(t, "pass", g3binding(2))
	if err := g3verifier(t).Verify(ctx, r, g3expectation(2)); err != nil {
		t.Fatalf("an honest pass must verify: %v", err)
	}

	// 3. The observations behind it are sufficient.
	obs := make([]confidence.Observation, 0, 100)
	for i := 0; i < 100; i++ {
		dim := "smoke"
		if i%2 == 0 {
			dim = "isolation"
		}
		obs = append(obs, confidence.Observation{Dimension: dim, Passed: true})
	}
	a := confidence.Assess(obs, confidence.Requirement{
		MinObservations: 30, Dimensions: []string{"smoke", "isolation"},
		MinLowerBound: 0.95, MaxFailureRate: 0.05,
	})
	if !confidence.Qualifies(a) {
		t.Fatalf("sufficient observations must qualify, got %+v", a)
	}

	// 4. The run is tracked and uninvalidated.
	tr := invalidation.NewTracker(func() time.Time { return g3now })
	run := tr.Start("env-1", 142, "abc123", 2, "smoke")
	if err := tr.Complete(run.ID, "pass"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !tr.Qualifies(run.ID) {
		t.Fatal("an uninvalidated pass must qualify")
	}

	// 5. The evidence is stored outside candidate write scope.
	store := evidencestore.NewStore(func() time.Time { return g3now })
	rec, err := store.Append(ctx, evidencestore.Write{
		ByRole: evidencestore.WriterHarness, Harness: "smoke",
		EnvironmentID: "env-1", Generation: 2, Outcome: "pass",
		Body: "smoke passed 100/100",
	})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if rec.ID == "" {
		t.Fatal("the stored record must be addressed")
	}
}

// TestGateBreaksInOrder: when several attacks combine, every layer still refuses.
// A gate whose layers interfere — where one attack disables another's refusal — is
// weaker than the sum of its layers.
func TestGateBreaksInOrder(t *testing.T) {
	ctx := context.Background()

	// Attack everything at once: edited result, stale generation, tiny sample,
	// candidate-written evidence.
	edited := g3sealed(t, "fail", g3binding(1))
	edited.Outcome = "pass"
	errSig := g3verifier(t).Verify(ctx, edited, g3expectation(3))

	tiny := confidence.Assess([]confidence.Observation{
		{Dimension: "smoke", Passed: true},
	}, confidence.Requirement{
		MinObservations: 30, Dimensions: []string{"smoke"},
		MinLowerBound: 0.95, MaxFailureRate: 0.05,
	})

	store := evidencestore.NewStore(func() time.Time { return g3now })
	_, errWrite := store.Append(ctx, evidencestore.Write{
		ByRole: "candidate", Harness: "smoke", EnvironmentID: "env-1",
		Generation: 3, Outcome: "pass", Body: "trust me",
	})

	if !errors.Is(errSig, evidence.ErrBadSignature) {
		t.Fatalf("the edited result must fail signature, got %v", errSig)
	}
	if tiny.Verdict != confidence.VerdictInconclusive {
		t.Fatalf("the tiny sample must be inconclusive, got %+v", tiny)
	}
	if !errors.Is(errWrite, evidencestore.ErrForbiddenWriter) {
		t.Fatalf("the candidate write must be refused, got %v", errWrite)
	}
}
