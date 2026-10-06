package environments

import (
	"errors"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func validCandidate() Candidate {
	return Candidate{
		SourceSHA:         "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
		BaseSHA:           "0f9e8d7c6b5a4938271605f4e3d2c1b0a99887766",
		ArtifactDigest:    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		ConfigDigest:      "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		MigrationDigest:   "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		EventSchemaDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444",
		RecipeDigest:      "sha256:5555555555555555555555555555555555555555555555555555555555555555",
		PolicyDigest:      "sha256:6666666666666666666666666666666666666666666666666666666666666666",
	}
}

func freshEnv() Environment {
	return Environment{
		Identity:   Identity{ID: "env-01HQ", Slug: "pr-142-a7d32c"},
		Repository: "repo-1",
		Desired:    DesiredPresent,
		Observed:   ObsRequested,
		Runtime:    RuntimeRunning,
		Candidate:  validCandidate(),
		ExpiresAt:  testNow.Add(24 * time.Hour),
	}
}

// driveTo advances an environment to a target state through the happy path.
func driveTo(t *testing.T, e *Environment, target ObservedLifecycle) {
	t.Helper()
	for i := 0; i < 32; i++ {
		if e.Observed == target {
			return
		}
		if !e.Advance() {
			t.Fatalf("cannot advance from %s toward %s", e.Observed, target)
		}
	}
	t.Fatalf("did not reach %s, stuck at %s", target, e.Observed)
}

func TestCandidateRequiresExactIdentity(t *testing.T) {
	c := validCandidate()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid candidate rejected: %v", err)
	}

	// A candidate without a policy digest cannot be gated, so it must not be
	// admitted. This is the G0.6 fix: policy_digest is not optional.
	c.PolicyDigest = ""
	if err := c.Validate(); err == nil {
		t.Fatal("candidate without policy_digest was accepted; it could never be gate-bound")
	}
	if c.Gateable() {
		t.Fatal("Gateable returned true for a candidate with no policy digest")
	}
}

func TestProvisioningOrderInstallsPolicyBeforePods(t *testing.T) {
	order := ProvisioningOrder()
	idx := map[Phase]int{}
	for i, p := range order {
		idx[p] = i
	}
	for _, before := range []Phase{PhaseRuntimePolicy, PhaseMigration} {
		for _, after := range []Phase{PhaseRollout, PhaseHealth, PhaseGates, PhaseReady} {
			if idx[before] > idx[after] {
				t.Fatalf("%s must precede %s: policy and migration come before candidate pods", before, after)
			}
		}
	}
	if idx[PhaseReady] != len(order)-1 {
		t.Fatal("ready must be the final provisioning phase")
	}
}

func TestHappyPathReachesReady(t *testing.T) {
	e := freshEnv()
	driveTo(t, &e, ObsReady)
	if e.Observed != ObsReady {
		t.Fatalf("expected ready, got %s", e.Observed)
	}
	// Ready is terminal on the happy path until desired changes.
	if e.Advance() {
		t.Fatal("a ready environment must not advance further on its own")
	}
}

func TestDestroyedIsTerminalForThatIdentifier(t *testing.T) {
	e := freshEnv()
	driveTo(t, &e, ObsReady)
	e.Desired = DesiredAbsent
	for _, want := range []ObservedLifecycle{ObsDraining, ObsRevoking, ObsDestroying, ObsCleanupVerifying, ObsDestroyed} {
		if !e.Advance() {
			t.Fatalf("teardown stalled at %s before reaching %s", e.Observed, want)
		}
		if e.Observed != want {
			t.Fatalf("expected %s, got %s", want, e.Observed)
		}
	}
	if !e.IsTerminal() {
		t.Fatal("destroyed must be terminal")
	}
	if e.Advance() {
		t.Fatal("destroyed must not advance; the identifier is terminal")
	}
	if err := e.CanAdmit(testNow); !errors.Is(err, ErrDestroyedIsFinal) {
		t.Fatalf("expected ErrDestroyedIsFinal, got %v", err)
	}
}

func TestDesiredAbsentOverridesEverything(t *testing.T) {
	// Even a healthy, unexpired, running environment tears down when intent is
	// absent. Desired absent always wins.
	e := freshEnv()
	driveTo(t, &e, ObsReady)
	e.Runtime = RuntimeSuspended
	e.Desired = DesiredAbsent
	if !e.Advance() || e.Observed != ObsDraining {
		t.Fatalf("desired absent must force draining, got %s", e.Observed)
	}
	if err := e.CanAdmit(testNow); err == nil {
		t.Fatal("admission must be refused while tearing down")
	}
}

func TestDegradedAndFailedDoNotSelfAdvance(t *testing.T) {
	for _, state := range []ObservedLifecycle{ObsDegraded, ObsFailed} {
		e := freshEnv()
		driveTo(t, &e, ObsDeploying)
		e.Observed = state
		if e.Advance() {
			t.Fatalf("%s must not self-advance; recovery requires an observed action result", state)
		}
	}
}

func TestExpiryDrivesTeardownAndIsNotOverriddenByReady(t *testing.T) {
	e := freshEnv()
	driveTo(t, &e, ObsReady)

	// Not yet expired.
	if e.Expired(testNow) || e.ShouldTeardown(testNow) {
		t.Fatal("environment expired before its TTL")
	}

	// Expired. Expiry does not wait for a successful gate.
	after := e.ExpiresAt.Add(time.Second)
	if !e.Expired(after) {
		t.Fatal("expected expiry past expires_at")
	}
	if !e.ShouldTeardown(after) {
		t.Fatal("watchdog must request teardown on expiry")
	}
	if err := e.CanAdmit(after); err == nil {
		t.Fatal("an expired environment must not admit a new generation")
	}
}

func TestWatchdogDoesNotRequestTeardownTwice(t *testing.T) {
	e := freshEnv()
	e.ExpiresAt = testNow.Add(-time.Hour)
	e.Desired = DesiredAbsent // watchdog already acted
	if e.ShouldTeardown(testNow) {
		t.Fatal("watchdog must be idempotent; teardown is already requested")
	}
}

func TestQuarantineBlocksAdmission(t *testing.T) {
	e := freshEnv()
	e.Observed = ObsQuarantined
	e.QuarantineReason = "fault removal unverified"
	d := Admit(e, validCandidate(), testNow, true)
	if d.Allowed {
		t.Fatal("a quarantined environment must not admit a new generation")
	}
	if d.Reason == "" {
		t.Fatal("a refusal must carry an inspectable reason")
	}
}

func TestAdmissionRefusesUngateableCandidate(t *testing.T) {
	e := freshEnv()
	c := validCandidate()
	c.RecipeDigest = ""
	d := Admit(e, c, testNow, true)
	if d.Allowed {
		t.Fatal("a candidate without a recipe digest must not be admitted")
	}
}

func TestAdmissionRefusesTTLOverProfileMaximum(t *testing.T) {
	e := freshEnv()
	d := Admit(e, validCandidate(), testNow, false)
	if d.Allowed {
		t.Fatal("a TTL beyond the profile maximum must be refused; the client value is a request, not authority")
	}
}

func TestGenerationIsTheFence(t *testing.T) {
	e := freshEnv()
	start := e.Generation
	e.Generation = nextGeneration(start)
	if e.Generation != start+1 {
		t.Fatalf("generation must increment on admitted change, got %d", e.Generation)
	}
	// Two different candidates are distinguishable by identity alone, which is
	// what lets a gate result be refused for a newer candidate.
	other := validCandidate()
	other.ArtifactDigest = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	if other.ArtifactDigest == e.Candidate.ArtifactDigest {
		t.Fatal("test setup: candidates must differ")
	}
	if other == e.Candidate {
		t.Fatal("candidate identity must be value-comparable for fencing")
	}
}

func TestIdentityMustNotBeDerivedFromUserInput(t *testing.T) {
	// The slug is platform-generated. An identity missing either half cannot be
	// used to create or clean up resources.
	var bad Identity
	if bad.Valid() {
		t.Fatal("zero identity must be invalid")
	}
	if (Identity{ID: "env-1"}).Valid() {
		t.Fatal("identity without a slug is not usable")
	}
	if (Identity{Slug: "pr-142"}).Valid() {
		t.Fatal("identity without an immutable ID is not usable")
	}
	good := Identity{ID: "env-01HQ", Slug: "pr-142-a7d32c"}
	if !good.Valid() {
		t.Fatal("complete identity must be valid")
	}
}

func TestTeardownOrderRevokesBeforeDestroying(t *testing.T) {
	order := TeardownOrder()
	idx := map[ObservedLifecycle]int{}
	for i, s := range order {
		idx[s] = i
	}
	// Credentials are revoked before data is destroyed, and absence is verified
	// after destruction rather than assumed from it.
	if idx[ObsRevoking] > idx[ObsDestroying] {
		t.Fatal("revocation must precede destruction")
	}
	if idx[ObsDestroying] > idx[ObsCleanupVerifying] {
		t.Fatal("verification must follow destruction")
	}
	if idx[ObsCleanupVerifying] > idx[ObsDestroyed] {
		t.Fatal("destroyed must follow verified cleanup")
	}
}
