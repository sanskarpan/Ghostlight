package plan_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/actions"
	"github.com/sanskarpan/Ghostlight/internal/environments"
	"github.com/sanskarpan/Ghostlight/internal/plan"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func candidate() environments.Candidate {
	return environments.Candidate{
		SourceSHA:         "1111111111111111111111111111111111111111",
		BaseSHA:           "2222222222222222222222222222222222222222",
		ArtifactDigest:    "sha256:aaaa",
		ConfigDigest:      "sha256:bbbb",
		MigrationDigest:   "sha256:cccc",
		EventSchemaDigest: "sha256:dddd",
		RecipeDigest:      "sha256:eeee",
		PolicyDigest:      "sha256:ffff",
	}
}

func envAt(observed environments.ObservedLifecycle, desired environments.DesiredLifecycle, gen uint64) environments.Environment {
	return environments.Environment{
		Identity:   environments.Identity{ID: "env-01HQ", Slug: "pr-142-a7d32c"},
		Repository: "repo-1",
		Desired:    desired,
		Observed:   observed,
		Runtime:    environments.RuntimeRunning,
		Generation: gen,
		Candidate:  candidate(),
		ExpiresAt:  now.Add(24 * time.Hour),
	}
}

func input(e environments.Environment) plan.Input {
	return plan.Input{
		Env: e, Candidate: e.Candidate, Now: now,
		RequiredDependencies:  []string{"postgres", "redis"},
		SupportedDependencies: []string{"postgres", "redis", "kafka", "workflow", "object_store", "identity"},
	}
}

func planner() plan.Planner { return plan.Planner{Profile: plan.DefaultProfile()} }

// keys returns the logical keys of a plan, in order.
func keys(p plan.Plan) []string {
	out := make([]string, 0, len(p.Intents))
	for _, i := range p.Intents {
		out = append(out, i.Action.LogicalKey)
	}
	return out
}

func types(p plan.Plan) []actions.Type {
	out := make([]actions.Type, 0, len(p.Intents))
	for _, i := range p.Intents {
		out = append(out, i.Action.Type)
	}
	return out
}

// TestProvisioningStartsFromAdmission is the baseline: a requested environment has
// nothing done, so the first phase is planned.
func TestProvisioningStartsFromAdmission(t *testing.T) {
	got := planner().Plan(input(envAt(environments.ObsRequested, environments.DesiredPresent, 1)))
	if got.Refused != nil {
		t.Fatalf("unexpected refusal: %v", got.Refused)
	}
	if got.Empty() {
		t.Fatal("a requested environment must produce work")
	}
	if types(got)[0] != actions.TypeReserve {
		t.Fatalf("the first planned action must be a reservation, got %s", types(got)[0])
	}
}

// TestRuntimePolicyPrecedesAnyCandidateWork is the ordering guarantee: policy is
// installed before candidate pods can be scheduled.
func TestRuntimePolicyPrecedesAnyCandidateWork(t *testing.T) {
	got := planner().Plan(input(envAt(environments.ObsRequested, environments.DesiredPresent, 1)))

	policyIdx, rolloutIdx, migrateIdx := -1, -1, -1
	for i, intent := range got.Intents {
		switch intent.Phase {
		case environments.PhaseRuntimePolicy:
			policyIdx = i
		case environments.PhaseRollout:
			rolloutIdx = i
		case environments.PhaseMigration:
			migrateIdx = i
		}
	}
	if policyIdx < 0 {
		t.Fatal("runtime policy must be planned")
	}
	if rolloutIdx < 0 {
		t.Fatal("rollout must be planned")
	}
	if policyIdx > rolloutIdx {
		t.Fatal("runtime policy must be installed before any candidate workload is rolled out")
	}
	if migrateIdx > rolloutIdx {
		t.Fatal("migration must precede rollout")
	}
}

// TestReadyIsNeverPlannedAsAnAction is the anti-self-attestation rule: the platform
// must not plan an action that asserts its own health.
func TestReadyIsNeverPlannedAsAnAction(t *testing.T) {
	got := planner().Plan(input(envAt(environments.ObsRequested, environments.DesiredPresent, 1)))
	for _, intent := range got.Intents {
		if intent.Phase == environments.PhaseReady {
			t.Fatal("ready must never be a planned action; it is proven by gates")
		}
	}
}

// TestPlanningIsIdempotent is the core property: planning the same difference twice
// must resolve to the same logical keys, or the ledger creates duplicate work.
func TestPlanningIsIdempotent(t *testing.T) {
	p := planner()
	in := input(envAt(environments.ObsRequested, environments.DesiredPresent, 3))

	first := keys(p.Plan(in))
	second := keys(p.Plan(in))

	if len(first) != len(second) {
		t.Fatalf("planning twice produced different lengths: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("plan %d differs between runs: %q vs %q", i, first[i], second[i])
		}
	}
}

// TestGenerationIsPartOfTheLogicalKey checks a new generation plans distinct work.
func TestGenerationIsPartOfTheLogicalKey(t *testing.T) {
	p := planner()
	g1 := keys(p.Plan(input(envAt(environments.ObsRequested, environments.DesiredPresent, 1))))
	g2 := keys(p.Plan(input(envAt(environments.ObsRequested, environments.DesiredPresent, 2))))

	same := 0
	for i := range g1 {
		if i < len(g2) && g1[i] == g2[i] {
			same++
		}
	}
	if same > 0 {
		t.Fatalf("a new generation must plan distinct work; %d keys were reused", same)
	}
}

// TestCandidateChangeProducesADifferentIntentDigest checks a different candidate is
// not silently served by an intent planned for the previous one.
func TestCandidateChangeProducesADifferentIntentDigest(t *testing.T) {
	p := planner()

	in := input(envAt(environments.ObsRequested, environments.DesiredPresent, 1))
	first := p.Plan(in).Intents[0].Action.InputDigest

	changed := input(envAt(environments.ObsRequested, environments.DesiredPresent, 1))
	changed.Candidate.ArtifactDigest = "sha256:changed"
	second := p.Plan(changed).Intents[0].Action.InputDigest

	if first == second {
		t.Fatal("a different candidate must produce a different intent digest")
	}
}

// TestCompletedPhasesAreNotReplanned stops a planner re-emitting finished work.
func TestCompletedPhasesAreNotReplanned(t *testing.T) {
	// An environment already deploying has passed admission, identity and
	// dependencies, so those phases must not be planned again.
	got := planner().Plan(input(envAt(environments.ObsDeploying, environments.DesiredPresent, 1)))

	for _, intent := range got.Intents {
		switch intent.Phase {
		case environments.PhaseAdmission, environments.PhaseIdentity, environments.PhaseDependencies:
			t.Fatalf("phase %s already completed and must not be replanned", intent.Phase)
		}
	}
	if got.Empty() {
		t.Fatal("a deploying environment still has migration, seed, rollout and health to do")
	}
}

// TestFailedEnvironmentDoesNotResurrectEarlierPhases pins that a recoverable
// failure does not re-run work that already succeeded.
func TestFailedEnvironmentDoesNotResurrectEarlierPhases(t *testing.T) {
	got := planner().Plan(input(envAt(environments.ObsFailed, environments.DesiredPresent, 1)))
	for _, intent := range got.Intents {
		switch intent.Phase {
		case environments.PhaseAdmission, environments.PhaseIdentity, environments.PhaseDependencies:
			t.Fatalf("a failed environment must not replan completed phase %s", intent.Phase)
		}
	}
}

// TestTeardownPrecedesProvisioningAndIsOrdered guards the destruction order:
// credentials are revoked before data is destroyed.
func TestTeardownPrecedesProvisioningAndIsOrdered(t *testing.T) {
	got := planner().Plan(input(envAt(environments.ObsReady, environments.DesiredAbsent, 1)))

	if got.Refused != nil {
		t.Fatalf("unexpected refusal: %v", got.Refused)
	}
	if got.Empty() {
		t.Fatal("a desired-absent environment must plan teardown")
	}

	idx := map[actions.Type]int{}
	for i, intent := range got.Intents {
		if _, seen := idx[intent.Action.Type]; !seen {
			idx[intent.Action.Type] = i
		}
	}
	drain, hasDrain := idx[actions.TypeDrain]
	revoke, hasRevoke := idx[actions.TypeRevoke]
	destroy, hasDestroy := idx[actions.TypeDestroy]
	verify, hasVerify := idx[actions.TypeVerifyAbsent]

	if !hasDrain || !hasRevoke || !hasDestroy || !hasVerify {
		t.Fatalf("teardown must plan drain, revoke, destroy and verify; got %v", idx)
	}
	if drain > revoke {
		t.Fatal("drain must precede revoke so nothing uses credentials while they are removed")
	}
	if revoke > destroy {
		t.Fatal("revoke must precede destroy so a leaked credential cannot outlive its data")
	}
	if destroy > verify {
		t.Fatal("absence must be verified after destruction, not asserted instead of it")
	}

	for _, intent := range got.Intents {
		if !intent.Teardown {
			t.Fatal("a desired-absent environment must not plan provisioning work")
		}
	}
}

// TestDestroyedEnvironmentIsNeverPlannedFor is the terminal rule.
func TestDestroyedEnvironmentIsNeverPlannedFor(t *testing.T) {
	got := planner().Plan(input(envAt(environments.ObsDestroyed, environments.DesiredAbsent, 1)))
	if !got.Empty() {
		t.Fatalf("a destroyed environment must plan nothing, got %v", keys(got))
	}
	if got.Refused == nil {
		t.Fatal("planning for a destroyed environment must be refused with a reason")
	}
	if !strings.Contains(got.Refused.Error(), "terminal") {
		t.Fatalf("the refusal must explain terminality, got %q", got.Refused)
	}
}

// TestUngateableCandidateIsRefused means a candidate that cannot bind a policy is
// never provisioned.
func TestUngateableCandidateIsRefused(t *testing.T) {
	in := input(envAt(environments.ObsRequested, environments.DesiredPresent, 1))
	in.Candidate.PolicyDigest = ""
	in.Env.Candidate = in.Candidate

	got := planner().Plan(in)
	if !got.Empty() {
		t.Fatal("an ungateable candidate must produce no work")
	}
	if got.Refused == nil {
		t.Fatal("an ungateable candidate must be refused with a reason")
	}
}

// TestUnsupportedDependencyIsRefusedAtPlanningTime avoids half-allocating a
// dependency the profile cannot provision.
func TestUnsupportedDependencyIsRefusedAtPlanningTime(t *testing.T) {
	in := input(envAt(environments.ObsRequested, environments.DesiredPresent, 1))
	in.RequiredDependencies = []string{"postgres", "vector-database"}

	got := planner().Plan(in)
	if !got.Empty() {
		t.Fatalf("an unsupported dependency must plan nothing, got %v", keys(got))
	}
	if got.Refused == nil || !strings.Contains(got.Refused.Error(), "vector-database") {
		t.Fatalf("the refusal must name the unsupported dependency, got %v", got.Refused)
	}
}

// TestSupportedDependencyIsAccepted guards against an over-eager refusal that would
// block a valid candidate.
func TestSupportedDependencyIsAccepted(t *testing.T) {
	in := input(envAt(environments.ObsRequested, environments.DesiredPresent, 1))
	in.RequiredDependencies = []string{"postgres"}
	if got := planner().Plan(in); got.Refused != nil {
		t.Fatalf("a supported dependency must not be refused: %v", got.Refused)
	}
}

// TestExpiredEnvironmentIsNotPlanned is the TTL guarantee: expiry does not wait for
// a gate, and an expired environment must not receive new work.
func TestExpiredEnvironmentIsNotPlanned(t *testing.T) {
	e := envAt(environments.ObsReady, environments.DesiredPresent, 1)
	e.ExpiresAt = now.Add(-time.Minute)

	got := planner().Plan(input(e))
	if !got.Empty() {
		t.Fatalf("an expired environment must not receive new work, got %v", keys(got))
	}
	if got.Refused == nil {
		t.Fatal("an expired environment must be refused with a reason")
	}
}

// TestTTLOverProfileMaximumIsRefused means an over-long request is refused at
// planning rather than truncated later.
func TestTTLOverProfileMaximumIsRefused(t *testing.T) {
	e := envAt(environments.ObsRequested, environments.DesiredPresent, 1)
	e.ExpiresAt = now.Add(30 * 24 * time.Hour)

	got := planner().Plan(input(e))
	if !got.Empty() {
		t.Fatal("a TTL beyond the profile maximum must plan nothing")
	}
	if got.Refused == nil || !strings.Contains(got.Refused.Error(), "TTL") {
		t.Fatalf("the refusal must name the TTL, got %v", got.Refused)
	}
}

// TestQuarantinedEnvironmentIsRefused.
func TestQuarantinedEnvironmentIsRefused(t *testing.T) {
	e := envAt(environments.ObsQuarantined, environments.DesiredPresent, 1)
	e.QuarantineReason = "fault removal unverified"

	got := planner().Plan(input(e))
	if !got.Empty() {
		t.Fatal("a quarantined environment must plan nothing")
	}
	if got.Refused == nil || !strings.Contains(got.Refused.Error(), "quarantined") {
		t.Fatalf("the refusal must name quarantine, got %v", got.Refused)
	}
}

// TestPlanIsBounded stops one difference monopolising a controller.
func TestPlanIsBounded(t *testing.T) {
	bounded := plan.Planner{Profile: plan.Profile{
		MaxActionsPerPass:         2,
		MaxLifetimeHours:          72 * time.Hour,
		RequiresGateableCandidate: true,
	}}
	got := bounded.Plan(input(envAt(environments.ObsRequested, environments.DesiredPresent, 1)))
	if len(got.Intents) > 2 {
		t.Fatalf("a plan must respect its bound, got %d intents", len(got.Intents))
	}
}

// TestZeroBoundFallsBackToDefault guards against a misconfigured zero limit
// silently disabling planning.
func TestZeroBoundFallsBackToDefault(t *testing.T) {
	zero := plan.Planner{Profile: plan.Profile{MaxActionsPerPass: 0}}
	got := zero.Plan(input(envAt(environments.ObsRequested, environments.DesiredPresent, 1)))
	if got.Empty() {
		t.Fatal("a zero bound must fall back to the default rather than plan nothing")
	}
}

// TestIntentsCarryTheirEnvironmentGeneration is the fence precondition.
func TestIntentsCarryTheirEnvironmentGeneration(t *testing.T) {
	got := planner().Plan(input(envAt(environments.ObsRequested, environments.DesiredPresent, 7)))
	for _, intent := range got.Intents {
		a := intent.Action
		if a.Generation != 7 {
			t.Fatalf("intent %s carries generation %d, expected 7", a.LogicalKey, a.Generation)
		}
		if a.Fencing.ExpectedGeneration != 7 {
			t.Fatalf("intent %s must record the expected generation in its fence", a.LogicalKey)
		}
		if a.EnvironmentID != "env-01HQ" {
			t.Fatalf("intent %s names the wrong environment", a.LogicalKey)
		}
	}
}

// TestIntentsAreNeverTerminalBeforeExecution guards the intent-before-work rule.
func TestIntentsAreNeverTerminalBeforeExecution(t *testing.T) {
	got := planner().Plan(input(envAt(environments.ObsRequested, environments.DesiredPresent, 1)))
	for _, intent := range got.Intents {
		if intent.Action.State.Terminal() {
			t.Fatalf("a planned intent must not be terminal before execution, got %s", intent.Action.State)
		}
		if intent.Action.State != actions.StatePlanned {
			t.Fatalf("a planned intent must start planned, got %s", intent.Action.State)
		}
	}
}

// TestResourceScopeIsNarrow checks deletion authority is bounded by phase.
func TestResourceScopeIsNarrow(t *testing.T) {
	got := planner().Plan(input(envAt(environments.ObsRequested, environments.DesiredPresent, 1)))
	for _, intent := range got.Intents {
		for _, scope := range intent.Action.ResourceScope {
			if strings.Contains(scope, "foundation") {
				t.Fatalf("intent %s may not scope a shared foundation resource: %q",
					intent.Action.LogicalKey, scope)
			}
		}
	}
}

// TestPartialTeardownResumesRatherThanRestarts is the resume property: a teardown
// that reached revocation must continue from there.
func TestPartialTeardownResumesRatherThanRestarts(t *testing.T) {
	got := planner().Plan(input(envAt(environments.ObsRevoking, environments.DesiredAbsent, 1)))
	for _, intent := range got.Intents {
		if intent.Action.Type == actions.TypeDrain {
			t.Fatal("drain already completed; a resumed teardown must not restart it")
		}
	}
	if got.Empty() {
		t.Fatal("a resumed teardown must still have work to do")
	}
}

// TestRefusalTypeIsDistinguishable lets a caller tell a refusal from a failure.
func TestRefusalTypeIsDistinguishable(t *testing.T) {
	err := plan.Refuse("because")
	if err == nil {
		t.Fatal("Refuse must produce an error")
	}
	if !strings.Contains(err.Error(), "because") {
		t.Fatalf("the reason must be visible, got %q", err)
	}
	// It must satisfy errors.Is against ErrRefused so callers can branch on it.
	if !errors.Is(err, plan.ErrRefused) {
		t.Fatal("a refusal must satisfy errors.Is(err, ErrRefused)")
	}
}

// TestEveryPlannedPhaseHasAKnownActionType guards against a new phase silently
// mapping to a placeholder.
func TestEveryPlannedPhaseHasAKnownActionType(t *testing.T) {
	got := planner().Plan(input(envAt(environments.ObsRequested, environments.DesiredPresent, 1)))
	known := map[actions.Type]bool{
		actions.TypeReserve: true, actions.TypeAllocate: true, actions.TypeMigrate: true,
		actions.TypeSeed: true, actions.TypeRollout: true, actions.TypeHealth: true,
		actions.TypeGate: true,
	}
	for _, intent := range got.Intents {
		if !known[intent.Action.Type] {
			t.Fatalf("phase %s mapped to unknown action type %s", intent.Phase, intent.Action.Type)
		}
	}
}

// TestPlanLogKeyIsStable makes a plan debuggable without being order-dependent in a
// way that hides real changes.
func TestPlanLogKeyIsStable(t *testing.T) {
	p := planner()
	in := input(envAt(environments.ObsRequested, environments.DesiredPresent, 1))
	a, b := plan.LogKey(p.Plan(in)), plan.LogKey(p.Plan(in))
	if a != b {
		t.Fatalf("log key must be stable: %q vs %q", a, b)
	}
	if a == "" {
		t.Fatal("a non-empty plan must produce a log key")
	}
}
