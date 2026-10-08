// Package plan turns a desired-state difference into a durable action intent.
//
// This is the step that connects the lifecycle state machine to the action ledger.
// Without it the reconciler has work to run but nothing decides what the work is.
//
// Two properties matter more than the individual phases:
//
//   - Planning is idempotent. Each phase produces a logical key derived from the
//     environment, generation and phase, so planning the same difference twice
//     resolves to the same action rather than creating a second one.
//   - Planning never executes. It produces intents. An intent must be durably
//     committed before anything touches an external system, so planning is safe to
//     repeat, safe to interrupt, and safe to run concurrently with another planner.
//
// The phase order comes from the lifecycle's provisioning order, where policy is
// installed before any candidate pod can be scheduled. A planner that reordered the
// phases would quietly remove that guarantee.
package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/actions"
	"github.com/sanskarpan/Ghostlight/internal/environments"
)

// ErrRefused is returned when a difference cannot be planned into work.
//
// A refusal is not a failure and never a silent skip: the caller records it so the
// environment shows why it is not progressing.
var ErrRefused = errors.New("planning refused")

// Refusal explains why no work was planned.
//
// It wraps ErrRefused so a caller can distinguish a deliberate refusal, which is
// normal operation, from a genuine failure, using errors.Is.
type Refusal struct {
	Reason string
}

func (r Refusal) Error() string { return "planning refused: " + r.Reason }

// Is reports this as a refusal rather than an arbitrary error.
func (r Refusal) Is(target error) bool { return target == ErrRefused }

// Refuse builds a refusal.
func Refuse(reason string) error { return Refusal{Reason: reason} }

// Intent is one planned action, not yet committed.
type Intent struct {
	Action *actions.Action
	// Phase is the provisioning or teardown phase this action serves.
	Phase environments.Phase
	// Teardown marks an action belonging to destruction rather than provisioning.
	Teardown bool
}

// Plan is an ordered set of intents for one environment generation.
type Plan struct {
	EnvironmentID string
	Generation    uint64
	Intents       []Intent
	// Refused carries the reason nothing was planned, if that is the case.
	Refused error
}

// Empty reports whether the plan contains no work.
func (p Plan) Empty() bool { return len(p.Intents) == 0 }

// Planner builds intents from a lifecycle difference.
type Planner struct {
	// profile bounds, used to refuse work that exceeds the profile rather than
	// planning it and failing later.
	Profile Profile
}

// Profile is the subset of profile bounds planning needs.
type Profile struct {
	// MaxActionsPerPass bounds one plan. A single plan must not be able to
	// monopolise a controller.
	MaxActionsPerPass int
	// MaxLifetimeHours is the qualified TTL ceiling.
	MaxLifetimeHours time.Duration
	// RequiresGateableCandidate refuses candidates that cannot be gated.
	RequiresGateableCandidate bool
}

// DefaultProfile returns the qualified 1.0 bounds.
func DefaultProfile() Profile {
	return Profile{
		MaxActionsPerPass:         16,
		MaxLifetimeHours:          72 * time.Hour,
		RequiresGateableCandidate: true,
	}
}

// Input is everything planning reads.
type Input struct {
	Env       environments.Environment
	Candidate environments.Candidate
	Now       time.Time
	// Dependencies the recipe declares. Planning refuses a candidate whose
	// dependency set is not a subset of the profile's supported set, rather than
	// planning allocation for a dependency that cannot be provisioned.
	RequiredDependencies []string
	// SupportedDependencies is the profile's qualified set.
	SupportedDependencies []string
}

// Plan produces the intents needed to move the environment toward its desired
// state.
//
// It returns a plan even when it refuses, so the caller can record the refusal
// against the environment rather than treating it as an error.
func (p Planner) Plan(in Input) Plan {
	out := Plan{EnvironmentID: in.Env.Identity.ID, Generation: in.Env.Generation}

	bound := p.Profile
	if bound.MaxActionsPerPass <= 0 {
		bound = DefaultProfile()
	}

	// A destroyed environment is terminal. Nothing is planned for it, and nothing
	// may plan its way back into existence.
	if in.Env.IsTerminal() {
		out.Refused = Refuse(fmt.Sprintf("environment %s is destroyed; its identifier is terminal",
			in.Env.Identity.ID))
		return out
	}

	// Teardown takes precedence over provisioning. A desired-absent environment is
	// being removed, and provisioning work for it would be nonsense.
	if in.Env.Desired == environments.DesiredAbsent {
		out.Intents = p.planTeardown(in, bound)
		return out
	}

	if err := p.admissible(in, bound); err != nil {
		out.Refused = err
		return out
	}

	out.Intents = p.planProvisioning(in, bound)
	return out
}

// admissible refuses work that cannot succeed.
//
// Refusing here rather than failing later means an operator sees the reason
// against the environment instead of watching actions fail repeatedly.
func (p Planner) admissible(in Input, bound Profile) error {
	if p.Profile.RequiresGateableCandidate || bound.RequiresGateableCandidate {
		if err := in.Candidate.Validate(); err != nil {
			return Refuse(err.Error())
		}
	}
	if err := in.Env.CanAdmit(in.Now); err != nil {
		return Refuse(err.Error())
	}
	if in.Env.Observed == environments.ObsQuarantined {
		return Refuse("environment is quarantined: " + in.Env.QuarantineReason)
	}
	// A degraded or failed environment does not record how far it reached, so
	// planning from it would either repeat completed work or skip incomplete work.
	// The recorded actions are the authority, and until they are inspected the
	// honest answer is to plan nothing.
	if _, known := provisioningReached(in.Env.Observed); !known {
		if in.Env.Observed == environments.ObsDegraded || in.Env.Observed == environments.ObsFailed {
			return Refuse(fmt.Sprintf("environment is %s; progress is not derivable from lifecycle state and must be read from recorded actions",
				in.Env.Observed))
		}
	}
	// A candidate asking for dependencies the profile cannot provision is refused
	// at planning time rather than half-allocated.
	if len(in.RequiredDependencies) > 0 && len(in.SupportedDependencies) > 0 {
		supported := toSet(in.SupportedDependencies)
		for _, d := range in.RequiredDependencies {
			if !supported[strings.ToLower(strings.TrimSpace(d))] {
				return Refuse(fmt.Sprintf("candidate requires dependency %q which this profile does not support", d))
			}
		}
	}
	if bound.MaxLifetimeHours > 0 && !in.Env.ExpiresAt.IsZero() {
		if in.Env.ExpiresAt.Sub(in.Now) > bound.MaxLifetimeHours {
			return Refuse(fmt.Sprintf("requested TTL exceeds the profile maximum of %v", bound.MaxLifetimeHours))
		}
	}
	return nil
}

// planProvisioning produces the phases from the current observed state up to ready.
//
// It emits only the phases that have not been completed. A phase already recorded
// for this generation is skipped, because re-planning it would be duplicate work.
func (p Planner) planProvisioning(in Input, bound Profile) []Intent {
	completed := in.Env.Observed

	var intents []Intent
	for _, phase := range environments.ProvisioningOrder() {
		if phase == environments.PhaseReady {
			// Reaching ready is a consequence of the gates, not an action. Something
			// must prove the candidate is healthy before the environment claims to
			// be ready, and planning an action that asserts readiness would let the
			// platform mark itself healthy without evidence.
			continue
		}
		if phaseCompleted(completed, phase) {
			continue
		}
		// Teardown is planned in reverse, so a partial teardown that reverses must
		// resume at the phase it reached rather than restarting.
		if p.isTeardownPhase(completed, phase) {
			continue
		}

		action, err := p.intentFor(in, phase, false)
		if err != nil {
			continue
		}
		intents = append(intents, Intent{Action: action, Phase: phase})
		if len(intents) >= bound.MaxActionsPerPass {
			break
		}
	}
	return intents
}

// planTeardown produces destruction phases in reverse.
//
// Order is the guarantee: ingress and claims stop before credentials are revoked,
// and credentials are revoked before data is destroyed. Destroying data while a
// credential is still live is how a leaked credential outlives its environment.
func (p Planner) planTeardown(in Input, bound Profile) []Intent {
	var intents []Intent
	order := environments.TeardownOrder()

	// Find where teardown stands. A provisioning state means teardown has not begun
	// and every phase runs; a teardown state means that phase has been entered and
	// everything before it is done, so it resumes from there rather than restarting.
	resumeAt := -1
	if teardownPhaseIndex(in.Env.Observed) >= 0 {
		resumeAt = teardownPhaseIndex(in.Env.Observed)
	}

	for i, state := range order {
		if i < resumeAt {
			// Already completed.
			continue
		}
		// Destroyed is terminal and is reached by verification, not by an action
		// asserting it.
		if state == environments.ObsDestroyed {
			continue
		}
		action, err := p.intentFor(in, "", true, teardownActionType(state))
		if err != nil {
			continue
		}
		intents = append(intents, Intent{Action: action, Teardown: true})
		if len(intents) >= bound.MaxActionsPerPass {
			break
		}
	}
	return intents
}

// phaseCompleted reports whether an observed state means the phase already ran.
//
// The observed lifecycle is the record of progress, so mapping states onto phases is
// what stops a planner re-emitting completed work.
func phaseCompleted(observed environments.ObservedLifecycle, phase environments.Phase) bool {
	reached, ok := provisioningReached(observed)
	if !ok {
		return false
	}
	return reached[phase]
}

// provisioningReached maps an observed state onto the phases completed by it.
//
// The mapping is explicit rather than derived from the phase index, because the
// observed lifecycle has more states than phases and several phases collapse into
// one state. Getting this wrong replans work that already succeeded, or skips work
// that has not run, so each state names exactly what it implies.
func provisioningReached(observed environments.ObservedLifecycle) (map[environments.Phase]bool, bool) {
	out := map[environments.Phase]bool{}

	// through lists the phases an observed state proves complete.
	through := func(phases ...environments.Phase) (map[environments.Phase]bool, bool) {
		for _, p := range phases {
			out[p] = true
		}
		return out, true
	}

	switch observed {
	case environments.ObsRequested:
		// Nothing has been done yet, not even admission.
		return out, true
	case environments.ObsAdmitted:
		return through(environments.PhaseAdmission)
	case environments.ObsAllocating:
		// Allocation is in progress, so the phases before dependencies are done.
		return through(environments.PhaseAdmission, environments.PhaseIdentity)
	case environments.ObsDeploying:
		// Dependencies and runtime policy are in place; the workload has not
		// rolled out yet.
		return through(
			environments.PhaseAdmission, environments.PhaseIdentity,
			environments.PhaseDependencies, environments.PhaseRuntimePolicy,
			environments.PhaseMigration, environments.PhaseSeed)
	case environments.ObsValidating:
		// The workload is live and health has been checked; gates are running.
		return through(
			environments.PhaseAdmission, environments.PhaseIdentity,
			environments.PhaseDependencies, environments.PhaseRuntimePolicy,
			environments.PhaseMigration, environments.PhaseSeed,
			environments.PhaseRollout, environments.PhaseHealth)
	case environments.ObsReady:
		// Ready means the gates passed. It is only reachable through the
		// validating state, so every phase is complete.
		return through(
			environments.PhaseAdmission, environments.PhaseIdentity,
			environments.PhaseDependencies, environments.PhaseRuntimePolicy,
			environments.PhaseMigration, environments.PhaseSeed,
			environments.PhaseRollout, environments.PhaseHealth,
			environments.PhaseGates)
	case environments.ObsDegraded, environments.ObsFailed:
		// A recoverable failure does not record how far it got. The lifecycle state
		// machine deliberately does not self-advance out of these, so the progress
		// is whatever the actions recorded. Planning from here would either repeat
		// completed phases or skip incomplete ones, so the planner refuses instead
		// of guessing.
		return nil, false
	default:
		return nil, false
	}
}

// isTeardownPhase reports whether provisioning is irrelevant because the
// environment is being destroyed.
func (p Planner) isTeardownPhase(observed environments.ObservedLifecycle, phase environments.Phase) bool {
	switch observed {
	case environments.ObsDraining, environments.ObsRevoking, environments.ObsDestroying,
		environments.ObsCleanupVerifying:
		return true
	}
	return false
}

// intentFor builds one durable intent.
func (p Planner) intentFor(in Input, phase environments.Phase, teardown bool, override ...actions.Type) (*actions.Action, error) {
	actionType := actionTypeFor(phase)
	if len(override) > 0 {
		actionType = override[0]
	}

	// The logical key is derived from environment, generation, phase and type. It is
	// what makes planning idempotent: the same difference planned twice resolves to
	// the same row rather than creating a second action.
	key := logicalKey(in.Env.Identity.ID, in.Env.Generation, phase, actionType)

	digest := inputDigest(in.Candidate, phase, actionType)

	a, err := actions.New(in.Env.Identity.ID, in.Env.Generation, actionType, key,
		digest, resourceScope(phase), in.Now)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// actionTypeFor maps a provisioning phase to the work it performs.
func actionTypeFor(phase environments.Phase) actions.Type {
	switch phase {
	case environments.PhaseAdmission:
		return actions.TypeReserve
	case environments.PhaseIdentity:
		return actions.TypeAllocate
	case environments.PhaseDependencies:
		return actions.TypeAllocate
	case environments.PhaseRuntimePolicy:
		return actions.TypeAllocate
	case environments.PhaseMigration:
		return actions.TypeMigrate
	case environments.PhaseSeed:
		return actions.TypeSeed
	case environments.PhaseRollout:
		return actions.TypeRollout
	case environments.PhaseHealth:
		return actions.TypeHealth
	case environments.PhaseGates:
		return actions.TypeGate
	}
	return actions.TypeReserve
}

// teardownActionType maps a destruction state to the work that advances it.
func teardownActionType(state environments.ObservedLifecycle) actions.Type {
	switch state {
	case environments.ObsDraining:
		return actions.TypeDrain
	case environments.ObsRevoking:
		return actions.TypeRevoke
	case environments.ObsDestroying:
		return actions.TypeDestroy
	case environments.ObsCleanupVerifying:
		return actions.TypeVerifyAbsent
	}
	return actions.TypeDestroy
}

// resourceScope names the logical resources a phase may touch.
//
// The scope is checked before deletion, so it is deliberately narrow and names
// logical classes rather than cloud objects.
func resourceScope(phase environments.Phase) []string {
	switch phase {
	case environments.PhaseIdentity:
		return []string{"identity", "service_account"}
	case environments.PhaseDependencies:
		return []string{"dep/postgres", "dep/redis", "dep/kafka", "dep/workflow", "dep/object_store"}
	case environments.PhaseRuntimePolicy:
		return []string{"policy/namespace", "policy/network", "policy/egress", "policy/pod"}
	case environments.PhaseMigration:
		return []string{"dep/postgres/schema"}
	case environments.PhaseSeed:
		return []string{"dep/postgres/fixtures"}
	case environments.PhaseRollout:
		return []string{"workload"}
	}
	return []string{}
}

// logicalKey builds the idempotency key for a planned phase.
func logicalKey(envID string, generation uint64, phase environments.Phase, t actions.Type) string {
	// Phase is empty for teardown, so the action type distinguishes those.
	return fmt.Sprintf("%s/g%d/%s/%s", envID, generation, phase, t)
}

// inputDigest pins the arguments of a planned action.
//
// Two plans of the same generation produce the same digest, which is what lets the
// ledger treat them as the same work. A different candidate digest produces a
// different action rather than silently reusing the previous intent.
func inputDigest(c environments.Candidate, phase environments.Phase, t actions.Type) string {
	h := sha256.New()
	for _, part := range []string{
		c.SourceSHA, c.BaseSHA, c.ArtifactDigest, c.ConfigDigest,
		c.MigrationDigest, c.EventSchemaDigest, c.RecipeDigest, c.PolicyDigest,
		string(phase), string(t),
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// LogKey renders a plan for a log line.
func LogKey(p Plan) string {
	keys := make([]string, 0, len(p.Intents))
	for _, i := range p.Intents {
		keys = append(keys, i.Action.LogicalKey)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// teardownPhaseIndex returns the position of a state within the teardown order, or
// -1 when the state is a provisioning state and teardown has not begun.
func teardownPhaseIndex(observed environments.ObservedLifecycle) int {
	for i, state := range environments.TeardownOrder() {
		if state == observed {
			return i
		}
	}
	return -1
}

func toSet(items []string) map[string]bool {
	out := map[string]bool{}
	for _, i := range items {
		out[strings.ToLower(strings.TrimSpace(i))] = true
	}
	return out
}
