// Package console builds the view model the primary console renders.
//
// The console is where an operator finds out whether an environment is progressing,
// whether an action can be taken, and whether anything is standing in the way. It is
// the surface the product's own checklist row names: an accessible console with a
// queue, progress and resource timeline, where the failure, quota and cleanup states
// are actionable, and where the keyboard and narrow-screen review and abort tasks
// work.
//
// Most of the rules here are structural rather than advisory. A rule that lives only
// in a document is a rule the next renderer will quietly break, so each one is a
// function that refuses, and each refusal names the thing that was missing.
//
// The first property is that **progress is read from the recorded actions, not from
// the lifecycle state**. A lifecycle that self-advances cannot say how far a run got
// once it has degraded or failed, so the timeline is built from what was actually
// recorded. Every phase appears in the timeline whether or not anything was recorded
// for it, so a renderer never has to invent a missing row.
//
// The second is that **an uncertain outcome is neither a success nor a failure**. A
// native call that never reported back is unknown, and a console that paints it green
// or red is telling the operator something it does not know. Uncertain outcomes
// therefore have their own state, they are never folded into "complete" and never
// into "failed", and an unresolved phase blocks every later phase, because a later
// phase cannot be claimed complete while an earlier one is unresolved.
//
// The third is that **an action without a reason is not actionable**. A spinner that
// does not say what it is waiting for, and a denial without a recovery hint, are the
// two commonest ways a console leaves an operator stuck. The states that need an
// explanation require one, the states that need a way forward require that too, and a
// success carries a durable operation and version so that "it worked" can be audited
// and repeated.
//
// The fourth is that **meaning must not depend on colour**. A status badge carries a
// text label and a glyph, two different states never share a glyph, a chart carries a
// table alternative with bounded rows, and an over-large table is refused rather than
// truncated, because a truncated table that looks complete is a table that hides
// data.
//
// The fifth is that **the review and abort tasks must be reachable**. Every control
// has an accessible name, a unique focus order and a keyboard route to it, and a live
// region may not obscure the abort control, because a chart that updates over the stop
// button is exactly the failure the requirement names.
//
// The sixth is that **one tenant's console never shows another tenant's data**. Every
// counter and every search is scoped to the organization and its projects, and the
// scope is applied again here even when the caller believes it has already scoped the
// set, because a scoping mistake upstream must not leak repository names.
//
// The seventh is that **untrusted output is inert**. Log content is capped and its ANSI
// escape sequences are stripped so that a terminal cannot interpret them, and HTML
// escaping is available for the fields that carry untrusted text, because a log line
// containing markup must not become markup.
package console

import (
	"errors"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Errors returned by this package's console rules.
var (
	// ErrNoActionReason means an action in a state that needs an explanation
	// carried none.
	ErrNoActionReason = errors.New("action must carry a reason")
	// ErrNoRecoveryHint means an action that failed for a reason the operator can
	// act on carried no recovery hint.
	ErrNoRecoveryHint = errors.New("action must carry a recovery hint")
	// ErrNoOperationIdentity means a succeeded action carried no durable
	// operation identifier and version.
	ErrNoOperationIdentity = errors.New("succeeded action must carry an operation identifier and version")
	// ErrUnknownActionState means an action carried a state the console has no
	// rendering for.
	ErrUnknownActionState = errors.New("action state is not one the console renders")
	// ErrNoBadgeLabel means a status badge carried no text label.
	ErrNoBadgeLabel = errors.New("badge must carry a text label")
	// ErrNoBadgeGlyph means a status badge carried no glyph.
	ErrNoBadgeGlyph = errors.New("badge must carry a glyph")
	// ErrAmbiguousGlyph means two different states shared a glyph.
	ErrAmbiguousGlyph = errors.New("two different states must not share a glyph")
	// ErrNoTableAlternative means a chart carried no readable table alternative.
	ErrNoTableAlternative = errors.New("chart must carry a table alternative")
	// ErrTableTooLarge means a table alternative exceeded the row bound.
	ErrTableTooLarge = errors.New("table alternative exceeds the row bound")
	// ErrNoControlName means a control carried no name. A control nobody can
	// refer to cannot be found by the check that looks for the abort control.
	ErrNoControlName = errors.New("control must carry a name")
	// ErrUndeclaredCoverage means a live region does not state what it covers.
	// Silence is not a claim that nothing is covered.
	ErrUndeclaredCoverage = errors.New("live region must declare what it covers")
	// ErrNoAdmissionExpiry means an admission view carries no expiry.
	ErrNoAdmissionExpiry = errors.New("admission view must carry an expiry")
	// ErrNoAccessibleName means a control carried no accessible name.
	ErrNoAccessibleName = errors.New("control must carry an accessible name")
	// ErrDuplicateFocusOrder means two controls shared a focus order.
	ErrDuplicateFocusOrder = errors.New("control focus order is already in use")
	// ErrBadFocusOrder means a control carried a negative focus order.
	ErrBadFocusOrder = errors.New("control focus order must not be negative")
	// ErrNotKeyboardReachable means a control could not be reached by keyboard.
	ErrNotKeyboardReachable = errors.New("control is not keyboard reachable")
	// ErrNoAbortControl means a screen named no abort control.
	ErrNoAbortControl = errors.New("screen must name an abort control")
	// ErrAbortObscured means a live region covered the abort control.
	ErrAbortObscured = errors.New("live region obscures the abort control")
	// ErrNoFilterField means a filter named no field.
	ErrNoFilterField = errors.New("filter must name a field")
	// ErrFilterTooLarge means a filter held more values than the bound allows.
	ErrFilterTooLarge = errors.New("filter exceeds the value bound")
	// ErrFilterValueTooLong means a filter held a value longer than the bound
	// allows.
	ErrFilterValueTooLong = errors.New("filter value exceeds the length bound")
	// ErrBadQueuePosition means an admission view carried a negative queue
	// position.
	ErrBadQueuePosition = errors.New("queue position must not be negative")
	// ErrPolicyCheckFailed means an admission view hid a failed policy check.
	ErrPolicyCheckFailed = errors.New("a policy check failed")
	// ErrExpiredAdmission means an admission view had already expired.
	ErrExpiredAdmission = errors.New("admission has expired")
	// ErrBadEnvelope means an admission view expected negative resources.
	ErrBadEnvelope = errors.New("expected resource envelope must not be negative")
	// ErrIncompleteTimeline means a timeline did not carry every phase in order.
	ErrIncompleteTimeline = errors.New("timeline must carry every phase in order")
	// ErrInconsistentTimeline means a timeline claimed progress after a phase
	// that was unresolved.
	ErrInconsistentTimeline = errors.New("timeline claims progress after an unresolved phase")
)

// Bounds on what the console will render.
const (
	// MaxTableRows is the largest number of rows a table alternative may carry.
	//
	// The bound is a refusal rather than a truncation, because a truncated table
	// that looks complete is a table that hides data.
	MaxTableRows = 1000
	// MaxFilterValues is the largest number of values one filter may hold. An
	// unbounded filter is a client-side denial of service and a data-exposure
	// risk, because every value widens the query the browser is allowed to run.
	MaxFilterValues = 50
	// MaxFilterValueLength is the longest filter value, counted in characters.
	MaxFilterValueLength = 64
	// MaxLogBytes is the default cap on rendered log content.
	MaxLogBytes = 64 * 1024
)

// Phase is one stage of bringing an environment up.
//
// The order is the provisioning order: the artifact is built before the foundation is
// warmed, the foundation before dependencies are allocated, dependencies before the
// schema is migrated, and the gates last. A console that reordered them would
// describe a run that never happened.
type Phase string

const (
	// PhaseArtifactBuild is the phase that builds the candidate artifact.
	PhaseArtifactBuild Phase = "artifact-build"
	// PhaseFoundationWarmup is the phase that warms the shared foundation.
	PhaseFoundationWarmup Phase = "foundation-warmup"
	// PhaseDependencyAllocation is the phase that allocates dependencies.
	PhaseDependencyAllocation Phase = "dependency-allocation"
	// PhaseMigration is the phase that migrates the schema.
	PhaseMigration Phase = "migration"
	// PhaseGates is the phase that runs the gates.
	PhaseGates Phase = "gates"
)

// PhaseOrder returns the phases in provisioning order.
//
// A fresh slice is returned every call, so a caller that sorts or truncates it
// cannot change what the next caller sees.
func PhaseOrder() []Phase {
	return []Phase{
		PhaseArtifactBuild,
		PhaseFoundationWarmup,
		PhaseDependencyAllocation,
		PhaseMigration,
		PhaseGates,
	}
}

// knownPhase reports whether a phase is one the console renders.
func knownPhase(p Phase) bool {
	for _, known := range PhaseOrder() {
		if known == p {
			return true
		}
	}
	return false
}

// ActionOutcome is what a recorded action actually achieved.
type ActionOutcome string

const (
	// OutcomeSucceeded means the action completed and reported success.
	OutcomeSucceeded ActionOutcome = "succeeded"
	// OutcomeFailed means the action completed and reported failure.
	OutcomeFailed ActionOutcome = "failed"
	// OutcomeUncertain means the native call never reported back and the result
	// is genuinely unknown.
	OutcomeUncertain ActionOutcome = "uncertain"
	// OutcomeRunning means the action is still in flight.
	OutcomeRunning ActionOutcome = "running"
)

// RecordedAction is one action as the ledger recorded it.
//
// The ledger is the authority on progress. A lifecycle state cannot say how far a
// degraded run got, but these records can, and reading them is the only honest way
// to draw a timeline.
type RecordedAction struct {
	// ID identifies the action.
	ID string
	// Phase is the phase the action served.
	Phase Phase
	// Outcome is what the action achieved.
	Outcome ActionOutcome
	// StartedAt is when the action began.
	StartedAt time.Time
	// FinishedAt is when the action finished. A running action has none.
	FinishedAt time.Time
	// Detail is the recorded detail of the outcome.
	Detail string
}

// PhaseState is where a phase stands in the timeline.
type PhaseState string

const (
	// PhasePending means nothing has been recorded for the phase.
	PhasePending PhaseState = "pending"
	// PhaseRunning means an action of the phase is still in flight.
	PhaseRunning PhaseState = "running"
	// PhaseComplete means every recorded action of the phase succeeded.
	PhaseComplete PhaseState = "complete"
	// PhaseFailed means an action of the phase failed.
	PhaseFailed PhaseState = "failed"
	// PhaseUncertain means a native outcome of the phase never reported back.
	//
	// It is deliberately neither a failure nor a success. The provider did not say
	// what happened, and a console that renders that as either is lying to the
	// operator about something it does not know.
	PhaseUncertain PhaseState = "uncertain"
	// PhaseBlocked means an earlier phase is unresolved, so this one cannot be
	// claimed.
	PhaseBlocked PhaseState = "blocked"
)

// PhaseProgress is one row of the timeline.
type PhaseProgress struct {
	// Phase is the phase this row is about.
	Phase Phase
	// State is where the phase stands.
	State PhaseState
	// Actions is how many actions were recorded for the phase.
	Actions int
	// LastUpdate is the latest finish among the phase's actions, and the zero
	// time when none of them finished.
	LastUpdate time.Time
	// Reason explains a state that is not plainly complete, so a row the
	// operator cannot read is a row they have to ask about.
	Reason string
}

// Timeline is the console's progress view.
//
// It always carries every phase in order, including the phases that have nothing
// recorded against them, so that a rendering never has to guess at a missing row.
type Timeline struct {
	// Phases are the rows, in provisioning order.
	Phases []PhaseProgress
}

// BuildTimeline turns recorded actions into the console's progress view.
//
// The rules are deliberately conservative. An uncertain outcome is not a failure and
// not a success, and it is not folded into either: a phase that holds one is
// uncertain, whatever else was recorded alongside it, because the honest description
// of a phase with an unsettled native call is that it has not settled. A phase that
// failed or is uncertain blocks every phase after it, because a later phase cannot
// be claimed while an earlier one is unresolved.
//
// The function is deterministic: the same actions always produce the same timeline,
// whatever order they arrive in.
func BuildTimeline(actions []RecordedAction) Timeline {
	phases := PhaseOrder()
	recorded := make(map[Phase][]RecordedAction, len(phases))
	for _, a := range actions {
		// An action for a phase the console does not render has no row to live
		// in. Dropping it is the honest option, because inventing a sixth phase
		// would break the fixed shape every renderer depends on.
		if !knownPhase(a.Phase) {
			continue
		}
		recorded[a.Phase] = append(recorded[a.Phase], a)
	}

	progress := make([]PhaseProgress, len(phases))
	for i, p := range phases {
		acts := recorded[p]
		state, reason := phaseState(acts)
		last := time.Time{}
		for _, a := range acts {
			if a.FinishedAt.After(last) {
				last = a.FinishedAt
			}
		}
		progress[i] = PhaseProgress{
			Phase:      p,
			State:      state,
			Actions:    len(acts),
			LastUpdate: last,
			Reason:     reason,
		}
	}

	// The earliest unresolved phase is the root cause, so it is the one named in
	// every blocked row rather than the most recent one.
	blocker := ""
	for i := range progress {
		switch progress[i].State {
		case PhaseFailed, PhaseUncertain:
			if blocker == "" {
				blocker = string(progress[i].Phase)
			}
			// A phase that failed or is uncertain keeps its own state. It ran
			// and it did not settle; calling it blocked would hide a real
			// failure behind a word about something else.
			continue
		}
		if blocker != "" {
			progress[i].State = PhaseBlocked
			progress[i].Reason = fmt.Sprintf("blocked by %s", blocker)
		}
	}

	return Timeline{Phases: progress}
}

// phaseState decides the state of a phase from the actions recorded for it.
//
// Uncertainty dominates every other state, including a running action, because a
// phase holding a native call that never reported back is not making progress and
// must not be drawn as though it were.
func phaseState(acts []RecordedAction) (PhaseState, string) {
	if len(acts) == 0 {
		return PhasePending, "nothing recorded"
	}
	var uncertain, failed, running, succeeded int
	var uncertainDetail string
	for _, a := range acts {
		switch a.Outcome {
		case OutcomeUncertain:
			uncertain++
			if uncertainDetail == "" {
				uncertainDetail = a.Detail
			}
		case OutcomeFailed:
			failed++
		case OutcomeRunning:
			running++
		case OutcomeSucceeded:
			succeeded++
		default:
			// An outcome the console does not understand is not a success.
			// Treating it as one would be the same lie as treating an
			// uncertain outcome as a success.
			uncertain++
			if uncertainDetail == "" {
				uncertainDetail = a.Detail
			}
		}
	}
	switch {
	case uncertain > 0:
		reason := fmt.Sprintf("%d of %d actions uncertain: the native outcome never reported back",
			uncertain, len(acts))
		if failed > 0 {
			reason += fmt.Sprintf("; %d failed action(s) also recorded", failed)
		}
		if uncertainDetail != "" {
			reason += ": " + uncertainDetail
		}
		return PhaseUncertain, reason
	case running > 0:
		return PhaseRunning, fmt.Sprintf("%d of %d actions still running", running, len(acts))
	case failed > 0:
		return PhaseFailed, fmt.Sprintf("%d of %d actions failed", failed, len(acts))
	default:
		return PhaseComplete, fmt.Sprintf("%d of %d actions succeeded", succeeded, len(acts))
	}
}

// Phase looks a phase up in the timeline.
func (t Timeline) Phase(p Phase) (PhaseProgress, bool) {
	for _, row := range t.Phases {
		if row.Phase == p {
			return row, true
		}
	}
	return PhaseProgress{}, false
}

// Validate refuses a timeline that does not tell a coherent story.
//
// It is the check a renderer should run before drawing, because a timeline that says
// the gates completed while the migration failed is a timeline that has lost the
// ordering guarantee the phases exist to express.
func (t Timeline) Validate() error {
	order := PhaseOrder()
	if len(t.Phases) != len(order) {
		return fmt.Errorf("%w: %d rows, want %d", ErrIncompleteTimeline, len(t.Phases), len(order))
	}
	for i, p := range order {
		if t.Phases[i].Phase != p {
			return fmt.Errorf("%w: row %d is %q, want %q", ErrIncompleteTimeline, i, t.Phases[i].Phase, p)
		}
	}
	unresolved := false
	for _, row := range t.Phases {
		if unresolved && (row.State == PhaseComplete || row.State == PhaseRunning) {
			return fmt.Errorf("%w: phase %q claims %q after an unresolved phase", ErrInconsistentTimeline,
				row.Phase, row.State)
		}
		if row.State == PhaseFailed || row.State == PhaseUncertain {
			unresolved = true
		}
	}
	return nil
}

// ActionState is the state the console shows for one action.
//
// Every action has one of these nine, including the ones that did nothing yet and
// the ones that ended in a state the platform could not resolve on its own.
type ActionState string

const (
	// StateIdle means the action has not started.
	StateIdle ActionState = "idle"
	// StateLoading means the action is in flight.
	StateLoading ActionState = "loading"
	// StateDenied means the action was refused by policy or entitlement.
	StateDenied ActionState = "denied"
	// StateConflict means the action collided with another change.
	StateConflict ActionState = "conflict"
	// StateExpired means the action's window closed before it ran.
	StateExpired ActionState = "expired"
	// StateQuota means the action was refused for want of quota.
	StateQuota ActionState = "quota"
	// StateUncertain means the native outcome never reported back.
	StateUncertain ActionState = "uncertain"
	// StateSucceeded means the action completed and reported success.
	StateSucceeded ActionState = "succeeded"
	// StateFailed means the action completed and reported failure.
	StateFailed ActionState = "failed"
)

// ActionStates returns the states an action may be in.
//
// A fresh slice is returned every call, so a caller that reorders it cannot change
// what the next caller sees.
func ActionStates() []ActionState {
	return []ActionState{
		StateIdle,
		StateLoading,
		StateDenied,
		StateConflict,
		StateExpired,
		StateQuota,
		StateUncertain,
		StateSucceeded,
		StateFailed,
	}
}

// knownActionState reports whether a state is one the console renders.
func knownActionState(s ActionState) bool {
	for _, known := range ActionStates() {
		if known == s {
			return true
		}
	}
	return false
}

// needsRecovery reports whether a state is one an operator has to be able to act on.
//
// A denial with no way forward is a support ticket rather than an answer, so these
// states must carry a recovery hint as well as a reason.
func needsRecovery(s ActionState) bool {
	switch s {
	case StateDenied, StateConflict, StateExpired, StateQuota, StateUncertain:
		return true
	}
	return false
}

// ActionView is one action as the console shows it.
type ActionView struct {
	// ActionID identifies the action.
	ActionID string
	// Label is the action's human-readable name.
	Label string
	// State is where the action stands.
	State ActionState
	// Reason explains the state, and is required wherever an operator would
	// otherwise be left staring at a spinner.
	Reason string
	// Recovery is the way forward, and is required wherever the operator has to
	// be able to do something about the state.
	Recovery string
	// OperationID is the durable operation the action belongs to.
	OperationID string
	// Version is the version of that operation.
	Version int
}

// Validate refuses an action view that would leave an operator stuck.
//
// The rules are the ones the console owes the person reading it. A loading action
// that does not say what it is waiting for is a spinner with no explanation. A
// denied, conflicting, expired, quota-blocked or uncertain action with no recovery
// is a support ticket rather than an answer. A success with no durable operation
// and version cannot be audited or repeated.
func (a ActionView) Validate() error {
	if !knownActionState(a.State) {
		return fmt.Errorf("%w: %q", ErrUnknownActionState, a.State)
	}
	switch a.State {
	case StateLoading:
		if strings.TrimSpace(a.Reason) == "" {
			return fmt.Errorf("%w: loading action %q says what it is waiting for", ErrNoActionReason, a.ActionID)
		}
	case StateDenied, StateConflict, StateExpired, StateQuota, StateUncertain:
		if strings.TrimSpace(a.Reason) == "" {
			return fmt.Errorf("%w: %s action %q explains itself", ErrNoActionReason, a.State, a.ActionID)
		}
		if strings.TrimSpace(a.Recovery) == "" {
			return fmt.Errorf("%w: %s action %q names a way forward", ErrNoRecoveryHint, a.State, a.ActionID)
		}
	case StateSucceeded:
		if strings.TrimSpace(a.OperationID) == "" || a.Version <= 0 {
			return fmt.Errorf("%w: succeeded action %q", ErrNoOperationIdentity, a.ActionID)
		}
	}
	return nil
}

// Resolve maps a recorded outcome onto the state the console shows for it.
//
// This mapping is what stops an uncertain native outcome from being presented as a
// success: there is no path from OutcomeUncertain to StateSucceeded, and an outcome
// the console does not recognise becomes uncertain rather than successful, because
// an unknown result is not a good result.
//
// The durable operation and version are not filled in here. They come from the
// action ledger, and an action that claims success without them is refused by
// Validate.
func Resolve(outcome ActionOutcome, reason string) ActionView {
	return ResolveDetail(outcome, reason, "")
}

// ResolveDetail is Resolve with an explicit recovery hint.
//
// A hint given here is kept; a state that needs one and has none is given the
// default hint for that state, so the returned view is one an operator can act on.
func ResolveDetail(outcome ActionOutcome, reason, recovery string) ActionView {
	state := StateUncertain
	switch outcome {
	case OutcomeSucceeded:
		state = StateSucceeded
	case OutcomeFailed:
		state = StateFailed
	case OutcomeRunning:
		state = StateLoading
	case OutcomeUncertain:
		state = StateUncertain
	}

	view := ActionView{State: state, Reason: reason, Recovery: recovery}
	if strings.TrimSpace(view.Reason) == "" {
		view.Reason = defaultReason(state)
	}
	if strings.TrimSpace(view.Recovery) == "" && needsRecovery(state) {
		view.Recovery = defaultRecovery(state)
	}
	return view
}

// defaultReason is the explanation a state carries when the caller gave none.
//
// It exists so that a state which requires an explanation always has one. A view
// that says nothing is not a view an operator can act on.
func defaultReason(s ActionState) string {
	switch s {
	case StateLoading:
		return "waiting for the provider to respond"
	case StateUncertain:
		return "the native outcome never reported back"
	case StateFailed:
		return "the action failed"
	}
	return ""
}

// defaultRecovery is the way forward a state carries when the caller gave none.
func defaultRecovery(s ActionState) string {
	switch s {
	case StateDenied:
		return "ask an administrator for the entitlement this action needs"
	case StateConflict:
		return "reload the view and apply the action again"
	case StateExpired:
		return "request a fresh admission and apply the action again"
	case StateQuota:
		return "queue the action, or request a smaller reviewed profile"
	case StateUncertain:
		return "check the provider's own state before retrying"
	}
	return ""
}

// Badge is a status badge.
//
// The label is the text a screen reader reads and the glyph is the shape a sighted
// user sees, so neither channel is redundant and colour is never the only carrier
// of meaning.
type Badge struct {
	// State is what the badge reports.
	State string
	// Label is the badge's text.
	Label string
	// Glyph is the badge's shape.
	Glyph string
}

// canonicalGlyphs is the non-colour signal for each state the console renders.
//
// The registry is why a badge can be built from a state alone: the glyph is not
// decoration, it is the second channel carrying the meaning, so a state with no
// glyph has no accessible badge at all.
var canonicalGlyphs = map[string]string{
	"idle":      "·",
	"pending":   "○",
	"loading":   "◌",
	"running":   "◐",
	"succeeded": "✓",
	"failed":    "✗",
	"uncertain": "?",
	"denied":    "⊘",
	"conflict":  "≠",
	"expired":   "⌛",
	"quota":     "≡",
	"blocked":   "⊓",
}

// GlyphFor returns the canonical glyph for a state.
//
// It reports false for a state the console does not render, because a badge built
// from an unknown state would carry a glyph that means nothing.
func GlyphFor(state string) (string, bool) {
	g, ok := canonicalGlyphs[state]
	return g, ok
}

// glyphOwner returns the state that owns a glyph.
func glyphOwner(glyph string) (string, bool) {
	for state, g := range canonicalGlyphs {
		if g == glyph {
			return state, true
		}
	}
	return "", false
}

// NewBadge builds a badge for a state.
//
// The glyph comes from the state's canonical glyph, because the glyph has to mean
// something specific: two states that share a shape are two states that can only be
// told apart by colour. A state with no canonical glyph is refused, since a badge
// with no glyph is a badge whose meaning rests on colour alone.
func NewBadge(state, label string) (Badge, error) {
	if strings.TrimSpace(label) == "" {
		return Badge{}, fmt.Errorf("%w: state %q", ErrNoBadgeLabel, state)
	}
	glyph, ok := GlyphFor(state)
	if !ok {
		return Badge{}, fmt.Errorf("%w: state %q has no canonical glyph", ErrNoBadgeGlyph, state)
	}
	return Badge{State: state, Label: label, Glyph: glyph}, nil
}

// NewBadgeWithGlyph builds a badge with an explicit glyph.
//
// The glyph must not be one another state already owns, for the same reason the
// canonical registry exists: a shape that means two things carries no meaning.
func NewBadgeWithGlyph(state, label, glyph string) (Badge, error) {
	if strings.TrimSpace(label) == "" {
		return Badge{}, fmt.Errorf("%w: state %q", ErrNoBadgeLabel, state)
	}
	if strings.TrimSpace(glyph) == "" {
		return Badge{}, fmt.Errorf("%w: state %q", ErrNoBadgeGlyph, state)
	}
	if owner, ok := glyphOwner(glyph); ok && owner != state {
		return Badge{}, fmt.Errorf("%w: glyph %q belongs to state %q", ErrAmbiguousGlyph, glyph, owner)
	}
	return Badge{State: state, Label: label, Glyph: glyph}, nil
}

// NewBadges checks a set of badges for ambiguity.
//
// The check is over the set rather than over one badge, because the ambiguity only
// exists between badges: one badge's glyph is fine, and two states sharing it is
// the failure that makes colour the only way to tell them apart.
func NewBadges(badges []Badge) ([]Badge, error) {
	owner := map[string]string{}
	out := make([]Badge, 0, len(badges))
	for _, b := range badges {
		if strings.TrimSpace(b.Label) == "" {
			return nil, fmt.Errorf("%w: state %q", ErrNoBadgeLabel, b.State)
		}
		if strings.TrimSpace(b.Glyph) == "" {
			return nil, fmt.Errorf("%w: state %q", ErrNoBadgeGlyph, b.State)
		}
		if previous, ok := owner[b.Glyph]; ok && previous != b.State {
			return nil, fmt.Errorf("%w: states %q and %q both use %q", ErrAmbiguousGlyph, previous, b.State, b.Glyph)
		}
		// A badge may not borrow another state's canonical glyph. The badge
		// struct is exported, so a set can arrive with a glyph that belongs to
		// a state it was not built for, and a shape that means two things
		// carries no meaning.
		if owner, ok := glyphOwner(b.Glyph); ok && owner != b.State {
			return nil, fmt.Errorf("%w: glyph %q belongs to state %q", ErrAmbiguousGlyph, b.Glyph, owner)
		}
		owner[b.Glyph] = b.State
		out = append(out, b)
	}
	return out, nil
}

// Table is a tabular view of something.
type Table struct {
	// Title names the table.
	Title string
	// Columns are the column headings.
	Columns []string
	// Rows are the rows, each holding one cell per column.
	Rows [][]string
}

// Point is one plotted point.
type Point struct {
	// Label names the point on the axis.
	Label string
	// Value is the plotted value.
	Value float64
}

// Chart is a plotted view with a readable alternative.
//
// The alternative is not optional. A graph with no table cannot be read with a
// screen reader, and the console's own requirement names table alternatives for
// graphs, so the alternative is part of the type rather than an optional extra.
type Chart struct {
	// Title names the chart.
	Title string
	// Series are the plotted series.
	Series []string
	// Points are the plotted points.
	Points []Point
	// Alternative is the table that carries the same information.
	Alternative *Table
}

// NewChart checks that a chart can be read without seeing the picture.
//
// The alternative table must have columns, must carry a row for every series, and
// must be within the row bound. It is refused rather than truncated when it is
// too large, because a truncated table that looks complete is a table that hides
// data from the person who needed it.
func NewChart(c Chart) (Chart, error) {
	if c.Alternative == nil {
		return c, fmt.Errorf("%w: chart %q has none", ErrNoTableAlternative, c.Title)
	}
	if len(c.Alternative.Columns) == 0 {
		return c, fmt.Errorf("%w: chart %q has an alternative with no columns", ErrNoTableAlternative, c.Title)
	}
	if len(c.Alternative.Rows) > MaxTableRows {
		return c, fmt.Errorf("%w: chart %q has %d rows, bound is %d", ErrTableTooLarge, c.Title,
			len(c.Alternative.Rows), MaxTableRows)
	}
	for _, series := range c.Series {
		if !tableHasSeries(c.Alternative, series) {
			return c, fmt.Errorf("%w: chart %q has no row for series %q", ErrNoTableAlternative, c.Title, series)
		}
	}
	return c, nil
}

// tableHasSeries reports whether the table carries a row for a series.
//
// The series name is the row's first cell, because the table is the series' own
// reading of the same numbers and has to say which series each row belongs to.
func tableHasSeries(t *Table, series string) bool {
	for _, row := range t.Rows {
		if len(row) > 0 && row[0] == series {
			return true
		}
	}
	return false
}

// Region is a part of a screen that may be updated by itself.
type Region struct {
	// Name identifies the region.
	Name string
	// Live reports whether the region updates without the operator asking.
	Live bool
	// Announces is what the region announces to a screen reader.
	Announces string
	// DeclaresCoverage reports that the region has stated what it covers. It is
	// set even when the region covers nothing, because a region that has not
	// said either way has not claimed that it covers nothing.
	DeclaresCoverage bool
	// Covers names the controls the region obscures.
	//
	// The overlap between a live region and a control is stated rather than
	// inferred, because geometry is not something a view model can know for
	// certain, and a live region that covers the abort control must be
	// detectable from the model alone.
	Covers []string
}

// Control is something the operator can act on.
type Control struct {
	// Name identifies the control.
	Name string
	// AccessibleName is the name the control is announced under.
	AccessibleName string
	// FocusOrder is the control's place in the tab order.
	FocusOrder int
	// KeyboardReachable reports whether the control can be reached by keyboard.
	KeyboardReachable bool
}

// Screen is one console screen.
type Screen struct {
	// Title names the screen.
	Title string
	// Regions are the parts of the screen.
	Regions []Region
	// Controls are the things the operator can act on.
	Controls []Control
	// AbortControl names the control that stops the run.
	AbortControl string
}

// Validate refuses a screen that the review and abort tasks cannot be done on.
//
// Every control needs an accessible name, a focus order of its own and a keyboard
// route to it, because reviewing and aborting are release requirements and a
// keyboard-only operator has to reach them. The screen must name an abort control,
// and no live region may obscure it: a region that updates over the stop button is
// the failure the requirement names, and a stop button nobody can hit is not a stop
// button.
func (s Screen) Validate() error {
	seen := map[int]string{}
	for _, c := range s.Controls {
		if strings.TrimSpace(c.Name) == "" {
			return fmt.Errorf("%w: screen %q", ErrNoControlName, s.Title)
		}
		if strings.TrimSpace(c.AccessibleName) == "" {
			return fmt.Errorf("%w: control %q", ErrNoAccessibleName, c.Name)
		}
		if c.FocusOrder < 0 {
			return fmt.Errorf("%w: control %q", ErrBadFocusOrder, c.Name)
		}
		if !c.KeyboardReachable {
			return fmt.Errorf("%w: control %q", ErrNotKeyboardReachable, c.Name)
		}
		if previous, ok := seen[c.FocusOrder]; ok {
			return fmt.Errorf("%w: %q and %q", ErrDuplicateFocusOrder, previous, c.Name)
		}
		seen[c.FocusOrder] = c.Name
	}

	if strings.TrimSpace(s.AbortControl) == "" {
		return fmt.Errorf("%w: screen %q", ErrNoAbortControl, s.Title)
	}
	if _, ok := s.control(s.AbortControl); !ok {
		return fmt.Errorf("%w: screen %q names %q, which is not a control", ErrNoAbortControl, s.Title, s.AbortControl)
	}

	for _, r := range s.Regions {
		if !r.Live {
			continue
		}
		// A live region must state its coverage. The overlap between a region
		// and a control cannot be inferred, and a region that covers the abort
		// control without saying so would pass every check, so silence is
		// itself the refusal.
		if !r.DeclaresCoverage {
			return fmt.Errorf("%w: live region %q on screen %q", ErrUndeclaredCoverage, r.Name, s.Title)
		}
		for _, covered := range r.Covers {
			if covered == s.AbortControl {
				return fmt.Errorf("%w: region %q covers %q", ErrAbortObscured, r.Name, s.AbortControl)
			}
		}
		if mentionsControl(r.Announces, s.AbortControl) {
			return fmt.Errorf("%w: region %q announces %q", ErrAbortObscured, r.Name, s.AbortControl)
		}
	}
	return nil
}

// control looks a control up by name.
func (s Screen) control(name string) (Control, bool) {
	for _, c := range s.Controls {
		if c.Name == name {
			return c, true
		}
	}
	return Control{}, false
}

// mentionsControl reports whether an announcement names a control.
//
// The comparison is by whole word, because a live region announcing "aborting the
// run" is not a live region covering the "abort" control, and a rule that fired on
// every announcement would be a rule nobody kept.
func mentionsControl(announces, name string) bool {
	want := strings.ToLower(strings.TrimSpace(name))
	if want == "" {
		return false
	}
	for _, field := range strings.Fields(announces) {
		token := strings.ToLower(strings.Trim(field, ".,;:!?\"'()[]{}"))
		if token == want {
			return true
		}
	}
	return false
}

// Filter is a bounded table filter.
//
// The bounds are not caution for their own sake. An unbounded filter is a
// client-side denial of service, and a filter that can carry an unbounded value is
// a filter that can carry anything the caller likes into a query.
type Filter struct {
	// Field is the column the filter applies to.
	Field string
	// Values are the accepted values.
	Values []string
}

// Validate refuses a filter that is not bounded.
func (f Filter) Validate() error {
	if strings.TrimSpace(f.Field) == "" {
		return fmt.Errorf("%w: a filter must name a column", ErrNoFilterField)
	}
	if len(f.Values) > MaxFilterValues {
		return fmt.Errorf("%w: %d values, bound is %d", ErrFilterTooLarge, len(f.Values), MaxFilterValues)
	}
	for _, v := range f.Values {
		if utf8.RuneCountInString(v) > MaxFilterValueLength {
			return fmt.Errorf("%w: %d characters, bound is %d", ErrFilterValueTooLong,
				utf8.RuneCountInString(v), MaxFilterValueLength)
		}
	}
	return nil
}

// LogView is rendered log content.
type LogView struct {
	// Content is the rendered content.
	Content string
	// Truncated reports that the cap withheld part of the log.
	Truncated bool
	// OriginalBytes is the size of the content as it was supplied, so an
	// operator can see how much the cap or the sanitisation removed.
	OriginalBytes int
}

// RenderLog caps log content and makes it inert.
//
// The content is capped at maxBytes and the view says whether the cap withheld
// anything. The escape sequences are stripped rather than escaped, because the
// output goes to a terminal and a terminal that receives "\x1b[31m" does not print
// it, it applies the colour and carries on. The escape character itself goes too,
// so a sequence this scanner does not recognise still cannot reach the terminal.
//
// The cap is applied on a character boundary, so the rendered log is text rather
// than a byte string that happens to end halfway through a character. A
// non-positive cap renders nothing at all.
func RenderLog(content string, maxBytes int) LogView {
	view := LogView{OriginalBytes: len(content)}
	stripped := StripANSI(content)
	if maxBytes <= 0 {
		view.Truncated = len(stripped) > 0
		return view
	}
	if len(stripped) > maxBytes {
		view.Truncated = true
		stripped = stripped[:maxBytes]
		for len(stripped) > 0 && !utf8.ValidString(stripped) {
			stripped = stripped[:len(stripped)-1]
		}
	}
	view.Content = stripped
	return view
}

// RenderLogHTML renders untrusted log content for an HTML view.
//
// RenderLog bounds and strips ANSI but does not escape markup, because a caller
// may want the raw text for a terminal and the escaped text for a page. A renderer
// that forgets which one it needs ships unescaped markup with nothing complaining,
// so this is the form to use when the destination is markup: it bounds the content
// and escapes it in one call, and there is no way to get one without the other.
func RenderLogHTML(content string, maxBytes int) LogView {
	view := RenderLog(content, maxBytes)
	view.Content = EscapeHTML(view.Content)
	return view
}

// StripANSI removes ANSI escape sequences from a string.
//
// The sequences are removed rather than neutralised, because the output of a log
// viewer is written to a terminal, and the terminal is the thing that would act on
// them.
func StripANSI(s string) string {
	if !strings.ContainsRune(s, 0x1b) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != 0x1b {
			b.WriteByte(s[i])
			i++
			continue
		}
		i++
		if i >= len(s) {
			// A lone escape character at the end of the content is dropped
			// like any other, so the terminal cannot act on it.
			break
		}
		switch s[i] {
		case '[':
			// A control sequence: parameter bytes, then a final byte.
			i++
			for i < len(s) && (s[i] < 0x40 || s[i] > 0x7e) {
				i++
			}
			if i < len(s) {
				i++
			}
		case ']':
			// An operating system command, which runs until BEL or ST.
			i++
			for i < len(s) {
				if s[i] == 0x07 {
					i++
					break
				}
				if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
					i += 2
					break
				}
				i++
			}
		case '(', ')', '*', '+':
			// A character set selection, which takes one more byte.
			i++
			if i < len(s) {
				i++
			}
		default:
			// Any other two-character sequence.
		}
	}
	return b.String()
}

// EscapeHTML escapes a string for rendering as text.
//
// Untrusted output is escaped rather than trusted, because a log line or a
// repository name that happens to contain markup must never become markup. It is a
// separate step from RenderLog on purpose: escaping a whole log would turn every
// legitimate angle bracket in a JSON line into noise, so the renderer applies this
// to the fields that carry untrusted text.
func EscapeHTML(s string) string {
	return html.EscapeString(s)
}

// Scope is the organization and projects a console view is limited to.
type Scope struct {
	// OrganizationID is the organization the view belongs to.
	OrganizationID string
	// ProjectIDs are the projects within it that are in view.
	ProjectIDs []string
}

// Repository is one repository in the console's catalogue.
type Repository struct {
	// ID identifies the repository.
	ID string
	// FullName is the repository's full name, such as "acme/api".
	FullName string
	// ProjectID is the project it belongs to.
	ProjectID string
	// OrganizationID is the organization that owns it.
	OrganizationID string
}

// Counter is one numbered thing in the console.
type Counter struct {
	// Name is what the counter counts.
	Name string
	// Value is how many.
	Value int
}

// inScope reports whether a repository may be shown in a scope.
//
// The scope is applied to both the organization and the project, and an empty
// organization matches nothing. Failing closed matters here: a console that showed
// everything when it could not tell who was asking would be a console that shows
// another tenant's repository names.
func inScope(r Repository, scope Scope) bool {
	if strings.TrimSpace(scope.OrganizationID) == "" {
		return false
	}
	if r.OrganizationID != scope.OrganizationID {
		return false
	}
	for _, p := range scope.ProjectIDs {
		if p == r.ProjectID {
			return true
		}
	}
	return false
}

// Count counts the repositories a scope may show.
//
// The count is the tenant's own total and nothing else, because a counter that
// included another tenant's repositories would leak the existence of those
// repositories through a number. The scope is applied again here even when the
// caller believes the set is already scoped, because a scoping mistake upstream
// must not reach the operator's screen.
func Count(scoped []Repository, scope Scope, name string) Counter {
	count := 0
	for _, r := range scoped {
		if inScope(r, scope) {
			count++
		}
	}
	return Counter{Name: name, Value: count}
}

// CountMatching counts the repositories in a scope whose name matches a query.
//
// It is the counted form of Search, and it obeys the same rule: a query that names
// another tenant's repository returns nothing.
func CountMatching(scoped []Repository, scope Scope, query string) Counter {
	return Counter{Name: query, Value: len(Search(scoped, scope, query))}
}

// Search returns the repositories in a scope whose name matches a query.
//
// A query that matches a repository in another tenant returns an empty result. It
// does not return the repository, and it does not hint that one exists: an empty
// list is the whole answer, because a count or a suggestion would tell the other
// tenant's repository name to somebody who is not entitled to it.
//
// The results are sorted, so the same query always renders the same list.
func Search(scoped []Repository, scope Scope, query string) []Repository {
	needle := strings.ToLower(strings.TrimSpace(query))
	out := make([]Repository, 0, len(scoped))
	for _, r := range scoped {
		if !inScope(r, scope) {
			continue
		}
		if needle == "" ||
			strings.Contains(strings.ToLower(r.FullName), needle) ||
			strings.Contains(strings.ToLower(r.ID), needle) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FullName != out[j].FullName {
			return out[i].FullName < out[j].FullName
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// PolicyCheck is one admission policy check.
type PolicyCheck struct {
	// Name names the check.
	Name string
	// Passed reports whether the check passed.
	Passed bool
	// Detail explains the check's result.
	Detail string
}

// Envelope is the resources an admitted environment is expected to use.
type Envelope struct {
	// CPU is the expected processor count.
	CPU int
	// MemoryMB is the expected memory in megabytes.
	MemoryMB int
	// CostCeiling is the expected cost ceiling.
	CostCeiling float64
}

// AdmissionView is the console's view of a queued admission.
//
// It carries the queue position, the policy checks, the expected resource
// envelope, the forecast and the expiry, because an operator deciding whether to
// wait needs all of them, and a view that showed only the position would be a view
// that could not be acted on.
type AdmissionView struct {
	// Position is the place in the queue.
	Position int
	// Checks are the policy checks that were run.
	Checks []PolicyCheck
	// Expected is the resource envelope the admission expects.
	Expected Envelope
	// Forecast is the forecast shown to the operator.
	Forecast string
	// ExpiresAt is when the admission lapses.
	ExpiresAt time.Time
}

// Validate refuses an admission view that misleads.
//
// The position must be real, the expected envelope must not be negative, and a
// failed policy check must block the view rather than be hidden inside it: an
// admission view that showed a green queue position while a check had failed
// would be a console lying about admission.
//
// Validate cannot judge the expiry, because expiry is a statement about a moment
// and this function is given no clock. ValidateAt is the form that checks it.
func (v AdmissionView) Validate() error {
	if v.Position < 0 {
		return fmt.Errorf("%w: %d", ErrBadQueuePosition, v.Position)
	}
	if v.Expected.CPU < 0 || v.Expected.MemoryMB < 0 || v.Expected.CostCeiling < 0 {
		return fmt.Errorf("%w: %+v", ErrBadEnvelope, v.Expected)
	}
	for _, c := range v.Checks {
		if !c.Passed {
			return fmt.Errorf("%w: %q: %s", ErrPolicyCheckFailed, c.Name, c.Detail)
		}
	}
	// A view with no expiry at all is refused last, so that the more specific
	// failures are the ones reported. A queue position for an admission that
	// never lapses would send an operator into a queue that never closes.
	if v.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: position %d", ErrNoAdmissionExpiry, v.Position)
	}
	return nil
}

// ValidateAt refuses an admission view that misleads, judged at a given moment.
//
// An admission that has already lapsed is refused, because a view that showed a
// queued position for an admission nobody may use any more would send an operator
// into a queue that will never admit them.
func (v AdmissionView) ValidateAt(at time.Time) error {
	if err := v.Validate(); err != nil {
		return err
	}
	if !v.ExpiresAt.After(at) {
		return fmt.Errorf("%w: expiry %s is not after %s", ErrExpiredAdmission,
			v.ExpiresAt.Format(time.RFC3339), at.Format(time.RFC3339))
	}
	return nil
}

// View is a console view that owns a scoped set of repositories.
//
// Scoping is structural here rather than a convention. The repository list lives
// inside the view and the view's accessors are the only way to reach it, so a
// renderer cannot hold a raw list and skip the filter. A view built from a list
// containing another tenant's repositories exposes none of them, and the filtering
// happened once, at construction, rather than at every read.
type View struct {
	scope Scope
	repos []Repository
}

// NewView builds a view over the repositories inside the scope.
//
// The repositories outside the scope are dropped here and not merely hidden, so
// that a caller holding the view has no list to leak by accident.
func NewView(scope Scope, repositories []Repository) View {
	var kept []Repository
	for _, repo := range repositories {
		if !inScope(repo, scope) {
			continue
		}
		kept = append(kept, repo)
	}
	return View{scope: scope, repos: kept}
}

// Scope returns the view's scope.
func (v View) Scope() Scope { return v.scope }

// Repositories returns the repositories inside the scope, in the order they were
// supplied.
func (v View) Repositories() []Repository {
	out := make([]Repository, len(v.repos))
	copy(out, v.repos)
	return out
}

// Search returns the repositories inside the scope whose name or identifier
// contains the query.
//
// The result never mentions a repository outside the scope, and an empty result
// says nothing about whether a matching repository exists elsewhere: a search that
// hinted at other tenants' names would be the leak it exists to prevent.
func (v View) Search(query string) []Repository {
	needle := strings.ToLower(strings.TrimSpace(query))
	if needle == "" {
		return nil
	}
	var out []Repository
	for _, repo := range v.repos {
		if strings.Contains(strings.ToLower(repo.FullName), needle) ||
			strings.Contains(strings.ToLower(repo.ID), needle) {
			out = append(out, repo)
		}
	}
	return out
}

// Count returns the number of repositories inside the scope.
func (v View) Count() Counter {
	return Counter{Name: "repositories", Value: len(v.repos)}
}

// CountMatching returns the number of repositories inside the scope that match the
// query.
func (v View) CountMatching(query string) Counter {
	return Counter{Name: "matching repositories", Value: len(v.Search(query))}
}
