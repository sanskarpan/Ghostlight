package console

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2027, 1, 12, 10, 0, 0, 0, time.UTC)

// action is a recorded action that finished at a given moment.
func action(id string, phase Phase, outcome ActionOutcome, finished time.Time) RecordedAction {
	return RecordedAction{
		ID:         id,
		Phase:      phase,
		Outcome:    outcome,
		StartedAt:  finished.Add(-time.Minute),
		FinishedAt: finished,
	}
}

// ---------------------------------------------------------------------------
// Progress timeline
// ---------------------------------------------------------------------------

// A rendering must never have to invent a missing row, so every phase is present
// whether or not anything was recorded for it.
func TestBuildTimelineCarriesEveryPhaseInOrder(t *testing.T) {
	timeline := BuildTimeline(nil)
	if len(timeline.Phases) != len(PhaseOrder()) {
		t.Fatalf("phases = %d, want %d", len(timeline.Phases), len(PhaseOrder()))
	}
	for i, p := range PhaseOrder() {
		if timeline.Phases[i].Phase != p {
			t.Errorf("phase %d = %q, want %q", i, timeline.Phases[i].Phase, p)
		}
	}
}

func TestBuildTimelineMarksAPhaseWithNothingRecordedPending(t *testing.T) {
	timeline := BuildTimeline([]RecordedAction{
		action("a1", PhaseArtifactBuild, OutcomeSucceeded, now),
	})
	row, ok := timeline.Phase(PhaseGates)
	if !ok {
		t.Fatal("the gates phase must be present")
	}
	if row.State != PhasePending {
		t.Errorf("state = %q, want pending", row.State)
	}
	if row.Actions != 0 {
		t.Errorf("actions = %d, want 0", row.Actions)
	}
	if !row.LastUpdate.IsZero() {
		t.Errorf("last update = %s, want the zero time", row.LastUpdate)
	}
}

func TestBuildTimelineMarksAPhaseWithARunningActionRunning(t *testing.T) {
	timeline := BuildTimeline([]RecordedAction{
		action("a1", PhaseArtifactBuild, OutcomeRunning, time.Time{}),
	})
	row, _ := timeline.Phase(PhaseArtifactBuild)
	if row.State != PhaseRunning {
		t.Errorf("state = %q, want running", row.State)
	}
}

// An uncertain native outcome is not a failure and it is definitely not a success.
// A console that renders it as either is lying to the operator.
func TestBuildTimelineTreatsAnUncertainOutcomeAsNeitherSuccessNorFailure(t *testing.T) {
	timeline := BuildTimeline([]RecordedAction{
		action("a1", PhaseMigration, OutcomeUncertain, now),
	})
	row, _ := timeline.Phase(PhaseMigration)
	if row.State == PhaseFailed {
		t.Error("an uncertain outcome is not a failure")
	}
	if row.State == PhaseComplete {
		t.Error("an uncertain outcome is not a success")
	}
	if row.State != PhaseUncertain {
		t.Errorf("state = %q, want uncertain", row.State)
	}
}

// A phase holding an unsettled native call has not settled, whatever else was
// recorded beside it, and the failure is still named so nothing is hidden.
func TestBuildTimelineKeepsAFailureVisibleBesideAnUncertainOutcome(t *testing.T) {
	timeline := BuildTimeline([]RecordedAction{
		action("a1", PhaseMigration, OutcomeFailed, now),
		action("a2", PhaseMigration, OutcomeUncertain, now),
	})
	row, _ := timeline.Phase(PhaseMigration)
	if row.State != PhaseUncertain {
		t.Errorf("state = %q, want uncertain", row.State)
	}
	if !strings.Contains(row.Reason, "failed") {
		t.Errorf("reason = %q, want the recorded failure named", row.Reason)
	}
}

func TestBuildTimelineMarksAPhaseWhoseActionsAllSucceededComplete(t *testing.T) {
	timeline := BuildTimeline([]RecordedAction{
		action("a1", PhaseArtifactBuild, OutcomeSucceeded, now),
		action("a2", PhaseArtifactBuild, OutcomeSucceeded, now.Add(time.Minute)),
	})
	row, _ := timeline.Phase(PhaseArtifactBuild)
	if row.State != PhaseComplete {
		t.Errorf("state = %q, want complete", row.State)
	}
	if row.Actions != 2 {
		t.Errorf("actions = %d, want 2", row.Actions)
	}
}

func TestBuildTimelineMarksAPhaseWithAFailedActionFailed(t *testing.T) {
	timeline := BuildTimeline([]RecordedAction{
		action("a1", PhaseArtifactBuild, OutcomeSucceeded, now),
		action("a2", PhaseArtifactBuild, OutcomeFailed, now),
	})
	row, _ := timeline.Phase(PhaseArtifactBuild)
	if row.State != PhaseFailed {
		t.Errorf("state = %q, want failed", row.State)
	}
}

// A later phase cannot be claimed while an earlier one is unresolved.
func TestBuildTimelineBlocksLaterPhasesAfterAFailure(t *testing.T) {
	timeline := BuildTimeline([]RecordedAction{
		action("a1", PhaseFoundationWarmup, OutcomeFailed, now),
	})
	warmup, _ := timeline.Phase(PhaseFoundationWarmup)
	if warmup.State != PhaseFailed {
		t.Fatalf("state = %q, want failed", warmup.State)
	}
	for _, p := range []Phase{PhaseDependencyAllocation, PhaseMigration, PhaseGates} {
		row, _ := timeline.Phase(p)
		if row.State != PhaseBlocked {
			t.Errorf("phase %q state = %q, want blocked", p, row.State)
		}
		if !strings.Contains(row.Reason, string(PhaseFoundationWarmup)) {
			t.Errorf("phase %q reason = %q, want the blocking phase named", p, row.Reason)
		}
	}
}

func TestBuildTimelineBlocksLaterPhasesAfterAnUncertainOutcome(t *testing.T) {
	timeline := BuildTimeline([]RecordedAction{
		action("a1", PhaseMigration, OutcomeUncertain, now),
	})
	gates, _ := timeline.Phase(PhaseGates)
	if gates.State != PhaseBlocked {
		t.Errorf("state = %q, want blocked", gates.State)
	}
	if !strings.Contains(gates.Reason, string(PhaseMigration)) {
		t.Errorf("reason = %q, want the blocking phase named", gates.Reason)
	}
}

// The same actions must always produce the same timeline, whatever order they were
// recorded in.
func TestBuildTimelineIsDeterministic(t *testing.T) {
	actions := []RecordedAction{
		action("a1", PhaseArtifactBuild, OutcomeSucceeded, now),
		action("a2", PhaseFoundationWarmup, OutcomeFailed, now.Add(time.Minute)),
		action("a3", PhaseMigration, OutcomeUncertain, now.Add(2*time.Minute)),
	}
	reversed := []RecordedAction{actions[2], actions[1], actions[0]}
	if !reflect.DeepEqual(BuildTimeline(actions), BuildTimeline(reversed)) {
		t.Error("the timeline must not depend on the order the actions arrived in")
	}
	again := BuildTimeline(actions)
	if !reflect.DeepEqual(BuildTimeline(actions), again) {
		t.Error("the timeline must be the same every time it is built")
	}
}

func TestBuildTimelineLastUpdateIsTheLatestFinish(t *testing.T) {
	timeline := BuildTimeline([]RecordedAction{
		action("a1", PhaseArtifactBuild, OutcomeSucceeded, now),
		action("a2", PhaseArtifactBuild, OutcomeSucceeded, now.Add(5*time.Minute)),
	})
	row, _ := timeline.Phase(PhaseArtifactBuild)
	if !row.LastUpdate.Equal(now.Add(5 * time.Minute)) {
		t.Errorf("last update = %s, want the latest finish", row.LastUpdate)
	}
}

// An action for a phase the console does not render has no row to live in, and
// inventing a sixth phase would break the shape every renderer depends on.
func TestBuildTimelineDropsActionsForPhasesTheConsoleDoesNotRender(t *testing.T) {
	timeline := BuildTimeline([]RecordedAction{
		action("a1", Phase("not-a-phase"), OutcomeSucceeded, now),
	})
	total := 0
	for _, row := range timeline.Phases {
		total += row.Actions
	}
	if total != 0 {
		t.Errorf("recorded actions = %d, want 0", total)
	}
}

func TestTimelineValidateRefusesAMissingPhase(t *testing.T) {
	timeline := BuildTimeline(nil)
	timeline.Phases = timeline.Phases[:len(timeline.Phases)-1]
	if err := timeline.Validate(); !errors.Is(err, ErrIncompleteTimeline) {
		t.Errorf("Validate error = %v, want ErrIncompleteTimeline", err)
	}
}

func TestTimelineValidateRefusesProgressAfterAnUnresolvedPhase(t *testing.T) {
	timeline := BuildTimeline([]RecordedAction{
		action("a1", PhaseArtifactBuild, OutcomeFailed, now),
	})
	timeline.Phases[3].State = PhaseComplete
	if err := timeline.Validate(); !errors.Is(err, ErrInconsistentTimeline) {
		t.Errorf("Validate error = %v, want ErrInconsistentTimeline", err)
	}
}

// The happy path: every phase ran and every action succeeded.
func TestHappyPathTimeline(t *testing.T) {
	actions := []RecordedAction{
		action("a1", PhaseArtifactBuild, OutcomeSucceeded, now),
		action("a2", PhaseFoundationWarmup, OutcomeSucceeded, now.Add(time.Minute)),
		action("a3", PhaseDependencyAllocation, OutcomeSucceeded, now.Add(2*time.Minute)),
		action("a4", PhaseMigration, OutcomeSucceeded, now.Add(3*time.Minute)),
		action("a5", PhaseGates, OutcomeSucceeded, now.Add(4*time.Minute)),
	}
	timeline := BuildTimeline(actions)
	if err := timeline.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for _, row := range timeline.Phases {
		if row.State != PhaseComplete {
			t.Errorf("phase %q state = %q, want complete", row.Phase, row.State)
		}
	}
	gates, _ := timeline.Phase(PhaseGates)
	if !gates.LastUpdate.Equal(now.Add(4 * time.Minute)) {
		t.Errorf("gates last update = %s, want the recorded finish", gates.LastUpdate)
	}
}

// ---------------------------------------------------------------------------
// Action states
// ---------------------------------------------------------------------------

func TestActionStatesAreTheNineTheConsoleRenders(t *testing.T) {
	states := ActionStates()
	want := []ActionState{
		StateIdle, StateLoading, StateDenied, StateConflict, StateExpired,
		StateQuota, StateUncertain, StateSucceeded, StateFailed,
	}
	if !reflect.DeepEqual(states, want) {
		t.Errorf("states = %v, want %v", states, want)
	}
}

func TestActionViewValidateRefusesAnUnknownState(t *testing.T) {
	view := ActionView{ActionID: "a1", State: ActionState("pending-ish")}
	if err := view.Validate(); !errors.Is(err, ErrUnknownActionState) {
		t.Errorf("Validate error = %v, want ErrUnknownActionState", err)
	}
}

// A spinner with no explanation is the thing this rule exists to prevent.
func TestActionViewValidateRequiresAReasonWhileLoading(t *testing.T) {
	view := ActionView{ActionID: "a1", State: StateLoading}
	if err := view.Validate(); !errors.Is(err, ErrNoActionReason) {
		t.Errorf("Validate error = %v, want ErrNoActionReason", err)
	}
	view.Reason = "waiting for the scheduler"
	if err := view.Validate(); err != nil {
		t.Errorf("Validate error = %v, want nil", err)
	}
}

// A denied action with no recovery hint is a support ticket, not an answer.
func TestActionViewValidateRequiresAReasonAndARecoveryForActionableFailures(t *testing.T) {
	states := []ActionState{StateDenied, StateConflict, StateExpired, StateQuota, StateUncertain}
	for _, state := range states {
		t.Run(string(state), func(t *testing.T) {
			view := ActionView{ActionID: "a1", State: state}
			if err := view.Validate(); !errors.Is(err, ErrNoActionReason) {
				t.Errorf("Validate error = %v, want ErrNoActionReason", err)
			}
			view.Reason = "the policy refused the action"
			if err := view.Validate(); !errors.Is(err, ErrNoRecoveryHint) {
				t.Errorf("Validate error = %v, want ErrNoRecoveryHint", err)
			}
			view.Recovery = "ask an administrator"
			if err := view.Validate(); err != nil {
				t.Errorf("Validate error = %v, want nil", err)
			}
		})
	}
}

// "It worked" that cannot be audited or repeated is not a result.
func TestActionViewValidateRequiresADurableOperationForASuccess(t *testing.T) {
	view := ActionView{ActionID: "a1", State: StateSucceeded}
	if err := view.Validate(); !errors.Is(err, ErrNoOperationIdentity) {
		t.Errorf("Validate error = %v, want ErrNoOperationIdentity", err)
	}
	view.OperationID = "op-1"
	if err := view.Validate(); !errors.Is(err, ErrNoOperationIdentity) {
		t.Errorf("Validate error = %v, want ErrNoOperationIdentity for the missing version", err)
	}
	view.Version = 3
	if err := view.Validate(); err != nil {
		t.Errorf("Validate error = %v, want nil", err)
	}
}

// A failure carries its explanation but no separate recovery hint: the console
// shows the failure and the sanitized log together, and the states that need a
// route forward are the ones the operator has to be told how to leave.
func TestActionViewDoesNotRequireARecoveryHintForAFailure(t *testing.T) {
	view := ActionView{ActionID: "a1", State: StateFailed, Reason: "the migration failed"}
	if err := view.Validate(); err != nil {
		t.Errorf("Validate error = %v, want nil", err)
	}
}

func TestResolveMapsEveryOutcome(t *testing.T) {
	cases := map[ActionOutcome]ActionState{
		OutcomeSucceeded: StateSucceeded,
		OutcomeFailed:    StateFailed,
		OutcomeUncertain: StateUncertain,
		OutcomeRunning:   StateLoading,
	}
	for outcome, want := range cases {
		t.Run(string(outcome), func(t *testing.T) {
			if got := Resolve(outcome, "because").State; got != want {
				t.Errorf("state = %q, want %q", got, want)
			}
		})
	}
}

// No action may be presented as succeeded while an uncertain native outcome is
// outstanding, and an outcome the console does not understand is not a success
// either.
func TestResolveNeverPresentsAnUncertainOutcomeAsSuccess(t *testing.T) {
	for _, outcome := range []ActionOutcome{OutcomeUncertain, ActionOutcome("something-new")} {
		view := Resolve(outcome, "the provider never reported back")
		if view.State == StateSucceeded {
			t.Errorf("outcome %q was presented as succeeded", outcome)
		}
		if view.State != StateUncertain {
			t.Errorf("outcome %q state = %q, want uncertain", outcome, view.State)
		}
	}
}

func TestResolveSuppliesADefaultReasonAndRecovery(t *testing.T) {
	loading := Resolve(OutcomeRunning, "")
	if strings.TrimSpace(loading.Reason) == "" {
		t.Error("a loading action must say what it is waiting for")
	}
	if err := loading.Validate(); err != nil {
		t.Errorf("Validate error = %v, want nil", err)
	}
	uncertain := Resolve(OutcomeUncertain, "")
	if strings.TrimSpace(uncertain.Reason) == "" || strings.TrimSpace(uncertain.Recovery) == "" {
		t.Error("an uncertain action must carry a reason and a recovery")
	}
	if err := uncertain.Validate(); err != nil {
		t.Errorf("Validate error = %v, want nil", err)
	}
}

// The happy path: an action that succeeded, with the durable identity attached
// from the ledger.
func TestHappyPathActionView(t *testing.T) {
	view := Resolve(OutcomeSucceeded, "the gate passed")
	view.ActionID = "a1"
	view.Label = "Run the isolation gate"
	view.OperationID = "op-1"
	view.Version = 2
	if err := view.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if view.State != StateSucceeded {
		t.Errorf("state = %q, want succeeded", view.State)
	}
}

// ---------------------------------------------------------------------------
// Status badges
// ---------------------------------------------------------------------------

func TestNewBadgeRefusesAMissingLabel(t *testing.T) {
	if _, err := NewBadge("failed", "   "); !errors.Is(err, ErrNoBadgeLabel) {
		t.Errorf("NewBadge error = %v, want ErrNoBadgeLabel", err)
	}
}

// Colour is never the only carrier of meaning, so a badge with no glyph is not a
// badge at all.
func TestNewBadgeRefusesAStateWithNoGlyph(t *testing.T) {
	if _, err := NewBadge("no-such-state", "Something"); !errors.Is(err, ErrNoBadgeGlyph) {
		t.Errorf("NewBadge error = %v, want ErrNoBadgeGlyph", err)
	}
	if _, err := NewBadgeWithGlyph("failed", "Failed", ""); !errors.Is(err, ErrNoBadgeGlyph) {
		t.Errorf("NewBadgeWithGlyph error = %v, want ErrNoBadgeGlyph", err)
	}
}

// If every failure badge is the same shape, colour is doing the work.
func TestNewBadgeWithGlyphRefusesAGlyphOwnedByAnotherState(t *testing.T) {
	if _, err := NewBadgeWithGlyph("failed", "Failed", "✓"); !errors.Is(err, ErrAmbiguousGlyph) {
		t.Errorf("NewBadgeWithGlyph error = %v, want ErrAmbiguousGlyph", err)
	}
	badge, err := NewBadgeWithGlyph("failed", "Failed", "✗")
	if err != nil {
		t.Fatalf("NewBadgeWithGlyph: %v", err)
	}
	if badge.Glyph != "✗" {
		t.Errorf("glyph = %q, want the glyph that was asked for", badge.Glyph)
	}
}

func TestNewBadgesRefusesTwoStatesSharingAGlyph(t *testing.T) {
	badges := []Badge{
		{State: "failed", Label: "Failed", Glyph: "✗"},
		{State: "uncertain", Label: "Uncertain", Glyph: "✗"},
	}
	if _, err := NewBadges(badges); !errors.Is(err, ErrAmbiguousGlyph) {
		t.Errorf("NewBadges error = %v, want ErrAmbiguousGlyph", err)
	}
}

func TestNewBadgesAcceptsDistinctGlyphs(t *testing.T) {
	badges := []Badge{
		{State: "failed", Label: "Failed", Glyph: "✗"},
		{State: "uncertain", Label: "Uncertain", Glyph: "?"},
	}
	out, err := NewBadges(badges)
	if err != nil {
		t.Fatalf("NewBadges: %v", err)
	}
	if len(out) != len(badges) {
		t.Errorf("badges = %d, want %d", len(out), len(badges))
	}
	if _, err := NewBadges([]Badge{{State: "failed", Label: "", Glyph: "✗"}}); !errors.Is(err, ErrNoBadgeLabel) {
		t.Errorf("NewBadges error = %v, want ErrNoBadgeLabel", err)
	}
	if _, err := NewBadges([]Badge{{State: "failed", Label: "Failed"}}); !errors.Is(err, ErrNoBadgeGlyph) {
		t.Errorf("NewBadges error = %v, want ErrNoBadgeGlyph", err)
	}
}

// The happy path: a badge for every state the console renders, each with its own
// shape and its own text.
func TestHappyPathBadge(t *testing.T) {
	states := []string{"pending", "running", "succeeded", "failed", "uncertain", "denied", "quota"}
	badges := make([]Badge, 0, len(states))
	for _, state := range states {
		badge, err := NewBadge(state, strings.ToUpper(state[:1])+state[1:])
		if err != nil {
			t.Fatalf("NewBadge(%q): %v", state, err)
		}
		badges = append(badges, badge)
	}
	if _, err := NewBadges(badges); err != nil {
		t.Fatalf("NewBadges: %v", err)
	}
}

// Every state a phase can carry needs a badge, including a completed phase. The
// renderer found this gap: complete was a phase state with no canonical glyph, so
// the one state every successful run ends in could not be drawn without relying on
// colour. Complete also cannot borrow the succeeded glyph, because two states that
// share a shape can only be told apart by colour.
func TestEveryPhaseStateHasItsOwnGlyph(t *testing.T) {
	states := []PhaseState{PhasePending, PhaseRunning, PhaseComplete, PhaseFailed, PhaseUncertain, PhaseBlocked}
	badges := make([]Badge, 0, len(states))
	for _, state := range states {
		badge, err := NewBadge(string(state), string(state))
		if err != nil {
			t.Fatalf("NewBadge(%q): %v", state, err)
		}
		badges = append(badges, badge)
	}
	if _, err := NewBadges(badges); err != nil {
		t.Fatalf("NewBadges: %v", err)
	}
	complete, ok := GlyphFor(string(PhaseComplete))
	if !ok {
		t.Fatalf("GlyphFor(%q) reports no glyph", PhaseComplete)
	}
	succeeded, ok := GlyphFor(string(StateSucceeded))
	if !ok {
		t.Fatalf("GlyphFor(%q) reports no glyph", StateSucceeded)
	}
	if complete == succeeded {
		t.Errorf("complete and succeeded share the glyph %q", complete)
	}
}

// ---------------------------------------------------------------------------
// Charts and their table alternatives
// ---------------------------------------------------------------------------

// A graph with no table alternative is unreadable with a screen reader.
func TestNewChartRefusesAChartWithoutATableAlternative(t *testing.T) {
	chart := Chart{Title: "Queue depth", Series: []string{"queued"}}
	if _, err := NewChart(chart); !errors.Is(err, ErrNoTableAlternative) {
		t.Errorf("NewChart error = %v, want ErrNoTableAlternative", err)
	}
	chart.Alternative = &Table{Title: "Queue depth"}
	if _, err := NewChart(chart); !errors.Is(err, ErrNoTableAlternative) {
		t.Errorf("NewChart error = %v, want ErrNoTableAlternative", err)
	}
}

func TestNewChartRefusesAnAlternativeMissingASeries(t *testing.T) {
	chart := Chart{
		Title:  "Queue depth",
		Series: []string{"queued", "admitted"},
		Points: []Point{{Label: "now", Value: 2}},
		Alternative: &Table{
			Title:   "Queue depth",
			Columns: []string{"series", "value"},
			Rows:    [][]string{{"queued", "2"}},
		},
	}
	if _, err := NewChart(chart); !errors.Is(err, ErrNoTableAlternative) {
		t.Errorf("NewChart error = %v, want ErrNoTableAlternative", err)
	}
}

// A truncated table that looks complete is a table that hides data.
func TestNewChartRefusesAnOverlargeAlternative(t *testing.T) {
	rows := make([][]string, 0, MaxTableRows+1)
	for i := 0; i <= MaxTableRows; i++ {
		rows = append(rows, []string{"queued", "1"})
	}
	chart := Chart{
		Title:       "Queue depth",
		Series:      []string{"queued"},
		Alternative: &Table{Title: "Queue depth", Columns: []string{"series", "value"}, Rows: rows},
	}
	if _, err := NewChart(chart); !errors.Is(err, ErrTableTooLarge) {
		t.Errorf("NewChart error = %v, want ErrTableTooLarge", err)
	}
}

// The happy path: a chart whose alternative carries the same series as the chart.
func TestHappyPathChart(t *testing.T) {
	chart := Chart{
		Title:  "Queue depth",
		Series: []string{"queued", "admitted"},
		Points: []Point{{Label: "now", Value: 3}},
		Alternative: &Table{
			Title:   "Queue depth",
			Columns: []string{"series", "value"},
			Rows:    [][]string{{"queued", "3"}, {"admitted", "1"}},
		},
	}
	out, err := NewChart(chart)
	if err != nil {
		t.Fatalf("NewChart: %v", err)
	}
	if out.Alternative == nil || len(out.Alternative.Rows) != 2 {
		t.Errorf("alternative = %+v, want two rows", out.Alternative)
	}
}

// ---------------------------------------------------------------------------
// Screens
// ---------------------------------------------------------------------------

// validScreen is a screen the review and abort tasks can be done on.
func validScreen() Screen {
	return Screen{
		Title: "Run",
		Controls: []Control{
			{Name: "review", AccessibleName: "Review the candidate", FocusOrder: 1, KeyboardReachable: true},
			{Name: "abort", AccessibleName: "Abort the run", FocusOrder: 2, KeyboardReachable: true},
		},
		AbortControl: "abort",
	}
}

func TestScreenValidateRefusesAControlWithoutAnAccessibleName(t *testing.T) {
	screen := validScreen()
	screen.Controls[0].AccessibleName = "  "
	if err := screen.Validate(); !errors.Is(err, ErrNoAccessibleName) {
		t.Errorf("Validate error = %v, want ErrNoAccessibleName", err)
	}
}

func TestScreenValidateRefusesDuplicateFocusOrder(t *testing.T) {
	screen := validScreen()
	screen.Controls[1].FocusOrder = screen.Controls[0].FocusOrder
	if err := screen.Validate(); !errors.Is(err, ErrDuplicateFocusOrder) {
		t.Errorf("Validate error = %v, want ErrDuplicateFocusOrder", err)
	}
}

func TestScreenValidateRefusesAControlThatIsNotKeyboardReachable(t *testing.T) {
	screen := validScreen()
	screen.Controls[1].KeyboardReachable = false
	if err := screen.Validate(); !errors.Is(err, ErrNotKeyboardReachable) {
		t.Errorf("Validate error = %v, want ErrNotKeyboardReachable", err)
	}
}

func TestScreenValidateRefusesAScreenWithoutAnAbortControl(t *testing.T) {
	screen := validScreen()
	screen.AbortControl = ""
	if err := screen.Validate(); !errors.Is(err, ErrNoAbortControl) {
		t.Errorf("Validate error = %v, want ErrNoAbortControl", err)
	}
	screen.AbortControl = "stop"
	if err := screen.Validate(); !errors.Is(err, ErrNoAbortControl) {
		t.Errorf("Validate error = %v, want ErrNoAbortControl for a control that does not exist", err)
	}
}

func TestScreenValidateRefusesANegativeFocusOrder(t *testing.T) {
	screen := validScreen()
	screen.Controls[0].FocusOrder = -1
	if err := screen.Validate(); !errors.Is(err, ErrBadFocusOrder) {
		t.Errorf("Validate error = %v, want ErrBadFocusOrder", err)
	}
}

// A live region that updates over the stop button is the exact failure the
// requirement names.
func TestScreenValidateRefusesALiveRegionCoveringTheAbortControl(t *testing.T) {
	screen := validScreen()
	screen.Regions = []Region{{Name: "chart", Live: true, DeclaresCoverage: true, Covers: []string{"abort"}}}
	if err := screen.Validate(); !errors.Is(err, ErrAbortObscured) {
		t.Errorf("Validate error = %v, want ErrAbortObscured", err)
	}
}

func TestScreenValidateRefusesALiveRegionAnnouncingTheAbortControl(t *testing.T) {
	screen := validScreen()
	screen.Regions = []Region{{Name: "chart", Live: true, DeclaresCoverage: true, Announces: "the abort control is covered"}}
	if err := screen.Validate(); !errors.Is(err, ErrAbortObscured) {
		t.Errorf("Validate error = %v, want ErrAbortObscured", err)
	}
}

// The happy path: a keyboard-reachable screen with a live region that does not
// touch the abort control.
func TestHappyPathScreen(t *testing.T) {
	screen := validScreen()
	screen.Regions = []Region{
		{Name: "progress", Live: true, DeclaresCoverage: true, Announces: "the build is running"},
		{Name: "notes", Live: false},
	}
	if err := screen.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Table filters
// ---------------------------------------------------------------------------

func TestFilterValidateRefusesAMissingField(t *testing.T) {
	filter := Filter{Values: []string{"acme"}}
	if err := filter.Validate(); !errors.Is(err, ErrNoFilterField) {
		t.Errorf("Validate error = %v, want ErrNoFilterField", err)
	}
}

// An unbounded filter is a client-side denial of service.
func TestFilterValidateRefusesTooManyValues(t *testing.T) {
	values := make([]string, 0, MaxFilterValues+1)
	for i := 0; i <= MaxFilterValues; i++ {
		values = append(values, "v")
	}
	filter := Filter{Field: "organization", Values: values}
	if err := filter.Validate(); !errors.Is(err, ErrFilterTooLarge) {
		t.Errorf("Validate error = %v, want ErrFilterTooLarge", err)
	}
}

func TestFilterValidateRefusesAnOverlongValue(t *testing.T) {
	filter := Filter{Field: "name", Values: []string{strings.Repeat("x", MaxFilterValueLength+1)}}
	if err := filter.Validate(); !errors.Is(err, ErrFilterValueTooLong) {
		t.Errorf("Validate error = %v, want ErrFilterValueTooLong", err)
	}
}

// The happy path: a bounded filter on a named field.
func TestHappyPathFilter(t *testing.T) {
	filter := Filter{
		Field:  "organization",
		Values: []string{"acme", "beta"},
	}
	if err := filter.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

func TestRenderLogCapsContentAndReportsTruncation(t *testing.T) {
	view := RenderLog(strings.Repeat("a", 100), 10)
	if len(view.Content) != 10 {
		t.Errorf("content = %d bytes, want 10", len(view.Content))
	}
	if !view.Truncated {
		t.Error("truncated must report that the cap withheld content")
	}
	if view.OriginalBytes != 100 {
		t.Errorf("original bytes = %d, want 100", view.OriginalBytes)
	}
	whole := RenderLog("short", 100)
	if whole.Truncated {
		t.Error("content that fits must not be reported as truncated")
	}
	if whole.Content != "short" {
		t.Errorf("content = %q, want the whole log", whole.Content)
	}
}

// A terminal that receives an escape sequence does not print it, it acts on it.
func TestRenderLogStripsANSISequences(t *testing.T) {
	view := RenderLog("\x1b[31mred\x1b[0m and \x1b[1;32mgreen\x1b[0m", 100)
	if strings.ContainsRune(view.Content, 0x1b) {
		t.Errorf("content = %q, want no escape sequences", view.Content)
	}
	if view.Content != "red and green" {
		t.Errorf("content = %q, want the text without the sequences", view.Content)
	}
}

func TestRenderLogStripsTheBareEscapeCharacter(t *testing.T) {
	view := RenderLog("a\x1bb", 100)
	if strings.ContainsRune(view.Content, 0x1b) {
		t.Errorf("content = %q, want no escape character", view.Content)
	}
	if view.Content != "ab" {
		t.Errorf("content = %q, want %q", view.Content, "ab")
	}
}

// A log line containing markup must not become markup, and a legitimate angle
// bracket in a JSON line must not be mangled either, so the two are separate steps.
func TestRenderLogDoesNotEscapeHTML(t *testing.T) {
	view := RenderLog(`{"name":"acme"}`, 100)
	if view.Content != `{"name":"acme"}` {
		t.Errorf("content = %q, want the log text unchanged", view.Content)
	}
}

func TestEscapeHTMLMakesUntrustedOutputInert(t *testing.T) {
	escaped := EscapeHTML("<script>alert('x')</script>")
	if strings.Contains(escaped, "<script>") {
		t.Errorf("escaped = %q, want no markup", escaped)
	}
	if !strings.Contains(escaped, "&lt;script&gt;") {
		t.Errorf("escaped = %q, want the angle brackets escaped", escaped)
	}
}

// The happy path: a log that fits, carries no escape sequences and is complete.
func TestHappyPathLog(t *testing.T) {
	view := RenderLog("build step 1 ok\nbuild step 2 ok\n", MaxLogBytes)
	if view.Truncated {
		t.Error("content that fits must not be reported as truncated")
	}
	if view.OriginalBytes != len("build step 1 ok\nbuild step 2 ok\n") {
		t.Errorf("original bytes = %d, want the whole log", view.OriginalBytes)
	}
	if !strings.HasSuffix(view.Content, "ok\n") {
		t.Errorf("content = %q, want the whole log", view.Content)
	}
}

// ---------------------------------------------------------------------------
// Tenant scoping
// ---------------------------------------------------------------------------

// catalogue is a set of repositories from two tenants.
func catalogue() []Repository {
	return []Repository{
		{ID: "r1", FullName: "acme/api", ProjectID: "p1", OrganizationID: "org-1"},
		{ID: "r2", FullName: "acme/web", ProjectID: "p2", OrganizationID: "org-1"},
		{ID: "r3", FullName: "acme/secret-api", ProjectID: "p9", OrganizationID: "org-2"},
	}
}

func acmeScope() Scope {
	return Scope{OrganizationID: "org-1", ProjectIDs: []string{"p1", "p2"}}
}

func TestCountOnlyCountsRepositoriesInsideTheScope(t *testing.T) {
	counter := Count(catalogue(), acmeScope(), "repositories")
	if counter.Name != "repositories" {
		t.Errorf("name = %q, want the counter's name", counter.Name)
	}
	if counter.Value != 2 {
		t.Errorf("value = %d, want 2", counter.Value)
	}
}

func TestSearchOnlyReturnsRepositoriesInsideTheScope(t *testing.T) {
	found := Search(catalogue(), acmeScope(), "api")
	if len(found) != 1 {
		t.Fatalf("found = %v, want only the repository inside the scope", found)
	}
	if found[0].FullName != "acme/api" {
		t.Errorf("found = %v, want acme/api", found)
	}
}

// A search that matches nothing must not reveal that a matching repository exists
// in another tenant.
func TestSearchDoesNotRevealAnotherTenantsRepository(t *testing.T) {
	found := Search(catalogue(), acmeScope(), "secret-api")
	if len(found) != 0 {
		t.Errorf("found = %v, want nothing", found)
	}
	for _, r := range found {
		if strings.Contains(r.FullName, "secret-api") {
			t.Errorf("found = %v, want no other tenant's repository", found)
		}
	}
}

// The count must not leak the existence of another tenant's repository either.
func TestCountDoesNotIncludeAnotherTenantsRepository(t *testing.T) {
	if got := Count(catalogue(), acmeScope(), "repositories").Value; got != 2 {
		t.Errorf("count = %d, want 2", got)
	}
	if got := CountMatching(catalogue(), acmeScope(), "secret-api").Value; got != 0 {
		t.Errorf("matching count = %d, want 0", got)
	}
}

// An empty scope matches nothing, because a console that showed everything when it
// could not tell who was asking would show another tenant's names.
func TestScopeWithNoOrganizationShowsNothing(t *testing.T) {
	scope := Scope{ProjectIDs: []string{"p1"}}
	if got := Count(catalogue(), scope, "repositories").Value; got != 0 {
		t.Errorf("count = %d, want 0", got)
	}
	if found := Search(catalogue(), scope, "api"); len(found) != 0 {
		t.Errorf("found = %v, want nothing", found)
	}
}

// The same query must always render the same list.
func TestSearchIsSortedAndDeterministic(t *testing.T) {
	repos := []Repository{
		{ID: "b", FullName: "acme/web", ProjectID: "p1", OrganizationID: "org-1"},
		{ID: "a", FullName: "acme/api", ProjectID: "p1", OrganizationID: "org-1"},
	}
	found := Search(repos, Scope{OrganizationID: "org-1", ProjectIDs: []string{"p1"}}, "acme")
	if len(found) != 2 || found[0].FullName != "acme/api" {
		t.Errorf("found = %v, want the list sorted by name", found)
	}
	again := Search(repos, Scope{OrganizationID: "org-1", ProjectIDs: []string{"p1"}}, "acme")
	if !reflect.DeepEqual(found, again) {
		t.Error("the same query must always return the same list")
	}
}

// The happy path: a tenant counts and searches its own repositories.
func TestHappyPathScoping(t *testing.T) {
	scope := acmeScope()
	if got := Count(catalogue(), scope, "repositories").Value; got != 2 {
		t.Errorf("count = %d, want 2", got)
	}
	found := Search(catalogue(), scope, "acme")
	if len(found) != 2 {
		t.Fatalf("found = %v, want both of the tenant's repositories", found)
	}
	if found[0].FullName != "acme/api" || found[1].FullName != "acme/web" {
		t.Errorf("found = %v, want them sorted", found)
	}
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

func TestAdmissionViewRefusesANegativeQueuePosition(t *testing.T) {
	view := AdmissionView{Position: -1}
	if err := view.Validate(); !errors.Is(err, ErrBadQueuePosition) {
		t.Errorf("Validate error = %v, want ErrBadQueuePosition", err)
	}
}

// An admission view that hides a failed check is a console lying about admission.
func TestAdmissionViewRefusesAFailedPolicyCheck(t *testing.T) {
	view := AdmissionView{
		Position: 0,
		Checks: []PolicyCheck{
			{Name: "isolation", Passed: true},
			{Name: "quota", Passed: false, Detail: "the team is over its quota"},
		},
	}
	if err := view.Validate(); !errors.Is(err, ErrPolicyCheckFailed) {
		t.Errorf("Validate error = %v, want ErrPolicyCheckFailed", err)
	}
}

func TestAdmissionViewRefusesAnExpiredAdmission(t *testing.T) {
	view := AdmissionView{
		Position:  0,
		Checks:    []PolicyCheck{{Name: "isolation", Passed: true}},
		ExpiresAt: now.Add(-time.Minute),
	}
	if err := view.ValidateAt(now); !errors.Is(err, ErrExpiredAdmission) {
		t.Errorf("ValidateAt error = %v, want ErrExpiredAdmission", err)
	}
	view.ExpiresAt = now.Add(time.Minute)
	if err := view.ValidateAt(now); err != nil {
		t.Errorf("ValidateAt error = %v, want nil", err)
	}
}

func TestAdmissionViewRefusesANegativeEnvelope(t *testing.T) {
	view := AdmissionView{Expected: Envelope{CPU: -1, MemoryMB: 512, CostCeiling: 1.5}}
	if err := view.Validate(); !errors.Is(err, ErrBadEnvelope) {
		t.Errorf("Validate error = %v, want ErrBadEnvelope", err)
	}
}

// The happy path: a queued admission with passing checks, an expected envelope and
// an expiry still in the future.
func TestHappyPathAdmission(t *testing.T) {
	view := AdmissionView{
		Position: 3,
		Checks: []PolicyCheck{
			{Name: "isolation", Passed: true, Detail: "the candidate is isolated"},
			{Name: "quota", Passed: true, Detail: "within the team quota"},
		},
		Expected:  Envelope{CPU: 2, MemoryMB: 4096, CostCeiling: 12.5},
		Forecast:  "about 4 minutes",
		ExpiresAt: now.Add(30 * time.Minute),
	}
	if err := view.ValidateAt(now); err != nil {
		t.Fatalf("ValidateAt: %v", err)
	}
	if err := view.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The rules the accessibility gate found missing
// ---------------------------------------------------------------------------

// A badge may not borrow another state's canonical glyph. The badge struct is
// exported, so a set can arrive with a glyph that belongs to a state it was not
// built for, and a shape that means two things carries no meaning.
func TestABadgeInASetMayNotBorrowAnotherStatesGlyph(t *testing.T) {
	succeeded, ok := GlyphFor("succeeded")
	if !ok {
		t.Fatal("the succeeded state must have a canonical glyph")
	}
	bad := []Badge{{State: "failed", Label: "Failed", Glyph: succeeded}}
	if _, err := NewBadges(bad); !errors.Is(err, ErrAmbiguousGlyph) {
		t.Errorf("NewBadges error = %v, want ErrAmbiguousGlyph", err)
	}
}

// A control nobody can refer to cannot be found by the check that looks for the
// abort control.
func TestAControlMustCarryAName(t *testing.T) {
	screen := validScreen()
	screen.Controls = append(screen.Controls, Control{
		Name: "", AccessibleName: "Mystery", FocusOrder: 40, KeyboardReachable: true,
	})
	if err := screen.Validate(); !errors.Is(err, ErrNoControlName) {
		t.Errorf("Validate error = %v, want ErrNoControlName", err)
	}
}

// A live region must state its coverage. The overlap between a region and a
// control cannot be inferred, and a region that covers the abort control without
// saying so would pass every check, so silence is itself the refusal.
func TestALiveRegionMustDeclareWhatItCovers(t *testing.T) {
	screen := validScreen()
	screen.Regions = []Region{{Name: "progress", Live: true, Announces: "the build is running"}}
	if err := screen.Validate(); !errors.Is(err, ErrUndeclaredCoverage) {
		t.Errorf("Validate error = %v, want ErrUndeclaredCoverage", err)
	}
	// A region that declares that it covers nothing is fine.
	screen.Regions = []Region{{Name: "progress", Live: true, DeclaresCoverage: true, Announces: "the build is running"}}
	if err := screen.Validate(); err != nil {
		t.Errorf("a region that declares its coverage must be accepted: %v", err)
	}
	// A region that is not live does not need to declare anything.
	screen.Regions = []Region{{Name: "notes", Live: false}}
	if err := screen.Validate(); err != nil {
		t.Errorf("a static region must not need a declaration: %v", err)
	}
}

// A renderer that forgets which one it needs ships unescaped markup with nothing
// complaining, so the bounded-and-escaped form exists as one call.
func TestRenderLogHTMLBoundsAndEscapesTogether(t *testing.T) {
	view := RenderLogHTML("before <script>alert(1)</script> after", 1024)
	if strings.Contains(view.Content, "<script>") {
		t.Errorf("content = %q, want the markup escaped", view.Content)
	}
	if !strings.Contains(view.Content, "&lt;script&gt;") {
		t.Errorf("content = %q, want the escaped form", view.Content)
	}
	if !strings.Contains(view.Content, "before") || !strings.Contains(view.Content, "after") {
		t.Errorf("content = %q, want the surrounding text kept", view.Content)
	}
	capped := RenderLogHTML("abcdefghij", 4)
	if capped.Content != "abcd" || !capped.Truncated {
		t.Errorf("capped = %+v, want four bytes marked truncated", capped)
	}
}

// An admission with no expiry would send an operator into a queue that never closes.
func TestAnAdmissionViewMustCarryAnExpiry(t *testing.T) {
	view := AdmissionView{Position: 1, Checks: []PolicyCheck{{Name: "isolation", Passed: true}}}
	if err := view.Validate(); !errors.Is(err, ErrNoAdmissionExpiry) {
		t.Errorf("Validate error = %v, want ErrNoAdmissionExpiry", err)
	}
	view.ExpiresAt = now.Add(30 * time.Minute)
	if err := view.Validate(); err != nil {
		t.Errorf("an admission with an expiry must be accepted: %v", err)
	}
}

// Scoping is structural: the view drops the out-of-scope repositories at
// construction, so a renderer holding the view has no list to leak by accident.
func TestAViewOwnsItsScopedRepositories(t *testing.T) {
	scope := Scope{OrganizationID: "org-1", ProjectIDs: []string{"project-1"}}
	repos := []Repository{
		{ID: "r1", FullName: "acme/api", ProjectID: "project-1", OrganizationID: "org-1"},
		{ID: "r2", FullName: "acme/web", ProjectID: "project-2", OrganizationID: "org-1"},
		{ID: "r3", FullName: "other/secret-api", ProjectID: "project-1", OrganizationID: "org-2"},
	}
	view := NewView(scope, repos)
	if len(view.Repositories()) != 1 {
		t.Fatalf("repositories = %v, want only the in-scope one", view.Repositories())
	}
	if view.Count().Value != 1 {
		t.Errorf("count = %d, want 1", view.Count().Value)
	}
	found := view.Search("secret-api")
	if len(found) != 0 {
		t.Errorf("search = %v, want nothing from another tenant", found)
	}
	if view.CountMatching("secret-api").Value != 0 {
		t.Error("the matching count must not include another tenant's repository")
	}
	if len(view.Search("acme/api")) != 1 {
		t.Error("an in-scope repository must still be findable")
	}
}
