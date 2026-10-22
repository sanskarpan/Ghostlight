package gate_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/console"
)

// This file is the G7 gate: checklist row G7.7, feature G-F08 — the console must
// never present a state the platform cannot prove.
//
// The clause in full: progress must not claim success from an uncertain or
// unrecorded outcome, statuses must not be conveyed by colour alone, every control
// must be reachable by keyboard and named for a screen reader, the abort control
// must never be obscured by a live region, untrusted log content must be bounded
// and escaped, and the console must never reveal another tenant's repository names
// or counts.
//
// Every test here is an attack against that clause, and each asserts the layer that
// stops it, because a pass for the wrong reason is still a pass for the wrong
// reason. The attacks are ordered from naive to sophisticated: a gate that stops
// only naive attacks is decoration.
//
// What this suite may claim: that internal/console refuses to hand a renderer the
// presentations the clause names, and that each refusal names what was missing.
//
// What it may not claim: that the console is accessible. It exercises the view
// model's refusals, not a rendered page, a real screen reader, a real terminal or a
// real browser, and it says nothing about the renderer that draws the model.

// g7now is the fixed clock. Every moment in this file comes from it, so a test
// never depends on when the suite happens to run.
var g7now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// g7Attack is one hostile attempt against the console, described well enough that a
// failure says what the caller tried and which layer refused it.
type g7Attack struct {
	name  string
	layer string
}

// g7attacks is the registry of attacks, in naive-first order.
func g7attacks() []g7Attack {
	return []g7Attack{
		{"an uncertain outcome is drawn as a success", "the timeline builder and the action resolver"},
		{"a failed phase is followed by a phase drawn complete", "the timeline builder and the timeline validator"},
		{"a phase with nothing recorded is drawn complete", "the timeline builder"},
		{"two states share one glyph, or a badge carries no text", "the badge builder"},
		{"a chart has no table alternative", "the chart builder"},
		{"a control has no accessible name or no keyboard route", "the screen validator"},
		{"a live region covers the abort control", "the screen validator"},
		{"a screen names no abort control", "the screen validator"},
		{"an ANSI escape sequence reaches the terminal", "the log renderer"},
		{"untrusted markup reaches the renderer", "the exported HTML escaping helper"},
		{"an over-cap log is presented as complete", "the log renderer"},
		{"another tenant's repository reaches a result or a count", "the scope filter"},
		{"a filter carries unbounded values", "the filter validator"},
		{"a denied action names no way forward", "the action validator"},
		{"a success carries no operation identity", "the action validator"},
		{"an admission view hides a failed check or a lapsed expiry", "the admission validator"},
	}
}

// g7action is a recorded action that finished at the fixed clock, so a timeline
// built from it never depends on the wall clock.
func g7action(id string, phase console.Phase, outcome console.ActionOutcome) console.RecordedAction {
	return console.RecordedAction{
		ID:         id,
		Phase:      phase,
		Outcome:    outcome,
		StartedAt:  g7now.Add(-time.Minute),
		FinishedAt: g7now,
		Detail:     "recorded by the gate fixture",
	}
}

// g7scope is the tenant the console is looking at: one organization and the two
// projects that are in view.
func g7scope() console.Scope {
	return console.Scope{OrganizationID: "org-acme", ProjectIDs: []string{"p-1", "p-2"}}
}

// g7catalogue is a catalogue holding three kinds of repository: the tenant's own
// two, one of the tenant's own that sits outside the scoped projects, and one that
// belongs to another organization entirely.
func g7catalogue() []console.Repository {
	return []console.Repository{
		{ID: "r-1", FullName: "acme/api", ProjectID: "p-1", OrganizationID: "org-acme"},
		{ID: "r-2", FullName: "acme/web", ProjectID: "p-2", OrganizationID: "org-acme"},
		{ID: "r-3", FullName: "acme/billing", ProjectID: "p-9", OrganizationID: "org-acme"},
		{ID: "r-4", FullName: "globex/secret-api", ProjectID: "p-3", OrganizationID: "org-globex"},
	}
}

// g7screen is a screen the review and abort tasks can be done on.
func g7screen() console.Screen {
	return console.Screen{
		Title:   "Run",
		Regions: []console.Region{{Name: "progress", Live: true, DeclaresCoverage: true, Announces: "the build is running"}},
		Controls: []console.Control{
			{Name: "review", AccessibleName: "Review the candidate", FocusOrder: 1, KeyboardReachable: true},
			{Name: "abort", AccessibleName: "Abort the run", FocusOrder: 2, KeyboardReachable: true},
		},
		AbortControl: "abort",
	}
}

// g7completeTimeline is a run in which every phase ran and every action succeeded.
func g7completeTimeline() console.Timeline {
	return console.BuildTimeline([]console.RecordedAction{
		g7action("a-1", console.PhaseArtifactBuild, console.OutcomeSucceeded),
		g7action("a-2", console.PhaseFoundationWarmup, console.OutcomeSucceeded),
		g7action("a-3", console.PhaseDependencyAllocation, console.OutcomeSucceeded),
		g7action("a-4", console.PhaseMigration, console.OutcomeSucceeded),
		g7action("a-5", console.PhaseGates, console.OutcomeSucceeded),
	})
}

// ---------------------------------------------------------------------------
// Attacks: progress
// ---------------------------------------------------------------------------

// TestTheTimelineLayerRefusesToCallAnUncertainOutcomeComplete is the first and the
// most naive attack: a native call that never reported back is drawn as though it
// worked. The timeline builder and the action resolver are the layers that stop it,
// because neither has a path from an uncertain outcome to a success.
func TestTheTimelineLayerRefusesToCallAnUncertainOutcomeComplete(t *testing.T) {
	timeline := console.BuildTimeline([]console.RecordedAction{
		g7action("a-1", console.PhaseMigration, console.OutcomeUncertain),
	})
	row, ok := timeline.Phase(console.PhaseMigration)
	if !ok {
		t.Fatal("the migration phase must be present in the timeline")
	}
	if row.State == console.PhaseComplete {
		t.Fatalf("phase state = %q, want %q: an unsettled native outcome must never be drawn as a success",
			row.State, console.PhaseComplete)
	}
	if row.State != console.PhaseUncertain {
		t.Fatalf("phase state = %q, want %q", row.State, console.PhaseUncertain)
	}

	view := console.Resolve(console.OutcomeUncertain, "the provider never reported back")
	if view.State == console.StateSucceeded {
		t.Fatalf("the resolver presented an uncertain outcome as %q", view.State)
	}
	if view.State != console.StateUncertain {
		t.Fatalf("resolved state = %q, want %q", view.State, console.StateUncertain)
	}

	// An outcome the console does not recognise is unknown, not good. A renderer
	// that meets a new outcome string must not be handed a green tick.
	unknown := console.Resolve(console.ActionOutcome("something-new"), "the outcome was not one we know")
	if unknown.State == console.StateSucceeded {
		t.Fatalf("an unrecognised outcome was presented as %q", unknown.State)
	}
	if unknown.State != console.StateUncertain {
		t.Fatalf("an unrecognised outcome resolved to %q, want %q", unknown.State, console.StateUncertain)
	}
}

// TestTheTimelineLayerBlocksLaterPhasesAfterAFailedPhase is the next step up: the
// failed phase is drawn honestly, but the phases after it are drawn as though they
// had happened. The timeline builder blocks them, and the timeline validator refuses
// a hand-edited timeline that claims the same progress, because a renderer may be
// handed one.
func TestTheTimelineLayerBlocksLaterPhasesAfterAFailedPhase(t *testing.T) {
	timeline := console.BuildTimeline([]console.RecordedAction{
		g7action("a-1", console.PhaseFoundationWarmup, console.OutcomeFailed),
	})
	failed, ok := timeline.Phase(console.PhaseFoundationWarmup)
	if !ok {
		t.Fatal("the foundation-warmup phase must be present")
	}
	if failed.State != console.PhaseFailed {
		t.Fatalf("phase state = %q, want %q", failed.State, console.PhaseFailed)
	}
	for _, p := range []console.Phase{console.PhaseDependencyAllocation, console.PhaseMigration, console.PhaseGates} {
		row, _ := timeline.Phase(p)
		if row.State == console.PhaseComplete {
			t.Errorf("phase %q was drawn complete after an earlier failure", p)
		}
		if row.State != console.PhaseBlocked {
			t.Errorf("phase %q state = %q, want %q", p, row.State, console.PhaseBlocked)
		}
		if !strings.Contains(row.Reason, string(console.PhaseFoundationWarmup)) {
			t.Errorf("phase %q reason = %q, want the blocking phase named", p, row.Reason)
		}
	}

	tampered := console.BuildTimeline([]console.RecordedAction{
		g7action("a-1", console.PhaseFoundationWarmup, console.OutcomeFailed),
	})
	tampered.Phases[len(tampered.Phases)-1].State = console.PhaseComplete
	if err := tampered.Validate(); !errors.Is(err, console.ErrInconsistentTimeline) {
		t.Fatalf("Validate error = %v, want ErrInconsistentTimeline", err)
	}
}

// TestTheTimelineLayerReportsAPhaseWithNoRecordedActionAsPending: a phase with
// nothing recorded is not a phase that quietly succeeded. The timeline builder is
// the layer that stops it.
func TestTheTimelineLayerReportsAPhaseWithNoRecordedActionAsPending(t *testing.T) {
	timeline := console.BuildTimeline([]console.RecordedAction{
		g7action("a-1", console.PhaseArtifactBuild, console.OutcomeSucceeded),
	})
	row, ok := timeline.Phase(console.PhaseGates)
	if !ok {
		t.Fatal("the gates phase must be present in the timeline")
	}
	if row.State == console.PhaseComplete {
		t.Fatalf("phase state = %q, want %q: a phase with no recorded action has not completed",
			row.State, console.PhaseComplete)
	}
	if row.State != console.PhasePending {
		t.Fatalf("phase state = %q, want %q", row.State, console.PhasePending)
	}
	if row.Actions != 0 {
		t.Fatalf("recorded actions = %d, want 0", row.Actions)
	}
	if !row.LastUpdate.IsZero() {
		t.Fatalf("last update = %s, want the zero time", row.LastUpdate)
	}
}

// ---------------------------------------------------------------------------
// Attacks: meaning without colour
// ---------------------------------------------------------------------------

// TestTheBadgeLayerRefusesToLetColourBeTheOnlySignal: two states that share a
// shape can only be told apart by colour, and a badge with no text is a badge a
// screen reader has nothing to say. The badge builder is the layer that stops both.
func TestTheBadgeLayerRefusesToLetColourBeTheOnlySignal(t *testing.T) {
	failedGlyph, ok := console.GlyphFor("failed")
	if !ok {
		t.Fatal("the failed state must carry a canonical glyph")
	}
	ambiguous := []console.Badge{
		{State: "failed", Label: "Failed", Glyph: failedGlyph},
		{State: "uncertain", Label: "Uncertain", Glyph: failedGlyph},
	}
	if _, err := console.NewBadges(ambiguous); !errors.Is(err, console.ErrAmbiguousGlyph) {
		t.Fatalf("NewBadges error = %v, want ErrAmbiguousGlyph", err)
	}

	if _, err := console.NewBadge("failed", "   "); !errors.Is(err, console.ErrNoBadgeLabel) {
		t.Fatalf("NewBadge error = %v, want ErrNoBadgeLabel", err)
	}
	if _, err := console.NewBadge("no-such-state", "Something"); !errors.Is(err, console.ErrNoBadgeGlyph) {
		t.Fatalf("NewBadge error = %v, want ErrNoBadgeGlyph", err)
	}

	// The registry is the reason a badge can be built from a state alone, so no
	// two rendered states may end up sharing a shape.
	owners := map[string]string{}
	for _, state := range []string{
		"idle", "pending", "loading", "running", "succeeded",
		"failed", "uncertain", "denied", "conflict", "expired", "quota", "blocked",
	} {
		glyph, ok := console.GlyphFor(state)
		if !ok {
			t.Errorf("state %q has no canonical glyph, so its badge would rest on colour", state)
			continue
		}
		if owner, taken := owners[glyph]; taken {
			t.Errorf("states %q and %q share the glyph %q", owner, state, glyph)
		}
		owners[glyph] = state
	}
}

// TestTheChartLayerRefusesAChartWithNoTableAlternative: a picture with no table is
// unreadable with a screen reader, and an alternative that does not carry the same
// series is not an alternative. The chart builder is the layer that stops both, and
// it refuses an over-large table rather than truncating it.
func TestTheChartLayerRefusesAChartWithNoTableAlternative(t *testing.T) {
	chart := console.Chart{
		Title:  "Queue depth",
		Series: []string{"queued", "admitted"},
		Points: []console.Point{{Label: "now", Value: 3}},
	}
	if _, err := console.NewChart(chart); !errors.Is(err, console.ErrNoTableAlternative) {
		t.Fatalf("NewChart error = %v, want ErrNoTableAlternative", err)
	}

	chart.Alternative = &console.Table{
		Title:   "Queue depth",
		Columns: []string{"series", "value"},
		Rows:    [][]string{{"queued", "3"}},
	}
	if _, err := console.NewChart(chart); !errors.Is(err, console.ErrNoTableAlternative) {
		t.Fatalf("NewChart error = %v, want ErrNoTableAlternative for an alternative missing a series", err)
	}

	rows := make([][]string, 0, console.MaxTableRows+1)
	for i := 0; i <= console.MaxTableRows; i++ {
		rows = append(rows, []string{"queued", "1"})
	}
	chart.Alternative = &console.Table{
		Title:   "Queue depth",
		Columns: []string{"series", "value"},
		Rows:    rows,
	}
	if _, err := console.NewChart(chart); !errors.Is(err, console.ErrTableTooLarge) {
		t.Fatalf("NewChart error = %v, want ErrTableTooLarge", err)
	}
}

// ---------------------------------------------------------------------------
// Attacks: the review and abort tasks
// ---------------------------------------------------------------------------

// TestTheScreenLayerRefusesAControlThatIsUnnamedOrUnreachable: a control with no
// accessible name is a control a screen reader cannot announce, and a control the
// keyboard cannot reach is a control an operator cannot use. The screen validator
// is the layer that stops both, and it refuses two controls that share a focus
// order, because one of them is then unreachable in the tab order whatever the
// model says.
func TestTheScreenLayerRefusesAControlThatIsUnnamedOrUnreachable(t *testing.T) {
	unnamed := g7screen()
	unnamed.Controls[0].AccessibleName = "   "
	if err := unnamed.Validate(); !errors.Is(err, console.ErrNoAccessibleName) {
		t.Fatalf("Validate error = %v, want ErrNoAccessibleName", err)
	}

	unreachable := g7screen()
	unreachable.Controls[1].KeyboardReachable = false
	if err := unreachable.Validate(); !errors.Is(err, console.ErrNotKeyboardReachable) {
		t.Fatalf("Validate error = %v, want ErrNotKeyboardReachable", err)
	}

	collided := g7screen()
	collided.Controls[1].FocusOrder = collided.Controls[0].FocusOrder
	if err := collided.Validate(); !errors.Is(err, console.ErrDuplicateFocusOrder) {
		t.Fatalf("Validate error = %v, want ErrDuplicateFocusOrder", err)
	}
}

// TestTheScreenLayerRefusesALiveRegionOverTheAbortControl: a chart that updates
// over the stop button is exactly the failure the requirement names, and a stop
// button nobody can hit is not a stop button. The screen validator is the layer
// that stops it, whether the overlap is stated or merely announced.
func TestTheScreenLayerRefusesALiveRegionOverTheAbortControl(t *testing.T) {
	covering := g7screen()
	covering.Regions = append(covering.Regions,
		console.Region{Name: "chart", Live: true, DeclaresCoverage: true, Covers: []string{"abort"}})
	if err := covering.Validate(); !errors.Is(err, console.ErrAbortObscured) {
		t.Fatalf("Validate error = %v, want ErrAbortObscured", err)
	}

	announcing := g7screen()
	announcing.Regions = append(announcing.Regions,
		console.Region{Name: "chart", Live: true, DeclaresCoverage: true, Announces: "the abort control is covered"})
	if err := announcing.Validate(); !errors.Is(err, console.ErrAbortObscured) {
		t.Fatalf("Validate error = %v, want ErrAbortObscured", err)
	}
}

// TestTheScreenLayerRefusesAScreenWithNoAbortControl: a screen that names no
// abort control, or names one that does not exist, gives the operator no way to
// stop the run. The screen validator is the layer that stops it.
func TestTheScreenLayerRefusesAScreenWithNoAbortControl(t *testing.T) {
	missing := g7screen()
	missing.AbortControl = ""
	if err := missing.Validate(); !errors.Is(err, console.ErrNoAbortControl) {
		t.Fatalf("Validate error = %v, want ErrNoAbortControl", err)
	}

	phantom := g7screen()
	phantom.AbortControl = "stop"
	if err := phantom.Validate(); !errors.Is(err, console.ErrNoAbortControl) {
		t.Fatalf("Validate error = %v, want ErrNoAbortControl for a control that does not exist", err)
	}
}

// ---------------------------------------------------------------------------
// Attacks: untrusted output
// ---------------------------------------------------------------------------

// TestTheLogLayerStripsEscapeSequencesBeforeTheTerminalSeesThem: a terminal that
// receives "\x1b[31m" does not print it, it applies the colour and carries on. The
// log renderer is the layer that stops it, and it drops the escape character
// itself, so a sequence this scanner does not recognise still cannot reach the
// terminal.
func TestTheLogLayerStripsEscapeSequencesBeforeTheTerminalSeesThem(t *testing.T) {
	view := console.RenderLog("\x1b[31mred\x1b[0m and \x1b[1;32mgreen\x1b[0m", console.MaxLogBytes)
	if strings.ContainsRune(view.Content, 0x1b) {
		t.Fatalf("content = %q, want no escape byte left for the terminal", view.Content)
	}
	if view.Content != "red and green" {
		t.Fatalf("content = %q, want the text without the sequences", view.Content)
	}

	bare := console.RenderLog("a\x1bb", console.MaxLogBytes)
	if strings.ContainsRune(bare.Content, 0x1b) {
		t.Fatalf("content = %q, want no escape byte left for the terminal", bare.Content)
	}
	if bare.Content != "ab" {
		t.Fatalf("content = %q, want %q", bare.Content, "ab")
	}

	if got := console.StripANSI("\x1b[31mred\x1b[0m"); got != "red" {
		t.Fatalf("StripANSI = %q, want %q", got, "red")
	}
}

// TestTheEscapingLayerMakesUntrustedMarkupInert: a log line that happens to
// contain markup must not become markup. The exported escaping helper is the layer
// that stops it, applied to the fields that carry untrusted text rather than to the
// whole log, so a legitimate angle bracket in a JSON line is not mangled.
func TestTheEscapingLayerMakesUntrustedMarkupInert(t *testing.T) {
	const hostile = "build step failed: <script>alert('x')</script>"

	escaped := console.EscapeHTML(hostile)
	if strings.Contains(escaped, "<script>") {
		t.Fatalf("escaped = %q, want no markup", escaped)
	}
	if !strings.Contains(escaped, "&lt;script&gt;") {
		t.Fatalf("escaped = %q, want the angle brackets escaped", escaped)
	}

	// The renderer would escape the bounded log it is about to draw, so the whole
	// view is inert and not just the field that happened to be hostile.
	view := console.RenderLog(hostile, console.MaxLogBytes)
	rendered := console.EscapeHTML(view.Content)
	if strings.Contains(rendered, "<script>") {
		t.Fatalf("rendered = %q, want no markup", rendered)
	}
	if rendered != escaped {
		t.Fatalf("rendered = %q, want the same escaping as the field itself", rendered)
	}

	// A legitimate angle bracket in a log line is not markup, so it must survive
	// the bounded render unchanged and only be escaped at the point of rendering.
	json := console.RenderLog(`{"name":"acme"}`, console.MaxLogBytes)
	if json.Content != `{"name":"acme"}` {
		t.Fatalf("content = %q, want the log text unchanged", json.Content)
	}
}

// TestTheLogLayerSaysWhenTheCapWithheldContent: content beyond the cap is cut,
// and the view says so. A log that looks complete but is not is a log that hides
// data, so the truncation flag is the layer that stops it.
func TestTheLogLayerSaysWhenTheCapWithheldContent(t *testing.T) {
	view := console.RenderLog(strings.Repeat("a", 100), 10)
	if len(view.Content) != 10 {
		t.Fatalf("content = %d bytes, want 10", len(view.Content))
	}
	if !view.Truncated {
		t.Fatal("the view must report that the cap withheld content")
	}
	if view.OriginalBytes != 100 {
		t.Fatalf("original bytes = %d, want 100", view.OriginalBytes)
	}

	whole := console.RenderLog("short", console.MaxLogBytes)
	if whole.Truncated {
		t.Fatal("content that fits must not be reported as truncated")
	}
	if whole.Content != "short" {
		t.Fatalf("content = %q, want the whole log", whole.Content)
	}

	// The bound the renderer uses by default bounds it too.
	capped := console.RenderLog(strings.Repeat("a", console.MaxLogBytes+1), console.MaxLogBytes)
	if !capped.Truncated {
		t.Fatal("a log over the cap must be reported as truncated")
	}
	if len(capped.Content) != console.MaxLogBytes {
		t.Fatalf("content = %d bytes, want the cap %d", len(capped.Content), console.MaxLogBytes)
	}
}

// ---------------------------------------------------------------------------
// Attacks: tenancy
// ---------------------------------------------------------------------------

// TestTheScopeLayerKeepsAnotherTenantsRepositoriesOutOfTheResultsAndTheCount: a
// repository belonging to another organization, or to a project outside the scope,
// must not appear in a search and must not be counted either, because a counter
// leaks the existence of a repository through a number. The scope filter is the
// layer that stops it, and it is applied again here even though the caller
// believes it has already scoped the set.
func TestTheScopeLayerKeepsAnotherTenantsRepositoriesOutOfTheResultsAndTheCount(t *testing.T) {
	scope := g7scope()
	catalogue := g7catalogue()

	otherOrg := console.Search(catalogue, scope, "secret-api")
	if len(otherOrg) != 0 {
		t.Fatalf("found = %v, want nothing: another tenant's repository must not be revealed", otherOrg)
	}
	for _, r := range otherOrg {
		if strings.Contains(r.FullName, "secret-api") {
			t.Fatalf("found = %v, want no other tenant's repository", otherOrg)
		}
	}

	outsideProject := console.Search(catalogue, scope, "billing")
	if len(outsideProject) != 0 {
		t.Fatalf("found = %v, want nothing: a repository outside the scoped projects is out of scope", outsideProject)
	}

	if got := console.Count(catalogue, scope, "repositories").Value; got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
	if got := console.CountMatching(catalogue, scope, "secret-api").Value; got != 0 {
		t.Fatalf("matching count = %d, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// Attacks: bounded input
// ---------------------------------------------------------------------------

// TestTheFilterLayerRefusesAnUnboundedFilter: an unbounded filter is a client-side
// denial of service, and a filter that can carry an unbounded value can carry
// anything the caller likes into a query. The filter validator is the layer that
// stops it.
func TestTheFilterLayerRefusesAnUnboundedFilter(t *testing.T) {
	values := make([]string, 0, console.MaxFilterValues+1)
	for i := 0; i <= console.MaxFilterValues; i++ {
		values = append(values, "acme")
	}
	tooMany := console.Filter{Field: "organization", Values: values}
	if err := tooMany.Validate(); !errors.Is(err, console.ErrFilterTooLarge) {
		t.Fatalf("Validate error = %v, want ErrFilterTooLarge", err)
	}

	tooLong := console.Filter{
		Field:  "name",
		Values: []string{strings.Repeat("x", console.MaxFilterValueLength+1)},
	}
	if err := tooLong.Validate(); !errors.Is(err, console.ErrFilterValueTooLong) {
		t.Fatalf("Validate error = %v, want ErrFilterValueTooLong", err)
	}

	fieldless := console.Filter{Values: []string{"acme"}}
	if err := fieldless.Validate(); !errors.Is(err, console.ErrNoFilterField) {
		t.Fatalf("Validate error = %v, want ErrNoFilterField", err)
	}
}

// ---------------------------------------------------------------------------
// Attacks: actionable states
// ---------------------------------------------------------------------------

// TestTheActionLayerRefusesAnActionWithNoWayForward: a denial with no route
// forward is a support ticket rather than an answer, and a spinner with no
// explanation is a spinner the operator cannot read. The action validator is the
// layer that stops both, and the resolver is what keeps a caller who forgot from
// shipping a dead end.
func TestTheActionLayerRefusesAnActionWithNoWayForward(t *testing.T) {
	for _, state := range []console.ActionState{
		console.StateDenied, console.StateConflict, console.StateExpired,
		console.StateQuota, console.StateUncertain,
	} {
		t.Run(string(state), func(t *testing.T) {
			view := console.ActionView{ActionID: "a-1", State: state}
			if err := view.Validate(); !errors.Is(err, console.ErrNoActionReason) {
				t.Fatalf("Validate error = %v, want ErrNoActionReason", err)
			}
			view.Reason = "the platform refused the action"
			if err := view.Validate(); !errors.Is(err, console.ErrNoRecoveryHint) {
				t.Fatalf("Validate error = %v, want ErrNoRecoveryHint", err)
			}
			view.Recovery = "ask an administrator for the entitlement"
			if err := view.Validate(); err != nil {
				t.Fatalf("Validate error = %v, want nil", err)
			}
		})
	}

	loading := console.ActionView{ActionID: "a-2", State: console.StateLoading}
	if err := loading.Validate(); !errors.Is(err, console.ErrNoActionReason) {
		t.Fatalf("Validate error = %v, want ErrNoActionReason for a loading action that says nothing", err)
	}

	// The resolver fills the gap in, so a caller who forgot cannot ship a state
	// the operator has to write a ticket about.
	resolved := console.ResolveDetail(console.OutcomeUncertain, "", "")
	if strings.TrimSpace(resolved.Recovery) == "" {
		t.Fatal("a resolved uncertain action must name a way forward")
	}
	if err := resolved.Validate(); err != nil {
		t.Fatalf("Validate error = %v, want nil", err)
	}
}

// TestTheActionLayerRefusesASuccessWithNoOperationIdentity: "it worked" that
// carries no durable operation and version cannot be audited or repeated. The
// action validator is the layer that stops it.
func TestTheActionLayerRefusesASuccessWithNoOperationIdentity(t *testing.T) {
	view := console.ActionView{ActionID: "a-1", State: console.StateSucceeded, Reason: "the gate passed"}
	if err := view.Validate(); !errors.Is(err, console.ErrNoOperationIdentity) {
		t.Fatalf("Validate error = %v, want ErrNoOperationIdentity", err)
	}
	view.OperationID = "op-1"
	if err := view.Validate(); !errors.Is(err, console.ErrNoOperationIdentity) {
		t.Fatalf("Validate error = %v, want ErrNoOperationIdentity for the missing version", err)
	}
	view.Version = 3
	if err := view.Validate(); err != nil {
		t.Fatalf("Validate error = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// Attacks: admission
// ---------------------------------------------------------------------------

// TestTheAdmissionLayerRefusesToHideAFailedCheckOrALapsedExpiry: an admission view
// that showed a green queue position while a policy check had failed would be a
// console lying about admission, and a view that showed a position for an
// admission nobody may use any more sends the operator into a queue that will
// never admit them. The admission validator is the layer that stops both.
func TestTheAdmissionLayerRefusesToHideAFailedCheckOrALapsedExpiry(t *testing.T) {
	hidden := console.AdmissionView{
		Position:  0,
		ExpiresAt: g7now.Add(30 * time.Minute),
		Checks: []console.PolicyCheck{
			{Name: "isolation", Passed: true},
			{Name: "quota", Passed: false, Detail: "the team is over its quota"},
		},
	}
	if err := hidden.Validate(); !errors.Is(err, console.ErrPolicyCheckFailed) {
		t.Fatalf("Validate error = %v, want ErrPolicyCheckFailed", err)
	}

	lapsed := console.AdmissionView{
		Position:  0,
		Checks:    []console.PolicyCheck{{Name: "isolation", Passed: true}},
		ExpiresAt: g7now.Add(-time.Minute),
	}
	if err := lapsed.ValidateAt(g7now); !errors.Is(err, console.ErrExpiredAdmission) {
		t.Fatalf("ValidateAt error = %v, want ErrExpiredAdmission", err)
	}
}

// ---------------------------------------------------------------------------
// Negative control
// ---------------------------------------------------------------------------

// A gate that cannot fail is not a gate. This test breaks each of the console's
// own invariants in the test data and requires the console's checker to notice,
// which is the only evidence that the attacks above are testing something.
//
// The intact case is checked alongside every broken one, so the control also
// proves the checkers are not simply refusing everything: each verdict has to
// flip because the data was broken, not because the console refuses all input.
func TestTheConsoleCheckerNoticesWhenItsOwnInvariantsAreBroken(t *testing.T) {
	cases := []struct {
		name    string
		intact  func() error
		broken  func() error
		wantErr error
	}{
		{
			name: "a timeline that claims progress after a failure",
			intact: func() error {
				return g7completeTimeline().Validate()
			},
			broken: func() error {
				tampered := console.BuildTimeline([]console.RecordedAction{
					g7action("a-1", console.PhaseFoundationWarmup, console.OutcomeFailed),
				})
				tampered.Phases[len(tampered.Phases)-1].State = console.PhaseComplete
				return tampered.Validate()
			},
			wantErr: console.ErrInconsistentTimeline,
		},
		{
			name: "two states sharing one glyph",
			intact: func() error {
				_, err := console.NewBadges([]console.Badge{
					{State: "failed", Label: "Failed", Glyph: "x"},
					{State: "uncertain", Label: "Uncertain", Glyph: "y"},
				})
				return err
			},
			broken: func() error {
				_, err := console.NewBadges([]console.Badge{
					{State: "failed", Label: "Failed", Glyph: "x"},
					{State: "uncertain", Label: "Uncertain", Glyph: "x"},
				})
				return err
			},
			wantErr: console.ErrAmbiguousGlyph,
		},
		{
			name: "a control the keyboard cannot reach",
			intact: func() error {
				return g7screen().Validate()
			},
			broken: func() error {
				tampered := g7screen()
				tampered.Controls[1].KeyboardReachable = false
				return tampered.Validate()
			},
			wantErr: console.ErrNotKeyboardReachable,
		},
		{
			name: "a success with no operation identity",
			intact: func() error {
				return console.ActionView{
					ActionID: "a-1", State: console.StateSucceeded,
					Reason: "the gate passed", OperationID: "op-1", Version: 1,
				}.Validate()
			},
			broken: func() error {
				return console.ActionView{
					ActionID: "a-1", State: console.StateSucceeded,
					Reason: "the gate passed",
				}.Validate()
			},
			wantErr: console.ErrNoOperationIdentity,
		},
		{
			name: "an admission view hiding a failed check",
			intact: func() error {
				return console.AdmissionView{
					Position:  1,
					ExpiresAt: g7now.Add(30 * time.Minute),
					Checks:    []console.PolicyCheck{{Name: "isolation", Passed: true}},
				}.Validate()
			},
			broken: func() error {
				return console.AdmissionView{
					Position:  1,
					ExpiresAt: g7now.Add(30 * time.Minute),
					Checks: []console.PolicyCheck{
						{Name: "isolation", Passed: true},
						{Name: "quota", Passed: false, Detail: "over quota"},
					},
				}.Validate()
			},
			wantErr: console.ErrPolicyCheckFailed,
		},
		{
			name: "a chart with no table alternative",
			intact: func() error {
				_, err := console.NewChart(console.Chart{
					Title:  "Queue depth",
					Series: []string{"queued"},
					Alternative: &console.Table{
						Title:   "Queue depth",
						Columns: []string{"series", "value"},
						Rows:    [][]string{{"queued", "3"}},
					},
				})
				return err
			},
			broken: func() error {
				_, err := console.NewChart(console.Chart{
					Title:  "Queue depth",
					Series: []string{"queued"},
				})
				return err
			},
			wantErr: console.ErrNoTableAlternative,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.intact(); err != nil {
				t.Fatalf("the intact console was refused, so the checker cannot be trusted: %v", err)
			}
			if err := c.broken(); !errors.Is(err, c.wantErr) {
				t.Fatalf("the checker did not notice the broken invariant: error = %v, want %v", err, c.wantErr)
			}
		})
	}

	// The scope layer is a filter rather than a checker, so its negative control is
	// the fail-closed behaviour: a scope that cannot say which tenant is asking
	// shows nothing rather than everything.
	unknown := console.Scope{ProjectIDs: []string{"p-1", "p-2", "p-9"}}
	if got := console.Count(g7catalogue(), unknown, "repositories").Value; got != 0 {
		t.Fatalf("a scope with no organization counted %d repositories, want 0", got)
	}
	if found := console.Search(g7catalogue(), unknown, "acme"); len(found) != 0 {
		t.Fatalf("a scope with no organization found %v, want nothing", found)
	}
}

// ---------------------------------------------------------------------------
// Honest control
// ---------------------------------------------------------------------------

// The honest control. Without it every attack above would also pass against a
// console that refuses everything, and a gate that cannot pass proves nothing.
//
// A fully valid console: five complete phases, badges with distinct glyphs and
// text, a chart with a table alternative carrying the same series, a screen whose
// abort control is named and keyboard reachable, a bounded log, in-scope
// repositories only, a bounded filter, an actionable action and an admission view
// with nothing hidden.
func TestAFullyValidConsolePassesEveryCheck(t *testing.T) {
	timeline := g7completeTimeline()
	if err := timeline.Validate(); err != nil {
		t.Fatalf("timeline Validate: %v", err)
	}
	for _, row := range timeline.Phases {
		if row.State != console.PhaseComplete {
			t.Errorf("phase %q state = %q, want complete", row.Phase, row.State)
		}
	}

	badges := make([]console.Badge, 0, 4)
	for _, state := range []string{"pending", "running", "succeeded", "failed", "uncertain"} {
		badge, err := console.NewBadge(state, "state "+state)
		if err != nil {
			t.Fatalf("NewBadge(%q): %v", state, err)
		}
		badges = append(badges, badge)
	}
	if _, err := console.NewBadges(badges); err != nil {
		t.Fatalf("NewBadges: %v", err)
	}

	chart, err := console.NewChart(console.Chart{
		Title:  "Queue depth",
		Series: []string{"queued", "admitted"},
		Points: []console.Point{{Label: "now", Value: 3}},
		Alternative: &console.Table{
			Title:   "Queue depth",
			Columns: []string{"series", "value"},
			Rows:    [][]string{{"queued", "3"}, {"admitted", "1"}},
		},
	})
	if err != nil {
		t.Fatalf("NewChart: %v", err)
	}
	if chart.Alternative == nil || len(chart.Alternative.Rows) != 2 {
		t.Fatalf("alternative = %+v, want a row per series", chart.Alternative)
	}

	if err := g7screen().Validate(); err != nil {
		t.Fatalf("screen Validate: %v", err)
	}

	log := console.RenderLog("build step 1 ok\nbuild step 2 ok\n", console.MaxLogBytes)
	if log.Truncated {
		t.Fatal("a log that fits must not be reported as truncated")
	}
	if log.OriginalBytes != len("build step 1 ok\nbuild step 2 ok\n") {
		t.Fatalf("original bytes = %d, want the whole log", log.OriginalBytes)
	}

	filter := console.Filter{Field: "organization", Values: []string{"acme", "beta"}}
	if err := filter.Validate(); err != nil {
		t.Fatalf("filter Validate: %v", err)
	}

	succeeded := console.ActionView{
		ActionID: "a-1", State: console.StateSucceeded, Reason: "the gate passed",
		OperationID: "op-1", Version: 2,
	}
	if err := succeeded.Validate(); err != nil {
		t.Fatalf("action Validate: %v", err)
	}

	admission := console.AdmissionView{
		Position: 3,
		Checks: []console.PolicyCheck{
			{Name: "isolation", Passed: true, Detail: "the candidate is isolated"},
			{Name: "quota", Passed: true, Detail: "within the team quota"},
		},
		Expected:  console.Envelope{CPU: 2, MemoryMB: 4096, CostCeiling: 12.5},
		Forecast:  "about 4 minutes",
		ExpiresAt: g7now.Add(30 * time.Minute),
	}
	if err := admission.ValidateAt(g7now); err != nil {
		t.Fatalf("admission ValidateAt: %v", err)
	}

	scope := g7scope()
	if got := console.Count(g7catalogue(), scope, "repositories").Value; got != 2 {
		t.Fatalf("count = %d, want the tenant's own two", got)
	}
	found := console.Search(g7catalogue(), scope, "acme")
	if len(found) != 2 {
		t.Fatalf("found = %v, want the tenant's own repositories", found)
	}
}

// TestEveryAttackNamesTheLayerThatStopsIt: a failure has to say which layer
// refused the attack, so every entry in the registry names itself and its layer.
func TestEveryAttackNamesTheLayerThatStopsIt(t *testing.T) {
	attacks := g7attacks()
	if len(attacks) == 0 {
		t.Fatal("the attack registry is empty, so the gate proves nothing")
	}
	for _, a := range attacks {
		if strings.TrimSpace(a.name) == "" || strings.TrimSpace(a.layer) == "" {
			t.Errorf("attack %+v does not name itself and the layer that stops it", a)
		}
	}
}
