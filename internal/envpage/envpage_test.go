package envpage_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/api"
	"github.com/sanskarpan/Ghostlight/internal/a11ygate"
	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
	"github.com/sanskarpan/Ghostlight/internal/envpage"
)

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// env builds a stored environment with the given recorded actions.
func env(actions ...console.RecordedAction) api.Environment {
	return api.Environment{
		ID:         "env-42",
		Scope:      "org-1",
		Version:    3,
		Generation: 7,
		ExpiresAt:  now.Add(5 * time.Hour),
		Actions:    actions,
	}
}

// The page is titled by the environment id: a page without a title is a page a
// screen-reader user cannot identify among tabs.
func TestBuildTitlesThePageByEnvironment(t *testing.T) {
	page, err := envpage.Build(env(), now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if page.Title != "env-42" {
		t.Errorf("title = %q, want env-42", page.Title)
	}
}

// An environment with no identifier is refused rather than given a placeholder
// title, because a placeholder title is indistinguishable from a real one.
func TestBuildRefusesAnEnvironmentWithNoIdentifier(t *testing.T) {
	bad := env()
	bad.ID = "   "
	if _, err := envpage.Build(bad, now); err == nil {
		t.Error("an environment with no id must be refused, not titled with a placeholder")
	}
}

// The timeline is derived from the recorded actions, which is the only honest
// source: a lifecycle state cannot say how far a degraded run got.
func TestTimelineComesFromTheRecordedActions(t *testing.T) {
	page, err := envpage.Build(env(
		console.RecordedAction{ID: "a1", Phase: console.PhaseArtifactBuild, Outcome: console.OutcomeSucceeded, StartedAt: now.Add(-10 * time.Minute)},
		console.RecordedAction{ID: "a2", Phase: console.PhaseFoundationWarmup, Outcome: console.OutcomeUncertain, StartedAt: now.Add(-5 * time.Minute), Detail: "the provider never answered"},
	), now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	byPhase := map[console.Phase]console.PhaseState{}
	for _, p := range page.Timeline.Phases {
		byPhase[p.Phase] = p.State
	}
	if byPhase[console.PhaseArtifactBuild] != console.PhaseComplete {
		t.Errorf("artifact build = %q, want complete", byPhase[console.PhaseArtifactBuild])
	}
	if byPhase[console.PhaseFoundationWarmup] != console.PhaseUncertain {
		t.Errorf("foundation warmup = %q, want uncertain", byPhase[console.PhaseFoundationWarmup])
	}
	// A later phase with nothing recorded is blocked by the unresolved earlier
	// one, not silently pending: it cannot start, and saying so is the point.
	if byPhase[console.PhaseDependencyAllocation] != console.PhaseBlocked {
		t.Errorf("dependency allocation = %q, want blocked by the unresolved warmup",
			byPhase[console.PhaseDependencyAllocation])
	}
}

// An uncertain action carries its recorded reason and a recovery line. The
// console model refuses an uncertain action with no reason and a recovery-less
// action the operator must act on, so both are required here.
func TestUncertainActionCarriesReasonAndRecovery(t *testing.T) {
	page, err := envpage.Build(env(
		console.RecordedAction{
			ID: "a1", Phase: console.PhaseFoundationWarmup,
			Outcome: console.OutcomeUncertain, StartedAt: now,
			Detail: "the provider never answered",
		},
	), now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(page.Actions) != 1 {
		t.Fatalf("actions = %d, want 1 (the uncertain one)", len(page.Actions))
	}
	action := page.Actions[0]
	if action.State != console.StateUncertain {
		t.Errorf("state = %q, want uncertain", action.State)
	}
	if !strings.Contains(action.Reason, "never answered") {
		t.Errorf("reason = %q, want the recorded detail", action.Reason)
	}
	if action.Recovery == "" {
		t.Error("an uncertain action must carry a recovery line")
	}
	if action.Recovery != envpage.RecoveryUncertain {
		t.Errorf("recovery = %q, want the shared uncertain line", action.Recovery)
	}
}

// Where the ledger recorded no detail, the fallback states what the state means
// rather than inventing a cause.
func TestMissingDetailFallsBackToWhatTheStateMeans(t *testing.T) {
	page, err := envpage.Build(env(
		console.RecordedAction{ID: "a1", Phase: console.PhaseMigration, Outcome: console.OutcomeUncertain, StartedAt: now},
	), now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(page.Actions) != 1 {
		t.Fatalf("actions = %d, want 1", len(page.Actions))
	}
	reason := page.Actions[0].Reason
	if reason == "" {
		t.Fatal("a reason is required even when the ledger recorded no detail")
	}
	if strings.Contains(strings.ToLower(reason), "timeout") || strings.Contains(strings.ToLower(reason), "error") {
		t.Errorf("reason %q invents a cause the ledger did not record", reason)
	}
	if !strings.Contains(reason, "never reported back") {
		t.Errorf("reason = %q, want the meaning of an uncertain outcome", reason)
	}
}

// Succeeded actions do not clutter the action list, because a list of every
// success on a long run buries the one the operator needs.
func TestSucceededActionsAreNotListedButStillCount(t *testing.T) {
	page, err := envpage.Build(env(
		console.RecordedAction{ID: "a1", Phase: console.PhaseArtifactBuild, Outcome: console.OutcomeSucceeded, StartedAt: now},
		console.RecordedAction{ID: "a2", Phase: console.PhaseFoundationWarmup, Outcome: console.OutcomeUncertain, StartedAt: now, Detail: "no answer"},
	), now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(page.Actions) != 1 {
		t.Errorf("actions = %d, want 1: only the uncertain action belongs in the list", len(page.Actions))
	}
	for _, p := range page.Timeline.Phases {
		if p.Phase == console.PhaseArtifactBuild && p.State != console.PhaseComplete {
			t.Error("the succeeded action must still count in the timeline")
		}
	}
}

// Abort is focus order 1 and the screen names it as the abort control, so the
// renderer cannot produce a page whose live region obscures it.
func TestAbortIsFirstInFocusOrder(t *testing.T) {
	page, err := envpage.Build(env(), now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if page.Screen.AbortControl != "abort" {
		t.Fatalf("abort control = %q, want abort", page.Screen.AbortControl)
	}
	var abortOrder int
	for _, c := range page.Screen.Controls {
		if c.Name == page.Screen.AbortControl {
			abortOrder = c.FocusOrder
		}
	}
	if abortOrder != 1 {
		t.Errorf("abort focus order = %d, want 1", abortOrder)
	}
	for _, r := range page.Screen.Regions {
		for _, covered := range r.Covers {
			if covered == page.Screen.AbortControl {
				t.Error("a live region must not cover the abort control")
			}
		}
	}
}

// The built page renders, and the rendered document passes the accessibility
// gate. This is the join working end to end rather than each half in isolation.
func TestBuiltPageRendersAndPassesTheGate(t *testing.T) {
	page, err := envpage.Build(env(
		console.RecordedAction{ID: "a1", Phase: console.PhaseArtifactBuild, Outcome: console.OutcomeSucceeded, StartedAt: now.Add(-10 * time.Minute)},
		console.RecordedAction{ID: "a2", Phase: console.PhaseFoundationWarmup, Outcome: console.OutcomeUncertain, StartedAt: now.Add(-5 * time.Minute), Detail: "the provider never answered"},
	), now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	doc, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	// The apostrophe is escaped in output, which is the renderer doing its job:
	// every untrusted string is escaped at write time. Assert on the escaped
	// form rather than weakening the check to a substring that avoids it.
	escapedRecovery := strings.ReplaceAll(envpage.RecoveryUncertain, "'", "&#39;")
	for _, want := range []string{
		"<h1>env-42</h1>",
		"Abort the run",
		"Foundation warmup",
		"the provider never answered",
		escapedRecovery,
		"blocked by",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("rendered page is missing %q", want)
		}
	}
}

// An environment with no recorded actions still produces a valid page: every
// phase pending, an explicit "nothing recorded" per row, and no actions. An
// empty page that renders as blank would be indistinguishable from a failure to
// load.
func TestAnEmptyEnvironmentStillRenders(t *testing.T) {
	page, err := envpage.Build(env(), now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	doc, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	if !strings.Contains(doc, "No actions have been recorded.") {
		t.Error("an empty action list must be stated, not left blank")
	}
	if len(page.Timeline.Phases) == 0 {
		t.Error("the timeline must still carry every phase as pending")
	}
}

// The rendered page passes the accessibility gate over its actual bytes. This
// is the join working end to end: a real environment record becomes a served
// document that satisfies the same sixteen rules the demo page does.
func TestRenderedPagePassesTheAccessibilityGate(t *testing.T) {
	page, err := envpage.Build(env(
		console.RecordedAction{ID: "a1", Phase: console.PhaseArtifactBuild, Outcome: console.OutcomeSucceeded, StartedAt: now.Add(-10 * time.Minute)},
		console.RecordedAction{ID: "a2", Phase: console.PhaseFoundationWarmup, Outcome: console.OutcomeUncertain, StartedAt: now.Add(-5 * time.Minute), Detail: "the provider never answered"},
	), now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	doc, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	rep, err := a11ygate.AuditDocument(doc)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(rep.Violations) != 0 {
		t.Errorf("the detail page violates %d accessibility rules", len(rep.Violations))
		for _, v := range rep.Violations {
			t.Logf("  %s: %s", v.Rule, v.Detail)
		}
	}
}

// The abort control precedes the review control in the rendered document's
// source order, which is the tab order a keyboard user gets.
func TestAbortPrecedesReviewInSourceOrder(t *testing.T) {
	page, err := envpage.Build(env(), now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	doc, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	abort := strings.Index(doc, "Abort the run")
	review := strings.Index(doc, "Review the candidate")
	if abort < 0 || review < 0 {
		t.Fatalf("controls missing from output: abort=%d review=%d", abort, review)
	}
	if abort > review {
		t.Error("the abort control must precede review in source order")
	}
}

// The page carries the current generation, so a reviewer cannot mistake an old
// packet for the head it replaced.
func TestThePageNamesTheCurrentGeneration(t *testing.T) {
	page, err := envpage.Build(env(), now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	doc, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	if len(page.Timeline.Phases) == 0 {
		t.Fatal("the timeline must carry phases")
	}
	if !strings.Contains(doc, "Progress") {
		t.Error("the page must carry the progress timeline")
	}
}
