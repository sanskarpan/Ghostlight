package gate_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
)

// This file is the renderer half of the G7 gate: checklist row G7.7, feature
// G-F08. The view-model half in g7_console_test.go refuses to hand a renderer a
// misleading presentation; this half checks that the renderer given a valid model
// does not reintroduce the defect in markup.
//
// The attacks are the ones a view model cannot see: a hostile repository name
// becoming an element, a log line becoming an event handler, an uncertain outcome
// acquiring a success badge on its way to the page, and a chart losing the table
// that is its only readable copy. Each test names the layer that stops it, because
// a page that is safe for the wrong reason is still a page that is safe by
// accident.
//
// What this suite may claim: that internal/consolerender refuses an invalid model
// and escapes every untrusted field it draws.
//
// What it may not claim: that the page is accessible in a real browser. It
// exercises the markup, not a screen reader, a real focus ring or a narrow device.
// That audit remains under G7.9 and GQ.5.

// g7rTimeline is a run whose foundation phase is uncertain and whose later phases
// are therefore blocked.
func g7rTimeline() console.Timeline {
	return console.BuildTimeline([]console.RecordedAction{
		{ID: "a1", Phase: console.PhaseArtifactBuild, Outcome: console.OutcomeSucceeded},
		{ID: "a2", Phase: console.PhaseFoundationWarmup, Outcome: console.OutcomeUncertain, Detail: "the provider never answered"},
	})
}

// g7rScreen is a screen with a reachable abort control and a live region that does
// not cover it.
func g7rScreen() console.Screen {
	return console.Screen{
		Title: "Run",
		Regions: []console.Region{
			{Name: "progress", Live: true, DeclaresCoverage: true, Announces: "the build is running"},
		},
		Controls: []console.Control{
			{Name: "review", AccessibleName: "Review the candidate", FocusOrder: 2, KeyboardReachable: true},
			{Name: "abort", AccessibleName: "Abort the run", FocusOrder: 1, KeyboardReachable: true},
		},
		AbortControl: "abort",
	}
}

// g7rPage is a complete, valid page.
func g7rPage() consolerender.Page {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	return consolerender.Page{
		Title:    "Run 42",
		Screen:   g7rScreen(),
		Timeline: g7rTimeline(),
		Actions: []console.ActionView{
			{
				ActionID: "a2", Label: "Warm the foundation", State: console.StateUncertain,
				Reason: "the provider never answered", Recovery: "check the provider's state before retrying",
			},
		},
		Charts: []console.Chart{{
			Title:  "Queue depth",
			Series: []string{"queued"},
			Alternative: &console.Table{
				Title:   "Queue depth",
				Columns: []string{"series", "value"},
				Rows:    [][]string{{"queued", "2"}},
			},
		}},
		Log: "\x1b[31m<script>alert(1)</script>\x1b[0m",
		Repositories: console.NewView(
			console.Scope{OrganizationID: "org-1", ProjectIDs: []string{"project-1"}},
			[]console.Repository{
				{ID: "repo-1", FullName: "acme/api", ProjectID: "project-1", OrganizationID: "org-1"},
			},
		),
		Now: now,
	}
}

// renderProblems lists the markup defects this gate checks for. It is deliberately
// simple and deliberately fallible, so the negative control below can require it to
// notice a defect rather than trusting an empty result.
func renderProblems(page string) []string {
	var problems []string
	if strings.Contains(page, "<script") {
		problems = append(problems, "raw script element")
	}
	if strings.ContainsRune(page, 0x1b) {
		problems = append(problems, "ANSI escape")
	}
	if hasEventHandler(page) {
		problems = append(problems, "event handler attribute")
	}
	return problems
}

// hasEventHandler looks for an event handler inside a real tag. It scans tags
// rather than the whole document, because the escaped text
// "&lt;img src=x onerror=alert(1)&gt;" is inert text and must not be reported as
// an attribute.
func hasEventHandler(page string) bool {
	for i := 0; i < len(page); i++ {
		if page[i] != '<' {
			continue
		}
		end := strings.IndexByte(page[i:], '>')
		if end < 0 {
			break
		}
		tag := strings.ToLower(page[i : i+end+1])
		if strings.Contains(tag, " onerror=") ||
			strings.Contains(tag, " onclick=") ||
			strings.Contains(tag, " onload=") {
			return true
		}
		i += end
	}
	return false
}

// TestTheRenderLayerRefusesToDrawAnInvalidScreen: the view model's refusals must
// survive the trip through the renderer. A renderer that drew a screen with no
// abort control would turn a safe model into an unsafe page.
func TestTheRenderLayerRefusesToDrawAnInvalidScreen(t *testing.T) {
	screen := g7rScreen()
	screen.AbortControl = ""
	if _, err := consolerender.RenderScreen(screen); !errors.Is(err, console.ErrNoAbortControl) {
		t.Fatalf("RenderScreen error = %v, want ErrNoAbortControl", err)
	}
}

// TestTheRenderLayerNeverDrawsAnUncertainOutcomeAsComplete: uncertainty must not
// acquire a success label on the way to markup.
func TestTheRenderLayerNeverDrawsAnUncertainOutcomeAsComplete(t *testing.T) {
	out, err := consolerender.RenderPage(g7rPage())
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	if !strings.Contains(out, ">Uncertain<") {
		t.Fatal("the page does not label the uncertain phase")
	}
	// The only complete phase is the artifact build; the uncertain phase and the
	// three phases blocked behind it must not be called complete.
	if got := strings.Count(out, ">Complete<"); got != 1 {
		t.Fatalf("the page carries %d complete labels, want 1", got)
	}
	if strings.Contains(out, "the provider never answered") == false {
		t.Fatal("the page drops the uncertain reason")
	}
}

// TestTheRenderLayerEscapesUntrustedMarkupEverywhere: every field a candidate, a
// tenant or a provider can influence is escaped at the point of writing.
func TestTheRenderLayerEscapesUntrustedMarkupEverywhere(t *testing.T) {
	page := g7rPage()
	page.Title = `<script>alert("title")</script>`
	page.Actions[0].Reason = `<img src=x onerror=alert(1)>`
	page.Log = `<script>alert("log")</script>`
	page.Repositories = console.NewView(
		console.Scope{OrganizationID: "org-1", ProjectIDs: []string{"project-1"}},
		[]console.Repository{
			{ID: "repo-1", FullName: `<svg onload=alert(1)>`, ProjectID: "project-1", OrganizationID: "org-1"},
		},
	)
	out, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	if problems := renderProblems(out); len(problems) > 0 {
		t.Fatalf("rendered page has problems: %v", problems)
	}
	for _, escaped := range []string{"&lt;script&gt;", "&lt;img src=x", "&lt;svg onload=alert(1)&gt;"} {
		if !strings.Contains(out, escaped) {
			t.Errorf("escaped text %q is missing", escaped)
		}
	}
}

// TestTheRenderLayerKeepsTheAbortControlReachable: the abort control is a real
// button, in the document, first in focus order, with its accessible name as its
// text, and no live region states coverage of it.
func TestTheRenderLayerKeepsTheAbortControlReachable(t *testing.T) {
	out, err := consolerender.RenderScreen(g7rScreen())
	if err != nil {
		t.Fatalf("RenderScreen: %v", err)
	}
	abort := strings.Index(out, `data-control="abort"`)
	review := strings.Index(out, `data-control="review"`)
	if abort < 0 || review < 0 || abort > review {
		t.Fatal("the abort control is missing or is not first in focus order")
	}
	if !strings.Contains(out, `data-abort="true"`) {
		t.Fatal("the abort control is not marked")
	}
	if !strings.Contains(out, ">Abort the run<") {
		t.Fatal("the abort control has no accessible text")
	}
	if !strings.Contains(out, `<button type="button"`) {
		t.Fatal("the controls are not buttons")
	}
	if !strings.Contains(out, `aria-live="polite"`) {
		t.Fatal("the live region does not announce")
	}
}

// TestTheRenderLayerRendersChartsWithTheirTableAlternative: a chart without its
// readable copy is a picture a screen reader cannot use.
func TestTheRenderLayerRendersChartsWithTheirTableAlternative(t *testing.T) {
	out, err := consolerender.RenderPage(g7rPage())
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	if !strings.Contains(out, "<caption>Queue depth</caption>") {
		t.Fatal("the chart's table alternative is missing or uncaptioned")
	}
	if !strings.Contains(out, "<td>queued</td>") {
		t.Fatal("the chart's table alternative drops its data")
	}
}

// TestTheRenderLayerRefusesALapsedAdmission: a queue the operator may no longer
// join is not drawn.
func TestTheRenderLayerRefusesALapsedAdmission(t *testing.T) {
	page := g7rPage()
	page.Admission = &console.AdmissionView{Position: 2, ExpiresAt: page.Now.Add(-time.Second)}
	if _, err := consolerender.RenderPage(page); !errors.Is(err, console.ErrExpiredAdmission) {
		t.Fatalf("RenderPage error = %v, want ErrExpiredAdmission", err)
	}
}

// TestTheRenderLayerRefusesAnUnboundedFilter: a filter that can grow without bound
// is a client-side denial of service and a query-widening risk.
func TestTheRenderLayerRefusesAnUnboundedFilter(t *testing.T) {
	page := g7rPage()
	values := make([]string, console.MaxFilterValues+1)
	page.Filters = []console.Filter{{Field: "name", Values: values}}
	if _, err := consolerender.RenderPage(page); !errors.Is(err, console.ErrFilterTooLarge) {
		t.Fatalf("RenderPage error = %v, want ErrFilterTooLarge", err)
	}
}

// TestTheRenderLayerNegativeControlNoticesADefect: a checker that cannot fail is
// not a checker. The gate feeds renderProblems a page that carries the defects the
// renderer exists to prevent, and requires the checker to notice each one.
func TestTheRenderLayerNegativeControlNoticesADefect(t *testing.T) {
	problems := renderProblems("<script>alert(1)</script><img src=x onerror=alert(1)>\x1b[31m")
	if len(problems) != 3 {
		t.Fatalf("renderProblems found %d problems, want 3: %v", len(problems), problems)
	}
}

// TestTheRenderedHonestPagePassesEveryCheck: the honest path is walked end to end,
// so the gate proves the page works rather than only that attacks fail.
func TestTheRenderedHonestPagePassesEveryCheck(t *testing.T) {
	out, err := consolerender.RenderPage(g7rPage())
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	if problems := renderProblems(out); len(problems) > 0 {
		t.Fatalf("the honest page has problems: %v", problems)
	}
	for _, want := range []string{
		"<!doctype html>",
		`<html lang="en">`,
		`name="viewport"`,
		`class="skip-link"`,
		`data-abort="true"`,
		"<caption>Queue depth</caption>",
		"acme/api",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the honest page is missing %q", want)
		}
	}
}
