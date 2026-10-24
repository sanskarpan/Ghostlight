package consolerender_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
)

// completedTimeline is a run in which every phase succeeded.
func completedTimeline() console.Timeline {
	finished := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	var actions []console.RecordedAction
	for _, phase := range console.PhaseOrder() {
		actions = append(actions, console.RecordedAction{
			ID:         string(phase),
			Phase:      phase,
			Outcome:    console.OutcomeSucceeded,
			FinishedAt: finished,
		})
	}
	return console.BuildTimeline(actions)
}

// validScreen is a screen with the review and abort controls.
func validScreen() console.Screen {
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

// basePage is a valid page the specific tests can break.
func basePage() consolerender.Page {
	return consolerender.Page{
		Title:    "Run 42",
		Screen:   validScreen(),
		Timeline: completedTimeline(),
		Now:      time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC),
		Repositories: console.NewView(
			console.Scope{OrganizationID: "org-1", ProjectIDs: []string{"project-1"}},
			[]console.Repository{
				{ID: "repo-1", FullName: "acme/api", ProjectID: "project-1", OrganizationID: "org-1"},
			},
		),
	}
}

func TestRenderTimelineShowsEveryPhaseWithTextAndGlyph(t *testing.T) {
	timeline := console.BuildTimeline([]console.RecordedAction{
		{ID: "a1", Phase: console.PhaseArtifactBuild, Outcome: console.OutcomeSucceeded},
		{ID: "a2", Phase: console.PhaseFoundationWarmup, Outcome: console.OutcomeUncertain, Detail: "the native call timed out"},
	})
	out, err := consolerender.RenderTimeline(timeline)
	if err != nil {
		t.Fatalf("RenderTimeline: %v", err)
	}
	for _, name := range []string{
		"Artifact build", "Foundation warmup", "Dependency allocation", "Migration", "Gates",
	} {
		if !strings.Contains(out, name) {
			t.Errorf("timeline does not name phase %q", name)
		}
	}
	if !strings.Contains(out, `data-state="uncertain"`) {
		t.Error("timeline does not render the uncertain state")
	}
	if !strings.Contains(out, ">Uncertain<") {
		t.Error("timeline does not carry the uncertain label")
	}
	if !strings.Contains(out, ">?<") {
		t.Error("timeline does not carry the uncertain glyph")
	}
	if !strings.Contains(out, "aria-hidden=\"true\"") {
		t.Error("the badge glyph is not hidden from screen readers")
	}
	// Only the succeeded phase may be called complete; the uncertain phase and
	// every phase blocked behind it must not be.
	if got := strings.Count(out, ">Complete<"); got != 1 {
		t.Errorf("timeline carries %d complete labels, want 1", got)
	}
	if !strings.Contains(out, "the native call timed out") {
		t.Error("timeline drops the recorded reason")
	}
}

func TestRenderTimelineRefusesAnIncoherentTimeline(t *testing.T) {
	_, err := consolerender.RenderTimeline(console.Timeline{})
	if !errors.Is(err, consolerender.ErrInvalidModel) {
		t.Fatalf("error = %v, want ErrInvalidModel", err)
	}
	if !errors.Is(err, console.ErrIncompleteTimeline) {
		t.Fatalf("error = %v, want the console's ErrIncompleteTimeline", err)
	}
}

func TestRenderActionsCarriesTheWayForward(t *testing.T) {
	action := console.ResolveDetail(console.OutcomeUncertain, "the provider never reported back", "check the provider's state")
	out, err := consolerender.RenderActions([]console.ActionView{action})
	if err != nil {
		t.Fatalf("RenderActions: %v", err)
	}
	if !strings.Contains(out, ">Uncertain<") {
		t.Error("action does not carry the uncertain label")
	}
	if !strings.Contains(out, "Next step: check the provider&#39;s state") {
		t.Errorf("action does not carry the recovery hint:\n%s", out)
	}
}

func TestRenderActionsRefusesAnActionWithNoWayForward(t *testing.T) {
	_, err := consolerender.RenderActions([]console.ActionView{
		{ActionID: "a1", State: console.StateDenied, Reason: "the entitlement is missing"},
	})
	if !errors.Is(err, consolerender.ErrInvalidModel) {
		t.Fatalf("error = %v, want ErrInvalidModel", err)
	}
	if !errors.Is(err, console.ErrNoRecoveryHint) {
		t.Fatalf("error = %v, want the console's ErrNoRecoveryHint", err)
	}
}

func TestRenderActionsRefusesASuccessWithNoOperationIdentity(t *testing.T) {
	_, err := consolerender.RenderActions([]console.ActionView{
		{ActionID: "a1", State: console.StateSucceeded, Reason: "it worked"},
	})
	if !errors.Is(err, console.ErrNoOperationIdentity) {
		t.Fatalf("error = %v, want ErrNoOperationIdentity", err)
	}
}

func TestRenderScreenPutsTheAbortControlFirstInFocusOrder(t *testing.T) {
	out, err := consolerender.RenderScreen(validScreen())
	if err != nil {
		t.Fatalf("RenderScreen: %v", err)
	}
	abort := strings.Index(out, `data-control="abort"`)
	review := strings.Index(out, `data-control="review"`)
	if abort < 0 || review < 0 {
		t.Fatalf("controls are missing from the screen:\n%s", out)
	}
	if abort > review {
		t.Error("the abort control is not first in the document's focus order")
	}
	if !strings.Contains(out, `data-abort="true"`) {
		t.Error("the abort control is not marked")
	}
	if !strings.Contains(out, ">Abort the run<") {
		t.Error("the abort control does not use its accessible name as its text")
	}
	if !strings.Contains(out, `aria-live="polite"`) {
		t.Error("the live region does not announce updates")
	}
}

func TestRenderScreenRefusesAScreenWithoutAnAbortControl(t *testing.T) {
	screen := validScreen()
	screen.AbortControl = ""
	_, err := consolerender.RenderScreen(screen)
	if !errors.Is(err, console.ErrNoAbortControl) {
		t.Fatalf("error = %v, want ErrNoAbortControl", err)
	}
}

func TestRenderScreenRefusesALiveRegionOverTheAbortControl(t *testing.T) {
	screen := validScreen()
	screen.Regions = append(screen.Regions,
		console.Region{Name: "chart", Live: true, DeclaresCoverage: true, Covers: []string{"abort"}})
	_, err := consolerender.RenderScreen(screen)
	if !errors.Is(err, console.ErrAbortObscured) {
		t.Fatalf("error = %v, want ErrAbortObscured", err)
	}
}

func TestRenderChartRendersItsTableAlternative(t *testing.T) {
	chart := console.Chart{
		Title:  "Queue depth",
		Series: []string{"queued", "admitted"},
		Points: []console.Point{{Label: "now", Value: 3}},
		Alternative: &console.Table{
			Title:   "Queue depth",
			Columns: []string{"series", "value"},
			Rows:    [][]string{{"queued", "3"}, {"admitted", "1"}},
		},
	}
	out, err := consolerender.RenderChart(chart)
	if err != nil {
		t.Fatalf("RenderChart: %v", err)
	}
	if !strings.Contains(out, "<table>") {
		t.Error("chart has no table alternative")
	}
	if !strings.Contains(out, "<caption>Queue depth</caption>") {
		t.Error("chart alternative has no caption")
	}
	if !strings.Contains(out, `<th scope="col">series</th>`) {
		t.Error("chart alternative has no column headings")
	}
	for _, series := range chart.Series {
		if !strings.Contains(out, "<td>"+series+"</td>") {
			t.Errorf("chart alternative drops series %q", series)
		}
	}
}

func TestRenderChartRefusesAChartWithNoTableAlternative(t *testing.T) {
	_, err := consolerender.RenderChart(console.Chart{Title: "Queue depth", Series: []string{"queued"}})
	if !errors.Is(err, console.ErrNoTableAlternative) {
		t.Fatalf("error = %v, want ErrNoTableAlternative", err)
	}
}

func TestRenderTableRefusesARaggedRow(t *testing.T) {
	_, err := consolerender.RenderTable(console.Table{
		Title:   "Usage",
		Columns: []string{"name", "value"},
		Rows:    [][]string{{"cpu"}},
	})
	if !errors.Is(err, consolerender.ErrInvalidModel) {
		t.Fatalf("error = %v, want ErrInvalidModel", err)
	}
}

func TestRenderLogStripsBoundsAndEscapes(t *testing.T) {
	out := consolerender.RenderLog("\x1b[31m<script>alert(1)</script>\x1b[0m", 1024)
	if strings.Contains(out, "<script>") {
		t.Fatal("log markup reached the document")
	}
	if strings.ContainsRune(out, 0x1b) {
		t.Fatal("an ANSI escape reached the document")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("log content was not escaped:\n%s", out)
	}
	if !strings.Contains(out, `tabindex="0"`) {
		t.Error("the log is not keyboard reachable")
	}

	truncated := consolerender.RenderLog(strings.Repeat("a", 100), 10)
	if !strings.Contains(truncated, "truncated") {
		t.Error("a truncated log does not say so")
	}
	if !strings.Contains(truncated, "100 bytes") {
		t.Error("a truncated log does not report the original size")
	}
}

func TestRenderPageEscapesUntrustedTextEverywhere(t *testing.T) {
	page := basePage()
	page.Title = `Run </title><script>alert(1)</script>`
	page.Actions = []console.ActionView{{
		ActionID: "a1",
		Label:    `<img src=x onerror=alert(1)>`,
		State:    console.StateFailed,
		Reason:   `<script>alert(2)</script>`,
	}}
	page.Log = `<script>alert(3)</script>`
	// The query both matches the repository and carries markup, so the search
	// input's value and the result list are exercised together.
	page.SearchQuery = "<b>"
	page.Repositories = console.NewView(
		console.Scope{OrganizationID: "org-1", ProjectIDs: []string{"project-1"}},
		[]console.Repository{
			{ID: "repo-1", FullName: "<b>evil</b>", ProjectID: "project-1", OrganizationID: "org-1"},
		},
	)
	out, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	for _, raw := range []string{"<script>", "<img src=x", "<b>evil</b>"} {
		if strings.Contains(out, raw) {
			t.Errorf("raw markup %q reached the document", raw)
		}
	}
	for _, escaped := range []string{"&lt;script&gt;", "&lt;img src=x", "&lt;b&gt;evil&lt;/b&gt;", `value="&lt;b&gt;"`} {
		if !strings.Contains(out, escaped) {
			t.Errorf("escaped text %q is missing from the document", escaped)
		}
	}
	if !strings.HasPrefix(out, "<!doctype html>") {
		t.Error("the page is not an HTML document")
	}
	if !strings.Contains(out, `<html lang="en">`) {
		t.Error("the document declares no language")
	}
	if !strings.Contains(out, `name="viewport"`) {
		t.Error("the document declares no viewport for a narrow screen")
	}
	if !strings.Contains(out, `class="skip-link"`) {
		t.Error("the document has no skip link")
	}
}

func TestRenderPageRefusesAnInvalidModel(t *testing.T) {
	cases := map[string]func(consolerender.Page) consolerender.Page{
		"no title": func(p consolerender.Page) consolerender.Page {
			p.Title = "   "
			return p
		},
		"no timeline": func(p consolerender.Page) consolerender.Page {
			p.Timeline = console.Timeline{}
			return p
		},
		"no abort control": func(p consolerender.Page) consolerender.Page {
			p.Screen.AbortControl = ""
			return p
		},
		"lapsed admission": func(p consolerender.Page) consolerender.Page {
			expired := console.AdmissionView{
				Position:  0,
				ExpiresAt: p.Now.Add(-time.Minute),
			}
			p.Admission = &expired
			return p
		},
		"unbounded filter": func(p consolerender.Page) consolerender.Page {
			values := make([]string, console.MaxFilterValues+1)
			for i := range values {
				values[i] = "value"
			}
			p.Filters = []console.Filter{{Field: "name", Values: values}}
			return p
		},
	}
	for name, breakPage := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := consolerender.RenderPage(breakPage(basePage())); err == nil {
				t.Fatal("RenderPage accepted an invalid model")
			} else if !errors.Is(err, consolerender.ErrInvalidModel) {
				t.Fatalf("error = %v, want ErrInvalidModel", err)
			}
		})
	}
}

func TestRenderPageRefusesALapsedAdmission(t *testing.T) {
	page := basePage()
	page.Admission = &console.AdmissionView{
		Position:  3,
		ExpiresAt: page.Now.Add(-time.Second),
	}
	_, err := consolerender.RenderPage(page)
	if !errors.Is(err, console.ErrExpiredAdmission) {
		t.Fatalf("error = %v, want ErrExpiredAdmission", err)
	}
}

func TestRenderPageRendersAdmissionAndFilters(t *testing.T) {
	page := basePage()
	page.Admission = &console.AdmissionView{
		Position: 3,
		Checks: []console.PolicyCheck{
			{Name: "repository-bound", Passed: true, Detail: "the installation covers the repository"},
		},
		Expected:  console.Envelope{CPU: 2, MemoryMB: 2048, CostCeiling: 1.25},
		Forecast:  "about four minutes",
		ExpiresAt: page.Now.Add(10 * time.Minute),
	}
	page.Filters = []console.Filter{{Field: "language", Values: []string{"go", "typescript"}}}
	out, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	for _, want := range []string{
		"Position in queue: <strong>3</strong>",
		"repository-bound",
		"the installation covers the repository",
		"2048 MB",
		"1.25",
		"about four minutes",
		`<legend>language</legend>`,
		`value="go"`,
		`value="typescript"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
}

func TestRenderPageKeepsAnotherTenantsRepositoryOutOfTheDocument(t *testing.T) {
	page := basePage()
	page.Repositories = console.NewView(
		console.Scope{OrganizationID: "org-1", ProjectIDs: []string{"project-1"}},
		[]console.Repository{
			{ID: "repo-1", FullName: "acme/api", ProjectID: "project-1", OrganizationID: "org-1"},
			{ID: "repo-2", FullName: "other/secret-service", ProjectID: "project-1", OrganizationID: "org-2"},
		},
	)
	out, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	if strings.Contains(out, "other/secret-service") {
		t.Fatal("another tenant's repository reached the document")
	}
	if !strings.Contains(out, "acme/api") {
		t.Fatal("the scoped repository is missing from the document")
	}
}

func TestRenderPageIsDeterministic(t *testing.T) {
	page := basePage()
	page.Actions = []console.ActionView{
		{ActionID: "a1", State: console.StateSucceeded, Reason: "the gate passed", OperationID: "op-1", Version: 2},
	}
	first, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := consolerender.RenderPage(page)
		if err != nil {
			t.Fatalf("RenderPage: %v", err)
		}
		if again != first {
			t.Fatalf("RenderPage is not deterministic on call %d", i+2)
		}
	}
}
