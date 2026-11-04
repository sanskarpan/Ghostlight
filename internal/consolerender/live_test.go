package consolerender_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/a11ygate"
	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
)

func liveTimeline() console.Timeline {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	return console.BuildTimeline([]console.RecordedAction{
		{ID: "a1", Phase: console.PhaseArtifactBuild, Outcome: console.OutcomeSucceeded, StartedAt: now.Add(-8 * time.Minute)},
		{ID: "a2", Phase: console.PhaseFoundationWarmup, Outcome: console.OutcomeUncertain, StartedAt: now.Add(-3 * time.Minute), Detail: "the provider never answered"},
	})
}

// The live fragment carries its own polling attributes, because it replaces
// itself: without them the first swap stops every later one. This is the trap a
// prototype measured, and it is the reason the renderer emits the attributes
// rather than a caller patching them in.
func TestLiveTimelineCarriesItsPollingAttributes(t *testing.T) {
	out, err := consolerender.RenderTimelineLive(liveTimeline(), "/env/env-1/timeline", 4*time.Second)
	if err != nil {
		t.Fatalf("RenderTimelineLive: %v", err)
	}
	for _, want := range []string{
		`hx-get="/env/env-1/timeline"`,
		`hx-trigger="every 4s"`,
		`hx-swap="outerHTML"`,
		`aria-labelledby="timeline-heading"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("live timeline is missing %q", want)
		}
	}
	// The fragment must be the whole section, because outerHTML replaces it.
	if !strings.HasPrefix(out, `<section class="timeline"`) {
		t.Error("a swapped fragment must start at the section it replaces")
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "</section>") {
		t.Error("a swapped fragment must end at the section it replaces")
	}
}

// The live fragment is identical to the static one apart from its opening tag,
// so nothing about the states, reasons or glyphs changes when a page goes live.
func TestLiveTimelineKeepsEveryRowTheStaticOneHas(t *testing.T) {
	timeline := liveTimeline()
	static, err := consolerender.RenderTimeline(timeline)
	if err != nil {
		t.Fatalf("RenderTimeline: %v", err)
	}
	live, err := consolerender.RenderTimelineLive(timeline, "/env/env-1/timeline", time.Second)
	if err != nil {
		t.Fatalf("RenderTimelineLive: %v", err)
	}
	// Strip the added attributes and the two must be byte-identical: the only
	// permitted difference is the polling configuration.
	stripped := strings.Replace(live,
		` hx-get="/env/env-1/timeline" hx-trigger="every 1s" hx-swap="outerHTML"`, "", 1)
	if stripped != static {
		t.Error("the live timeline differs from the static one beyond its polling attributes")
	}
}

// A live timeline without a path or interval is refused: a poll target that is
// empty polls nothing, and an interval of zero is a busy loop.
func TestLiveTimelineRefusesAnUnusableConfiguration(t *testing.T) {
	timeline := liveTimeline()
	if _, err := consolerender.RenderTimelineLive(timeline, "", time.Second); err == nil {
		t.Error("an empty poll path must be refused")
	}
	if _, err := consolerender.RenderTimelineLive(timeline, "/x", 0); err == nil {
		t.Error("a zero interval must be refused")
	}
	if _, err := consolerender.RenderTimelineLive(timeline, "/x", -time.Second); err == nil {
		t.Error("a negative interval must be refused")
	}
}

// A page with a live timeline loads the script and carries the polling region;
// a static page loads nothing at all.
func TestOnlyALivePageLoadsTheScript(t *testing.T) {
	page := basePage()
	page.LiveTimelinePath = ""
	page.ScriptPath = "/assets/htmx.min.js"
	static, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage (static): %v", err)
	}
	if strings.Contains(static, "<script") {
		t.Error("a static page must load no script")
	}

	page.LiveTimelinePath = "/env/env-1/timeline"
	page.LiveTimelineEvery = 4 * time.Second
	live, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage (live): %v", err)
	}
	if !strings.Contains(live, `src="/assets/htmx.min.js"`) {
		t.Error("a live page must load the vendored script")
	}
	if !strings.Contains(live, `hx-get="/env/env-1/timeline"`) {
		t.Error("a live page must carry the polling region")
	}
	if !strings.Contains(live, `hx-trigger="every 4s"`) {
		t.Error("a live page must carry the poll interval")
	}
}

// A live page still passes the accessibility gate over its assembled bytes.
// This is the check that matters: the plan requires auditing the assembled page
// rather than a fragment, because a bare fragment fails five document-level
// rules by construction and auditing it would train the team to ignore the gate.
func TestALivePagePassesTheGate(t *testing.T) {
	page := basePage()
	page.LiveTimelinePath = "/env/env-1/timeline"
	page.LiveTimelineEvery = 4 * time.Second
	page.ScriptPath = "/assets/htmx.min.js"
	doc, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	report, err := a11ygate.AuditDocument(doc)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(report.Violations) != 0 {
		t.Errorf("the live page violates %d accessibility rules", len(report.Violations))
		for _, v := range report.Violations {
			t.Logf("  %s: %s", v.Rule, v.Detail)
		}
	}
}

// The abort control stays outside the live region and out of the polling swap.
// A page whose abort button were inside the swapped region would replace the
// control under the operator's finger.
func TestTheLiveRegionDoesNotContainTheAbortControl(t *testing.T) {
	page := basePage()
	page.LiveTimelinePath = "/env/env-1/timeline"
	page.LiveTimelineEvery = 4 * time.Second
	page.ScriptPath = "/assets/htmx.min.js"
	doc, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	regionStart := strings.Index(doc, `<section class="timeline"`)
	if regionStart < 0 {
		t.Fatal("the live region is missing from the page")
	}
	// Find the close of *this* section by counting nesting, so an earlier or
	// later section cannot be mistaken for it.
	depth := 0
	regionEnd := -1
	for i := regionStart; i < len(doc); i++ {
		if strings.HasPrefix(doc[i:], "<section") {
			depth++
		}
		if strings.HasPrefix(doc[i:], "</section>") {
			depth--
			if depth == 0 {
				regionEnd = i
				break
			}
		}
	}
	if regionEnd < 0 {
		t.Fatal("the live region is never closed")
	}
	region := doc[regionStart : regionEnd+len("</section>")]
	if strings.Contains(region, "Abort the run") {
		t.Error("the abort control must not be inside the swapped live region")
	}
	if !strings.Contains(doc, "Abort the run") {
		t.Error("the page must still carry the abort control")
	}
}
