package main

import (
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/consolerender"
)

// Every scenario must render. The command exists so people can run a
// screen-reader or usability session without assembling a page; a scenario
// whose model drifts out of validity would greet the participant with a 500,
// which is the one failure the tool must not have.
func TestEveryScenarioRenders(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	for _, s := range scenarios() {
		page, err := s.Build(now)
		if err != nil {
			t.Errorf("%s: model invalid: %v", s.Path, err)
			continue
		}
		html, err := consolerender.RenderPage(page)
		if err != nil {
			t.Errorf("%s: render: %v", s.Path, err)
			continue
		}
		for _, want := range []string{`<html lang="en">`, `id="main" tabindex="-1"`, `Abort the run`} {
			if !strings.Contains(html, want) {
				t.Errorf("%s: page does not contain %q", s.Path, want)
			}
		}
	}
}

// The uncertain scenario is the one study sessions are pointed at, so its
// shape is pinned: a blocked phase naming the phase the way the heading names
// it, and recovery advice for the stuck action.
func TestUncertainScenarioCarriesTheStudyShape(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	var run scenario
	for _, s := range scenarios() {
		if s.Path == "/run" {
			run = s
		}
	}
	if run.Build == nil {
		t.Fatal("no /run scenario")
	}
	page, err := run.Build(now)
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	html, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(html, "blocked by Foundation warmup") {
		t.Error("the blocked reason must name the phase the way its heading does")
	}
	if strings.Contains(html, "blocked by foundation-warmup") {
		t.Error("the blocked reason leaks the machine key")
	}
	if !strings.Contains(html, "Next step: check the provider") {
		t.Error("the stuck action carries no recovery advice")
	}
	for _, state := range []string{"complete", "uncertain", "blocked"} {
		if !strings.Contains(html, `data-state="`+state+`"`) {
			t.Errorf("the study page does not show a %s phase", state)
		}
	}
}
