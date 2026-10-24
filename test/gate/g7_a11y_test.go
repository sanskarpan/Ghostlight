package gate_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/a11ygate"
	"github.com/sanskarpan/Ghostlight/internal/communications"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
	"github.com/sanskarpan/Ghostlight/internal/support"
)

// This file is the G7.9 automated-gate attack: the structural half of the WCAG
// 2.2 AA gate over the authenticated review and abort path. It audits the
// real pages the renderer produces — the run page and the support page — and
// then breaks each structural property in a copy and requires the gate to
// notice. A gate that passes the honest page and sleeps through the broken
// ones is decoration.
//
// What this suite may claim: that the rendered pages carry a language, a
// title, one top-level heading, ordered headings, named controls, labelled
// inputs, headed tables, a working skip link, unique IDs, resolvable ARIA
// references and no mouse-only handlers.
//
// What it may not claim: color contrast, focus visibility, keyboard
// operability on a real device, resize behavior, or anything a screen reader
// announces. Those are the browser half of G7.9, and this file exercises
// bytes, not a browser.

// g7aHonestPage renders the run page with its support section attached.
func g7aHonestPage(t *testing.T) string {
	t.Helper()
	page := g7rPage()
	article := support.Article{
		ID: "help-1", Title: "Reviewing a preview", Body: "Open the run, read the findings, abort if unsure.",
		Surface: "console", Version: "1", PublishedAt: g7sReceived.Add(-time.Hour),
	}
	opts := g7sOptions()
	opts.Surfaces = []string{"console"}
	opts.Components = []string{"api"}
	opts.Checks = []communications.StatusCheck{{
		Component: "api", OK: true, At: g7sAt.Add(-time.Minute),
	}}
	view := g7sBuild(t,
		support.Registry{
			Requests: []support.Request{g7sRequest("req-1", "acme", "Preview stays pending")},
			Articles: []support.Article{article},
		},
		communications.Registry{Notices: []communications.Notice{g7sNotice("notice-1", "acme", "Capacity work")}},
		opts)
	page.Support = &view
	out, err := consolerender.RenderPage(page)
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	return out
}

func g7aAudit(t *testing.T, page string) a11ygate.Report {
	t.Helper()
	report, err := a11ygate.AuditDocument(page)
	if err != nil {
		t.Fatalf("AuditDocument: %v", err)
	}
	return report
}

func TestG7A11yHonestPagesPassTheStructuralGate(t *testing.T) {
	for name, page := range map[string]string{
		"run page": func() string {
			out, err := consolerender.RenderPage(g7rPage())
			if err != nil {
				t.Fatalf("RenderPage: %v", err)
			}
			return out
		}(),
		"run page with support": g7aHonestPage(t),
	} {
		report := g7aAudit(t, page)
		if !report.Pass() {
			t.Errorf("%s: honest page failed: %+v", name, report.Violations)
		}
	}
}

func TestG7A11yGateNoticesEachBreakage(t *testing.T) {
	honest := g7aHonestPage(t)
	breakages := map[string]struct {
		breakIt string
		rule    string
	}{
		"language removed": {
			breakIt: "REPLACE:<html lang=\"en\">:<html>",
			rule:    a11ygate.RuleDocLang,
		},
		"title emptied": {
			breakIt: "REPLACE:<title>Run 42</title>:<title>  </title>",
			rule:    a11ygate.RuleDocTitle,
		},
		"second h1 added": {
			breakIt: "REPLACE:<h1>Run 42</h1>:<h1>Run 42</h1><h1>Again</h1>",
			rule:    a11ygate.RuleSingleH1,
		},
		"heading level skipped": {
			breakIt: "REPLACE:<h3 id=\"controls-heading\">Controls</h3>:<h5 id=\"controls-heading\">Controls</h5>",
			rule:    a11ygate.RuleHeadingOrder,
		},
		"skip link removed": {
			breakIt: "REPLACE:Skip to main content:Back to top",
			rule:    a11ygate.RuleSkipLink,
		},
		"skip target removed": {
			breakIt: "REPLACE:<main id=\"main\">:<main>",
			rule:    a11ygate.RuleFragmentTarget,
		},
		"button unnamed": {
			breakIt: "REPLACE:>Abort the run</button>:></button>",
			rule:    a11ygate.RuleButtonName,
		},
		"input unlabelled": {
			breakIt: "REPLACE:<label for=\"repository-search\">Search repositories</label>:",
			rule:    a11ygate.RuleInputLabel,
		},
		"caption dropped": {
			breakIt: "REPLACE:<caption>Component status</caption>:",
			rule:    a11ygate.RuleTableHeaders,
		},
		"tabindex hijack": {
			breakIt: "REPLACE:<button type=\"button\":<button type=\"button\" tabindex=\"1\"",
			rule:    a11ygate.RuleNoPositiveTabindex,
		},
		"id duplicated": {
			breakIt: "REPLACE:id=\"support-heading\":id=\"timeline-heading\"",
			rule:    a11ygate.RuleDuplicateID,
		},
		"describedby dangling": {
			breakIt: "REPLACE:aria-describedby=\"support-status-note\":aria-describedby=\"ghost-note\"",
			rule:    a11ygate.RuleAriaRefTarget,
		},
		"mouse-only handler": {
			breakIt: "REPLACE:<button type=\"button\":<button type=\"button\" onclick=\"go()\"",
			rule:    a11ygate.RuleNoMouseOnly,
		},
	}
	for name, b := range breakages {
		if !strings.HasPrefix(b.breakIt, "REPLACE:") {
			t.Fatalf("%s: bad breakage encoding", name)
		}
		rest := strings.TrimPrefix(b.breakIt, "REPLACE:")
		parts := strings.SplitN(rest, ":", 2)
		old, new := parts[0], parts[1]
		if !strings.Contains(honest, old) {
			t.Fatalf("%s: honest page does not contain %q; the attack is stale", name, old)
		}
		broken := strings.Replace(honest, old, new, 1)
		report := g7aAudit(t, broken)
		if report.Pass() {
			t.Errorf("%s: broken page passed the gate", name)
			continue
		}
		found := false
		for _, v := range report.Violations {
			if v.Rule == b.rule {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: gate failed but not on %s: %+v", name, b.rule, report.Violations)
		}
	}
}
