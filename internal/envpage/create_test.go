package envpage_test

import (
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/internal/a11ygate"
	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
	"github.com/sanskarpan/Ghostlight/internal/envpage"
)

func renderList(t *testing.T, page consolerender.ListPage) string {
	t.Helper()
	doc, err := consolerender.RenderListPage(page)
	if err != nil {
		t.Fatalf("RenderListPage: %v", err)
	}
	return doc
}

// The create form carries everything a POST needs, and the forecast precedes
// the confirm control in the markup order — admission is where a customer
// commits money, and a forecast after the button is one nobody reads.
func TestCreateFormCarriesThePostAndStatesTheForecastFirst(t *testing.T) {
	page, err := envpage.BuildCreate(envpage.CreateForm{
		Repositories: []string{"repo:org-a/api"},
		CSRFToken:    "token-1",
		RequestID:    "req-1",
		Forecast:     "$0.42 for the first 24 hours",
		ExpiresAt:    "in 30 minutes",
	})
	if err != nil {
		t.Fatalf("BuildCreate: %v", err)
	}
	doc := renderList(t, page)

	for _, want := range []string{
		`method="post"`,
		`action="/env"`,
		`name="csrf_token" value="token-1"`,
		`name="request_id" value="req-1"`,
		`<option value="repo:org-a/api">`,
		`Estimated cost: $0.42 for the first 24 hours`,
		`Admission lapses: in 30 minutes`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the create form is missing %q", want)
		}
	}
	forecast := strings.Index(doc, "Estimated cost")
	confirm := strings.Index(doc, `type="submit"`)
	if forecast < 0 || confirm < 0 {
		t.Fatalf("forecast=%d confirm=%d", forecast, confirm)
	}
	if forecast > confirm {
		t.Error("the forecast must precede the confirm control in the document order")
	}
}

// The form works without JavaScript: it is a native form POST. No script tag,
// no hx- attributes, no onsubmit.
func TestCreateFormIsNativeAndNeedsNoJavaScript(t *testing.T) {
	page, err := envpage.BuildCreate(envpage.CreateForm{
		Repositories: []string{"repo:org-a/api"},
		CSRFToken:    "t", RequestID: "r",
	})
	if err != nil {
		t.Fatalf("BuildCreate: %v", err)
	}
	doc := renderList(t, page)
	if strings.Contains(doc, "<script") {
		t.Error("the create form must not load a script")
	}
	if strings.Contains(doc, "hx-") {
		t.Error("the create form must not use htmx")
	}
	if strings.Contains(doc, "onsubmit") {
		t.Error("the create form must not submit through script")
	}
}

// An operator with no repositories cannot create anything, and the page says
// so rather than rendering a select with nothing in it.
func TestCreateFormWithoutRepositoriesSaysSo(t *testing.T) {
	page, err := envpage.BuildCreate(envpage.CreateForm{CSRFToken: "t", RequestID: "r"})
	if err != nil {
		t.Fatalf("BuildCreate: %v", err)
	}
	doc := renderList(t, page)
	if !strings.Contains(doc, "No repositories are bound to your grants") {
		t.Error("the page must explain that there is nothing to create for")
	}
	if strings.Contains(doc, "<select") {
		t.Error("an empty select must not be rendered")
	}
}

// Every interpolated value is escaped. A repository name is caller-supplied
// data and a repository name with a quote in it must not break out of the
// attribute it is rendered into.
func TestCreateFormEscapesEveryInterpolatedValue(t *testing.T) {
	page, err := envpage.BuildCreate(envpage.CreateForm{
		Repositories: []string{`repo:org-a/api"><script>alert(1)</script>`},
		CSRFToken:    `tok"><script>alert(2)</script>`,
		RequestID:    `req"><script>alert(3)</script>`,
		Forecast:     `$1"><script>alert(4)</script>`,
	})
	if err != nil {
		t.Fatalf("BuildCreate: %v", err)
	}
	doc := renderList(t, page)
	for _, marker := range []string{"<script>alert(1)", "<script>alert(2)", "<script>alert(3)", "<script>alert(4)"} {
		if strings.Contains(doc, marker) {
			t.Errorf("the page contains an unescaped injection: %q", marker)
		}
	}
}

// A refused admission says why in its own words: a quota refusal is the ≡ quota
// glyph with the quota recovery line, not a generic error.
func TestCreateRefusalRendersItsOwnState(t *testing.T) {
	page, err := envpage.BuildCreateRefused(console.StateQuota, "this profile would exceed the concurrency entitlement")
	if err != nil {
		t.Fatalf("BuildCreateRefused: %v", err)
	}
	doc := renderList(t, page)
	for _, want := range []string{
		`data-state="quota"`,
		"Environment not created",
		"exceed the concurrency entitlement",
		"Next step:",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the quota refusal is missing %q", want)
		}
	}
	// The quota glyph is ≡ in the canonical registry; a generic ✗ would collapse
	// a quota refusal into a failure, which are different facts.
	if !strings.Contains(doc, "≡") {
		t.Error("a quota refusal must carry the quota glyph, not the failure one")
	}
	if strings.Contains(doc, "✗") {
		t.Error("a quota refusal must not be rendered as a failure")
	}
}

// A denial is a different refusal with a different glyph and a different next
// step, and the page must not collapse the two.
func TestCreateRefusalSeparatesDenialFromQuota(t *testing.T) {
	page, err := envpage.BuildCreateRefused(console.StateDenied, "policy denies this repository")
	if err != nil {
		t.Fatalf("BuildCreateRefused: %v", err)
	}
	doc := renderList(t, page)
	if !strings.Contains(doc, `data-state="denied"`) {
		t.Error("a denial must carry the denied state")
	}
	if strings.Contains(doc, `data-state="quota"`) {
		t.Error("a denial must not be rendered as a quota refusal")
	}
}

// A state that is not a create refusal is refused by the builder, because a
// page that rendered "pending" as a refusal would be lying about what happened.
func TestCreateRefusalRefusesNonRefusalStates(t *testing.T) {
	for _, state := range []console.ActionState{console.StateSucceeded, console.StateLoading, console.StateUncertain} {
		if _, err := envpage.BuildCreateRefused(state, "reason"); err == nil {
			t.Errorf("state %q is not a refusal and must be refused by the builder", state)
		}
	}
}

// The refusal page is audited like every other page.
func TestCreatePagesPassTheGate(t *testing.T) {
	form, err := envpage.BuildCreate(envpage.CreateForm{
		Repositories: []string{"repo:org-a/api"},
		CSRFToken:    "t", RequestID: "r",
		Forecast: "$0.42",
	})
	if err != nil {
		t.Fatalf("BuildCreate: %v", err)
	}
	refused, err := envpage.BuildCreateRefused(console.StateQuota, "over the entitlement")
	if err != nil {
		t.Fatalf("BuildCreateRefused: %v", err)
	}
	for name, page := range map[string]consolerender.ListPage{"form": form, "refusal": refused} {
		doc := renderList(t, page)
		rep, err := a11ygate.AuditDocument(doc)
		if err != nil {
			t.Fatalf("%s audit: %v", name, err)
		}
		if len(rep.Violations) != 0 {
			t.Errorf("%s violates %d accessibility rules", name, len(rep.Violations))
			for _, v := range rep.Violations {
				t.Logf("  %s: %s", v.Rule, v.Detail)
			}
		}
	}
}
