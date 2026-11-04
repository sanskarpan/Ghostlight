package envpage_test

import (
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/internal/a11ygate"
	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
	"github.com/sanskarpan/Ghostlight/internal/envpage"
)

// The abort form is a native POST carrying the session's token, and it is not
// an htmx target: abort must work with JavaScript disabled, and a swap must
// never replace the control under the operator's finger.
func TestAbortFormIsAPlainPost(t *testing.T) {
	form := envpage.AbortForm("env-1", "tok-1")
	for _, want := range []string{
		`method="post"`,
		`action="/env/env-1/abort"`,
		`name="csrf_token" value="tok-1"`,
		`Abort the run`,
	} {
		if !strings.Contains(form, want) {
			t.Errorf("the abort form is missing %q", want)
		}
	}
	for _, forbidden := range []string{"hx-", "<script", "onsubmit"} {
		if strings.Contains(form, forbidden) {
			t.Errorf("the abort form must not use %q: abort works without JavaScript", forbidden)
		}
	}
}

// The destroy flow starts as a GET to a confirm page, not a direct POST:
// destructive actions deserve the friction of a page a person has to read.
func TestDestroyFormStartsWithAConfirmPage(t *testing.T) {
	form := envpage.DestroyForm("env-1", "tok-1")
	if !strings.Contains(form, `method="get"`) {
		t.Error("the destroy form must navigate to the confirm page with GET")
	}
	if !strings.Contains(form, `action="/env/env-1/destroy/confirm"`) {
		t.Errorf("the destroy form must target the confirm page")
	}
	if strings.Contains(form, `method="post"`) {
		t.Error("the destroy form must not POST directly")
	}
}

// The confirm page states what will happen, carries the POST with its token,
// and offers a way out.
func TestDestroyConfirmStatesTheConsequences(t *testing.T) {
	page, err := envpage.BuildDestroyConfirm("env-1", "tok-1", []string{"vol-9", "net-7"})
	if err != nil {
		t.Fatalf("BuildDestroyConfirm: %v", err)
	}
	doc := renderList(t, page)
	for _, want := range []string{
		"Destroy env-1?",
		"cannot be undone from here",
		`action="/env/env-1/destroy"`,
		`name="csrf_token" value="tok-1"`,
		"Destroy</button>",
		`href="/env/env-1">Cancel</a>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the destroy confirmation is missing %q", want)
		}
	}
}

// Unresolved resources are listed before the button, because a teardown that
// will leave things behind is a fact the operator needs before they click.
func TestDestroyConfirmListsUnresolvedResources(t *testing.T) {
	page, err := envpage.BuildDestroyConfirm("env-1", "tok-1", []string{"vol-9"})
	if err != nil {
		t.Fatalf("BuildDestroyConfirm: %v", err)
	}
	doc := renderList(t, page)
	if !strings.Contains(doc, "still unresolved") {
		t.Error("the confirm page must name unresolved resources")
	}
	if !strings.Contains(doc, "vol-9") {
		t.Error("the unresolved resource must be named")
	}
	button := strings.Index(doc, `>Destroy</button>`)
	listed := strings.Index(doc, "vol-9")
	if listed < 0 || button < 0 || listed > button {
		t.Error("the unresolved resources must be listed before the destroy button")
	}
}

// A confirm page with no unresolved resources says nothing about them.
func TestDestroyConfirmWithoutUnresolvedResources(t *testing.T) {
	page, err := envpage.BuildDestroyConfirm("env-1", "tok-1", nil)
	if err != nil {
		t.Fatalf("BuildDestroyConfirm: %v", err)
	}
	doc := renderList(t, page)
	if strings.Contains(doc, "still unresolved") {
		t.Error("a confirm page with nothing unresolved must not claim there are")
	}
}

// A lifecycle result without a reason is refused: a result page that says
// "aborted" and nothing else leaves the operator guessing whether it worked.
func TestLifecycleResultRequiresAReason(t *testing.T) {
	if _, err := envpage.BuildLifecycleResult("env-1", console.StateFailed, "   "); err == nil {
		t.Error("a lifecycle result without a reason must be refused")
	}
}

// An abort result keeps its reason: an aborted run is a fact with a cause, not
// a disappearance.
func TestLifecycleResultKeepsItsReason(t *testing.T) {
	reason := "aborted at the request of the operator"
	page, err := envpage.BuildLifecycleResult("env-1", console.StateFailed, reason)
	if err != nil {
		t.Fatalf("BuildLifecycleResult: %v", err)
	}
	doc := renderList(t, page)
	if !strings.Contains(doc, `data-state="failed"`) {
		t.Error("the result must carry the state it ended in")
	}
	if !strings.Contains(doc, reason) {
		t.Error("the result must carry its reason")
	}
	if !strings.Contains(doc, `href="/env/env-1"`) {
		t.Error("the result must link back to the environment")
	}
}

// Every value is escaped: an environment id arrives from a URL and a reason
// from a ledger, and neither is trusted.
func TestLifecycleMarkupEscapesItsValues(t *testing.T) {
	page, err := envpage.BuildDestroyConfirm(`env"><script>alert(1)</script>`, "tok", []string{`vol"><script>alert(2)</script>`})
	if err != nil {
		t.Fatalf("BuildDestroyConfirm: %v", err)
	}
	doc := renderList(t, page)
	for _, marker := range []string{"<script>alert(1)", "<script>alert(2)"} {
		if strings.Contains(doc, marker) {
			t.Errorf("the confirm page contains an unescaped injection: %q", marker)
		}
	}
	result, err := envpage.BuildLifecycleResult(`env"><script>alert(3)</script>`, console.StateFailed, "reason<script>alert(4)</script>")
	if err != nil {
		t.Fatalf("BuildLifecycleResult: %v", err)
	}
	doc = renderList(t, result)
	for _, marker := range []string{"<script>alert(3)", "<script>alert(4)"} {
		if strings.Contains(doc, marker) {
			t.Errorf("the result page contains an unescaped injection: %q", marker)
		}
	}
}

// The confirm and result pages pass the accessibility gate over their bytes.
func TestLifecyclePagesPassTheGate(t *testing.T) {
	confirm, err := envpage.BuildDestroyConfirm("env-1", "tok", []string{"vol-9"})
	if err != nil {
		t.Fatalf("BuildDestroyConfirm: %v", err)
	}
	result, err := envpage.BuildLifecycleResult("env-1", console.StateFailed, "aborted")
	if err != nil {
		t.Fatalf("BuildLifecycleResult: %v", err)
	}
	for name, page := range map[string]consolerender.ListPage{"confirm": confirm, "result": result} {
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
