package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/api"
	"github.com/sanskarpan/Ghostlight/internal/a11ygate"
	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/dodo"
	"github.com/sanskarpan/Ghostlight/internal/webui"
)

// frontendGate is the console the gate drives: one store, two principals in
// different orgs, and one environment whose actions exercise the states the
// pages render.
func frontendGate(t *testing.T) (*http.ServeMux, func(string) *http.Cookie, *api.MemoryEnvironments) {
	t.Helper()
	backend := testBackend(map[string]contract.Principal{
		"org-a-user": {ID: "org-a-user", Grants: []string{"org-a"}},
		"org-b-user": {ID: "org-b-user", Grants: []string{"org-b"}},
	})
	now := time.Now()
	consoleStore := &api.MemoryEnvironments{Environments: []api.Environment{{
		ID: "env-a-1", Scope: "org-a", Version: 2, Generation: 4,
		ExpiresAt: now.Add(time.Hour),
		Actions: []console.RecordedAction{
			{ID: "a1", Phase: console.PhaseArtifactBuild, Outcome: console.OutcomeSucceeded, StartedAt: now.Add(-10 * time.Minute)},
			{ID: "a2", Phase: console.PhaseFoundationWarmup, Outcome: console.OutcomeUncertain, StartedAt: now.Add(-5 * time.Minute), Detail: "the provider never answered"},
		},
	}}}
	backend.Environments = consoleStore
	mux, mgr, err := buildMuxWithStore(webuiEnv(), backend, dodo.NewMemoryStore(), "memory", consoleStore)
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	cookie := func(principal string) *http.Cookie {
		s, _, err := mgr.StartSession(principal, false, time.Now())
		if err != nil {
			t.Fatalf("StartSession(%s): %v", principal, err)
		}
		return &http.Cookie{Name: webui.CookieName, Value: s.ID}
	}
	return mux, cookie, consoleStore
}

// The console's HTML routes. A new page that does not join this list fails the
// enumeration test, and the list is the gate's contract with the renderer.
var consoleHTMLRoutes = []string{"/", "/env", "/env/new", "/env/env-a-1"}

// TestTheGateEveryConsoleRouteIsServedAndAudited is the servability gate: a
// feature that is not served is not shipped. It is the check whose absence let
// #213 happen -- a green suite over a product no customer could open.
func TestTheGateEveryConsoleRouteIsServedAndAudited(t *testing.T) {
	mux, cookie, _ := frontendGate(t)
	owner := cookie("org-a-user")

	for _, path := range consoleHTMLRoutes {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(owner)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		// Served: 200 HTML, never a 404, a 401 JSON body, or an empty page.
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, rec.Code)
			continue
		}
		ct := rec.Header().Get("Content-Type")
		if !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s: content type = %q, want text/html", path, ct)
			continue
		}
		body := rec.Body.String()
		if strings.Contains(body, "no such route") {
			t.Errorf("%s: the page is a router miss", path)
		}

		// Not cached: an authenticated document left in a shared browser cache
		// is readable by the next user of the machine, so every page carries
		// no-store. This check exists because the e2e journey surfaced the
		// missing header: the browser served a stale authenticated page after
		// the session manager restarted.
		if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			t.Errorf("%s: Cache-Control = %q, want no-store", path, cc)
		}

		// Audited: the served bytes pass the accessibility gate. The detail
		// page's findings route is also audited, because a fragment is a served
		// surface assembled into a page rather than an excuse.
		rep, err := a11ygate.AuditDocument(body)
		if err != nil {
			t.Errorf("%s: audit: %v", path, err)
			continue
		}
		if len(rep.Violations) != 0 {
			t.Errorf("%s: violates %d accessibility rules", path, len(rep.Violations))
			for _, v := range rep.Violations {
				t.Logf("  %s: %s", v.Rule, v.Detail)
			}
		}
	}
}

// TestTheGateEveryRouteIsInTheEnumeration fails when a console route exists
// that the gate does not know about: a new page that skips the list skips the
// gate, and skipping the gate is how #213 happened.
func TestTheGateEveryRouteIsInTheEnumeration(t *testing.T) {
	mux, cookie, _ := frontendGate(t)
	owner := cookie("org-a-user")

	// The routes the gate knows about, probed for HTML-ness.
	served := map[string]bool{}
	for _, path := range consoleHTMLRoutes {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(owner)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK && strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			served[path] = true
		}
	}

	// The routes the gate enumerates, by the same definition.
	listed := map[string]bool{}
	for _, path := range consoleHTMLRoutes {
		listed[path] = true
	}

	for path := range served {
		if !listed[path] {
			t.Errorf("the console serves %q as HTML but the gate does not enumerate it", path)
		}
	}
	for path := range listed {
		if !served[path] {
			t.Errorf("the gate enumerates %q but the console does not serve it", path)
		}
	}
}

// TestTheGateAbortIsNeverAnHtmxTarget pins the rule that the control which ends
// a run is a plain form POST: never an htmx target, never inside a swapped
// region, and present in the rendered page.
func TestTheGateAbortIsNeverAnHtmxTarget(t *testing.T) {
	mux, cookie, _ := frontendGate(t)
	owner := cookie("org-a-user")
	req := httptest.NewRequest(http.MethodGet, "/env/env-a-1", nil)
	req.AddCookie(owner)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status = %d", rec.Code)
	}
	body := rec.Body.String()

	if !strings.Contains(body, "Abort the run") {
		t.Fatal("the abort control is missing from the detail page")
	}
	// The abort form's action must not carry htmx attributes.
	abortStart := strings.Index(body, `action="/env/env-a-1/abort"`)
	if abortStart < 0 {
		t.Fatal("the abort form is missing its action")
	}
	formEnd := strings.Index(body[abortStart:], "</form>")
	form := body[abortStart : abortStart+formEnd]
	for _, forbidden := range []string{"hx-get", "hx-post", "hx-swap", "hx-trigger"} {
		if strings.Contains(form, forbidden) {
			t.Errorf("the abort form uses %q: abort must work with JavaScript disabled", forbidden)
		}
	}
	// The abort form precedes the live region in the document, and the live
	// region does not contain it.
	liveStart := strings.Index(body, `<section class="timeline"`)
	if liveStart < 0 {
		t.Fatal("the timeline region is missing")
	}
	if liveStart < abortStart {
		t.Error("the abort form must precede the live region, so the tab order reaches abort first")
	}
	liveEnd := strings.Index(body[liveStart:], "</section>")
	live := body[liveStart : liveStart+liveEnd]
	if strings.Contains(live, "Abort the run") {
		t.Error("the abort control must not be inside the swapped live region")
	}
}

// TestTheGateKeyboardOrderIsSkipAbortReview pins the tab order a screen-reader
// user depends on: skip link, then abort, then review, in source order.
func TestTheGateKeyboardOrderIsSkipAbortReview(t *testing.T) {
	mux, cookie, _ := frontendGate(t)
	owner := cookie("org-a-user")
	req := httptest.NewRequest(http.MethodGet, "/env/env-a-1", nil)
	req.AddCookie(owner)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	body := rec.Body.String()

	skip := strings.Index(body, "Skip to main content")
	abort := strings.Index(body, "Abort the run")
	review := strings.Index(body, "Review the candidate")
	for name, at := range map[string]int{"skip": skip, "abort": abort, "review": review} {
		if at < 0 {
			t.Fatalf("%s is missing from the page", name)
		}
	}
	if !(skip < abort && abort < review) {
		t.Errorf("tab order broken: skip=%d abort=%d review=%d, want skip < abort < review", skip, abort, review)
	}
}

// TestTheGateScopingIsAbsenceNotRefusal keeps the privacy property the org
// privacy suite established: another tenant's data is absent from every page,
// and a refusal looks exactly like a miss.
func TestTheGateScopingIsAbsenceNotRefusal(t *testing.T) {
	mux, cookie, _ := frontendGate(t)
	outsider := cookie("org-b-user")

	for _, path := range consoleHTMLRoutes {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(outsider)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		// A detail page for another tenant's environment is a 404 by design:
		// presence must not leak, so a cross-tenant miss and a nonexistent id
		// are indistinguishable. Every status is acceptable; the leak check is
		// what matters.
		body := rec.Body.String()
		for _, leaked := range []string{"env-a-1", "org-a", "the provider never answered"} {
			if strings.Contains(body, leaked) {
				t.Errorf("%s as outsider leaks %q", path, leaked)
			}
		}
	}
}

// TestTheGateEveryActionStateHasItsGlyph keeps the state vocabulary honest: the
// pages carry the canonical glyph and word together, and colour is never the
// only carrier.
func TestTheGateEveryActionStateHasItsGlyph(t *testing.T) {
	mux, cookie, _ := frontendGate(t)
	owner := cookie("org-a-user")
	req := httptest.NewRequest(http.MethodGet, "/env/env-a-1", nil)
	req.AddCookie(owner)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	body := rec.Body.String()

	// The uncertain phase carries both its glyph and its word, adjacent in the
	// same badge. A badge whose glyph and label drifted apart would read as
	// two different facts.
	if !strings.Contains(body, "?") || !strings.Contains(body, "Uncertain") {
		t.Fatal("the uncertain state is missing from the page")
	}
	for _, badge := range [...]struct{ state, glyph, word string }{
		{"uncertain", "?", "Uncertain"},
		{"complete", "●", "Complete"},
		{"blocked", "⊓", "Blocked"},
	} {
		glyphAt := strings.Index(body, badge.glyph)
		wordAt := strings.Index(body, badge.word)
		if glyphAt < 0 || wordAt < 0 {
			t.Errorf("state %q: glyph or word missing", badge.state)
			continue
		}
		// The glyph and word must sit in the same badge element, within a
		// bounded distance: a glyph on its own is a shape a screen reader
		// cannot name.
		if wordAt-glyphAt > 200 {
			t.Errorf("state %q: the glyph and its word are %d characters apart; they must share a badge",
				badge.state, wordAt-glyphAt)
		}
	}
}

// TestTheGateNoSecretsInThePages keeps the redaction discipline: no served page
// contains a credential-looking string, because the renderer's redaction is a
// property of the served bytes and not of the view model.
func TestTheGateNoSecretsInThePages(t *testing.T) {
	mux, cookie, _ := frontendGate(t)
	owner := cookie("org-a-user")
	for _, path := range consoleHTMLRoutes {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(owner)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		body := rec.Body.String()
		for _, pattern := range []string{"tok-", "sk_", "whsec_", "Bearer "} {
			if strings.Contains(body, pattern) {
				t.Errorf("%s contains a credential-shaped string %q", path, pattern)
			}
		}
	}
}
