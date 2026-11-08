package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/api"
	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/dodo"
)

// servedRoutes are the JSON API routes the server answers today, as
// "METHOD path" pairs. This list is
// the executable form of the reconciliation table at the top of docs/API.md §0:
// the two must agree, and the test below fails when either side drifts.
// Entries are "METHOD path", because a route is a method and a path: probing a
// POST-only route with GET answers "no such route", which would read as drift
// when the real defect is the probe.
var servedRoutes = []string{
	"POST /v1/environments",
	"GET /v1/environments/{id}",
	"POST /v1/environments/{id}/destroy",
	"GET /v1/environments/{id}/resources",
	"POST /v1/environments/{id}/extend",
	"POST /v1/integrations/github/events",
	"POST /v1/environments/{id}/generations",
	"POST /v1/environments/{id}/gates",
	"GET /v1/gates/{run_id}",
	"GET /v1/environments/{id}/review-threads",
	"POST /v1/environments/{id}/review-threads",
	"POST /v1/review-threads/{id}/findings",
	"POST /v1/review-threads/{id}/findings/{fid}/carry-forward",
	"GET /v1/passports/{id}",
}

// servedPatterns pairs each served route with the concrete path shapes the test
// drives. A route marked served with no pattern here fails the test, so a route
// cannot be claimed served and silently untested.
var servedPatterns = map[string][]string{
	"POST /v1/environments":                                     {"/v1/environments"},
	"GET /v1/environments/{id}":                                 {"/v1/environments/env-1"},
	"POST /v1/environments/{id}/destroy":                        {"/v1/environments/env-1/destroy"},
	"GET /v1/environments/{id}/resources":                       {"/v1/environments/env-1/resources"},
	"POST /v1/environments/{id}/extend":                         {"/v1/environments/env-1/extend"},
	"POST /v1/integrations/github/events":                       {"/v1/integrations/github/events"},
	"POST /v1/environments/{id}/generations":                    {"/v1/environments/env-1/generations"},
	"POST /v1/environments/{id}/gates":                          {"/v1/environments/env-1/gates"},
	"GET /v1/gates/{run_id}":                                    {"/v1/gates/gate-1"},
	"GET /v1/environments/{id}/review-threads":                  {"/v1/environments/env-1/review-threads"},
	"POST /v1/environments/{id}/review-threads":                 {"/v1/environments/env-1/review-threads"},
	"POST /v1/review-threads/{id}/findings":                     {"/v1/review-threads/th-1/findings"},
	"POST /v1/review-threads/{id}/findings/{fid}/carry-forward": {"/v1/review-threads/th-1/findings/f-1/carry-forward"},
	"GET /v1/passports/{id}":                                    {"/v1/passports/pp-1"},
}

// realityBackend builds the handler the reality test drives, with one
// environment seeded so the served GET routes answer with a resource rather
// than a 404 — the difference between "served" and "answers nothing". It also
// returns the bearer token that authenticates as the seeded principal.
func realityBackend(t *testing.T) (*http.ServeMux, string) {
	t.Helper()
	backend := testBackend(map[string]contract.Principal{
		"t1": {ID: "ada", Grants: []string{"org-a"}, Permissions: []string{"environment:read"}},
	})
	backend.Environments = api.MemoryEnvironments{Environments: []api.Environment{{
		ID: "env-1", Scope: "org-a", Version: 1, Generation: 1,
	}}}
	mux := newMux("reality", backend, "memory", nil)

	auth, ok := backend.Auth.(api.StaticAuthenticator)
	if !ok {
		t.Fatal("the reality test requires a StaticAuthenticator")
	}
	for token, p := range auth.Tokens {
		if p.ID == "ada" {
			return mux, token
		}
	}
	t.Fatal("no token authenticates as the reality-test principal")
	return nil, ""
}

// TestAPIRealityChecksTheDocumentAgainstTheServer is the drift gate for
// docs/API.md §0: every route marked served answers, and no route the server
// answers is unmarked. A document that promises a route the binary does not
// serve is a claim without an artifact — the same defect as a faked pass.
func TestAPIRealityChecksTheDocumentAgainstTheServer(t *testing.T) {
	mux, token := realityBackend(t)
	header := "Bearer " + token

	// 1. Every served route answers with an authenticated response that is not
	//    a router miss. A router-level 404 is drift; a 200 or a domain error is
	//    the route existing.
	for _, route := range servedRoutes {
		patterns, ok := servedPatterns[route]
		if !ok || len(patterns) == 0 {
			t.Errorf("route %q is marked served but has no test path: the table and the probe list have drifted", route)
			continue
		}
		method := strings.Fields(route)[0]
		for _, path := range patterns {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(method, path, nil)
			req.Header.Set("Authorization", header)
			mux.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound && strings.Contains(rec.Body.String(), "no such route") {
				t.Errorf("%s is marked served in docs/API.md but the router answers %q: the document promises a route the binary does not have",
					route, "no such route")
			}
		}
	}

	// 2. The document marks exactly these routes served. Parsing the table keeps
	//    the markdown honest: editing the table without the list, or the list
	//    without the table, fails here.
	raw, err := os.ReadFile("../../docs/API.md")
	if err != nil {
		t.Fatalf("docs/API.md: %v", err)
	}
	marked := docServedRoutes(string(raw))
	if len(marked) == 0 {
		t.Fatal("docs/API.md §0 marks no routes as served; the reconciliation table is missing or malformed")
	}
	for _, route := range servedRoutes {
		if !slices.Contains(marked, route) {
			t.Errorf("route %q is served by the server but not marked served in docs/API.md", route)
		}
	}
	for _, route := range marked {
		if !slices.Contains(servedRoutes, route) {
			t.Errorf("route %q is marked served in docs/API.md but the server does not answer it", route)
		}
	}
}

// docServedRoutes parses the §0 reconciliation table and returns the routes
// marked served.
func docServedRoutes(doc string) []string {
	var out []string
	tick := "`"
	re := regexp.MustCompile(`\| ` + tick + `([A-Z]+ /v1/[^` + tick + `]+)` + tick + ` \| \*\*served\*\*`)
	for _, m := range re.FindAllStringSubmatch(doc, -1) {
		out = append(out, m[1])
	}
	return out
}

// The console's HTML routes are part of the served reality too, and they are
// session-authenticated rather than bearer-authenticated. An unauthenticated
// browser request to any of them must redirect to sign-in, never serve HTML.
// This needs the console mux, because an API-only mux answers 401 with JSON.
func TestConsoleRoutesRequireASession(t *testing.T) {
	consoleStore := &api.MemoryEnvironments{Environments: []api.Environment{{
		ID: "env-1", Scope: "org-a", Version: 1, Generation: 1,
	}}}
	backend := testBackend(map[string]contract.Principal{
		"t1": {ID: "ada", Grants: []string{"org-a"}, Permissions: []string{"environment:read"}},
	})
	backend.Environments = consoleStore
	mux, _, err := buildMuxWithStore(func(string) string { return "" }, backend,
		dodo.NewMemoryStore(), "memory", consoleStore)
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	for _, path := range []string{"/", "/env", "/env/new", "/env/env-1"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
			t.Errorf("%s without a session: status=%d location=%q, want 302 /login",
				path, rec.Code, rec.Header().Get("Location"))
		}
		if strings.Contains(rec.Body.String(), "<h1>") {
			t.Errorf("%s served HTML to an unauthenticated caller", path)
		}
	}
}
