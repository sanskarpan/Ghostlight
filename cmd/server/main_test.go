package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/api"
	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/passport"
	"github.com/sanskarpan/Ghostlight/internal/reviewer"
)

func testBackend(tokens map[string]contract.Principal) *api.Server {
	ops := contract.Registry{}
	return &api.Server{
		Auth:         api.StaticAuthenticator{Tokens: tokens},
		Operations:   ops,
		Authorizer:   &contract.Authorizer{Registry: ops},
		Environments: api.MemoryEnvironments{},
		Room:         &reviewer.Room{},
		Passports:    &passport.Registry{},
	}
}

func TestParseTokensAcceptsAValidSet(t *testing.T) {
	tokens, err := parseTokens("ada:tok-ada-1|repo:acme,repo:other|environment:read,environment:write;kim:tok-kim-9|repo:acme|")
	if err != nil {
		t.Fatalf("parseTokens: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("got %d principals, want 2", len(tokens))
	}
	ada := tokens["tok-ada-1"]
	if ada.ID != "ada" {
		t.Errorf("principal id = %q, want ada", ada.ID)
	}
	if len(ada.Grants) != 2 || len(ada.Permissions) != 2 {
		t.Errorf("ada grants/permissions = %v/%v, want 2 and 2", ada.Grants, ada.Permissions)
	}
	kim := tokens["tok-kim-9"]
	if len(kim.Permissions) != 0 {
		t.Errorf("kim permissions = %v, want none (denial, not wildcard)", kim.Permissions)
	}
}

func TestParseTokensRefusesEverythingDoubtful(t *testing.T) {
	cases := map[string]string{
		"empty spec":         "",
		"blank spec":         "   ",
		"empty entry":        "ada:t1|g|p;;kim:t2|g|p",
		"one field":          "ada",
		"no pipe":            "ada:t1:g:p",
		"one pipe":           "ada:t1|g",
		"three pipes":        "ada:t1|g|p|x",
		"no colon in head":   "ada|g|p",
		"empty id":           ":t1|g|p",
		"empty token":        "ada:|g|p",
		"duplicate id":       "ada:t1|g|p;ada:t2|g|p",
		"duplicate token":    "ada:t1|g|p;kim:t1|g|p",
		"token with space":   "ada:tok en|g|p",
		"token with comma":   "ada:t1,x|g|p",
		"token with semicol": "ada:t1;|g|p",
		"token with pipe":    "ada:t1|x|g|p",
		"id with colon":      "a:da:t1|g|p",
	}
	for name, spec := range cases {
		if _, err := parseTokens(spec); err == nil {
			t.Errorf("%s: expected a refusal", name)
		}
	}
}

func get(t *testing.T, mux *http.ServeMux, path, token string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET %s: response is not JSON: %v", path, err)
	}
	return rec.Code, body
}

func TestHealthEndpointsAreOpenAndHonest(t *testing.T) {
	mux := newMux("test-sha", testBackend(map[string]contract.Principal{
		"t1": {ID: "ada"},
	}))
	if code, body := get(t, mux, "/health/live", ""); code != http.StatusOK || body["status"] != "live" {
		t.Errorf("live: code=%d body=%v", code, body)
	}
	if code, body := get(t, mux, "/health/ready", ""); code != http.StatusOK || body["status"] != "ready" {
		t.Errorf("ready: code=%d body=%v", code, body)
	}
	if code, body := get(t, mux, "/health/startup", ""); code != http.StatusOK || body["status"] != "started" {
		t.Errorf("startup: code=%d body=%v", code, body)
	}
	if code, body := get(t, mux, "/version", ""); code != http.StatusOK || body["build"] != "test-sha" {
		t.Errorf("version: code=%d body=%v", code, body)
	}
	// Non-GET methods are refused, not silently reinterpreted.
	req := httptest.NewRequest(http.MethodPost, "/health/live", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /health/live: code=%d, want 405", rec.Code)
	}
}

func TestAPIRoutesStayAuthenticated(t *testing.T) {
	mux := newMux("test-sha", testBackend(map[string]contract.Principal{
		"t1": {ID: "ada", Grants: []string{"repo:acme"}, Permissions: []string{"environment:read"}},
	}))
	// No token: 401, full stop.
	if code, _ := get(t, mux, "/v1/environments/env-1", ""); code != http.StatusUnauthorized {
		t.Errorf("no token: code=%d, want 401", code)
	}
	// Valid token, unknown route: 404, which proves authentication passed
	// and routing works — a 401 here would mean the token was not honored.
	if code, _ := get(t, mux, "/no/such/route", "t1"); code != http.StatusNotFound {
		t.Errorf("valid token, bad route: code=%d, want 404", code)
	}
	// Wrong token: 401 again.
	if code, _ := get(t, mux, "/v1/environments/env-1", "wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong token: code=%d, want 401", code)
	}
}

func TestRunRefusesWithoutCredentials(t *testing.T) {
	if code := run(func(string) string { return "" }); code == 0 {
		t.Error("run with no configuration: expected a refusal, got success")
	}
}

func TestRunRefusesABadTokenSet(t *testing.T) {
	getenv := func(key string) string {
		switch key {
		case "PORT":
			return "18081"
		case "GHOSTLIGHT_API_TOKENS":
			return "ada:t1"
		}
		return ""
	}
	if code := run(getenv); code == 0 {
		t.Error("run with a malformed token set: expected a refusal, got success")
	}
}

func TestBuildSHAOrder(t *testing.T) {
	render := func(v string) func(string) string {
		return func(key string) string {
			if key == "RENDER_GIT_COMMIT" {
				return v
			}
			return ""
		}
	}
	if got := buildSHA(render("abc123")); got != "abc123" {
		t.Errorf("render commit: got %q", got)
	}
	if got := buildSHA(func(string) string { return "" }); got != "unknown" {
		t.Errorf("no sha anywhere: got %q, want an honest unknown", got)
	}
	if got := buildSHA(func(key string) string {
		if key == "GHOSTLIGHT_BUILD_SHA" {
			return "manual-sha"
		}
		return ""
	}); got != "manual-sha" {
		t.Errorf("fallback sha: got %q", got)
	}
}

func TestReadyReportsNoSecrets(t *testing.T) {
	mux := newMux("s", testBackend(nil))
	_, body := get(t, mux, "/health/ready", "")
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "tok") || strings.Contains(string(raw), "ada") {
		t.Errorf("ready response leaks credential material: %v", body)
	}
}
