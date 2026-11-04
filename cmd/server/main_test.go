package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/api"
	"github.com/sanskarpan/Ghostlight/internal/a11ygate"
	"github.com/sanskarpan/Ghostlight/internal/billing"
	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/dodo"
	"github.com/sanskarpan/Ghostlight/internal/identity"
	"github.com/sanskarpan/Ghostlight/internal/passport"
	"github.com/sanskarpan/Ghostlight/internal/reviewer"
	"github.com/sanskarpan/Ghostlight/internal/webui"
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
	}), "memory", nil)
	if code, body := get(t, mux, "/health/live", ""); code != http.StatusOK || body["status"] != "live" {
		t.Errorf("live: code=%d body=%v", code, body)
	}
	if code, body := get(t, mux, "/health/ready", ""); code != http.StatusOK || body["status"] != "ready" {
		t.Errorf("ready: code=%d body=%v", code, body)
	}
	_, readyBody := get(t, mux, "/health/ready", "")
	if backing, _ := readyBody["backing"].(map[string]any); backing["billing_store"] != "memory" {
		t.Errorf("ready hides the billing backend: %v", readyBody)
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
	}), "memory", nil)
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
	mux := newMux("s", testBackend(nil), "memory", nil)
	_, body := get(t, mux, "/health/ready", "")
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "tok") || strings.Contains(string(raw), "ada") {
		t.Errorf("ready response leaks credential material: %v", body)
	}
}

// dodoTestSecret is a fixed test signing key (base64 of 32 bytes).
var dodoTestSecret = "whsec_" + base64.StdEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))

func dodoEnv() func(string) string {
	return func(key string) string {
		switch key {
		case "GHOSTLIGHT_API_TOKENS":
			return "op:tok-op-1|repo:acme|environment:read"
		case "DODO_WEBHOOK_SECRET":
			return dodoTestSecret
		case "DODO_BUSINESS_ID":
			return "bus_1"
		case "DODO_PRODUCT_PLANS":
			return "prod_team:team"
		}
		return ""
	}
}

func signDodo(t *testing.T, secret, id, ts, body string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		t.Fatalf("bad test secret: %v", err)
	}
	mac := hmac.New(sha256.New, raw)
	fmt.Fprintf(mac, "%s.%s.%s", id, ts, body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func postHook(t *testing.T, mux *http.ServeMux, secret, id, typ, business, data string) (int, map[string]any) {
	t.Helper()
	now := time.Now().UTC()
	payload := fmt.Sprintf(`{"business_id":%q,"type":%q,"timestamp":%q,"data":%s}`,
		business, typ, now.Add(-time.Minute).Format(time.RFC3339), data)
	ts := fmt.Sprint(now.Unix())
	req := httptest.NewRequest(http.MethodPost, "/hooks/dodo", strings.NewReader(payload))
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", ts)
	req.Header.Set("webhook-signature", signDodo(t, secret, id, ts, payload))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("POST /hooks/dodo: response is not JSON: %v", err)
	}
	return rec.Code, out
}

func TestDodoRouteIsMountedAndVerified(t *testing.T) {
	mux, err := buildMux(dodoEnv(), testBackend(nil), dodo.NewMemoryStore(), "memory")
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	// Unsigned: 401 proves the route exists and verifies (a missing route
	// would be 404 from the API layer, since the token below is absent too).
	req := httptest.NewRequest(http.MethodPost, "/hooks/dodo", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unsigned delivery: code=%d, want 401", rec.Code)
	}
	// Wrong method: 405, not silently reinterpreted.
	getReq := httptest.NewRequest(http.MethodGet, "/hooks/dodo", nil)
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /hooks/dodo: code=%d, want 405", getRec.Code)
	}
	// Honest loop through the mounted route: start applies once.
	code, out := postHook(t, mux, dodoTestSecret, "evt_live", "subscription.active", "bus_1",
		`{"subscription_id":"sub_live","customer_id":"cus_live","product_id":"prod_team"}`)
	if code != http.StatusOK || out["applied"] != true {
		t.Fatalf("live delivery: code=%d body=%v", code, out)
	}
	code, out = postHook(t, mux, dodoTestSecret, "evt_live", "subscription.active", "bus_1",
		`{"subscription_id":"sub_live","customer_id":"cus_live","product_id":"prod_team"}`)
	if code != http.StatusOK || out["duplicate"] != true || out["applied"] != false {
		t.Fatalf("redelivery: code=%d body=%v", code, out)
	}
	// Tampered body: 401.
	now := time.Now().UTC()
	payload := fmt.Sprintf(`{"business_id":"bus_1","type":"subscription.cancelled","timestamp":%q,"data":{"subscription_id":"sub_live","customer_id":"cus_live"}}`,
		now.Add(-time.Minute).Format(time.RFC3339))
	ts := fmt.Sprint(now.Unix())
	req = httptest.NewRequest(http.MethodPost, "/hooks/dodo", strings.NewReader(payload+" "))
	req.Header.Set("webhook-id", "evt_tamper")
	req.Header.Set("webhook-timestamp", ts)
	req.Header.Set("webhook-signature", signDodo(t, dodoTestSecret, "evt_tamper", ts, payload))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("tampered delivery: code=%d, want 401", rec.Code)
	}
}

func TestDodoRouteUnconfiguredRefusesEveryDelivery(t *testing.T) {
	mux, err := buildMux(func(string) string { return "" }, testBackend(nil), dodo.NewMemoryStore(), "memory")
	if err != nil {
		t.Fatalf("buildMux without secrets: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/hooks/dodo", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("unconfigured receiver: code=%d, want 500", rec.Code)
	}
}

func TestDodoRouteBadProductMapRefusesStartup(t *testing.T) {
	getenv := func(key string) string {
		if key == "DODO_PRODUCT_PLANS" {
			return "prod_x:platinum"
		}
		return ""
	}
	if _, err := buildMux(getenv, testBackend(nil), dodo.NewMemoryStore(), "memory"); err == nil {
		t.Error("malformed product map: expected a refusal, got success")
	}
	if code := run(func(key string) string {
		if key == "GHOSTLIGHT_API_TOKENS" {
			return "op:tok|g|p"
		}
		if key == "DODO_PRODUCT_PLANS" {
			return "prod_x:platinum"
		}
		return ""
	}); code == 0 {
		t.Error("run with a malformed product map: expected a refusal, got success")
	}
}

func TestMigrateRefusesWithoutADatabase(t *testing.T) {
	if code := run(func(key string) string {
		if key == "MIGRATE" {
			return "1"
		}
		return ""
	}); code == 0 {
		t.Error("migrate without DATABASE_URL: expected a refusal, got success")
	}
}

func TestMigrateRefusesAnUnreachableDatabase(t *testing.T) {
	getenv := func(key string) string {
		switch key {
		case "MIGRATE":
			return "1"
		case "DATABASE_URL":
			return "postgres://ghostlight:ghostlight@127.0.0.1:1/ghostlight?sslmode=disable"
		}
		return ""
	}
	if code := run(getenv); code == 0 {
		t.Error("migrate against a refused port: expected a refusal, got success")
	}
}

func TestOpenBillingStoreMemoryWhenUnconfigured(t *testing.T) {
	store, name, err := openBillingStore(func(string) string { return "" })
	if err != nil {
		t.Fatalf("openBillingStore: %v", err)
	}
	if name != "memory" {
		t.Errorf("store name = %q, want memory", name)
	}
	if store == nil {
		t.Fatal("expected a working in-memory store, got nil")
	}
}

func TestOpenBillingStoreRefusesAnUnreachableDatabase(t *testing.T) {
	getenv := func(key string) string {
		if key == "DATABASE_URL" {
			return "postgres://ghostlight:ghostlight@127.0.0.1:1/ghostlight?sslmode=disable"
		}
		return ""
	}
	if _, _, err := openBillingStore(getenv); err == nil {
		t.Error("unreachable database: expected a refusal, got a store that would silently forget")
	}
}

func TestReadyNamesTheBillingBackend(t *testing.T) {
	mux := newMux("s", testBackend(nil), "postgres", nil)
	_, body := get(t, mux, "/health/ready", "")
	backing, _ := body["backing"].(map[string]any)
	if backing["billing_store"] != "postgres" {
		t.Errorf("ready backing = %v, want the postgres backend named", body["backing"])
	}
}

const webuiTestKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func webuiEnv() func(string) string {
	return func(key string) string {
		if key == "GHOSTLIGHT_WEBUI_KEY" {
			return webuiTestKey
		}
		return ""
	}
}

// Without a signing key the console is not mounted at all, so an existing
// API-only deployment keeps behaving exactly as it did: JSON everywhere.
func TestConsoleUnmountedWithoutAKey(t *testing.T) {
	mux, err := buildMux(func(string) string { return "" }, testBackend(nil), dodo.NewMemoryStore(), "memory")
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: the API-only behaviour must be unchanged", rec.Code)
	}
}

// A malformed signing key refuses the start rather than serving a console whose
// CSRF tokens anyone could forge.
func TestConsoleWithABadKeyRefusesStartup(t *testing.T) {
	for _, bad := range []string{"not-hex", "aabb", webuiTestKey + "00"} {
		env := func(key string) string {
			if key == "GHOSTLIGHT_WEBUI_KEY" {
				return bad
			}
			return ""
		}
		if _, err := buildMux(env, testBackend(nil), dodo.NewMemoryStore(), "memory"); err == nil {
			t.Errorf("key %q must refuse startup", bad)
		}
	}
}

// With a key, the HTML root requires a session: an unauthenticated browser is
// redirected to sign in while the JSON API on /v1 stays bearer-authenticated
// with its own 401 semantics.
func TestConsoleRootRequiresASessionAndLeavesTheAPIAlone(t *testing.T) {
	mux, err := buildMux(webuiEnv(), testBackend(nil), dodo.NewMemoryStore(), "memory")
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("console without a session: status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}

	// The API keeps its own contract: 401 with a problem body, not a redirect.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/environments/env-1", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("API without credentials: status = %d, want 401", rec.Code)
	}
}

// A signed-in browser reaches the placeholder page, which is real served HTML
// and must therefore pass the accessibility gate like every other page.
func TestSignedInBrowserReachesThePlaceholderAndItPassesTheGate(t *testing.T) {
	mux, mgr, err := buildMuxWithSessions(webuiEnv(), testBackend(nil), dodo.NewMemoryStore(), "memory")
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	session, _, err := mgr.StartSession("principal-1", false, time.Now())
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: webui.CookieName, Value: session.ID})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("signed-in status = %d want 200, location=%q body=%q", rec.Code, rec.Header().Get("Location"), rec.Body.String()[:min(80, rec.Body.Len())])
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content type = %q, want text/html", ct)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `<html lang="en">`) {
		t.Error("the page must declare its language")
	}
	if !strings.Contains(body, "<title>Ghostlight console</title>") {
		t.Error("the page must have a title")
	}
	if !strings.Contains(body, "<h1>") {
		t.Error("the page must have exactly one h1")
	}
	if !strings.Contains(body, `href="#main"`) {
		t.Error("the page must carry the skip link")
	}

	rep, err := a11ygate.AuditDocument(body)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(rep.Violations) != 0 {
		t.Errorf("the placeholder violates %d accessibility rules; served HTML is not exempt", len(rep.Violations))
		for _, v := range rep.Violations {
			t.Logf("  %s: %s", v.Rule, v.Detail)
		}
	}
}

// A session started through the wired mux is revoked server-side by logout
// semantics: after Revoke, the same cookie is a redirect again.
func TestWiredConsoleRevocationEndsAccess(t *testing.T) {
	mux, mgr, err := buildMuxWithSessions(webuiEnv(), testBackend(nil), dodo.NewMemoryStore(), "memory")
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	session, _, err := mgr.StartSession("principal-1", false, time.Now())
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	do := func() int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: webui.CookieName, Value: session.ID})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := do(); code != http.StatusOK {
		t.Fatalf("before revoke: status = %d, want 200", code)
	}
	if err := mgr.Revoke(session.ID, "logged out", time.Now()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if code := do(); code != http.StatusFound {
		t.Errorf("after revoke: status = %d, want 302", code)
	}
}

// buildMuxWithSessions is buildMux with the console enabled, returning the
// session manager the mux actually uses, so tests start sessions on the same
// store the transport verifies against rather than on a parallel one.
func buildMuxWithSessions(getenv func(string) string, backend *api.Server, store billing.RecordStore, storeName string) (*http.ServeMux, *identity.Manager, error) {
	key, err := hex.DecodeString(webuiTestKey)
	if err != nil {
		return nil, nil, err
	}
	manager, err := identity.NewManager(time.Now)
	if err != nil {
		return nil, nil, err
	}
	transport, err := webui.NewTransport(manager, key, time.Now)
	if err != nil {
		return nil, nil, err
	}
	// Mirror production: signIn decides between the explanation page and a real
	// flow, so the tests exercise the same route table the server serves.
	session, err := signIn(getenv, transport, manager, SessionPage())
	if err != nil {
		return nil, nil, err
	}
	root, err := consoleRoot(backend, transport, session)
	if err != nil {
		return nil, nil, err
	}
	mux := newMux(buildSHA(getenv), backend, storeName, root)
	receiver, err := dodoReceiver(getenv, store)
	if err != nil {
		return nil, nil, err
	}
	mux.Handle("/hooks/dodo", receiver)
	return mux, manager, nil
}

// /login is served rather than redirected: Require sends unauthenticated
// browsers there, so redirecting /login to /login would loop forever. Until
// FE-2 wires the identity flow, the page says so with 503, and it is still
// served HTML and still audited.
func TestLoginPlaceholderServesInsteadOfLooping(t *testing.T) {
	mux, _, err := buildMuxWithSessions(webuiEnv(), testBackend(nil), dodo.NewMemoryStore(), "memory")
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Sign-in is not wired yet") {
		t.Error("the page must say plainly that the flow is not wired")
	}
	rep, err := a11ygate.AuditDocument(rec.Body.String())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(rep.Violations) != 0 {
		t.Errorf("the login placeholder violates %d accessibility rules", len(rep.Violations))
	}
}

// With no provider configured the sign-in page explains itself with 503 — it
// does not redirect (which would loop, since Require sends browsers to /login)
// and it does not serve a broken form.
func TestSignInUnconfiguredExplainsRatherThanLoops(t *testing.T) {
	mux, _, err := buildMuxWithSessions(webuiEnv(), testBackend(nil), dodo.NewMemoryStore(), "memory")
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Sign-in is not wired yet") {
		t.Error("the page must say plainly that the flow is not configured")
	}
	if rec.Header().Get("Location") != "" {
		t.Error("the unconfigured sign-in page must not redirect")
	}
}

// A half-configured provider refuses the start rather than running with a flow
// whose callback could never complete.
func TestSignInRefusesPartialConfiguration(t *testing.T) {
	mgr, err := identity.NewManager(time.Now)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	tr, err := webui.NewTransport(mgr, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	env := func(key string) string {
		switch key {
		case "ZITADEL_ISSUER":
			return "http://localhost:8080"
		case "ZITADEL_CLIENT_ID":
			return "ghostlight-console"
		default:
			return "" // no ZITADEL_REDIRECT_URI
		}
	}
	if _, err := signIn(env, tr, mgr, SessionPage()); err == nil {
		t.Error("an issuer and client id without a redirect URI must refuse the start")
	}
}

// /auth/callback refuses a provider error, a missing state and a missing code
// with the same redirect to /login and no session. An operator should not be
// able to tell which check failed.
func TestCallbackRefusesIncompleteOrErroredReturns(t *testing.T) {
	mux, mgr, err := buildMuxWithSessions(webuiEnv(), testBackend(nil), dodo.NewMemoryStore(), "memory")
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	before := mgr.SessionCount()
	for _, target := range []string{
		"/auth/callback?error=access_denied",
		"/auth/callback",
		"/auth/callback?state=x",
		"/auth/callback?code=y",
		"/auth/callback?state=never-minted&code=z",
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusFound {
			t.Errorf("%s: status = %d, want 302", target, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login" {
			t.Errorf("%s: Location = %q, want /login", target, loc)
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == webui.CookieName && c.Value != "" {
				t.Errorf("%s: a refused callback must not set a session cookie", target)
			}
		}
	}
	if after := mgr.SessionCount(); after != before {
		t.Errorf("session count changed from %d to %d across refused callbacks", before, after)
	}
}

// The sign-in routes are GET-only: a state-changing method on them is refused
// rather than treated as a sign-in.
func TestSignInRoutesRefuseNonGet(t *testing.T) {
	mux, _, err := buildMuxWithSessions(webuiEnv(), testBackend(nil), dodo.NewMemoryStore(), "memory")
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	for _, path := range []string{"/login", "/auth/callback"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s POST: status = %d, want 405", path, rec.Code)
		}
	}
}

// End-to-end sign-in against a stub provider: /login redirects to the
// authorization endpoint, the provider returns a code, and /auth/callback
// creates a session whose cookie then opens the console. This is the ticket's
// full-flow proof; the same path runs against local Zitadel manually.
func TestSignInEndToEndAgainstAStubProvider(t *testing.T) {
	provider := newStubOIDC(t)

	env := func(key string) string {
		switch key {
		case "GHOSTLIGHT_WEBUI_KEY":
			return webuiTestKey
		case "ZITADEL_ISSUER":
			return provider.issuer
		case "ZITADEL_CLIENT_ID":
			return "ghostlight-console"
		case "ZITADEL_REDIRECT_URI":
			return provider.issuer + "/auth/callback"
		default:
			return ""
		}
	}
	mux, mgr, err := buildMuxWithSessions(env, testBackend(nil), dodo.NewMemoryStore(), "memory")
	if err != nil {
		t.Fatalf("buildMux with a provider: %v", err)
	}
	before := mgr.SessionCount()

	// 1. /login sends the browser to the provider's authorization endpoint.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login?next=/env/7", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("/login status = %d, want 302", rec.Code)
	}
	authz, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("authorize URL does not parse: %v", err)
	}
	if !strings.HasPrefix(authz.String(), provider.issuer) {
		t.Fatalf("authorize URL left the provider: %q", authz)
	}
	state := authz.Query().Get("state")
	nonce := authz.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatalf("authorize URL carries state=%q nonce=%q; both are required", state, nonce)
	}

	// 2. The provider redirects back with a code. The stub mints an id_token
	//    carrying the flow's nonce, which is what real Zitadel does.
	provider.issueCode("code-1", nonce)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?state="+state+"&code=code-1", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want 303 (body: %s)", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/env/7" {
		t.Errorf("post-sign-in destination = %q, want /env/7: the flow must honour the target", loc)
	}
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == webui.CookieName && c.Value != "" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("a completed sign-in must set a session cookie")
	}
	if !sessionCookie.HttpOnly {
		t.Error("the session cookie must be HttpOnly")
	}
	if after := mgr.SessionCount(); after != before+1 {
		t.Errorf("session count = %d, want %d: a completed sign-in creates exactly one", after, before+1)
	}

	// 3. That cookie opens the console.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("signed-in console status = %d, want 200", rec.Code)
	}

	// 4. Replaying the same callback is refused: the flow was consumed.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?state="+state+"&code=code-1", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
		t.Errorf("replayed callback: status=%d location=%q, want 302 /login", rec.Code, rec.Header().Get("Location"))
	}
}

// A token minted for a different nonce is refused even though it verifies: it
// is genuine, but not genuine for this sign-in attempt.
func TestSignInRefusesATokenForAnotherNonce(t *testing.T) {
	provider := newStubOIDC(t)
	env := func(key string) string {
		switch key {
		case "GHOSTLIGHT_WEBUI_KEY":
			return webuiTestKey
		case "ZITADEL_ISSUER":
			return provider.issuer
		case "ZITADEL_CLIENT_ID":
			return "ghostlight-console"
		case "ZITADEL_REDIRECT_URI":
			return provider.issuer + "/auth/callback"
		default:
			return ""
		}
	}
	mux, mgr, err := buildMuxWithSessions(env, testBackend(nil), dodo.NewMemoryStore(), "memory")
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	before := mgr.SessionCount()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	authz, _ := url.Parse(rec.Header().Get("Location"))
	state := authz.Query().Get("state")

	provider.issueCode("code-1", "a-nonce-from-another-flow")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?state="+state+"&code=code-1", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
		t.Errorf("status=%d location=%q, want 302 /login", rec.Code, rec.Header().Get("Location"))
	}
	if after := mgr.SessionCount(); after != before {
		t.Errorf("a nonce mismatch created a session: count %d -> %d", before, after)
	}
}
