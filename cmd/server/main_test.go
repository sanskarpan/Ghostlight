package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/api"
	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/dodo"
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
	}), "memory")
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
	}), "memory")
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
	mux := newMux("s", testBackend(nil), "memory")
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
	mux := newMux("s", testBackend(nil), "postgres")
	_, body := get(t, mux, "/health/ready", "")
	backing, _ := body["backing"].(map[string]any)
	if backing["billing_store"] != "postgres" {
		t.Errorf("ready backing = %v, want the postgres backend named", body["backing"])
	}
}
