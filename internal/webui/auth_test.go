package webui

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/identity"
)

var now = time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)

// harness builds a transport over a real session manager and a handler that
// reports what it received, so every test asserts through the same path the
// browser would take.
type harness struct {
	t         *testing.T
	transport *Transport
	manager   *identity.Manager
	seen      *Session
	status    int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	mgr, err := identity.NewManager(func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	tr, err := NewTransport(mgr, []byte("test-signing-key-not-empty"), func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	h := &harness{t: t, transport: tr, manager: mgr}
	return h
}

// handler records the session the middleware resolved, or the status a refusal
// wrote, and always answers 200 so tests can tell "reached the handler" from
// "stopped at the door".
func (h *harness) handler() http.Handler {
	return h.transport.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := SessionFrom(r.Context())
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		h.seen = &s
		w.WriteHeader(http.StatusOK)
	}))
}

func (h *harness) do(req *http.Request) *http.Response {
	h.t.Helper()
	rec := httptest.NewRecorder()
	h.handler().ServeHTTP(rec, req)
	h.status = rec.Code
	return rec.Result()
}

// signedIn starts a real session through the manager and returns its cookie.
func (h *harness) signedIn(t *testing.T) (sessionID, csrf string) {
	t.Helper()
	session, _, err := h.manager.StartSession("principal-1", false, now)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	return session.ID, h.transport.CSRFToken(session.ID)
}

func get(target string, cookies ...*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

// An unauthenticated browser is redirected to sign in, never 401'd: the
// consumer is a person following a link, and a JSON error body is for programs.
func TestUnauthenticatedBrowserIsRedirectedToSignIn(t *testing.T) {
	h := newHarness(t)
	resp := h.do(get("/"))
	if h.status != http.StatusFound {
		t.Fatalf("status = %d, want 302", h.status)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
	if h.seen != nil {
		t.Error("no principal may reach the handler without a session")
	}
}

// A valid session reaches the handler with its principal, and nothing else
// resolves: the cookie value is an identity.Manager session ID, not a token
// this package interprets.
func TestValidSessionReachesTheHandler(t *testing.T) {
	h := newHarness(t)
	sid, _ := h.signedIn(t)
	h.do(get("/", &http.Cookie{Name: CookieName, Value: sid}))
	if h.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", h.status)
	}
	if h.seen == nil || h.seen.PrincipalID != "principal-1" {
		t.Fatalf("handler session = %+v, want principal-1", h.seen)
	}
	if h.seen.SessionID != sid {
		t.Errorf("session id = %q, want %q", h.seen.SessionID, sid)
	}
}

// A revoked session is a sign-in, not an error page, and the stale cookie is
// cleared so the next request does not repeat the lookup.
func TestRevokedSessionRedirectsAndClearsTheCookie(t *testing.T) {
	h := newHarness(t)
	sid, _ := h.signedIn(t)
	if err := h.manager.Revoke(sid, "logged out", now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	resp := h.do(get("/", &http.Cookie{Name: CookieName, Value: sid}))
	if h.status != http.StatusFound {
		t.Fatalf("status = %d, want 302", h.status)
	}
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == CookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the stale session cookie must be expired, not left in place")
	}
}

// An absolute-expired session is refused even though the ID still exists: the
// session manager owns validity and this package adds no second opinion.
func TestExpiredSessionIsRefused(t *testing.T) {
	h := newHarness(t)
	sid, _ := h.signedIn(t)
	later := now.Add(24 * 30 * time.Hour)
	h.transport.now = func() time.Time { return later }
	h.do(get("/", &http.Cookie{Name: CookieName, Value: sid}))
	if h.status != http.StatusFound {
		t.Fatalf("status = %d, want 302 after absolute expiry", h.status)
	}
}

// A malformed cookie value is a sign-in, never a 500: cookie contents are
// untrusted input.
func TestMalformedCookieValueIsRedirectedNotErrored(t *testing.T) {
	h := newHarness(t)
	for _, value := range []string{"", "   ", "not-a-session", strings.Repeat("x", 4096)} {
		h.do(get("/", &http.Cookie{Name: CookieName, Value: value}))
		if h.status != http.StatusFound {
			t.Fatalf("cookie %q: status = %d, want 302", value, h.status)
		}
	}
}

// The cookie attributes are the protection. Every write asserts all of them,
// because a cookie that is HttpOnly but not SameSite is half a defence.
func TestSessionCookieCarriesEveryAttribute(t *testing.T) {
	h := newHarness(t)
	sid, _ := h.signedIn(t)
	req := httptest.NewRequest(http.MethodGet, "https://ghostlight.example/", nil)
	rec := httptest.NewRecorder()
	h.transport.SetCookie(rec, req, sid)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != CookieName {
		t.Errorf("name = %q, want %q", c.Name, CookieName)
	}
	if !c.HttpOnly {
		t.Error("HttpOnly must be set: page script must not read the session")
	}
	if !c.Secure {
		t.Error("Secure must be set when the request arrived over TLS")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want /", c.Path)
	}
}

// Behind a TLS-terminating proxy the request itself is plain HTTP, so Secure
// follows X-Forwarded-Proto. A forged header from a direct client does not
// matter here: the platform sets it, and a direct-HTTP client setting it only
// marks its own cookie Secure, which its browser will then drop.
func TestSecureFollowsTheForwardedProto(t *testing.T) {
	h := newHarness(t)
	sid, _ := h.signedIn(t)

	plain := httptest.NewRequest(http.MethodGet, "http://ghostlight.example/", nil)
	rec := httptest.NewRecorder()
	h.transport.SetCookie(rec, plain, sid)
	if rec.Result().Cookies()[0].Secure {
		t.Error("a plain-HTTP request must not set Secure, or local development breaks")
	}

	forwarded := httptest.NewRequest(http.MethodGet, "http://ghostlight.example/", nil)
	forwarded.Header.Set("X-Forwarded-Proto", "https")
	rec = httptest.NewRecorder()
	h.transport.SetCookie(rec, forwarded, sid)
	if !rec.Result().Cookies()[0].Secure {
		t.Error("an HTTPS-forwarded request must set Secure")
	}
}

// A POST without the session's token is refused before the handler runs, and a
// well-formed token from a different session is refused too: a token that
// floats between sessions is decoration, not defence.
func TestCSRFIsBoundToTheSession(t *testing.T) {
	h := newHarness(t)
	sidA, tokenA := h.signedIn(t)
	_, tokenB := h.signedIn(t)

	// The composition the product uses: Require resolves the session, then
	// RequireCSRF verifies the form token against it. Testing the CSRF layer
	// without Require would prove less than nothing, since it reads the session
	// from the context Require provides.
	protected := h.transport.Require(h.transport.RequireCSRF(SessionHandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
	)))

	post := func(token string) *http.Response {
		form := url.Values{"csrf_token": {token}}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: CookieName, Value: sidA})
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		return rec.Result()
	}

	if resp := post(""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("missing token: status = %d, want 403", resp.StatusCode)
	}
	if resp := post(tokenB); resp.StatusCode != http.StatusForbidden {
		t.Errorf("another session's token: status = %d, want 403", resp.StatusCode)
	}
	if resp := post(tokenA); resp.StatusCode != http.StatusOK {
		t.Errorf("own token: status = %d, want 200", resp.StatusCode)
	}
}

// CSRF verification fails closed for a request with no session at all, because
// the compose order is Require then RequireCSRF and this is the backstop.
func TestCSRFWithoutASessionRedirects(t *testing.T) {
	h := newHarness(t)
	form := url.Values{"csrf_token": {"anything"}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.transport.RequireCSRF(SessionHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rec.Code)
	}
}

// The token is stable for the session's life, so a form rendered before an
// action still validates after it, and two sessions never share one.
func TestCSRFTokenIsStablePerSessionAndDistinctAcrossSessions(t *testing.T) {
	h := newHarness(t)
	sidA, _ := h.signedIn(t)
	tokenA1 := h.transport.CSRFToken(sidA)
	tokenA2 := h.transport.CSRFToken(sidA)
	if tokenA1 != tokenA2 {
		t.Error("a session's token must not change between renders")
	}
	sidB, _ := h.signedIn(t)
	if h.transport.CSRFToken(sidB) == tokenA1 {
		t.Error("two sessions must never share a token")
	}
}

// The transport refuses to exist without a signing key, because a CSRF token
// anyone can compute protects nothing.
func TestTransportRefusesAnEmptySigningKey(t *testing.T) {
	mgr, err := identity.NewManager(func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if _, err := NewTransport(mgr, nil, nil); err == nil {
		t.Error("an empty CSRF key must be a construction refusal")
	}
	if _, err := NewTransport(nil, []byte("key"), nil); err == nil {
		t.Error("a nil session manager must be a construction refusal")
	}
}

// End-to-end through a real cookie jar: start a session, follow the protected
// route, revoke, and confirm the jar's cookie stops working. This is the path a
// browser takes, not a hand-built request.
func TestFullSessionLifecycleThroughACookieJar(t *testing.T) {
	h := newHarness(t)
	sid, _ := h.signedIn(t)
	server := httptest.NewServer(h.handler())
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	u, _ := url.Parse(server.URL)
	jar.SetCookies(u, []*http.Cookie{{Name: CookieName, Value: sid, Path: "/"}})

	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signed-in status = %d, want 200", resp.StatusCode)
	}

	if err := h.manager.Revoke(sid, "logged out", now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	resp, err = client.Get(server.URL)
	if err != nil {
		t.Fatalf("get after revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("post-revoke status = %d, want 302", resp.StatusCode)
	}
}
