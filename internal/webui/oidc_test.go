package webui

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// stubProvider is a minimal OIDC provider: discovery, an authorize endpoint
// that records the PKCE challenge, and a token endpoint that refuses. The
// tests mint id_tokens directly from the provider's key, which exercises the
// same signature shape the real zitadel.Verifier expects.
type stubProvider struct {
	t          *testing.T
	srv        *httptest.Server
	key        *rsa.PrivateKey
	kid        string
	issuer     string
	challenges map[string]bool
}

func newStubProvider(t *testing.T) *stubProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	s := &stubProvider{t: t, key: key, kid: "test-key-1", challenges: make(map[string]bool)}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q}`,
			s.issuer, s.issuer+"/oauth/v2/authorize", s.issuer+"/oauth/v2/token")
	})
	mux.HandleFunc("/oauth/v2/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "pkce required", http.StatusBadRequest)
			return
		}
		s.challenges[q.Get("code_challenge")] = true
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=code-1&state="+q.Get("state"), http.StatusFound)
	})
	mux.HandleFunc("/oauth/v2/token", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "tests mint tokens directly", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	s.srv = srv
	s.issuer = srv.URL
	t.Cleanup(srv.Close)
	return s
}

// mintIDToken signs a minimal RS256 id_token carrying whatever claims the test
// asks for.
func (s *stubProvider) mintIDToken(audience string, extra map[string]any) string {
	s.t.Helper()
	header := b64(map[string]any{"alg": "RS256", "kid": s.kid, "typ": "JWT"})
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": s.issuer,
		"aud": audience,
		"sub": "user-42",
		"exp": now + 300,
		"iat": now,
	}
	for k, v := range extra {
		claims[k] = v
	}
	signingInput := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		s.t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func b64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func newTestFlow(t *testing.T, issuer string) *Flow {
	t.Helper()
	f, err := NewFlow(context.Background(), FlowConfig{
		Issuer:      issuer,
		ClientID:    "ghostlight-console",
		RedirectURI: issuer + "/auth/callback",
	})
	if err != nil {
		t.Fatalf("NewFlow: %v", err)
	}
	return f
}

// startedFlow mints a flow and returns its state, verifier and the claims
// verifier to use with finishVerified, so tests drive the real seams.
func startedFlow(t *testing.T, f *Flow, target string) (state, verifier, nonce string) {
	t.Helper()
	authz, err := f.Start(target)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, err := url.Parse(authz)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	q := u.Query()
	f.mu.Lock()
	pending, ok := f.pending[q.Get("state")]
	f.mu.Unlock()
	if !ok {
		t.Fatal("Start stored no pending flow")
	}
	return q.Get("state"), pending.verifier, q.Get("nonce")
}

func fakeVerifyOK(context.Context, string) (Claims, error) {
	return Claims{Subject: "user-42"}, nil
}

func fakeVerifyFail(context.Context, string) (Claims, error) {
	return Claims{}, fmt.Errorf("signature check failed")
}

// The authorize URL carries everything the flow needs to prove itself on
// return: state, nonce, and an S256 PKCE challenge.
func TestStartBuildsAnAuthorizeURLWithStateNonceAndPKCE(t *testing.T) {
	provider := newStubProvider(t)
	f := newTestFlow(t, provider.issuer)

	authz, err := f.Start("/env/9")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !strings.HasPrefix(authz, provider.issuer+"/oauth/v2/authorize?") {
		t.Errorf("authorize endpoint came from discovery, got %q", authz)
	}
	u, _ := url.Parse(authz)
	q := u.Query()
	for _, key := range []string{"state", "nonce", "code_challenge", "code_challenge_method", "client_id", "redirect_uri", "response_type"} {
		if q.Get(key) == "" {
			t.Errorf("authorize URL is missing %q", key)
		}
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("challenge method = %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("scope") != "openid" {
		t.Errorf("scope = %q, want openid", q.Get("scope"))
	}
	// The challenge must be the S256 of the stored verifier, not the verifier
	// itself: a challenge that reverses to the verifier is a password.
	f.mu.Lock()
	verifier := f.pending[q.Get("state")].verifier
	f.mu.Unlock()
	if q.Get("code_challenge") == verifier {
		t.Error("the authorize URL carries the verifier, not the challenge")
	}
	if q.Get("code_challenge") != s256(verifier) {
		t.Error("the challenge is not the S256 of the stored verifier")
	}
}

// The post-sign-in destination is same-origin or nothing: absolute URLs,
// scheme-relative forms and backslash tricks are all refused at Start, because
// a login flow that will redirect anywhere is an open redirect.
func TestStartRefusesDestinationsOffThisOrigin(t *testing.T) {
	provider := newStubProvider(t)
	f := newTestFlow(t, provider.issuer)

	for _, bad := range []string{
		"https://evil.example/steal",
		"//evil.example/steal",
		"/\\evil.example", // browsers normalise the backslash to //evil.example
		"\\/evil.example",
		"/\\/evil.example",
		"http://evil.example",
		"HTTP://evil.example", // scheme matching is case-insensitive
		"/path with space",
		"/path\ttab",
		"/path\nnewline",
		"javascript:alert(1)",
		"data:text/html,<script>",
		"env/9", // relative, not rooted
	} {
		if _, err := f.Start(bad); err == nil {
			t.Errorf("destination %q must be refused", bad)
		}
	}
	if _, err := f.Start(""); err != nil {
		t.Errorf("an empty destination means the default, not a refusal: %v", err)
	}
}

// The happy path through verification: nonce matched, subject surfaced,
// destination honoured.
func TestFinishVerifiedHonoursTheFlow(t *testing.T) {
	provider := newStubProvider(t)
	f := newTestFlow(t, provider.issuer)
	_, _, nonce := startedFlow(t, f, "/env/9")

	idToken := provider.mintIDToken("ghostlight-console", map[string]any{"nonce": nonce})
	result, err := f.finishVerified(pendingFlow{nonce: nonce, redirectTo: "/env/9"}, idToken, fakeVerifyOK)
	if err != nil {
		t.Fatalf("finishVerified: %v", err)
	}
	if result.Subject != "user-42" {
		t.Errorf("subject = %q, want user-42", result.Subject)
	}
	if result.Target != "/env/9" {
		t.Errorf("target = %q, want /env/9", result.Target)
	}
}

// A state this process never minted is refused, and an expired flow is the
// same refusal, so replay cannot be told apart from forgery.
func TestFinishRefusesUnknownAndExpiredStates(t *testing.T) {
	provider := newStubProvider(t)
	f := newTestFlow(t, provider.issuer)

	if _, err := f.Finish(context.Background(), "never-minted", "code", fakeVerifyOK); err == nil {
		t.Error("an unknown state must be refused")
	}

	state, _, _ := startedFlow(t, f, "/")
	f.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if _, err := f.Finish(context.Background(), state, "code", fakeVerifyOK); err == nil {
		t.Error("an expired flow must be refused")
	}
}

// A verified token whose nonce does not belong to this flow is refused: the
// token is genuine, but it is not genuine for this sign-in attempt.
func TestFinishRefusesANonceMismatch(t *testing.T) {
	provider := newStubProvider(t)
	f := newTestFlow(t, provider.issuer)
	state, _, _ := startedFlow(t, f, "/")
	f.mu.Lock()
	pending := f.pending[state]
	f.mu.Unlock()

	idToken := provider.mintIDToken("ghostlight-console", map[string]any{"nonce": "someone-elses-nonce"})
	if _, err := f.finishVerified(pending, idToken, fakeVerifyOK); err != ErrNonceMismatch {
		t.Errorf("err = %v, want ErrNonceMismatch", err)
	}
}

// A token that fails verification is refused, and a consumed flow is not
// reusable: Finish deletes the pending flow before anything can go wrong.
func TestFinishRefusesVerificationFailureAndDoesNotReuseTheFlow(t *testing.T) {
	provider := newStubProvider(t)
	f := newTestFlow(t, provider.issuer)
	state, _, _ := startedFlow(t, f, "/")

	if _, err := f.Finish(context.Background(), state, "code", fakeVerifyFail); err == nil {
		t.Error("a failing verifier must refuse the finish")
	}
	if _, err := f.Finish(context.Background(), state, "code", fakeVerifyOK); err == nil {
		t.Error("a consumed flow must not be reusable")
	}
}

// An unusable discovery document is a construction refusal, not a runtime
// surprise on the first sign-in.
func TestNewFlowRefusesBrokenDiscovery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	if _, err := NewFlow(context.Background(), FlowConfig{
		Issuer: srv.URL, ClientID: "c", RedirectURI: srv.URL + "/auth/callback",
	}); err == nil {
		t.Error("a broken discovery document must refuse construction")
	}
}

// The local Zitadel dev stack proves the real discovery document has the
// endpoints this flow needs. It skips when the stack is not running, so CI
// without Docker stays green; when it runs, it is the ticket's full-flow proof
// one hop away from live.
func TestLocalZitadelDiscoveryServesTheEndpoints(t *testing.T) {
	issuer := "http://localhost:8080"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Skipf("local Zitadel not running: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("local Zitadel answered %d", resp.StatusCode)
	}
	var doc struct {
		Authz string `json:"authorization_endpoint"`
		Token string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("discovery does not parse: %v", err)
	}
	if doc.Authz == "" || doc.Token == "" {
		t.Errorf("discovery endpoints = %q / %q, both required", doc.Authz, doc.Token)
	}
}
