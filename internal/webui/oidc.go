// OIDC authorization-code flow for the browser console.
//
// The rules this file enforces come from the frontend plan (§3) and ticket
// FE-2. The first is that **the flow begins at /login and ends at a session**,
// and nothing in between is trusted: the state parameter is generated here and
// matched on return, the nonce is generated here and matched inside the
// verified token, and the PKCE verifier is generated here and spent exactly
// once at the token endpoint. A callback carrying anything this process did
// not mint is refused before a session exists.
//
// The second is that **a refused callback creates no session.** An invalid
// state, a wrong nonce, an expired flow or a token that will not verify all
// end at the same place: no cookie, no session, and the operator back at the
// sign-in card. A half-created session from a half-verified login is worse
// than none, because it looks like an answer.
//
// The third is that **the post-sign-in destination is same-origin or
// nothing.** The state carries where the operator was headed, and that value
// is checked against absolute URLs and scheme-relative forms before it is
// honoured, because a login flow that will redirect anywhere is an open
// redirect wearing a lanyard.
package webui

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Flow errors.
var (
	// ErrFlowUnknown means the callback's state matches nothing this process
	// minted. It is the same response an expired flow gets, so an attacker
	// cannot distinguish replay from forgery.
	ErrFlowUnknown = errors.New("webui: unknown or expired sign-in flow")
	// ErrNonceMismatch means the verified token's nonce does not match the one
	// bound to this flow. The token is genuine; it is not genuine *for this
	// sign-in attempt*, which is the thing that matters.
	ErrNonceMismatch = errors.New("webui: token nonce does not match the sign-in flow")
	// ErrUnsafeRedirect means the post-sign-in destination was absolute or
	// scheme-relative. Only paths on this origin are honoured.
	ErrUnsafeRedirect = errors.New("webui: post-sign-in destination must be a path on this origin")
	// ErrDiscovery means the provider's discovery document is unusable.
	ErrDiscovery = errors.New("webui: provider discovery is unusable")
	// ErrExchange means the code exchange failed for any reason. The token
	// endpoint's own error text is not surfaced: it is the provider's business
	// and it must not become our error oracle.
	ErrExchange = errors.New("webui: code exchange failed")
)

// FlowConfig names the provider and this client.
type FlowConfig struct {
	// Issuer is the provider's base URL, for example http://localhost:8080.
	// The authorize and token endpoints come from its discovery document, not
	// from configuration, so the paths cannot drift from the issuer.
	Issuer string
	// ClientID is this application's registered identifier.
	ClientID string
	// ClientSecret authenticates the token exchange. Empty means a public
	// client, which then must use PKCE — and PKCE is always used anyway.
	ClientSecret string
	// RedirectURI is where the provider returns the browser, for example
	// http://localhost:8080/auth/callback.
	RedirectURI string
	// HTTPClient performs discovery and exchange. Nil means a default client
	// with a timeout, because a login must never hang indefinitely.
	HTTPClient *http.Client
	// Now bounds flow lifetimes. Nil means the wall clock.
	Now func() time.Time
}

// pendingFlow is one in-flight sign-in attempt.
type pendingFlow struct {
	nonce      string
	verifier   string
	redirectTo string
	expiresAt  time.Time
}

// Flow drives the authorization-code flow and remembers what it minted.
type Flow struct {
	mu       sync.Mutex
	issuer   string
	clientID string
	secret   string
	redirect string
	authzURL string
	tokenURL string
	client   *http.Client
	now      func() time.Time
	pending  map[string]pendingFlow
	ttl      time.Duration
}

// NewFlow builds the flow. Discovery runs once at construction so the
// authorize and token endpoints cannot drift from the issuer per request.
func NewFlow(ctx context.Context, cfg FlowConfig) (*Flow, error) {
	issuer := strings.TrimSuffix(strings.TrimSpace(cfg.Issuer), "/")
	clientID := strings.TrimSpace(cfg.ClientID)
	redirect := strings.TrimSpace(cfg.RedirectURI)
	if issuer == "" || clientID == "" || redirect == "" {
		return nil, fmt.Errorf("%w: issuer, client id and redirect uri are all required", ErrDiscovery)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	var doc struct {
		AuthzEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := fetchInto(ctx, client, issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, err
	}
	if strings.TrimSpace(doc.AuthzEndpoint) == "" || strings.TrimSpace(doc.TokenEndpoint) == "" {
		return nil, fmt.Errorf("%w: discovery names no authorization or token endpoint", ErrDiscovery)
	}
	return &Flow{
		issuer:   issuer,
		clientID: clientID,
		secret:   cfg.ClientSecret,
		redirect: redirect,
		authzURL: doc.AuthzEndpoint,
		tokenURL: doc.TokenEndpoint,
		client:   client,
		now:      now,
		pending:  make(map[string]pendingFlow),
		ttl:      10 * time.Minute,
	}, nil
}

// Start mints one sign-in attempt and returns the URL to redirect the browser
// to. The state, nonce and PKCE verifier are all generated here; the target is
// stored under the state so the return trip can honour it after checking it.
func (f *Flow) Start(target string) (string, error) {
	if target == "" {
		target = "/"
	}
	if !sameOriginPath(target) {
		return "", ErrUnsafeRedirect
	}
	state, err := randomToken(32)
	if err != nil {
		return "", err
	}
	nonce, err := randomToken(32)
	if err != nil {
		return "", err
	}
	verifier, err := randomToken(64)
	if err != nil {
		return "", err
	}
	challenge := s256(verifier)

	q := url.Values{}
	q.Set("client_id", f.clientID)
	q.Set("redirect_uri", f.redirect)
	q.Set("response_type", "code")
	q.Set("scope", "openid")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	f.mu.Lock()
	// Bound the map: a forgotten flow expires and is swept on the next start,
	// so a client that mints starts forever cannot grow the memory forever.
	for k, v := range f.pending {
		if f.now().After(v.expiresAt) {
			delete(f.pending, k)
		}
	}
	f.pending[state] = pendingFlow{
		nonce:      nonce,
		verifier:   verifier,
		redirectTo: target,
		expiresAt:  f.now().Add(f.ttl),
	}
	f.mu.Unlock()

	return f.authzURL + "?" + q.Encode(), nil
}

// Finish exchanges the callback's code for a verified token and returns the
// claims, the nonce check being part of the verification, and the destination
// the operator was originally headed to.
//
// The signature is verified by the zitadel.Verifier; the nonce is read from
// the same token payload afterwards, which is sound because the signature has
// already bound the payload to the issuer.
type FinishResult struct {
	Subject string
	Email   string
	Name    string
	Target  string
}

// Finish verifies and completes the sign-in. verify is the zitadel verifier's
// Verify method (or equivalent); it is injected so the flow does not own
// signature verification and cannot grow a second one.
func (f *Flow) Finish(ctx context.Context, state, code string, verify func(context.Context, string) (Claims, error)) (FinishResult, error) {
	result := FinishResult{}
	f.mu.Lock()
	pending, ok := f.pending[state]
	if ok {
		delete(f.pending, state)
	}
	f.mu.Unlock()
	if !ok || f.now().After(pending.expiresAt) {
		return result, ErrFlowUnknown
	}

	idToken, err := f.exchange(ctx, code, pending.verifier)
	if err != nil {
		return result, err
	}
	return f.finishVerified(pending, idToken, verify)
}

// finishVerified completes a sign-in whose token has been obtained: verify the
// claims, check the nonce against the flow, and surface the destination. The
// exchange and this half are separate so tests can drive verification with a
// token minted in the test itself.
func (f *Flow) finishVerified(pending pendingFlow, idToken string, verify func(context.Context, string) (Claims, error)) (FinishResult, error) {
	result := FinishResult{}
	claims, err := verify(context.Background(), idToken)
	if err != nil {
		return result, err
	}
	nonce, err := tokenNonce(idToken)
	if err != nil {
		return result, err
	}
	if nonce != pending.nonce {
		return result, ErrNonceMismatch
	}
	result.Subject = claims.Subject
	result.Email = claims.Email
	result.Name = claims.Name
	result.Target = pending.redirectTo
	if !sameOriginPath(result.Target) {
		// The stored target was checked at Start; this is the belt to that
		// check's braces, because the map is in this process's memory only.
		result.Target = "/"
	}
	return result, nil
}

// exchange posts the code to the token endpoint.
func (f *Flow) exchange(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", f.redirect)
	form.Set("client_id", f.clientID)
	form.Set("code_verifier", verifier)
	if f.secret != "" {
		form.Set("client_secret", f.secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", ErrExchange
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrExchange, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", ErrExchange
	}
	var token struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil || strings.TrimSpace(token.IDToken) == "" {
		return "", ErrExchange
	}
	return token.IDToken, nil
}

// SafeTarget exposes the same-origin check to callers that need to validate a
// destination before handing it to Start, so the rule lives in one place.
func SafeTarget(target string) bool { return sameOriginPath(target) }

// sameOriginPath reports whether a destination is a path on this origin.
// Absolute URLs, scheme-relative forms and backslash tricks are all refused:
// a sign-in flow that will redirect anywhere is an open redirect.
//
// The backslash check is not decoration. Browsers normalise "\" to "/" in URLs,
// so a target of `/\evil.example` is sent to the browser as `//evil.example` —
// a scheme-relative URL to another host. Checking only for a leading "//"
// misses it. Any backslash anywhere is therefore refused, and so is a control
// character or whitespace, which some parsers strip before the browser sees
// the difference.
func sameOriginPath(target string) bool {
	if target == "" {
		return false
	}
	if strings.ContainsAny(target, "\\") {
		return false
	}
	for _, r := range target {
		if r < 0x20 || r == 0x7f || r == ' ' {
			return false
		}
	}
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	// A URL with a scheme or a host is not a path on this origin.
	if u.Scheme != "" || u.Host != "" || u.Opaque != "" {
		return false
	}
	if strings.HasPrefix(target, "//") {
		return false
	}
	if !strings.HasPrefix(u.Path, "/") {
		return false
	}
	return true
}

// tokenNonce reads the nonce claim from a token whose signature has already
// been verified by the caller.
func tokenNonce(idToken string) (string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", ErrNonceMismatch
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrNonceMismatch
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", ErrNonceMismatch
	}
	if strings.TrimSpace(claims.Nonce) == "" {
		return "", ErrNonceMismatch
	}
	return claims.Nonce, nil
}

func randomToken(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// s256 is the PKCE S256 challenge: base64url of the SHA-256 of the verifier.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func fetchInto(ctx context.Context, client *http.Client, endpoint string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDiscovery, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDiscovery, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s answered %d", ErrDiscovery, endpoint, resp.StatusCode)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("%w: does not parse", ErrDiscovery)
	}
	return nil
}

// Claims mirrors the fields of zitadel.Claims this flow surfaces. It exists so
// the Finish signature does not import the zitadel package, keeping this file's
// dependency on verification injectable.
type Claims struct {
	Subject string
	Email   string
	Name    string
}
