// Package previewaccess issues authenticated preview URLs and checks readiness.
//
// G2.5: "Implement authenticated preview URL and identity/config readiness checks."
// Two halves with one ordering between them.
//
// A preview URL is a capability: whoever holds it can see the preview. Capabilities
// that are unsigned, unexpiring, or unscoped are how previews leak — a URL pasted into
// a ticket, a log, or another preview's chat stays valid forever and opens whatever it
// opens. So every URL carries a signed token bound to one environment, one principal,
// and one purpose, with a short expiry. A token for env-A does not open env-B, and a
// token that outlives its purpose is refused rather than honoured.
//
// And no URL is issued unless the environment is ready: the caller's identity is
// authenticated and authorized for that environment, and the environment's config is
// verified current. Issuing a URL into an environment whose config is stale would serve
// yesterday's preview under today's address.
package previewaccess

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Errors returned by this package.
var (
	// ErrUnauthenticated means no usable identity was presented.
	ErrUnauthenticated = errors.New("no authenticated identity")
	// ErrUnauthorized means the identity may not access this environment.
	ErrUnauthorized = errors.New("identity is not authorized for this environment")
	// ErrNotReady means the environment's identity or config checks have not passed.
	ErrNotReady = errors.New("environment is not ready to serve")
	// ErrBadToken means the token is forged, malformed, or signed by nobody.
	ErrBadToken = errors.New("preview token is invalid")
	// ErrExpired means the token outlived its purpose.
	ErrExpired = errors.New("preview token has expired")
	// ErrWrongEnvironment means the token opens a different environment than the one
	// requested.
	ErrWrongEnvironment = errors.New("preview token is bound to a different environment")
	// ErrRevoked means the token was revoked before serving.
	ErrRevoked = errors.New("preview token has been revoked")
)

// Purpose scopes what a token is for. A token minted for viewing must not authorize
// mutation, and a token minted for one operation must not be reusable for another.
type Purpose string

const (
	// PurposeView opens the preview read-only.
	PurposeView Purpose = "view"
	// PurposeInteract allows interacting with the preview (forms, websockets).
	PurposeInteract Purpose = "interact"
)

// DefaultTTL bounds how long a URL stays valid.
const DefaultTTL = 15 * time.Minute

// Identity is an authenticated caller.
type Identity struct {
	// Principal is who this is, such as a user id or service account.
	Principal string
	// AuthenticatedAt is when authentication happened. Stale authentication is not
	// authentication: a session from last week must not mint fresh capabilities.
	AuthenticatedAt time.Time
	// ExpiresAt bounds the session itself.
	ExpiresAt time.Time
}

// Fresh reports whether the authentication is current.
func (i Identity) Fresh(now time.Time) bool {
	if i.Principal == "" {
		return false
	}
	if i.AuthenticatedAt.IsZero() || i.ExpiresAt.IsZero() {
		return false
	}
	if now.Before(i.AuthenticatedAt) {
		return false
	}
	return now.Before(i.ExpiresAt)
}

// Authorizer decides whether an identity may access an environment.
type Authorizer interface {
	// Authorized reports whether a principal may access an environment for a purpose.
	Authorized(ctx context.Context, principal, environmentID string, purpose Purpose) (bool, error)
}

// Readiness reports whether an environment may serve.
type Readiness struct {
	// IdentityChecked reports that the caller's identity was authenticated and
	// authorized.
	IdentityChecked bool
	// ConfigCurrent reports that the served config matches the current generation.
	ConfigCurrent bool
	// CheckedAt is when this was established.
	CheckedAt time.Time
	// Detail explains any failure for an operator.
	Detail string
}

// Ready reports whether serving may proceed.
func (r Readiness) Ready() bool { return r.IdentityChecked && r.ConfigCurrent }

// Checker establishes readiness.
type Checker interface {
	// Check verifies identity authorization and config currency for an environment.
	Check(ctx context.Context, id Identity, environmentID string, purpose Purpose) (Readiness, error)
}

// Token is a signed preview capability.
type Token struct {
	// EnvironmentID is the one environment this opens.
	EnvironmentID string
	// Principal is who it was minted for.
	Principal string
	// Purpose scopes what it authorizes.
	Purpose Purpose
	// IssuedAt bounds its life from below.
	IssuedAt time.Time
	// ExpiresAt bounds its life from above.
	ExpiresAt time.Time
	// Nonce makes every token unique even for identical claims.
	Nonce string
	// Signature authenticates the claims.
	Signature string
}

// payload is the signed content.
func (t Token) payload() string {
	claims := map[string]string{
		"env":     t.EnvironmentID,
		"sub":     t.Principal,
		"purpose": string(t.Purpose),
		"iat":     t.IssuedAt.UTC().Format(time.RFC3339),
		"exp":     t.ExpiresAt.UTC().Format(time.RFC3339),
		"nonce":   t.Nonce,
	}
	raw, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// Encode renders the token for a URL query parameter.
func (t Token) Encode() string {
	return t.payload() + "." + t.Signature
}

// DecodeToken parses an encoded token without verifying it.
//
// Parsing and verifying are separate because the failure modes differ: a malformed
// token is a client bug, while a well-formed token with a bad signature is an attack.
// Collapsing them makes incident response slower.
func DecodeToken(encoded string) (Token, error) {
	parts := strings.Split(encoded, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Token{}, fmt.Errorf("%w: malformed token", ErrBadToken)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Token{}, fmt.Errorf("%w: payload is not decodable", ErrBadToken)
	}
	var claims map[string]string
	if err := json.Unmarshal(raw, &claims); err != nil {
		return Token{}, fmt.Errorf("%w: payload is not valid", ErrBadToken)
	}
	iat, err := time.Parse(time.RFC3339, claims["iat"])
	if err != nil {
		return Token{}, fmt.Errorf("%w: issued-at is not a time", ErrBadToken)
	}
	exp, err := time.Parse(time.RFC3339, claims["exp"])
	if err != nil {
		return Token{}, fmt.Errorf("%w: expiry is not a time", ErrBadToken)
	}
	purpose := Purpose(claims["purpose"])
	if purpose != PurposeView && purpose != PurposeInteract {
		return Token{}, fmt.Errorf("%w: unknown purpose %q", ErrBadToken, claims["purpose"])
	}
	return Token{
		EnvironmentID: claims["env"],
		Principal:     claims["sub"],
		Purpose:       purpose,
		IssuedAt:      iat,
		ExpiresAt:     exp,
		Nonce:         claims["nonce"],
		Signature:     parts[1],
	}, nil
}

// Keeper signs tokens. Production uses the platform KMS; tests use HMAC.
type Keeper struct {
	key []byte
	id  string
}

// NewKeeper builds a keeper. An empty key is refused: it would mint tokens anyone
// could forge.
func NewKeeper(key []byte, id string) (*Keeper, error) {
	if len(key) == 0 {
		return nil, errors.New("a token signing key is required; an empty key would mint forgeable URLs")
	}
	if id == "" {
		return nil, errors.New("a keeper id is required")
	}
	return &Keeper{key: key, id: id}, nil
}

// Sign authenticates a token's claims.
func (k *Keeper) Sign(t Token) string {
	mac := hmac.New(sha256.New, k.key)
	fmt.Fprintf(mac, "ghostlight-preview:v1:%s:%s", k.id, t.payload())
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify checks a token's signature.
func (k *Keeper) Verify(t Token) error {
	if t.Signature == "" {
		return fmt.Errorf("%w: no signature", ErrBadToken)
	}
	want := k.Sign(t)
	if !hmac.Equal([]byte(want), []byte(t.Signature)) {
		return fmt.Errorf("%w: signature does not match the claims", ErrBadToken)
	}
	return nil
}

// Revocations tracks revoked tokens by nonce.
type Revocations interface {
	// Revoked reports whether a nonce was revoked.
	Revoked(ctx context.Context, nonce string) (bool, error)
	// Revoke records a revocation.
	Revoke(ctx context.Context, nonce string, at time.Time) error
}

// Issuer mints preview URLs.
type Issuer struct {
	keeper     *Keeper
	authorizer Authorizer
	checker    Checker
	now        func() time.Time
	ttl        time.Duration
	// seq makes every nonce unique even when the clock does not advance. Tests freeze
	// time, and two issuances in the same nanosecond must still be revocable
	// independently.
	mu  sync.Mutex
	seq uint64
}

// Config bounds an issuer.
type Config struct {
	// TTL bounds token life. Zero means the default.
	TTL time.Duration
	// Now overrides the clock.
	Now func() time.Time
}

// NewIssuer builds an issuer.
func NewIssuer(k *Keeper, a Authorizer, c Checker, cfg Config) (*Issuer, error) {
	if k == nil {
		return nil, errors.New("a URL issuer requires a signing keeper; unsigned preview URLs are the leak")
	}
	if a == nil {
		return nil, errors.New("a URL issuer requires an authorizer")
	}
	if c == nil {
		return nil, errors.New("a URL issuer requires a readiness checker; URLs must not be issued into unready environments")
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Issuer{keeper: k, authorizer: a, checker: c, now: cfg.Now, ttl: ttl}, nil
}

// Issue mints an authenticated preview URL.
//
// Readiness first: no URL is issued into an environment whose identity or config checks
// have not passed. Issuing first and checking later would hand out a capability and
// then try to take it back, which does not work once the URL has been copied.
func (u *Issuer) Issue(ctx context.Context, id Identity, environmentID string, purpose Purpose, baseURL string) (string, Token, error) {
	now := u.now()
	if !id.Fresh(now) {
		return "", Token{}, fmt.Errorf("%w: authentication for %q is missing, stale, or expired",
			ErrUnauthenticated, id.Principal)
	}
	if environmentID == "" {
		return "", Token{}, errors.New("a preview URL must name its environment")
	}
	if purpose != PurposeView && purpose != PurposeInteract {
		return "", Token{}, fmt.Errorf("%w: unknown purpose %q", ErrBadToken, purpose)
	}

	authorized, err := u.authorizer.Authorized(ctx, id.Principal, environmentID, purpose)
	if err != nil {
		return "", Token{}, fmt.Errorf("authorize %s for %s: %w", id.Principal, environmentID, err)
	}
	if !authorized {
		return "", Token{}, fmt.Errorf("%w: %s may not %s %s",
			ErrUnauthorized, id.Principal, purpose, environmentID)
	}

	readiness, err := u.checker.Check(ctx, id, environmentID, purpose)
	if err != nil {
		return "", Token{}, fmt.Errorf("check readiness of %s: %w", environmentID, err)
	}
	if !readiness.Ready() {
		return "", Token{}, fmt.Errorf("%w: %s (%s)", ErrNotReady, environmentID, readiness.Detail)
	}

	tok := Token{
		EnvironmentID: environmentID,
		Principal:     id.Principal,
		Purpose:       purpose,
		IssuedAt:      now,
		ExpiresAt:     now.Add(u.ttl),
		Nonce:         u.nonce(id.Principal, environmentID, now),
	}
	tok.Signature = u.keeper.Sign(tok)

	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}
	return baseURL + sep + "preview_token=" + tok.Encode(), tok, nil
}

// Verifier checks tokens at serve time.
type Verifier struct {
	keeper      *Keeper
	revocations Revocations
	now         func() time.Time
}

// NewVerifier builds a verifier.
func NewVerifier(k *Keeper, r Revocations, now func() time.Time) (*Verifier, error) {
	if k == nil {
		return nil, errors.New("a verifier requires the signing keeper")
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Verifier{keeper: k, revocations: r, now: now}, nil
}

// Verify checks a token for one environment and purpose.
//
// Every property is checked, in an order that fails safe: shape, signature, expiry,
// binding, revocation. A token that fails any of them opens nothing.
func (v *Verifier) Verify(ctx context.Context, encoded, environmentID string, purpose Purpose) (Token, error) {
	tok, err := DecodeToken(encoded)
	if err != nil {
		return Token{}, err
	}
	if err := v.keeper.Verify(tok); err != nil {
		return Token{}, err
	}
	now := v.now()
	if now.Before(tok.IssuedAt) {
		// Issued in the future. Either the clocks disagree or the token was minted by
		// someone playing games; either way it must not open anything yet.
		return Token{}, fmt.Errorf("%w: token is not yet valid", ErrBadToken)
	}
	if !now.Before(tok.ExpiresAt) {
		return Token{}, fmt.Errorf("%w: token for %s expired at %s",
			ErrExpired, tok.EnvironmentID, tok.ExpiresAt.Format(time.RFC3339))
	}
	if tok.EnvironmentID != environmentID {
		return Token{}, fmt.Errorf("%w: token opens %s, not %s",
			ErrWrongEnvironment, tok.EnvironmentID, environmentID)
	}
	if tok.Purpose != purpose {
		return Token{}, fmt.Errorf("%w: token is for %s, not %s",
			ErrBadToken, tok.Purpose, purpose)
	}
	if v.revocations != nil && tok.Nonce != "" {
		revoked, err := v.revocations.Revoked(ctx, tok.Nonce)
		if err != nil {
			// A revocation store that cannot be read is a fault, and the safe answer
			// to "was this revoked?" when the answer is unknowable is to refuse.
			return Token{}, fmt.Errorf("check revocation: %w", err)
		}
		if revoked {
			return Token{}, fmt.Errorf("%w: token for %s", ErrRevoked, tok.EnvironmentID)
		}
	}
	return tok, nil
}

// nonce derives a unique nonce. Uniqueness per issuance is what makes revocation
// addressable: revoking a nonce must revoke exactly one token.
func (u *Issuer) nonce(principal, environmentID string, now time.Time) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.seq++
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%d|%d", principal, environmentID, now.UnixNano(), u.seq)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))[:22]
}

// Describe renders a token for an operator without ever including the signature.
//
// A signature in a log next to the claims it authenticates is everything needed to
// replay the token.
func Describe(t Token) string {
	return fmt.Sprintf("env=%s sub=%s purpose=%s exp=%s",
		t.EnvironmentID, t.Principal, t.Purpose, t.ExpiresAt.Format(time.RFC3339))
}
