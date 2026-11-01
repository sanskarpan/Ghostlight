// Package zitadel verifies OIDC identity tokens minted by the self-hosted
// Zitadel instance chosen in ADR G-038.
//
// `internal/identity` owns everything about a session after sign-in; this
// package answers the one question before it: did this token actually come
// from our Zitadel, for us, and is it usable right now. The two halves meet
// at the subject: a verified token's `sub` names the principal that
// `identity.Manager` opens sessions for and revokes by.
//
// Five rules shape the verifier, and every one of them is a refusal:
//
// The first is that **verification is indistinguishable**. A wrong key, a
// tampered payload, a token for another audience, an expired token and
// garbage all return the same error. Telling a forger which check tripped
// turns the endpoint into an oracle — and an expired-but-genuine token is
// still a token worth distinguishing only to an attacker deciding whether
// to keep it.
//
// The second is that **the algorithm is pinned, not negotiated**. Only
// RS256 verifies. A token that says `none` is unsigned, and one that says
// HS256 against an RSA keyring is the classic confusion attack: the same
// bytes verified under the wrong primitive. Both are refused before any key
// is even looked up.
//
// The third is that **issuer and audience are equality checks, not
// suggestions**. The discovery document's issuer must equal the configured
// one exactly — a prefix match would let one Zitadel instance mint for
// another — and the token's audience must contain our client ID, whether it
// arrives as a string or a list. A token minted for someone else's login is
// not our user.
//
// The fourth is that **keys rotate through the JWKS, never around it**. An
// unknown `kid` triggers exactly one refresh; if the key is still unknown,
// the token is refused rather than accepted on stale keys or fetched in a
// loop. Rotation is the normal case (Zitadel already serves two signing
// keys), and a verifier that cannot follow it breaks every login at the
// first rotation.
//
// The fifth is that **the verifier holds no sessions and mints nothing**.
// It maps a token to claims and stops. Sessions, revocation, lockout and
// recovery live in `internal/identity`, which is the only place that can
// end what the provider started.
//
// What this package does not do is reach the network beyond discovery and
// the JWKS document, accept any other issuer, or trust a token's own claims
// about who verified the email: `email_verified` is reported, not enforced —
// enforcement is the caller's policy, and a verifier that silently decided
// it would be making the caller's decisions.
package zitadel

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Verification bounds.
const (
	// ClockSkew tolerates verifiers and issuers disagreeing about the time.
	// Expiry is granted this much grace, and not-before/issued-at this much
	// future tolerance. Beyond it, the clocks disagree and the token is
	// refused rather than guessed about.
	ClockSkew = time.Minute
	// MaxDocumentBytes bounds discovery and JWKS responses. Key sets are
	// small; an unbounded read is a memory allocation the server controls.
	MaxDocumentBytes = 1 << 20
	// HTTPTimeout bounds each metadata fetch. Verification that hangs is
	// verification that never answers, which upstream reads as an outage.
	HTTPTimeout = 10 * time.Second
)

// ErrUnverified means a token cannot be proven genuine, usable by us, and
// current. Every verification failure is this one error, with no detail.
var ErrUnverified = errors.New("zitadel token cannot be verified")

// Claims is a verified token's identity. Only the standard claims the
// platform binds sessions to are surfaced; everything else in the token is
// the provider's business.
type Claims struct {
	// Subject names the principal. It is stable across key rotations and is
	// what sessions bind to.
	Subject string
	// Email is the address the provider reports, if any.
	Email string
	// EmailVerified reports whether the provider verified the address.
	// Reported, not enforced: the caller decides what an unverified address
	// may do.
	EmailVerified bool
	// Name is the display name, if the provider supplies one.
	Name string
	// ExpiresAt bounds the token. IssuedAt dates it.
	ExpiresAt time.Time
	IssuedAt  time.Time
}

// Config names the Zitadel this verifier trusts and the audience it serves.
type Config struct {
	// Issuer is the expected issuer exactly as discovery reports it, for
	// example http://localhost:8080 in development. The discovered document
	// must agree byte for byte.
	Issuer string
	// Audience is our client ID. Tokens minted for anyone else are refused.
	Audience string
	// HTTPClient performs metadata fetches. Nil means a default client with
	// HTTPTimeout, because verification must never hang indefinitely.
	HTTPClient *http.Client
	// Now reports the verification moment. Nil means the wall clock.
	Now func() time.Time
}

// Verifier verifies tokens against a Zitadel issuer's key set.
type Verifier struct {
	issuer   string
	audience string
	jwksURI  string
	client   *http.Client
	now      func() time.Time

	mu   sync.Mutex
	keys map[string]*rsa.PublicKey
}

// NewVerifier discovers the issuer and loads its key set. Discovery runs
// once, at construction: the issuer and the JWKS location must not be able
// to drift independently per request, because a token verified against
// drifting metadata is verified against nothing in particular.
func NewVerifier(ctx context.Context, cfg Config) (*Verifier, error) {
	issuer := strings.TrimSpace(cfg.Issuer)
	audience := strings.TrimSpace(cfg.Audience)
	if issuer == "" || audience == "" {
		return nil, fmt.Errorf("%w: an issuer and an audience are both required; a verifier that trusts anyone verifies nothing", ErrUnverified)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: HTTPTimeout}
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	doc, err := fetchJSON(ctx, client, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("%w: discovery unreachable: %v", ErrUnverified, err)
	}
	var discovered struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(doc, &discovered); err != nil {
		return nil, fmt.Errorf("%w: discovery does not parse", ErrUnverified)
	}
	if discovered.Issuer != issuer || strings.TrimSpace(discovered.JWKSURI) == "" {
		return nil, fmt.Errorf("%w: discovery names a different issuer or no key set", ErrUnverified)
	}
	v := &Verifier{
		issuer: issuer, audience: audience, jwksURI: discovered.JWKSURI,
		client: client, now: now, keys: make(map[string]*rsa.PublicKey),
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	return v, nil
}

// Keys reports how many signing keys are cached, for tests and operators.
// It reports a count, never key material.
func (v *Verifier) Keys() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.keys)
}

// Verify proves a token genuine, ours, and current, and returns its claims.
// Unknown key IDs trigger exactly one JWKS refresh; anything still unknown
// afterwards is refused.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Claims{}, ErrUnverified
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrUnverified
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return Claims{}, ErrUnverified
	}
	if header.Algorithm != "RS256" || strings.TrimSpace(header.KeyID) == "" {
		return Claims{}, ErrUnverified
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrUnverified
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrUnverified
	}
	key, ok := v.key(header.KeyID)
	if !ok {
		if err := v.refresh(ctx); err != nil {
			return Claims{}, ErrUnverified
		}
		key, ok = v.key(header.KeyID)
		if !ok {
			return Claims{}, ErrUnverified
		}
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return Claims{}, ErrUnverified
	}
	var payload struct {
		Issuer        string `json:"iss"`
		Subject       string `json:"sub"`
		ExpiresAt     int64  `json:"exp"`
		NotBefore     int64  `json:"nbf"`
		IssuedAt      int64  `json:"iat"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return Claims{}, ErrUnverified
	}
	var envelope map[string]any
	if err := json.Unmarshal(payloadRaw, &envelope); err != nil {
		return Claims{}, ErrUnverified
	}
	now := v.now()
	if now.IsZero() {
		return Claims{}, ErrUnverified
	}
	if payload.Issuer != v.issuer || strings.TrimSpace(payload.Subject) == "" {
		return Claims{}, ErrUnverified
	}
	if !audienceContains(envelope["aud"], v.audience) {
		return Claims{}, ErrUnverified
	}
	if payload.ExpiresAt == 0 || now.After(time.Unix(payload.ExpiresAt, 0).Add(ClockSkew)) {
		return Claims{}, ErrUnverified
	}
	if payload.NotBefore != 0 && time.Unix(payload.NotBefore, 0).After(now.Add(ClockSkew)) {
		return Claims{}, ErrUnverified
	}
	if payload.IssuedAt != 0 && time.Unix(payload.IssuedAt, 0).After(now.Add(ClockSkew)) {
		return Claims{}, ErrUnverified
	}
	return Claims{
		Subject: payload.Subject, Email: payload.Email, EmailVerified: payload.EmailVerified,
		Name:      payload.Name,
		ExpiresAt: time.Unix(payload.ExpiresAt, 0).UTC(),
		IssuedAt:  time.Unix(payload.IssuedAt, 0).UTC(),
	}, nil
}

// audienceContains reports whether the token's audience names us, accepting
// the string and list shapes OIDC allows. Anything else is not an audience.
func audienceContains(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// key returns the cached key for a key ID.
func (v *Verifier) key(kid string) (*rsa.PublicKey, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	k, ok := v.keys[kid]
	return k, ok
}

// refresh reloads the key set, replacing the cache. Replacement, not merge:
// a removed key must stop verifying, because a rotation the verifier
// ignores is a revocation it misses.
func (v *Verifier) refresh(ctx context.Context) error {
	doc, err := fetchJSON(ctx, v.client, v.jwksURI)
	if err != nil {
		return fmt.Errorf("%w: key set unreachable", ErrUnverified)
	}
	var set struct {
		Keys []struct {
			Type      string `json:"kty"`
			Use       string `json:"use"`
			KeyID     string `json:"kid"`
			Algorithm string `json:"alg"`
			Modulus   string `json:"n"`
			Exponent  string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(doc, &set); err != nil {
		return fmt.Errorf("%w: key set does not parse", ErrUnverified)
	}
	next := make(map[string]*rsa.PublicKey)
	for _, k := range set.Keys {
		if k.Type != "RSA" || strings.TrimSpace(k.KeyID) == "" {
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.Modulus)
		if err != nil || len(nb) == 0 {
			continue
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.Exponent)
		if err != nil || len(eb) == 0 {
			continue
		}
		e := 0
		for _, b := range eb {
			e = e<<8 + int(b)
		}
		if e <= 0 {
			continue
		}
		next[k.KeyID] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
	}
	if len(next) == 0 {
		return fmt.Errorf("%w: key set holds no usable signing key", ErrUnverified)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keys = next
	return nil
}

// fetchJSON GETs a metadata document, bounded in size.
func fetchJSON(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxDocumentBytes {
		return nil, fmt.Errorf("metadata larger than %d bytes", MaxDocumentBytes)
	}
	return body, nil
}
