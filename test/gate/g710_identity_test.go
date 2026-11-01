package gate_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/identity"
	"github.com/sanskarpan/Ghostlight/internal/zitadel"
)

// This file is the G7.10 identity seam gate: the place where a
// provider-established fact becomes one of our sessions.
//
// internal/zitadel answers whether a token came from our Zitadel, for us,
// and usable now. internal/identity owns everything after: the session, its
// revocation, and what happens when the person behind the subject leaves.
// The seam is the subject: the verified `sub` is the principal the manager
// opens sessions for — and the same principal it revokes by when the
// employment ends. A token that does not verify must never reach the
// manager at all, and a revoked principal must lose every session the
// provider's subjects ever opened, because the moment revocation is needed
// the person leaving is not available to enumerate their own sessions.
//
// What this suite may not claim: a hosted-sandbox SSO round-trip, SCIM
// provisioning, or a real login ceremony. Those need the sandbox and a
// human. What it does claim: the composition from verified token to
// session lifecycle holds over the real packages, with forgery stopped at
// the seam.

var g710Now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// g710Keys is one RSA signing key behind a test JWKS + discovery.
type g710Keys struct {
	kid string
	key *rsa.PrivateKey
}

func g710Gen(t *testing.T, kid string) g710Keys {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return g710Keys{kid: kid, key: key}
}

type g710Server struct {
	mu     sync.Mutex
	keys   []g710Keys
	srv    *httptest.Server
	issuer string
}

func g710Up(t *testing.T, keys ...g710Keys) *g710Server {
	t.Helper()
	z := &g710Server{keys: keys}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, z.srv.URL, z.srv.URL+"/keys")
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		z.mu.Lock()
		defer z.mu.Unlock()
		jwks := make([]map[string]any, 0, len(z.keys))
		for _, k := range z.keys {
			jwks = append(jwks, map[string]any{
				"kty": "RSA", "use": "sig", "kid": k.kid, "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(k.key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.key.E)).Bytes()),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": jwks})
	})
	z.srv = httptest.NewServer(mux)
	z.issuer = z.srv.URL
	t.Cleanup(z.srv.Close)
	return z
}

func g710Verifier(t *testing.T, z *g710Server) *zitadel.Verifier {
	t.Helper()
	v, err := zitadel.NewVerifier(context.Background(), zitadel.Config{
		Issuer: z.srv.URL, Audience: "ghostlight-api",
		Now: func() time.Time { return g710Now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func g710Manager(t *testing.T) *identity.Manager {
	t.Helper()
	m, err := identity.NewManager(func() time.Time { return g710Now })
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func g710Token(t *testing.T, k g710Keys, issuer, subject string, valid bool) string {
	t.Helper()
	payload := map[string]any{
		"iss": issuer, "sub": subject, "aud": "ghostlight-api",
		"email": "leaver@example.com", "email_verified": true,
		"exp": g710Now.Add(time.Hour).Unix(), "iat": g710Now.Add(-time.Minute).Unix(),
	}
	if !valid {
		payload["aud"] = "someone-else"
	}
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": k.kid, "typ": "JWT"})
	pb, _ := json.Marshal(payload)
	h, p := base64.RawURLEncoding.EncodeToString(hb), base64.RawURLEncoding.EncodeToString(pb)
	sum := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// The honest path: a verified token's subject becomes the session's
// principal, and the session verifies until the person leaves — at which
// point one revocation by principal ends every session their subjects ever
// opened, without enumerating them.
func TestG710GateVerifiedSubjectBindsAndRevokesByPrincipal(t *testing.T) {
	k := g710Gen(t, "key-1")
	z := g710Up(t, k)
	v := g710Verifier(t, z)
	m := g710Manager(t)
	ctx := context.Background()

	claims, err := v.Verify(ctx, g710Token(t, k, z.srv.URL, "zitadel-sub-leaver", true))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	s1, _, err := m.StartSession(claims.Subject, false, g710Now)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	s2, _, err := m.StartSession(claims.Subject, false, g710Now)
	if err != nil {
		t.Fatalf("StartSession again: %v", err)
	}
	if _, err := m.Verify(s1.ID, g710Now); err != nil {
		t.Fatalf("session must verify: %v", err)
	}
	ended, err := m.RevokePrincipal(claims.Subject, "employment ended", g710Now)
	if err != nil {
		t.Fatalf("RevokePrincipal: %v", err)
	}
	if ended != 2 {
		t.Errorf("revocation ended %d sessions, want both", ended)
	}
	if _, err := m.Verify(s1.ID, g710Now); err == nil {
		t.Error("revoked principal's session still verifies")
	}
	if _, err := m.Verify(s2.ID, g710Now); err == nil {
		t.Error("revoked principal's second session still verifies")
	}
}

// A token minted for someone else's login never reaches the manager: there
// is no principal to bind, so there is nothing to open, enumerate, or
// revoke. The seam stops forgery before identity ever sees it.
func TestG710GateForgedTokenOpensNoSession(t *testing.T) {
	k := g710Gen(t, "key-1")
	z := g710Up(t, k)
	verifier := g710Verifier(t, z)
	m := g710Manager(t)
	if _, err := verifier.Verify(context.Background(), g710Token(t, k, z.srv.URL, "zitadel-sub-impostor", false)); err == nil {
		t.Fatal("another audience's token verified: the seam is open")
	}
	if m.SessionCount() != 0 {
		t.Errorf("manager holds %d sessions with no verified token ever presented", m.SessionCount())
	}
}

// Rotation on the provider side does not strand the principal: a token under
// the new key verifies to the same subject, and the manager binds it to the
// same sessions the old key's tokens opened. Identity follows the subject,
// not the key.
func TestG710GateRotationKeepsThePrincipal(t *testing.T) {
	old := g710Gen(t, "key-old")
	next := g710Gen(t, "key-new")
	z := g710Up(t, old)
	verifier := g710Verifier(t, z)
	m := g710Manager(t)
	ctx := context.Background()

	first, err := verifier.Verify(ctx, g710Token(t, old, z.srv.URL, "zitadel-sub-steady", true))
	if err != nil {
		t.Fatalf("before rotation: %v", err)
	}
	s, _, err := m.StartSession(first.Subject, false, g710Now)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	z.mu.Lock()
	z.keys = []g710Keys{next}
	z.mu.Unlock()
	second, err := verifier.Verify(ctx, g710Token(t, next, z.srv.URL, "zitadel-sub-steady", true))
	if err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if second.Subject != first.Subject {
		t.Errorf("rotation changed the subject from %q to %q: identity must follow the person, not the key", first.Subject, second.Subject)
	}
	if _, err := m.Verify(s.ID, g710Now); err != nil {
		t.Errorf("rotation broke the open session: %v", err)
	}
}
