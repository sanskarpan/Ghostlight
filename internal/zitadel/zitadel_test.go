package zitadel

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

var zitNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// zitKeys is one RSA signing key with a stable ID.
type zitKeys struct {
	kid string
	key *rsa.PrivateKey
}

func zitGen(t *testing.T, kid string) zitKeys {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return zitKeys{kid: kid, key: key}
}

func zitJWK(k zitKeys) map[string]any {
	return map[string]any{
		"kty": "RSA", "use": "sig", "kid": k.kid, "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(k.key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.key.E)).Bytes()),
	}
}

// zitServer serves discovery + JWKS for issuer-for-its-URL, with swappable keys.
type zitServer struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	keys   []zitKeys
	issuer string
}

func zitUp(t *testing.T, keys ...zitKeys) *zitServer {
	t.Helper()
	z := &zitServer{t: t, keys: keys}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, z.issuerURL(), z.issuerURL()+"/keys")
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		z.mu.Lock()
		defer z.mu.Unlock()
		jwks := make([]map[string]any, 0, len(z.keys))
		for _, k := range z.keys {
			jwks = append(jwks, zitJWK(k))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": jwks})
	})
	z.srv = httptest.NewServer(mux)
	z.issuer = z.srv.URL
	t.Cleanup(z.srv.Close)
	return z
}

func (z *zitServer) issuerURL() string {
	return z.srv.URL
}

// rotate swaps the served key set, modelling a provider rotation.
func (z *zitServer) rotate(keys ...zitKeys) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.keys = keys
}

func zitVerifier(t *testing.T, z *zitServer) *Verifier {
	t.Helper()
	v, err := NewVerifier(context.Background(), Config{
		Issuer: z.issuerURL(), Audience: "ghostlight-api",
		Now: func() time.Time { return zitNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// zitMint signs a token. Header and payload overrides mutate the honest
// shape at exactly one joint each.
func zitMint(t *testing.T, k zitKeys, kid, alg string, payload map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": alg, "kid": kid, "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	h, p := base64.RawURLEncoding.EncodeToString(hb), base64.RawURLEncoding.EncodeToString(pb)
	if alg == "none" {
		return h + "." + p + "."
	}
	if alg == "HS256" {
		mac := hmac.New(sha256.New, []byte("wrong-primitive-shared-secret"))
		fmt.Fprintf(mac, "%s.%s", h, p)
		return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	sum := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func zitPayload(issuer string, exp, nbf, iat time.Time, aud any) map[string]any {
	p := map[string]any{
		"iss": issuer, "sub": "zitadel-sub-1", "aud": aud,
		"email": "user@example.com", "email_verified": true, "name": "Test User",
	}
	if !exp.IsZero() {
		p["exp"] = exp.Unix()
	}
	if !nbf.IsZero() {
		p["nbf"] = nbf.Unix()
	}
	if !iat.IsZero() {
		p["iat"] = iat.Unix()
	}
	return p
}

func zitHonest(t *testing.T, k zitKeys, issuer string, aud any) string {
	t.Helper()
	return zitMint(t, k, k.kid, "RS256",
		zitPayload(issuer, zitNow.Add(time.Hour), time.Time{}, zitNow.Add(-time.Minute), aud))
}

func TestVerifyAcceptsAGenuineToken(t *testing.T) {
	k := zitGen(t, "key-1")
	z := zitUp(t, k)
	v := zitVerifier(t, z)
	claims, err := v.Verify(context.Background(), zitHonest(t, k, z.issuerURL(), "ghostlight-api"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "zitadel-sub-1" || claims.Email != "user@example.com" || !claims.EmailVerified {
		t.Errorf("claims = %+v", claims)
	}
	if !claims.ExpiresAt.Equal(zitNow.Add(time.Hour)) {
		t.Errorf("ExpiresAt = %v", claims.ExpiresAt)
	}
	if v.Keys() != 1 {
		t.Errorf("cached keys = %d, want 1", v.Keys())
	}
}

// Every verification failure is the same error, or the endpoint teaches a
// forger which check tripped — including whether a token was once genuine.
func TestVerifyFailuresAreIndistinguishable(t *testing.T) {
	k := zitGen(t, "key-1")
	other := zitGen(t, "key-9")
	z := zitUp(t, k)
	v := zitVerifier(t, z)
	iss := z.issuerURL()
	base := func() map[string]any {
		return zitPayload(iss, zitNow.Add(time.Hour), time.Time{}, zitNow.Add(-time.Minute), "ghostlight-api")
	}
	hsPayload := zitPayload(iss, zitNow.Add(time.Hour), time.Time{}, zitNow.Add(-time.Minute), "ghostlight-api")
	cases := map[string]string{
		"wrong key":        zitMint(t, other, "key-9", "RS256", base()),
		"taken key id":     zitMint(t, other, "key-1", "RS256", base()),
		"tampered payload": strings.TrimSuffix(zitHonest(t, k, iss, "ghostlight-api"), "e") + "f",
		"tampered sig":     zitHonest(t, k, iss, "ghostlight-api")[:len(zitHonest(t, k, iss, "ghostlight-api"))-2] + "==",
		"wrong issuer":     zitMint(t, k, k.kid, "RS256", zitPayload("https://evil.example", zitNow.Add(time.Hour), time.Time{}, zitNow.Add(-time.Minute), "ghostlight-api")),
		"empty subject":    zitMint(t, k, k.kid, "RS256", func() map[string]any { p := base(); p["sub"] = ""; return p }()),
		"wrong audience":   zitMint(t, k, k.kid, "RS256", zitPayload(iss, zitNow.Add(time.Hour), time.Time{}, zitNow.Add(-time.Minute), "someone-else")),
		"missing audience": zitMint(t, k, k.kid, "RS256", func() map[string]any { p := base(); delete(p, "aud"); return p }()),
		"numeric audience": zitMint(t, k, k.kid, "RS256", func() map[string]any { p := base(); p["aud"] = 42; return p }()),
		"expired":          zitMint(t, k, k.kid, "RS256", zitPayload(iss, zitNow.Add(-time.Hour), time.Time{}, zitNow.Add(-2*time.Hour), "ghostlight-api")),
		"missing exp":      zitMint(t, k, k.kid, "RS256", func() map[string]any { p := base(); delete(p, "exp"); return p }()),
		"nbf future":       zitMint(t, k, k.kid, "RS256", zitPayload(iss, zitNow.Add(2*time.Hour), zitNow.Add(time.Hour), zitNow, "ghostlight-api")),
		"iat future":       zitMint(t, k, k.kid, "RS256", zitPayload(iss, zitNow.Add(2*time.Hour), time.Time{}, zitNow.Add(time.Hour), "ghostlight-api")),
		"alg none":         zitMint(t, k, k.kid, "none", hsPayload),
		"alg hs256":        zitMint(t, k, k.kid, "HS256", hsPayload),
		"missing kid":      zitMint(t, k, "", "RS256", base()),
		"unknown kid":      zitMint(t, other, "key-gone", "RS256", base()),
		"two parts":        "abc.def",
		"bad base64":       "!!!.@@@.###",
		"empty":            "",
	}
	for name, token := range cases {
		_, err := v.Verify(context.Background(), token)
		if !errors.Is(err, ErrUnverified) {
			t.Errorf("%s: error = %v, want ErrUnverified", name, err)
		}
		if err != nil && err.Error() != ErrUnverified.Error() {
			t.Errorf("%s: error carries detail %q", name, err.Error())
		}
	}
}

// List audiences verify too: OIDC allows both shapes, and both must work.
func TestVerifyAcceptsListAudiences(t *testing.T) {
	k := zitGen(t, "key-1")
	z := zitUp(t, k)
	v := zitVerifier(t, z)
	token := zitHonest(t, k, z.issuerURL(), []any{"other-client", "ghostlight-api"})
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("list audience containing us: %v", err)
	}
	without := zitHonest(t, k, z.issuerURL(), []any{"other-client"})
	if _, err := v.Verify(context.Background(), without); !errors.Is(err, ErrUnverified) {
		t.Errorf("list audience without us: error = %v", err)
	}
}

// Rotation is the normal case: an unknown kid refreshes once and verifies
// when the key is really there — and refuses when rotation removed the key,
// proving the refresh replaces rather than merges.
func TestVerifyFollowsKeyRotation(t *testing.T) {
	old := zitGen(t, "key-old")
	next := zitGen(t, "key-new")
	z := zitUp(t, old)
	v := zitVerifier(t, z)
	if _, err := v.Verify(context.Background(), zitHonest(t, old, z.issuerURL(), "ghostlight-api")); err != nil {
		t.Fatalf("before rotation: %v", err)
	}
	z.rotate(next)
	if _, err := v.Verify(context.Background(), zitHonest(t, next, z.issuerURL(), "ghostlight-api")); err != nil {
		t.Fatalf("rotated-in key after refresh: %v", err)
	}
	if v.Keys() != 1 {
		t.Errorf("cached keys = %d after rotation, want replacement not merge", v.Keys())
	}
	if _, err := v.Verify(context.Background(), zitHonest(t, old, z.issuerURL(), "ghostlight-api")); !errors.Is(err, ErrUnverified) {
		t.Error("rotated-out key still verifies: rotation must revoke")
	}
}

func TestNewVerifierRefusesBadConfig(t *testing.T) {
	z := zitUp(t, zitGen(t, "key-1"))
	for name, cfg := range map[string]Config{
		"empty issuer":   {Issuer: "", Audience: "ghostlight-api"},
		"empty audience": {Issuer: z.issuerURL(), Audience: ""},
	} {
		if _, err := NewVerifier(context.Background(), cfg); !errors.Is(err, ErrUnverified) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	if _, err := NewVerifier(context.Background(), Config{Issuer: "http://127.0.0.1:1", Audience: "ghostlight-api"}); !errors.Is(err, ErrUnverified) {
		t.Errorf("unreachable discovery: error = %v", err)
	}
}

// TestLiveDiscoveryShape pins the integration against the real local
// Zitadel: discovery is self-consistent and the JWKS parses into usable RSA
// keys. Shape only — no credentials, no tokens, no users created.
func TestLiveDiscoveryShape(t *testing.T) {
	v, err := NewVerifier(context.Background(), Config{
		Issuer: "http://localhost:8080", Audience: "ghostlight-api",
		Now: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		t.Skipf("local Zitadel is not serving (shape check needs it): %v", err)
	}
	if v.Keys() < 1 {
		t.Fatalf("live JWKS holds no keys")
	}
}
