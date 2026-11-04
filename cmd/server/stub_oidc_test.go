package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// stubOIDC is a minimal OpenID provider for the server's end-to-end sign-in
// tests: discovery, a JWKS, and a token endpoint that mints a real RS256
// id_token carrying the nonce the test registers against the code. It is
// deliberately small — the point is to exercise the server's flow, not to
// reimplement Zitadel.
type stubOIDC struct {
	t      *testing.T
	srv    *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	issuer string

	mu     sync.Mutex
	nonces map[string]string // code -> nonce to embed
}

func newStubOIDC(t *testing.T) *stubOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	s := &stubOIDC{t: t, key: key, kid: "stub-key-1", nonces: make(map[string]string)}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			s.issuer, s.issuer+"/oauth/v2/authorize", s.issuer+"/oauth/v2/token", s.issuer+"/oauth/v2/keys")
	})

	mux.HandleFunc("/oauth/v2/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(s.key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}) // 65537 as 3 bytes
		fmt.Fprintf(w, `{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":%q,"n":%q,"e":%q}]}`, s.kid, n, e)
	})

	mux.HandleFunc("/oauth/v2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "form", http.StatusBadRequest)
			return
		}
		code := r.PostFormValue("code")
		s.mu.Lock()
		nonce, ok := s.nonces[code]
		s.mu.Unlock()
		if !ok {
			http.Error(w, "unknown code", http.StatusBadRequest)
			return
		}
		if r.PostFormValue("code_verifier") == "" {
			http.Error(w, "pkce required", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id_token":%q}`, s.mint(r.PostFormValue("client_id"), nonce))
	})

	srv := httptest.NewServer(mux)
	s.srv = srv
	s.issuer = srv.URL
	t.Cleanup(srv.Close)
	return s
}

// issueCode registers a code whose id_token will carry the given nonce.
func (s *stubOIDC) issueCode(code, nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[code] = nonce
}

func (s *stubOIDC) mint(audience, nonce string) string {
	s.t.Helper()
	header := stubB64(map[string]any{"alg": "RS256", "kid": s.kid, "typ": "JWT"})
	now := time.Now().Unix()
	claims := map[string]any{
		"iss":   s.issuer,
		"aud":   audience,
		"sub":   "user-42",
		"email": "operator@acme.test",
		"name":  "Operator",
		"exp":   now + 300,
		"iat":   now,
		"nonce": nonce,
	}
	input := header + "." + stubB64(claims)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		s.t.Fatalf("sign: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func stubB64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}
