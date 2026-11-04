package main

// Manual end-to-end harness: GHOSTLIGHT_E2E=1 go test ./cmd/server -run TestE2EManual
// serves the real production handler chain on 127.0.0.1:8199 with a stub OIDC
// provider, so the full browser journey runs through the code the server serves.
// It is skipped unless the env var is set, so CI never runs it.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/api"
	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/dodo"
)

type e2eStub struct {
	mu      sync.Mutex
	key     *rsa.PrivateKey
	kid     string
	issuer  string
	nonces  map[string]string
	counter int
}

func TestE2EManualServe(t *testing.T) {
	if os.Getenv("GHOSTLIGHT_E2E") != "1" {
		t.Skip("manual harness: set GHOSTLIGHT_E2E=1 to serve the browser journey")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	stub := &e2eStub{key: key, kid: "e2e-key", nonces: map[string]string{}}
	const issuer = "http://127.0.0.1:8198"

	m := http.NewServeMux()
	m.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			issuer, issuer+"/authorize", issuer+"/token", issuer+"/keys")
	})
	m.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(stub.key.N.Bytes())
		fmt.Fprintf(w, `{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":%q,"n":%q,"e":"AQAB"}]}`, stub.kid, n)
	})
	m.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		stub.mu.Lock()
		stub.counter++
		code := fmt.Sprintf("code-%d", stub.counter)
		stub.nonces[code] = q.Get("nonce")
		stub.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+q.Get("state"), http.StatusFound)
	})
	m.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		stub.mu.Lock()
		nonce := stub.nonces[r.PostFormValue("code")]
		stub.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id_token":%q}`, stub.mint(issuer, r.PostFormValue("client_id"), nonce))
	})
	go func() {
		srv := &http.Server{Addr: "127.0.0.1:8198", Handler: m}
		_ = srv.ListenAndServe()
	}()

	store := &api.MemoryEnvironments{Environments: []api.Environment{{
		ID: "api-482", Scope: "org-a", Version: 2, Generation: 7,
		ExpiresAt: time.Now().Add(6 * time.Hour),
		Actions: []console.RecordedAction{
			{ID: "a1", Phase: console.PhaseArtifactBuild, Outcome: console.OutcomeSucceeded, StartedAt: time.Now().Add(-14 * time.Minute)},
			{ID: "a2", Phase: console.PhaseFoundationWarmup, Outcome: console.OutcomeUncertain, StartedAt: time.Now().Add(-9 * time.Minute), Detail: "the provider never answered"},
		},
	}}}
	backend := &api.Server{
		Auth: api.StaticAuthenticator{Tokens: map[string]contract.Principal{
			"org-a-user": {ID: "org-a-user", Grants: []string{"org-a"}},
		}},
		Operations:   contract.Registry{},
		Authorizer:   &contract.Authorizer{Registry: contract.Registry{}},
		Environments: store,
		Room:         roomPtr(),
		Passports:    passportPtr(),
	}
	getenv := func(k string) string {
		switch k {
		case "GHOSTLIGHT_WEBUI_KEY":
			return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		case "ZITADEL_ISSUER":
			return issuer
		case "ZITADEL_CLIENT_ID":
			return "e2e-console"
		case "ZITADEL_REDIRECT_URI":
			return "http://127.0.0.1:8199/auth/callback"
		}
		return ""
	}
	mux, err := buildMux(getenv, backend, dodo.NewMemoryStore(), "memory", store)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("e2e console serving on http://127.0.0.1:8199/")
	srv := &http.Server{Addr: "127.0.0.1:8199", Handler: mux}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		t.Fatal(err)
	}
}
