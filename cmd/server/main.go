// Command server is the platform API's HTTP entrypoint for checklist row G7.7
// and the Render deploy in test/gate issue #182.
//
// It wires the api.Server from the api package to the network and nothing
// else: the rules live in internal/contract, internal/console and friends;
// this command only binds them to a port. The previous deploy failed because
// the build ran at the repo root, which holds no Go files, and because no
// HTTP entrypoint existed at all — this is that entrypoint.
//
// Configuration comes from the environment and nothing else:
//
//	PORT                     Port to listen on. Render injects it; when unset
//	                         the server listens on 8080 and says so (local default).
//	GHOSTLIGHT_API_TOKENS    The bearer-token credential set, as one or more
//	                         entries separated by ";". Each entry is exactly
//	                         "principal-id:token|grant1,grant2|perm1,perm2",
//	                         where the grant and permission lists may be empty
//	                         but the pipes may not be omitted. The pipe
//	                         separates the fields because grants and
//	                         permissions themselves contain colons
//	                         ("repo:acme"), so colons cannot delimit them.
//	                         Ids and tokens must be unique; ids must be free
//	                         of whitespace, ':' and ';', and tokens free of
//	                         whitespace, ':', ';', '|' and ','. Empty or
//	                         malformed means the server refuses to start: an
//	                         API with no credentials configured is a
//	                         misconfiguration, not a mode.
//	GHOSTLIGHT_WEBUI_KEY     Hex signing key (64 chars / 32 bytes) for the
//	                         browser console's CSRF tokens. Unset means the
//	                         console is not mounted at all and the deployment
//	                         stays API-only, which is the current default.
//	                         Present-but-malformed refuses the start: a console
//	                         whose tokens anyone could forge is worse than no
//	                         console. Sessions are in-memory and end on restart.
//	DODO_WEBHOOK_SECRET      Signing secret for the Dodo webhook endpoint.
//	                         Missing means the route stays mounted and refuses
//	                         every delivery: an unverifiable endpoint must not
//	                         acknowledge.
//	DODO_BUSINESS_ID         Expected Dodo business_id; empty disables the
//	                         cross-business check.
//	DODO_PRODUCT_PLANS       Dodo product ID to approved plan mapping,
//	                         "prod_abc:team,prod_def:growth". Malformed means
//	                         the server refuses to start.
//	DATABASE_URL             Postgres connection string. Unset means billing
//	                         records live in memory and forget on restart
//	                         (reported on /health/ready, never hidden). Set
//	                         means the durable store; an unreachable database
//	                         is a startup refusal.
//	RENDER_GIT_COMMIT        Build SHA reported by /version when present.
//	GHOSTLIGHT_BUILD_SHA     Fallback build SHA for non-Render environments.
//
// Usage:
//
//	./app [-migrate]
//
// -migrate applies pending schema migrations and exits. It is the deploy
// pre-step, run explicitly — never as part of startup, because a server
// that migrates itself on boot can wedge a fleet on a bad migration with
// no human in the loop.
//
// Open (unauthenticated) routes, per shared/CONTRACTS.md §3:
//
//	GET /health/live     Process liveness. Probes nothing else.
//	GET /health/ready    Ability to accept work, with dependency states.
//	GET /health/startup  Configuration finished loading.
//	GET /version         Build SHA and service identity.
//
// Every other route goes to the platform API, which authenticates every
// request: no token means 401, full stop.
package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sanskarpan/Ghostlight/api"
	"github.com/sanskarpan/Ghostlight/internal/billing"
	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/dodo"
	"github.com/sanskarpan/Ghostlight/internal/identity"
	"github.com/sanskarpan/Ghostlight/internal/passport"
	"github.com/sanskarpan/Ghostlight/internal/postgres"
	"github.com/sanskarpan/Ghostlight/internal/reviewer"
	"github.com/sanskarpan/Ghostlight/internal/webui"
	"github.com/sanskarpan/Ghostlight/migrations"

	_ "github.com/lib/pq"
)

// defaultPort is the local-development port. Render always injects PORT.
const defaultPort = "8080"

// serviceName identifies the service in health and version responses.
const serviceName = "ghostlight-api"

// parseTokens parses the GHOSTLIGHT_API_TOKENS credential set.
//
// The format is strict on purpose: a credential string the server reads
// loosely is a credential string an operator miswrites quietly. Entries are
// separated by ";" and each is "id:token|grants|perms" with comma-separated
// grant and permission lists. An empty spec is an error — the server must
// not start with no credentials configured.
func parseTokens(spec string) (map[string]contract.Principal, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, fmt.Errorf("no credentials configured: set GHOSTLIGHT_API_TOKENS")
	}
	tokens := make(map[string]contract.Principal)
	ids := make(map[string]bool)
	for _, entry := range strings.Split(spec, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, fmt.Errorf("malformed credential set: empty entry")
		}
		fields := strings.Split(entry, "|")
		if len(fields) != 3 {
			return nil, fmt.Errorf("malformed credential entry %q: want id:token|grants|perms", entry)
		}
		head := strings.SplitN(fields[0], ":", 2)
		if len(head) != 2 {
			return nil, fmt.Errorf("malformed credential entry %q: want principal-id:token before the first pipe", entry)
		}
		id := strings.TrimSpace(head[0])
		token := head[1]
		if id == "" || strings.ContainsAny(id, " \t\n;:|") {
			return nil, fmt.Errorf("malformed credential entry %q: principal id must be non-empty and free of whitespace, ':', ';' and '|'", entry)
		}
		if token == "" || strings.ContainsAny(token, " \t\n;|,:") {
			return nil, fmt.Errorf("malformed credential entry for %q: token must be non-empty and free of whitespace, ':', ';', '|' and ','", id)
		}
		if ids[id] {
			return nil, fmt.Errorf("duplicate principal id %q", id)
		}
		if _, ok := tokens[token]; ok {
			return nil, fmt.Errorf("duplicate token for principal %q", id)
		}
		ids[id] = true
		tokens[token] = contract.Principal{
			ID:          id,
			Grants:      splitList(fields[1]),
			Permissions: splitList(fields[2]),
		}
	}
	return tokens, nil
}

// splitList splits a comma-separated list, dropping empties. An empty field
// means no grants or no permissions — which the authorizer reads as denial,
// never as wildcard.
func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// writeJSON writes a JSON response. Health and version responses are
// fixed-shape and carry no secrets.
func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// newMux routes the open contract endpoints and hands everything else to the
// platform API. The health endpoints deliberately bypass authentication:
// Render's health checker carries no credentials, and a health endpoint that
// needs them is a health endpoint that never answers. billingStore names the
// billing record backend ("postgres" or "memory") so an operator can see
// whether restarts forget — it names the backend, never a credential.
func newMux(build string, backend *api.Server, billingStore string, root http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/live", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "method-not-allowed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "live", "service": serviceName})
	})
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "method-not-allowed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ready",
			"backing": map[string]any{
				"environments":  "empty-memory-store",
				"operations":    len(backend.Operations.Operations),
				"billing_store": billingStore,
			},
		})
	})
	mux.HandleFunc("/health/startup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "method-not-allowed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "started", "service": serviceName})
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "method-not-allowed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"service": serviceName, "build": build})
	})
	if root == nil {
		root = backend
	}
	mux.Handle("/", root)
	return mux
}

// dodoReceiver builds the Dodo webhook receiver from the environment.
// DODO_PRODUCT_PLANS maps Dodo product IDs to approved plan IDs as
// "prod_abc:team,prod_def:growth"; malformed means the server refuses to
// start, because a mapping nobody can read strictly cannot be audited.
// A missing DODO_WEBHOOK_SECRET is not a startup refusal — the route stays
// mounted and refuses every delivery with 500, so billing misconfiguration
// can never take down the API. DODO_BUSINESS_ID empty disables the
// cross-business check.
func dodoReceiver(getenv func(string) string, store billing.RecordStore) (*dodo.Receiver, error) {
	plans, err := dodo.ParseProductPlans(getenv("DODO_PRODUCT_PLANS"))
	if err != nil {
		return nil, err
	}
	return dodo.NewReceiver(
		getenv("DODO_WEBHOOK_SECRET"),
		strings.TrimSpace(getenv("DODO_BUSINESS_ID")),
		plans,
		store,
	)
}

// buildMux wires the open contract endpoints, the authenticated platform
// API, and the Dodo webhook receiver into one handler.
func buildMux(getenv func(string) string, backend *api.Server, store billing.RecordStore, storeName string) (*http.ServeMux, error) {
	rc, err := dodoReceiver(getenv, store)
	if err != nil {
		return nil, err
	}
	root, _, err := htmlRoot(getenv, backend)
	if err != nil {
		return nil, err
	}
	mux := newMux(buildSHA(getenv), backend, storeName, root)
	mux.Handle("/hooks/dodo", rc)
	if strings.TrimSpace(getenv("DODO_WEBHOOK_SECRET")) == "" {
		log.Printf("dodo webhook receiver mounted but unconfigured (DODO_WEBHOOK_SECRET unset): deliveries will be refused")
	} else {
		log.Printf("dodo webhook receiver mounted at /hooks/dodo")
	}
	return mux, nil
}

// htmlRoot builds the browser-console root: everything that is not the JSON API
// requires a session, and an unauthenticated browser is redirected to sign in.
// It returns nil when the console is disabled, which is the current default, so
// the API-only deployment is unchanged.
func htmlRoot(getenv func(string) string, backend *api.Server) (http.Handler, *identity.Manager, error) {
	raw := strings.TrimSpace(getenv("GHOSTLIGHT_WEBUI_KEY"))
	if raw == "" {
		return nil, nil, nil
	}
	key, err := hex.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, nil, errors.New("GHOSTLIGHT_WEBUI_KEY must be 64 hex characters (32 bytes)")
	}
	manager, err := identity.NewManager(time.Now)
	if err != nil {
		return nil, nil, err
	}
	transport, err := webui.NewTransport(manager, key, time.Now)
	if err != nil {
		return nil, nil, err
	}
	root, err := consoleRoot(backend, transport)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("browser console mounted at / (sessions are in-memory and end on restart)")
	return root, manager, nil
}

// consoleRoot builds the browser surface over a transport. /v1 stays the JSON
// API with its bearer authentication; everything else is the browser surface,
// which currently has two pages: the sign-in placeholder and the signed-in
// placeholder that FE-3 replaces with real screens.
//
// /login is served, not redirected: Require sends unauthenticated browsers
// there, so a redirect from /login to /login would be an infinite loop and a
// 404 would strand every signed-out visitor. The page says plainly that the
// flow arrives with FE-2 - a missing feature and a broken loop are different
// facts.
func consoleRoot(backend *api.Server, transport *webui.Transport) (http.Handler, error) {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/v1" {
			backend.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/login" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(loginPlaceholderHTML))
			return
		}
		transport.Require(SessionPage()).ServeHTTP(w, r)
	}), nil
}

const loginPlaceholderHTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Sign-in - Ghostlight</title></head>
<body>
<a class="skip" href="#main">Skip to main content</a>
<main id="main" tabindex="-1">
<h1>Sign-in is not wired yet</h1>
<p>The console's session transport exists; the identity-provider flow lands with
the next change. Until then there is nothing to sign in with.</p>
</main>
</body>
</html>
`

// SessionPage is the authenticated placeholder until FE-3 serves real pages.
// It is a constant document with no untrusted input, and it must still pass the
// accessibility gate, because it is served HTML like any other.
func SessionPage() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(placeholderHTML))
	})
}

const placeholderHTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Ghostlight console</title></head>
<body>
<a class="skip" href="#main">Skip to main content</a>
<main id="main">
<h1>Signed in</h1>
<p>The console is not built yet. This page exists so the session, the route
protection and the CSRF handling have something real to protect.</p>
</main>
</body>
</html>
`

// buildSHA reports the build this binary came from: Render's injected commit
// first, an explicit override second, and an honest "unknown" otherwise.
func buildSHA(getenv func(string) string) string {
	if sha := strings.TrimSpace(getenv("RENDER_GIT_COMMIT")); sha != "" {
		return sha
	}
	if sha := strings.TrimSpace(getenv("GHOSTLIGHT_BUILD_SHA")); sha != "" {
		return sha
	}
	return "unknown"
}

// openBillingStore returns the billing record store. DATABASE_URL selects
// the durable Postgres store; unset means the in-memory store, which forgets
// everything on restart. The choice is logged and reported on /health/ready
// so an operator can see which one is in force — silently running the wrong
// one would be worse than either. An unreachable database is a startup
// refusal: running billing on memory while configured for Postgres would
// silently discard durability nobody chose to give up.
func openBillingStore(getenv func(string) string) (billing.RecordStore, string, error) {
	dsn := strings.TrimSpace(getenv("DATABASE_URL"))
	if dsn == "" {
		log.Printf("DATABASE_URL unset: billing records live in memory and forget on restart")
		return dodo.NewMemoryStore(), "memory", nil
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, "", fmt.Errorf("open database: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, "", fmt.Errorf("unreachable database: %w", err)
	}
	store, err := postgres.NewBillingStore(db)
	if err != nil {
		_ = db.Close()
		return nil, "", err
	}
	log.Printf("billing records are durable in Postgres")
	return store, "postgres", nil
}

// migrate applies pending schema migrations and exits. It is the deploy
// pre-step (render.yaml preDeployCommand), run explicitly — never as part
// of startup, because shared/CONTRACTS.md forbids automatic schema
// mutation: a server that migrates itself on boot can wedge a fleet on a
// bad migration with no human in the loop.
func migrate(getenv func(string) string) int {
	dsn := strings.TrimSpace(getenv("DATABASE_URL"))
	if dsn == "" {
		log.Printf("refusing to migrate: DATABASE_URL is not set and there is no database to migrate")
		return 1
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Printf("refusing to migrate: %v", err)
		return 1
	}
	defer func() { _ = db.Close() }()
	applied, err := migrations.ApplyPending(db)
	if err != nil {
		log.Printf("refusing to migrate: %v", err)
		return 1
	}
	if len(applied) == 0 {
		log.Printf("schema is current: nothing to apply")
		return 0
	}
	log.Printf("applied %d migration(s): %s", len(applied), strings.Join(applied, ", "))
	return 0
}

// migrateFlag makes ./app -migrate apply pending schema migrations and exit.
// It is the deploy pre-step (render.yaml preDeployCommand), run explicitly —
// never as part of startup.
var migrateFlag = flag.Bool("migrate", false, "apply pending schema migrations and exit")

// run wires the server and serves until the process is stopped. It returns a
// process exit code: 0 serves (or rather, served until killed), 1 is a
// configuration refusal — a server that cannot be configured safely does not
// start unsafely.
func run(getenv func(string) string) int {
	if strings.TrimSpace(getenv("MIGRATE")) == "1" || *migrateFlag {
		return migrate(getenv)
	}
	port := strings.TrimSpace(getenv("PORT"))
	if port == "" {
		port = defaultPort
		log.Printf("PORT unset, listening on %s (local default; Render injects PORT)", port)
	}
	tokens, err := parseTokens(getenv("GHOSTLIGHT_API_TOKENS"))
	if err != nil {
		log.Printf("refusing to start: %v", err)
		return 1
	}
	log.Printf("loaded credentials for %d principal(s)", len(tokens))

	store, storeName, err := openBillingStore(getenv)
	if err != nil {
		log.Printf("refusing to start: %v", err)
		return 1
	}

	ops := contract.Registry{}
	backend := &api.Server{
		Auth:         api.StaticAuthenticator{Tokens: tokens},
		Operations:   ops,
		Authorizer:   &contract.Authorizer{Registry: ops},
		Environments: api.MemoryEnvironments{},
		Room:         &reviewer.Room{},
		Passports:    &passport.Registry{},
	}
	mux, err := buildMux(getenv, backend, store, storeName)
	if err != nil {
		log.Printf("refusing to start: %v", err)
		return 1
	}
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("serving %s on :%s", serviceName, port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("server stopped: %v", err)
		return 1
	}
	return 0
}

func main() {
	flag.Parse()
	os.Exit(run(os.Getenv))
}
