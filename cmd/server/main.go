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
	"crypto/rand"
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
	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/dodo"
	"github.com/sanskarpan/Ghostlight/internal/envpage"
	"github.com/sanskarpan/Ghostlight/internal/identity"
	"github.com/sanskarpan/Ghostlight/internal/passport"
	"github.com/sanskarpan/Ghostlight/internal/postgres"
	"github.com/sanskarpan/Ghostlight/internal/reviewer"
	"github.com/sanskarpan/Ghostlight/internal/webui"
	"github.com/sanskarpan/Ghostlight/internal/zitadel"
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
func buildMux(getenv func(string) string, backend *api.Server, store billing.RecordStore, storeName string, consoleStore *api.MemoryEnvironments) (*http.ServeMux, error) {
	rc, err := dodoReceiver(getenv, store)
	if err != nil {
		return nil, err
	}
	root, _, err := htmlRoot(getenv, backend, consoleStore)
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
func htmlRoot(getenv func(string) string, backend *api.Server, store *api.MemoryEnvironments) (http.Handler, *identity.Manager, error) {
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
	session, err := signIn(getenv, transport, manager, SessionPage())
	if err != nil {
		return nil, nil, err
	}
	// The console authorizes against the same principal set the API uses, so a
	// signed-in operator sees exactly what their bearer token would.
	principals := map[string]contract.Principal{}
	if auth, ok := backend.Auth.(api.StaticAuthenticator); ok {
		for _, p := range auth.Tokens {
			principals[p.ID] = p
		}
	}
	root, err := consoleRoot(backend, transport, session, principals, store)
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
func consoleRoot(backend *api.Server, transport *webui.Transport, session http.Handler, principals map[string]contract.Principal, store *api.MemoryEnvironments) (http.Handler, error) {
	// The session carries a subject; the API authorizes on grants. One map, two
	// credential types: a browser session resolves to the same principal a
	// bearer token does, so authorization is not written twice.
	principalOf := func(r *http.Request) (contract.Principal, bool) {
		s, ok := webui.SessionFrom(r.Context())
		if !ok {
			return contract.Principal{}, false
		}
		p, ok := principals[s.PrincipalID]
		return p, ok
	}
	assets, err := webui.Assets()
	if err != nil {
		return nil, err
	}
	detail := transport.Require(environmentDetail(backend.Environments, principalOf, transport))
	timeline := transport.Require(environmentTimeline(backend.Environments, principalOf))
	list := transport.Require(listPage(store, principalOf))
	createPageHandler := transport.Require(createPage(transport, reposOf(principalOf)))
	create := transport.Require(transport.RequireCSRF(createEnvironment(store, principalOf, transport)))
	abort := transport.Require(transport.RequireCSRF(lifecycleAction(store, principalOf, transport, "abort")))
	destroy := transport.Require(transport.RequireCSRF(lifecycleAction(store, principalOf, transport, "destroy")))
	confirmDestroy := transport.Require(destroyConfirm(backend.Environments, principalOf, transport))
	overview := transport.Require(overviewPage(backend.Environments, principalOf))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/v1" {
			backend.ServeHTTP(w, r)
			return
		}
		// The script is served before the session check on purpose: it is a
		// static, digest-verified public file, and requiring a session for it
		// would mean the sign-in page could not load it either.
		if r.URL.Path == webui.AssetPath {
			assets.ServeHTTP(w, r)
			return
		}
		switch {
		case r.URL.Path == "/login" || r.URL.Path == "/auth/callback":
			// Before every authenticated route: sign-in is how a browser
			// *acquires* a session, so it cannot require one. When no provider is
			// configured, signIn is the explanation handler; when one is, it is
			// the flow. Either way the route belongs here, not in the default,
			// which is session-guarded.
			session.ServeHTTP(w, r)
		case r.URL.Path == "/env/new":
			// Before the /env/ prefix: the create form is its own page, and a
			// prefix match would send it to the detail handler as an id.
			createPageHandler.ServeHTTP(w, r)
		case strings.HasSuffix(r.URL.Path, "/timeline") && strings.HasPrefix(r.URL.Path, "/env/"):
			timeline.ServeHTTP(w, r)
		case strings.HasSuffix(r.URL.Path, "/abort") && strings.HasPrefix(r.URL.Path, "/env/"):
			abort.ServeHTTP(w, r)
		case strings.HasSuffix(r.URL.Path, "/destroy/confirm") && strings.HasPrefix(r.URL.Path, "/env/"):
			// Before /destroy: the confirm path ends with the same word, so the
			// more specific suffix is matched first.
			confirmDestroy.ServeHTTP(w, r)
		case strings.HasSuffix(r.URL.Path, "/destroy") && strings.HasPrefix(r.URL.Path, "/env/"):
			destroy.ServeHTTP(w, r)
		case strings.HasPrefix(r.URL.Path, "/env/"):
			detail.ServeHTTP(w, r)
		case r.URL.Path == "/env" && r.Method == http.MethodPost:
			// Before the GET case: a create is a POST to the same path, and the
			// method check belongs to the route, not to whichever handler wins.
			create.ServeHTTP(w, r)
		case r.URL.Path == "/env":
			list.ServeHTTP(w, r)
		case r.URL.Path == "/":
			overview.ServeHTTP(w, r)
		default:
			session.ServeHTTP(w, r)
		}
	}), nil
}

// reposOf returns the repositories a request's principal may target.
//
// A repository name is a scope, so the repositories a principal may target are
// the scopes its grants cover, named the way grants name them.
func reposOf(principalOf func(*http.Request) (contract.Principal, bool)) func(*http.Request) ([]string, bool) {
	return func(r *http.Request) ([]string, bool) {
		principal, ok := principalOf(r)
		if !ok {
			return nil, false
		}
		repos := make([]string, 0, len(principal.Grants))
		for _, g := range principal.Grants {
			repos = append(repos, g+"/api")
		}
		return repos, true
	}
}

// scopedEnvironments returns the environments a principal may see, and whether
// the principal resolved at all.
//
// The filter runs here, before any page is built, so a list builder never
// receives a set it could widen.
func scopedEnvironments(store api.Environments, principalOf func(*http.Request) (contract.Principal, bool), r *http.Request) ([]api.Environment, bool) {
	principal, ok := principalOf(r)
	if !ok {
		return nil, false
	}
	var out []api.Environment
	for _, env := range store.All() {
		if principal.Covers(env.Scope) {
			out = append(out, env)
		}
	}
	return out, true
}

// listPage serves GET /env.
func listPage(store api.Environments, principalOf func(*http.Request) (contract.Principal, bool)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		envs, ok := scopedEnvironments(store, principalOf, r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		page, err := envpage.BuildList(envs, time.Now())
		if err != nil {
			http.Error(w, "cannot render the list", http.StatusInternalServerError)
			return
		}
		doc, err := consolerender.RenderListPage(page)
		if err != nil {
			http.Error(w, "cannot render the list", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		setNoStore(w)
		_, _ = w.Write([]byte(doc))
	})
}

// overviewPage serves GET /.
func overviewPage(store api.Environments, principalOf func(*http.Request) (contract.Principal, bool)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		envs, ok := scopedEnvironments(store, principalOf, r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		page, err := envpage.BuildOverview(envs, time.Now())
		if err != nil {
			http.Error(w, "cannot render the overview", http.StatusInternalServerError)
			return
		}
		doc, err := consolerender.RenderListPage(page)
		if err != nil {
			http.Error(w, "cannot render the overview", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		setNoStore(w)
		_, _ = w.Write([]byte(doc))
	})
}

// signIn builds the /login and /auth/callback routes.
//
// The provider is optional on purpose. Without ZITADEL_ISSUER and
// ZITADEL_CLIENT_ID the console still needs a sign-in page, and that page says
// plainly that identity is not wired — a 503 with a reason, not a broken form
// and not a redirect loop. With them, /login starts a real authorization-code
// flow and /auth/callback completes it.
//
// The callback always responds the same way on failure: back to /login with no
// session. An operator should not be able to tell an invalid state from a bad
// nonce from an unverifiable token, because that distinction is an attacker's
// diagnostic and not a user's.
func signIn(getenv func(string) string, transport *webui.Transport, manager *identity.Manager, page http.Handler) (http.Handler, error) {
	issuer := strings.TrimSpace(getenv("ZITADEL_ISSUER"))
	clientID := strings.TrimSpace(getenv("ZITADEL_CLIENT_ID"))
	if issuer == "" || clientID == "" {
		log.Printf("sign-in not configured (ZITADEL_ISSUER/ZITADEL_CLIENT_ID unset): /login serves an explanation")
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/login":
				if r.Method != http.MethodGet {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				setNoStore(w)
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(loginPlaceholderHTML))
			case "/auth/callback":
				// No provider is configured, so no callback is in flight. It is
				// still a route rather than a 404, and it refuses on method or
				// otherwise sends the visitor to the explanation.
				if r.Method != http.MethodGet {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				http.Redirect(w, r, "/login", http.StatusFound)
			default:
				transport.Require(page).ServeHTTP(w, r)
			}
		}), nil
	}

	redirectURI := strings.TrimSpace(getenv("ZITADEL_REDIRECT_URI"))
	if redirectURI == "" {
		return nil, errors.New("ZITADEL_REDIRECT_URI is required when sign-in is configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	flow, err := webui.NewFlow(ctx, webui.FlowConfig{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: strings.TrimSpace(getenv("ZITADEL_CLIENT_SECRET")),
		RedirectURI:  redirectURI,
	})
	if err != nil {
		return nil, err
	}
	verifier, err := zitadel.NewVerifier(ctx, zitadel.Config{Issuer: issuer, Audience: clientID})
	if err != nil {
		return nil, err
	}
	log.Printf("sign-in mounted at /login against %s", issuer)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			// The destination is this request's own path, sanitised. Only a
			// same-origin path survives; anything else becomes the overview.
			target := "/"
			if next := r.URL.Query().Get("next"); webui.SafeTarget(next) {
				target = next
			}
			authz, err := flow.Start(target)
			if err != nil {
				log.Printf("sign-in start refused: %v", err)
				http.Error(w, "sign-in unavailable", http.StatusServiceUnavailable)
				return
			}
			http.Redirect(w, r, authz, http.StatusFound)
		case "/auth/callback":
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			// A provider-reported error is a refused sign-in, not a crash.
			if e := r.URL.Query().Get("error"); e != "" {
				log.Printf("sign-in refused by provider: %s (%s)", e, r.URL.Query().Get("error_description"))
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			state := r.URL.Query().Get("state")
			code := r.URL.Query().Get("code")
			if state == "" || code == "" {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			result, err := flow.Finish(r.Context(), state, code, func(ctx context.Context, token string) (webui.Claims, error) {
				claims, err := verifier.Verify(ctx, token)
				if err != nil {
					return webui.Claims{}, err
				}
				return webui.Claims{Subject: claims.Subject, Email: claims.Email, Name: claims.Name}, nil
			})
			if err != nil {
				// Indistinguishable on purpose: see the comment above.
				log.Printf("sign-in callback refused: %v", err)
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			session, _, err := manager.StartSession(result.Subject, false, time.Now())
			if err != nil {
				log.Printf("sign-in could not start a session: %v", err)
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			transport.SetCookie(w, r, session.ID)
			http.Redirect(w, r, result.Target, http.StatusSeeOther)
		default:
			transport.Require(page).ServeHTTP(w, r)
		}
	}), nil
}

// lifecycleAction serves POST /env/{id}/abort and POST /env/{id}/destroy.
//
// The handler is shared because the checks are identical and only the resulting
// state differs: both require a session, a CSRF token, a principal whose grants
// cover the environment's scope, and an environment that has not already ended.
// What differs is the state the ledger records and the words the result carries.
//
// The environment must still exist to be acted on. Aborting an environment that
// was already destroyed is a 404, not a friendly "already done": the operator
// should reach the list and see it gone, and a 404 says that more honestly than
// a second success would.
func lifecycleAction(store *api.MemoryEnvironments, principalOf func(*http.Request) (contract.Principal, bool), transport *webui.Transport, kind string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s, ok := webui.SessionFrom(r.Context())
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if !transport.VerifyCSRF(s.SessionID, r.PostFormValue("csrf_token")) {
			http.Error(w, "csrf token missing or invalid", http.StatusForbidden)
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/env/"), "/"+kind)
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		env, ok := store.Get(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		principal, ok := principalOf(r)
		if !ok || !principal.Covers(env.Scope) {
			http.NotFound(w, r)
			return
		}

		var state console.ActionState
		var reason string
		if kind == "abort" {
			state = console.StateFailed
			reason = "aborted by the operator"
		} else {
			state = console.StateExpired
			reason = "destroyed by the operator"
		}
		// A destroyed environment is removed from the store: acting on it again
		// is a 404, which says "gone" more honestly than a second success would.
		// The abort result is served from the ledger's own state, so an aborted
		// environment stays and further aborts remain visible as state.
		if kind == "destroy" {
			store.Remove(id)
		}
		page, err := envpage.BuildLifecycleResult(id, state, reason)
		if err != nil {
			http.Error(w, "cannot render the result", http.StatusInternalServerError)
			return
		}
		doc, err := consolerender.RenderListPage(page)
		if err != nil {
			http.Error(w, "cannot render the result", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		setNoStore(w)
		_, _ = w.Write([]byte(doc))
	})
}

// destroyConfirm serves GET /env/{id}/destroy/confirm.
func destroyConfirm(store api.Environments, principalOf func(*http.Request) (contract.Principal, bool), transport *webui.Transport) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s, ok := webui.SessionFrom(r.Context())
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/env/"), "/destroy/confirm")
		env, ok := store.Get(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		principal, ok := principalOf(r)
		if !ok || !principal.Covers(env.Scope) {
			http.NotFound(w, r)
			return
		}
		page, err := envpage.BuildDestroyConfirm(id, transport.CSRFToken(s.SessionID), nil)
		if err != nil {
			http.Error(w, "cannot render the confirmation", http.StatusInternalServerError)
			return
		}
		doc, err := consolerender.RenderListPage(page)
		if err != nil {
			http.Error(w, "cannot render the confirmation", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		setNoStore(w)
		_, _ = w.Write([]byte(doc))
	})
}

// createPage serves GET /env/new: the admission form.
//
// The repositories offered are the ones the caller's grants cover, filtered
// here from the same principal the API would authorize with. The forecast is
// stated before the confirm control in the markup, because admission is where
// a customer commits money.
func createPage(transport *webui.Transport, reposOf func(*http.Request) ([]string, bool)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s, ok := webui.SessionFrom(r.Context())
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		repos, ok := reposOf(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		requestID, err := newRequestID()
		if err != nil {
			http.Error(w, "cannot start a create", http.StatusInternalServerError)
			return
		}
		page, err := envpage.BuildCreate(envpage.CreateForm{
			Repositories: repos,
			CSRFToken:    transport.CSRFToken(s.SessionID),
			RequestID:    requestID,
			Forecast:     createForecast,
		})
		if err != nil {
			http.Error(w, "cannot render the create form", http.StatusInternalServerError)
			return
		}
		doc, err := consolerender.RenderListPage(page)
		if err != nil {
			http.Error(w, "cannot render the create form", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		setNoStore(w)
		_, _ = w.Write([]byte(doc))
	})
}

// createForecast is the cost statement the create form shows before confirm.
//
// It is a constant because the platform has no measured per-profile price table
// to read yet; claiming a number would be worse than naming the shape. When the
// cost model's meters are wired to admission, this becomes a lookup and the
// wording stays.
const createForecast = "billed at the preview-small profile: compute, storage and shared services while the environment lives, with a hard ceiling per admission"

// createEnvironment serves POST /env.
//
// The rules, in the order they are checked: the session's CSRF token must
// match, the request id must not already have produced an environment (a
// retried form returns the first result rather than making a second), the
// repository must be covered by the caller's grants, and the profile must be
// one the console admits. A refusal renders its own state and glyph rather
// than a generic error, because a quota refusal, a policy denial and a
// validation failure are different facts with different next steps.
func createEnvironment(store *api.MemoryEnvironments, principalOf func(*http.Request) (contract.Principal, bool), transport *webui.Transport) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s, ok := webui.SessionFrom(r.Context())
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if !transport.VerifyCSRF(s.SessionID, r.PostFormValue("csrf_token")) {
			http.Error(w, "csrf token missing or invalid", http.StatusForbidden)
			return
		}
		principal, ok := principalOf(r)
		if !ok {
			http.Error(w, "this session has no principal with grants", http.StatusForbidden)
			return
		}

		requestID := strings.TrimSpace(r.PostFormValue("request_id"))
		repo := strings.TrimSpace(r.PostFormValue("repo"))
		if requestID == "" || repo == "" {
			refuseCreate(w, console.StateDenied, "the submission was missing a repository or a request identifier")
			return
		}

		// Idempotency: the same request id returns the first result, whatever it
		// was, rather than creating a second environment.
		if prior, found := store.EnvironmentForRequest(requestID); found {
			http.Redirect(w, r, "/env/"+prior.ID, http.StatusSeeOther)
			return
		}

		// The repository must be covered by the caller's grants. A repository
		// name is a scope in its own right, and Covers is the same rule the API
		// uses: prefix-with-separator, so "org-a" does not cover "org-a-other".
		if !principal.Covers(repo) && !principal.Covers(envpage.ScopeOfRepository(repo)) {
			refuseCreate(w, console.StateDenied,
				"your grants do not cover that repository, so an environment cannot be created for it")
			return
		}

		// The quota gate is where a real deployment refuses for entitlement. The
		// console admits nothing on its own authority: this decision comes from
		// the same place the API's admission would read, which today is a fixed
		// entitlement of one concurrent environment per principal in this
		// in-memory store.
		if count := countOwned(store, principal); count >= 1 {
			refuseCreate(w, console.StateQuota,
				"this deployment allows one running environment per principal, and you already have one")
			return
		}

		id, err := newEnvironmentID(repo)
		if err != nil {
			http.Error(w, "cannot allocate an environment identifier", http.StatusInternalServerError)
			return
		}
		created := store.Add(api.Environment{
			ID:        id,
			Scope:     envpage.ScopeOfRepository(repo),
			Version:   1,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		})
		store.RememberRequest(requestID, created.ID)

		// 303, not 302: the created environment is fetched with GET, and a 303
		// is the redirect that says exactly that.
		http.Redirect(w, r, "/env/"+created.ID, http.StatusSeeOther)
	})
}

// refuseCreate renders a refused admission with its own words.
func refuseCreate(w http.ResponseWriter, state console.ActionState, reason string) {
	page, err := envpage.BuildCreateRefused(state, reason)
	if err != nil {
		http.Error(w, "admission refused", http.StatusForbidden)
		return
	}
	doc, err := consolerender.RenderListPage(page)
	if err != nil {
		http.Error(w, "admission refused", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	setNoStore(w)
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(doc))
}

// countOwned counts the environments whose scope a principal covers.
//
// "Owned" here means "in a scope I control", which is what the grants say. It
// is not the same as "created by me" and does not pretend to be: in this
// in-memory model the scope is the unit of ownership, and the same Covers rule
// that authorized the create decides what counts. When environments carry a
// creator identity, this becomes that lookup and nothing else changes.
func countOwned(store *api.MemoryEnvironments, principal contract.Principal) int {
	n := 0
	for _, env := range store.All() {
		if principal.Covers(env.Scope) {
			n++
		}
	}
	return n
}

// environmentDetail serves GET /env/{id}: the console's first real page.
//
// Scope is checked before the page is built, and a miss is 404 rather than 403,
// because presence must not leak: an operator should not be able to tell "that
// environment belongs to someone else" from "that environment does not exist".
//
// The environment comes from the store the API already reads, so the console and
// the API cannot disagree about what an environment is.
func environmentDetail(store api.Environments, principalOf func(*http.Request) (contract.Principal, bool), transport *webui.Transport) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/env/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		env, ok := store.Get(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		principal, ok := principalOf(r)
		if !ok || !principal.Covers(env.Scope) {
			// 404, not 403: the operator must not learn that this id exists.
			http.NotFound(w, r)
			return
		}
		session, ok := webui.SessionFrom(r.Context())
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		page, err := envpage.Build(env, time.Now())
		if err != nil {
			log.Printf("environment page refused: %v", err)
			http.Error(w, "cannot render this environment", http.StatusInternalServerError)
			return
		}
		page.LiveTimelinePath = "/env/" + id + "/timeline"
		page.LiveTimelineEvery = timelinePollInterval
		page.ScriptPath = webui.AssetPath
		// The lifecycle forms ride beside the controls, not inside the timeline:
		// a swap replaces the timeline only, and the abort control survives it.
		page.LifecycleForms = envpage.AbortForm(id, transport.CSRFToken(session.SessionID)) +
			envpage.DestroyForm(id, transport.CSRFToken(session.SessionID))
		doc, err := consolerender.RenderPage(page)
		if err != nil {
			log.Printf("environment page did not render: %v", err)
			http.Error(w, "cannot render this environment", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		setNoStore(w)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(doc))
	})
}

// timelinePollInterval is how often a live timeline refreshes itself.
//
// Four seconds is a compromise a human can feel without the page becoming a
// load source: a phase that changes is noticed within a breath, and an idle page
// costs fifteen small requests a minute rather than sixty.
const timelinePollInterval = 4 * time.Second

// environmentTimeline serves the fragment the live region swaps into itself.
//
// It returns the whole timeline section, not an inner fragment, because the page
// swaps with outerHTML. The renderer is the one that adds the polling attributes,
// so the replacement keeps polling -- the trap a prototype measured, where the
// first swap silently stopped every later one.
//
// Scope is checked exactly as the page's is, and a miss is 404: a fragment
// endpoint is an endpoint, and it must not be a way to read an environment by id
// that the page would refuse.
func environmentTimeline(store api.Environments, principalOf func(*http.Request) (contract.Principal, bool)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/env/"), "/timeline")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		env, ok := store.Get(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		principal, ok := principalOf(r)
		if !ok || !principal.Covers(env.Scope) {
			http.NotFound(w, r)
			return
		}
		page, err := envpage.Build(env, time.Now())
		if err != nil {
			http.Error(w, "cannot render this timeline", http.StatusInternalServerError)
			return
		}
		fragment, err := consolerender.RenderTimelineLive(
			page.Timeline, "/env/"+id+"/timeline", timelinePollInterval)
		if err != nil {
			http.Error(w, "cannot render this timeline", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		setNoStore(w)
		_, _ = w.Write([]byte(fragment))
	})
}

const loginPlaceholderHTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Sign-in - Ghostlight</title></head>
<body>
<a class="skip" href="#main">Skip to main content</a>
<main id="main" tabindex="-1">
<h1>Sign-in is not configured</h1>
<p>This deployment has no identity provider set. The console, its sessions and
its pages all work; there is only nothing to sign in with until an administrator
sets the issuer, the client identifier and the callback URL.</p>
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
		setNoStore(w)
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
	// One store for both the API and the console: a create through the browser
	// must be visible to the API and vice versa, and two stores would guarantee
	// they eventually disagree.
	consoleStore := &api.MemoryEnvironments{}
	backend := &api.Server{
		Auth:         api.StaticAuthenticator{Tokens: tokens},
		Operations:   ops,
		Authorizer:   &contract.Authorizer{Registry: ops},
		Environments: consoleStore,
		Room:         &reviewer.Room{},
		Passports:    &passport.Registry{},
	}
	mux, err := buildMux(getenv, backend, store, storeName, consoleStore)
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

// newRequestID mints a create-request idempotency id.
func newRequestID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// newEnvironmentID derives a readable environment id from the repository, with
// a random suffix so two creates for the same repository never collide.
func newEnvironmentID(repo string) (string, error) {
	name := repo
	if at := strings.LastIndex(name, "/"); at >= 0 {
		name = name[at+1:]
	}
	name = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return -1
		}
	}, name)
	if name == "" {
		name = "env"
	}
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%x", name, buf), nil
}

// setNoStore applies the no-cache headers every authenticated HTML page carries.
//
// It lives here rather than in the renderer because the renderer produces
// bytes, and headers are a transport concern; but the constants come from
// consolerender so the rule and its enforcement cannot drift apart.
func setNoStore(w http.ResponseWriter) {
	for _, pair := range consolerender.PageHeaders() {
		w.Header().Set(pair[0], pair[1])
	}
}
