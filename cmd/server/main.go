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
//	RENDER_GIT_COMMIT        Build SHA reported by /version when present.
//	GHOSTLIGHT_BUILD_SHA     Fallback build SHA for non-Render environments.
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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sanskarpan/Ghostlight/api"
	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/passport"
	"github.com/sanskarpan/Ghostlight/internal/reviewer"
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
// needs them is a health endpoint that never answers.
func newMux(build string, backend *api.Server) *http.ServeMux {
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
				"environments": "empty-memory-store",
				"operations":   len(backend.Operations.Operations),
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
	mux.Handle("/", backend)
	return mux
}

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

// run wires the server and serves until the process is stopped. It returns a
// process exit code: 0 serves (or rather, served until killed), 1 is a
// configuration refusal — a server that cannot be configured safely does not
// start unsafely.
func run(getenv func(string) string) int {
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

	ops := contract.Registry{}
	backend := &api.Server{
		Auth:         api.StaticAuthenticator{Tokens: tokens},
		Operations:   ops,
		Authorizer:   &contract.Authorizer{Registry: ops},
		Environments: api.MemoryEnvironments{},
		Room:         &reviewer.Room{},
		Passports:    &passport.Registry{},
	}
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           newMux(buildSHA(getenv), backend),
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
	os.Exit(run(os.Getenv))
}
