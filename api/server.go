package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/attestations"
	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/exceptions"
	"github.com/sanskarpan/Ghostlight/internal/experiments"
	"github.com/sanskarpan/Ghostlight/internal/gates"
	"github.com/sanskarpan/Ghostlight/internal/intake"
	"github.com/sanskarpan/Ghostlight/internal/passport"
	"github.com/sanskarpan/Ghostlight/internal/resource"
	"github.com/sanskarpan/Ghostlight/internal/reviewer"
)

// Environment is the state of one preview environment, as the API exposes it.
type Environment struct {
	// ID identifies the environment.
	ID string
	// Scope is the scope the environment belongs to, and the scope a principal's
	// grant must cover.
	Scope string
	// Version is the environment's current version, used for preconditions.
	Version int
	// Generation is the environment's current generation.
	Generation int
	// ExpiresAt is when the environment's TTL ends.
	ExpiresAt time.Time
	// SourceSHA, RecipeDigest and ConfigurationDigest are the exact candidate
	// set the environment's current generation runs: a new generation names a
	// new exact set, and the digests are the identity, not a description.
	// Console-created environments carry zeros until a generation names them.
	SourceSHA           string
	RecipeDigest        string
	ConfigurationDigest string
	// Actions are the recorded actions the progress timeline is derived from.
	//
	// The timeline is not derivable from the lifecycle state, and the console
	// package already refuses to pretend otherwise. Reading the recorded
	// actions is what makes "ready" mean something.
	Actions []console.RecordedAction
}

// Environments is the environment store the API reads from.
type Environments interface {
	// Get returns an environment, and whether it exists.
	Get(id string) (Environment, bool)
	// All returns every environment in the store, unscoped.
	//
	// It is deliberately unscoped: a store cannot know a caller's grants, so
	// the caller filters before building anything. Returning an already-scoped
	// set would put the authorization rule in two places, and the second place
	// is always the one that drifts.
	All() []Environment
}

// Creator is the write half of an environment store.
//
// It is a separate capability because reading and creating are different
// authorities: a console page that only lists environments should not be able
// to create one merely because it can read. Handlers that create assert this
// interface; handlers that only read never need it.
type Creator interface {
	// Add stores a new environment and returns it as stored.
	Add(env Environment) Environment
	// EnvironmentForRequest returns the environment a request id already
	// created, and whether there is one. A retried submission must return the
	// first result rather than make a second environment, and the only way to
	// honour that is to remember which request made which environment.
	EnvironmentForRequest(requestID string) (Environment, bool)
}

// Add stores an environment and records the request that created it.
func (m *MemoryEnvironments) Add(env Environment) Environment {
	m.Environments = append(m.Environments, env)
	return env
}

// Remove deletes an environment from the store. A destroyed environment is
// gone, not flagged: acting on it again is a 404, which says "gone" more
// honestly than a second success would.
func (m *MemoryEnvironments) Remove(id string) {
	out := m.Environments[:0:0]
	for _, e := range m.Environments {
		if e.ID != id {
			out = append(out, e)
		}
	}
	m.Environments = out
}

// Update replaces a stored environment by id. An update of an environment
// the store does not hold is a no-op, because the caller resolved the
// environment from this store moments before and its absence now is a race
// the read-back should surface, not a second error path.
func (m *MemoryEnvironments) Update(env Environment) {
	for i, e := range m.Environments {
		if e.ID == env.ID {
			m.Environments[i] = env
			return
		}
	}
}

// RememberRequest records which environment a request id produced.
func (m *MemoryEnvironments) RememberRequest(requestID, envID string) {
	if m.RequestEnvironments == nil {
		m.RequestEnvironments = map[string]string{}
	}
	m.RequestEnvironments[requestID] = envID
}

// EnvironmentForRequest returns the environment a request id already created.
func (m *MemoryEnvironments) EnvironmentForRequest(requestID string) (Environment, bool) {
	id, ok := m.RequestEnvironments[requestID]
	if !ok {
		return Environment{}, false
	}
	return m.Get(id)
}

// RememberIdempotentRequest records the body digest an idempotency key was
// first presented with, alongside the environment it produced. Reuse of the
// key with a different body is a refused retry, not a second creation.
func (m *MemoryEnvironments) RememberIdempotentRequest(key, bodyDigest, envID string) {
	m.RememberIdempotentResult(key, bodyDigest, envID, "")
}

// RememberIdempotentResult records the encoded result a key produced, so a
// replay returns it rather than applying a second time.
func (m *MemoryEnvironments) RememberIdempotentResult(key, bodyDigest, envID, result string) {
	if m.IdempotentRequests == nil {
		m.IdempotentRequests = map[string]IdempotentRequestRecord{}
	}
	m.IdempotentRequests[key] = IdempotentRequestRecord{BodyDigest: bodyDigest, EnvironmentID: envID, Result: result}
}

// IdempotentRequest returns what an idempotency key first produced.
func (m *MemoryEnvironments) IdempotentRequest(key string) (IdempotentRequestRecord, bool) {
	rec, ok := m.IdempotentRequests[key]
	return rec, ok
}

// IdempotentRequestRecord is what the store remembers about one idempotency
// key: the exact body it first carried, the environment that body created or
// mutated, and the encoded result to replay.
type IdempotentRequestRecord struct {
	BodyDigest    string
	EnvironmentID string
	Result        string
}

// MemoryEnvironments is an in-memory environment store.
type MemoryEnvironments struct {
	// Environments are the stored environments.
	Environments []Environment
	// RequestEnvironments maps a create request's idempotency id to the
	// environment it produced, so a retried form returns the first result.
	RequestEnvironments map[string]string
	// IdempotentRequests maps an API idempotency key to the body digest it
	// first carried and the environment it produced.
	IdempotentRequests map[string]IdempotentRequestRecord
}

// All returns every stored environment.
func (m MemoryEnvironments) All() []Environment { return m.Environments }

// Get returns the environment with the given identifier.
func (m MemoryEnvironments) Get(id string) (Environment, bool) {
	for _, e := range m.Environments {
		if e.ID == id {
			return e, true
		}
	}
	return Environment{}, false
}

// Server serves the platform API.
//
// The dependencies are interfaces so the handlers can be tested without a database, a
// cluster or an identity provider, and so that a caller cannot smuggle in an
// unauthenticated path.
type Server struct {
	// Auth derives the principal from the request.
	Auth Authenticator
	// Operations declares the operations the API exposes. The API surface is
	// derived from it, so the API and the CLI cannot drift.
	Operations contract.Registry
	// Authorizer enforces scope, permission, idempotency and preconditions.
	Authorizer *contract.Authorizer
	// Environments is the environment store.
	Environments Environments
	// Creator is the write half of the environment store. Unset means this
	// deployment does not serve environment creation, and the route refuses
	// rather than guessing a store.
	Creator Creator
	// Destroyer removes an environment from the store. Unset means this
	// deployment does not serve environment destruction, and the route
	// refuses rather than guessing a store.
	Destroyer Destroyer
	// Updater applies a changed environment back to the store. Unset means
	// this deployment does not serve environment extension.
	Updater Updater
	// Ledger is the resource ledger the safe ownership inventory reads. Unset
	// means this deployment does not serve the resources route.
	Ledger resource.Ledger
	// Intake admits provider webhooks: exact-byte signature verification, a
	// replay window, and the durable delivery inbox. Unset means this
	// deployment does not serve the webhook route.
	Intake *intake.Service
	// Gates is the gate-run store. Unset means this deployment does not serve
	// the gates routes.
	Gates *gates.Store
	// Exceptions is the exception store. Unset means this deployment does not
	// serve the exceptions route.
	Exceptions *exceptions.Store
	// Experiments is the experiment-run store. Unset means this deployment
	// does not serve the experiments routes.
	Experiments *experiments.Store
	// Attestations is the platform's signing authority. Unset means this
	// deployment does not serve the attestations route.
	Attestations *attestations.Authority
	// Room is the reviewer room.
	Room *reviewer.Room
	// Passports is the evidence passport registry.
	Passports *passport.Registry
	// Now supplies the current moment.
	Now func() time.Time
}

// Destroyer is the store capability destroy needs: the environment leaves the
// store rather than being flagged, so acting on it again is a 404 — which
// says "gone" more honestly than a second success would.
type Destroyer interface {
	Remove(id string)
}

// Updater is the store capability extend needs: the environment's row moves
// to the new expiry and version as one write.
type Updater interface {
	Update(env Environment)
}

// now returns the server's current moment.
func (s *Server) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

// ServeHTTP routes a request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get(RequestIDHeader)
	if strings.TrimSpace(requestID) == "" {
		requestID = newRequestID()
	}
	w.Header().Set(RequestIDHeader, requestID)

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		s.fail(w, r, CodeInvalid, "the request body could not be read", requestID)
		return
	}
	if err := CheckRequestBody(body); err != nil {
		s.fail(w, r, CodeInvalid, err.Error(), requestID)
		return
	}

	// The provider webhook route is answered before credential
	// authentication, because its identity is its signature over the exact
	// bytes, not a bearer token: a webhook has no token to bear.
	segments := splitPath(r.URL.Path)
	if len(segments) == 4 && segments[0] == "v1" && segments[1] == "integrations" && segments[2] == "github" && segments[3] == "events" {
		s.githubWebhook(w, r, body, requestID)
		return
	}

	principal, err := s.Authenticate(r)
	if err != nil {
		s.fail(w, r, CodeUnauthenticated, "the request carried no usable credentials", requestID)
		return
	}

	switch {
	case len(segments) == 2 && segments[0] == "v1" && segments[1] == "environments" && r.Method == http.MethodPost:
		s.createEnvironment(w, r, principal, body, requestID)
	case len(segments) == 3 && segments[0] == "v1" && segments[1] == "environments" && r.Method == http.MethodGet:
		s.getEnvironment(w, r, principal, segments[2], requestID)
	case len(segments) == 4 && segments[0] == "v1" && segments[1] == "environments" && segments[3] == "destroy" && r.Method == http.MethodPost:
		s.destroyEnvironment(w, r, principal, segments[2], body, requestID)
	case len(segments) == 4 && segments[0] == "v1" && segments[1] == "environments" && segments[3] == "extend" && r.Method == http.MethodPost:
		s.extendEnvironment(w, r, principal, segments[2], body, requestID)
	case len(segments) == 4 && segments[0] == "v1" && segments[1] == "environments" && segments[3] == "generations" && r.Method == http.MethodPost:
		s.createGeneration(w, r, principal, segments[2], body, requestID)
	case len(segments) == 4 && segments[0] == "v1" && segments[1] == "environments" && segments[3] == "gates" && r.Method == http.MethodPost:
		s.requestGateRun(w, r, principal, segments[2], body, requestID)
	case len(segments) == 3 && segments[0] == "v1" && segments[1] == "gates" && r.Method == http.MethodGet:
		s.getGateRun(w, r, principal, segments[2], requestID)
	case len(segments) == 2 && segments[0] == "v1" && segments[1] == "exceptions" && r.Method == http.MethodPost:
		s.grantException(w, r, principal, body, requestID)
	case len(segments) == 4 && segments[0] == "v1" && segments[1] == "environments" && segments[3] == "experiments" && r.Method == http.MethodPost:
		s.requestExperiment(w, r, principal, segments[2], body, requestID)
	case len(segments) == 4 && segments[0] == "v1" && segments[1] == "experiments" && segments[3] == "abort" && r.Method == http.MethodPost:
		s.abortExperiment(w, r, principal, segments[2], body, requestID)
	case len(segments) == 3 && segments[0] == "v1" && segments[1] == "experiments" && r.Method == http.MethodGet:
		s.getExperiment(w, r, principal, segments[2], requestID)
	case len(segments) == 3 && segments[0] == "v1" && segments[1] == "attestations" && r.Method == http.MethodGet:
		s.getAttestation(w, r, principal, segments[2], requestID)
	case len(segments) == 4 && segments[0] == "v1" && segments[1] == "environments" && segments[3] == "resources" && r.Method == http.MethodGet:
		s.listEnvironmentResources(w, r, principal, segments[2], requestID)
	case len(segments) == 4 && segments[0] == "v1" && segments[1] == "environments" && segments[3] == "review-threads" && r.Method == http.MethodGet:
		s.listReviewThreads(w, r, principal, segments[2], requestID)
	case len(segments) == 4 && segments[0] == "v1" && segments[1] == "environments" && segments[3] == "review-threads" && r.Method == http.MethodPost:
		s.createReviewThread(w, r, principal, segments[2], body, requestID)
	case len(segments) == 4 && segments[0] == "v1" && segments[1] == "review-threads" && segments[3] == "findings" && r.Method == http.MethodPost:
		s.raiseFinding(w, r, principal, segments[2], body, requestID)
	case len(segments) == 6 && segments[0] == "v1" && segments[1] == "review-threads" && segments[3] == "findings" && segments[5] == "carry-forward" && r.Method == http.MethodPost:
		s.carryForward(w, r, principal, segments[2], segments[4], body, requestID)
	case len(segments) == 3 && segments[0] == "v1" && segments[1] == "passports" && r.Method == http.MethodGet:
		s.getPassport(w, r, principal, segments[2], requestID)
	default:
		s.fail(w, r, CodeNotFound, "no such route", requestID)
	}
}

// Authenticate derives the principal from the request.
func (s *Server) Authenticate(r *http.Request) (contract.Principal, error) {
	if s.Auth == nil {
		return contract.Principal{}, ErrUnauthenticated
	}
	principal, err := s.Auth.Authenticate(r)
	if err != nil {
		return contract.Principal{}, ErrUnauthenticated
	}
	if strings.TrimSpace(principal.ID) == "" {
		return contract.Principal{}, ErrUnauthenticated
	}
	return principal, nil
}

// environmentView is the console's view of an environment.
type environmentView struct {
	ID         string           `json:"id"`
	Generation int              `json:"generation"`
	ExpiresAt  time.Time        `json:"expires_at"`
	Timeline   console.Timeline `json:"timeline"`
}

// createEnvironmentBody is the §2 environment request shape: references and
// bounded values only. Every field is an assertion to validate, never
// authority — the actor and the scope are derived server-side, and the
// digests are checked for shape because a digest that does not parse cannot
// pin anything.
type createEnvironmentBody struct {
	RepositoryID        int64  `json:"repository_id"`
	PullRequestNumber   int    `json:"pull_request_number"`
	SourceSHA           string `json:"source_sha"`
	RecipeDigest        string `json:"recipe_digest"`
	ConfigurationDigest string `json:"configuration_digest"`
	ResourceProfile     string `json:"resource_profile"`
	RequestedTTLSeconds int    `json:"requested_ttl_seconds"`
}

// admittedProfiles is the profile catalog this deployment admits. Recipes,
// profiles and policies are catalog references — a request never carries the
// thing itself, only a name the catalog must know.
var admittedProfiles = map[string]bool{"preview-small": true}

// ttlBounds are the platform's bounded TTL policy in seconds.
const (
	minTTLSeconds = 300
	maxTTLSeconds = 86400
)

// digestShape reports whether s is a "sha256:<64 hex>" digest. A digest that
// does not parse cannot pin anything, and accepting it would be an assertion
// recorded as if it were proof.
func digestShape(s string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) || len(s) != len(prefix)+64 {
		return false
	}
	for _, c := range s[len(prefix):] {
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return false
	}
	return true
}

// shaShape reports whether s is a 40-character lowercase hex SHA-1, the shape
// of a git commit id.
func shaShape(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return false
	}
	return true
}

// createEnvironment serves POST /v1/environments: an admitted
// recipe/candidate/repository request becomes a 202 with the immutable
// environment identity and the status URL.
//
// The scope is derived server-side from the caller's own grants — the
// environment belongs to the scope the credential names, never to a scope the
// body asserts. Idempotency is the request-key memory: the same key with the
// same body returns the first result, and the same key with a different body
// is a refused retry. The contract's precondition machinery applies to
// mutations of an existing resource; a create has no resource version to
// precondition on, so its idempotency lives here, where the first result is
// remembered.
func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request, principal contract.Principal, body []byte, requestID string) {
	if s.Creator == nil {
		s.fail(w, r, CodeInternal, "this deployment does not wire an environment creator", requestID)
		return
	}
	key := strings.TrimSpace(r.Header.Get(IdempotencyHeader))
	if key == "" {
		s.fail(w, r, CodeInvalid, "a create carries an Idempotency-Key header; a retried submission must be recognisable as the same submission", requestID)
		return
	}
	var in createEnvironmentBody
	if err := json.Unmarshal(body, &in); err != nil {
		s.fail(w, r, CodeInvalid, "the body does not parse as the environment request shape", requestID)
		return
	}
	switch {
	case in.RepositoryID <= 0:
		s.fail(w, r, CodeUnprocessable, "repository_id must be a positive identifier", requestID)
		return
	case in.PullRequestNumber <= 0:
		s.fail(w, r, CodeUnprocessable, "pull_request_number must be a positive number", requestID)
		return
	case !shaShape(in.SourceSHA):
		s.fail(w, r, CodeUnprocessable, "source_sha must be a 40-character lowercase git sha", requestID)
		return
	case !digestShape(in.RecipeDigest), !digestShape(in.ConfigurationDigest):
		s.fail(w, r, CodeUnprocessable, "recipe_digest and configuration_digest must be sha256:<64 hex> digests; a digest that does not parse pins nothing", requestID)
		return
	case !admittedProfiles[in.ResourceProfile]:
		s.fail(w, r, CodeUnprocessable, "resource_profile must be a catalog profile this deployment admits", requestID)
		return
	case in.RequestedTTLSeconds < minTTLSeconds || in.RequestedTTLSeconds > maxTTLSeconds:
		s.fail(w, r, CodeUnprocessable, fmt.Sprintf("requested_ttl_seconds must be between %d and %d: the platform's TTL is bounded policy, not a client's preference", minTTLSeconds, maxTTLSeconds), requestID)
		return
	}

	// The scope is the caller's own grant. A principal with no grants owns no
	// scope, and an environment must belong to one.
	scope := ""
	for _, g := range principal.Grants {
		if strings.TrimSpace(g) != "" {
			scope = g
			break
		}
	}
	if scope == "" {
		s.fail(w, r, CodeForbidden, "your credential carries no grants, so no scope exists for the environment to belong to", requestID)
		return
	}

	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	if prior, ok := s.Creator.(interface {
		IdempotentRequest(string) (IdempotentRequestRecord, bool)
	}); ok {
		if rec, found := prior.IdempotentRequest(key); found {
			if rec.BodyDigest != digest {
				s.fail(w, r, CodeConflict, "this idempotency key was already used with a different body; a retried request must repeat its body exactly", requestID)
				return
			}
			env, ok := s.Environments.Get(rec.EnvironmentID)
			if !ok {
				s.fail(w, r, CodeNotFound, "the environment this key created no longer exists", requestID)
				return
			}
			s.writeCreated(w, r, env, requestID)
			return
		}
	}

	// The quota gate is where a real deployment refuses for entitlement. This
	// deployment admits one running environment per scope, the same decision
	// the console's form reads.
	count := 0
	for _, e := range s.Environments.All() {
		if e.Scope == scope {
			count++
		}
	}
	if count >= 1 {
		s.fail(w, r, CodeQuota, "this deployment allows one running environment per scope, and one is already running", requestID)
		return
	}

	created := s.Creator.Add(Environment{
		ID:         "env-" + newRequestID(),
		Scope:      scope,
		Version:    1,
		Generation: 1,
		ExpiresAt:  s.now().Add(time.Duration(in.RequestedTTLSeconds) * time.Second),
	})
	if rec, ok := s.Creator.(interface {
		RememberIdempotentRequest(string, string, string)
	}); ok {
		rec.RememberIdempotentRequest(key, digest, created.ID)
	}
	s.writeCreated(w, r, created, requestID)
}

// writeCreated writes the 202 create response: the immutable identity and the
// status URL, never secret values.
func (s *Server) writeCreated(w http.ResponseWriter, r *http.Request, env Environment, requestID string) {
	s.write(w, r, http.StatusAccepted, map[string]any{
		"environment_id": env.ID,
		"slug":           env.ID,
		"generation":     env.Generation,
		"status_url":     "/v1/environments/" + env.ID,
	}, requestID)
}

// destroyEnvironment serves POST /v1/environments/{id}/destroy: desired
// absent, with the contract's idempotency key and resource-version
// precondition enforced by the authorizer. In this in-memory deployment the
// async draining completes with the removal: a follow-up GET answers 404,
// which says "gone" more honestly than a second success would.
func (s *Server) destroyEnvironment(w http.ResponseWriter, r *http.Request, principal contract.Principal, id string, body []byte, requestID string) {
	if s.Destroyer == nil {
		s.fail(w, r, CodeInternal, "this deployment does not wire an environment destroyer", requestID)
		return
	}
	env, ok := s.Environments.Get(id)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such environment", requestID)
		return
	}
	if err := s.authorizeMutation("environments.destroy", principal, env, body, r); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	s.Destroyer.Remove(id)
	s.write(w, r, http.StatusAccepted, map[string]any{
		"environment_id": id,
		"state":          "destroying",
		"status_url":     "/v1/environments/" + id,
	}, requestID)
}

// extendBody is the extend request's shape: one bounded value.
type extendBody struct {
	RequestedTTLSeconds int `json:"requested_ttl_seconds"`
}

// extendEnvironment serves POST /v1/environments/{id}/extend: a bounded TTL
// extension under the platform's policy. The extension moves the expiry and
// bumps the resource version as one write, so the next mutation's
// precondition is the version this response names.
//
// The replay rule runs before the precondition check, because a retried
// extension that already applied would otherwise answer 409 against the very
// version it moved: the same key with the same body returns the recorded
// result, and the same key with a different body is a refused retry.
func (s *Server) extendEnvironment(w http.ResponseWriter, r *http.Request, principal contract.Principal, id string, body []byte, requestID string) {
	if s.Updater == nil {
		s.fail(w, r, CodeInternal, "this deployment does not wire an environment updater", requestID)
		return
	}
	key := strings.TrimSpace(r.Header.Get(IdempotencyHeader))
	if key == "" {
		s.fail(w, r, CodeInvalid, "a mutation carries an Idempotency-Key header", requestID)
		return
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	if rec, found := s.idempotentRequest(key); found {
		if rec.BodyDigest != digest {
			s.fail(w, r, CodeConflict, "this idempotency key was already used with a different body; a retried request must repeat its body exactly", requestID)
			return
		}
		s.write(w, r, http.StatusOK, json.RawMessage(rec.Result), requestID)
		return
	}

	env, ok := s.Environments.Get(id)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such environment", requestID)
		return
	}
	if err := s.authorizeMutation("environments.extend", principal, env, body, r); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	var in extendBody
	if err := json.Unmarshal(body, &in); err != nil {
		s.fail(w, r, CodeInvalid, "the body does not parse as the extend shape", requestID)
		return
	}
	if in.RequestedTTLSeconds < minTTLSeconds {
		s.fail(w, r, CodeUnprocessable, fmt.Sprintf("requested_ttl_seconds must be at least %d", minTTLSeconds), requestID)
		return
	}
	newExpiry := env.ExpiresAt.Add(time.Duration(in.RequestedTTLSeconds) * time.Second)
	if ceiling := s.now().Add(maxTTLSeconds * time.Second); newExpiry.After(ceiling) {
		s.fail(w, r, CodeUnprocessable, fmt.Sprintf("the extension would carry the expiry past %s: the platform's TTL is bounded policy, not a client's preference", ceiling.Format(time.RFC3339)), requestID)
		return
	}

	env.ExpiresAt = newExpiry
	env.Version++
	s.Updater.Update(env)

	result := map[string]any{
		"environment_id":   id,
		"expires_at":       newExpiry,
		"resource_version": env.Version,
	}
	encoded, _ := json.Marshal(result)
	s.rememberIdempotentResult(key, digest, id, string(encoded))
	s.write(w, r, http.StatusOK, result, requestID)
}

// idempotentRequest returns what a key first produced, if the store
// remembers it.
func (s *Server) idempotentRequest(key string) (IdempotentRequestRecord, bool) {
	if store, ok := s.Creator.(interface {
		IdempotentRequest(string) (IdempotentRequestRecord, bool)
	}); ok {
		return store.IdempotentRequest(key)
	}
	return IdempotentRequestRecord{}, false
}

// rememberIdempotentResult records the result a key produced, so a replay
// returns it rather than applying a second time.
func (s *Server) rememberIdempotentResult(key, digest, envID, result string) {
	if store, ok := s.Updater.(interface {
		RememberIdempotentResult(string, string, string, string)
	}); ok {
		store.RememberIdempotentResult(key, digest, envID, result)
	}
}

// generationBody is a new generation's exact candidate set. It is the create
// shape's provenance half: the candidate and configuration are named by
// digest, because a generation is an identity, not a description.
type generationBody struct {
	SourceSHA           string `json:"source_sha"`
	RecipeDigest        string `json:"recipe_digest"`
	ConfigurationDigest string `json:"configuration_digest"`
}

// createGeneration serves POST /v1/environments/{id}/generations: a new
// exact candidate/config for the environment.
//
// The rollout is serialized by the resource-version precondition: two
// generation attempts against the same version conflict, and the loser
// re-reads and retries. The response names the new version, which is the
// one the next generation's precondition must carry.
//
// Gate invalidation is stated honestly: this deployment holds no gate runs,
// so there is nothing to invalidate and nothing pretended — when a gate
// store exists, the invalidation belongs here, before the response.
func (s *Server) createGeneration(w http.ResponseWriter, r *http.Request, principal contract.Principal, id string, body []byte, requestID string) {
	if s.Updater == nil {
		s.fail(w, r, CodeInternal, "this deployment does not wire an environment updater", requestID)
		return
	}
	env, ok := s.Environments.Get(id)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such environment", requestID)
		return
	}
	if err := s.authorizeMutation("environments.generations.create", principal, env, body, r); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	var in generationBody
	if err := json.Unmarshal(body, &in); err != nil {
		s.fail(w, r, CodeInvalid, "the body does not parse as the generation shape", requestID)
		return
	}
	if !shaShape(in.SourceSHA) {
		s.fail(w, r, CodeUnprocessable, "source_sha must be a 40-character lowercase git sha", requestID)
		return
	}
	if !digestShape(in.RecipeDigest) || !digestShape(in.ConfigurationDigest) {
		s.fail(w, r, CodeUnprocessable, "recipe_digest and configuration_digest must be sha256:<64 hex> digests; a digest that does not parse pins nothing", requestID)
		return
	}

	env.Generation++
	env.Version++
	env.SourceSHA = in.SourceSHA
	env.RecipeDigest = in.RecipeDigest
	env.ConfigurationDigest = in.ConfigurationDigest
	s.Updater.Update(env)

	s.write(w, r, http.StatusAccepted, map[string]any{
		"environment_id":   id,
		"generation":       env.Generation,
		"resource_version": env.Version,
		"status_url":       "/v1/environments/" + id,
	}, requestID)
}

// gateRequestBody names the gate to run and asserts the policy digest.
type gateRequestBody struct {
	Kind         string `json:"kind"`
	PolicyDigest string `json:"policy_digest"`
}

// requestGateRun serves POST /v1/environments/{id}/gates: a request for one
// independent gate run, bound to the environment's exact generation.
//
// The candidate digest is computed by the server from the row's recorded
// candidate set — a candidate identity the server did not compute is an
// assertion wearing a digest's clothes. The policy digest is accepted as an
// assertion, validated for shape and recorded as what was asserted.
func (s *Server) requestGateRun(w http.ResponseWriter, r *http.Request, principal contract.Principal, id string, body []byte, requestID string) {
	if s.Gates == nil {
		s.fail(w, r, CodeInternal, "this deployment does not wire a gate-run store", requestID)
		return
	}
	env, ok := s.Environments.Get(id)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such environment", requestID)
		return
	}
	if err := s.authorizeMutation("environments.gates.request", principal, env, body, r); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	var in gateRequestBody
	if err := json.Unmarshal(body, &in); err != nil {
		s.fail(w, r, CodeInvalid, "the body does not parse as the gate request shape", requestID)
		return
	}
	if !gates.Allowed(gates.Kind(in.Kind)) {
		s.fail(w, r, CodeUnprocessable, fmt.Sprintf("gate %q is not in the catalog; the allowed set is %v", in.Kind, gates.AllowedKinds()), requestID)
		return
	}
	if in.PolicyDigest != "" && !digestShape(in.PolicyDigest) {
		s.fail(w, r, CodeUnprocessable, "policy_digest must be a sha256:<64 hex> digest", requestID)
		return
	}
	// The candidate digest covers the environment's exact candidate set: the
	// source sha and both digests, in a canonical order, so a generation's
	// identity is one digest and not three loose strings.
	canonical := env.SourceSHA + "\n" + env.RecipeDigest + "\n" + env.ConfigurationDigest
	candidateSum := sha256.Sum256([]byte(canonical))
	candidate := "sha256:" + hex.EncodeToString(candidateSum[:])

	run, err := s.Gates.Request(id, env.Scope, uint64(env.Generation),
		gates.Kind(in.Kind), candidate, in.PolicyDigest)
	if err != nil {
		s.fail(w, r, CodeUnprocessable, err.Error(), requestID)
		return
	}
	s.write(w, r, http.StatusAccepted, map[string]any{
		"run_id":     run.ID,
		"state":      string(run.State),
		"generation": run.Generation,
		"status_url": "/v1/gates/" + run.ID,
	}, requestID)
}

// getGateRun serves GET /v1/gates/{run_id}: the run's §3 shape, as it is.
// A requested run carries no result and no invariant outcomes — §3's result
// vocabulary belongs to a trusted agent, and none is wired, so the record
// says "requested" and stops.
func (s *Server) getGateRun(w http.ResponseWriter, r *http.Request, principal contract.Principal, id, requestID string) {
	if s.Gates == nil {
		s.fail(w, r, CodeInternal, "this deployment does not wire a gate-run store", requestID)
		return
	}
	run, err := s.Gates.Get(id)
	if err != nil {
		s.fail(w, r, CodeNotFound, "no such gate run", requestID)
		return
	}
	if err := s.authorizeScope("gates.get", principal, run.Scope); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	s.write(w, r, http.StatusOK, run, requestID)
}

// exceptionBody is the grant request: what is excepted, why, and for how
// long.
type exceptionBody struct {
	EnvironmentID string `json:"environment_id"`
	Reason        string `json:"reason"`
	TTLHours      int    `json:"ttl_hours"`
}

// grantException serves POST /v1/exceptions: a bounded, separately
// authorized exception to policy.
//
// Separately authorized means exactly that: the operation's permission is
// not the ordinary write — granting exceptions must not ride along with
// using the feature. The scope is derived from the environment the
// exception applies to; the actor is the credential's own identity; the
// bound is the store's, not the client's.
func (s *Server) grantException(w http.ResponseWriter, r *http.Request, principal contract.Principal, body []byte, requestID string) {
	if s.Exceptions == nil {
		s.fail(w, r, CodeInternal, "this deployment does not wire an exception store", requestID)
		return
	}
	var in exceptionBody
	if err := json.Unmarshal(body, &in); err != nil {
		s.fail(w, r, CodeInvalid, "the body does not parse as the exception shape", requestID)
		return
	}
	env, ok := s.Environments.Get(in.EnvironmentID)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such environment", requestID)
		return
	}
	if err := s.authorizeRequest("exceptions.grant", principal, env, body, r); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	window := time.Duration(in.TTLHours) * time.Hour
	if in.TTLHours == 0 {
		// The default window is the cap: an exception lives as long as the
		// platform allows, and not a moment longer.
		window = exceptions.MaxWindow
	}
	rec, err := s.Exceptions.Request(env.ID, env.Scope, in.Reason, principal.ID, window)
	if err != nil {
		s.fail(w, r, CodeUnprocessable, err.Error(), requestID)
		return
	}
	s.write(w, r, http.StatusCreated, rec, requestID)
}

// experimentBody names the catalog profile and its bounded parameters. The
// body names NO target: the target is the environment the request is
// authorized against, derived server-side, because an experiment parameter
// cannot override the target's ownership.
type experimentBody struct {
	Profile string         `json:"profile"`
	Params  map[string]int `json:"parameters"`
}

// requestExperiment serves POST /v1/environments/{id}/experiments: a
// catalog profile plus bounded parameters against this environment and
// nothing else — the blast radius is one environment, and it is not a
// client's choice.
func (s *Server) requestExperiment(w http.ResponseWriter, r *http.Request, principal contract.Principal, id string, body []byte, requestID string) {
	if s.Experiments == nil {
		s.fail(w, r, CodeInternal, "this deployment does not wire an experiment store", requestID)
		return
	}
	env, ok := s.Environments.Get(id)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such environment", requestID)
		return
	}
	if err := s.authorizeMutation("environments.experiments.request", principal, env, body, r); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	var in experimentBody
	if err := json.Unmarshal(body, &in); err != nil {
		s.fail(w, r, CodeInvalid, "the body does not parse as the experiment shape", requestID)
		return
	}
	run, err := s.Experiments.Request(env.ID, env.Scope, in.Profile, in.Params)
	if err != nil {
		s.fail(w, r, CodeUnprocessable, err.Error(), requestID)
		return
	}
	s.write(w, r, http.StatusAccepted, map[string]any{
		"run_id":     run.ID,
		"state":      string(run.State),
		"profile":    run.Profile,
		"parameters": run.Params,
		"status_url": "/v1/experiments/" + run.ID,
	}, requestID)
}

// abortBody carries the visible reason.
type abortBody struct {
	Reason string `json:"reason"`
}

// abortExperiment serves POST /v1/experiments/{run_id}/abort: idempotent
// fault removal. Aborting an aborted run returns the same record, because a
// retried abort is the same intent, not a second fault. Recovery
// verification is not claimed: the record says "aborted", and the recovery
// statement belongs to the injector that would have run the fault.
func (s *Server) abortExperiment(w http.ResponseWriter, r *http.Request, principal contract.Principal, id string, body []byte, requestID string) {
	if s.Experiments == nil {
		s.fail(w, r, CodeInternal, "this deployment does not wire an experiment store", requestID)
		return
	}
	run, err := s.Experiments.Get(id)
	if err != nil {
		s.fail(w, r, CodeNotFound, "no such experiment run", requestID)
		return
	}
	// The abort is a mutation of the run's record, so the full contract
	// applies against the run's own resource: idempotency key, body digest,
	// and a precondition on the record as it exists (version 1 — a run's
	// only transition is to aborted).
	sum := sha256.Sum256(body)
	req := contract.Request{
		Principal:      &principal,
		Resource:       contract.Resource{ID: run.ID, Scope: run.Scope, Version: 1},
		IdempotencyKey: r.Header.Get(IdempotencyHeader),
		BodyDigest:     hex.EncodeToString(sum[:]),
	}
	if raw := r.Header.Get(PreconditionHeader); raw != "" {
		version, convErr := strconv.Atoi(strings.Trim(raw, `"`))
		if convErr != nil {
			s.fail(w, r, CodeInvalid, "If-Match must be the run's resource version", requestID)
			return
		}
		req.Precondition = version
	}
	if err := s.Authorizer.Authorize("experiments.abort", req, s.now()); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	var in abortBody
	if err := json.Unmarshal(body, &in); err != nil {
		s.fail(w, r, CodeInvalid, "the body does not parse as the abort shape", requestID)
		return
	}
	aborted, err := s.Experiments.Abort(id, in.Reason)
	if err != nil {
		s.fail(w, r, CodeUnprocessable, err.Error(), requestID)
		return
	}
	s.write(w, r, http.StatusOK, aborted, requestID)
}

// getExperiment serves GET /v1/experiments/{run_id}: the run's state,
// targets, parameters and (empty until an agent exists) results.
func (s *Server) getExperiment(w http.ResponseWriter, r *http.Request, principal contract.Principal, id, requestID string) {
	if s.Experiments == nil {
		s.fail(w, r, CodeInternal, "this deployment does not wire an experiment store", requestID)
		return
	}
	run, err := s.Experiments.Get(id)
	if err != nil {
		s.fail(w, r, CodeNotFound, "no such experiment run", requestID)
		return
	}
	if err := s.authorizeScope("experiments.get", principal, run.Scope); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	s.write(w, r, http.StatusOK, run, requestID)
}

// getAttestation serves GET /v1/attestations/{id}: the signed,
// candidate-bound result, with its state as the reader should see it —
// valid, expired, or revoked with the withdrawal record carried.
//
// The signature is verified over the record's own content on every read:
// the store is not the source of truth for validity, the signature is, and
// a stored record that no longer verifies is a server fault rather than a
// served fact.
func (s *Server) getAttestation(w http.ResponseWriter, r *http.Request, principal contract.Principal, id, requestID string) {
	if s.Attestations == nil {
		s.fail(w, r, CodeInternal, "this deployment does not wire an attestation authority", requestID)
		return
	}
	rec, state, err := s.Attestations.Get(id)
	if err != nil {
		if errors.Is(err, attestations.ErrTampered) {
			// The store's record and its signature disagree. Serving it would
			// be serving a fact nobody signed; refusing it loudly is the only
			// honest answer, and it is the server's fault to own.
			s.fail(w, r, CodeInternal, "the stored attestation's signature no longer verifies over its content", requestID)
			return
		}
		s.fail(w, r, CodeNotFound, "no such attestation", requestID)
		return
	}
	if err := s.authorizeScope("attestations.get", principal, rec.Scope); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	s.write(w, r, http.StatusOK, map[string]any{
		"attestation":     rec,
		"state":           string(state),
		"candidate_bound": true,
	}, requestID)
}

// githubWebhook serves POST /v1/integrations/github/events: exact-byte
// signature verification and the durable provider-delivery inbox.
//
// The order is the intake service's, and it is deliberate: validate the
// delivery metadata, verify the signature over the exact bytes that arrived,
// and only then persist — a payload that fails any of these is never stored.
// A duplicate delivery is a no-op that still answers 202: the row was written
// before the first acknowledgement, and a redelivery must not become a second
// run. A store rejection answers 500 so the provider redelivers — acking a
// delivery whose row was lost would lose the event permanently.
func (s *Server) githubWebhook(w http.ResponseWriter, r *http.Request, body []byte, requestID string) {
	if s.Intake == nil {
		s.fail(w, r, CodeInternal, "this deployment does not wire a webhook intake", requestID)
		return
	}
	d := intake.Delivery{
		DeliveryID: r.Header.Get("X-GitHub-Delivery"),
		EventType:  r.Header.Get("X-GitHub-Event"),
		// GitHub signs the raw body and carries no signature timestamp; the
		// receipt moment is the replay window's reference, and the durable
		// (provider, delivery id) uniqueness is the replay defense.
		Timestamp:       s.now(),
		InstallationRef: r.Header.Get("X-GitHub-Hook-Installation-Target-ID"),
		RepositoryRef:   r.Header.Get("X-GitHub-Repository"),
	}
	stored, err := s.Intake.Intake(r.Context(), d, body, r.Header.Get("X-Hub-Signature-256"))
	if err != nil {
		switch {
		case errors.Is(err, intake.ErrSignatureInvalid):
			s.fail(w, r, CodeUnauthenticated, "the payload's signature did not verify over the exact bytes received", requestID)
		case errors.Is(err, intake.ErrMalformedDelivery):
			s.fail(w, r, CodeInvalid, err.Error(), requestID)
		case errors.Is(err, intake.ErrTimestampOutsideTolerance):
			s.fail(w, r, CodeInvalid, err.Error(), requestID)
		default:
			// ErrStoreRejected: not acknowledged, so the provider redelivers.
			s.fail(w, r, CodeInternal, "the verified delivery could not be persisted; expect a redelivery", requestID)
		}
		return
	}
	s.write(w, r, http.StatusAccepted, map[string]any{
		"delivery_id": stored.DeliveryID,
		"duplicate":   stored.Duplicate,
		"expires_at":  stored.ExpiresAt,
	}, requestID)
}

// resourceView is one allocation's safe ownership view: what the resource is,
// what state its cleanup is in, and a credential reference that is visibly
// redacted. The credential itself never appears anywhere in a response, and
// the ref is shown redacted rather than omitted so a client cannot mistake
// absence for having been checked.
type resourceView struct {
	ID            string            `json:"id"`
	Kind          string            `json:"kind"`
	LogicalKey    string            `json:"logical_key"`
	Generation    uint64            `json:"generation"`
	State         string            `json:"state"`
	ProviderRef   map[string]string `json:"provider_ref"`
	CredentialRef string            `json:"credential_ref"`
	CreatedAt     time.Time         `json:"created_at"`
}

// listEnvironmentResources serves GET /v1/environments/{id}/resources: the
// safe ownership inventory. It is the environment's own allocations and
// nothing else — a scope-wide or account-wide list is the operator tooling's
// job, not a customer API's.
func (s *Server) listEnvironmentResources(w http.ResponseWriter, r *http.Request, principal contract.Principal, id, requestID string) {
	if s.Ledger == nil {
		s.fail(w, r, CodeInternal, "this deployment does not wire a resource ledger", requestID)
		return
	}
	env, ok := s.Environments.Get(id)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such environment", requestID)
		return
	}
	if err := s.authorize("environments.resources", principal, env); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	allocs, err := s.Ledger.List(r.Context(), id)
	if err != nil {
		s.fail(w, r, CodeInternal, "the ownership inventory could not be read", requestID)
		return
	}
	items := make([]resourceView, 0, len(allocs))
	for _, a := range allocs {
		items = append(items, resourceView{
			ID: a.ID, Kind: a.Kind, LogicalKey: a.LogicalKey,
			Generation:    a.Generation,
			State:         string(a.State),
			ProviderRef:   a.ProviderRef,
			CredentialRef: "[redacted]",
			CreatedAt:     a.CreatedAt,
		})
	}
	s.write(w, r, http.StatusOK, map[string]any{"items": items}, requestID)
}

// getEnvironment serves the environment's state, progress and expiry.
func (s *Server) getEnvironment(w http.ResponseWriter, r *http.Request, principal contract.Principal, id, requestID string) {
	env, ok := s.Environments.Get(id)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such environment", requestID)
		return
	}
	if err := s.authorize("environments.get", principal, env); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	s.write(w, r, http.StatusOK, environmentView{
		ID:         env.ID,
		Generation: env.Generation,
		ExpiresAt:  env.ExpiresAt,
		Timeline:   console.BuildTimeline(env.Actions),
	}, requestID)
}

// threadView is the console's view of a reviewer thread.
type threadView struct {
	ID         string        `json:"id"`
	ResourceID string        `json:"resource_id"`
	Generation int           `json:"generation"`
	Title      string        `json:"title"`
	Findings   []findingView `json:"findings"`
}

// findingView is the console's view of a finding.
type findingView struct {
	ID         string `json:"id"`
	Generation int    `json:"generation"`
	State      string `json:"state"`
	Owner      string `json:"owner"`
	Reference  string `json:"reference,omitempty"`
	Body       string `json:"body"`
}

// listReviewThreads serves the reviewer room's threads for an environment.
func (s *Server) listReviewThreads(w http.ResponseWriter, r *http.Request, principal contract.Principal, envID, requestID string) {
	env, ok := s.Environments.Get(envID)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such environment", requestID)
		return
	}
	if err := s.authorize("environments.reviewThreads.list", principal, env); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	size, err := PageSize(r.URL.Query().Get("limit"))
	if err != nil {
		s.fail(w, r, CodeTooLarge, err.Error(), requestID)
		return
	}
	offset := 0
	if token := r.URL.Query().Get("cursor"); token != "" {
		cursor, err := DecodeCursor(token, "review-threads", env.Scope)
		if err != nil {
			s.fail(w, r, CodeInvalid, err.Error(), requestID)
			return
		}
		offset = cursor.Offset
	}
	threads := s.threadsFor(env)
	page, next := paginate(threads, offset, size, "review-threads", env.Scope)
	s.write(w, r, http.StatusOK, map[string]any{"items": page, "next": next}, requestID)
}

// threadsFor returns the threads belonging to an environment.
func (s *Server) threadsFor(env Environment) []threadView {
	if s.Room == nil {
		return nil
	}
	var out []threadView
	for _, t := range s.Room.Threads {
		if t.ResourceID != env.ID {
			continue
		}
		view := threadView{ID: t.ID, ResourceID: t.ResourceID, Generation: t.Generation, Title: t.Title}
		for _, f := range t.Findings {
			view.Findings = append(view.Findings, findingView{
				ID:         f.ID,
				Generation: f.Generation,
				State:      string(f.State),
				Owner:      f.Owner,
				Reference:  f.Reference,
				Body:       f.Body,
			})
		}
		out = append(out, view)
	}
	return out
}

// createReviewThreadRequest is the body of a thread creation.
type createReviewThreadRequest struct {
	Title      string `json:"title"`
	Generation int    `json:"generation"`
}

// createReviewThread opens a thread in the reviewer room.
func (s *Server) createReviewThread(w http.ResponseWriter, r *http.Request, principal contract.Principal, envID string, body []byte, requestID string) {
	env, ok := s.Environments.Get(envID)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such environment", requestID)
		return
	}
	if err := s.authorizeMutation("environments.reviewThreads.create", principal, env, body, r); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	var req createReviewThreadRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.fail(w, r, CodeInvalid, "the body is not a review-thread request", requestID)
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		s.fail(w, r, CodeInvalid, "a thread needs a title", requestID)
		return
	}
	generation := req.Generation
	if generation == 0 {
		generation = env.Generation
	}
	room := reviewer.Room{}
	if s.Room != nil {
		room = *s.Room
	}
	opened, err := room.OpenThread(reviewer.Thread{
		ID:         newRequestID(),
		ResourceID: env.ID,
		Scope:      env.Scope,
		Generation: generation,
		Title:      req.Title,
		CreatedBy:  principal.ID,
	}, reviewerPrincipal(principal), s.now())
	if err != nil {
		s.fail(w, r, CodeInvalid, err.Error(), requestID)
		return
	}
	if s.Room != nil {
		*s.Room = opened
	}
	s.write(w, r, http.StatusCreated, map[string]any{"id": opened.Threads[len(opened.Threads)-1].ID}, requestID)
}

// raiseFindingRequest is the body of a finding.
type raiseFindingRequest struct {
	ID         string `json:"id"`
	Generation int    `json:"generation"`
	Kind       string `json:"kind"`
	Reference  string `json:"reference"`
	Body       string `json:"body"`
	Owner      string `json:"owner"`
}

// raiseFinding records a finding against a thread.
func (s *Server) raiseFinding(w http.ResponseWriter, r *http.Request, principal contract.Principal, threadID string, body []byte, requestID string) {
	room := reviewer.Room{}
	if s.Room != nil {
		room = *s.Room
	}
	thread, ok := room.Thread(threadID)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such thread", requestID)
		return
	}
	env, ok := s.Environments.Get(thread.ResourceID)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such environment", requestID)
		return
	}
	if err := s.authorizeMutation("reviewThreads.findings.create", principal, env, body, r); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	var req raiseFindingRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.fail(w, r, CodeInvalid, "the body is not a finding request", requestID)
		return
	}
	if strings.TrimSpace(req.ID) == "" {
		req.ID = newRequestID()
	}
	if strings.TrimSpace(req.Owner) == "" {
		req.Owner = principal.ID
	}
	raised, err := room.Raise(threadID, reviewer.Finding{
		ID:         req.ID,
		ThreadID:   threadID,
		Generation: req.Generation,
		Kind:       req.Kind,
		Reference:  req.Reference,
		Body:       req.Body,
		Owner:      req.Owner,
	}, reviewerPrincipal(principal), s.now())
	if err != nil {
		s.fail(w, r, CodeInvalid, err.Error(), requestID)
		return
	}
	if s.Room != nil {
		*s.Room = raised
	}
	s.write(w, r, http.StatusCreated, map[string]any{"id": req.ID}, requestID)
}

// carryForwardRequest is the body of a carry-forward.
type carryForwardRequest struct {
	Reason string `json:"reason"`
}

// carryForward carries a finding forward across a generation change.
func (s *Server) carryForward(w http.ResponseWriter, r *http.Request, principal contract.Principal, threadID, findingID string, body []byte, requestID string) {
	room := reviewer.Room{}
	if s.Room != nil {
		room = *s.Room
	}
	thread, ok := room.Thread(threadID)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such thread", requestID)
		return
	}
	env, ok := s.Environments.Get(thread.ResourceID)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such environment", requestID)
		return
	}
	if err := s.authorizeMutation("reviewThreads.findings.carryForward", principal, env, body, r); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	var req carryForwardRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.fail(w, r, CodeInvalid, "the body is not a carry-forward request", requestID)
		return
	}
	carried, err := room.CarryForward(threadID, findingID, principal.ID, req.Reason, s.now())
	if err != nil {
		s.fail(w, r, CodeInvalid, err.Error(), requestID)
		return
	}
	if s.Room != nil {
		*s.Room = carried
	}
	s.write(w, r, http.StatusOK, map[string]any{"id": findingID, "state": string(reviewer.StateCarriedForward)}, requestID)
}

// getPassport serves an evidence passport's manifest.
func (s *Server) getPassport(w http.ResponseWriter, r *http.Request, principal contract.Principal, id, requestID string) {
	if s.Passports == nil {
		s.fail(w, r, CodeNotFound, "no such passport", requestID)
		return
	}
	p, ok := s.Passports.Passport(id)
	if !ok {
		s.fail(w, r, CodeNotFound, "no such passport", requestID)
		return
	}
	scope := p.Scope
	if err := s.authorizeScope("passports.get", principal, scope); err != nil {
		s.failFromError(w, r, err, requestID)
		return
	}
	export, err := s.Passports.ExportPassport(p, scope, passportRedactor{}, s.now())
	if err != nil {
		s.fail(w, r, CodeForbiddenContent, err.Error(), requestID)
		return
	}
	s.write(w, r, http.StatusOK, map[string]any{
		"id":          export.PassportID,
		"version":     export.Version,
		"digest":      export.ManifestDigest,
		"previous_id": export.PreviousID,
		"evidence":    export.Evidence,
	}, requestID)
}

// passportRedactor withholds evidence content from an export.
type passportRedactor struct{}

// Sanitize returns the redacted content.
func (passportRedactor) Sanitize(kind, content string) string { return "[redacted]" }

// authorize authorizes a read against an environment.
func (s *Server) authorize(opID string, principal contract.Principal, env Environment) error {
	return s.authorizeRequest(opID, principal, env, nil, nil)
}

// authorizeMutation authorizes a mutation against an environment, using the request's
// idempotency key and precondition.
func (s *Server) authorizeMutation(opID string, principal contract.Principal, env Environment, body []byte, r *http.Request) error {
	return s.authorizeRequest(opID, principal, env, body, r)
}

// authorizeRequest builds and checks the authorization request.
func (s *Server) authorizeRequest(opID string, principal contract.Principal, env Environment, body []byte, r *http.Request) error {
	if s.Authorizer == nil {
		return contract.ErrNoPrincipal
	}
	req := contract.Request{
		Principal: &principal,
		Resource: contract.Resource{
			ID:      env.ID,
			Scope:   env.Scope,
			Version: env.Version,
		},
	}
	if r != nil {
		req.IdempotencyKey = r.Header.Get(IdempotencyHeader)
		if raw := r.Header.Get(PreconditionHeader); raw != "" {
			version, err := strconv.Atoi(strings.Trim(raw, `"`))
			if err != nil {
				return contract.ErrNoResource
			}
			req.Precondition = version
		}
	}
	if body != nil {
		sum := sha256.Sum256(body)
		req.BodyDigest = hex.EncodeToString(sum[:])
	}
	return s.Authorizer.Authorize(opID, req, s.now())
}

// authorizeScope authorizes against a scope rather than a resource.
func (s *Server) authorizeScope(opID string, principal contract.Principal, scope string) error {
	if s.Authorizer == nil {
		return contract.ErrNoPrincipal
	}
	req := contract.Request{
		Principal: &principal,
		Resource:  contract.Resource{ID: scope, Scope: scope, Version: 1},
	}
	return s.Authorizer.Authorize(opID, req, s.now())
}

// reviewerPrincipal converts an API principal into a reviewer principal.
func reviewerPrincipal(p contract.Principal) reviewer.Principal {
	return reviewer.Principal{ID: p.ID, Grants: p.Grants}
}

// paginate slices a page and builds the next cursor.
func paginate[T any](items []T, offset, size int, collection, scope string) ([]T, string) {
	if offset > len(items) {
		offset = len(items)
	}
	end := offset + size
	if end > len(items) {
		end = len(items)
	}
	page := items[offset:end]
	if end >= len(items) {
		return page, ""
	}
	return page, EncodeCursor(Cursor{Collection: collection, Scope: scope, Offset: end})
}

// write renders a successful response, refusing content that must not leave.
func (s *Server) write(w http.ResponseWriter, r *http.Request, status int, body any, requestID string) {
	if err := CheckResponseContent(body); err != nil {
		s.fail(w, r, CodeForbiddenContent, err.Error(), requestID)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(RequestIDHeader, requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// fail writes a problem response.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, code Code, detail, requestID string) {
	WriteProblem(w, NewProblem(code, detail, r.URL.Path, requestID))
}

// failFromError writes the problem for a library refusal.
//
// A refusal from the authorization rules is a denial, and a denial is not retryable.
// A conflict is retryable because the world may have moved. Everything else is a
// malformed request.
func (s *Server) failFromError(w http.ResponseWriter, r *http.Request, err error, requestID string) {
	switch {
	case errors.Is(err, contract.ErrNoPrincipal):
		s.fail(w, r, CodeUnauthenticated, err.Error(), requestID)
	case errors.Is(err, contract.ErrNotPermitted), errors.Is(err, contract.ErrMissingPermission):
		s.fail(w, r, CodeForbidden, err.Error(), requestID)
	case errors.Is(err, contract.ErrMissingIdempotencyKey), errors.Is(err, contract.ErrMissingPrecondition):
		s.fail(w, r, CodeInvalid, err.Error(), requestID)
	case errors.Is(err, contract.ErrStalePrecondition), errors.Is(err, contract.ErrIdempotencyConflict):
		s.fail(w, r, CodeConflict, err.Error(), requestID)
	case errors.Is(err, contract.ErrNoResource), errors.Is(err, contract.ErrNoResourceScope):
		s.fail(w, r, CodeInvalid, err.Error(), requestID)
	default:
		s.fail(w, r, CodeInvalid, err.Error(), requestID)
	}
}

// splitPath splits a request path into its segments.
func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// newRequestID returns a random-looking identifier for a request or a new object.
func newRequestID() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return hex.EncodeToString(sum[:8])
}
