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

	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/passport"
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
}

// MemoryEnvironments is an in-memory environment store.
type MemoryEnvironments struct {
	// Environments are the stored environments.
	Environments []Environment
}

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
	// Room is the reviewer room.
	Room *reviewer.Room
	// Passports is the evidence passport registry.
	Passports *passport.Registry
	// Now supplies the current moment.
	Now func() time.Time
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

	principal, err := s.Authenticate(r)
	if err != nil {
		s.fail(w, r, CodeUnauthenticated, "the request carried no usable credentials", requestID)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		s.fail(w, r, CodeInvalid, "the request body could not be read", requestID)
		return
	}
	if err := CheckRequestBody(body); err != nil {
		s.fail(w, r, CodeInvalid, err.Error(), requestID)
		return
	}

	segments := splitPath(r.URL.Path)
	switch {
	case len(segments) == 3 && segments[0] == "v1" && segments[1] == "environments" && r.Method == http.MethodGet:
		s.getEnvironment(w, r, principal, segments[2], requestID)
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
