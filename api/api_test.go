package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/gates"
	"github.com/sanskarpan/Ghostlight/internal/intake"
	"github.com/sanskarpan/Ghostlight/internal/passport"
	"github.com/sanskarpan/Ghostlight/internal/resource"
	"github.com/sanskarpan/Ghostlight/internal/reviewer"
)

var now = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

// server builds a server with the operations declared, one environment and one
// reviewer room.
func server(t *testing.T) *Server {
	t.Helper()
	var ops contract.Registry
	var err error
	add := func(op contract.Operation) {
		ops, err = ops.Register(op)
		if err != nil {
			t.Fatalf("Register(%q): %v", op.ID, err)
		}
	}
	add(contract.Operation{ID: "environments.get", Method: contract.MethodGet, Path: "/environments/{id}",
		CLIName: "environment get", Scope: "repo:acme", Permission: "environment:read"})
	add(contract.Operation{ID: "environments.reviewThreads.list", Method: contract.MethodGet, Path: "/environments/{id}/review-threads",
		CLIName: "environment threads", Scope: "repo:acme", Permission: "environment:read"})
	add(contract.Operation{ID: "environments.reviewThreads.create", Method: contract.MethodPost, Path: "/environments/{id}/review-threads",
		CLIName: "environment thread create", Scope: "repo:acme", Permission: "environment:write"})
	add(contract.Operation{ID: "reviewThreads.findings.create", Method: contract.MethodPost, Path: "/review-threads/{id}/findings",
		CLIName: "finding create", Scope: "repo:acme", Permission: "environment:write"})
	add(contract.Operation{ID: "reviewThreads.findings.carryForward", Method: contract.MethodPost, Path: "/review-threads/{id}/findings/{fid}/carry-forward",
		CLIName: "finding carry-forward", Scope: "repo:acme", Permission: "environment:write"})
	add(contract.Operation{ID: "passports.get", Method: contract.MethodGet, Path: "/passports/{id}",
		CLIName: "passport get", Scope: "repo:acme", Permission: "environment:read"})

	room := reviewer.Room{}
	env := Environment{
		ID: "env-1", Scope: "repo:acme", Version: 7, Generation: 3,
		ExpiresAt: now.Add(24 * time.Hour),
		Actions: []console.RecordedAction{
			{ID: "a1", Phase: console.PhaseArtifactBuild, Outcome: console.OutcomeSucceeded, FinishedAt: now.Add(-time.Hour)},
		},
	}
	return &Server{
		Auth: StaticAuthenticator{Tokens: map[string]contract.Principal{
			"token-ada":    {ID: "ada", Grants: []string{"repo:acme"}, Permissions: []string{"environment:read", "environment:write"}},
			"token-eve":    {ID: "eve", Grants: []string{"repo:other"}, Permissions: []string{"environment:read", "environment:write"}},
			"token-noperm": {ID: "kim", Grants: []string{"repo:acme"}},
		}},
		Operations:   ops,
		Authorizer:   &contract.Authorizer{Registry: ops},
		Environments: MemoryEnvironments{Environments: []Environment{env}},
		Room:         &room,
		Now:          func() time.Time { return now },
	}
}

// do issues a request against the server.
func do(t *testing.T, s *Server, method, path, token string, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, reader)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// problem decodes a problem response.
func problem(t *testing.T, w *httptest.ResponseRecorder) Problem {
	t.Helper()
	var p Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("response is not a problem: %v (%s)", err, w.Body.String())
	}
	return p
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

// A request with no identity is a request with no permissions, which is not the same
// as a request with broad ones.
func TestUnauthenticatedRequestsAreRefused(t *testing.T) {
	s := server(t)
	for _, path := range []string{
		"/v1/environments/env-1",
		"/v1/environments/env-1/review-threads",
		"/v1/passports/passport-1",
	} {
		w := do(t, s, http.MethodGet, path, "", "", nil)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s = %d, want 401", path, w.Code)
		}
		p := problem(t, w)
		if p.Code != CodeUnauthenticated {
			t.Errorf("GET %s code = %q, want %q", path, p.Code, CodeUnauthenticated)
		}
		if p.Retryable {
			t.Error("an unauthenticated request must not be marked retryable")
		}
	}
}

// A body that names a different actor does not change the derived principal: a request
// that can say who it is has no identity at all.
func TestTheActorIsDerivedServerSideAndNotFromTheBody(t *testing.T) {
	s := server(t)
	body := `{"title":"a thread","actor":"eve","principal_id":"eve"}`
	w := do(t, s, http.MethodPost, "/v1/environments/env-1/review-threads", "token-ada", body, map[string]string{
		IdempotencyHeader:  "idem-1",
		PreconditionHeader: "7",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (%s)", w.Code, w.Body.String())
	}
	threads := s.Room.Threads
	if len(threads) != 1 {
		t.Fatalf("threads = %d, want 1", len(threads))
	}
	if threads[0].CreatedBy != "ada" {
		t.Errorf("thread author = %q, want the derived principal ada", threads[0].CreatedBy)
	}
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

// A handler that acts before authorizing is the bug this package exists to prevent.
func TestAnUnauthorizedRequestChangesNothing(t *testing.T) {
	s := server(t)
	body := `{"title":"a thread"}`
	w := do(t, s, http.MethodPost, "/v1/environments/env-1/review-threads", "token-eve", body, map[string]string{
		IdempotencyHeader:  "idem-1",
		PreconditionHeader: "7",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", w.Code, w.Body.String())
	}
	if len(s.Room.Threads) != 0 {
		t.Error("a refused request must not have created a thread")
	}
	p := problem(t, w)
	if p.Code != CodeForbidden {
		t.Errorf("code = %q, want %q", p.Code, CodeForbidden)
	}
	if p.Retryable {
		t.Error("a denial must not be marked retryable")
	}
}

func TestAPrincipalWithoutThePermissionIsRefused(t *testing.T) {
	s := server(t)
	w := do(t, s, http.MethodGet, "/v1/environments/env-1", "token-noperm", "", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Idempotency and preconditions
// ---------------------------------------------------------------------------

func TestAMutationWithoutAnIdempotencyKeyIsRefused(t *testing.T) {
	s := server(t)
	w := do(t, s, http.MethodPost, "/v1/environments/env-1/review-threads", "token-ada", `{"title":"t"}`, map[string]string{
		PreconditionHeader: "7",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "idempotency") {
		t.Errorf("the refusal must name the missing key, got %s", w.Body.String())
	}
}

func TestAMutationWithoutAPreconditionIsRefused(t *testing.T) {
	s := server(t)
	w := do(t, s, http.MethodPost, "/v1/environments/env-1/review-threads", "token-ada", `{"title":"t"}`, map[string]string{
		IdempotencyHeader: "idem-1",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestAStalePreconditionIsAConflict(t *testing.T) {
	s := server(t)
	w := do(t, s, http.MethodPost, "/v1/environments/env-1/review-threads", "token-ada", `{"title":"t"}`, map[string]string{
		IdempotencyHeader:  "idem-1",
		PreconditionHeader: "3",
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
	p := problem(t, w)
	if p.Code != CodeConflict {
		t.Errorf("code = %q, want %q", p.Code, CodeConflict)
	}
	if !p.Retryable {
		t.Error("a conflict must be marked retryable: the world may have moved")
	}
}

// The same key with a different body is a client bug that would otherwise silently do
// the wrong thing.
func TestAnIdempotencyKeyReusedWithADifferentBodyIsRefused(t *testing.T) {
	s := server(t)
	headers := map[string]string{IdempotencyHeader: "idem-1", PreconditionHeader: "7"}
	first := do(t, s, http.MethodPost, "/v1/environments/env-1/review-threads", "token-ada", `{"title":"one"}`, headers)
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d, want 201 (%s)", first.Code, first.Body.String())
	}
	second := do(t, s, http.MethodPost, "/v1/environments/env-1/review-threads", "token-ada", `{"title":"two"}`, headers)
	if second.Code != http.StatusConflict {
		t.Fatalf("second status = %d, want 409 (%s)", second.Code, second.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Response content
// ---------------------------------------------------------------------------

// A response that quietly dropped a secret would look like a successful response
// missing data, which is the failure nobody investigates.
func TestAResponseCarryingForbiddenContentIsRefused(t *testing.T) {
	cases := map[string]any{
		"a provider credential": map[string]string{"note": "AKIAIOSFODNN7EXAMPLE"},
		"a forbidden field":     map[string]string{"terraform_state": "{}"},
		"a secret field":        map[string]string{"token": "abc"},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := CheckResponseContent(body); !errors.Is(err, ErrForbiddenContent) {
				t.Errorf("CheckResponseContent error = %v, want ErrForbiddenContent", err)
			}
		})
	}
}

// The image rule is internal/recipe's, reused rather than reimplemented.
func TestAMutableImageTagIsRefusedAndADigestIsAllowed(t *testing.T) {
	if err := CheckResponseContent(map[string]string{"image": "nginx:latest"}); !errors.Is(err, ErrForbiddenContent) {
		t.Errorf("a mutable tag must be refused, got %v", err)
	}
	if err := CheckResponseContent(map[string]string{"image": "acme/api"}); !errors.Is(err, ErrForbiddenContent) {
		t.Errorf("an untagged name must be refused, got %v", err)
	}
	digest := "acme/api@sha256:" + strings.Repeat("a", 64)
	if err := CheckResponseContent(map[string]string{"image": digest}); err != nil {
		t.Errorf("a digest-pinned image must be allowed, got %v", err)
	}
	// An ordinary word is not an image reference and must not be refused.
	if err := CheckResponseContent(map[string]string{"state": "latest"}); err != nil {
		t.Errorf("an ordinary word must not be treated as an image reference, got %v", err)
	}
}

// No endpoint accepts a manifest: an endpoint that accepts one is a remote execution
// surface wearing a JSON body.
func TestAManifestShapedBodyIsRefused(t *testing.T) {
	cases := []string{
		`{"terraform":"resource {}"}`,
		`{"helm":{"values":{}}}`,
		`{"sql":"DROP TABLE x"}`,
		`{"chaos":{"faults":[]}}`,
	}
	for _, body := range cases {
		if err := CheckRequestBody([]byte(body)); !errors.Is(err, ErrManifestRefused) {
			t.Errorf("CheckRequestBody(%s) error = %v, want ErrManifestRefused", body, err)
		}
	}
	if err := CheckRequestBody([]byte(`{"title":"fine"}`)); err != nil {
		t.Errorf("an ordinary body must be accepted, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

// A cursor the client edited is rejected, and a cursor issued for another collection or
// scope is rejected, because a cursor that carried over between tenants would hand the
// wrong reader the next rows.
func TestCursorsAreOpaqueAndScoped(t *testing.T) {
	cursor := EncodeCursor(Cursor{Collection: "review-threads", Scope: "repo:acme", Offset: 25})
	if cursor == "" {
		t.Fatal("a cursor must be produced")
	}
	if strings.Contains(cursor, "review-threads") {
		t.Error("the cursor must not reveal its contents")
	}
	if _, err := DecodeCursor(cursor, "review-threads", "repo:acme"); err != nil {
		t.Errorf("a fresh cursor must decode: %v", err)
	}
	edited := cursor[:len(cursor)-1] + "A"
	if _, err := DecodeCursor(edited, "review-threads", "repo:acme"); !errors.Is(err, ErrBadCursor) {
		t.Errorf("an edited cursor error = %v, want ErrBadCursor", err)
	}
	if _, err := DecodeCursor(cursor, "other-threads", "repo:acme"); !errors.Is(err, ErrBadCursor) {
		t.Errorf("a cursor for another collection error = %v, want ErrBadCursor", err)
	}
	if _, err := DecodeCursor(cursor, "review-threads", "repo:other"); !errors.Is(err, ErrBadCursor) {
		t.Errorf("a cursor from another scope error = %v, want ErrBadCursor", err)
	}
}

func TestPageSizeIsBounded(t *testing.T) {
	if _, err := PageSize(""); err != nil {
		t.Errorf("an absent page size must default, got %v", err)
	}
	if _, err := PageSize("10"); err != nil {
		t.Errorf("a bounded page size must be accepted, got %v", err)
	}
	if _, err := PageSize("0"); !errors.Is(err, ErrInvalid) {
		t.Errorf("a zero page size error = %v, want ErrInvalid", err)
	}
	if _, err := PageSize("1000"); !errors.Is(err, ErrPageTooLarge) {
		t.Errorf("an over-bound page size error = %v, want ErrPageTooLarge", err)
	}
}

// ---------------------------------------------------------------------------
// The environment view
// ---------------------------------------------------------------------------

// The timeline is read from the recorded actions, so "ready" means something.
func TestTheEnvironmentViewCarriesTheProgressTimeline(t *testing.T) {
	s := server(t)
	w := do(t, s, http.MethodGet, "/v1/environments/env-1", "token-ada", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var view environmentView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatalf("body is not an environment view: %v", err)
	}
	if view.ID != "env-1" || view.Generation != 3 {
		t.Errorf("view = %+v, want the environment", view)
	}
	if len(view.Timeline.Phases) != 5 {
		t.Errorf("timeline has %d phases, want all five", len(view.Timeline.Phases))
	}
	first, ok := view.Timeline.Phase(console.PhaseArtifactBuild)
	if !ok || first.State != console.PhaseComplete {
		t.Errorf("artifact build = %+v, want complete", first)
	}
}

func TestAnUnknownEnvironmentIsNotFound(t *testing.T) {
	s := server(t)
	w := do(t, s, http.MethodGet, "/v1/environments/nope", "token-ada", "", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestAnUnknownRouteIsNotFound(t *testing.T) {
	s := server(t)
	w := do(t, s, http.MethodGet, "/v1/nonsense", "token-ada", "", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// The reviewer room over HTTP
// ---------------------------------------------------------------------------

func TestTheReviewerRoomHappyPathOverHTTP(t *testing.T) {
	s := server(t)

	// Open a thread.
	w := do(t, s, http.MethodPost, "/v1/environments/env-1/review-threads", "token-ada", `{"title":"Login page"}`, map[string]string{
		IdempotencyHeader: "idem-1", PreconditionHeader: "7",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create thread status = %d, want 201 (%s)", w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("body is not a thread: %v", err)
	}
	if created.ID == "" {
		t.Fatal("the created thread must have an identifier")
	}

	// Raise a finding against it.
	w = do(t, s, http.MethodPost, "/v1/review-threads/"+created.ID+"/findings", "token-ada", `{"id":"f1","generation":3,"body":"the error text is unreadable","owner":"ada"}`, map[string]string{
		IdempotencyHeader: "idem-2", PreconditionHeader: "7",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("raise finding status = %d, want 201 (%s)", w.Code, w.Body.String())
	}

	// Carry it forward.
	w = do(t, s, http.MethodPost, "/v1/review-threads/"+created.ID+"/findings/f1/carry-forward", "token-ada", `{"reason":"the same problem exists in the new code"}`, map[string]string{
		IdempotencyHeader: "idem-3", PreconditionHeader: "7",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("carry forward status = %d, want 200 (%s)", w.Code, w.Body.String())
	}

	// The room records it, with the original provenance intact.
	thread, ok := s.Room.Thread(created.ID)
	if !ok {
		t.Fatal("the thread must exist")
	}
	if len(thread.Findings) != 1 {
		t.Fatalf("findings = %v, want one", thread.Findings)
	}
	if thread.Findings[0].State != reviewer.StateCarriedForward {
		t.Errorf("finding state = %q, want carried-forward", thread.Findings[0].State)
	}
	if thread.Findings[0].Provenance.Generation != 3 {
		t.Errorf("provenance generation = %d, want 3", thread.Findings[0].Provenance.Generation)
	}

	// And the list endpoint shows it.
	w = do(t, s, http.MethodGet, "/v1/environments/env-1/review-threads", "token-ada", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "the error text is unreadable") {
		t.Errorf("the list must carry the finding, got %s", w.Body.String())
	}
}

// A carry-forward without a reason is refused: a carry-forward is a judgement that a
// specific observation still holds, and it is worth recording why.
func TestACarryForwardWithoutAReasonIsRefused(t *testing.T) {
	s := server(t)
	w := do(t, s, http.MethodPost, "/v1/environments/env-1/review-threads", "token-ada", `{"title":"t"}`, map[string]string{
		IdempotencyHeader: "idem-1", PreconditionHeader: "7",
	})
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	w = do(t, s, http.MethodPost, "/v1/review-threads/"+created.ID+"/findings", "token-ada", `{"id":"f1","generation":3,"body":"b"}`, map[string]string{
		IdempotencyHeader: "idem-2", PreconditionHeader: "7",
	})
	w = do(t, s, http.MethodPost, "/v1/review-threads/"+created.ID+"/findings/f1/carry-forward", "token-ada", `{}`, map[string]string{
		IdempotencyHeader: "idem-3", PreconditionHeader: "7",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// The passport
// ---------------------------------------------------------------------------

func TestAPassportIsServedWithItsDigest(t *testing.T) {
	s := server(t)
	registry, err := passport.Registry{}.AddKey(passport.Key{ID: "signer-1", PublicKey: "ed25519:abc", ValidFrom: now.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	registry, issued, err := registry.Issue("passport-1", passport.Manifest{
		EnvironmentID:      "env-1",
		Generation:         3,
		CandidateDigest:    "sha256:candidate",
		Completeness:       passport.CompletenessComplete,
		Confidence:         "high",
		CleanupObservation: "all resources verified absent",
		Evidence: []passport.EvidenceRef{
			{GateRunID: "run-1", Invariant: "isolation", Result: "pass", Signer: "harness", At: now},
		},
	}, "repo:acme", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	s.Passports = &registry

	w := do(t, s, http.MethodGet, "/v1/passports/passport-1", "token-ada", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), issued.ManifestDigest) {
		t.Errorf("the response must carry the manifest digest, got %s", w.Body.String())
	}
	// The exported evidence content is sanitized. The gate run identifier is not
	// a secret and stays, so a recipient can look it up; the content does not.
	if !strings.Contains(w.Body.String(), "[redacted]") {
		t.Errorf("the exported evidence must be sanitized, got %s", w.Body.String())
	}
}

func TestAPassportInAnotherScopeIsRefused(t *testing.T) {
	s := server(t)
	registry, err := passport.Registry{}.AddKey(passport.Key{ID: "signer-1", PublicKey: "ed25519:abc", ValidFrom: now.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	registry, _, err = registry.Issue("passport-1", passport.Manifest{
		EnvironmentID:      "env-1",
		Generation:         3,
		CandidateDigest:    "sha256:candidate",
		Completeness:       passport.CompletenessComplete,
		Confidence:         "high",
		CleanupObservation: "all resources verified absent",
		Evidence: []passport.EvidenceRef{
			{GateRunID: "run-1", Invariant: "isolation", Result: "pass", Signer: "harness", At: now},
		},
	}, "repo:other", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	s.Passports = &registry
	w := do(t, s, http.MethodGet, "/v1/passports/passport-1", "token-ada", "", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Problems
// ---------------------------------------------------------------------------

// A client branches on the code and never on the prose, so the code is stable and the
// request id is always present.
func TestProblemsCarryAStableCodeAndTheRequestID(t *testing.T) {
	s := server(t)
	w := do(t, s, http.MethodGet, "/v1/environments/nope", "token-ada", "", nil)
	p := problem(t, w)
	if p.Code != CodeNotFound {
		t.Errorf("code = %q, want %q", p.Code, CodeNotFound)
	}
	if p.RequestID == "" {
		t.Error("a problem must carry the request id")
	}
	if p.Type == "" || p.Title == "" {
		t.Error("a problem must carry a type and a title")
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("content type = %q, want application/problem+json", ct)
	}
}

// A denial is never retryable, because retrying a denied request is a loop.
func TestTheRetryGuidanceIsHonest(t *testing.T) {
	cases := map[Code]bool{
		CodeUnauthenticated:  false,
		CodeForbidden:        false,
		CodeNotFound:         false,
		CodeInvalid:          false,
		CodeForbiddenContent: false,
		CodeConflict:         true,
		CodeInternal:         true,
	}
	for code, wantRetryable := range cases {
		p := NewProblem(code, "detail", "/instance", "req-1")
		if p.Retryable != wantRetryable {
			t.Errorf("%q retryable = %v, want %v", code, p.Retryable, wantRetryable)
		}
		if p.Status == 0 {
			t.Errorf("%q has no status", code)
		}
	}
}

// createServer builds a server wired for the lifecycle family: an empty
// store, the creator and destroyer capabilities installed, and the operations
// the family needs declared.
func createServer(t *testing.T) (*Server, *MemoryEnvironments) {
	t.Helper()
	var ops contract.Registry
	var err error
	add := func(op contract.Operation) {
		ops, err = ops.Register(op)
		if err != nil {
			t.Fatalf("Register(%q): %v", op.ID, err)
		}
	}
	add(contract.Operation{ID: "environments.destroy", Method: contract.MethodPost, Path: "/environments/{id}/destroy",
		CLIName: "environment destroy", Scope: "repo:acme", Permission: "environment:write"})
	add(contract.Operation{ID: "environments.resources", Method: contract.MethodGet, Path: "/environments/{id}/resources",
		CLIName: "environment resources", Scope: "repo:acme", Permission: "environment:read"})
	add(contract.Operation{ID: "environments.extend", Method: contract.MethodPost, Path: "/environments/{id}/extend",
		CLIName: "environment extend", Scope: "repo:acme", Permission: "environment:write"})
	add(contract.Operation{ID: "environments.generations.create", Method: contract.MethodPost, Path: "/environments/{id}/generations",
		CLIName: "environment generation create", Scope: "repo:acme", Permission: "environment:write"})
	add(contract.Operation{ID: "environments.gates.request", Method: contract.MethodPost, Path: "/environments/{id}/gates",
		CLIName: "gate request", Scope: "repo:acme", Permission: "environment:write"})
	add(contract.Operation{ID: "gates.get", Method: contract.MethodGet, Path: "/gates/{run_id}",
		CLIName: "gate get", Scope: "repo:acme", Permission: "environment:read"})
	store := &MemoryEnvironments{}
	s := &Server{
		Auth: StaticAuthenticator{Tokens: map[string]contract.Principal{
			"token-ada":     {ID: "ada", Grants: []string{"repo:acme"}, Permissions: []string{"environment:read", "environment:write"}},
			"token-nogrant": {ID: "noa", Grants: nil, Permissions: []string{"environment:write"}},
		}},
		Operations:   ops,
		Authorizer:   &contract.Authorizer{Registry: ops},
		Environments: store,
		Creator:      store,
		Destroyer:    store,
		Updater:      store,
		Ledger:       resource.NewMemoryLedger(func() time.Time { return now }),
		Gates:        gates.NewStore(func() time.Time { return now }),
		Now:          func() time.Time { return now },
	}
	return s, store
}

const validCreateBody = `{"repository_id":12345,"pull_request_number":142,
"source_sha":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
"recipe_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
"configuration_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
"resource_profile":"preview-small","requested_ttl_seconds":86400}`

// TestCreateEnvironmentAnswersAcceptedWithIdentity: the §1 contract — a
// 202 carrying the immutable identity and the status URL, never secret values.
func TestCreateEnvironmentAnswersAcceptedWithIdentity(t *testing.T) {
	s, store := createServer(t)
	rec := do(t, s, http.MethodPost, "/v1/environments", "token-ada", validCreateBody,
		map[string]string{"Idempotency-Key": "key-1"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body: %s)", rec.Code, rec.Body.String())
	}
	var out struct {
		EnvironmentID string `json:"environment_id"`
		Slug          string `json:"slug"`
		Generation    int    `json:"generation"`
		StatusURL     string `json:"status_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.EnvironmentID == "" || out.Slug == "" || out.Generation != 1 {
		t.Fatalf("identity = %+v", out)
	}
	if out.StatusURL != "/v1/environments/"+out.EnvironmentID {
		t.Errorf("status_url = %q, want the environment's own path", out.StatusURL)
	}
	env, ok := store.Get(out.EnvironmentID)
	if !ok {
		t.Fatal("the store does not hold the created environment")
	}
	if env.Scope != "repo:acme" {
		t.Errorf("scope = %q, want the caller's own grant (derived server-side)", env.Scope)
	}
	if !env.ExpiresAt.Equal(now.Add(86400 * time.Second)) {
		t.Errorf("expires_at = %v, want the requested TTL from the server's clock", env.ExpiresAt)
	}
}

// TestCreateEnvironmentReplaysIdempotently: the same key with the same body
// returns the first result; the same key with a different body is a refused
// retry, not a second creation.
func TestCreateEnvironmentReplaysIdempotently(t *testing.T) {
	s, _ := createServer(t)
	first := do(t, s, http.MethodPost, "/v1/environments", "token-ada", validCreateBody,
		map[string]string{"Idempotency-Key": "key-1"})
	if first.Code != http.StatusAccepted {
		t.Fatalf("first: %d", first.Code)
	}
	replay := do(t, s, http.MethodPost, "/v1/environments", "token-ada", validCreateBody,
		map[string]string{"Idempotency-Key": "key-1"})
	if replay.Code != http.StatusAccepted {
		t.Fatalf("replay: %d", replay.Code)
	}
	if replay.Body.String() != first.Body.String() {
		t.Errorf("a replay must return the first result, got %s vs %s", replay.Body.String(), first.Body.String())
	}
	other := do(t, s, http.MethodPost, "/v1/environments", "token-ada",
		strings.Replace(validCreateBody, "142", "143", 1),
		map[string]string{"Idempotency-Key": "key-1"})
	if other.Code != http.StatusConflict {
		t.Fatalf("same key with a different body: %d, want 409", other.Code)
	}
}

// TestCreateEnvironmentValidatesTheRequestShape: values are assertions to
// validate. A digest that does not parse pins nothing; a TTL outside the
// platform's bounds is a client preference, not policy.
func TestCreateEnvironmentValidatesTheRequestShape(t *testing.T) {
	s, _ := createServer(t)
	cases := map[string]string{
		"bad source sha":      strings.Replace(validCreateBody, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", "zzz", 1),
		"bad recipe digest":   strings.Replace(validCreateBody, `"recipe_digest":"sha256:aaaa`, `"recipe_digest":"sha512:aaaa`, 1),
		"unknown profile":     strings.Replace(validCreateBody, "preview-small", "gpu-monster", 1),
		"ttl over the bound":  strings.Replace(validCreateBody, "86400", "864000", 1),
		"ttl under the bound": strings.Replace(validCreateBody, "86400", "10", 1),
		"no repository":       strings.Replace(validCreateBody, `"repository_id":12345`, `"repository_id":0`, 1),
	}
	for name, body := range cases {
		rec := do(t, s, http.MethodPost, "/v1/environments", "token-ada", body,
			map[string]string{"Idempotency-Key": "key-" + name})
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status = %d, want 422 (body: %s)", name, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"unprocessable"`) {
			t.Errorf("%s: problem code is not unprocessable: %s", name, rec.Body.String())
		}
	}
	missing := do(t, s, http.MethodPost, "/v1/environments", "token-ada", validCreateBody, nil)
	if missing.Code != http.StatusBadRequest || !strings.Contains(missing.Body.String(), "Idempotency-Key") {
		t.Errorf("a create without an idempotency key: %d %s", missing.Code, missing.Body.String())
	}
}

// TestCreateEnvironmentQuotaAnswers429: §5 reserves 429 for quota, and the
// code must say quota, not a generic refusal.
func TestCreateEnvironmentQuotaAnswers429(t *testing.T) {
	s, _ := createServer(t)
	first := do(t, s, http.MethodPost, "/v1/environments", "token-ada", validCreateBody,
		map[string]string{"Idempotency-Key": "key-1"})
	if first.Code != http.StatusAccepted {
		t.Fatalf("first create: %d", first.Code)
	}
	second := do(t, s, http.MethodPost, "/v1/environments", "token-ada",
		strings.Replace(validCreateBody, "142", "143", 1),
		map[string]string{"Idempotency-Key": "key-2"})
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second create: %d, want 429", second.Code)
	}
	if !strings.Contains(second.Body.String(), `"quota"`) {
		t.Errorf("the problem code must be quota: %s", second.Body.String())
	}
}

// TestCreateEnvironmentRefusesACredentialWithNoGrants: the scope is the
// caller's own grant; a credential with none owns no scope for an
// environment to belong to.
func TestCreateEnvironmentRefusesACredentialWithNoGrants(t *testing.T) {
	s, _ := createServer(t)
	rec := do(t, s, http.MethodPost, "/v1/environments", "token-nogrant", validCreateBody,
		map[string]string{"Idempotency-Key": "key-1"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestDestroyEnvironmentSetsDesiredAbsent: a 202 whose follow-up GET answers
// 404 — gone, not flagged.
func TestDestroyEnvironmentSetsDesiredAbsent(t *testing.T) {
	s, store := createServer(t)
	store.Add(Environment{ID: "env-1", Scope: "repo:acme", Version: 3, Generation: 1})

	rec := do(t, s, http.MethodPost, "/v1/environments/env-1/destroy", "token-ada", "",
		map[string]string{"Idempotency-Key": "key-1", "If-Match": "3"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	if _, ok := store.Get("env-1"); ok {
		t.Fatal("the destroyed environment is still in the store")
	}
	after := do(t, s, http.MethodGet, "/v1/environments/env-1", "token-ada", "", nil)
	if after.Code != http.StatusNotFound {
		t.Errorf("GET after destroy: %d, want 404 — gone says gone", after.Code)
	}
}

// TestDestroyRequiresPreconditionAndKey: the §1 contract — mutations are
// idempotent and conditional, and the refusal for a stale version is 409.
func TestDestroyRequiresPreconditionAndKey(t *testing.T) {
	s, store := createServer(t)
	store.Add(Environment{ID: "env-1", Scope: "repo:acme", Version: 3, Generation: 1})

	noKey := do(t, s, http.MethodPost, "/v1/environments/env-1/destroy", "token-ada", "",
		map[string]string{"If-Match": "3"})
	if noKey.Code != http.StatusBadRequest {
		t.Errorf("destroy without an idempotency key: %d, want 400", noKey.Code)
	}
	stale := do(t, s, http.MethodPost, "/v1/environments/env-1/destroy", "token-ada", "",
		map[string]string{"Idempotency-Key": "key-1", "If-Match": "2"})
	if stale.Code != http.StatusConflict {
		t.Errorf("destroy with a stale version: %d, want 409", stale.Code)
	}
	if _, ok := store.Get("env-1"); !ok {
		t.Fatal("a refused destroy removed the environment")
	}
	outsider := do(t, s, http.MethodPost, "/v1/environments/env-1/destroy", "token-ada", "",
		map[string]string{"Idempotency-Key": "key-2", "If-Match": "9"})
	if outsider.Code == http.StatusAccepted {
		t.Error("a destroy with a wrong version succeeded")
	}
}

// TestResourcesShowOwnershipAndRedactCredentials: the safe inventory answers
// the environment's own allocations with cleanup state, and the credential
// reference is visibly redacted — a client must not mistake absence for
// having been checked.
func TestResourcesShowOwnershipAndRedactCredentials(t *testing.T) {
	s, store := createServer(t)
	store.Add(Environment{ID: "env-1", Scope: "repo:acme", Version: 1, Generation: 2})
	if err := s.Ledger.Record(context.Background(), resource.Allocation{
		ID: "alloc-1", EnvironmentID: "env-1", Generation: 2,
		Kind: "database", LogicalKey: "primary",
		ProviderRef:   map[string]string{"native_id": "nat-db-1"},
		CredentialRef: "secret://ghostlight/env-1/database/primary",
		State:         resource.StateActive, CreatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	// Another environment's allocation must not appear in env-1's inventory.
	if err := s.Ledger.Record(context.Background(), resource.Allocation{
		ID: "alloc-2", EnvironmentID: "env-other", Generation: 1,
		Kind: "topic", LogicalKey: "events",
		ProviderRef: map[string]string{"native_id": "nat-topic-1"},
		State:       resource.StateActive, CreatedAt: now,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	rec := do(t, s, http.MethodGet, "/v1/environments/env-1/resources", "token-ada", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Items []struct {
			ID            string            `json:"id"`
			Kind          string            `json:"kind"`
			LogicalKey    string            `json:"logical_key"`
			Generation    uint64            `json:"generation"`
			State         string            `json:"state"`
			ProviderRef   map[string]string `json:"provider_ref"`
			CredentialRef string            `json:"credential_ref"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Items) != 1 {
		t.Fatalf("items = %d, want only the environment's own allocation", len(out.Items))
	}
	item := out.Items[0]
	if item.ID != "alloc-1" || item.Kind != "database" || item.Generation != 2 || item.State != "active" {
		t.Errorf("inventory item = %+v", item)
	}
	if item.ProviderRef["native_id"] != "nat-db-1" {
		t.Errorf("provider ref = %v", item.ProviderRef)
	}
	if item.CredentialRef != "[redacted]" {
		t.Errorf("credential_ref = %q, want the visible redaction", item.CredentialRef)
	}
	if strings.Contains(rec.Body.String(), "secret://") {
		t.Error("the response carries a credential reference")
	}
}

// TestResourcesOfAnUnknownEnvironmentAnswer404: an inventory is bound to an
// environment that exists, and the route answers like the other family
// members do.
func TestResourcesOfAnUnknownEnvironmentAnswer404(t *testing.T) {
	s, _ := createServer(t)
	rec := do(t, s, http.MethodGet, "/v1/environments/env-nope/resources", "token-ada", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestExtendMovesTheExpiryAndTheVersion: a bounded extension applies as one
// write and names the version the next mutation's precondition must carry.
func TestExtendMovesTheExpiryAndTheVersion(t *testing.T) {
	s, store := createServer(t)
	store.Add(Environment{ID: "env-1", Scope: "repo:acme", Version: 4, Generation: 1,
		ExpiresAt: now.Add(2 * time.Hour)})

	rec := do(t, s, http.MethodPost, "/v1/environments/env-1/extend", "token-ada",
		`{"requested_ttl_seconds":3600}`,
		map[string]string{"Idempotency-Key": "key-1", "If-Match": "4"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	env, ok := store.Get("env-1")
	if !ok {
		t.Fatal("the environment vanished")
	}
	if !env.ExpiresAt.Equal(now.Add(3 * time.Hour)) {
		t.Errorf("expires_at = %v, want the old expiry plus the extension", env.ExpiresAt)
	}
	if env.Version != 5 {
		t.Errorf("version = %d, want 5 — the response names the version the next mutation preconditions on", env.Version)
	}
	if !strings.Contains(rec.Body.String(), `"resource_version":5`) {
		t.Errorf("the response does not name the new version: %s", rec.Body.String())
	}
}

// TestExtendReplaysIdempotently: the same key with the same body returns the
// recorded result and must not extend twice — a retried extension that
// applied twice would quietly hand out double the time.
func TestExtendReplaysIdempotently(t *testing.T) {
	s, store := createServer(t)
	store.Add(Environment{ID: "env-1", Scope: "repo:acme", Version: 4, Generation: 1,
		ExpiresAt: now.Add(2 * time.Hour)})

	first := do(t, s, http.MethodPost, "/v1/environments/env-1/extend", "token-ada",
		`{"requested_ttl_seconds":3600}`,
		map[string]string{"Idempotency-Key": "key-1", "If-Match": "4"})
	if first.Code != http.StatusOK {
		t.Fatalf("first: %d", first.Code)
	}
	// The replay carries the SAME precondition the first attempt carried —
	// the version has since moved, and the replay must still answer with the
	// recorded result rather than a 409 against it.
	replay := do(t, s, http.MethodPost, "/v1/environments/env-1/extend", "token-ada",
		`{"requested_ttl_seconds":3600}`,
		map[string]string{"Idempotency-Key": "key-1", "If-Match": "4"})
	if replay.Code != http.StatusOK {
		t.Fatalf("replay: %d (body: %s)", replay.Code, replay.Body.String())
	}
	if replay.Body.String() != first.Body.String() {
		t.Errorf("the replay must return the recorded result")
	}
	env, _ := store.Get("env-1")
	if !env.ExpiresAt.Equal(now.Add(3 * time.Hour)) {
		t.Errorf("the replay applied a second time: expires_at = %v", env.ExpiresAt)
	}
	other := do(t, s, http.MethodPost, "/v1/environments/env-1/extend", "token-ada",
		`{"requested_ttl_seconds":7200}`,
		map[string]string{"Idempotency-Key": "key-1", "If-Match": "5"})
	if other.Code != http.StatusConflict {
		t.Errorf("same key, different body: %d, want 409", other.Code)
	}
}

// TestExtendRefusesPolicyViolations: below the floor and past the ceiling
// are both 422 — the platform's TTL is bounded policy.
func TestExtendRefusesPolicyViolations(t *testing.T) {
	s, store := createServer(t)
	store.Add(Environment{ID: "env-1", Scope: "repo:acme", Version: 1, Generation: 1,
		ExpiresAt: now.Add(23 * time.Hour)})

	below := do(t, s, http.MethodPost, "/v1/environments/env-1/extend", "token-ada",
		`{"requested_ttl_seconds":60}`,
		map[string]string{"Idempotency-Key": "key-1", "If-Match": "1"})
	if below.Code != http.StatusUnprocessableEntity {
		t.Errorf("below the floor: %d, want 422", below.Code)
	}
	// 23h + 4h crosses the 24h ceiling from the server's now.
	above := do(t, s, http.MethodPost, "/v1/environments/env-1/extend", "token-ada",
		`{"requested_ttl_seconds":14400}`,
		map[string]string{"Idempotency-Key": "key-2", "If-Match": "1"})
	if above.Code != http.StatusUnprocessableEntity {
		t.Errorf("past the ceiling: %d, want 422", above.Code)
	}
	env, _ := store.Get("env-1")
	if env.Version != 1 {
		t.Errorf("a refused extension must not move the version, got %d", env.Version)
	}
}

// TestExtendRequiresKeyAndPrecondition: the §1 contract, same as destroy.
func TestExtendRequiresKeyAndPrecondition(t *testing.T) {
	s, store := createServer(t)
	store.Add(Environment{ID: "env-1", Scope: "repo:acme", Version: 4, Generation: 1})

	noKey := do(t, s, http.MethodPost, "/v1/environments/env-1/extend", "token-ada",
		`{"requested_ttl_seconds":3600}`, map[string]string{"If-Match": "4"})
	if noKey.Code != http.StatusBadRequest {
		t.Errorf("no key: %d, want 400", noKey.Code)
	}
	stale := do(t, s, http.MethodPost, "/v1/environments/env-1/extend", "token-ada",
		`{"requested_ttl_seconds":3600}`,
		map[string]string{"Idempotency-Key": "key-1", "If-Match": "3"})
	if stale.Code != http.StatusConflict {
		t.Errorf("stale version: %d, want 409", stale.Code)
	}
	if _, ok := store.Get("env-1"); !ok {
		t.Fatal("the environment vanished on a refused extend")
	}
}

// webhookStore is the durable delivery inbox the webhook test drives: an
// idempotent insert on (provider, delivery id), reporting whether the row
// was new — the contract the intake store holds.
type webhookStore struct {
	mu   sync.Mutex
	seen map[string]intake.Stored
	fail bool
}

func (f *webhookStore) Insert(_ context.Context, s intake.Stored) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return false, errors.New("store down")
	}
	if _, dup := f.seen[s.DeliveryID]; dup {
		return false, nil
	}
	f.seen[s.DeliveryID] = s
	return true, nil
}

// webhookServer builds a server wired for the webhook route, with the HMAC
// secret the test signs deliveries with.
func webhookServer(t *testing.T) (*Server, *webhookStore, []byte) {
	t.Helper()
	secret := []byte("webhook-secret-for-tests")
	store := &webhookStore{seen: map[string]intake.Stored{}}
	s := &Server{
		Auth:   StaticAuthenticator{Tokens: map[string]contract.Principal{}},
		Intake: intake.NewService("github", intake.HMACVerifier{Secret: secret}, store, intake.ReplayGuard{Now: func() time.Time { return now }}),
		Now:    func() time.Time { return now },
	}
	return s, store, secret
}

// sign computes the signature header a provider would send over the exact
// bytes.
func sign(body []byte, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// TestWebhookAdmitsAVerifiedDeliveryIntoTheDurableInbox: the signature is the
// identity — no bearer token exists — and a verified delivery lands in the
// inbox with its payload digest and retention expiry.
func TestWebhookAdmitsAVerifiedDeliveryIntoTheDurableInbox(t *testing.T) {
	s, store, secret := webhookServer(t)
	payload := []byte(`{"action":"opened","pull_request":{"number":142}}`)
	rec := do(t, s, http.MethodPost, "/v1/integrations/github/events", "",
		string(payload), map[string]string{
			"X-GitHub-Delivery":                    "d-1",
			"X-GitHub-Event":                       "pull_request",
			"X-GitHub-Repository":                  "acme/app",
			"X-Hub-Signature-256":                  sign(payload, secret),
			"X-GitHub-Hook-Installation-Target-ID": "98765",
		})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	store.mu.Lock()
	stored, ok := store.seen["d-1"]
	store.mu.Unlock()
	if !ok {
		t.Fatal("the delivery never reached the durable inbox")
	}
	if stored.EventType != "pull_request" || stored.Repository != "acme/app" {
		t.Errorf("stored = %+v", stored)
	}
	if stored.PayloadSHA != intake.Digest(payload) {
		t.Error("the recorded digest is not the digest of the exact bytes received")
	}
	if !strings.Contains(rec.Body.String(), `"duplicate":false`) {
		t.Errorf("the first delivery is not a duplicate: %s", rec.Body.String())
	}
}

// TestWebhookRefusesUnverifiablePayloads: a bad signature, a missing
// signature, and empty bytes are all refused before anything is stored —
// a payload that fails verification is never persisted.
func TestWebhookRefusesUnverifiablePayloads(t *testing.T) {
	s, store, secret := webhookServer(t)
	payload := []byte(`{"action":"opened"}`)

	cases := []struct {
		name     string
		body     string
		headers  map[string]string
		wantCode int
	}{
		{"wrong signature", string(payload), map[string]string{
			"X-GitHub-Delivery": "d-1", "X-GitHub-Event": "pull_request",
			"X-Hub-Signature-256": sign([]byte(`{"tampered":true}`), secret),
		}, http.StatusUnauthorized},
		{"absent signature", string(payload), map[string]string{
			"X-GitHub-Delivery": "d-2", "X-GitHub-Event": "pull_request",
		}, http.StatusUnauthorized},
		{"empty payload", "", map[string]string{
			"X-GitHub-Delivery": "d-3", "X-GitHub-Event": "pull_request",
			"X-Hub-Signature-256": sign([]byte(""), secret),
		}, http.StatusUnauthorized},
		{"missing delivery id", string(payload), map[string]string{
			"X-GitHub-Event":      "pull_request",
			"X-Hub-Signature-256": sign(payload, secret),
		}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		rec := do(t, s, http.MethodPost, "/v1/integrations/github/events", "", tc.body, tc.headers)
		if rec.Code != tc.wantCode {
			t.Errorf("%s: status = %d, want %d (body: %s)", tc.name, rec.Code, tc.wantCode, rec.Body.String())
		}
	}
	store.mu.Lock()
	n := len(store.seen)
	store.mu.Unlock()
	if n != 0 {
		t.Errorf("the inbox holds %d rows after refused deliveries; a payload that fails verification is never stored", n)
	}
}

// TestWebhookRedeliveryIsANoOpThatStillAnswers: the row was written before
// the first acknowledgement, so a redelivery is a no-op that still answers
// 202 — and never becomes a second run.
func TestWebhookRedeliveryIsANoOpThatStillAnswers(t *testing.T) {
	s, _, secret := webhookServer(t)
	payload := []byte(`{"action":"synchronize"}`)
	headers := map[string]string{
		"X-GitHub-Delivery":   "d-1",
		"X-GitHub-Event":      "pull_request",
		"X-Hub-Signature-256": sign(payload, secret),
	}
	first := do(t, s, http.MethodPost, "/v1/integrations/github/events", "", string(payload), headers)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first: %d", first.Code)
	}
	again := do(t, s, http.MethodPost, "/v1/integrations/github/events", "", string(payload), headers)
	if again.Code != http.StatusAccepted {
		t.Fatalf("redelivery: %d", again.Code)
	}
	if !strings.Contains(again.Body.String(), `"duplicate":true`) {
		t.Errorf("the redelivery must say so: %s", again.Body.String())
	}
}

// TestWebhookStoreFailureIsNotAcknowledged: a verified delivery whose row
// could not be persisted answers 500 so the provider redelivers — acking
// would lose the event permanently.
func TestWebhookStoreFailureIsNotAcknowledged(t *testing.T) {
	s, store, secret := webhookServer(t)
	store.mu.Lock()
	store.fail = true
	store.mu.Unlock()
	payload := []byte(`{"action":"closed"}`)
	rec := do(t, s, http.MethodPost, "/v1/integrations/github/events", "", string(payload), map[string]string{
		"X-GitHub-Delivery":   "d-1",
		"X-GitHub-Event":      "pull_request",
		"X-Hub-Signature-256": sign(payload, secret),
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestCreateGenerationNamesAnExactCandidateAndSerializesRollout: a new
// generation is an identity — the digests are recorded on the row — and the
// resource-version precondition is the rollout's serialization.
func TestCreateGenerationNamesAnExactCandidateAndSerializesRollout(t *testing.T) {
	s, store := createServer(t)
	store.Add(Environment{ID: "env-1", Scope: "repo:acme", Version: 6, Generation: 2})

	rec := do(t, s, http.MethodPost, "/v1/environments/env-1/generations", "token-ada",
		`{"source_sha":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
		"recipe_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"configuration_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`,
		map[string]string{"Idempotency-Key": "key-1", "If-Match": "6"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	env, _ := store.Get("env-1")
	if env.Generation != 3 {
		t.Errorf("generation = %d, want 3", env.Generation)
	}
	if env.Version != 7 {
		t.Errorf("version = %d, want 7 — the response names the next generation's precondition", env.Version)
	}
	if env.SourceSHA == "" || env.RecipeDigest == "" || env.ConfigurationDigest == "" {
		t.Error("the exact candidate set was not recorded on the row")
	}
	if !strings.Contains(rec.Body.String(), `"generation":3`) {
		t.Errorf("the response does not name the new generation: %s", rec.Body.String())
	}

	// The rollout is serialized: a second attempt against the version the
	// first one superseded conflicts, rather than racing the first.
	loser := do(t, s, http.MethodPost, "/v1/environments/env-1/generations", "token-ada",
		`{"source_sha":"b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0a1",
		"recipe_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"configuration_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`,
		map[string]string{"Idempotency-Key": "key-2", "If-Match": "6"})
	if loser.Code != http.StatusConflict {
		t.Errorf("a generation against a superseded version: %d, want 409", loser.Code)
	}
}

// TestCreateGenerationValidatesTheCandidateSet: a digest that does not parse
// pins nothing, and an unparseable generation is refused, not guessed.
func TestCreateGenerationValidatesTheCandidateSet(t *testing.T) {
	s, store := createServer(t)
	store.Add(Environment{ID: "env-1", Scope: "repo:acme", Version: 1, Generation: 1})

	bad := do(t, s, http.MethodPost, "/v1/environments/env-1/generations", "token-ada",
		`{"source_sha":"nope",
		"recipe_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"configuration_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`,
		map[string]string{"Idempotency-Key": "key-1", "If-Match": "1"})
	if bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a bad source sha: %d, want 422", bad.Code)
	}
	env, _ := store.Get("env-1")
	if env.Generation != 1 || env.Version != 1 {
		t.Errorf("a refused generation moved the row: generation=%d version=%d", env.Generation, env.Version)
	}
	unknown := do(t, s, http.MethodPost, "/v1/environments/env-nope/generations", "token-ada",
		`{"source_sha":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
		"recipe_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"configuration_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`,
		map[string]string{"Idempotency-Key": "key-2", "If-Match": "1"})
	if unknown.Code != http.StatusNotFound {
		t.Errorf("a generation for an unknown environment: %d, want 404", unknown.Code)
	}
}

// TestRequestingAGateRunBindsItToTheExactGeneration: the candidate digest is
// computed by the server from the row's recorded candidate set, the run
// binds the generation it was requested against, and the record is honest
// about being unsigned.
func TestRequestingAGateRunBindsItToTheExactGeneration(t *testing.T) {
	s, store := createServer(t)
	store.Add(Environment{ID: "env-1", Scope: "repo:acme", Version: 2, Generation: 3,
		SourceSHA:           "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
		RecipeDigest:        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ConfigurationDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"})

	rec := do(t, s, http.MethodPost, "/v1/environments/env-1/gates", "token-ada",
		`{"kind":"isolation","policy_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`,
		map[string]string{"Idempotency-Key": "key-1", "If-Match": "2"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	var out struct {
		RunID      string `json:"run_id"`
		State      string `json:"state"`
		Generation uint64 `json:"generation"`
		StatusURL  string `json:"status_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.State != "requested" || out.Generation != 3 {
		t.Fatalf("run = %+v", out)
	}
	if out.StatusURL != "/v1/gates/"+out.RunID {
		t.Errorf("status_url = %q", out.StatusURL)
	}

	// GET answers the §3 shape as it IS: no result, no invariant outcomes,
	// nothing a trusted agent has not signed.
	got := do(t, s, http.MethodGet, "/v1/gates/"+out.RunID, "token-ada", "", nil)
	if got.Code != http.StatusOK {
		t.Fatalf("GET status = %d (body: %s)", got.Code, got.Body.String())
	}
	var run gates.Run
	if err := json.Unmarshal(got.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	if run.State != gates.StateRequested || run.Result != "" || run.ObservationsComplete {
		t.Fatalf("a requested run claimed signed facts: %+v", run)
	}
	// The candidate digest is the server's own computation over the row's
	// exact candidate set.
	canonical := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0\n" +
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sum := sha256.Sum256([]byte(canonical))
	want := "sha256:" + hex.EncodeToString(sum[:])
	if run.CandidateDigest != want {
		t.Errorf("candidate_digest = %q, want the server's computation %q", run.CandidateDigest, want)
	}
}

// TestTheGateCatalogRefusesUndefinedGates: a gate nobody defined is a
// string, and a string is not a gate.
func TestTheGateCatalogRefusesUndefinedGates(t *testing.T) {
	s, store := createServer(t)
	store.Add(Environment{ID: "env-1", Scope: "repo:acme", Version: 1, Generation: 1})
	rec := do(t, s, http.MethodPost, "/v1/environments/env-1/gates", "token-ada",
		`{"kind":"vibes"}`,
		map[string]string{"Idempotency-Key": "key-1", "If-Match": "1"})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not in the catalog") {
		t.Errorf("the refusal does not name the catalog: %s", rec.Body.String())
	}
}

// TestAGateRunOfAnotherScopeIsNotReadable: the run's scope is what a
// reader's grants must cover; eve's grant does not reach repo:acme.
func TestAGateRunOfAnotherScopeIsNotReadable(t *testing.T) {
	s, store := createServer(t)
	store.Add(Environment{ID: "env-1", Scope: "repo:acme", Version: 1, Generation: 1})
	run, err := s.Gates.Request("env-1", "repo:acme", 1, gates.KindCleanup,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	// token-eve authenticates but covers only repo:other.
	s.Auth = StaticAuthenticator{Tokens: map[string]contract.Principal{
		"token-ada": {ID: "ada", Grants: []string{"repo:acme"}, Permissions: []string{"environment:read", "environment:write"}},
		"token-eve": {ID: "eve", Grants: []string{"repo:other"}, Permissions: []string{"environment:read"}},
	}}
	got := do(t, s, http.MethodGet, "/v1/gates/"+run.ID, "token-eve", "", nil)
	if got.Code != http.StatusForbidden {
		t.Fatalf("eve's read: %d, want 403", got.Code)
	}
}
