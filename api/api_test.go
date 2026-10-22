package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/contract"
	"github.com/sanskarpan/Ghostlight/internal/passport"
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
