package contract

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

// registry declares the operations the platform actually exposes, in the shape the
// API documentation describes.
func registry(t *testing.T) Registry {
	t.Helper()
	var r Registry
	var err error
	add := func(op Operation) {
		r, err = r.Register(op)
		if err != nil {
			t.Fatalf("Register(%q): %v", op.ID, err)
		}
	}
	add(Operation{
		ID: "environments.create", Method: MethodPost, Path: "/environments",
		CLIName: "environment create", Scope: "repo:acme", Permission: "environment:write",
		Summary: "Create a preview environment",
	})
	add(Operation{
		ID: "environments.get", Method: MethodGet, Path: "/environments/{id}",
		CLIName: "environment get", Scope: "repo:acme", Permission: "environment:read",
		Summary: "Read a preview environment",
	})
	add(Operation{
		ID: "environments.destroy", Method: MethodDelete, Path: "/environments/{id}",
		CLIName: "environment destroy", Scope: "repo:acme", Permission: "environment:write",
		Summary: "Destroy a preview environment",
	})
	add(Operation{
		ID: "experiments.abort", Method: MethodPost, Path: "/experiments/{run_id}/abort",
		CLIName: "experiment abort", Scope: "repo:acme", Permission: "experiment:abort",
		Summary: "Abort a running experiment",
	})
	return r
}

func principal() *Principal {
	return &Principal{
		ID:          "ada",
		Grants:      []string{"repo:acme"},
		Permissions: []string{"environment:read", "environment:write", "experiment:abort"},
	}
}

func resource() Resource {
	return Resource{ID: "env-1", Scope: "repo:acme", Version: 7}
}

// ---------------------------------------------------------------------------
// Declaration
// ---------------------------------------------------------------------------

func TestRegisterRefusesIncompleteOperations(t *testing.T) {
	base := Operation{
		ID: "environments.create", Method: MethodPost, Path: "/environments",
		CLIName: "environment create", Scope: "repo:acme", Permission: "environment:write",
	}
	cases := map[string]struct {
		mutate func(*Operation)
		want   error
	}{
		"no identifier": {func(o *Operation) { o.ID = "" }, ErrNoOperationID},
		"no method":     {func(o *Operation) { o.Method = "" }, ErrNoMethod},
		"odd method":    {func(o *Operation) { o.Method = Method("FETCH") }, ErrUnknownMethod},
		"no path":       {func(o *Operation) { o.Path = "" }, ErrNoPath},
		"no cli name":   {func(o *Operation) { o.CLIName = "" }, ErrNoCLIName},
		"no scope":      {func(o *Operation) { o.Scope = "" }, ErrNoScope},
		"no permission": {func(o *Operation) { o.Permission = "" }, ErrNoPermission},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			op := base
			tc.mutate(&op)
			if _, err := (Registry{}).Register(op); !errors.Is(err, tc.want) {
				t.Errorf("Register error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestRegisterRefusesDuplicateIdentifiers(t *testing.T) {
	r := registry(t)
	op := Operation{
		ID: "environments.create", Method: MethodPost, Path: "/x",
		CLIName: "x y", Scope: "repo:acme", Permission: "environment:write",
	}
	if _, err := r.Register(op); !errors.Is(err, ErrDuplicateOperation) {
		t.Errorf("Register error = %v, want ErrDuplicateOperation", err)
	}
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

// The two surfaces are two renderings of one declaration, so they cannot drift.
func TestDerivedSurfacesAgree(t *testing.T) {
	for _, op := range registry(t).Operations {
		api := DeriveAPI(op)
		cli := DeriveCLI(op)
		if api.Scope != cli.Scope {
			t.Errorf("%q scope %q vs %q", op.ID, api.Scope, cli.Scope)
		}
		if api.Permission != cli.Permission {
			t.Errorf("%q permission %q vs %q", op.ID, api.Permission, cli.Permission)
		}
	}
	if problems := registry(t).Parity(); len(problems) != 0 {
		t.Errorf("parity problems = %v, want none", problems)
	}
}

// The CLI has no headers, so the idempotency key and the precondition become
// arguments — and they are still required, because a retried command that omits them
// creates a second environment.
func TestMutatingOperationsRequireIdempotencyOnBothSurfaces(t *testing.T) {
	for _, op := range registry(t).Operations {
		api := DeriveAPI(op)
		cli := DeriveCLI(op)
		mutating := op.Method.IsMutating()
		if api.RequiresIdempotencyKey != mutating || cli.RequiresIdempotencyKey != mutating {
			t.Errorf("%q idempotency requirement = %v / %v, want %v",
				op.ID, api.RequiresIdempotencyKey, cli.RequiresIdempotencyKey, mutating)
		}
		if api.RequiresPrecondition != mutating || cli.RequiresPrecondition != mutating {
			t.Errorf("%q precondition requirement = %v / %v, want %v",
				op.ID, api.RequiresPrecondition, cli.RequiresPrecondition, mutating)
		}
	}
}

func TestReadingOperationsRequireNoIdempotency(t *testing.T) {
	op := Operation{ID: "g", Method: MethodGet, Path: "/g", CLIName: "g get", Scope: "s", Permission: "p"}
	if DeriveAPI(op).RequiresIdempotencyKey {
		t.Error("a read must not require an idempotency key")
	}
	if DeriveCLI(op).RequiresPrecondition {
		t.Error("a read must not require a precondition")
	}
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

// An unauthenticated request is not a request with broad permissions; it is a request
// with none, and the two must not be conflated.
func TestUnauthenticatedRequestIsRefusedFirst(t *testing.T) {
	a := &Authorizer{Registry: registry(t)}
	err := a.Authorize("environments.get", Request{Resource: resource()}, now)
	if !errors.Is(err, ErrNoPrincipal) {
		t.Errorf("Authorize error = %v, want ErrNoPrincipal", err)
	}
	// And it is refused as unauthenticated even when the scope would not have
	// matched either, so the reason is not a scope problem.
	err = a.Authorize("environments.get", Request{Resource: Resource{ID: "e", Scope: "repo:other"}}, now)
	if !errors.Is(err, ErrNoPrincipal) {
		t.Errorf("Authorize error = %v, want ErrNoPrincipal", err)
	}
}

func TestPrincipalMustHoldTheOperationPermission(t *testing.T) {
	a := &Authorizer{Registry: registry(t)}
	p := principal()
	p.Permissions = []string{"environment:read"}
	err := a.Authorize("environments.create", Request{Principal: p, Resource: resource()}, now)
	if !errors.Is(err, ErrMissingPermission) {
		t.Errorf("Authorize error = %v, want ErrMissingPermission", err)
	}
}

// The check is against the resource's scope, so a principal cannot act outside its
// grants by choosing a different operation.
func TestPrincipalCannotActOutsideItsScope(t *testing.T) {
	a := &Authorizer{Registry: registry(t)}
	p := principal()
	err := a.Authorize("environments.get", Request{Principal: p, Resource: Resource{ID: "env-1", Scope: "repo:other"}}, now)
	if !errors.Is(err, ErrNotPermitted) {
		t.Errorf("Authorize error = %v, want ErrNotPermitted", err)
	}
	if !strings.Contains(err.Error(), "repo:other") {
		t.Errorf("the refusal must name the scope that was needed, got %v", err)
	}
}

// A grant covers its own scope and any scope beneath it, but not a similarly-named
// sibling.
func TestGrantCoversNestedScopesButNotSimilarNames(t *testing.T) {
	p := Principal{ID: "ada", Grants: []string{"repo:acme"}}
	if !p.Covers("repo:acme") {
		t.Error("a grant must cover its own scope")
	}
	if !p.Covers("repo:acme/api") {
		t.Error("a grant must cover a nested scope")
	}
	if p.Covers("repo:acme-other") {
		t.Error("a grant must not cover a similarly-named sibling scope")
	}
	if p.Covers("repo:other") {
		t.Error("a grant must not cover an unrelated scope")
	}
}

func TestRequestMustNameAResourceWithAScope(t *testing.T) {
	a := &Authorizer{Registry: registry(t)}
	if err := a.Authorize("environments.get", Request{Principal: principal()}, now); !errors.Is(err, ErrNoResource) {
		t.Errorf("Authorize error = %v, want ErrNoResource", err)
	}
	if err := a.Authorize("environments.get", Request{
		Principal: principal(), Resource: Resource{ID: "env-1"},
	}, now); !errors.Is(err, ErrNoResourceScope) {
		t.Errorf("Authorize error = %v, want ErrNoResourceScope", err)
	}
}

func TestUnknownOperationIsRefused(t *testing.T) {
	a := &Authorizer{Registry: registry(t)}
	if err := a.Authorize("no.such.operation", Request{Principal: principal(), Resource: resource()}, now); !errors.Is(err, ErrNoOperationID) {
		t.Errorf("Authorize error = %v, want ErrNoOperationID", err)
	}
}

// ---------------------------------------------------------------------------
// Idempotency and preconditions
// ---------------------------------------------------------------------------

func TestMutatingRequestRequiresAnIdempotencyKey(t *testing.T) {
	a := &Authorizer{Registry: registry(t)}
	err := a.Authorize("environments.create", Request{
		Principal: principal(), Resource: resource(), Precondition: 7,
	}, now)
	if !errors.Is(err, ErrMissingIdempotencyKey) {
		t.Errorf("Authorize error = %v, want ErrMissingIdempotencyKey", err)
	}
}

func TestMutatingRequestRequiresAPrecondition(t *testing.T) {
	a := &Authorizer{Registry: registry(t)}
	err := a.Authorize("environments.create", Request{
		Principal: principal(), Resource: resource(), IdempotencyKey: "k1",
	}, now)
	if !errors.Is(err, ErrMissingPrecondition) {
		t.Errorf("Authorize error = %v, want ErrMissingPrecondition", err)
	}
}

// The precondition catches a resource that changed under the caller.
func TestStalePreconditionIsRefused(t *testing.T) {
	a := &Authorizer{Registry: registry(t)}
	err := a.Authorize("environments.create", Request{
		Principal: principal(), Resource: resource(), IdempotencyKey: "k1", Precondition: 3,
	}, now)
	if !errors.Is(err, ErrStalePrecondition) {
		t.Errorf("Authorize error = %v, want ErrStalePrecondition", err)
	}
}

// The same key with the same request is the same request, so a retry is allowed.
func TestRepeatedIdempotencyKeyWithTheSameRequestIsAllowed(t *testing.T) {
	a := &Authorizer{Registry: registry(t)}
	req := Request{
		Principal: principal(), Resource: resource(),
		IdempotencyKey: "k1", Precondition: 7, BodyDigest: "sha256:body",
	}
	if err := a.Authorize("environments.create", req, now); err != nil {
		t.Fatalf("first Authorize: %v", err)
	}
	if err := a.Authorize("environments.create", req, now.Add(time.Second)); err != nil {
		t.Errorf("a retry with the same key and body must be allowed: %v", err)
	}
}

// The key names one request; the same key naming a different one is a client bug that
// would otherwise silently do the wrong thing.
func TestIdempotencyKeyReusedWithADifferentBodyIsRefused(t *testing.T) {
	a := &Authorizer{Registry: registry(t)}
	first := Request{
		Principal: principal(), Resource: resource(),
		IdempotencyKey: "k1", Precondition: 7, BodyDigest: "sha256:one",
	}
	if err := a.Authorize("environments.create", first, now); err != nil {
		t.Fatalf("first Authorize: %v", err)
	}
	second := first
	second.BodyDigest = "sha256:two"
	if err := a.Authorize("environments.create", second, now.Add(time.Second)); !errors.Is(err, ErrIdempotencyConflict) {
		t.Errorf("Authorize error = %v, want ErrIdempotencyConflict", err)
	}
}

// A read needs neither an idempotency key nor a precondition.
func TestReadsDoNotRequireIdempotencyOrPrecondition(t *testing.T) {
	a := &Authorizer{Registry: registry(t)}
	if err := a.Authorize("environments.get", Request{Principal: principal(), Resource: resource()}, now); err != nil {
		t.Errorf("Authorize: %v", err)
	}
}

// The recorded keys are visible for the audit record.
func TestIdempotencyKeysAreRecorded(t *testing.T) {
	a := &Authorizer{Registry: registry(t)}
	for _, key := range []string{"k-b", "k-a"} {
		req := Request{
			Principal: principal(), Resource: resource(),
			IdempotencyKey: key, Precondition: 7, BodyDigest: "sha256:" + key,
		}
		if err := a.Authorize("environments.create", req, now); err != nil {
			t.Fatalf("Authorize(%s): %v", key, err)
		}
	}
	keys := a.IdempotencyKeys()
	if len(keys) != 2 || keys[0] != "k-a" || keys[1] != "k-b" {
		t.Errorf("recorded keys = %v, want them sorted", keys)
	}
}

// ---------------------------------------------------------------------------
// Authorization result
// ---------------------------------------------------------------------------

func TestAuthorizeToReturnsTheConfinedScope(t *testing.T) {
	a := &Authorizer{Registry: registry(t)}
	auth, err := a.AuthorizeTo("environments.get", Request{Principal: principal(), Resource: resource()}, now)
	if err != nil {
		t.Fatalf("AuthorizeTo: %v", err)
	}
	if auth.Scope != "repo:acme" {
		t.Errorf("scope = %q, want the resource's scope", auth.Scope)
	}
	if auth.Operation.ID != "environments.get" {
		t.Errorf("operation = %q, want the authorized one", auth.Operation.ID)
	}
	if auth.Principal.ID != "ada" {
		t.Errorf("principal = %q, want ada", auth.Principal.ID)
	}
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

// Create an environment over the API, retry it with the same key, destroy it with the
// CLI's shape, and confirm both surfaces demanded the same things throughout.
func TestHappyPathAPIAndCLIParity(t *testing.T) {
	reg := registry(t)
	a := &Authorizer{Registry: reg}

	create := DeriveAPI(reg.Operations[0])
	cliCreate := DeriveCLI(reg.Operations[0])
	if !create.RequiresIdempotencyKey || !cliCreate.RequiresIdempotencyKey {
		t.Fatal("both surfaces must require an idempotency key for a creation")
	}

	req := Request{
		Principal: principal(), Resource: resource(),
		IdempotencyKey: "idem-1", Precondition: 7, BodyDigest: "sha256:body",
	}
	if err := a.Authorize("environments.create", req, now); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	// The retry is the same request, so it is allowed.
	if err := a.Authorize("environments.create", req, now.Add(2*time.Second)); err != nil {
		t.Errorf("retry: %v", err)
	}
	// A read needs nothing extra.
	if err := a.Authorize("environments.get", Request{Principal: principal(), Resource: resource()}, now); err != nil {
		t.Errorf("read: %v", err)
	}
	// The abort carries its own idempotency key, as the CLI would demand.
	if err := a.Authorize("experiments.abort", Request{
		Principal: principal(), Resource: resource(),
		IdempotencyKey: "idem-2", Precondition: 7, BodyDigest: "sha256:abort",
	}, now); err != nil {
		t.Errorf("abort: %v", err)
	}
	if problems := reg.Parity(); len(problems) != 0 {
		t.Errorf("parity problems = %v, want none", problems)
	}
}
