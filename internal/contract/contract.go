// Package contract makes API and CLI parity structural rather than maintained by hand.
//
// The problem this solves is not that somebody might forget to add a permission check
// to the CLI. It is that the API and the CLI are two separate descriptions of the same
// operation, and every property that has to match between them — the scope it
// requires, the permission it checks, whether it is idempotent, whether it needs a
// precondition — is a property somebody has to remember to write down twice. The
// properties that are remembered twice are the properties that drift.
//
// So an operation is declared **once**, and both surfaces are derived from it. The API
// surface and the CLI surface are not two things that must agree; they are two
// renderings of one thing, and the parity check confirms that rather than hoping.
//
// The derivation is not entirely mechanical, because the two surfaces genuinely differ
// in one place: a mutating API call carries an `Idempotency-Key` header and a
// resource-version precondition, while a CLI invocation has no headers and must carry
// the same two things as arguments. That difference is real and it is the most likely
// place for parity to break, so the derivation handles it explicitly and the parity
// check verifies that the CLI surface really does demand both — a CLI command that
// mutates without an idempotency key is a command that a retry turns into a second
// environment.
//
// Authorization is scoped, and the scope is checked against the resource rather than
// against the operation. An operation declares the scope it needs; a principal holds
// grants naming scopes; a resource carries the scope it belongs to. The check is that
// the principal's grant covers the resource's scope, so a principal who can act on one
// repository cannot act on another by calling a differently-named operation.
//
// Two refusals are load-bearing and are tested hardest.
//
// The first is that a principal with no grant for the resource's scope is refused, and
// the error says which scope was needed — because an authorization failure a developer
// cannot act on is an authorization failure that gets worked around.
//
// The second is that a request with no principal at all is refused. An unauthenticated
// request is not a request with broad permissions; it is a request with none, and the
// two are not the same thing.
package contract

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package's contract rules.
var (
	// ErrNoOperationID means an operation has no identifier.
	ErrNoOperationID = errors.New("operation must carry an identifier")
	// ErrDuplicateOperation means two operations share an identifier.
	ErrDuplicateOperation = errors.New("operation identifier is already in use")
	// ErrNoMethod means an operation names no HTTP method.
	ErrNoMethod = errors.New("operation must carry a method")
	// ErrUnknownMethod means an operation names a method this package does not know.
	ErrUnknownMethod = errors.New("unsupported http method")
	// ErrNoPath means an operation has no path.
	ErrNoPath = errors.New("operation must carry a path")
	// ErrNoCLIName means an operation has no CLI command name.
	ErrNoCLIName = errors.New("operation must carry a cli command name")
	// ErrNoScope means an operation requires no scope, or a principal holds no
	// grant. An operation with no scope is unscoped, and unscoped means any
	// principal can call it.
	ErrNoScope = errors.New("operation requires a scope")
	// ErrNoPermission means an operation declares no permission.
	ErrNoPermission = errors.New("operation must declare a permission")
	// ErrNoPrincipal means a request named no principal. An unauthenticated
	// request is not a request with broad permissions; it is a request with none.
	ErrNoPrincipal = errors.New("request must name a principal")
	// ErrNotPermitted means the principal holds no grant covering the resource's
	// scope.
	ErrNotPermitted = errors.New("principal is not permitted in that scope")
	// ErrMissingPermission means the principal's grants do not include the
	// operation's permission.
	ErrMissingPermission = errors.New("principal lacks the required permission")
	// ErrMissingIdempotencyKey means a mutating request carried no idempotency
	// key. A retry without one is a second operation, not the same one.
	ErrMissingIdempotencyKey = errors.New("mutating request requires an idempotency key")
	// ErrMissingPrecondition means a mutating request carried no resource version
	// precondition.
	ErrMissingPrecondition = errors.New("mutating request requires a resource version precondition")
	// ErrStalePrecondition means the request's precondition does not match the
	// resource's current version, so the resource changed under the caller.
	ErrStalePrecondition = errors.New("resource version precondition does not match")
	// ErrIdempotencyConflict means an idempotency key was reused with a different
	// request body. The key names one request; the same key naming a different one
	// is a client bug that would otherwise silently do the wrong thing.
	ErrIdempotencyConflict = errors.New("idempotency key was used with a different request")
	// ErrParityBroken means an operation's derived surfaces disagree.
	ErrParityBroken = errors.New("api and cli surfaces disagree")
	// ErrNoResource means a request named no resource.
	ErrNoResource = errors.New("request must name a resource")
	// ErrNoResourceScope means a resource carries no scope.
	ErrNoResourceScope = errors.New("resource must carry a scope")
	// ErrNoGrant means a principal holds a grant naming no scope.
	ErrNoGrant = errors.New("grant must name a scope")
)

// Method is an HTTP method.
type Method string

const (
	MethodGet    Method = "GET"
	MethodPost   Method = "POST"
	MethodPut    Method = "PUT"
	MethodPatch  Method = "PATCH"
	MethodDelete Method = "DELETE"
)

// IsMutating reports whether the method changes state.
func (m Method) IsMutating() bool {
	switch m {
	case MethodPost, MethodPut, MethodPatch, MethodDelete:
		return true
	}
	return false
}

// Operation is one operation of the platform, declared once.
type Operation struct {
	// ID identifies the operation, and is what the parity check keys on.
	ID string
	// Method is the HTTP method.
	Method Method
	// Path is the API path, without a version prefix.
	Path string
	// CLIName is the CLI command, in the form "group command".
	CLIName string
	// Scope is the scope a principal needs to invoke the operation.
	Scope string
	// Permission is the permission a principal needs to invoke the operation.
	Permission string
	// Summary describes the operation.
	Summary string
}

// APISurface is the derived API rendering of an operation.
type APISurface struct {
	// OperationID is the operation this came from.
	OperationID string
	// Method is the HTTP method.
	Method Method
	// Path is the path.
	Path string
	// Scope is the scope required.
	Scope string
	// Permission is the permission required.
	Permission string
	// RequiresIdempotencyKey reports whether the call must carry an
	// Idempotency-Key header. Only mutating calls do.
	RequiresIdempotencyKey bool
	// RequiresPrecondition reports whether the call must carry a resource-version
	// precondition. Only mutating calls do.
	RequiresPrecondition bool
}

// CLISurface is the derived CLI rendering of an operation.
type CLISurface struct {
	// OperationID is the operation this came from.
	OperationID string
	// Name is the command name.
	Name string
	// Scope is the scope required.
	Scope string
	// Permission is the permission required.
	Permission string
	// RequiresIdempotencyKey reports whether the command must accept an
	// idempotency key. The CLI has no headers, so the key is an argument — and it
	// is required, because a retried command without one creates a second
	// resource.
	RequiresIdempotencyKey bool
	// RequiresPrecondition reports whether the command must accept a resource
	// version precondition, for the same reason.
	RequiresPrecondition bool
}

// DeriveAPI renders an operation as its API surface.
func DeriveAPI(op Operation) APISurface {
	return APISurface{
		OperationID:            op.ID,
		Method:                 op.Method,
		Path:                   op.Path,
		Scope:                  op.Scope,
		Permission:             op.Permission,
		RequiresIdempotencyKey: op.Method.IsMutating(),
		RequiresPrecondition:   op.Method.IsMutating(),
	}
}

// DeriveCLI renders an operation as its CLI surface.
//
// The CLI has no headers, so the idempotency key and the precondition become
// arguments. The requirement itself does not change: a mutating command demands both,
// because a retried command that omits them is a second resource rather than the same
// one.
func DeriveCLI(op Operation) CLISurface {
	return CLISurface{
		OperationID:            op.ID,
		Name:                   op.CLIName,
		Scope:                  op.Scope,
		Permission:             op.Permission,
		RequiresIdempotencyKey: op.Method.IsMutating(),
		RequiresPrecondition:   op.Method.IsMutating(),
	}
}

// Registry is the set of declared operations.
type Registry struct {
	// Operations are the declared operations.
	Operations []Operation
}

// Register declares an operation.
func (r Registry) Register(op Operation) (Registry, error) {
	if strings.TrimSpace(op.ID) == "" {
		return r, ErrNoOperationID
	}
	switch op.Method {
	case MethodGet, MethodPost, MethodPut, MethodPatch, MethodDelete:
	case "":
		return r, ErrNoMethod
	default:
		return r, fmt.Errorf("%w: %q", ErrUnknownMethod, op.Method)
	}
	if strings.TrimSpace(op.Path) == "" {
		return r, ErrNoPath
	}
	if strings.TrimSpace(op.CLIName) == "" {
		return r, ErrNoCLIName
	}
	if strings.TrimSpace(op.Scope) == "" {
		return r, fmt.Errorf("%w: operation %q", ErrNoScope, op.ID)
	}
	if strings.TrimSpace(op.Permission) == "" {
		return r, fmt.Errorf("%w: operation %q", ErrNoPermission, op.ID)
	}
	for _, existing := range r.Operations {
		if existing.ID == op.ID {
			return r, fmt.Errorf("%w: %q", ErrDuplicateOperation, op.ID)
		}
	}
	r.Operations = append(r.Operations, op)
	return r, nil
}

// operation looks an operation up by identifier.
func (r Registry) operation(id string) (Operation, bool) {
	for _, op := range r.Operations {
		if op.ID == id {
			return op, true
		}
	}
	return Operation{}, false
}

// Parity reports the operations whose derived surfaces disagree.
//
// The check exists because the derivation is the only thing keeping them in step, and
// a derivation that has been changed without the surfaces being re-derived would
// otherwise pass unnoticed until a consumer found it.
func (r Registry) Parity() []error {
	var problems []error
	for _, op := range r.Operations {
		api := DeriveAPI(op)
		cli := DeriveCLI(op)
		switch {
		case api.Scope != cli.Scope:
			problems = append(problems, fmt.Errorf("%w: operation %q scope %q vs %q",
				ErrParityBroken, op.ID, api.Scope, cli.Scope))
		case api.Permission != cli.Permission:
			problems = append(problems, fmt.Errorf("%w: operation %q permission %q vs %q",
				ErrParityBroken, op.ID, api.Permission, cli.Permission))
		case api.RequiresIdempotencyKey != cli.RequiresIdempotencyKey:
			problems = append(problems, fmt.Errorf("%w: operation %q idempotency requirement differs",
				ErrParityBroken, op.ID))
		case api.RequiresPrecondition != cli.RequiresPrecondition:
			problems = append(problems, fmt.Errorf("%w: operation %q precondition requirement differs",
				ErrParityBroken, op.ID))
		}
	}
	return problems
}

// Principal is an authenticated caller.
type Principal struct {
	// ID identifies the principal.
	ID string
	// Grants are the scopes the principal may act in.
	Grants []string
	// Permissions are the permissions the principal holds.
	Permissions []string
}

// HasPermission reports whether the principal holds a permission.
func (p Principal) HasPermission(permission string) bool {
	for _, held := range p.Permissions {
		if held == permission {
			return true
		}
	}
	return false
}

// Covers reports whether the principal's grants cover a scope.
//
// A grant covers the scope it names and any scope beneath it, written with a slash:
// a grant of "repo:acme" covers "repo:acme/api" but not "repo:other". The rule is
// prefix-with-separator rather than plain prefix, because "repo:acme" must not cover
// "repo:acme-other" — that is a different repository with a similar name, and plain
// prefix matching is how one repository's data reaches another.
func (p Principal) Covers(scope string) bool {
	for _, grant := range p.Grants {
		if grant == scope {
			return true
		}
		if strings.HasPrefix(scope, grant+"/") {
			return true
		}
	}
	return false
}

// Resource is the thing an operation acts on.
type Resource struct {
	// ID identifies the resource.
	ID string
	// Scope is the scope the resource belongs to.
	Scope string
	// Version is the resource's current version, used for preconditions.
	Version int
}

// Request is a call to an operation.
type Request struct {
	// Principal is the authenticated caller. It is required: an unauthenticated
	// request is not a request with broad permissions, it is a request with none.
	Principal *Principal
	// Resource is the resource the operation acts on.
	Resource Resource
	// IdempotencyKey is the key a mutating call must carry.
	IdempotencyKey string
	// Precondition is the resource version the caller believes it is acting on.
	Precondition int
	// BodyDigest is the digest of the request body, used to detect an idempotency
	// key reused with a different request.
	BodyDigest string
}

// IdempotencyRecord remembers what a key was used for.
type IdempotencyRecord struct {
	// Key is the idempotency key.
	Key string
	// BodyDigest is the request body the key was first used with.
	BodyDigest string
	// At is when the key was first used.
	At time.Time
}

// Authorizer checks requests against the declared operations.
//
// It holds the idempotency records, because remembering what a key was used for is
// part of authorizing the second use of it.
type Authorizer struct {
	// Registry is the declared operations.
	Registry Registry
	// records remembers the idempotency keys already used.
	records map[string]IdempotencyRecord
}

// Authorize checks that a principal may perform an operation on a resource.
//
// The order is the policy. The principal is checked first, because an unauthenticated
// request must not reach the scope check and produce a different error — the two mean
// different things, and conflating them turns "you are not signed in" into "you are
// not allowed", which sends developers looking in the wrong place. Then the
// permission, because a principal in the right scope with the wrong permission is a
// different mistake from one in the wrong scope. Then the scope, against the
// *resource* rather than the operation, so a principal cannot act outside its grants
// by choosing a different operation. Then the idempotency and precondition rules,
// which only apply to mutating operations.
func (a *Authorizer) Authorize(opID string, req Request, at time.Time) error {
	op, ok := a.Registry.operation(opID)
	if !ok {
		return fmt.Errorf("%w: %q", ErrNoOperationID, opID)
	}
	if req.Principal == nil || strings.TrimSpace(req.Principal.ID) == "" {
		return ErrNoPrincipal
	}
	if !req.Principal.HasPermission(op.Permission) {
		return fmt.Errorf("%w: %q needs %q", ErrMissingPermission, op.ID, op.Permission)
	}
	if strings.TrimSpace(req.Resource.ID) == "" {
		return ErrNoResource
	}
	if strings.TrimSpace(req.Resource.Scope) == "" {
		return ErrNoResourceScope
	}
	if !req.Principal.Covers(req.Resource.Scope) {
		return fmt.Errorf("%w: %q needs scope %q", ErrNotPermitted, op.ID, req.Resource.Scope)
	}
	if !op.Method.IsMutating() {
		return nil
	}
	if strings.TrimSpace(req.IdempotencyKey) == "" {
		return fmt.Errorf("%w: %q", ErrMissingIdempotencyKey, op.ID)
	}
	if req.Precondition == 0 {
		return fmt.Errorf("%w: %q", ErrMissingPrecondition, op.ID)
	}
	if req.Precondition != req.Resource.Version {
		return fmt.Errorf("%w: %q expected %d, resource is at %d",
			ErrStalePrecondition, op.ID, req.Precondition, req.Resource.Version)
	}
	if a.records == nil {
		a.records = map[string]IdempotencyRecord{}
	}
	if prior, used := a.records[req.IdempotencyKey]; used {
		if prior.BodyDigest != req.BodyDigest {
			return fmt.Errorf("%w: %q", ErrIdempotencyConflict, req.IdempotencyKey)
		}
		return nil
	}
	a.records[req.IdempotencyKey] = IdempotencyRecord{Key: req.IdempotencyKey, BodyDigest: req.BodyDigest, At: at}
	return nil
}

// Authorization is a successful authorization, carrying what the surfaces need.
type Authorization struct {
	// Operation is the authorized operation.
	Operation Operation
	// Principal is the caller.
	Principal Principal
	// Scope is the scope the authorization is confined to.
	Scope string
}

// Authorize returns the authorized operation and scope.
func (a *Authorizer) AuthorizeTo(opID string, req Request, at time.Time) (Authorization, error) {
	if err := a.Authorize(opID, req, at); err != nil {
		return Authorization{}, err
	}
	op, _ := a.Registry.operation(opID)
	return Authorization{Operation: op, Principal: *req.Principal, Scope: req.Resource.Scope}, nil
}

// IdempotencyKeys returns the recorded idempotency keys, sorted, for the audit record.
func (a *Authorizer) IdempotencyKeys() []string {
	keys := make([]string, 0, len(a.records))
	for k := range a.records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
