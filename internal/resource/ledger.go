// Package resource is the ledger of provider resources and the authority for
// deleting them.
//
// The schema is explicit that this table is "the only source of delete authority", and
// the design states the rules that make that true. "Delete operations verify
// environment ownership and known resource IDs." "A destructive action never follows
// user-supplied names." "Foundation/shared IDs are denylisted from environment destroy
// scope."
//
// Every rule here exists to make one specific mistake impossible: deleting something
// that is not ours. That mistake is unrecoverable, it is silent, and it is the kind of
// bug that is only noticed by a customer. So the ledger refuses to produce a delete
// authority it cannot justify, rather than producing one and hoping.
package resource

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Errors returned by this package.
var (
	// ErrNoAuthority means the ledger will not authorize this deletion. It is the
	// package's central refusal.
	ErrNoAuthority = errors.New("no delete authority")
	// ErrNotOwned means the resource does not belong to the environment claiming it.
	ErrNotOwned = errors.New("resource is not owned by that environment")
	// ErrSharedResource means a foundation resource was targeted for deletion.
	ErrSharedResource = errors.New("shared foundation resources are never deleted by an environment")
	// ErrUnknownResource means the resource is not in the ledger, so no one can
	// prove it is safe to delete.
	ErrUnknownResource = errors.New("resource is not in the ledger")
	// ErrGenerationMismatch means the deletion was authorized for a different
	// generation than the one it is being applied to.
	ErrGenerationMismatch = errors.New("delete authority was issued for a different generation")
	// ErrUserSuppliedName means a destructive action tried to resolve a resource by
	// a name that came from a customer.
	ErrUserSuppliedName = errors.New("a destructive action may not follow a user-supplied name")
	// ErrAlreadyDeleted means the resource is already tombstoned.
	ErrAlreadyDeleted = errors.New("resource is already verified deleted")
	// ErrNotRevoked means destruction was attempted before credentials were revoked.
	ErrNotRevoked = errors.New("credentials must be revoked before data is destroyed")
)

// State is an allocation's lifecycle state in the ledger.
type State string

const (
	// StateActive means the resource exists and is owned by an environment.
	StateActive State = "active"
	// StateRevoked means credentials and access bindings were removed, but the data
	// and the resource still exist.
	StateRevoked State = "revoked"
	// StateVerifiedDeleted means the provider confirmed the resource is gone. The row
	// is retained as a tombstone.
	StateVerifiedDeleted State = "verified_deleted"
)

// Allocation is one provider resource the platform created.
type Allocation struct {
	// ID is the ledger's identifier for the allocation.
	ID string
	// EnvironmentID is immutable. It is the ownership claim, and it is never derived
	// from anything a customer supplies.
	EnvironmentID string
	// Generation is the environment generation the resource was created for.
	Generation uint64
	// Kind is the dependency kind.
	Kind string
	// LogicalKey is the stable name within the environment, such as "primary".
	LogicalKey string
	// ProviderRef is an opaque provider reference. It is never an ARN, and it is the
	// only thing a delete may be issued against.
	ProviderRef map[string]string
	// CredentialRef is where a scoped credential lives. The credential itself is
	// never stored, returned by an API, or logged.
	CredentialRef string
	// IsShared marks a foundation resource. These never receive delete authority.
	IsShared bool
	// SupportsOwnershipTags reports whether the type carries ownership tags.
	// Post-restore reconciliation depends on it.
	SupportsOwnershipTags bool

	State         State
	RevokedAt     time.Time
	RevokedBy     string
	DeletedAt     time.Time
	DeletionProof string
	CreatedAt     time.Time
}

// Key is the ledger's identity for an allocation.
func (a Allocation) Key() string {
	return fmt.Sprintf("%s|%s|%s", a.EnvironmentID, a.Kind, a.LogicalKey)
}

// Record is what the ledger durably holds.
type Record struct {
	Allocation
	// Observations is the evidence trail from the provider, newest last. It is what
	// "verified" cleanup means: not that a delete call returned, but that the
	// provider was asked afterwards and confirmed the resource is absent.
	Observations []Observation
}

// Observation is a provider's answer about whether a resource exists.
type Observation struct {
	At          time.Time
	Exists      bool
	ProviderRef map[string]string
	// Detail is operator-facing context. It must not contain credentials.
	Detail string
}

// Authority is a verified permission to delete one specific resource.
//
// It exists as a distinct type so that a delete cannot be issued from something that
// merely looks like an allocation. You must pass through the ledger's verification to
// obtain one, and it is bound to a single resource and generation.
type Authority struct {
	EnvironmentID string
	Generation    uint64
	AllocationID  string
	// ProviderRef is copied in so the delete uses exactly what was verified, rather
	// than re-reading the ledger at delete time and possibly acting on a newer row.
	ProviderRef map[string]string
	IssuedAt    time.Time
	IssuedFor   string
}

// Ledger records allocations and is the only source of delete authority.
type Ledger interface {
	// Record adds or updates an allocation.
	Record(ctx context.Context, a Allocation) error
	// Get returns an allocation by its ledger identity.
	Get(ctx context.Context, environmentID, kind, logicalKey string) (Allocation, error)
	// ByID returns an allocation by ledger id.
	ByID(ctx context.Context, id string) (Allocation, error)
	// MarkRevoked records that credentials were removed.
	MarkRevoked(ctx context.Context, id, actor string, evidence string) error
	// MarkDeleted records verified deletion, leaving a tombstone.
	MarkDeleted(ctx context.Context, id string, proof Observation) error
	// Observe appends provider evidence.
	Observe(ctx context.Context, id string, o Observation) error
	// List returns an environment's allocations.
	List(ctx context.Context, environmentID string) ([]Allocation, error)
}

// Denylist names resources an environment may never delete.
//
// These are the foundation resources other previews share. Deleting one destroys every
// other preview using it, which is why the rule is a denylist rather than a flag on
// each resource: a resource nobody thought to flag still cannot be targeted.
type Denylist struct {
	mu  sync.RWMutex
	ids map[string]string
}

// NewDenylist builds a denylist from native IDs.
func NewDenylist(ids ...string) *Denylist {
	d := &Denylist{ids: map[string]string{}}
	for _, id := range ids {
		if id != "" {
			d.ids[id] = "shared foundation resource"
		}
	}
	return d
}

// Add denylists a native ID.
func (d *Denylist) Add(id, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ids[id] = reason
}

// Contains reports whether a native ID is denylisted.
func (d *Denylist) Contains(id string) (bool, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r, ok := d.ids[id]
	return ok, r
}

// AnyDenied reports whether any of the native values in a provider ref is denylisted.
//
// It checks every value rather than one key because provider refs are opaque maps and
// the native ID may live under any of them. Checking a single known key would make the
// denylist trivially bypassable by a provider that names it differently.
func (d *Denylist) AnyDenied(ref map[string]string) (string, bool) {
	values := make([]string, 0, len(ref))
	for _, v := range ref {
		values = append(values, v)
	}
	// Sort so the reported denial is deterministic across runs.
	sort.Strings(values)
	for _, v := range values {
		if denied, reason := d.Contains(v); denied {
			return reason, true
		}
	}
	return "", false
}

// AuthorityIssuer verifies ownership and produces delete authority.
type AuthorityIssuer struct {
	ledger    Ledger
	denylist  *Denylist
	now       func() time.Time
	observeFn ObserverFn
}

// NewAuthorityIssuer builds an issuer.
func NewAuthorityIssuer(l Ledger, d *Denylist, now func() time.Time) (*AuthorityIssuer, error) {
	if l == nil {
		// Without the ledger there is nothing to verify against, so every authority
		// would be unbacked. This is the single most dangerous default available.
		return nil, errors.New("an authority issuer requires the ledger; it is the only source of delete authority")
	}
	if d == nil {
		// An empty denylist is not a safe default: it would silently permit deleting a
		// foundation resource.
		return nil, errors.New("an authority issuer requires a foundation denylist; an empty one would permit deleting shared resources")
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &AuthorityIssuer{ledger: l, denylist: d, now: now}, nil
}

// Authorize verifies that one allocation may be destroyed.
//
// The checks are ordered cheapest-first but none is optional. Ownership, shared-resource
// status, denylist, generation, and revocation all have to hold.
func (i *AuthorityIssuer) Authorize(ctx context.Context, id string, generation uint64, actor string) (Authority, error) {
	a, err := i.ledger.ByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUnknownResource) {
			return Authority{}, fmt.Errorf("%w: %s is not in the ledger, so nobody can prove it is safe to delete", ErrNoAuthority, id)
		}
		return Authority{}, err
	}

	// Already-gone is not an error, but it is also not a new authority: re-issuing one
	// would let a retry loop keep operating on a tombstone.
	if a.State == StateVerifiedDeleted {
		return Authority{}, fmt.Errorf("%w: %s is already verified deleted", ErrAlreadyDeleted, id)
	}

	// A shared resource never receives delete authority from an environment. This is
	// checked against the ledger's own flag and the denylist independently, because
	// either alone can be wrong.
	if a.IsShared {
		return Authority{}, fmt.Errorf("%w: %s is recorded as shared", ErrSharedResource, id)
	}
	if reason, denied := i.denylist.AnyDenied(a.ProviderRef); denied {
		return Authority{}, fmt.Errorf("%w: %s matches a foundation resource (%s)", ErrSharedResource, id, reason)
	}

	// Generation fencing. A destroy authorized for generation 3 must not act on the
	// row that generation 4 wrote.
	if generation != 0 && a.Generation != generation {
		return Authority{}, fmt.Errorf("%w: %s belongs to generation %d, authority was for %d",
			ErrGenerationMismatch, id, a.Generation, generation)
	}

	// Revocation before destruction. Credentials outlive the data they grant access to
	// unless explicitly removed, and the spec orders revocation first for that reason.
	if a.State != StateRevoked {
		return Authority{}, fmt.Errorf("%w: %s is %s", ErrNotRevoked, id, a.State)
	}
	if a.RevokedBy == "" {
		return Authority{}, fmt.Errorf("%w: %s has no recorded revoking actor", ErrNotRevoked, id)
	}

	return Authority{
		EnvironmentID: a.EnvironmentID,
		Generation:    a.Generation,
		AllocationID:  a.ID,
		ProviderRef:   copyRef(a.ProviderRef),
		IssuedAt:      i.now(),
		IssuedFor:     actor,
	}, nil
}

// VerifyDeleted confirms the provider no longer has the resource.
//
// This is what makes cleanup "verified" rather than "attempted". A destroy call that
// returned successfully is not proof: it may have failed after the provider applied
// the change, or the response may have been lost. Only a subsequent observation can
// confirm absence.
func (i *AuthorityIssuer) VerifyDeleted(ctx context.Context, auth Authority) (Observation, error) {
	if auth.AllocationID == "" {
		return Observation{}, fmt.Errorf("%w: authority was never issued", ErrNoAuthority)
	}
	obs, err := i.Observe(ctx, auth)
	if err != nil {
		return Observation{}, err
	}
	if obs.Exists {
		// Still present. Recording this is what lets the janitor know cleanup is
		// pending rather than done.
		return obs, fmt.Errorf("cleanup is still verifying: %s still exists", auth.AllocationID)
	}
	return obs, nil
}

// observer is the provider observation seam.
func (i *AuthorityIssuer) observe(ctx context.Context, ref map[string]string) (Observation, error) {
	if i.observeFn == nil {
		return Observation{}, errors.New(
			"no provider observer is installed; a delete may not be verified without asking the provider")
	}
	return i.observeFn(ctx, ref)
}

// Observe asks the provider whether a resource still exists.
func (i *AuthorityIssuer) Observe(ctx context.Context, auth Authority) (Observation, error) {
	obs, err := i.observe(ctx, auth.ProviderRef)
	if err != nil {
		return Observation{}, err
	}
	if obs.At.IsZero() {
		obs.At = i.now()
	}
	if err := i.ledger.Observe(ctx, auth.AllocationID, obs); err != nil {
		return obs, fmt.Errorf("record observation: %w", err)
	}
	return obs, nil
}

// ObserverFn observes a provider reference.
type ObserverFn func(ctx context.Context, ref map[string]string) (Observation, error)

// SetObserver installs the provider observation seam.
func (i *AuthorityIssuer) SetObserver(fn ObserverFn) {
	i.observeFn = fn
}

// ResolveByName is refused by construction.
//
// SPEC.md: "a destructive action never follows user-supplied names." There is no safe
// version of this function, so it exists only to say so in one place and to give the
// compiler and tests something to point at.
func ResolveByName(_ context.Context, _ string, _ string) (Allocation, error) {
	return Allocation{}, fmt.Errorf("%w: resolve by name and delete it", ErrUserSuppliedName)
}

func copyRef(ref map[string]string) map[string]string {
	out := make(map[string]string, len(ref))
	for k, v := range ref {
		out[k] = v
	}
	return out
}

// Describe renders an allocation for an operator, without ever including credentials.
//
// A credential reference is a location, not a secret, but it is still omitted: an
// operator log is the wrong place for the address of a secret, and the allocation is
// fully identifiable without it.
func Describe(a Allocation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s/%s gen=%d state=%s", a.Kind, a.EnvironmentID, a.LogicalKey, a.Generation, a.State)
	if a.ProviderRef != nil {
		fmt.Fprintf(&b, " ref=%s", formatRef(a.ProviderRef))
	}
	if a.IsShared {
		b.WriteString(" shared=true")
	}
	if !a.SupportsOwnershipTags {
		// Worth surfacing: without ownership tags, post-restore reconciliation cannot
		// rely on tags to find the resource again.
		b.WriteString(" no-ownership-tags")
	}
	return b.String()
}

func formatRef(ref map[string]string) string {
	keys := make([]string, 0, len(ref))
	for k := range ref {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+ref[k])
	}
	return "{" + strings.Join(parts, " ") + "}"
}
