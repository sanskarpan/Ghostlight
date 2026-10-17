package fixtures

import (
	"errors"
	"fmt"
)

// Errors returned by cloning.
var (
	// ErrInvalidIdentity means the clone target is missing an id or a slug, or the
	// parent snapshot has no usable identity to record as provenance.
	ErrInvalidIdentity = errors.New("clone requires a complete identity")
	// ErrIdentityReused means the clone target reuses part of the parent identity.
	// A clone exists to move the data under a fresh principal; reusing the parent
	// id or slug would leave the parent's authority reachable.
	ErrIdentityReused = errors.New("clone reuses the parent identity")
	// ErrAuthorityInherited means a clone carries authority-bearing values. A clone
	// starts with none, whether the value came from the parent or was minted later.
	ErrAuthorityInherited = errors.New("clone inherits authority from its parent")
)

// Clone copies a snapshot to a fresh identity.
//
// The load-bearing rule is that a clone inherits no authority. Grants, capability
// tokens, session references and delete authority are all cleared, because they
// were issued for the parent principal and would silently extend that principal's
// reach into the clone. The clone records the parent identity id and the parent's
// digest as provenance, but never copies the parent identity itself: provenance is
// a fact about where the data came from, not a credential that can be used.
//
// The clone is scoped to the new identity's environment. Keeping the parent's
// environment id would leave an address back into the parent's scope.
func Clone(snap Snapshot, newIdentity Identity) (Snapshot, error) {
	if !snap.Identity.Valid() {
		return Snapshot{}, fmt.Errorf("%w: parent snapshot has no usable identity", ErrInvalidIdentity)
	}
	if !newIdentity.Valid() {
		return Snapshot{}, fmt.Errorf("%w: new identity needs both an id and a slug", ErrInvalidIdentity)
	}
	if newIdentity.ID == snap.Identity.ID || newIdentity.Slug == snap.Identity.Slug {
		return Snapshot{}, fmt.Errorf("%w: %s/%s", ErrIdentityReused, newIdentity.ID, newIdentity.Slug)
	}

	clone := snap
	clone.Identity = newIdentity
	clone.EnvironmentID = newIdentity.ID
	clone.Grants = nil
	clone.Tokens = nil
	clone.Sessions = nil
	clone.DeleteAuthority = nil
	clone.CloneOf = snap.Identity.ID
	clone.ParentDigest = snap.Digest()
	return clone, nil
}

// InheritsNothing checks that a clone carries no authority from its parent.
//
// It is intentionally stronger than a set-intersection check: any authority at all
// on a clone is a failure, because a clone starts with none. A value that happens
// to be absent from the parent but present on the clone did not "inherit" in the
// narrow sense, but it is still authority on something that must have none.
//
// The negative control matters. A checker that always returns nil would pass every
// correct clone and prove nothing, so the tests deliberately corrupt a clone and
// require a non-nil error.
func InheritsNothing(parent, clone Snapshot) error {
	var errs []error

	check := func(name string, parentValues, cloneValues []string) {
		if len(cloneValues) == 0 {
			return
		}
		inherited := make(map[string]struct{}, len(parentValues))
		for _, value := range parentValues {
			inherited[value] = struct{}{}
		}
		errs = append(errs, fmt.Errorf("%w: clone carries %s values",
			ErrAuthorityInherited, name))
		for _, value := range cloneValues {
			if _, ok := inherited[value]; ok {
				errs = append(errs, fmt.Errorf("%w: clone shares a %s value with its parent",
					ErrAuthorityInherited, name))
			}
		}
	}

	check("grant", parent.Grants, clone.Grants)
	check("capability token", parent.Tokens, clone.Tokens)
	check("session", parent.Sessions, clone.Sessions)
	check("delete authority", parent.DeleteAuthority, clone.DeleteAuthority)

	return errors.Join(errs...)
}
