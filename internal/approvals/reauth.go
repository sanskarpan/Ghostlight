package approvals

import (
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/roles"
)

// Errors returned by this package's execution reauthorization.
var (
	// ErrNoAuthority means reauthorization was attempted without an authority. It is
	// checked before anything else because a missing authority would otherwise panic
	// somewhere in the middle of a run, and a gate that fails by crashing may fail
	// after some actions have already happened.
	ErrNoAuthority = errors.New("execution reauthorization requires an authority")
	// ErrActorMismatch means the actor attempting execution is not the actor the
	// approval names. An approval names a person, so a different person running it is
	// running somebody else's decision.
	ErrActorMismatch = errors.New("a different actor is executing an approval")
	// ErrAuthorityRevoked means the authority now denies a verb the approval covers.
	// An approval is a record that somebody said yes once, not a capability that
	// survives them losing the right to say it.
	ErrAuthorityRevoked = errors.New("the executing actor is no longer allowed to perform an approved verb")
)

// Authority is the injected execution-time permission source.
//
// It is an interface because reauthorization must ask whoever currently holds the
// policy; a boolean captured at approval time would answer a question that has since
// changed, which is precisely the case this package exists to catch. The error return
// is part of the contract and not an afterthought: an authority that cannot answer has
// not said no, and the two must never be conflated.
type Authority interface {
	// Allowed reports whether actor, acting as role, may perform verb right now. An
	// error means the answer is unknown, not that the answer is false.
	Allowed(actor string, role roles.Role, verb string) (bool, error)
}

// Reauthorize re-checks an approval at the moment of execution.
//
// Verification at approval time proves nothing about execution time, because the two
// are separated by exactly the window in which things change. This function closes that
// window on four fronts, in order:
//
// First, a nil authority is ErrNoAuthority. An execution path that would panic halfway
// through is worse than one that refuses at the start, because the panic may arrive
// after some actions have already happened.
//
// Second, expiry is re-checked against the execution clock. An approval that expired
// between approval and execution must not run: its window was the platform's statement
// about how long the decision stays valid, and the statement has lapsed.
//
// Third, the digest is re-checked with the same comparison Verify uses, so a plan that
// changed by one character after approval -- the attack this package exists for -- is
// refused at the last moment before it would matter.
//
// Fourth, the executing actor must equal the approving actor. An approval names a
// person; a different person executing it is executing somebody else's decision, and
// no amount of role membership makes that the right person's call.
//
// Then the authority is consulted for every action's verb. An approval is a record that
// somebody said yes once, not a capability that survives them losing the right to say
// it, so a verb the authority now denies refuses the whole run with ErrAuthorityRevoked.
// The check runs over the canonical action order, so which verb is reported is
// deterministic when more than one is denied.
//
// A failed authority check is a fault, not a denial. If Allowed returns an error, that
// error is returned wrapped with %w, so errors.Is finds it and ErrAuthorityRevoked does
// not: an outage must never look like a policy decision. Treating "cannot answer" as
// "said no" turns an availability problem into a silent policy change, and treating it
// as "said yes" grants permissions through a failure. The only safe reading is that the
// run did not happen and nobody decided anything.
func Reauthorize(a Approval, p Plan, actor string, role roles.Role, auth Authority, at time.Time) error {
	if auth == nil {
		return fmt.Errorf("%w: a nil authority would otherwise panic mid-run", ErrNoAuthority)
	}
	if !at.Before(a.ExpiresAt) {
		return fmt.Errorf("%w: approval %s expired at %s, execution at %s",
			ErrApprovalExpired, a.ID, a.ExpiresAt.UTC().Format(time.RFC3339Nano), at.UTC().Format(time.RFC3339Nano))
	}
	if got := Digest(p); got != a.Digest {
		return fmt.Errorf("%w: approval %s binds %s, the plan to execute digests to %s",
			ErrDigestMismatch, a.ID, a.Digest, got)
	}
	if actor != a.Actor {
		return fmt.Errorf("%w: approval %s names %q, execution attempted by %q",
			ErrActorMismatch, a.ID, a.Actor, actor)
	}
	for _, action := range canonicalActions(p) {
		allowed, err := auth.Allowed(actor, role, action.Verb)
		if err != nil {
			return fmt.Errorf("authority check for %q on %q failed: %w", action.Verb, action.Target, err)
		}
		if !allowed {
			return fmt.Errorf("%w: %s may no longer %q on %q (approval %s)",
				ErrAuthorityRevoked, role, action.Verb, action.Target, a.ID)
		}
	}
	return nil
}
