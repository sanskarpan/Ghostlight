package approvals

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"time"
)

// Errors returned by this package's approval rules.
var (
	// ErrAnonymousApproval means an approval was attempted with no actor. An approval
	// is a person taking responsibility for a plan; without a name it is an anonymous
	// yes, and the reauthorization step has nothing to re-check against.
	ErrAnonymousApproval = errors.New("approval must name an actor")
	// ErrDigestMismatch means the plan presented does not digest to what the approval
	// binds. It is the load-bearing refusal of this package: approving what you saw
	// and executing what arrived later is the attack, and one changed character in one
	// parameter is the attack's smallest form.
	ErrDigestMismatch = errors.New("plan digest does not match the approved digest")
	// ErrApprovalExpired means the approval's lifetime had already ended at the time
	// of verification or execution. An approval is a decision made about the world at
	// one moment; after its window closes, the world it was a decision about has
	// moved on.
	ErrApprovalExpired = errors.New("approval has expired")
	// ErrNotYetValid means verification happened before the approval was issued. A
	// non-monotonic clock is far more likely to be a broken clock than a real result,
	// and either way the approval cannot vouch for a time that precedes it.
	ErrNotYetValid = errors.New("approval is not yet valid")
)

// Approval lifetimes. The bounds are constants for the same reason the destructive set
// is data: a caller who can raise the bound can also raise it past the point where an
// approval still describes anything.
const (
	// MaxApprovalTTL is the longest an approval may remain valid. An approval is a
	// decision made at one moment about a plan that existed at that moment; a decision
	// that stays actionable forever stops being a decision and becomes a standing
	// grant. Twenty-four hours is long enough for an approval made at the end of a
	// working day to be used the next morning, and short enough that a forgotten
	// approval ages out before the plan under it has drifted.
	MaxApprovalTTL = 24 * time.Hour
	// DefaultApprovalTTL is granted when a caller asks for no particular lifetime. It
	// is deliberately shorter than the maximum: the common case is an approval used
	// within the same working session, and a default that sits at the maximum would
	// make every approval a day-long one by accident.
	DefaultApprovalTTL = 1 * time.Hour
)

// Approval is a person's decision to allow one plan, bound to the plan's digest.
//
// The digest is the approval. ID, Actor and the timestamps exist so the decision can
// be found, attributed, and aged out; only Digest decides what plan the decision
// covers, which is why Verify recomputes it from the plan in hand instead of trusting
// anything the caller says about the plan's name.
type Approval struct {
	// ID identifies the approval in a ledger. It is derived deterministically from the
	// actor and the issue instant, so a retry of the same decision produces the same
	// reference rather than a duplicate.
	ID string
	// Actor is the person who took responsibility. Reauthorization refuses any other
	// actor.
	Actor string
	// Digest is the canonical plan digest this approval binds.
	Digest string
	// IssuedAt is when the decision was made. Verification before this instant is
	// refused.
	IssuedAt time.Time
	// ExpiresAt is the end of the validity window. Verification at or after it is
	// refused.
	ExpiresAt time.Time
}

// Approve records a person's decision to allow a plan, bound to the plan's digest.
//
// The actor is required. An approval with no name is not an approval, it is an
// anonymous yes, and the entire point of this package is that a yes belongs to somebody
// and can later be re-checked against what that somebody is still allowed to do.
//
// An undeclared destructive plan is refused here as well as at preview time, because
// Approve is reachable without Preview and a refusal that exists on only one path is a
// refusal that can be walked around.
//
// A ttl at or below zero means DefaultApprovalTTL. A ttl above MaxApprovalTTL is
// clamped down to the maximum rather than refused, for the same reason internal/quota
// clamps its own TTLs: a caller asking for too long should get the policy maximum,
// never the extra time. Clamping cannot widen the policy, and refusing would teach the
// well-meaning caller the wrong lesson -- that long approvals fail, rather than that
// the platform has a maximum.
func Approve(actor string, p Plan, at time.Time, ttl time.Duration) (Approval, error) {
	if strings.TrimSpace(actor) == "" {
		return Approval{}, fmt.Errorf("%w: the decision must belong to a named person", ErrAnonymousApproval)
	}
	if err := checkDestructiveDeclared(p); err != nil {
		return Approval{}, err
	}
	digest := Digest(p)
	return Approval{
		ID:        approvalID(actor, at),
		Actor:     actor,
		Digest:    digest,
		IssuedAt:  at,
		ExpiresAt: at.Add(resolveTTL(ttl)),
	}, nil
}

// Verify checks that an approval covers this plan at this time.
//
// The digest check is the load-bearing rule: a plan whose digest differs from the
// approval's -- even by one character in one parameter value -- is refused with
// ErrDigestMismatch. Approving what you saw and executing what arrived later is the
// attack this exists for, and the only defense that survives an honest mistake in a
// pipeline is comparing the whole plan, not a name and not a count.
//
// The time checks come first because an approval invalid at this instant is invalid
// regardless of what plan is presented, and they are two-sided: before issue is
// ErrNotYetValid, at or after expiry is ErrApprovalExpired. The window is closed at
// ExpiresAt, not one instant later, so an expiry is never a race between two clocks
// reading the same value.
func Verify(a Approval, p Plan, at time.Time) error {
	if at.Before(a.IssuedAt) {
		return fmt.Errorf("%w: approval %s was issued at %s, presented at %s",
			ErrNotYetValid, a.ID, a.IssuedAt.UTC().Format(time.RFC3339Nano), at.UTC().Format(time.RFC3339Nano))
	}
	if !at.Before(a.ExpiresAt) {
		return fmt.Errorf("%w: approval %s expired at %s, presented at %s",
			ErrApprovalExpired, a.ID, a.ExpiresAt.UTC().Format(time.RFC3339Nano), at.UTC().Format(time.RFC3339Nano))
	}
	if got := Digest(p); got != a.Digest {
		return fmt.Errorf("%w: approval %s binds %s, the plan digests to %s",
			ErrDigestMismatch, a.ID, a.Digest, got)
	}
	return nil
}

// Digest returns the canonical action digest of a plan.
//
// The digest is what an approval binds, so it must have two properties. Two plans that
// are equal up to ordering must digest identically, because a map and a slice built in
// a different order describe the same work and refusing one of them would make
// approvals a lottery. Two plans that differ anywhere -- including one character in one
// parameter value -- must digest differently, because "approve what you saw and run
// what arrived" is the attack this exists to prevent.
//
// The encoding is sorted (actions by target and verb, parameters by key), prefixed with
// counts and field lengths, and free of map iteration, so it is deterministic across
// processes and machines. The length prefixes are what stop text from moving across a
// boundary: the parameter sets {"ab": "c"} and {"a": "bc"} concatenate to the same
// bytes, but their keys carry different lengths, so they cannot share a digest. The
// plan's name and its destructive declaration are part of the encoding too, because a
// plan that declares its intent is a different proposal from one that stays quiet.
func Digest(p Plan) string {
	h := sha256.New()
	writeField(h, p.Name)
	if p.DeclaresDestructive {
		writeField(h, "declares-destructive")
	} else {
		writeField(h, "quiet")
	}
	actions := canonicalActions(p)
	writeField(h, strconv.Itoa(len(actions)))
	for _, a := range actions {
		writeField(h, a.Target)
		writeField(h, a.Verb)
		params := sortedParams(a.Params)
		writeField(h, strconv.Itoa(len(params)))
		for _, kv := range params {
			writeField(h, kv.Key)
			writeField(h, kv.Value)
		}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// writeField writes one length-prefixed field into a hasher.
//
// The length comes first so the digest depends on where every field begins, not only on
// the bytes it contains.
func writeField(h hash.Hash, field string) {
	h.Write([]byte(strconv.Itoa(len(field))))
	h.Write([]byte{':'})
	h.Write([]byte(field))
}

// approvalID derives a deterministic reference from the actor and the issue instant.
//
// Deterministic rather than random because two identical decisions at the same instant
// are the same decision; an ID that changed per call would make an idempotent retry
// indistinguishable from a new approval in a ledger that deduplicates by ID.
func approvalID(actor string, at time.Time) string {
	return fmt.Sprintf("approval:%s@%d", actor, at.UnixNano())
}

// resolveTTL applies the platform's approval lifetime policy.
func resolveTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return DefaultApprovalTTL
	}
	if ttl > MaxApprovalTTL {
		return MaxApprovalTTL
	}
	return ttl
}
