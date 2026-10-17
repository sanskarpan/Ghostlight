// Package drift classifies the resources a customer's cloud actually holds and turns
// the classification into a remediation plan a person reviews before anything runs.
//
// It is the enterprise sibling of internal/janitor, and it inherits the janitor's
// central rule at fleet scale: an unowned resource is quarantined, never deleted,
// because nobody can prove whose it is. Drift detection adds one more act to that
// rule. Classification never destroys anything; it only describes. Destruction, when
// it is ever appropriate, is a separate act expressed as a remediation plan that is
// bounded, deterministic, reviewed by a named human, and serialized so two operators
// cannot run the same remediation at once.
//
// SPEC.md, fleet policy, drift and reliability programs: "Observe first; unknown
// ownership forbids automatic deletion. Default remediation is a reviewed plan,
// serialized by existing native locks." Every rule in this package exists to keep
// those two sentences true.
//
// The classifier is deliberately fail-closed. An object is owned only when the exact
// ownership tag key the platform writes carries a non-empty value that names an
// environment the fleet still expects. A tag key that merely resembles the ownership
// key ("ghostlight_env" for "ghostlight-env") is not ownership: reading an answer from
// a key we did not write is how a foreign object becomes deletable. An empty
// ownership tag is not ownership either, for the janitor's reason: it looks like an
// answer without being one. An object that is neither of those things is described as
// unmanaged or foreign, and neither of those is ever deletable.
//
// The planner refuses in three more places. It never plans ActionRemove for anything
// but an orphaned object, and only when removal was explicitly allowed. It never
// plans ActionTag at all, because stamping an ownership tag onto a resource whose
// provenance cannot be proven manufactures exactly the false claim the classifier
// refuses to trust. And it refuses a plan larger than its bound rather than truncating
// it, because a truncated remediation plan that looks complete is a plan that
// silently leaves half the drift behind.
package drift

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package.
var (
	// ErrNoReviewer means a plan was approved without a named reviewer. An anonymous
	// approval is not a review, because the one thing review has to produce is
	// somebody to ask when the classification turns out to have been wrong.
	ErrNoReviewer = errors.New("remediation plan requires a named reviewer")
	// ErrUnreviewed means execution was attempted before approval. Remediation is the
	// one place where a classification mistake becomes a deletion, so an unreviewed
	// plan must not run.
	ErrUnreviewed = errors.New("remediation plan has not been reviewed")
	// ErrPlanTooLarge means the drift found exceeds the plan's bound. It is a refusal
	// rather than a truncation, because a truncated remediation plan that looks
	// complete is a plan that silently leaves half the drift behind.
	ErrPlanTooLarge = errors.New("remediation plan exceeds the maximum number of steps")
	// ErrAlreadyExecuted means the plan has already run. Two operators running the
	// same remediation at once is how a remove step races a tag step.
	ErrAlreadyExecuted = errors.New("remediation plan has already been executed")
	// ErrNoGuard means execution was attempted without a serialization guard. A
	// serialization point that can be skipped silently is not a serialization point.
	ErrNoGuard = errors.New("remediation execution requires a serialization guard")
	// ErrNoPlan means the plan being approved or executed has no identity, so a
	// decision about it would be a decision about nothing and could not be attributed
	// later.
	ErrNoPlan = errors.New("no identified remediation plan")
	// ErrMissingObjectID means a finding that would become a plan step names no
	// object. A step without a target is a destructive action waiting to happen.
	ErrMissingObjectID = errors.New("drift finding names no object identity")
)

// DefaultOwnershipTagKey is the default key the platform writes on resources it
// creates.
//
// It is the key the classifier reads ownership from, and only this exact key: a tag
// whose key merely resembles it must never be read as ownership, because the answer
// would be about a key nobody on the platform wrote.
const DefaultOwnershipTagKey = "ghostlight-env"

// DefaultMaxSteps bounds a remediation plan when Options carries no bound.
//
// It exists so that "no bound configured" cannot mean "unbounded": a fleet scan can
// observe more objects than any person can review in one sitting, and a plan nobody
// finishes reviewing is a plan that gets rubber-stamped.
const DefaultMaxSteps = 500

// Confidence values attached to each classification. They are percentages in 0..100
// and they are advisory: the class is the decision, and confidence never overrides a
// refusal. An owned object is the only class that may authorise anything, and that
// requires the exact ownership tag plus an expected environment, not a high score.
const (
	ConfidenceOwned     = 95
	ConfidenceOrphaned  = 90
	ConfidenceUnmanaged = 80
	ConfidenceForeign   = 70
	ConfidenceUnknown   = 40
)

// Class is what a drift scan concluded about one observed object.
type Class string

const (
	// ClassOwned means the object carries a well-formed ownership tag naming an
	// environment the fleet still expects. It needs nothing.
	ClassOwned Class = "owned"
	// ClassUnmanaged means the object has no ownership tag and its type is one the
	// fleet knows. It is the customer's own object, visible in their account, and the
	// fleet does not manage it. Never deletable.
	ClassUnmanaged Class = "unmanaged"
	// ClassForeign means the object has no ownership tag and its type is unknown. It
	// belongs to somebody else, or to something this fleet cannot reason about. Never
	// deletable.
	ClassForeign Class = "foreign"
	// ClassOrphaned means the object carries our ownership tag but names an
	// environment that is not expected. We made it and its environment is gone, which
	// makes it the only class removal may ever be considered for, and only by a person.
	ClassOrphaned Class = "orphaned"
	// ClassUnknown means nothing could be established: an empty ownership tag, a tag
	// key that merely resembles ours, or no ownership tag key configured at all.
	// Failing closed to unknown is the point.
	ClassUnknown Class = "unknown"
)

// CloudObject is one object observed in a customer's cloud.
type CloudObject struct {
	// ID is the provider's identifier. It is the only handle a plan step may target.
	ID string `json:"id"`
	// Tags are the tags the provider reports. Ownership is established from these,
	// because after an environment is gone the tags are the only stable handle left.
	Tags map[string]string `json:"tags,omitempty"`
	// Type is the provider's resource type, such as "aws_db_instance".
	Type string `json:"type"`
}

// Finding is one classification.
type Finding struct {
	// Object is the observed object, carried through unchanged so a plan step always
	// refers to exactly what the classifier saw.
	Object CloudObject `json:"object"`
	// Class is the conclusion.
	Class Class `json:"class"`
	// Reason is operator-facing context: why the class was chosen, in words a person
	// reviewing a plan can check against the cloud.
	Reason string `json:"reason"`
	// Confidence is how sure the classifier is, 0..100. It is carried for review
	// ordering; it must never be the thing that authorises an action.
	Confidence int `json:"confidence"`
}

// Expected is what the fleet currently believes it owns.
//
// Classification is relative to this: the same object is owned under one expected set
// and orphaned under another, which is the whole point. When an environment is
// retired, this set is what changes, and every object tagged for it becomes orphaned
// without anybody having to hunt for them.
type Expected struct {
	// TagKey is the ownership tag key the platform writes. It must be the exact key:
	// a near miss fails closed. An empty TagKey means ownership cannot be established
	// at all, and every object is then unknown.
	TagKey string `json:"tag_key"`
	// Environments names the environment IDs the fleet still expects to exist.
	Environments []string `json:"environments"`
	// KnownTypes names the resource types the fleet knows how to reason about.
	KnownTypes []string `json:"known_types"`
}

// Owns reports whether an environment is expected.
func (e Expected) Owns(environmentID string) bool {
	for _, id := range e.Environments {
		if id == environmentID {
			return true
		}
	}
	return false
}

// KnowsType reports whether a resource type is one the fleet knows.
func (e Expected) KnowsType(kind string) bool {
	for _, known := range e.KnownTypes {
		if known == kind {
			return true
		}
	}
	return false
}

// Classify decides what one observed object is, relative to what the fleet expects.
//
// It is a pure function: classification never destroys, never mutates, and never
// touches the cloud. That is deliberate, because classification is the step most
// likely to be wrong and the step that must therefore have no consequences. The
// consequences live in a plan, which a person approves.
//
// The rules, in order:
//  1. Tagged with the exact ownership tag and the named environment is expected:
//     owned.
//  2. Tagged with the exact ownership tag and the environment is not expected:
//     orphaned. This is the dangerous-to-act-on class: the object is ours, but
//     proving removal is safe needs a person, because the environment that would
//     explain it is gone.
//  3. Tagged with an empty value: unknown. An empty tag on a resource we did not
//     create is worse than no tag, because it looks like an answer.
//  4. Untagged and the type is known: unmanaged, never deletable.
//  5. Untagged and the type is unknown: foreign, never deletable.
//  6. Anything else fails closed to unknown, including a tag key that merely
//     resembles the ownership key. The classifier never guesses ownership from a
//     key the platform did not write.
func Classify(obj CloudObject, expected Expected) Finding {
	if expected.TagKey == "" {
		return Finding{
			Object: obj, Class: ClassUnknown, Confidence: ConfidenceUnknown,
			Reason: "no ownership tag key is configured, so ownership cannot be established and no object may be treated as ours",
		}
	}

	if value, tagged := obj.Tags[expected.TagKey]; tagged {
		if strings.TrimSpace(value) == "" {
			return Finding{
				Object: obj, Class: ClassUnknown, Confidence: ConfidenceUnknown,
				Reason: fmt.Sprintf("ownership tag %q is present but empty; an empty tag looks like an answer without being one", expected.TagKey),
			}
		}
		if expected.Owns(value) {
			return Finding{
				Object: obj, Class: ClassOwned, Confidence: ConfidenceOwned,
				Reason: fmt.Sprintf("tagged %q=%q and environment %q is expected", expected.TagKey, value, value),
			}
		}
		return Finding{
			Object: obj, Class: ClassOrphaned, Confidence: ConfidenceOrphaned,
			Reason: fmt.Sprintf("tagged %q=%q but environment %q is not expected; the object is ours and its environment is gone", expected.TagKey, value, value),
		}
	}

	if near, ok := nearMissTagKey(obj.Tags, expected.TagKey); ok {
		return Finding{
			Object: obj, Class: ClassUnknown, Confidence: ConfidenceUnknown,
			Reason: fmt.Sprintf("tag key %q resembles the ownership key %q but is not it; refusing to read ownership from a key the platform did not write", near, expected.TagKey),
		}
	}

	if expected.KnowsType(obj.Type) {
		return Finding{
			Object: obj, Class: ClassUnmanaged, Confidence: ConfidenceUnmanaged,
			Reason: fmt.Sprintf("no ownership tag and type %q is known; it exists in the account and the fleet does not manage it", obj.Type),
		}
	}

	return Finding{
		Object: obj, Class: ClassForeign, Confidence: ConfidenceForeign,
		Reason: fmt.Sprintf("no ownership tag and type %q is unknown; it belongs to somebody else and is never deletable", obj.Type),
	}
}

// nearMissTagKey finds a tag key that is the ownership key after folding case and
// separators ("ghostlight_env" for "ghostlight-env").
//
// Such a key is the most dangerous kind of almost-answer: it is close enough to
// invite a guess and was not written by the platform. Returning it lets the
// classifier fail closed and say exactly which key it refused.
func nearMissTagKey(tags map[string]string, ownership string) (string, bool) {
	target := normalizeTagKey(ownership)
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	// Sorted so the refusal names the same key on every scan.
	sort.Strings(keys)
	for _, k := range keys {
		if k == ownership {
			continue
		}
		if normalizeTagKey(k) == target {
			return k, true
		}
	}
	return "", false
}

// normalizeTagKey folds case and folds all common tag separators to single spaces, so
// "Ghostlight-Env", "ghostlight_env" and "ghostlight env" are one key to the near-miss
// check while still being distinct map keys to everything else.
func normalizeTagKey(key string) string {
	folded := strings.Map(func(r rune) rune {
		switch r {
		case '-', '_', '.', '/', ':':
			return ' '
		}
		return r
	}, strings.ToLower(key))
	return strings.Join(strings.Fields(folded), " ")
}

// Action is one remediation verb. The vocabulary is small on purpose: every word in
// it is something a person can review and an executor can serialize.
type Action string

const (
	// ActionReview asks a person to look at an object and decide. It is the safe
	// default for objects the fleet does not own.
	ActionReview Action = "review"
	// ActionTag exists in the vocabulary but BuildPlan never emits it. Stamping an
	// ownership tag onto a resource whose provenance cannot be proven would
	// manufacture the exact claim Classify refuses to trust, so the planner's answer
	// to "should we tag this" is always no.
	ActionTag Action = "tag"
	// ActionQuarantine flags an object for human attention without touching it. It is
	// the strongest action a plan may contain when removal was not explicitly
	// allowed.
	ActionQuarantine Action = "quarantine"
	// ActionRemove destroys an object. It is the only destructive verb, it is planned
	// only for orphaned objects, and only when Options.AllowRemoval was set.
	ActionRemove Action = "remove"
)

// Step is one action a plan asks for, against one object.
type Step struct {
	// ObjectID is the provider identity the action targets.
	ObjectID string `json:"object_id"`
	// Action is what the plan asks to do.
	Action Action `json:"action"`
}

// Plan is a reviewed, serialized remediation plan.
//
// It is a value: approval and execution each return or update it, so the reviewed
// plan and the executed plan are the same artifact rather than two things that
// drifted apart. Executed is the one field updated in place, by Execute, under the
// caller's guard.
type Plan struct {
	// ID is the plan's identity, derived from its steps. The same drift always
	// yields the same ID, and a changed plan is a changed ID, which is what review
	// and audit need.
	ID string `json:"id"`
	// Steps are the remediation actions, sorted by object id.
	Steps []Step `json:"steps"`
	// Reviewed starts false. It is set only by Approve, with a named reviewer.
	Reviewed bool `json:"reviewed"`
	// Reviewer is who approved the plan.
	Reviewer string `json:"reviewer,omitempty"`
	// ReviewedAt is when they approved it.
	ReviewedAt time.Time `json:"reviewed_at"`
	// Executed is set once, under the guard, by Execute.
	Executed bool `json:"executed"`
}

// Options governs how a plan is built.
type Options struct {
	// AllowRemoval permits ActionRemove steps for orphaned objects. Without it the
	// strongest action BuildPlan can emit is ActionQuarantine, no matter what the
	// findings say.
	AllowRemoval bool `json:"allow_removal"`
	// MaxSteps bounds the plan. Zero or negative means DefaultMaxSteps; there is no
	// value that means unbounded.
	MaxSteps int `json:"max_steps"`
}

// BuildPlan turns findings into a bounded, deterministic remediation plan for review.
//
// Four properties make the plan safe to review and safe to run:
//
//  1. Removal is planned only for an orphaned object, and only when AllowRemoval is
//     set. Unmanaged and foreign objects never receive ActionRemove under any
//     options: unmanaged objects are the customer's own, and foreign objects belong
//     to somebody else. Owned objects receive no step at all; there is nothing to
//     remediate.
//  2. Without AllowRemoval the strongest action this planner can produce is
//     ActionQuarantine, and unknown classifications are quarantined either way,
//     because an unprovable object is exactly what a person must look at.
//  3. The plan is bounded by MaxSteps and refused whole when it is too large.
//     Truncating would produce a plan that looks complete while leaving the rest of
//     the drift in place.
//  4. Steps are sorted by object id and then action, so the same drift always
//     produces the same plan and the plan's ID is a digest of its steps. A plan that
//     changes between two identical scans cannot be reviewed, because the reviewer
//     never saw the plan that runs.
func BuildPlan(findings []Finding, opts Options) (Plan, error) {
	max := opts.MaxSteps
	if max <= 0 {
		max = DefaultMaxSteps
	}

	steps := make([]Step, 0, len(findings))
	for _, f := range findings {
		action, wanted := planAction(f.Class, opts.AllowRemoval)
		if !wanted {
			continue
		}
		if f.Object.ID == "" {
			return Plan{}, fmt.Errorf("%w: a finding classified %q names no object, so no step can target it", ErrMissingObjectID, f.Class)
		}
		steps = append(steps, Step{ObjectID: f.Object.ID, Action: action})
	}

	sort.Slice(steps, func(i, j int) bool {
		if steps[i].ObjectID != steps[j].ObjectID {
			return steps[i].ObjectID < steps[j].ObjectID
		}
		return steps[i].Action < steps[j].Action
	})

	if len(steps) > max {
		return Plan{}, fmt.Errorf("%w: %d findings produce %d steps and the limit is %d; refusing beats silently leaving drift behind",
			ErrPlanTooLarge, len(findings), len(steps), max)
	}

	return Plan{ID: planID(steps), Steps: steps}, nil
}

// planAction maps a classification to the action a plan may ask for. It is the one
// place where a class becomes a verb, and it is deliberately total and conservative:
// a class this package did not produce is quarantined, not skipped.
func planAction(class Class, allowRemoval bool) (Action, bool) {
	switch class {
	case ClassOwned:
		// Owned and expected: nothing to do, and a step for it would be noise that
		// makes reviewers skim.
		return "", false
	case ClassOrphaned:
		if allowRemoval {
			return ActionRemove, true
		}
		return ActionQuarantine, true
	case ClassUnmanaged, ClassForeign:
		// Both are somebody's real resource: the customer's own, or another party's.
		// Review is the only action that can be asked for.
		return ActionReview, true
	default:
		// ClassUnknown and anything unrecognised fail closed to quarantine.
		return ActionQuarantine, true
	}
}

// planID derives a plan identity from its steps.
//
// It is content-addressed so that two scans of the same drift produce the same plan
// identity, and any change to the steps produces a different one. Review is a
// statement about an exact plan, and this is what makes that statement checkable.
func planID(steps []Step) string {
	h := sha256.New()
	for _, s := range steps {
		fmt.Fprintf(h, "%s\x00%s\x00", s.ObjectID, s.Action)
	}
	return "plan-" + hex.EncodeToString(h.Sum(nil))
}

// Approve records that a named human reviewed a plan, and when.
//
// The reviewer must be named: an anonymous approval is not a review, because the one
// thing review has to produce is somebody to ask when the classification turns out to
// have been wrong. Approval changes only the review fields, so what was approved is
// byte for byte the plan that will run.
func Approve(plan Plan, reviewer string, at time.Time) (Plan, error) {
	if plan.ID == "" {
		return plan, ErrNoPlan
	}
	if strings.TrimSpace(reviewer) == "" {
		return plan, ErrNoReviewer
	}
	plan.Reviewed = true
	plan.Reviewer = reviewer
	plan.ReviewedAt = at
	return plan, nil
}

// Guard is the lock-like serialization point Execute runs under.
//
// *sync.Mutex satisfies it. The same guard must be shared by every executor of the
// same plan; a guard constructed per call guards nothing.
type Guard interface {
	Lock()
	Unlock()
}

// Execute records that a reviewed plan has run, under a guard that serializes it.
//
// The plan is updated in place, and that is the point: two operators who hold the
// same plan and the same guard cannot both execute it, because the second one to
// take the lock sees Executed already true and is refused. Two operators running the
// same remediation at once is how a remove step races a tag step, so serialization is
// not optional: a nil guard is refused rather than defaulted, because a serialization
// point that can be skipped silently is not a serialization point.
//
// This package has no side effects beyond the plan; applying a step belongs to the
// executor that owns the native locks. Execute is the model of the gate that executor
// must pass through: reviewed, exactly once, and under the lock.
func Execute(plan *Plan, guard Guard) error {
	if plan == nil || plan.ID == "" {
		return ErrNoPlan
	}
	if guard == nil {
		return ErrNoGuard
	}

	// Every check happens inside the guard. Checking review state outside it would
	// leave exactly the window this exists to close: two operators reading "not yet
	// executed" at the same time.
	guard.Lock()
	defer guard.Unlock()

	if !plan.Reviewed {
		return ErrUnreviewed
	}
	if plan.Executed {
		return ErrAlreadyExecuted
	}
	plan.Executed = true
	return nil
}
