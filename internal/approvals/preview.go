// Package approvals implements the read-only policy preview, the digest-bound approval,
// and the execution-time reauthorization that stand between a proposed plan and the
// actions it asks to happen.
//
// G8.7: "Add read-only policy preview, action-digest approvals and execution
// reauthorization; G-F22."
//
// Approval is the moment a person takes responsibility for a plan, and everything in
// this package follows from one observation: the plan a person approved and the plan
// that runs must be the same plan, or the approval means nothing. The preview is
// read-only so that looking cannot itself change anything. The digest is computed over
// a canonical, sorted, length-prefixed encoding, so two plans that differ by one
// character cannot share an identity and one plan cannot imitate another's digest by
// sliding text across a field boundary. The approval binds that digest, not a name and
// not a timestamp.
//
// Reauthorization exists because an approval is a record that somebody said yes once,
// not a capability that survives them losing the right to say it. An approval that
// expired between preview and run must not run. An approval naming one person must not
// be spent by another. A verb the actor was allowed to name at approval time must still
// be allowed at execution time, and a failure to answer that question at all is a
// fault, not a denial, because an outage must never be mistaken for a policy decision.
//
// A plan that carries a destructive verb without declaring destructive intent is
// refused outright. That is the specific case where somebody approves what they were
// not shown: a preview that renders "destroy" among ordinary reads with no marker has
// laundered the one action the reviewer needed to notice. When destructive intent is
// declared, the actions render as irreversible and nothing else refuses them -- the
// declaration is the disagreement, not the act.
package approvals

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrUndeclaredDestructive means a plan contains an action whose verb is on the
// destructive set, but the plan does not declare destructive intent.
//
// This is the package's central preview refusal. A preview is read-only, and a plan
// quietly including "destroy" among ordinary reads is exactly the case where somebody
// approves what they were not shown. The refusal is not configurable: a plan obtains a
// preview of a destructive action only by declaring, in the plan itself, that it is
// destructive, which is the fact the reviewer needs in order to read the rest of it
// with the right posture.
var ErrUndeclaredDestructive = errors.New("plan contains a destructive action without declaring destructive intent")

// DestructiveVerbs is the fixed set of verbs this platform treats as irreversible.
//
// It is data rather than a comment so the policy can be reviewed and tested cell by
// cell. The slice is the single source of truth: a verb added here becomes destructive
// everywhere at once, and a verb removed stops being destructive everywhere at once,
// and the table test that drives every entry through IsDestructive is what keeps the
// declaration and the decision from drifting apart.
//
// The set is deliberately small. "destroy" removes a resource, "delete" removes data,
// "revoke" removes credentials or bindings, "terminate" stops a running process -- none
// of the four can be undone by running something else, which is the property that makes
// a person, rather than a rollout, the right gate.
var DestructiveVerbs = []string{"delete", "destroy", "revoke", "terminate"}

// Action is one thing a plan asks to happen: a verb applied to a target with
// parameters.
type Action struct {
	// Target is what the verb applies to, such as a database or a service.
	Target string
	// Verb is the operation. Its spelling is exact; IsDestructive normalises case and
	// surrounding space, but no other spelling is guessed at.
	Verb string
	// Params are the verb's arguments. They are rendered and digested in key order,
	// never in map iteration order.
	Params map[string]string
}

// Plan is a named set of actions plus the plan's own declaration of whether any of
// them is destructive.
//
// The declaration is a field rather than something the platform infers from the verbs,
// because inference is exactly what a hidden destructive action would defeat. The
// declaration is the plan's own statement about itself, and Approve and Preview can
// then hold the plan to its own word: no declaration plus a destructive verb is the one
// combination that is refused without appeal.
type Plan struct {
	// Name identifies the plan in review.
	Name string
	// Actions are the steps the plan asks to happen.
	Actions []Action
	// DeclaresDestructive states that the plan knows it contains actions that cannot
	// be undone. It is part of the plan's digest, because a plan that declares its
	// destructive intent is a different proposal from one that stays quiet.
	DeclaresDestructive bool
}

// KeyValue is one rendered parameter.
type KeyValue struct {
	// Key is the parameter name.
	Key string
	// Value is the parameter value.
	Value string
}

// RenderedAction is one action as previewed, with its parameters in sorted order.
//
// Irreversible is not a warning label: it is the platform's own classification carried
// into the rendering, so a caller showing a preview to a person does not have to
// re-derive the destructive set and cannot disagree with the package about which
// actions cannot be undone.
type RenderedAction struct {
	// Target is what the verb applies to.
	Target string
	// Verb is the operation.
	Verb string
	// Params are the arguments, sorted by key.
	Params []KeyValue
	// Irreversible reports that the verb is on the destructive set.
	Irreversible bool
}

// Rendered is the result of a preview: the text a person reads, the digest an approval
// binds, and the same actions in structured form for a caller that does not want to
// parse the text.
type Rendered struct {
	// Text is the deterministic rendering: actions sorted by (target, verb), parameters
	// sorted by key.
	Text string
	// Digest is the plan's canonical digest, identical to Digest(p).
	Digest string
	// Actions are the rendered actions, sorted by (target, verb).
	Actions []RenderedAction
}

// IsDestructive reports whether a verb is on the platform's destructive set.
//
// Case and surrounding whitespace are normalised before the comparison, so "Destroy"
// and " destroy " are treated the same as "destroy". The normalisation only ever moves
// a verb into the set, never out of it: the failure direction that matters is a
// destructive verb escaping notice, not a harmless one being held for review.
func IsDestructive(verb string) bool {
	v := strings.ToLower(strings.TrimSpace(verb))
	for _, d := range DestructiveVerbs {
		if v == d {
			return true
		}
	}
	return false
}

// Preview renders a plan for review without performing any part of it.
//
// Preview is read-only in the strong sense: this package contains no file, socket, or
// process handle, so there is nothing a preview could do even if a caller wanted it to.
// The rendering is sorted by (target, verb) and parameters by key, with a canonical
// tie-break on the parameters, so two equal plans render byte-identically and a reviewer
// diffing two previews sees real changes rather than map iteration order.
//
// A plan carrying a destructive verb without declaring destructive intent is refused
// with ErrUndeclaredDestructive. The rationale is the whole reason this function exists:
// a preview is the last time a person can notice, and a plan that quietly includes
// "destroy" is the case where somebody approves what they were not shown. When the plan
// declares destructive intent, the destructive actions render with Irreversible set,
// which is what the reviewer is being asked to accept.
func Preview(p Plan) (Rendered, error) {
	if err := checkDestructiveDeclared(p); err != nil {
		return Rendered{}, err
	}

	actions := canonicalActions(p)
	rendered := make([]RenderedAction, 0, len(actions))
	var b strings.Builder
	fmt.Fprintf(&b, "plan %q\n", p.Name)
	fmt.Fprintf(&b, "declares-destructive %t\n", p.DeclaresDestructive)
	for _, a := range actions {
		irreversible := IsDestructive(a.Verb)
		fmt.Fprintf(&b, "%s %s irreversible=%t\n", a.Target, a.Verb, irreversible)
		params := sortedParams(a.Params)
		for _, kv := range params {
			fmt.Fprintf(&b, "  %s=%s\n", kv.Key, kv.Value)
		}
		rendered = append(rendered, RenderedAction{
			Target:       a.Target,
			Verb:         a.Verb,
			Params:       params,
			Irreversible: irreversible,
		})
	}
	return Rendered{Text: b.String(), Digest: Digest(p), Actions: rendered}, nil
}

// checkDestructiveDeclared refuses a plan whose actions include a destructive verb
// while the plan's own declaration says it is quiet.
//
// Shared by Preview and Approve, because Approve is reachable without Preview and a
// refusal that lives on only one path is a refusal with a way around it.
func checkDestructiveDeclared(p Plan) error {
	if p.DeclaresDestructive {
		return nil
	}
	for _, a := range canonicalActions(p) {
		if IsDestructive(a.Verb) {
			return fmt.Errorf("%w: %q on %q cannot be undone", ErrUndeclaredDestructive, a.Verb, a.Target)
		}
	}
	return nil
}

// canonicalActions returns the plan's actions in the one order this package uses for
// everything: (target, verb), with the parameters' canonical encoding as the tie-break.
//
// The tie-break is load-bearing rather than cosmetic. sort.Slice is not stable, so two
// actions with the same target and verb but different parameters would otherwise have
// an order that depends on the input arrangement, and a digest computed over that order
// would not be permutation-invariant. With a total order on every distinct action, two
// arrangements of the same plan always produce the same sequence, and two actions that
// are equal in every field can be swapped freely because their rendering is identical.
func canonicalActions(p Plan) []Action {
	out := make([]Action, len(p.Actions))
	copy(out, p.Actions)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		if out[i].Verb != out[j].Verb {
			return out[i].Verb < out[j].Verb
		}
		return paramsCanonicalKey(out[i].Params) < paramsCanonicalKey(out[j].Params)
	})
	return out
}

// sortedParams returns a parameter map as key-sorted pairs.
//
// The only correct way to read a Go map into an ordered form is to sort the keys.
// Rendering and digesting both come through here, so no map iteration order can reach
// either a preview or a digest.
func sortedParams(params map[string]string) []KeyValue {
	out := make([]KeyValue, 0, len(params))
	for k, v := range params {
		out = append(out, KeyValue{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// paramsCanonicalKey encodes parameters length-prefixed for use as a sort tie-break.
// It is not a digest; it exists only so two actions with the same target and verb but
// different parameters have a stable relative order.
func paramsCanonicalKey(params map[string]string) string {
	var b strings.Builder
	for _, kv := range sortedParams(params) {
		fmt.Fprintf(&b, "%d:%s%d:%s", len(kv.Key), kv.Key, len(kv.Value), kv.Value)
	}
	return b.String()
}
