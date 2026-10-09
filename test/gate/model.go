// Package gate verifies the G1 gate: duplicate, reorder, crash and timeout
// scenarios cannot leak unowned resources or resurrect destroyed IDs.
//
// The checklist is explicit about what this gate may and may not claim:
//
//	"This gate is satisfied against the independent reference model with a faked
//	provider; deployed native-resource proof is the G2 gate and must not be claimed
//	here."
//
// So this is a model check, not a claim about real infrastructure. What it does prove
// is that the platform's own logic has no path to the two failure modes the gate names,
// under every ordering and fault the model can express.
//
// The reference model is deliberately written from the invariants rather than by
// reusing the code under test. A model that calls the same helpers proves only that the
// helpers agree with themselves.
package gate

import (
	"fmt"
	"sort"

	"github.com/sanskarpan/Ghostlight/internal/resource"
)

// Invariant is a property the platform must never violate.
type Invariant string

const (
	// InvNoUnownedSurvivor means every provider resource is either accounted for in
	// the ledger or explicitly quarantined. Nothing may be quietly unaccounted for,
	// because an unaccounted resource is a leak nobody is tracking.
	InvNoUnownedSurvivor Invariant = "no unowned resource survives untracked"
	// InvNoResurrection means a tombstoned allocation cannot come back. An ID that
	// returns is one a customer's environment may be rebuilt on.
	InvNoResurrection Invariant = "a destroyed ID is never resurrected"
	// InvNoWrongfulDeletion means nothing outside the ledger's authority was deleted.
	InvNoWrongfulDeletion Invariant = "nothing outside delete authority is deleted"
	// InvNoDuplicateCreate means a logical dependency exists exactly once.
	InvNoDuplicateCreate Invariant = "no duplicate resource for one logical key"
)

// Violation is a broken invariant.
type Violation struct {
	Invariant Invariant
	Detail    string
	Resource  string
}

func (v Violation) String() string {
	return fmt.Sprintf("%s: %s (%s)", v.Invariant, v.Detail, v.Resource)
}

// Reference is an independent model of what should exist.
//
// It is built by the scenario, not by the code under test, so agreement between the two
// is evidence rather than tautology.
type Reference struct {
	// want is the logical key of every resource that should exist, mapped to how many
	// copies of it.
	want map[string]int
	// destroyed records logical keys that have been tombstoned.
	destroyed map[string]bool
}

// NewReference builds an empty reference.
func NewReference() *Reference {
	return &Reference{want: map[string]int{}, destroyed: map[string]bool{}}
}

// Expect records that a logical key should exist.
func (r *Reference) Expect(logicalKey string) {
	r.want[logicalKey]++
}

// Absent records that a logical key should not exist.
func (r *Reference) Absent(logicalKey string) {
	r.want[logicalKey] = 0
}

// Destroy records that a logical key has been tombstoned.
func (r *Reference) Destroy(logicalKey string) {
	r.destroyed[logicalKey] = true
	r.want[logicalKey] = 0
}

// Wants reports whether the model expects the key.
func (r *Reference) Wants(logicalKey string) bool { return r.want[logicalKey] > 0 }

// Destroyed reports whether the key was tombstoned.
func (r *Reference) Destroyed(logicalKey string) bool { return r.destroyed[logicalKey] }

// Expectations returns the model's view, sorted so failures are reproducible.
func (r *Reference) Expectations() map[string]int {
	out := make(map[string]int, len(r.want))
	for k, v := range r.want {
		out[k] = v
	}
	return out
}

// State is what actually happened, read back from the implementation.
type State struct {
	// LedgerAllocs is every allocation the platform recorded.
	LedgerAllocs []resource.Allocation
	// ProviderResources is every resource the provider actually holds, whether or not
	// the platform knows about it.
	ProviderResources []string
	// Quarantined is what the janitor refused to delete.
	Quarantined []string
	// Deleted is what was removed from the provider.
	Deleted []string
}

// Check evaluates the state against the reference and returns every violation.
//
// It returns all of them rather than the first, because a gate that stops at the first
// failure makes each run cost a full cycle to discover a problem that was already there.
func Check(ref *Reference, st State) []Violation {
	var out []Violation

	// Index what exists, keyed by logical key.
	live := map[string][]string{}
	for _, id := range st.ProviderResources {
		key := logicalKeyOf(id)
		live[key] = append(live[key], id)
	}

	// A tombstoned key must not exist at all.
	keys := make([]string, 0, len(ref.want))
	for k := range ref.want {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		existing := live[key]

		if ref.Destroyed(key) && len(existing) > 0 {
			out = append(out, Violation{
				Invariant: InvNoResurrection,
				Detail:    "a tombstoned logical key exists again in the provider",
				Resource:  key,
			})
		}

		if ref.Wants(key) {
			if len(existing) == 0 {
				out = append(out, Violation{
					Invariant: InvNoUnownedSurvivor,
					Detail:    "an expected resource is missing",
					Resource:  key,
				})
			}
			if len(existing) > 1 {
				// Two copies of one logical key is not a duplicate create in the
				// platform's favour; it is an unbounded cost.
				out = append(out, Violation{
					Invariant: InvNoDuplicateCreate,
					Detail:    fmt.Sprintf("%d copies exist for one logical key", len(existing)),
					Resource:  key,
				})
			}
		}
	}

	// Nothing may exist that the model does not expect, unless it was quarantined.
	// An unexpected survivor is the leak the gate names.
	quarantined := map[string]bool{}
	for _, q := range st.Quarantined {
		quarantined[logicalKeyOf(q)] = true
	}
	for _, id := range st.ProviderResources {
		key := logicalKeyOf(id)
		if ref.Wants(key) {
			continue
		}
		if quarantined[key] {
			// Tracked, and a person will decide. That is the janitor's contract.
			continue
		}
		out = append(out, Violation{
			Invariant: InvNoUnownedSurvivor,
			Detail:    "an unexpected resource exists and is neither expected nor quarantined",
			Resource:  key,
		})
	}

	// Every deletion must have been of something the model expected to be removed.
	for _, d := range st.Deleted {
		key := logicalKeyOf(d)
		if ref.Wants(key) {
			out = append(out, Violation{
				Invariant: InvNoWrongfulDeletion,
				Detail:    "a resource the model still expects was deleted",
				Resource:  key,
			})
		}
	}

	return out
}

// CheckAll is the gate's entry point: it returns an error naming every violation.
func CheckAll(ref *Reference, st State) error {
	v := Check(ref, st)
	if len(v) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(v))
	for _, x := range v {
		msgs = append(msgs, x.String())
	}
	sort.Strings(msgs)
	return fmt.Errorf("G1 gate violated:\n  %s", joinLines(msgs))
}

func joinLines(s []string) string {
	out := ""
	for i, m := range s {
		if i > 0 {
			out += "\n  "
		}
		out += m
	}
	return out
}

// logicalKeyOf extracts the logical key from a resource identifier.
//
// Identifiers are shaped "<environment>/<logicalKey>" so a test failure names something
// an operator can act on rather than an opaque handle.
func logicalKeyOf(id string) string {
	for i := len(id) - 1; i >= 0; i-- {
		if id[i] == '/' {
			return id[i+1:]
		}
	}
	return id
}
