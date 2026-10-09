package foundation

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// MemoryRegistry is an in-memory Registry.
//
// It is the reference implementation, and the place where "unqualified means unusable"
// is made structural rather than aspirational: there is no read path that returns an
// output without also being able to return its qualification.
type MemoryRegistry struct {
	outputs map[string]Output
	quals   map[string]Qualification
	now     func() time.Time
}

func key(kind Kind, name string) string { return string(kind) + "/" + name }

// NewMemoryRegistry builds an empty registry.
func NewMemoryRegistry(now func() time.Time) *MemoryRegistry {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &MemoryRegistry{
		outputs: map[string]Output{},
		quals:   map[string]Qualification{},
		now:     now,
	}
}

// Publish adds a foundation output.
func (m *MemoryRegistry) Publish(o Output) error {
	if o.Kind == "" || o.Name == "" {
		return fmt.Errorf("a foundation output must name its kind and name")
	}
	// A foundation output is platform-owned by definition. Refusing an
	// environment-owned one here is what stops a mislabelled output from ever being
	// depended upon, rather than relying on every consumer to check.
	if o.Ownership != OwnershipPlatform {
		return fmt.Errorf(
			"foundation output %s/%s cannot be published as %s-owned; foundation resources are platform-owned",
			o.Kind, o.Name, o.Ownership)
	}
	m.outputs[key(o.Kind, o.Name)] = o
	return nil
}

// Qualify records qualification evidence for an output.
func (m *MemoryRegistry) Qualify(q Qualification) error {
	if q.Output.Kind == "" || q.Output.Name == "" {
		return fmt.Errorf("qualification must name the output it qualifies")
	}
	if q.QualifiedBy == "" {
		return fmt.Errorf("%w: qualification requires someone to have established it", ErrUnqualified)
	}
	k := key(q.Output.Kind, q.Output.Name)
	if _, ok := m.outputs[k]; !ok {
		return fmt.Errorf("%w: %s", ErrUnknownOutput, k)
	}
	q.Output = m.outputs[k]
	m.quals[k] = q
	return nil
}

// Output returns a published output.
func (m *MemoryRegistry) Output(_ context.Context, kind Kind, name string) (Output, error) {
	o, ok := m.outputs[key(kind, name)]
	if !ok {
		return Output{}, fmt.Errorf("%w: %s/%s", ErrUnknownOutput, kind, name)
	}
	return o, nil
}

// Qualification returns the evidence for an output.
func (m *MemoryRegistry) Qualification(_ context.Context, kind Kind, name string) (Qualification, error) {
	q, ok := m.quals[key(kind, name)]
	if !ok {
		return Qualification{}, fmt.Errorf("%w: %s/%s", ErrNoQualificationRecord, kind, name)
	}
	return q, nil
}

// All lists every published output.
func (m *MemoryRegistry) All(context.Context) ([]Output, error) {
	out := make([]Output, 0, len(m.outputs))
	for _, o := range m.outputs {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// NetworkOutput is the shared VPC fixture.
func NetworkOutput() Output {
	return Output{
		Kind: KindNetwork, Name: "primary", Value: "vpc-0123abc",
		Ownership: OwnershipPlatform,
	}
}

// RoleOutput is the base execution role fixture.
func RoleOutput() Output {
	return Output{
		Kind: KindRole, Name: "preview-base", Value: "arn:aws:iam::123456789012:role/preview-base",
		Ownership: OwnershipPlatform,
	}
}

// StateOutput is the encrypted state bucket fixture.
func StateOutput() Output {
	return Output{
		Kind: KindStateBucket, Name: "tfstate", Value: "ghostlight-tfstate",
		Ownership: OwnershipPlatform,
	}
}

// PassingChecks returns the checks an output of a kind must carry to qualify.
//
// Exported so a qualification written by an operator and the checks the depender
// requires derive from the same list and cannot drift apart silently.
func PassingChecks(kind Kind) []Check {
	var names []string
	switch kind {
	case KindNetwork:
		names = []string{"isolated_from_shared", "egress_default_deny"}
	case KindRole:
		names = []string{"scoped_to_environment", "no_foundation_destroy"}
	case KindStateBucket:
		names = []string{"encrypted", "per_environment_prefix", "lock_enabled"}
	default:
		names = []string{"present"}
	}
	out := make([]Check, 0, len(names))
	for _, n := range names {
		out = append(out, Check{Name: n, Passed: true, Detail: "verified"})
	}
	return out
}
