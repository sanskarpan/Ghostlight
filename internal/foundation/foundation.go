// Package foundation qualifies the shared resources a preview environment is built on.
//
// SPEC.md separates two things that are easy to conflate. The foundation is deployed
// once, by the platform, and every preview depends on it. An environment's own module
// is deployed per preview and is disposable. Mixing them is how a preview teardown ends
// up destroying the thing every other preview is standing on.
//
// So consumption of a foundation output is gated on **qualification**, not merely on
// the value existing. An output that is present but unqualified is refused. That
// distinction is the whole package: an unqualified network is far more dangerous than a
// missing one, because a missing one fails visibly while an unqualified one is used.
//
// This is deliberately not Terraform-specific. The foundation may be provisioned by any
// means; what matters is that no environment module can consume an output without
// qualification evidence attached to it.
package foundation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package.
var (
	// ErrUnqualified means a foundation output has no qualification evidence. It is
	// refused rather than assumed usable.
	ErrUnqualified = errors.New("foundation output is not qualified")
	// ErrUnknownOutput means the foundation does not publish this output at all.
	ErrUnknownOutput = errors.New("unknown foundation output")
	// ErrExpired means the qualification evidence has lapsed and must be re-established.
	ErrExpired = errors.New("foundation qualification has expired")
	// ErrForbidden means an environment module asked for something environments may not
	// consume.
	ErrForbidden = errors.New("environments may not consume this foundation output")
	// ErrNoQualificationRecord means nothing vouches for the output.
	ErrNoQualificationRecord = errors.New("no qualification record")
)

// Kind is a foundation output category.
type Kind string

const (
	// KindAccount is the AWS account a preview's resources land in.
	KindAccount Kind = "account"
	// KindRegion is the region.
	KindRegion Kind = "region"
	// KindNetwork is the shared VPC and its subnets.
	KindNetwork Kind = "network"
	// KindRole is the base execution role previews assume.
	KindRole Kind = "role"
	// KindStateBucket is the encrypted Terraform state bucket.
	KindStateBucket Kind = "state_bucket"
	// KindLogging is the platform's audit and log destination.
	KindLogging Kind = "logging"
	// KindCluster is the compute plane.
	KindCluster Kind = "cluster"
)

// Consumable reports whether an environment module may depend on this output kind.
//
// The state bucket and logging destinations are in the list because a preview does write
// state and emit logs. They are still never *destroyable* by an environment, which is a
// separate question answered by Ownership.
func (k Kind) Consumable() bool {
	switch k {
	case KindAccount, KindRegion, KindNetwork, KindRole, KindStateBucket, KindLogging, KindCluster:
		return true
	default:
		return false
	}
}

// Output is one published foundation value.
type Output struct {
	Kind Kind
	Name string
	// Value is the opaque reference or attribute. It is never parsed for meaning here,
	// because foundation values are provider-native.
	Value string
	// Ownership records who may destroy it.
	Ownership Ownership
}

// Ownership is who may destroy a resource.
type Ownership string

const (
	// OwnershipPlatform means only the platform may destroy it. Every environment output
	// has this, and it is the value that keeps a preview teardown from reaching the
	// foundation.
	OwnershipPlatform Ownership = "platform"
	// OwnershipEnvironment means an environment-scoped resource may destroy it.
	OwnershipEnvironment Ownership = "environment"
)

// Qualification is the evidence that an output is fit to be depended on.
type Qualification struct {
	Output Output
	// QualifiedBy names who established it. Empty qualification is not qualification.
	QualifiedBy string
	// QualifiedAt is when it was established.
	QualifiedAt time.Time
	// ExpiresAt bounds how long the evidence is good for. Zero means it never lapses,
	// which is only appropriate for a value that cannot change.
	ExpiresAt time.Time
	// Checks are the specific properties that were verified.
	Checks []Check
}

// Check is one verified property.
type Check struct {
	Name string
	// Passed records the outcome. A check that did not pass does not qualify the
	// output, and recording the failed checks is what makes the refusal diagnosable.
	Passed bool
	Detail string
}

// Valid reports whether every check passed.
func (q Qualification) Valid() bool {
	for _, c := range q.Checks {
		if !c.Passed {
			return false
		}
	}
	return len(q.Checks) > 0
}

// FailedChecks names the checks that did not pass.
func (q Qualification) FailedChecks() []string {
	var out []string
	for _, c := range q.Checks {
		if !c.Passed {
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Expired reports whether the evidence has lapsed at a moment.
func (q Qualification) Expired(now time.Time) bool {
	if q.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(q.ExpiresAt)
}

// Registry holds the published foundation.
type Registry interface {
	// Output returns a published foundation output.
	Output(ctx context.Context, kind Kind, name string) (Output, error)
	// Qualification returns the evidence for an output.
	Qualification(ctx context.Context, kind Kind, name string) (Qualification, error)
	// All lists every published output, for verification.
	All(ctx context.Context) ([]Output, error)
}

// Depender consumes foundation outputs for one environment.
type Depender struct {
	registry Registry
	// requiredChecks are the properties an environment's module insists on, by kind.
	requiredChecks map[Kind][]string
	now            func() time.Time
}

// Config bounds a depender.
type Config struct {
	// Now overrides the clock.
	Now func() time.Time
}

// New builds a depender.
func New(r Registry, cfg Config) (*Depender, error) {
	if r == nil {
		// Without a registry there is nothing to qualify against, so every dependency
		// would be unqualified by omission.
		return nil, errors.New("a depender requires the foundation registry")
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Depender{
		registry: r,
		// The network and role are the outputs an environment most depends on and most
		// often gets wrong, so their required checks are fixed rather than optional.
		requiredChecks: map[Kind][]string{
			KindNetwork: {"isolated_from_shared", "egress_default_deny"},
			KindRole:    {"scoped_to_environment", "no_foundation_destroy"},
			KindStateBucket: {
				"encrypted", "per_environment_prefix", "lock_enabled",
			},
		},
		now: cfg.Now,
	}, nil
}

// Require declares that an environment module depends on a foundation output, and
// returns it only if it is qualified.
//
// Every failure mode refuses. There is no "assume and continue", because the failure this
// prevents is invisible: an unqualified network does not error, it just isolates badly.
func (d *Depender) Require(ctx context.Context, kind Kind, name string) (Output, error) {
	if !kind.Consumable() {
		return Output{}, fmt.Errorf("%w: %s", ErrForbidden, kind)
	}
	out, err := d.registry.Output(ctx, kind, name)
	if err != nil {
		if errors.Is(err, ErrUnknownOutput) {
			return Output{}, fmt.Errorf("%w: %s/%s", ErrUnknownOutput, kind, name)
		}
		return Output{}, err
	}
	if out.Value == "" {
		// An empty value is not a usable dependency. It fails here rather than
		// producing an environment wired to nothing.
		return Output{}, fmt.Errorf("%w: %s/%s has no value", ErrUnqualified, kind, name)
	}

	q, err := d.registry.Qualification(ctx, kind, name)
	if err != nil {
		if errors.Is(err, ErrNoQualificationRecord) {
			return Output{}, fmt.Errorf("%w: %s/%s has no qualification record; refusing to assume it is usable",
				ErrUnqualified, kind, name)
		}
		return Output{}, err
	}
	if q.QualifiedBy == "" {
		return Output{}, fmt.Errorf("%w: %s/%s is qualified by nobody", ErrUnqualified, kind, name)
	}
	if !q.Valid() {
		return Output{}, fmt.Errorf("%w: %s/%s failed checks %v (qualified by %q)",
			ErrUnqualified, kind, name, q.FailedChecks(), q.QualifiedBy)
	}
	if q.Expired(d.now()) {
		return Output{}, fmt.Errorf("%w: %s/%s qualification lapsed at %s",
			ErrExpired, kind, name, q.ExpiresAt.Format(time.RFC3339))
	}

	// Every foundation output is platform-owned. An environment may depend on it and
	// may never destroy it, so this is asserted rather than assumed.
	if out.Ownership != OwnershipPlatform {
		return Output{}, fmt.Errorf("%w: %s/%s is marked %s-owned; a foundation output must be platform-owned",
			ErrForbidden, kind, name, out.Ownership)
	}

	// The environment's own required checks must be present in the evidence.
	if missing := d.missingChecks(q); len(missing) > 0 {
		return Output{}, fmt.Errorf("%w: %s/%s has no evidence for %v",
			ErrUnqualified, kind, name, missing)
	}
	return out, nil
}

// missingChecks reports required checks the evidence does not mention at all.
//
// A check that is absent is not a check that passed. This distinction matters because the
// evidence is written by whoever provisioned the foundation, and the most likely bug is
// forgetting to run a check rather than a check failing.
func (d *Depender) missingChecks(q Qualification) []string {
	required, ok := d.requiredChecks[q.Output.Kind]
	if !ok {
		return nil
	}
	present := map[string]bool{}
	for _, c := range q.Checks {
		present[c.Name] = true
	}
	var missing []string
	for _, name := range required {
		if !present[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

// PlatformOwned reports whether an output is platform-owned, which is what keeps it out
// of any environment's destroy scope.
func PlatformOwned(o Output) bool { return o.Ownership == OwnershipPlatform }

// DestroyPlan is the set of outputs an environment may destroy.
//
// It is derived by exclusion rather than by inclusion: everything platform-owned is
// excluded. A new foundation output is therefore excluded by default, which is the safe
// direction. An allowlist would make every new output destroyable until someone noticed.
type DestroyPlan struct {
	// EnvironmentOwned is what this environment may destroy.
	EnvironmentOwned []Output
	// Excluded is every platform-owned output encountered, with its reason.
	Excluded []Exclusion
}

// Exclusion is an output kept out of a destroy scope.
type Exclusion struct {
	Output Output
	Reason string
}

// BuildDestroyPlan decides what an environment may destroy.
func BuildDestroyPlan(outputs []Output, environmentOwnedNativeIDs []string) (DestroyPlan, error) {
	// The native IDs the environment legitimately owns. Anything not on this list is not
	// ours to remove.
	owned := map[string]bool{}
	for _, id := range environmentOwnedNativeIDs {
		owned[id] = true
	}

	var plan DestroyPlan
	for _, o := range outputs {
		if PlatformOwned(o) {
			plan.Excluded = append(plan.Excluded, Exclusion{
				Output: o,
				Reason: "platform-owned foundation resource; never in an environment's destroy scope",
			})
			continue
		}
		if !owned[o.Value] {
			// Not platform-owned, and not ours either. Refusing is the same reasoning the
			// ledger applies to an unknown resource.
			plan.Excluded = append(plan.Excluded, Exclusion{
				Output: o,
				Reason: "not among this environment's recorded native ids",
			})
			continue
		}
		plan.EnvironmentOwned = append(plan.EnvironmentOwned, o)
	}

	// A stable order so two runs produce the same plan and the same audit trail.
	sort.Slice(plan.Excluded, func(i, j int) bool {
		if plan.Excluded[i].Output.Kind != plan.Excluded[j].Output.Kind {
			return plan.Excluded[i].Output.Kind < plan.Excluded[j].Output.Kind
		}
		return plan.Excluded[i].Output.Name < plan.Excluded[j].Output.Name
	})
	sort.Slice(plan.EnvironmentOwned, func(i, j int) bool {
		if plan.EnvironmentOwned[i].Kind != plan.EnvironmentOwned[j].Kind {
			return plan.EnvironmentOwned[i].Kind < plan.EnvironmentOwned[j].Kind
		}
		return plan.EnvironmentOwned[i].Name < plan.EnvironmentOwned[j].Name
	})
	return plan, nil
}

// StateLocation is where an environment's Terraform state lives.
//
// It is derived entirely from the environment ID and never from anything a customer
// supplies, because the state prefix is effectively a path into the platform's own
// bucket. A caller-chosen prefix would be a traversal primitive against the state store.
type StateLocation struct {
	// Bucket is the dedicated encrypted state bucket.
	Bucket string
	// Prefix is the per-environment object prefix.
	Prefix string
	// LockName is the DynamoDB lock name for this environment's state.
	LockName string
}

// ErrUnsafeStateLocation means a derived location escaped its bucket.
var ErrUnsafeStateLocation = errors.New("derived state location escapes the foundation bucket")

// StatePrefix returns the object prefix for an environment.
func StatePrefix(environmentID string) (string, error) {
	if environmentID == "" {
		return "", errors.New("an environment id is required")
	}
	if strings.ContainsAny(environmentID, "/\\.\x00") || environmentID == "." || environmentID == ".." {
		// The ID is platform-issued, so this should be impossible. Refusing anyway means
		// a bug in ID generation cannot become a path traversal into the state store.
		return "", fmt.Errorf("%w: environment id %q is not a safe prefix segment", ErrUnsafeStateLocation, environmentID)
	}
	return "environments/" + environmentID + "/terraform/", nil
}

// StateLockName returns the lock name for an environment's state.
func StateLockName(environmentID string) (string, error) {
	if _, err := StatePrefix(environmentID); err != nil {
		return "", err
	}
	return "ghostlight-tfstate-" + environmentID, nil
}

// BuildStateLocation derives where an environment's state lives.
func BuildStateLocation(bucket, environmentID string) (StateLocation, error) {
	prefix, err := StatePrefix(environmentID)
	if err != nil {
		return StateLocation{}, err
	}
	lock, err := StateLockName(environmentID)
	if err != nil {
		return StateLocation{}, err
	}
	if bucket == "" {
		return StateLocation{}, errors.New("a state bucket is required")
	}
	if strings.ContainsAny(bucket, "/\\.\x00") {
		return StateLocation{}, fmt.Errorf("%w: %q is not a bucket name", ErrUnsafeStateLocation, bucket)
	}
	return StateLocation{Bucket: bucket, Prefix: prefix, LockName: lock}, nil
}
