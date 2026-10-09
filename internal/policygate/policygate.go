// Package policygate refuses to start a preview's pods until its namespace policies
// are confirmed installed.
//
// G2.3: "Install namespace/network/egress/resource/pod policies before candidate pods."
// The ordering is the safety property. A pod that starts before its network policy
// exists has a window in which it can reach anything, and that window is exactly when an
// attacker-controlled image would use it. A pod that starts before its resource quota
// exists can consume the node's allocation before anyone notices.
//
// So pod admission depends on verified policy presence, not on policies having been
// requested. Requesting a policy and having it are different states, and only one of
// them constrains anything.
//
// The second property is drift. Policies can be deleted out from under a running
// preview. A gate that checked once at startup and never again would keep a preview
// running with no boundary at all, so readiness is re-verified, not remembered.
package policygate

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Errors returned by this package.
var (
	// ErrNotReady means pods may not start. It names what is missing, because a bare
	// refusal sends an operator to go find out what is wrong with a namespace that
	// looks fine.
	ErrNotReady = errors.New("namespace policies are not ready")
	// ErrDrift means a policy that was present is gone. It is distinct from never-ready
	// because the remedy is different: something removed a boundary, and that needs a
	// person, not a retry.
	ErrDrift = errors.New("installed policy is missing")
	// ErrUnknownNamespace means nothing is known about this namespace at all.
	ErrUnknownNamespace = errors.New("unknown namespace")
)

// Kind is a required policy kind.
type Kind string

const (
	// KindNamespace means the namespace itself exists.
	KindNamespace Kind = "namespace"
	// KindDefaultDeny means a default-deny network policy is installed. Without it,
	// every allow rule is only a maximum rather than a default.
	KindDefaultDeny Kind = "default_deny_networkpolicy"
	// KindEgress means the egress allowlist is installed.
	KindEgress Kind = "egress_networkpolicy"
	// KindQuota means the resource quota is installed.
	KindQuota Kind = "resourcequota"
	// KindPodPolicy means the pod security policy is installed.
	KindPodPolicy Kind = "pod_policy"
)

// Required is the fixed set every preview namespace must carry.
//
// It is fixed rather than configurable per preview because a preview that could opt out
// of its default-deny would. The set is the platform's decision, not the customer's.
func Required() []Kind {
	return []Kind{KindNamespace, KindDefaultDeny, KindEgress, KindQuota, KindPodPolicy}
}

// Observation is what was found in a namespace.
type Observation struct {
	Kind Kind
	// Present reports whether the policy exists right now.
	Present bool
	// ObservedAt is when this was established.
	ObservedAt time.Time
	// Detail is operator-facing context.
	Detail string
}

// Observer reads policy state from the cluster.
type Observer interface {
	// Observe returns the current state of every required policy in a namespace.
	Observe(ctx context.Context, namespace string) ([]Observation, error)
}

// Verdict is whether pods may start.
type Verdict struct {
	// Ready reports that every required policy is confirmed present.
	Ready bool
	// Missing names the policies that are absent, so the refusal is actionable.
	Missing []Kind
	// CheckedAt is when readiness was established.
	CheckedAt time.Time
}

// Gate admits pods against verified policy presence.
type Gate struct {
	observer Observer
	now      func() time.Time
	// maxAge bounds how long a verdict may be trusted. Readiness is re-verified, not
	// remembered, because a policy deleted a minute ago is the same danger as one that
	// was never installed.
	maxAge time.Duration
}

// Config bounds a gate.
type Config struct {
	// MaxAge is how long a positive verdict stays valid.
	MaxAge time.Duration
	// Now overrides the clock.
	Now func() time.Time
}

// DefaultMaxAge is how long readiness is trusted before re-verification.
const DefaultMaxAge = 5 * time.Minute

// New builds a gate.
func New(o Observer, cfg Config) (*Gate, error) {
	if o == nil {
		// Without an observer there is nothing to verify against, so every verdict
		// would be assumed. An assumed boundary is not a boundary.
		return nil, errors.New("a policy gate requires a cluster observer; readiness must be verified, not assumed")
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultMaxAge
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Gate{observer: o, now: cfg.Now, maxAge: cfg.MaxAge}, nil
}

// Ready reports whether pods may start in a namespace.
//
// Every required policy must be observed present. There is no partial readiness: a
// namespace with a quota but no default-deny is a namespace whose pods can reach
// anything, and calling that "mostly ready" would admit them.
func (g *Gate) Ready(ctx context.Context, namespace string) (Verdict, error) {
	if namespace == "" {
		return Verdict{}, fmt.Errorf("%w: a namespace is required", ErrNotReady)
	}
	obs, err := g.observer.Observe(ctx, namespace)
	if err != nil {
		if errors.Is(err, ErrUnknownNamespace) {
			return Verdict{}, fmt.Errorf("%w: %s is not a known namespace", ErrNotReady, namespace)
		}
		return Verdict{}, fmt.Errorf("observe policies in %s: %w", namespace, err)
	}

	present := map[Kind]bool{}
	var latest time.Time
	for _, o := range obs {
		if o.Present {
			present[o.Kind] = true
			if o.ObservedAt.After(latest) {
				latest = o.ObservedAt
			}
		}
	}

	var missing []Kind
	for _, k := range Required() {
		if !present[k] {
			missing = append(missing, k)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })

	if len(missing) > 0 {
		return Verdict{Missing: missing, CheckedAt: g.now()}, fmt.Errorf(
			"%w: %s is missing %v; pods may not start", ErrNotReady, namespace, missing)
	}
	return Verdict{Ready: true, CheckedAt: g.now()}, nil
}

// Verify re-checks a namespace that was previously ready and reports drift.
//
// A policy that was present and is now gone means something removed a boundary. That is
// not a readiness problem to retry through; it is an incident to page about. The
// distinction matters because retrying through removed-boundary drift would keep pods
// running with no constraint while the platform waited for the policy to come back.
func (g *Gate) Verify(ctx context.Context, namespace string, wasReadyAt time.Time) (Verdict, error) {
	v, err := g.Ready(ctx, namespace)
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, ErrNotReady) {
		return v, err
	}
	// It was ready within the trust window and is not now. That is drift, not
	// slowness: the boundary existed and something took it away.
	if !wasReadyAt.IsZero() && g.now().Sub(wasReadyAt) <= g.maxAge {
		return v, fmt.Errorf("%w: %s was ready and lost %v", ErrDrift, namespace, v.Missing)
	}
	return v, err
}

// Fresh reports whether a verdict is still within its trust window.
func (g *Gate) Fresh(v Verdict) bool {
	if !v.Ready {
		return false
	}
	if v.CheckedAt.IsZero() {
		return false
	}
	return !g.now().After(v.CheckedAt.Add(g.maxAge))
}

// Describe renders a verdict for an operator.
func Describe(v Verdict) string {
	if v.Ready {
		return "ready: every required policy confirmed present"
	}
	return fmt.Sprintf("not ready: missing %v", v.Missing)
}
