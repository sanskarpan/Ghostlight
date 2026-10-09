package policygate_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/policygate"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// observer is a controllable cluster.
type observer struct {
	mu      sync.Mutex
	present map[string]map[policygate.Kind]bool
	err     error
	calls   int
}

func newObserver() *observer {
	return &observer{present: map[string]map[policygate.Kind]bool{}}
}

func (o *observer) install(ns string, kinds ...policygate.Kind) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.present[ns] == nil {
		o.present[ns] = map[policygate.Kind]bool{}
	}
	for _, k := range kinds {
		o.present[ns][k] = true
	}
}

func (o *observer) remove(ns string, kind policygate.Kind) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.present[ns], kind)
}

func (o *observer) Observe(_ context.Context, ns string) ([]policygate.Observation, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls++
	if o.err != nil {
		return nil, o.err
	}
	known, ok := o.present[ns]
	if !ok {
		return nil, policygate.ErrUnknownNamespace
	}
	var out []policygate.Observation
	for _, k := range policygate.Required() {
		out = append(out, policygate.Observation{Kind: k, Present: known[k], ObservedAt: now})
	}
	return out, nil
}

func newGate(t *testing.T, o *observer) *policygate.Gate {
	t.Helper()
	g, err := policygate.New(o, policygate.Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("new gate: %v", err)
	}
	return g
}

// TestGateRequiresAnObserver: without one every verdict would be assumed, and an
// assumed boundary is not a boundary.
func TestGateRequiresAnObserver(t *testing.T) {
	if _, err := policygate.New(nil, policygate.Config{}); err == nil {
		t.Fatal("a gate must not be constructible without a cluster observer")
	}
}

// TestFullyProvisionedNamespaceIsReady is the ordinary path.
func TestFullyProvisionedNamespaceIsReady(t *testing.T) {
	o := newObserver()
	o.install("preview-1", policygate.Required()...)
	g := newGate(t, o)

	v, err := g.Ready(context.Background(), "preview-1")
	if err != nil {
		t.Fatalf("ready: %v", err)
	}
	if !v.Ready || len(v.Missing) != 0 {
		t.Fatalf("a fully provisioned namespace must be ready, got %+v", v)
	}
	if !g.Fresh(v) {
		t.Fatal("a fresh verdict must be fresh")
	}
}

// TestNoPartialReadiness: a namespace with a quota but no default-deny is a namespace
// whose pods can reach anything. Calling that "mostly ready" would admit them.
func TestNoPartialReadiness(t *testing.T) {
	o := newObserver()
	o.install("preview-1", policygate.KindNamespace, policygate.KindQuota, policygate.KindEgress, policygate.KindPodPolicy)
	g := newGate(t, o)

	v, err := g.Ready(context.Background(), "preview-1")
	if !errors.Is(err, policygate.ErrNotReady) {
		t.Fatalf("a namespace without default-deny must refuse pods, got %v", err)
	}
	if v.Ready {
		t.Fatal("the verdict must not be ready")
	}
	if len(v.Missing) != 1 || v.Missing[0] != policygate.KindDefaultDeny {
		t.Fatalf("the refusal must name exactly what is missing, got %+v", v.Missing)
	}
	if g.Fresh(v) {
		t.Fatal("an unready verdict is never fresh")
	}
}

// TestAnEmptyNamespaceRefusesEverything.
func TestAnEmptyNamespaceRefusesEverything(t *testing.T) {
	o := newObserver()
	o.install("preview-1")
	g := newGate(t, o)

	v, err := g.Ready(context.Background(), "preview-1")
	if !errors.Is(err, policygate.ErrNotReady) {
		t.Fatalf("an empty namespace must refuse, got %v", err)
	}
	if len(v.Missing) != len(policygate.Required()) {
		t.Fatalf("every policy must be reported missing, got %+v", v.Missing)
	}
}

// TestUnknownNamespaceIsDistinct: absent is a different problem from unready.
func TestUnknownNamespaceIsDistinct(t *testing.T) {
	o := newObserver()
	g := newGate(t, o)

	_, err := g.Ready(context.Background(), "nope")
	if !errors.Is(err, policygate.ErrNotReady) {
		t.Fatalf("an unknown namespace must refuse, got %v", err)
	}
	if !strings.Contains(err.Error(), "not a known namespace") {
		t.Fatalf("the refusal must say the namespace is unknown, got %q", err)
	}
}

// TestObserverFailureIsNotReadiness: a cluster that cannot be read is not a cluster
// with policies.
func TestObserverFailureIsNotReadiness(t *testing.T) {
	o := newObserver()
	o.install("preview-1", policygate.Required()...)
	o.err = errors.New("apiserver unreachable")
	g := newGate(t, o)

	_, err := g.Ready(context.Background(), "preview-1")
	if err == nil {
		t.Fatal("an unreadable cluster must refuse pods, not admit them")
	}
	if errors.Is(err, policygate.ErrNotReady) {
		t.Fatal("an observation failure is a fault, not a readiness verdict; it must not be wrapped as one")
	}
	if !strings.Contains(err.Error(), "apiserver unreachable") {
		t.Fatalf("the cause must be preserved, got %q", err)
	}
}

// TestRemovedPolicyIsDriftNotSlowness: something took a boundary away, and that needs a
// person rather than a retry.
func TestRemovedPolicyIsDriftNotSlowness(t *testing.T) {
	o := newObserver()
	o.install("preview-1", policygate.Required()...)
	g := newGate(t, o)

	v, err := g.Ready(context.Background(), "preview-1")
	if err != nil {
		t.Fatalf("initially ready: %v", err)
	}

	// Someone deletes the default-deny.
	o.remove("preview-1", policygate.KindDefaultDeny)

	_, err = g.Verify(context.Background(), "preview-1", v.CheckedAt)
	if !errors.Is(err, policygate.ErrDrift) {
		t.Fatalf("a removed boundary must be drift, got %v", err)
	}
	if !strings.Contains(err.Error(), "was ready and lost") {
		t.Fatalf("the error must say what happened, got %q", err)
	}
}

// TestNeverReadyIsNotDrift: a namespace that never had policies is slow provisioning,
// not an incident.
func TestNeverReadyIsNotDrift(t *testing.T) {
	o := newObserver()
	o.install("preview-1", policygate.KindNamespace)
	g := newGate(t, o)

	_, err := g.Verify(context.Background(), "preview-1", time.Time{})
	if !errors.Is(err, policygate.ErrNotReady) {
		t.Fatalf("a never-ready namespace must report not-ready, got %v", err)
	}
	if errors.Is(err, policygate.ErrDrift) {
		t.Fatal("without prior readiness there is no drift")
	}
}

// TestOldReadinessDoesNotBecomeDrift: outside the trust window, a re-check is just a
// re-check. Treating stale memory as evidence of removal would page on every slow
// re-verification.
func TestOldReadinessDoesNotBecomeDrift(t *testing.T) {
	o := newObserver()
	o.install("preview-1", policygate.Required()...)
	g := newGate(t, o)

	// Ready long ago, policy since removed.
	o.remove("preview-1", policygate.KindQuota)
	_, err := g.Verify(context.Background(), "preview-1", now.Add(-time.Hour))
	if errors.Is(err, policygate.ErrDrift) {
		t.Fatal("readiness outside the trust window must not be treated as drift")
	}
	if !errors.Is(err, policygate.ErrNotReady) {
		t.Fatalf("it must still refuse, got %v", err)
	}
}

// TestVerdictsExpire: readiness is re-verified, not remembered.
func TestVerdictsExpire(t *testing.T) {
	o := newObserver()
	o.install("preview-1", policygate.Required()...)

	late := now.Add(10 * time.Minute)
	g, err := policygate.New(o, policygate.Config{Now: func() time.Time { return late }})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	v := policygate.Verdict{Ready: true, CheckedAt: now}
	if g.Fresh(v) {
		t.Fatal("a verdict past its trust window must not be fresh")
	}
}

// TestMissingListIsStable: two runs must report the same refusal.
func TestMissingListIsStable(t *testing.T) {
	o := newObserver()
	o.install("preview-1", policygate.KindNamespace)
	g := newGate(t, o)

	first, _ := g.Ready(context.Background(), "preview-1")
	for i := 0; i < 5; i++ {
		again, _ := g.Ready(context.Background(), "preview-1")
		if len(first.Missing) != len(again.Missing) {
			t.Fatal("the missing list must be stable")
		}
		for j := range first.Missing {
			if first.Missing[j] != again.Missing[j] {
				t.Fatalf("unstable refusal: %v vs %v", first.Missing, again.Missing)
			}
		}
	}
}

// TestDescribeIsPresentable: refusals reach operators and customers.
func TestDescribeIsPresentable(t *testing.T) {
	if got := policygate.Describe(policygate.Verdict{Ready: true}); !strings.Contains(got, "ready") {
		t.Fatalf("a ready verdict must say so, got %q", got)
	}
	got := policygate.Describe(policygate.Verdict{Missing: []policygate.Kind{policygate.KindQuota}})
	if !strings.Contains(got, "resourcequota") {
		t.Fatalf("a refusal must name the missing policy, got %q", got)
	}
}

// TestRequiredSetIsFixed: a preview that could opt out of default-deny would.
func TestRequiredSetIsFixed(t *testing.T) {
	required := policygate.Required()
	if len(required) != 5 {
		t.Fatalf("the required set must have five policies, got %v", required)
	}
	seen := map[policygate.Kind]bool{}
	for _, k := range required {
		if k == "" {
			t.Fatal("a required policy must be named")
		}
		if seen[k] {
			t.Fatalf("%s is duplicated", k)
		}
		seen[k] = true
	}
	for _, k := range []policygate.Kind{policygate.KindDefaultDeny, policygate.KindQuota, policygate.KindEgress} {
		if !seen[k] {
			t.Fatalf("%s must always be required", k)
		}
	}
}

// TestConcurrentReadsAreConsistent: several admission checks must not disagree.
func TestConcurrentReadsAreConsistent(t *testing.T) {
	o := newObserver()
	o.install("preview-1", policygate.Required()...)
	g := newGate(t, o)

	var wg sync.WaitGroup
	results := make([]bool, 12)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := g.Ready(context.Background(), "preview-1")
			results[i] = err == nil && v.Ready
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		if !r {
			t.Fatalf("admission check %d disagreed with the others", i)
		}
	}
	if o.calls != 12 {
		t.Fatalf("every check must observe rather than cache, got %d calls", o.calls)
	}
}

// TestNamespaceIsRequired.
func TestNamespaceIsRequired(t *testing.T) {
	o := newObserver()
	g := newGate(t, o)
	if _, err := g.Ready(context.Background(), ""); !errors.Is(err, policygate.ErrNotReady) {
		t.Fatalf("an empty namespace must be refused, got %v", err)
	}
}
