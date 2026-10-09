// Package fake provides a reference model provider.
//
// It is a test double, not a mock in the loose sense: it deliberately
// reproduces the external failure modes the platform must survive, including the
// ones that make absence unprovable. It never demonstrates real isolation.
//
// The injected failures cover the six boundaries named in TESTING.md: before
// create, after native create but before the response, after the response but
// before the durable save, after the state lock, during destroy, and during gate
// signing.
package fake

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/provider"
)

// FailureMode selects an injected external failure.
type FailureMode string

const (
	// FailNone succeeds normally.
	FailNone FailureMode = ""
	// FailBeforeCreate fails before any external effect, so absence is provable.
	FailBeforeCreate FailureMode = "before_create"
	// FailAfterCreateBeforeResponse creates the resource and then fails, so the
	// caller cannot know whether it succeeded. This is the case that produces an
	// uncertain action, and it is the reason observe-before-retry exists.
	FailAfterCreateBeforeResponse FailureMode = "after_create_before_response"
	// FailAfterResponseBeforeSave succeeds externally but fails to persist,
	// leaving local state unaware of an existing resource.
	FailAfterResponseBeforeSave FailureMode = "after_response_before_save"
	// FailDuringDestroy removes part of the resource and fails, leaving a
	// partial teardown that must not be reported as destroyed.
	FailDuringDestroy FailureMode = "during_destroy"
	// FailObserve makes observation impossible, which is not absence.
	FailObserve FailureMode = "observe_unavailable"
	// Slow exceeds the caller's deadline.
	Slow FailureMode = "slow"
)

// Fake is an in-memory provider model. It is safe for concurrent use so the
// reference model can drive duplicate and reordered deliveries.
type Fake struct {
	mu sync.Mutex

	// resources is the "native" world. A slice, not a map keyed by logical key:
	// a real cloud knows nothing about the platform's idempotency key, so two
	// unobserved creates for the same logical key produce two distinct native
	// resources. That duplication is precisely the hazard observe-before-retry
	// exists to prevent.
	resources []*stored

	// modes are scoped per operation, so a failure injected into Observe is not
	// consumed by Allocate.
	allocMode   FailureMode
	destroyMode FailureMode
	observeMode FailureMode
	modeOnce    bool

	capabilities map[provider.Capability]bool
	// unownedResources are resources present natively but absent from local
	// state, used to exercise janitor reconciliation after local record loss.
	unowned []provider.Allocation
	clock   time.Time

	seq int
}

type stored struct {
	alloc provider.Allocation
	// logicalKey is recorded for lookup, but does not identify the native object.
	logicalKey string
	revoked    bool
	destroyed  bool
	// stateLockHeld models the native state lock that serialises mutation.
	stateLockHeld bool
}

// New builds a fake provider. A nil capabilities map means every capability is
// satisfied, which keeps unrelated tests from having to enumerate them.
//
// FailObserve is scoped to Observe only; the other modes are scoped to Allocate
// and Destroy. An allocation with no explicit mode uses FailBeforeCreate.
func New(mode FailureMode, caps map[provider.Capability]bool) *Fake {
	if caps == nil {
		caps = map[provider.Capability]bool{}
		for _, c := range []provider.Capability{
			provider.CapIsolationClass,
			provider.CapOwnershipTags,
			provider.CapDedicatedDependencies,
			provider.CapSharedBrokerWithQuota,
			provider.CapEgressEnforcement,
			provider.CapNodeIdentityWithheld,
			provider.CapCostCapsEnforceable,
		} {
			caps[c] = true
		}
	}
	f := &Fake{
		capabilities: caps,
		clock:        time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC),
	}
	switch mode {
	case FailObserve:
		f.observeMode = mode
	case FailDuringDestroy:
		f.destroyMode = mode
	default:
		f.allocMode = mode
	}
	return f
}

// WithOnce makes the injected failure apply to only the next matching call.
func (f *Fake) WithOnce() *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.modeOnce = true
	return f
}

// WithObserveMode sets the failure injected into Observe.
func (f *Fake) WithObserveMode(m FailureMode) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.observeMode = m
	return f
}

// WithDestroyMode sets the failure injected into Destroy.
func (f *Fake) WithDestroyMode(m FailureMode) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.destroyMode = m
	return f
}

// takeAlloc consumes the allocation mode if it applies to this call.
func (f *Fake) takeAlloc() FailureMode {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.allocMode
	if f.modeOnce && m != FailNone {
		f.allocMode = FailNone
		f.modeOnce = false
	}
	return m
}

func (f *Fake) takeDestroy() FailureMode {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.destroyMode
	if f.modeOnce && m != FailNone {
		f.destroyMode = FailNone
		f.modeOnce = false
	}
	return m
}

func (f *Fake) takeObserve() FailureMode {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.observeMode
	if f.modeOnce && m != FailNone {
		f.observeMode = FailNone
		f.modeOnce = false
	}
	return m
}

func (f *Fake) Capabilities() map[provider.Capability]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[provider.Capability]bool{}
	for k, v := range f.capabilities {
		out[k] = v
	}
	return out
}

func (f *Fake) Describe(context.Context) (provider.Description, error) {
	return provider.Description{Name: "fake", Account: "test-account", Region: "test-region"}, nil
}

func (f *Fake) Allocate(ctx context.Context, req provider.AllocationRequest) (*provider.Allocation, error) {
	mode := f.takeAlloc()

	switch mode {
	case FailBeforeCreate:
		return nil, fmt.Errorf("injected: rejected before any external effect (%s)", req.LogicalKey)
	case Slow:
		return nil, ctx.Err()
	}

	f.mu.Lock()
	f.seq++
	seq := f.seq
	alloc := provider.Allocation{
		EnvironmentID:         req.EnvironmentID,
		Kind:                  req.Kind,
		Reference:             map[string]string{"handle": "ref-" + req.LogicalKey + "-" + itoa(seq)},
		CredentialRef:         "secretref://" + req.EnvironmentID + "/" + string(req.Kind),
		EndpointRef:           "endpointref://" + req.EnvironmentID + "/" + string(req.Kind),
		SupportsOwnershipTags: true,
		Shared:                req.Kind.SharedResource(),
	}
	f.resources = append(f.resources, &stored{alloc: alloc, logicalKey: req.LogicalKey})
	f.mu.Unlock()

	switch mode {
	case FailAfterCreateBeforeResponse:
		// The resource exists natively but the caller never learns that. Absence
		// is unprovable from the caller's side, so it must observe.
		return nil, fmt.Errorf("injected: transport failure after create (%s)", req.LogicalKey)
	case FailAfterResponseBeforeSave:
		// Succeeds externally, fails to persist locally.
		return nil, fmt.Errorf("injected: local persistence failed after external success (%s)", req.LogicalKey)
	}

	return &alloc, nil
}

func (f *Fake) Revoke(_ context.Context, a provider.Allocation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s := f.find(a.Reference["handle"]); s != nil {
		s.revoked = true
	}
	return nil
}

func (f *Fake) Destroy(_ context.Context, a provider.Allocation) error {
	mode := f.takeDestroy()
	f.mu.Lock()
	s := f.find(a.Reference["handle"])
	if s == nil {
		f.mu.Unlock()
		// Already gone. Destroy is idempotent.
		return nil
	}
	if mode == FailDuringDestroy {
		// Partial teardown: credentials revoked, data still present. The caller
		// must not report this as destroyed.
		s.revoked = true
		f.mu.Unlock()
		return fmt.Errorf("injected: destroy failed after partial removal (%s)", s.logicalKey)
	}
	s.revoked = true
	s.destroyed = true
	f.resources = remove(f.resources, s)
	f.mu.Unlock()
	return nil
}

// Observe reports presence. A permission or transport failure returns an error
// rather than a negative observation, because absence must be provable.
func (f *Fake) Observe(ctx context.Context, ref map[string]string) (provider.Observation, error) {
	mode := f.takeObserve()
	if mode == FailObserve {
		return provider.Observation{}, fmt.Errorf("injected: observation unavailable: %w", provider.ErrNotAbsent)
	}
	if mode == Slow {
		return provider.Observation{}, ctx.Err()
	}
	handle := ref["handle"]
	f.mu.Lock()
	defer f.mu.Unlock()
	if s := f.find(handle); s != nil {
		return provider.Observation{Present: true, Reference: s.alloc.Reference, Detail: "present"}, nil
	}
	return provider.Observation{Present: false, Detail: "absent in account and region"}, nil
}

// find locates a stored resource by handle. Caller must hold the lock.
func (f *Fake) find(handle string) *stored {
	for _, s := range f.resources {
		if s.alloc.Reference["handle"] == handle {
			return s
		}
	}
	return nil
}

func remove(list []*stored, target *stored) []*stored {
	out := list[:0]
	for _, s := range list {
		if s != target {
			out = append(out, s)
		}
	}
	return out
}

// SetStateLockHeld models the native state lock that serialises mutation of one
// environment. A replacement runner must not start a conflicting mutation while
// it is held.
func (f *Fake) SetStateLockHeld(envID string, held bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.resources {
		if s.alloc.EnvironmentID == envID {
			s.stateLockHeld = held
		}
	}
}

// StateLockHeld reports whether the native state lock is held for an environment.
func (f *Fake) StateLockHeld(envID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.resources {
		if s.alloc.EnvironmentID == envID {
			return s.stateLockHeld
		}
	}
	return false
}

// AddUnowned adds a resource that exists natively but is absent from local
// state, modelling a leak or a post-restore orphan.
func (f *Fake) AddUnowned(a provider.Allocation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unowned = append(f.unowned, a)
}

// Unowned returns resources the janitor should discover.
func (f *Fake) Unowned() []provider.Allocation {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]provider.Allocation, len(f.unowned))
	copy(out, f.unowned)
	return out
}

// Exists reports whether any live resource carries the given logical key.
func (f *Fake) Exists(logicalKey string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.resources {
		if s.logicalKey == logicalKey {
			return true
		}
	}
	return false
}

// Count returns the number of live native resources, used to assert that
// duplicate and crash scenarios do not leak.
func (f *Fake) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.resources)
}

// Live returns every live native resource the provider holds.
//
// It exists for the G1 gate, which must read provider state directly rather than trust
// the platform's own ledger — the ledger saying a resource is gone while the provider
// still holds it is exactly the disagreement the gate is looking for.
//
// Handles are reported as "<environment>/<logicalKey>" so a gate failure names something
// an operator can act on rather than an opaque handle.
func (f *Fake) Live() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.resources))
	for _, s := range f.resources {
		out = append(out, s.alloc.EnvironmentID+"/"+s.logicalKey)
	}
	sort.Strings(out)
	return out
}

// HandleFor returns the native handle assigned to the nth (0-based) resource
// created for a logical key.
func (f *Fake) HandleFor(logicalKey string, n int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := 0
	for _, s := range f.resources {
		if s.logicalKey == logicalKey {
			if seen == n {
				return s.alloc.Reference["handle"]
			}
			seen++
		}
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// ErrNoProvider is returned by tests that expect a refusal.
var ErrNoProvider = errors.New("no provider adapter configured")

// Compile-time check.
var _ provider.Provider = (*Fake)(nil)
