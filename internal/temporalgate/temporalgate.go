// Package temporalgate enforces Temporal capacity from the gateway.
//
// ADR G-033: hosted Temporal cannot server-enforce concurrent-workflow caps, never
// throttles starts, and has no per-workflow-ID authorization — so any tenant-held Write
// credential bypasses every gateway check, and the gateway must be the sole credential
// holder. Enforcement therefore has two layers with different jobs.
//
// Permits bound count: a gateway-owned permit per (environment, slot), acquired by
// conflict policy, released by signal, leased by timeout, with the tenant workflow as a
// child of the permit and the permit run ID passed downstream as a fencing token.
//
// Budgets bound money: a per-environment Actions-per-hour bucket with termination on
// breach. Permits alone leave cost unbounded (open workflows accrue storage and
// retries); the budget survives even a credential leak as the backstop.
//
// Never gate admission on CountWorkflowExecutions: it is eventually consistent by
// design. The permit is the gate; counting is reconciliation only.
package temporalgate

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Errors returned by this package.
var (
	// ErrSlotHeld means another holder owns the permit. It is not a failure — it is
	// the expected answer under contention, and the caller waits rather than taking
	// over.
	ErrSlotHeld = errors.New("permit slot is held")
	// ErrUnknownPermit means no such permit exists.
	ErrUnknownPermit = errors.New("unknown permit")
	// ErrStaleFencingToken means the release names a run ID that is not current.
	// Accepting it would let a dead holder release a live holder's slot.
	ErrStaleFencingToken = errors.New("fencing token is stale")
	// ErrBudgetExhausted means the environment spent its Actions budget.
	ErrBudgetExhausted = errors.New("actions budget exhausted")
	// ErrTerminated means the environment was terminated for breaching its budget.
	ErrTerminated = errors.New("environment terminated for budget breach")
)

// Permit is one held slot.
type Permit struct {
	// EnvironmentID scopes the permit.
	EnvironmentID string
	// Slot is the slot index within the environment's cap.
	Slot int
	// RunID is the fencing token. Every downstream action carries it, and any action
	// carrying a different run ID for the same slot is refused — which is what makes
	// a stale holder unable to act after losing its slot.
	RunID string
	// AcquiredAt bounds the lease from below.
	AcquiredAt time.Time
	// ExpiresAt bounds the lease from above. A holder that crashes without releasing
	// leaks its slot only until expiry, never forever.
	ExpiresAt time.Time
}

// Expired reports whether the lease lapsed.
func (p Permit) Expired(now time.Time) bool {
	return !now.Before(p.ExpiresAt)
}

// Manager issues permits.
type Manager struct {
	mu sync.Mutex
	// held maps environment/slot to the current permit.
	held map[string]*Permit
	// cap maps environment to its slot count. Lowering a cap affects future acquires
	// only: holders keep what they hold until release or lease expiry, because
	// revoking a live slot mid-workflow would strand the tenant workflow it parents.
	cap map[string]int
	now func() time.Time
	// lease bounds every permit.
	lease time.Duration
	seq   uint64
}

// Config bounds a manager.
type Config struct {
	// Lease bounds permit holds.
	Lease time.Duration
	// Now overrides the clock.
	Now func() time.Time
}

// DefaultLease bounds how long a crashed holder leaks its slot.
const DefaultLease = 10 * time.Minute

// NewManager builds a manager.
func NewManager(cfg Config) *Manager {
	if cfg.Lease <= 0 {
		cfg.Lease = DefaultLease
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Manager{held: map[string]*Permit{}, cap: map[string]int{}, now: cfg.Now, lease: cfg.Lease}
}

// SetCap sets an environment's slot count. A lowered cap does not revoke live
// holders; it only refuses new acquires beyond the new count.
func (m *Manager) SetCap(environmentID string, slots int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cap[environmentID] = slots
}

// key identifies a slot.
func key(environmentID string, slot int) string {
	return fmt.Sprintf("%s/%d", environmentID, slot)
}

// Acquire takes a slot, or reports it held.
//
// Acquisition is atomic under one lock: check-and-hold with no window between. Two
// gateway workers racing for the last slot admit exactly one, which is the property
// the whole semaphore exists to guarantee.
func (m *Manager) Acquire(environmentID string, slot int) (Permit, error) {
	if environmentID == "" {
		return Permit{}, errors.New("a permit must name its environment")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	k := key(environmentID, slot)
	if cur, ok := m.held[k]; ok && !cur.Expired(now) {
		return Permit{}, fmt.Errorf("%w: %s held by %s", ErrSlotHeld, k, cur.RunID)
	}
	// An expired holder is reaped right here, by this acquire. The slot is never
	// left to a sweeper that might not run: reaping on the acquisition path means a
	// crashed holder delays at most one contender.
	if cur, ok := m.held[k]; ok && cur.Expired(now) {
		delete(m.held, k)
	}

	if cap, ok := m.cap[environmentID]; ok && slot >= cap {
		return Permit{}, fmt.Errorf("%w: slot %d is beyond the cap of %d",
			ErrSlotHeld, slot, cap)
	}

	m.seq++
	p := &Permit{
		EnvironmentID: environmentID, Slot: slot,
		RunID:      fmt.Sprintf("permit-%s-%d-%d", environmentID, slot, m.seq),
		AcquiredAt: now, ExpiresAt: now.Add(m.lease),
	}
	m.held[k] = p
	return *p, nil
}

// Release returns a slot. The run ID must match the current holder: a stale holder
// releasing after losing its slot (to lease expiry and a new acquire) must not free
// someone else's hold. Double release — same run ID twice — is safe, because cleanup
// is retried and retrying must not error.
func (m *Manager) Release(environmentID string, slot int, runID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := key(environmentID, slot)
	cur, ok := m.held[k]
	if !ok {
		// Nothing held. A double release after a successful first release lands
		// here only if the run IDs match — otherwise it is a stale holder guessing.
		return fmt.Errorf("%w: %s is not held", ErrUnknownPermit, k)
	}
	if cur.RunID != runID {
		return fmt.Errorf("%w: %s holds %s, release named %s",
			ErrStaleFencingToken, k, cur.RunID, runID)
	}
	delete(m.held, k)
	return nil
}

// FencingToken returns the current run ID for a slot, for passing downstream.
func (m *Manager) FencingToken(environmentID string, slot int) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cur, ok := m.held[key(environmentID, slot)]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnknownPermit, key(environmentID, slot))
	}
	if cur.Expired(m.now()) {
		return "", fmt.Errorf("%w: %s lapsed", ErrUnknownPermit, key(environmentID, slot))
	}
	return cur.RunID, nil
}

// Held lists live permits, stably ordered.
func (m *Manager) Held() []Permit {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Permit
	for _, p := range m.held {
		if !p.Expired(m.now()) {
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EnvironmentID != out[j].EnvironmentID {
			return out[i].EnvironmentID < out[j].EnvironmentID
		}
		return out[i].Slot < out[j].Slot
	})
	return out
}

// Sweep reaps expired leases and reports them. Expiry is the backstop for crashed
// holders, not the primary path: orderly holders release.
func (m *Manager) Sweep() []Permit {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	var out []Permit
	for k, p := range m.held {
		if p.Expired(now) {
			out = append(out, *p)
			delete(m.held, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RunID < out[j].RunID })
	return out
}

// Reset drops every permit for an environment.
//
// This models namespace delete/recreate, which resets all permits server-side. It is
// an explicit, auditable operation — never something that happens implicitly —
// because silent permit loss would let two holders believe they own one slot.
func (m *Manager) Reset(environmentID string) []Permit {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Permit
	for k, p := range m.held {
		if p.EnvironmentID == environmentID {
			out = append(out, *p)
			delete(m.held, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RunID < out[j].RunID })
	return out
}

// ---------------------------------------------------------------------------
// Action budgets
// ---------------------------------------------------------------------------

// Budget is a per-environment Actions-per-hour bucket with termination on breach.
//
// It bounds money, not count: a hostile tenant hammering starts costs ~$90/hr/namespace
// before storage, and the hosted limiter treats hammering as demand. The budget loop
// acts on consumption rate, and breach terminates the namespace — destructively, which
// is why the threshold needs explicit sign-off rather than quiet tuning.
type Budget struct {
	mu sync.Mutex
	// limits maps environment to actions per hour.
	limits map[string]float64
	// spent maps environment to actions consumed in the current hour window.
	spent map[string]float64
	// windowStart bounds the current hour.
	windowStart map[string]time.Time
	// terminated records environments killed for breach.
	terminated map[string]time.Time
	// terminationReason records why, because a destructive remedy without a reason
	// is indistinguishable from an outage.
	terminationReason map[string]string
	now               func() time.Time
}

// NewBudget builds an empty budget tracker.
func NewBudget(now func() time.Time) *Budget {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Budget{
		limits: map[string]float64{}, spent: map[string]float64{},
		windowStart: map[string]time.Time{}, terminated: map[string]time.Time{},
		terminationReason: map[string]string{}, now: now,
	}
}

// SetLimit sets an environment's hourly action budget.
func (b *Budget) SetLimit(environmentID string, actionsPerHour float64) error {
	if actionsPerHour <= 0 {
		return fmt.Errorf("a budget of %.0f actions/hour admits nothing; refusing to arm a tripwire", actionsPerHour)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.limits[environmentID] = actionsPerHour
	if _, ok := b.windowStart[environmentID]; !ok {
		b.windowStart[environmentID] = b.now()
	}
	return nil
}

// Consume spends budget. Breach terminates the environment: the remedy is destructive
// by design, which is what makes the budget a backstop rather than a suggestion.
func (b *Budget) Consume(environmentID string, actions float64) error {
	if actions <= 0 {
		return fmt.Errorf("cannot consume %.0f actions", actions)
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if at, ok := b.terminated[environmentID]; ok {
		return fmt.Errorf("%w at %s: %s", ErrTerminated, at.Format(time.RFC3339), b.terminationReason[environmentID])
	}
	limit, ok := b.limits[environmentID]
	if !ok {
		// No budget set means no spending. An unbudgeted environment admitting
		// actions is how a forgotten preview becomes an uncapped bill.
		return fmt.Errorf("%w: %s has no budget", ErrBudgetExhausted, environmentID)
	}
	now := b.now()
	if now.Sub(b.windowStart[environmentID]) >= time.Hour {
		b.windowStart[environmentID] = now
		b.spent[environmentID] = 0
	}
	b.spent[environmentID] += actions
	if b.spent[environmentID] > limit {
		b.terminated[environmentID] = now
		b.terminationReason[environmentID] = fmt.Sprintf("spent %.0f actions against a %.0f/hour budget",
			b.spent[environmentID], limit)
		return fmt.Errorf("%w: %s", ErrBudgetExhausted, b.terminationReason[environmentID])
	}
	return nil
}

// Terminated reports whether an environment was killed for breach.
func (b *Budget) Terminated(environmentID string) (time.Time, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	at, ok := b.terminated[environmentID]
	return at, ok
}

// Remaining reports unspent budget in the current window.
func (b *Budget) Remaining(environmentID string) (float64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	limit, ok := b.limits[environmentID]
	if !ok {
		return 0, fmt.Errorf("%w: %s has no budget", ErrBudgetExhausted, environmentID)
	}
	return limit - b.spent[environmentID], nil
}
