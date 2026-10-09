package quota

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// MemoryLedger is a transactional in-memory Ledger.
//
// It exists as the reference implementation of the ledger contract, and as the place
// where the last-slot race is made impossible by construction: Reserve takes a single
// mutex for the whole check-and-decrement, so no interleaving can occur between
// observing availability and consuming it.
//
// The mutex is the point. A ledger that reads availability, returns, and decrements
// later has a window where two controllers both observe the last slot free. Holding
// one lock across check and decrement closes it, and any SQL implementation must do
// the equivalent in one transaction.
type MemoryLedger struct {
	mu sync.Mutex

	grants map[ScopeRef]Grant
	// used tracks consumption per scope.
	used map[ScopeRef]Demand
	// reservations indexes active reservations.
	reservations map[string]Reservation
	// nextID makes reservation identifiers deterministic.
	nextID int
	// audit records privileged decisions made through this ledger.
	audit []AuditEntry
	// now overrides the clock.
	now func() time.Time
}

// NewMemoryLedger builds an empty ledger.
func NewMemoryLedger(grants []Grant, now func() time.Time) *MemoryLedger {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	l := &MemoryLedger{
		grants:       map[ScopeRef]Grant{},
		used:         map[ScopeRef]Demand{},
		reservations: map[string]Reservation{},
		now:          now,
	}
	for _, g := range grants {
		l.grants[ScopeRef{Scope: g.Scope, Ref: g.Ref}] = g
	}
	return l
}

// Reserve takes capacity in every scope or takes nothing.
func (l *MemoryLedger) Reserve(_ context.Context, req Request, scopes []ScopeRef) (Reservation, error) {
	if req.EnvironmentID == "" {
		return Reservation{}, fmt.Errorf("a reservation must name the environment consuming it")
	}
	now := req.Now
	if now.IsZero() {
		now = l.now()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Check every scope before mutating any of them. Validating in a first pass and
	// decrementing in a second is what produces a partial reservation, and a partial
	// reservation leaks the scopes it did consume.
	for _, s := range scopes {
		g, ok := l.grants[s]
		if !ok {
			return Reservation{}, fmt.Errorf("%w: %s has no grant", ErrNotAuthorized, ShortestRef(s))
		}
		if !g.Covers(now) {
			return Reservation{}, fmt.Errorf("%w: %s does not cover %s (window %s..%s)",
				ErrNotAuthorized, ShortestRef(s), now.Format(time.RFC3339),
				g.WindowStart.Format(time.RFC3339), g.WindowEnd.Format(time.RFC3339))
		}
		if d, missing := shortfall(s, g, l.used[s], req.Demanded); missing {
			return Reservation{}, fmt.Errorf("%w: %w", ErrExhausted, DenialReason{
				Scope:   s,
				Missing: d,
				Advice:  AdviceForScope(s.Scope),
			})
		}
	}

	// Only now, with every scope known satisfiable, does anything get consumed.
	for _, s := range scopes {
		used := l.used[s]
		l.used[s] = Demand{
			Concurrency:    used.Concurrency + req.Demanded.Concurrency,
			CPUMillicores:  used.CPUMillicores + req.Demanded.CPUMillicores,
			StorageGiB:     used.StorageGiB + req.Demanded.StorageGiB,
			AllowanceMinor: used.AllowanceMinor + req.Demanded.AllowanceMinor,
		}
	}

	l.nextID++
	id := fmt.Sprintf("res-%04d", l.nextID)
	res := Reservation{
		ID:            id,
		EnvironmentID: req.EnvironmentID,
		ScopeRefs:     append([]ScopeRef(nil), scopes...),
		Demanded:      req.Demanded,
		ReservedAt:    now,
		ExpiresAt:     now.Add(DefaultTTL),
	}
	l.reservations[id] = res
	return res, nil
}

// shortfall reports what a demand lacks against a grant, if anything.
func shortfall(s ScopeRef, g Grant, used, want Demand) (Demand, bool) {
	var missing Demand
	missing.Concurrency = used.Concurrency + want.Concurrency - g.MaxConcurrency
	missing.CPUMillicores = used.CPUMillicores + want.CPUMillicores - g.MaxCPUMillicores
	missing.StorageGiB = used.StorageGiB + want.StorageGiB - g.MaxStorageGiB
	missing.AllowanceMinor = used.AllowanceMinor + want.AllowanceMinor - g.AllowanceMinor

	// A grant that does not constrain a dimension must not refuse on it. A profile
	// with no storage ceiling must not refuse every environment that attaches some.
	if g.MaxCPUMillicores == 0 {
		missing.CPUMillicores = 0
	}
	if g.MaxStorageGiB == 0 {
		missing.StorageGiB = 0
	}
	if g.AllowanceMinor == 0 {
		missing.AllowanceMinor = 0
	}
	for _, v := range []int{missing.Concurrency, missing.CPUMillicores, missing.StorageGiB} {
		if v > 0 {
			return missing, true
		}
	}
	if missing.AllowanceMinor > 0 {
		return missing, true
	}
	_ = s
	return Demand{}, false
}

// Release returns capacity.
//
// Idempotent, because cleanup must be retryable: a release that failed halfway and is
// retried must not credit the scope twice, which would invent capacity that was never
// bought.
func (l *MemoryLedger) Release(_ context.Context, id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	res, ok := l.reservations[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNoReservation, id)
	}
	for _, s := range res.ScopeRefs {
		cur := l.used[s]
		cur.Concurrency -= res.Demanded.Concurrency
		cur.CPUMillicores -= res.Demanded.CPUMillicores
		cur.StorageGiB -= res.Demanded.StorageGiB
		cur.AllowanceMinor -= res.Demanded.AllowanceMinor
		l.used[s] = cur
	}
	delete(l.reservations, id)
	return nil
}

// Remaining reports available capacity in a scope.
func (l *MemoryLedger) Remaining(_ context.Context, s ScopeRef, now time.Time) (Demand, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	g, ok := l.grants[s]
	if !ok {
		return Demand{}, fmt.Errorf("%w: %s has no grant", ErrNotAuthorized, ShortestRef(s))
	}
	if now.IsZero() {
		now = l.now()
	}
	if !g.Covers(now) {
		// Outside the window nothing is available. Reporting the grant's full ceiling
		// here would admit an environment against an allowance that is not running.
		return Demand{}, nil
	}
	used := l.used[s]
	return Demand{
		Concurrency:    g.MaxConcurrency - used.Concurrency,
		CPUMillicores:  max(0, g.MaxCPUMillicores-used.CPUMillicores),
		StorageGiB:     max(0, g.MaxStorageGiB-used.StorageGiB),
		AllowanceMinor: max64(0, g.AllowanceMinor-used.AllowanceMinor),
	}, nil
}

// Granted reports a scope's total grant.
func (l *MemoryLedger) Granted(ctx context.Context, s ScopeRef) (Grant, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	g, ok := l.grants[s]
	if !ok {
		return Grant{}, fmt.Errorf("%w: %s has no grant", ErrNotAuthorized, ShortestRef(s))
	}
	return g, nil
}

// Active returns the reservations still held, in a stable order.
func (l *MemoryLedger) Active() []Reservation {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Reservation, 0, len(l.reservations))
	for _, r := range l.reservations {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Report describes every scope's consumption, binding constraint first.
//
// The binding constraint leads because it is the only thing that tells an operator
// what to change. Reporting that the fleet has one slot left when the repository is
// already full sends them to fix the wrong thing.
func (l *MemoryLedger) Report(ctx context.Context, scopes []ScopeRef, now time.Time) ([]Report, error) {
	out := make([]Report, 0, len(scopes))
	for _, s := range Bindings(scopes) {
		g, err := l.Granted(ctx, s)
		if err != nil {
			return nil, err
		}
		rem, err := l.Remaining(ctx, s, now)
		if err != nil {
			return nil, err
		}
		out = append(out, Report{
			Ref: s,
			Granted: Demand{
				Concurrency:    g.MaxConcurrency,
				CPUMillicores:  g.MaxCPUMillicores,
				StorageGiB:     g.MaxStorageGiB,
				AllowanceMinor: g.AllowanceMinor,
			},
			Remaining: rem,
			Exhausted: rem.Concurrency <= 0,
		})
	}
	return out, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
