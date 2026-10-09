package resource

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// MemoryLedger is an in-memory Ledger.
//
// It is the reference implementation, and the place where the invariants the schema
// declares are made structural rather than aspirational: the shared-resource check, the
// tombstone, and the uniqueness of logical keys.
type MemoryLedger struct {
	mu sync.RWMutex

	byID map[string]*Record
	// byKey indexes the schema's UNIQUE (environment_id, dependency_kind, logical_key).
	byKey map[string]string

	now func() time.Time
}

// NewMemoryLedger builds an empty ledger.
func NewMemoryLedger(now func() time.Time) *MemoryLedger {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &MemoryLedger{
		byID:  map[string]*Record{},
		byKey: map[string]string{},
		now:   now,
	}
}

// Record adds or updates an allocation.
//
// Re-recording an existing allocation updates it in place rather than replacing its
// identity, because the tombstone and its observations are the evidence that a stale
// webhook must not be able to erase.
func (m *MemoryLedger) Record(_ context.Context, a Allocation) error {
	if a.ID == "" {
		return fmt.Errorf("an allocation must have a ledger id")
	}
	if a.EnvironmentID == "" {
		return fmt.Errorf("an allocation must name the environment that owns it")
	}
	if a.Kind == "" || a.LogicalKey == "" {
		return fmt.Errorf("an allocation must name its kind and logical key")
	}
	if len(a.ProviderRef) == 0 {
		// A resource with no provider reference cannot be observed, so it can never
		// be verified deleted. Allowing one would guarantee an unverifiable leak.
		return fmt.Errorf("an allocation must carry a provider reference, or it can never be verified deleted")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if a.CreatedAt.IsZero() {
		a.CreatedAt = m.now()
	}
	key := a.Key()

	// The schema's uniqueness constraint: one allocation per environment/kind/key.
	if id, exists := m.byKey[key]; exists && id != a.ID {
		return fmt.Errorf("%s/%s already has allocation %s", a.EnvironmentID, a.Kind+"."+a.LogicalKey, id)
	}

	if existing, ok := m.byID[a.ID]; ok {
		// A tombstone is never overwritten. This is the rule that stops a stale webhook
		// recreating a removed allocation.
		if existing.State == StateVerifiedDeleted {
			return fmt.Errorf("%w: %s is tombstoned and must not be recreated", ErrAlreadyDeleted, a.ID)
		}
		// Generation fencing on write. An out-of-order delivery carrying an older
		// generation must not roll the record back: the newer generation is the one
		// that owns the resource, and accepting the older one would let a delayed
		// webhook authorize cleanup of something a later generation replaced.
		if a.Generation < existing.Generation {
			return fmt.Errorf(
				"%w: %s is at generation %d; an event for generation %d arrived out of order",
				ErrGenerationMismatch, a.ID, existing.Generation, a.Generation)
		}
		existing.Allocation = a
		m.byKey[key] = a.ID
		return nil
	}

	if a.State == "" {
		a.State = StateActive
	}
	rec := &Record{Allocation: a}
	m.byID[a.ID] = rec
	m.byKey[key] = a.ID
	return nil
}

// Get returns an allocation by environment, kind and logical key.
func (m *MemoryLedger) Get(_ context.Context, environmentID, kind, logicalKey string) (Allocation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byKey[fmt.Sprintf("%s|%s|%s", environmentID, kind, logicalKey)]
	if !ok {
		return Allocation{}, fmt.Errorf("%w: %s/%s.%s", ErrUnknownResource, environmentID, kind, logicalKey)
	}
	return m.byID[id].Allocation, nil
}

// ByID returns an allocation and its evidence trail.
func (m *MemoryLedger) ByID(_ context.Context, id string) (Allocation, error) {
	rec, err := m.record(id)
	if err != nil {
		return Allocation{}, err
	}
	return rec.Allocation, nil
}

// record returns a copy of a record, taken while the lock is held.
//
// It deliberately does not return the stored pointer. Handing out a pointer to mutable
// state and letting the caller read it after the lock is released means a concurrent
// MarkRevoked can change those fields underneath them, which is a genuine data race
// rather than a theoretical one.
func (m *MemoryLedger) record(id string) (Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.byID[id]
	if !ok {
		return Record{}, fmt.Errorf("%w: %s", ErrUnknownResource, id)
	}
	return Record{
		Allocation:   rec.Allocation,
		Observations: append([]Observation(nil), rec.Observations...),
	}, nil
}

// MarkRevoked records that credentials were removed.
//
// The actor and evidence are both required. A revocation with no actor is an unattributable
// privilege change, which is the thing an audit exists to make impossible.
func (m *MemoryLedger) MarkRevoked(_ context.Context, id, actor string, evidence string) error {
	if actor == "" {
		return fmt.Errorf("%w: revocation requires an identified actor", ErrNotRevoked)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.byID[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownResource, id)
	}
	if rec.State == StateVerifiedDeleted {
		return fmt.Errorf("%w: %s", ErrAlreadyDeleted, id)
	}
	// Revocation is idempotent but never reversible. Re-revoking is safe; un-revoking
	// would re-grant credentials nobody has verified still exist.
	if rec.State == StateRevoked {
		return nil
	}
	rec.State = StateRevoked
	rec.RevokedAt = m.now()
	rec.RevokedBy = actor
	if evidence != "" {
		rec.Observations = append(rec.Observations, Observation{
			At: rec.RevokedAt, Detail: "revoked by " + actor + ": " + evidence,
		})
	}
	return nil
}

// MarkDeleted records verified deletion, leaving a tombstone.
func (m *MemoryLedger) MarkDeleted(_ context.Context, id string, proof Observation) error {
	if proof.Exists {
		// Recording absence as verified presence is the one error that would make the
		// tombstone a lie.
		return fmt.Errorf("%w: %s still exists, so deletion cannot be verified", ErrNoAuthority, id)
	}
	if proof.Detail == "" {
		return fmt.Errorf("%w: verified deletion requires evidence of absence", ErrNoAuthority)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.byID[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownResource, id)
	}
	if rec.State == StateVerifiedDeleted {
		// Idempotent, because cleanup is retried and re-confirming absence is harmless.
		return nil
	}
	if rec.State != StateRevoked {
		return fmt.Errorf("%w: %s was destroyed before its credentials were revoked", ErrNotRevoked, id)
	}
	rec.State = StateVerifiedDeleted
	rec.DeletedAt = m.now()
	rec.DeletionProof = proof.Detail
	rec.Observations = append(rec.Observations, proof)
	return nil
}

// Observe appends provider evidence.
func (m *MemoryLedger) Observe(_ context.Context, id string, o Observation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownResource, id)
	}
	if o.At.IsZero() {
		o.At = m.now()
	}
	rec.Observations = append(rec.Observations, o)
	return nil
}

// List returns an environment's allocations in a stable order.
//
// Ordering matters because teardown deletes in dependency order, and two runs must not
// produce two different orders.
func (m *MemoryLedger) List(_ context.Context, environmentID string) ([]Allocation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Allocation
	for _, rec := range m.byID {
		if rec.EnvironmentID == environmentID {
			out = append(out, rec.Allocation)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].LogicalKey < out[j].LogicalKey
	})
	return out, nil
}

// Evidence returns the observation trail for an allocation.
func (m *MemoryLedger) Evidence(_ context.Context, id string) ([]Observation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.byID[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownResource, id)
	}
	return append([]Observation(nil), rec.Observations...), nil
}

// All returns every allocation, for the janitor.
func (m *MemoryLedger) All() []Allocation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Allocation, 0, len(m.byID))
	for _, rec := range m.byID {
		out = append(out, rec.Allocation)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
