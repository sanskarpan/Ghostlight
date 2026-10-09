// Package statelock serialises mutation of one environment against a native lock.
//
// This exists because a database lease is not sufficient, and the design says so
// plainly: "Database epochs fence ledger updates, not AWS/Kubernetes/Terraform side
// effects by themselves" and "no concurrent apply/destroy is started solely because a
// DB lease expired" (SPEC.md, fencing limitations).
//
// The failure this prevents is specific. A runner dies mid-apply. Its database lease
// expires. A replacement takes the lease and starts a fresh apply against the same
// environment while the original's provider-side operation is still running. Two
// mutators now race on one resource set, and the loser may destroy state the winner
// just created.
//
// So the rule is: acquire the native lock, do the work, release it. A replacement
// must wait for confirmed termination and observation of outstanding operations. It
// does not get to proceed because a lease lapsed.
package statelock

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrLockHeld means another runner holds the native lock.
//
// It is not a failure. It is the expected answer while a previous runner is being
// observed and terminated, and a caller must treat it as "wait", never as "take over".
var ErrLockHeld = errors.New("native state lock is held by another runner")

// ErrLockLost means the lock was lost mid-operation.
//
// This is more serious than not acquiring it: work may have been applied without
// exclusivity, so the environment must be observed before anything else touches it.
var ErrLockLost = errors.New("native state lock was lost during the operation")

// ErrNotTerminated means a previous runner has not been confirmed terminated.
var ErrNotTerminated = errors.New("previous runner has not been confirmed terminated")

// Runner identifies a runner process.
type Runner struct {
	// Ref is the provider-side handle: a job name, a process id, a lease name.
	// It is what termination is confirmed against.
	Ref string
	// Generation records which candidate the runner was operating on.
	Generation uint64
	// TakenAt is when this runner acquired the lock, from database time.
	TakenAt time.Time
}

// Lease is the recorded ownership of an environment's native lock.
type Lease struct {
	EnvironmentID string
	Generation    uint64
	Holder        Runner
	// ExpiresAt bounds how long the platform will wait before escalating. It never
	// authorises a takeover.
	ExpiresAt time.Time
}

// Backend is the native lock, such as a state-backend lock or a coordination lease.
//
// Acquire and Release must be operations the provider itself serialises. A lock held
// only in the platform database is the thing this package exists to avoid.
type Backend interface {
	// Acquire takes the lock for a runner. It reports ErrLockHeld rather than
	// blocking, so a caller can decide whether to wait or escalate. A ttl of zero
	// verifies exclusivity without taking anything.
	Acquire(ctx context.Context, environmentID string, holder Runner, ttl time.Duration) error
	// Release drops the lock. It must be safe to call for a lock this runner does
	// not hold, because a process that lost its lock still needs to clean up.
	Release(ctx context.Context, environmentID string, holder Runner) error
	// Current returns the runner holding the lock, or nil when it is free. It is
	// how a replacement learns whose operation it must account for.
	Current(ctx context.Context, environmentID string) (*Runner, error)
	// ConfirmTerminated reports whether a runner has definitively stopped.
	ConfirmTerminated(ctx context.Context, environmentID string, holder Runner) (bool, error)
	// Observe reports whether the runner's external operation is still in flight.
	// A runner that has exited but whose operation is still running has not been
	// replaced.
	Observe(ctx context.Context, environmentID string, holder Runner) (OperationState, error)
}

// OperationState is what is known about a runner's external work.
type OperationState string

const (
	// StateUnknown means it could not be determined. Treating unknown as idle is
	// how two mutators end up running.
	StateUnknown OperationState = "unknown"
	// StateNotStarted means the operation never began.
	StateNotStarted OperationState = "not_started"
	// StateInFlight means the operation is running.
	StateInFlight OperationState = "in_flight"
	// StateSettled means the operation finished and its outcome is known.
	StateSettled OperationState = "settled"
)

// Manager serialises mutation for environments.
type Manager struct {
	backend Backend
	// now is injected so expiry decisions are testable.
	now func() time.Time
	// lockTTL bounds how long a lock is held before the platform escalates. It is
	// not a takeover window.
	lockTTL time.Duration
	// escalationGrace is how long a lapsed lock is tolerated before an operator is
	// involved. Silence here is worse than noise: a stuck lock is a stuck
	// environment either way.
	escalationGrace time.Duration
}

// Config bounds a manager.
type Config struct {
	// LockTTL is how long an acquired lock is valid.
	LockTTL time.Duration
	// EscalationGrace is how long a lapsed lock waits for manual intervention.
	EscalationGrace time.Duration
	// Now overrides the clock.
	Now func() time.Time
}

// DefaultConfig returns the qualified bounds.
func DefaultConfig() Config {
	return Config{
		LockTTL:         10 * time.Minute,
		EscalationGrace: 30 * time.Minute,
	}
}

// New builds a manager.
func New(backend Backend, cfg Config) (*Manager, error) {
	if backend == nil {
		return nil, errors.New("a native lock backend is required; a platform-database lock is not sufficient")
	}
	if cfg.LockTTL <= 0 {
		cfg = DefaultConfig()
	}
	if cfg.EscalationGrace <= 0 {
		cfg.EscalationGrace = cfg.LockTTL * 3
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Manager{backend: backend, now: now, lockTTL: cfg.LockTTL, escalationGrace: cfg.EscalationGrace}, nil
}

// Acquire takes the native lock for an environment.
//
// The sequence matters and is the whole point: a previous holder must be confirmed
// terminated *before* this runner proceeds. Locking and waiting are not
// interchangeable, because a lock alone says nothing about whether the previous
// runner's provider-side operation is still running.
func (m *Manager) Acquire(ctx context.Context, environmentID string, generation uint64, runner Runner) (Lease, error) {
	if environmentID == "" {
		return Lease{}, errors.New("environment id is required")
	}
	if runner.Ref == "" {
		// Without a handle there is nothing to confirm termination against, which
		// means a replacement could never safely take over.
		return Lease{}, errors.New("runner reference is required; termination cannot be confirmed without one")
	}
	runner.Generation = generation
	runner.TakenAt = m.now()

	if err := m.backend.Acquire(ctx, environmentID, runner, m.lockTTL); err != nil {
		if !errors.Is(err, ErrLockHeld) {
			return Lease{}, fmt.Errorf("acquire native lock: %w", err)
		}
		// Someone holds it. Establish whether they are gone before deciding.
		if err := m.awaitTermination(ctx, environmentID, runner); err != nil {
			return Lease{}, err
		}
		// The holder is gone but the lock still has to be released by whoever owns
		// it, so acquire again rather than returning a lease we never took.
		if err := m.backend.Acquire(ctx, environmentID, runner, m.lockTTL); err != nil {
			return Lease{}, fmt.Errorf("acquire native lock after previous runner ended: %w", err)
		}
	}

	return Lease{
		EnvironmentID: environmentID,
		Generation:    generation,
		Holder:        runner,
		ExpiresAt:     m.now().Add(m.lockTTL),
	}, nil
}

// awaitTermination waits out a held lock by observing the holder, and reports an
// escalation rather than proceeding when it cannot be established that the holder
// stopped.
//
// It never returns "proceed anyway". An unknown state is treated as still running,
// because treating unknown as idle is exactly how two mutators end up on one
// environment.
func (m *Manager) awaitTermination(ctx context.Context, environmentID string, next Runner) error {
	current, err := m.holder(ctx, environmentID)
	if err != nil {
		return err
	}
	if current == nil {
		// Nobody holds it after all; the caller retries acquisition.
		return nil
	}

	terminated, err := m.backend.ConfirmTerminated(ctx, environmentID, *current)
	if err != nil {
		return fmt.Errorf("confirm termination of %s: %w", current.Ref, err)
	}

	state, err := m.backend.Observe(ctx, environmentID, *current)
	if err != nil {
		return fmt.Errorf("observe %s: %w", current.Ref, err)
	}

	// The provider-side operation is the thing that actually races, so it is checked
	// before the process state. A runner whose process is gone but whose apply is
	// still running is the exact case that must not be reported as merely waiting for
	// a lock release.
	if state == StateInFlight {
		if terminated {
			return fmt.Errorf("%w: previous runner %s is terminated but its operation is still in flight; %s must not start",
				ErrNotTerminated, current.Ref, next.Ref)
		}
		return fmt.Errorf("%w: previous runner %s still has an operation in flight", ErrNotTerminated, current.Ref)
	}
	if state == StateUnknown {
		return fmt.Errorf("%w: state of previous runner %s is unknown and must not be assumed idle",
			ErrNotTerminated, current.Ref)
	}

	if terminated {
		// The previous runner and its operation are both done. The lock still has to
		// be released by whoever owns it, so this is a wait, not a takeover.
		return fmt.Errorf("%w: previous runner %s is terminated but its lock must be released before %s proceeds",
			ErrNotTerminated, current.Ref, next.Ref)
	}

	// Settled but not terminated. Escalate: this is the case where automation must
	// stop guessing and a person decides.
	lapsed := m.now().Sub(current.TakenAt)
	if lapsed > m.escalationGrace {
		return fmt.Errorf("%w: previous runner %s settled %v ago, beyond the %v grace; operator action required",
			ErrNotTerminated, current.Ref, lapsed, m.escalationGrace)
	}
	return fmt.Errorf("%w: previous runner %s has settled but not terminated; wait %v before proceeding",
		ErrNotTerminated, current.Ref, m.escalationGrace-lapsed)
}

// holder returns the current lock holder, or nil when the lock is free.
func (m *Manager) holder(ctx context.Context, environmentID string) (*Runner, error) {
	r, err := m.backend.Current(ctx, environmentID)
	if err != nil {
		return nil, fmt.Errorf("read current lock holder for %s: %w", environmentID, err)
	}
	return r, nil
}

// Release drops the lock.
//
// It is deliberately safe to call for a lock this runner does not hold: a process
// that lost its lock still needs to release, and refusing would strand the lock.
func (m *Manager) Release(ctx context.Context, l Lease) error {
	if l.EnvironmentID == "" {
		return nil
	}
	if err := m.backend.Release(ctx, l.EnvironmentID, l.Holder); err != nil {
		return fmt.Errorf("release native lock: %w", err)
	}
	return nil
}

// AssertHeld verifies the lock is still held before a destructive step.
//
// A lock lost part-way through an operation means work may have been applied without
// exclusivity, so the environment must be observed before continuing. This is checked
// rather than assumed because the window between check and action is exactly where
// the race lives.
func (m *Manager) AssertHeld(ctx context.Context, l Lease) error {
	if err := m.backend.Acquire(ctx, l.EnvironmentID, l.Holder, 0); err != nil {
		if errors.Is(err, ErrLockHeld) {
			return fmt.Errorf("%w: %s was taken by another runner", ErrLockLost, l.EnvironmentID)
		}
		// Any other failure means exclusivity cannot be established, which is the
		// same danger: proceeding would assume a guarantee that does not hold.
		return fmt.Errorf("%w: exclusivity of %s could not be established: %w",
			ErrLockLost, l.EnvironmentID, err)
	}
	return nil
}

// Expired reports whether a lease has lapsed past its bound.
//
// A lapsed lease is an escalation signal, never a takeover trigger.
func (m *Manager) Expired(l Lease) bool {
	return m.now().After(l.ExpiresAt)
}

// EscalationDue reports whether a lapsed lock has waited long enough for a person.
func (m *Manager) EscalationDue(l Lease) bool {
	if !m.Expired(l) {
		return false
	}
	return m.now().Sub(l.ExpiresAt) > m.escalationGrace
}
