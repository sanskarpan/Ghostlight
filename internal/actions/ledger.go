// Package actions defines the durable action intent ledger.
//
// The central rule: an action's intent is committed to durable storage before
// any external mutation is attempted, and a result is accepted only if the
// lease owner, lease epoch and expected generation all still match. A timeout is
// not proof that creation failed, so an unacknowledged external call becomes
// uncertain rather than failed, and is resolved by observing ownership.
package actions

import (
	"errors"
	"fmt"
	"time"
)

// State is the lifecycle of a single action attempt.
type State string

const (
	// StatePlanned is committed before any external call is made.
	StatePlanned State = "planned"
	// StateRunning means an external operation is believed in flight.
	StateRunning   State = "running"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
	// StateUncertain means the request may or may not have taken effect. This
	// is the state a timeout lands in, and it is not a failure: retrying
	// blindly can duplicate a resource that already exists.
	StateUncertain State = "uncertain"
	StateCanceled  State = "canceled"
)

var (
	// ErrNotFound is returned when an action does not exist.
	ErrNotFound = errors.New("action not found")
	// ErrAlreadyExists is returned when a logical action key has already been
	// recorded. Duplicate events must be no-ops.
	ErrAlreadyExists = errors.New("action already exists")
	// ErrFenced is returned when a result is written by a stale owner, a stale
	// epoch, or against a superseded generation.
	ErrFenced = errors.New("result rejected by generation or epoch fence")
	// ErrTerminal is returned for any mutation of an action that has already
	// reached a terminal state.
	ErrTerminal = errors.New("action already reached a terminal state")
	// ErrNotUncertain is returned when an observation is attempted on an action
	// that is not in the uncertain state.
	ErrNotUncertain = errors.New("action is not uncertain")
)

// Type is the logical kind of external work. It forms part of the idempotency
// key, so a duplicate delivery of the same logical work cannot run twice.
type Type string

const (
	// TypeReserve takes a capacity reservation. It runs before allocation so a
	// preview that cannot fit the profile is refused before anything is created.
	TypeReserve  Type = "reserve"
	TypeAllocate Type = "allocate"
	TypeDeploy   Type = "deploy"
	TypeMigrate  Type = "migrate"
	TypeSeed     Type = "seed"
	TypeRollout  Type = "rollout"
	TypeHealth   Type = "health"
	// TypeGate runs an independent gate. Readiness is never asserted by the
	// platform about itself; it is proven.
	TypeGate Type = "gate"
	// TypeDrain stops ingress and new work claims. It runs before revocation so
	// nothing is still using the credentials when they are removed.
	TypeDrain Type = "drain"
	// TypeRevoke removes credentials and access bindings.
	TypeRevoke Type = "revoke"
	// TypeDestroy removes data. It runs after revocation.
	TypeDestroy Type = "destroy"
	// TypeVerifyAbsent proves removal against the provider. Reaching a destroyed
	// state is a consequence of this succeeding, never an assertion.
	TypeVerifyAbsent Type = "verify_absent"
)

// Terminal reports whether the state admits no further transition.
func (s State) Terminal() bool {
	switch s {
	case StateSucceeded, StateFailed, StateCanceled:
		return true
	}
	return false
}

// Fencing is the triple that a result write must present to be accepted. All
// three must match the action's current values.
//
// The epoch bounds ledger writes. It does not fence a cloud API call, which is
// why a runner holding a stale epoch must be terminated and observed before a
// replacement starts, rather than being replaced on lease expiry alone.
type Fencing struct {
	Owner              string
	Epoch              int64
	ExpectedGeneration uint64
}

// Action is one unit of external work against one environment generation.
type Action struct {
	ID            string
	EnvironmentID string
	Generation    uint64
	Type          Type
	// LogicalKey is caller-stable across retries. Uniqueness is on
	// (environment, generation, type, logical key), so a redelivered event
	// resolves to the same row.
	LogicalKey string
	// InputDigest pins the arguments. A retry with different arguments is a
	// different action, not a resend.
	InputDigest string
	// ResourceScope names the logical resources this action may touch. Deletion
	// authority is checked against this scope and against the shared-resource
	// denylist.
	ResourceScope []string

	State         State
	Attempts      int
	NextAttemptAt time.Time
	// LastError is diagnostic only and never satisfies an observation.
	LastError string

	Fencing Fencing

	// ExternalRef is an opaque provider reference. It deliberately holds no
	// cloud-native identifier as a typed field; the concrete reference is
	// resolved through the provider adapter.
	ExternalRef map[string]string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Lease bundles the identity a controller uses to claim an action.
type Lease struct {
	Owner string
	Epoch int64
}

// Observe is the result of inspecting an external system after an uncertain
// action, to determine whether the effect actually occurred.
type Observe struct {
	// Existed reports whether the external resource is present. A permission
	// failure must never be reported as absence.
	Existed bool
	// Reference is the observed provider reference, used to record ownership.
	Reference map[string]string
	// Terminal reports whether the resource has definitively gone away.
	Gone bool
	// Reason explains a negative observation.
	Reason string
}

// ErrUnresolvedObservation is returned when an observation could not reach a
// conclusion, leaving the action uncertain.
var ErrUnresolvedObservation = errors.New("observation unresolved; action remains uncertain")

// New creates a planned action. It must be durably committed before any external
// call is attempted for it.
func New(envID string, generation uint64, t Type, logicalKey, inputDigest string, scope []string, now time.Time) (*Action, error) {
	if envID == "" {
		return nil, errors.New("environment id is required")
	}
	if logicalKey == "" {
		return nil, errors.New("logical key is required; it is part of the idempotency key")
	}
	if inputDigest == "" {
		return nil, errors.New("input digest is required; a retry with different arguments is a different action")
	}
	return &Action{
		ID:            "",
		EnvironmentID: envID,
		Generation:    generation,
		Type:          t,
		LogicalKey:    logicalKey,
		InputDigest:   inputDigest,
		ResourceScope: append([]string(nil), scope...),
		State:         StatePlanned,
		NextAttemptAt: now,
		Fencing:       Fencing{ExpectedGeneration: generation},
		CreatedAt:     now,
		UpdatedAt:     now,
	}, nil
}

// Claim takes a lease on a planned or retryable action and moves it to running.
// The returned epoch is what a later result write must present.
func (a *Action) Claim(l Lease, now time.Time) error {
	if a.State.Terminal() {
		return fmt.Errorf("%w: %s", ErrTerminal, a.State)
	}
	if a.State == StateUncertain {
		// An uncertain action must be observed, not re-run. Re-running risks a
		// duplicate external resource.
		return fmt.Errorf("%w: %s must be observed before it can be retried", ErrNotUncertain, a.State)
	}
	if now.Before(a.NextAttemptAt) {
		return fmt.Errorf("action not yet due; next attempt at %s", a.NextAttemptAt.Format(time.RFC3339))
	}
	a.State = StateRunning
	a.Attempts++
	a.Fencing.Owner = l.Owner
	a.Fencing.Epoch = l.Epoch
	a.UpdatedAt = now
	return nil
}

// AcceptResult applies a result, subject to the fence. A completion from a stale
// owner, a stale epoch, or an older generation is refused: a stale completion
// must never mark a newer generation ready.
func (a *Action) AcceptResult(l Lease, generation uint64, result State, extRef map[string]string, now time.Time) error {
	if !result.Terminal() {
		return fmt.Errorf("result %q is not a terminal state", result)
	}
	if err := a.CheckFence(l, generation); err != nil {
		return err
	}
	a.State = result
	if len(extRef) > 0 {
		a.ExternalRef = extRef
	}
	a.UpdatedAt = now
	return nil
}

// MarkUncertain records that an external call may or may not have taken effect.
// It is deliberately distinct from failed: failure is an answer, uncertainty is
// the absence of one.
func (a *Action) MarkUncertain(l Lease, generation uint64, cause string, nextAttempt time.Time, now time.Time) error {
	if err := a.CheckFence(l, generation); err != nil {
		return err
	}
	a.State = StateUncertain
	a.LastError = cause
	a.NextAttemptAt = nextAttempt
	a.UpdatedAt = now
	return nil
}

// CheckFence verifies the fencing triple.
func (a *Action) CheckFence(l Lease, generation uint64) error {
	if l.Owner == "" {
		return fmt.Errorf("%w: no owner presented", ErrFenced)
	}
	if a.Fencing.Owner != "" && a.Fencing.Owner != l.Owner {
		return fmt.Errorf("%w: owner %q does not hold this action (held by %q)", ErrFenced, l.Owner, a.Fencing.Owner)
	}
	if a.Fencing.Epoch != l.Epoch {
		return fmt.Errorf("%w: epoch %d does not match %d", ErrFenced, l.Epoch, a.Fencing.Epoch)
	}
	if generation != a.Generation || a.Fencing.ExpectedGeneration != a.Generation {
		return fmt.Errorf("%w: generation %d is not current (action generation %d)", ErrFenced, generation, a.Generation)
	}
	return nil
}

// ResolveUncertain applies the outcome of an observation to an uncertain action.
//
//   - Existence means the call succeeded after all, and the observed ownership
//     reference is recorded.
//   - Verified absence means the call did not take effect, so retrying is now
//     safe. The action returns to planned rather than to a terminal failure:
//     otherwise the observation that made the retry safe would also prevent it.
//   - An unresolved observation deliberately leaves the action uncertain.
func (a *Action) ResolveUncertain(obs Observe, now time.Time) error {
	if a.State != StateUncertain {
		return fmt.Errorf("%w: state is %s", ErrNotUncertain, a.State)
	}
	switch {
	case obs.Existed:
		a.State = StateSucceeded
		if len(obs.Reference) > 0 {
			a.ExternalRef = obs.Reference
		}
	case obs.Gone:
		// Absence is verified against the correct account and region. A
		// permission failure is never reported as absence, so reaching this
		// branch means a retry cannot duplicate an existing resource.
		a.State = StatePlanned
		a.NextAttemptAt = now
	default:
		// Remains uncertain. It is better to stay uncertain than to guess.
		return fmt.Errorf("%w: %s", ErrUnresolvedObservation, obs.Reason)
	}
	a.LastError = obs.Reason
	a.UpdatedAt = now
	return nil
}

// NeedsObservation reports whether the action is awaiting evidence of an
// external effect.
func (a *Action) NeedsObservation() bool { return a.State == StateUncertain }

// MaxElapsed bounds how long an action may keep retrying before it requires a
// corrected request or a reviewed exception. It is a deadline, not a retry limit:
// the caller compares NextAttemptAt against it.
const MaxElapsed = 30 * time.Minute

// BackoffCeiling caps a single backoff interval.
const BackoffCeiling = 256 * time.Second

// ScheduleRetry applies exponential backoff with full jitter and returns the
// next attempt time. A terminal configuration or security failure must not be
// retried at all; it requires a corrected request or a reviewed exception, so
// the caller inspects LastError before calling this.
//
// A terminal action is never rescheduled; its existing schedule is returned
// unchanged.
func (a *Action) ScheduleRetry(now time.Time, jitter float64) time.Time {
	if a.State.Terminal() {
		return a.NextAttemptAt
	}
	a.State = StatePlanned

	attempt := a.Attempts
	if attempt < 1 {
		attempt = 1
	}
	ceiling := time.Second << min(attempt-1, 8)
	if ceiling > BackoffCeiling {
		ceiling = BackoffCeiling
	}
	// Full jitter: uniformly distributed in [ceiling/2, ceiling]. The caller
	// supplies the random fraction so this package stays deterministic in tests.
	if jitter < 0 {
		jitter = 0
	}
	if jitter > 1 {
		jitter = 1
	}
	delay := ceiling/2 + time.Duration(float64(ceiling/2)*jitter)

	a.NextAttemptAt = now.Add(delay)
	a.UpdatedAt = now
	return a.NextAttemptAt
}

// Exhausted reports whether the retry budget for this action has elapsed. An
// exhausted action must not be retried indefinitely; it needs a corrected
// request, a reviewed exception, or janitor intervention.
func (a *Action) Exhausted(now time.Time) bool {
	return !a.NextAttemptAt.IsZero() && now.Sub(a.NextAttemptAt) > MaxElapsed
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
