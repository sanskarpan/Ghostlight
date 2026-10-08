// Package prstate resolves current pull-request state and guards resurrection.
//
// Intake records what a provider asserted. This package answers the separate
// question of what is true now, and it exists mainly to enforce one rule:
//
//   - A late reopened or synchronize event must not resurrect an environment that
//     was already torn down. Destroyed is terminal for that immutable identifier,
//     so a new pull-request event creates a new environment rather than reviving
//     the old one.
//
// Arrival order is not authoritative. Nothing here trusts the head SHA from an
// event payload to decide whether a candidate is current; that comparison belongs
// to the authenticated lookup, and its result carries the time it was observed.
package prstate

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// State is a pull request's current state.
type State string

const (
	StateOpen   State = "open"
	StateClosed State = "closed"
	StateMerged State = "merged"
)

// ErrNoEnvironment means the pull request has no bound environment.
var ErrNoEnvironment = errors.New("pull request has no bound environment")

// ErrEnvironmentTerminal means the bound environment is destroyed. This is the
// case that must create a new environment rather than revive the old one.
var ErrEnvironmentTerminal = errors.New("bound environment is destroyed; a new one is required")

// Snapshot is current pull-request state resolved from an authenticated source.
type Snapshot struct {
	RepositoryRef string
	Number        int
	State         State
	HeadSHA       string
	BaseSHA       string
	// ObservedAt records when this was true. A comparison against a later event
	// uses this, not arrival order.
	ObservedAt time.Time
}

// EnvironmentBinding describes the environment currently bound to a pull request.
type EnvironmentBinding struct {
	EnvironmentID string
	Generation    uint64
	// Destroyed records that the identifier is terminal.
	Destroyed bool
	// Slug is the routing identity, kept for the operator message that tells a
	// customer their old environment is gone rather than silently vanishing.
	Slug string
}

// Lookup resolves current state from an authenticated source.
//
// It is deliberately a separate dependency from intake: intake must not depend on
// being able to reach the provider, because a verified event has to be admitted
// even when the provider is unavailable.
type Lookup interface {
	CurrentPullRequest(ctx context.Context, repositoryRef string, number int) (Snapshot, error)
}

// Decisions is the outcome of reconciling an event against current state.
type Decisions struct {
	// Resolved reports that current state was consulted.
	Resolved bool
	Snapshot Snapshot
	// StaleEvent reports that the event described a head that is no longer current,
	// so it is ignored. This is how out-of-order delivery is handled without
	// discarding the event entirely.
	StaleEvent bool
	// Action describes what should happen, in terms a caller can act on.
	Action Action
	// Reason is always populated, so a decision is never opaque.
	Reason string
}

// Action is the reconciliation outcome.
type Action string

const (
	// ActionNone means the event needs no lifecycle change.
	ActionNone Action = "none"
	// ActionCreate means a new environment should be requested.
	ActionCreate Action = "create"
	// ActionUpdate means the existing environment should take a new generation.
	ActionUpdate Action = "update"
	// ActionTeardown means the environment should be destroyed.
	ActionTeardown Action = "teardown"
)

// Event is what a provider asserted, used only to decide whether the event is
// still relevant.
type Event struct {
	RepositoryRef string
	Number        int
	// HeadSHA is the event's claim about the head. It is never used as authority;
	// it is compared against the resolved snapshot to detect a stale event.
	HeadSHA string
	Action  string
}

// Reconciler decides what an event should cause, given current state.
type Reconciler struct {
	lookup Lookup
	// NewestWinsTolerance is how much older a snapshot may be than the event
	// before the event is treated as authoritative for the head. Kept small; the
	// lookup is authoritative in almost every case.
	NewestWinsTolerance time.Duration
}

// NewReconciler builds a reconciler.
func NewReconciler(lookup Lookup) *Reconciler {
	return &Reconciler{lookup: lookup, NewestWinsTolerance: 2 * time.Minute}
}

// Reconcile resolves current state and decides the action.
//
// The lookup result is authoritative. The event's head is compared against it only
// to recognise a stale delivery, never to override it.
func (r *Reconciler) Reconcile(ctx context.Context, e Event, binding *EnvironmentBinding, now time.Time) (Decisions, error) {
	snap, err := r.lookup.CurrentPullRequest(ctx, e.RepositoryRef, e.Number)
	if err != nil {
		// Failing to resolve current state is not a reason to act on the event's
		// claim. It leaves the environment alone.
		return Decisions{
			Action: ActionNone,
			Reason: "current pull-request state could not be resolved; no lifecycle change",
		}, fmt.Errorf("resolve pull request: %w", err)
	}

	d := Decisions{Resolved: true, Snapshot: snap}

	// A pull request that is no longer open tears down, regardless of what the
	// event claimed.
	if snap.State != StateOpen {
		d.Action = ActionTeardown
		d.Reason = fmt.Sprintf("pull request is %s", snap.State)
		return d, nil
	}

	// An event describing a head older than the observed snapshot is stale. This
	// is the out-of-order delivery case, and it is ignored rather than treated as
	// a new candidate.
	if e.HeadSHA != "" && snap.HeadSHA != "" && e.HeadSHA != snap.HeadSHA {
		if r.NewestWinsTolerance == 0 || now.Sub(snap.ObservedAt) <= r.NewestWinsTolerance {
			d.Action = ActionNone
			d.StaleEvent = true
			d.Reason = fmt.Sprintf("event head %s is not current head %s", short(e.HeadSHA), short(snap.HeadSHA))
			return d, nil
		}
	}

	if binding == nil {
		d.Action = ActionCreate
		d.Reason = "no environment bound to this pull request"
		return d, nil
	}

	// The rule this package exists for: a destroyed environment is terminal. A
	// later reopened or synchronize event creates a new environment rather than
	// reviving this identifier.
	if binding.Destroyed {
		d.Action = ActionCreate
		d.Reason = fmt.Sprintf("environment %s is destroyed and its identifier is terminal; a new environment is required",
			binding.EnvironmentID)
		return d, nil
	}

	d.Action = ActionUpdate
	d.Reason = fmt.Sprintf("current head %s differs from generation %d", short(snap.HeadSHA), binding.Generation)
	return d, nil
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
