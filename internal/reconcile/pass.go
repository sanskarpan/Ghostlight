// Package reconcile is the controller pass.
//
// One pass does five things in a fixed order, and the order is the design:
//
//  1. Resolve undecided intake events into lifecycle decisions.
//  2. Reconcile environments whose desired state has changed.
//  3. Claim and commit work for runnable actions.
//  4. Observe uncertain actions, because an unknown external effect is the only
//     state that can leak a resource.
//  5. Expire environments whose TTL has passed, which is a watchdog duty and is
//     deliberately performed by a component that is not the controller.
//
// Observation is given its own pass and its own ordering guarantee rather than
// being folded into the work loop, because work can always be deferred and an
// unresolved uncertain action cannot.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Metrics records what a pass did. Every count is named so an operator can tell a
// quiet system from a stalled one.
type Metrics struct {
	EventsProcessed        int
	EventsIgnored          int
	EventsFailed           int
	EnvironmentsMoved      int
	ActionsClaimed         int
	ActionsCommitted       int
	ActionsUncertain       int
	ObservationsMade       int
	ObservationsUnresolved int
	EnvironmentsExpired    int
	LeasesTaken            int
	LeasesReleased         int
	StaleResultsRejected   int
}

// Add merges another set of counts.
func (m *Metrics) Add(o Metrics) {
	m.EventsProcessed += o.EventsProcessed
	m.EventsIgnored += o.EventsIgnored
	m.EventsFailed += o.EventsFailed
	m.EnvironmentsMoved += o.EnvironmentsMoved
	m.ActionsClaimed += o.ActionsClaimed
	m.ActionsCommitted += o.ActionsCommitted
	m.ActionsUncertain += o.ActionsUncertain
	m.ObservationsMade += o.ObservationsMade
	m.ObservationsUnresolved += o.ObservationsUnresolved
	m.EnvironmentsExpired += o.EnvironmentsExpired
	m.LeasesTaken += o.LeasesTaken
	m.LeasesReleased += o.LeasesReleased
	m.StaleResultsRejected += o.StaleResultsRejected
}

// Empty reports whether a pass did nothing at all.
//
// A pass that claims work but commits nothing is not empty: it means work is
// in flight, which is a healthy state rather than a stall.
func (m Metrics) Empty() bool {
	return m.EventsProcessed == 0 && m.EnvironmentsMoved == 0 &&
		m.ActionsClaimed == 0 && m.ObservationsMade == 0 &&
		m.EnvironmentsExpired == 0
}

// Config bounds one pass.
type Config struct {
	// ClaimLimit bounds how many actions one pass claims, so a large backlog
	// cannot monopolise a controller.
	ClaimLimit int
	// ObservationLimit bounds observation work for the same reason. An uncertain
	// action must never be starved by runnable work.
	ObservationLimit int
	// EventLimit bounds intake processing.
	EventLimit int
	// LeaseTTL is how long a claimed environment lease is held. Expiry does not
	// authorise takeover on its own; the previous runner is observed first.
	LeaseTTL time.Duration
}

// DefaultConfig returns bounds suitable for the initial fleet size.
func DefaultConfig() Config {
	return Config{
		ClaimLimit:       32,
		ObservationLimit: 32,
		EventLimit:       64,
		LeaseTTL:         5 * time.Minute,
	}
}

// validate rejects a configuration that would starve a stage.
func (c Config) validate() error {
	if c.ClaimLimit <= 0 {
		return errors.New("claim limit must be positive")
	}
	if c.ObservationLimit <= 0 {
		return errors.New("observation limit must be positive; an uncertain action must never be starved")
	}
	if c.EventLimit <= 0 {
		return errors.New("event limit must be positive")
	}
	if c.LeaseTTL <= 0 {
		return errors.New("lease ttl must be positive")
	}
	return nil
}

// Store is the durable state the pass operates on.
//
// Each method returns whether it changed something, so the pass can distinguish
// "did work" from "found nothing to do". A method that returns nil for both is
// indistinguishable from a broken integration.
type Store interface {
	// ClaimAction takes the lease on one runnable action.
	ClaimAction(ctx context.Context, envID string, generation uint64, actionType, logicalKey, owner string) (Claim, error)
	// CommitResult writes a terminal result under the fence.
	CommitResult(ctx context.Context, c Claim, result Result) error
	// MarkUncertain records that an external call may have taken effect.
	MarkUncertain(ctx context.Context, c Claim, cause string, nextAttempt time.Time) error
	// ResolveObservation applies an observation to an uncertain action.
	ResolveObservation(ctx context.Context, envID string, generation uint64, obs Observation) error
}

// Claim identifies a held lease.
type Claim struct {
	EnvironmentID string
	Generation    uint64
	Owner         string
	Epoch         int64
	ActionType    string
	LogicalKey    string
}

// Result is a terminal outcome.
type Result string

const (
	ResultSucceeded Result = "succeeded"
	ResultFailed    Result = "failed"
	ResultCanceled  Result = "canceled"
)

// Terminal reports whether a result ends the action.
func (r Result) Terminal() bool {
	switch r {
	case ResultSucceeded, ResultFailed, ResultCanceled:
		return true
	}
	return false
}

// Observation is the outcome of inspecting an external system.
type Observation struct {
	// Existed reports the resource is present.
	Existed bool
	// Gone reports the resource is definitively absent.
	Gone bool
	// Reference is the observed ownership reference.
	Reference map[string]string
	Reason    string
	// Unresolvable means the check could not reach a conclusion. It is distinct
	// from absence, and leaving an action uncertain is the correct response.
	Unresolvable bool
}

// Executor performs the external work for a claimed action.
//
// Execute must report an error whenever the external call may or may not have
// taken effect, including on timeout. Reporting "failed" for a call that actually
// succeeded is how a resource gets orphaned, so the caller's only correct options
// are a definite outcome or an error.
type Executor interface {
	Execute(ctx context.Context, c Claim) (Result, error)
}

// Observer inspects an uncertain action's external effect.
type Observer interface {
	Observe(ctx context.Context, c Claim) Observation
}

// UncertainWork identifies an action awaiting observation.
type UncertainWork struct {
	Claim
	// Reference is what was last known about the external effect.
	Reference map[string]string
}

// Watchdog expires environments whose TTL has passed.
//
// It is a separate dependency because expiry must not be the controller's
// decision: a controller that is stuck, overloaded or partitioned must not be the
// thing deciding that an environment may live forever.
type Watchdog interface {
	// ExpireDue marks environments past their TTL as desired-absent and returns
	// how many it expired.
	ExpireDue(ctx context.Context, limit int) (int, error)
}

// Clock supplies time. Injected so a pass is testable without sleeping.
type Clock func() time.Time

// Pass is one reconciliation pass.
type Pass struct {
	store     Store
	executor  Executor
	observer  Observer
	watchdog  Watchdog
	queue     IntakeQueue
	lifecycle Lifecycle
	cfg       Config
	owner     string
	now       Clock
	// jitter varies retry scheduling so a fleet of controllers does not retry in
	// lockstep. Injected for determinism in tests.
	jitter func() float64
	// intake records the last intake outcome, so a caller can report it without
	// the pass having to publish metrics into a shared sink.
	lastIntake IntakeSummary
}

// Options configures a pass.
type Options struct {
	Store     Store
	Executor  Executor
	Observer  Observer
	Watchdog  Watchdog
	Queue     IntakeQueue
	Lifecycle Lifecycle
	Config    Config
	Owner     string
	Now       Clock
	Jitter    func() float64
}

// New builds a pass. Executor, Observer, Queue and Lifecycle may be nil, in which
// case the corresponding stages report nothing rather than failing the pass.
func New(o Options) (*Pass, error) {
	if o.Store == nil {
		return nil, errors.New("store is required")
	}
	if o.Owner == "" {
		return nil, errors.New("owner is required; an unattributed lease cannot be released or audited")
	}
	// A queue without a lifecycle, or the reverse, would admit events with nothing
	// able to decide what they mean. Failing at construction beats a queue that
	// silently drains into nothing.
	if o.Queue != nil && o.Lifecycle == nil {
		return nil, errors.New("an intake queue requires a lifecycle to reconcile against")
	}
	if o.Lifecycle != nil && o.Queue == nil {
		return nil, errors.New("a lifecycle requires an intake queue to consume")
	}
	cfg := o.Config
	if cfg == (Config{}) {
		cfg = DefaultConfig()
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	now := o.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	jitter := o.Jitter
	if jitter == nil {
		jitter = func() float64 { return 0.5 }
	}
	return &Pass{
		store: o.Store, executor: o.Executor, observer: o.Observer,
		watchdog: o.Watchdog, queue: o.Queue, lifecycle: o.Lifecycle,
		cfg: cfg, owner: o.Owner, now: now, jitter: jitter,
	}, nil
}

// LastIntake returns the intake outcome of the most recent pass.
func (p *Pass) LastIntake() IntakeSummary { return p.lastIntake }

// ErrFenced means a completion was refused because the lease or generation moved.
var ErrFenced = errors.New("result rejected by generation or epoch fence")

// Run performs one pass and returns what it did.
//
// Stage failures are collected rather than aborting the pass. One broken stage must
// not prevent the others from running: an unreachable provider must not stop TTL
// expiry from happening, and a stuck intake queue must not stop observation of
// uncertain actions.
func (p *Pass) Run(ctx context.Context, work []Work, uncertain []UncertainWork) (Metrics, error) {
	var m Metrics
	var errs []error

	// Intake runs first. An admitted event is durable work that is already
	// recorded, and leaving it queued behind a large work backlog would let the
	// backlog win indefinitely.
	if p.queue != nil && p.lifecycle != nil {
		im, ierr := p.processIntake(ctx, p.queue, p.lifecycle)
		p.lastIntake = im.Summary()
		m.EventsProcessed += im.processed
		m.EventsIgnored += im.ignored + im.stale
		m.EventsFailed += im.failed + im.unresolvable
		m.EnvironmentsMoved += im.created + im.updated + im.torndown
		if ierr != nil {
			errs = append(errs, fmt.Errorf("intake: %w", ierr))
		}
	}

	// Observation runs second. An uncertain action is the only state that can leak
	// a resource, so it gets priority over starting new work.
	if p.observer != nil && len(uncertain) > 0 {
		obs, oerr := p.observe(ctx, uncertain)
		m.Add(obs)
		if oerr != nil {
			errs = append(errs, fmt.Errorf("observe: %w", oerr))
		}
	}

	if p.executor != nil && len(work) > 0 {
		done, derr := p.execute(ctx, work)
		m.Add(done)
		if derr != nil {
			errs = append(errs, fmt.Errorf("execute: %w", derr))
		}
	}

	// Expiry last, so it happens even when the earlier stages failed.
	if p.watchdog != nil {
		n, werr := p.watchdog.ExpireDue(ctx, p.cfg.ObservationLimit)
		m.EnvironmentsExpired += n
		if werr != nil {
			errs = append(errs, fmt.Errorf("expire: %w", werr))
		}
	}

	return m, errors.Join(errs...)
}

// Work is one runnable action.
type Work struct {
	Claim
	// Attempts is how many times this action has been tried, used to schedule
	// backoff.
	Attempts int
}

// execute claims and runs work, committing under the fence.
//
// The claim happens before execution, so a result always has a lease to commit
// against. An action that cannot be claimed is skipped rather than failed: another
// controller holds it, and that is normal operation.
func (p *Pass) execute(ctx context.Context, work []Work) (Metrics, error) {
	var m Metrics
	budget := p.cfg.ClaimLimit
	if budget > len(work) {
		budget = len(work)
	}

	var errs []error
	for _, w := range work[:budget] {
		if err := ctx.Err(); err != nil {
			return m, err
		}

		claim, err := p.store.ClaimAction(ctx, w.EnvironmentID, w.Generation,
			w.ActionType, w.LogicalKey, p.owner)
		if err != nil {
			// Another owner holds it, or it is not due. Not an error worth
			// escalating: a busy fleet looks like this constantly.
			continue
		}
		m.ActionsClaimed++
		m.LeasesTaken++
		if claim.Owner == "" {
			claim.Owner = p.owner
		}
		if claim.Generation == 0 {
			claim.Generation = w.Generation
		}

		result, execErr := p.executor.Execute(ctx, claim)

		switch {
		case execErr != nil:
			// The external call may have taken effect. This is uncertain, never
			// failed, and it must be observed before it is retried.
			next := p.now().Add(p.backoff(w.Attempts + 1))
			if uerr := p.store.MarkUncertain(ctx, claim, execErr.Error(), next); uerr != nil {
				if errors.Is(uerr, ErrFenced) {
					m.StaleResultsRejected++
					continue
				}
				errs = append(errs, fmt.Errorf("mark uncertain: %w", uerr))
				continue
			}
			m.ActionsUncertain++
		case !result.Terminal():
			errs = append(errs, fmt.Errorf("executor returned non-terminal result %q for %s/%s",
				result, claim.EnvironmentID, claim.LogicalKey))
		default:
			if cerr := p.store.CommitResult(ctx, claim, result); cerr != nil {
				if errors.Is(cerr, ErrFenced) {
					// The lease moved while the work was in flight. The external
					// effect happened; the ledger write did not. Count it and move
					// on rather than retrying, which would duplicate the work.
					m.StaleResultsRejected++
					continue
				}
				errs = append(errs, fmt.Errorf("commit result: %w", cerr))
				continue
			}
			m.ActionsCommitted++
			m.LeasesReleased++
		}
	}
	return m, errors.Join(errs...)
}

// observe resolves uncertain actions.
//
// An unresolvable observation is deliberately left uncertain. Concluding absence
// from an inspection that could not complete is how a duplicate create or an
// orphaned resource happens.
func (p *Pass) observe(ctx context.Context, uncertain []UncertainWork) (Metrics, error) {
	var m Metrics
	budget := p.cfg.ObservationLimit
	if budget > len(uncertain) {
		budget = len(uncertain)
	}

	var errs []error
	for _, u := range uncertain[:budget] {
		if err := ctx.Err(); err != nil {
			return m, err
		}
		obs := p.observer.Observe(ctx, u.Claim)
		m.ObservationsMade++

		if obs.Unresolvable || (!obs.Existed && !obs.Gone) {
			m.ObservationsUnresolved++
			continue
		}
		if err := p.store.ResolveObservation(ctx, u.EnvironmentID, u.Generation, obs); err != nil {
			errs = append(errs, fmt.Errorf("resolve observation: %w", err))
			continue
		}
		m.ActionsCommitted++
	}
	return m, errors.Join(errs...)
}

// MaxBackoff bounds a single retry interval. Beyond this, an action that keeps
// failing needs a corrected request or a reviewed exception, not more retries.
const MaxBackoff = 5 * time.Minute

// backoff computes a full-jitter exponential delay.
//
// The jitter is applied to the whole interval rather than only the tail, so a fleet
// of controllers that failed together does not retry together.
func (p *Pass) backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	// Cap the shift so it cannot overflow on a long-lived failure.
	if attempt > 20 {
		attempt = 20
	}
	base := time.Second << (attempt - 1)
	if base > MaxBackoff {
		base = MaxBackoff
	}
	j := p.jitter()
	if j < 0 {
		j = 0
	}
	if j > 1 {
		j = 1
	}
	return time.Duration(float64(base) * j)
}
