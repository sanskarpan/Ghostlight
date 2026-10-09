package reconcile

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/prstate"
)

// ErrLookupUnavailable means current pull-request state could not be resolved.
//
// It is distinct from a refusal. A refusal is a decision; this is an absence of
// information, and the only safe response is to leave the environment alone and
// retry.
var ErrLookupUnavailable = errors.New("current pull-request state unavailable")

// IntakeQueue is the durable inbox, read as work to be done.
type IntakeQueue interface {
	// Pending returns admitted events awaiting processing, oldest first and bounded.
	//
	// The implementation must honour limit. The pass relies on it to keep one backlog
	// from monopolising a controller, and a queue that silently returns everything
	// would let a queue that grew once never drain.
	Pending(ctx context.Context, limit int) ([]PendingEvent, error)
	// Processed records that an event was handled.
	Processed(ctx context.Context, deliveryID string) error
	// Ignored records a deliberate no-op with its reason.
	Ignored(ctx context.Context, deliveryID, reason string) error
	// Failed records a failure and schedules a retry on the same row.
	Failed(ctx context.Context, deliveryID, reason string, nextAttempt time.Time) error
}

// PendingEvent is an admitted event awaiting processing.
//
// The payload body is not carried here. Intake recorded a digest rather than
// retaining the body, so processing resolves current state from an authenticated
// source instead of trusting what the event claimed.
type PendingEvent struct {
	DeliveryID string
	EventType  string
	Repository string
	// Attempts is how many times processing has been tried.
	Attempts int
}

// Lifecycle is the reconciliation decision an event produces.
//
// It is a narrow interface deliberately: the intake stage needs to turn a decision
// into a lifecycle change and nothing more. The planning of that change into action
// intents is a separate concern with its own tests.
type Lifecycle interface {
	// Reconcile decides what an event should cause.
	Reconcile(ctx context.Context, e prstate.Event, binding *prstate.EnvironmentBinding, now time.Time) (prstate.Decisions, error)
	// Binding returns the environment currently serving a pull request, or nil.
	Binding(ctx context.Context, repositoryRef string, number int) (*prstate.EnvironmentBinding, error)
	// NumberFor extracts the pull-request number from an event payload digest and
	// type. It returns ok=false when the event carries no usable pull request.
	NumberFor(ctx context.Context, e PendingEvent) (int, bool, error)
}

// intakeMetrics counts intake outcomes separately from work outcomes, because a
// queue that is draining looks identical to a quiet system unless counted.
type intakeMetrics struct {
	processed    int
	ignored      int
	failed       int
	stale        int
	unresolvable int
	created      int
	updated      int
	torndown     int
}

// processIntake consumes the inbox queue and turns each event into a lifecycle
// decision.
//
// Three rules apply to every event, and they are the reason this stage is separate
// from the work loop:
//
//   - An event that cannot be resolved causes no lifecycle change. Falling back to
//     the event's own claims would act on unverified state during a provider outage.
//   - An event describing a non-current head is ignored, not failed. It is stale
//     data, not a broken one, and failing it would retry something that should
//     never be applied.
//   - The delivery row is always resolved. A failure that leaves the row pending
//     would retry the same event forever with no recorded reason.
func (p *Pass) processIntake(ctx context.Context, q IntakeQueue, lc Lifecycle) (intakeMetrics, error) {
	var m intakeMetrics
	if q == nil || lc == nil {
		return m, nil
	}

	pending, err := q.Pending(ctx, p.cfg.EventLimit)
	if err != nil {
		return m, fmt.Errorf("read intake queue: %w", err)
	}

	var errs []error
	for _, e := range pending {
		if err := ctx.Err(); err != nil {
			return m, errors.Join(append(errs, err)...)
		}

		number, ok, err := lc.NumberFor(ctx, e)
		if err != nil {
			m.failed++
			if ferr := q.Failed(ctx, e.DeliveryID, err.Error(), p.now().Add(p.backoff(e.Attempts+1))); ferr != nil {
				errs = append(errs, fmt.Errorf("record intake failure: %w", ferr))
			}
			continue
		}
		if !ok {
			// Not a pull-request event. Nothing to reconcile, and that is a
			// deliberate no-op rather than a failure.
			if ierr := q.Ignored(ctx, e.DeliveryID, "event carries no pull request"); ierr != nil {
				errs = append(errs, fmt.Errorf("record intake ignore: %w", ierr))
			} else {
				m.ignored++
			}
			continue
		}

		binding, err := lc.Binding(ctx, e.Repository, number)
		if err != nil {
			m.failed++
			if ferr := q.Failed(ctx, e.DeliveryID, err.Error(), p.now().Add(p.backoff(e.Attempts+1))); ferr != nil {
				errs = append(errs, fmt.Errorf("record intake failure: %w", ferr))
			}
			continue
		}

		decision, rerr := lc.Reconcile(ctx,
			prstate.Event{RepositoryRef: e.Repository, Number: number, Action: e.EventType},
			binding, p.now())

		if rerr != nil {
			// The lookup could not be reached. Leave the environment alone; do not
			// act on the event's claims.
			m.unresolvable++
			if ferr := q.Failed(ctx, e.DeliveryID, rerr.Error(), p.now().Add(p.backoff(e.Attempts+1))); ferr != nil {
				errs = append(errs, fmt.Errorf("record intake failure: %w", ferr))
			}
			continue
		}

		switch decision.Action {
		case prstate.ActionNone:
			if decision.StaleEvent {
				// Stale data, not a failure. Ignoring it with its reason keeps it
				// out of the retry queue and leaves the audit trail intact.
				m.stale++
				if ierr := q.Ignored(ctx, e.DeliveryID, decision.Reason); ierr != nil {
					errs = append(errs, fmt.Errorf("record intake ignore: %w", ierr))
				}
				continue
			}
			// Nothing to do, and nothing went wrong. A legitimate no-op.
			if ierr := q.Ignored(ctx, e.DeliveryID, decision.Reason); ierr != nil {
				errs = append(errs, fmt.Errorf("record intake ignore: %w", ierr))
			} else {
				m.ignored++
			}
		case prstate.ActionCreate:
			m.created++
		case prstate.ActionUpdate:
			m.updated++
		case prstate.ActionTeardown:
			m.torndown++
		}

		if perr := q.Processed(ctx, e.DeliveryID); perr != nil {
			errs = append(errs, fmt.Errorf("record intake processed: %w", perr))
			continue
		}
		m.processed++
	}

	return m, errors.Join(errs...)
}

// IntakeSummary reports intake outcomes for metrics.
type IntakeSummary struct {
	Processed            int
	Ignored              int
	Failed               int
	Stale                int
	Unresolvable         int
	EnvironmentsCreated  int
	EnvironmentsUpdated  int
	EnvironmentsTornDown int
}

// Summary converts intake counts into reportable metrics.
func (m intakeMetrics) Summary() IntakeSummary {
	return IntakeSummary{
		Processed:            m.processed,
		Ignored:              m.ignored,
		Failed:               m.failed,
		Stale:                m.stale,
		Unresolvable:         m.unresolvable,
		EnvironmentsCreated:  m.created,
		EnvironmentsUpdated:  m.updated,
		EnvironmentsTornDown: m.torndown,
	}
}
