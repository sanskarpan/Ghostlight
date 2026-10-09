// Package ttlwatch expires environments independently of the controller.
//
// SPEC.md requires a watchdog because a controller that is stuck, overloaded or
// partitioned must not be the thing deciding that an environment may live forever.
// Expiry is therefore a separate component with its own dependencies and its own
// database access, not a branch inside the reconciliation loop.
//
// It also enforces two rules that only make sense here:
//
//   - Expiry does not wait for a successful gate. A preview that never passes its
//     gates still expires; otherwise a stuck gate becomes a permanent environment.
//   - Capacity is released on expiry. Holding the reservation after teardown would
//     make the fleet leak slots for environments nobody is using.
package ttlwatch

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/quota"
)

// ErrRefused marks an expiry that policy will not permit.
var ErrRefused = errors.New("expiry refused by policy")

// Environment is the minimal state the watchdog needs.
type Environment struct {
	ID         string
	Repository string
	Actor      string
	Profile    string
	Desired    string
	// ExpiresAt is when the environment's TTL ends. A zero value means no TTL was
	// ever granted, which the watchdog refuses rather than treating as infinite.
	ExpiresAt time.Time
	// ReservationID is the capacity held for this environment.
	ReservationID string
	// Extensions records how many extensions it has used.
	Extensions int
}

// Due reports whether the watchdog should expire it.
func (e Environment) Due(now time.Time) bool {
	if e.Desired == DesiredAbsent {
		return false
	}
	if e.ExpiresAt.IsZero() {
		// A missing TTL is a data problem. Treating it as "never expires" would
		// convert a bug into a permanent environment, and treating it as "already
		// expired" would destroy a preview someone is using.
		return false
	}
	return !now.Before(e.ExpiresAt)
}

// DesiredAbsent mirrors the lifecycle's terminal intent.
const DesiredAbsent = "absent"

// Store is the watchdog's persistence.
type Store interface {
	// Expired lists environments past their TTL, bounded.
	Expired(ctx context.Context, limit int) ([]Environment, error)
	// MarkAbsent sets desired absent. It must be idempotent, because the watchdog
	// may re-read the same row after a partial failure.
	MarkAbsent(ctx context.Context, id string, at time.Time) error
}

// Ledger releases the capacity an expired environment was holding.
type Ledger interface {
	Release(ctx context.Context, reservationID string) error
}

// Watchdog expires environments independently of the controller.
type Watchdog struct {
	store  Store
	ledger Ledger
	maxima quota.Maxima
	now    func() time.Time
	// requireReservation refuses expiry when no capacity is held, because releasing
	// nothing would leave a slot consumed with no environment to account for it.
	requireReservation bool
}

// Config bounds a watchdog.
type Config struct {
	Maxima             quota.Maxima
	Now                func() time.Time
	RequireReservation bool
}

// New builds a watchdog.
func New(store Store, ledger Ledger, cfg Config) (*Watchdog, error) {
	if store == nil {
		return nil, errors.New("a watchdog needs its own store; expiry must not depend on the controller")
	}
	if cfg.Maxima == (quota.Maxima{}) {
		cfg.Maxima = quota.DefaultMaxima()
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Watchdog{
		store: store, ledger: ledger, maxima: cfg.Maxima, now: cfg.Now,
		requireReservation: cfg.RequireReservation,
	}, nil
}

// Result is what one expiry pass did.
type Result struct {
	// Expired counts environments marked desired-absent.
	Expired int
	// Released counts capacity reservations returned.
	Released int
	// Skipped counts environments the watchdog declined to expire, with reasons.
	Skipped []Skip
}

// Skip is an environment the watchdog did not expire, and why.
type Skip struct {
	EnvironmentID string
	Reason        string
	// Err is set when the refusal was an error rather than a policy decision.
	Err error
}

// Run expires due environments.
//
// The order is fixed and matters: mark absent first, then release capacity. Releasing
// first would free a slot that a still-present environment is occupying, admitting a
// replacement into capacity the previous environment is still using.
func (w *Watchdog) Run(ctx context.Context, limit int) (Result, error) {
	var res Result
	var errs []error

	due, err := w.store.Expired(ctx, limit)
	if err != nil {
		return res, fmt.Errorf("list expired environments: %w", err)
	}

	for _, env := range due {
		if !env.Due(w.now()) {
			res.Skipped = append(res.Skipped, Skip{
				EnvironmentID: env.ID,
				Reason:        "not yet past its TTL, or already absent",
			})
			continue
		}
		if w.requireReservation && env.ReservationID == "" {
			res.Skipped = append(res.Skipped, Skip{
				EnvironmentID: env.ID,
				Reason:        "no capacity reservation is held, so there is nothing safe to release",
			})
			continue
		}

		if err := w.store.MarkAbsent(ctx, env.ID, w.now()); err != nil {
			// Capacity is deliberately not released: the environment is still
			// present, and freeing its slot would oversubscribe the fleet.
			res.Skipped = append(res.Skipped, Skip{
				EnvironmentID: env.ID,
				Reason:        "could not mark absent",
				Err:           err,
			})
			errs = append(errs, fmt.Errorf("expire %s: %w", env.ID, err))
			continue
		}
		res.Expired++

		if w.ledger != nil && env.ReservationID != "" {
			if err := w.ledger.Release(ctx, env.ReservationID); err != nil {
				// Expiry succeeded, so this is not a leak of the environment. It is
				// a leak of a slot, which is retryable.
				res.Skipped = append(res.Skipped, Skip{
					EnvironmentID: env.ID,
					Reason:        "expired but its capacity reservation was not released",
					Err:           err,
				})
				errs = append(errs, fmt.Errorf("release capacity for %s: %w", env.ID, err))
			} else {
				res.Released++
			}
		}
	}

	return res, errors.Join(errs...)
}

// GraceLapsed reports whether an administrative grace period has run out.
//
// Grace is bounded precisely so that this answer exists. A grace period with no
// expiry would make this function unanswerable and the environment permanent.
func (w *Watchdog) GraceLapsed(grace quota.Grace, now time.Time) (bool, error) {
	if err := quota.ValidateGrace(grace, w.maxima); err != nil {
		return false, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return !now.Before(grace.ExpiresAt), nil
}

// Extendable reports whether an environment may still be extended, and if not why.
//
// The extension count is checked here rather than only in the authorization gate so
// a caller can explain the refusal before attempting it.
func (w *Watchdog) Extendable(env Environment) error {
	if env.Extensions >= w.maxima.MaxExtensions {
		return fmt.Errorf("%w: environment %s has used all %d extensions; extending further requires an audited capacity revision",
			ErrRefused, env.ID, w.maxima.MaxExtensions)
	}
	return nil
}
