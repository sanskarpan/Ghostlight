// Package admission gates environment admission on held capacity.
//
// SPEC.md: "admission transaction reserves repository/actor/fleet concurrency,
// CPU/storage ceiling and monetary allowance." Reserving is transactional, so a retry
// cannot consume the last slot twice and two controllers cannot each see it free.
//
// This package is the gate in front of that reservation. It exists separately from the
// ledger because the two answer different questions. The ledger knows what capacity is
// left. This knows whether *this* request is admissible at all, before any capacity
// moves — including the checks no amount of remaining capacity makes pass, such as a
// TTL beyond the profile maximum.
package admission

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/quota"
)

// ErrRefused marks an admission that policy will not permit.
var ErrRefused = errors.New("admission refused")

// Request is a proposed admission.
type Request struct {
	EnvironmentID string
	Actor         string
	Repository    string
	Profile       string
	// RequestedTTL is what the caller asked for. Zero means the default.
	RequestedTTL time.Duration
	// Demanded is the capacity the environment would consume.
	Demanded quota.Demand
	// ExtensionsSoFar bounds how many extensions the environment has used.
	ExtensionsSoFar int
	Now             time.Time
}

// Decision is the outcome of an admission check.
type Decision struct {
	// ReservationID is the capacity held, empty when refused.
	ReservationID string
	// GrantedTTL is the TTL actually granted after clamping.
	GrantedTTL time.Duration
	// ExpiresAt is when the environment must be reclaimed.
	ExpiresAt time.Time
	// Clamped reports that the requested TTL exceeded policy and was reduced.
	Clamped bool
	// Scopes are the scope references capacity was taken against.
	Scopes []quota.ScopeRef
}

// Granted reports whether admission succeeded.
func (d Decision) Granted() bool { return d.ReservationID != "" }

// Gate admits environments against held capacity.
type Gate struct {
	ledger quota.Ledger
	maxima quota.Maxima
	now    func() time.Time
}

// New builds a gate.
func New(ledger quota.Ledger, m quota.Maxima, now func() time.Time) (*Gate, error) {
	if ledger == nil {
		// Admitting without a reservation is how an environment comes to exist with
		// nothing accounting for it, so this is not a defaulted field.
		return nil, errors.New("an admission gate requires a ledger; capacity must be reserved, not assumed")
	}
	if m == (quota.Maxima{}) {
		m = quota.DefaultMaxima()
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Gate{ledger: ledger, maxima: m, now: now}, nil
}

// Admit checks every precondition and, if all pass, reserves capacity.
//
// The checks run before the reservation on purpose. A request that cannot be admitted
// should not briefly consume a window and leave a partial hold for a rollback to
// clean up.
func (g *Gate) Admit(ctx context.Context, req Request) (Decision, error) {
	switch {
	case req.EnvironmentID == "":
		return Decision{}, fmt.Errorf("%w: an admission must name the environment", ErrRefused)
	case req.Repository == "":
		return Decision{}, fmt.Errorf("%w: an admission must name the repository", ErrRefused)
	case req.Actor == "":
		return Decision{}, fmt.Errorf("%w: an admission must name the actor consuming capacity", ErrRefused)
	}

	now := req.Now
	if now.IsZero() {
		now = g.now()
	}

	// A request no profile can satisfy is refused before anything is reserved.
	if err := quota.CheckDemand(req.Demanded, g.maxima); err != nil {
		return Decision{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}

	// The TTL is clamped rather than refused: a caller asking for too long gets the
	// most the policy allows, which is the point. It does not get the extra time.
	ttl, err := quota.TTLBounds(req.RequestedTTL, g.maxima)
	if err != nil {
		return Decision{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	clamped := req.RequestedTTL > ttl

	res, err := g.ledger.Reserve(ctx, quota.Request{
		EnvironmentID: req.EnvironmentID,
		Actor:         req.Actor,
		Repository:    req.Repository,
		Profile:       req.Profile,
		Demanded:      req.Demanded,
		Now:           now,
	}, quota.Scopes(quota.Request{Repository: req.Repository, Actor: req.Actor, Profile: req.Profile}))
	if err != nil {
		// An exhausted ledger is a refusal, not a fault. It is wrapped so a caller
		// can distinguish "no capacity" from "the ledger is broken" and present them
		// differently.
		if errors.Is(err, quota.ErrExhausted) {
			return Decision{}, fmt.Errorf("%w: %w", ErrRefused, err)
		}
		return Decision{}, fmt.Errorf("reserve capacity: %w", err)
	}

	return Decision{
		ReservationID: res.ID,
		GrantedTTL:    ttl,
		ExpiresAt:     now.Add(ttl),
		Clamped:       clamped,
		Scopes:        res.ScopeRefs,
	}, nil
}

// Release returns an admitted environment's capacity.
//
// It is called on teardown, not on expiry alone: capacity is held for as long as the
// environment occupies it, and the watchdog releases it once the environment is
// actually marked absent.
func (g *Gate) Release(ctx context.Context, reservationID string) error {
	if reservationID == "" {
		// Nothing was held, so there is nothing to return. Failing here would turn a
		// cleanup path into a permanent error for a state that is already correct.
		return nil
	}
	if err := g.ledger.Release(ctx, reservationID); err != nil {
		return fmt.Errorf("release capacity %s: %w", reservationID, err)
	}
	return nil
}

// Extend authorizes an extension and records it.
//
// The three requirements from SPEC.md are all enforced here rather than split across
// callers: an authorized actor, remaining fleet/cost allowance, and an audit record.
// Each is a distinct failure with a distinct fix, so collapsing them into "not allowed"
// makes each take longer to diagnose.
func (g *Gate) Extend(ctx context.Context, e quota.Extension, audited []quota.AuditEntry) (quota.ExtensionDecision, error) {
	if e.EnvironmentID == "" {
		return quota.ExtensionDecision{}, fmt.Errorf("%w: an extension must name the environment", ErrRefused)
	}
	// The environment's own reservation is the scope that must still have room: an
	// extension keeps the environment occupying capacity for longer.
	fleet := quota.ScopeRef{Scope: quota.ScopeFleet, Ref: "global"}
	now := e.Now
	if now.IsZero() {
		now = g.now()
	}
	remaining, err := g.ledger.Remaining(ctx, fleet, now)
	if err != nil {
		return quota.ExtensionDecision{}, fmt.Errorf("read remaining capacity: %w", err)
	}

	gg := quota.NewGate(g.maxima, true, g.now)
	dec, err := gg.EvaluateExtension(e, audited, remaining)
	if err != nil {
		return quota.ExtensionDecision{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return dec, nil
}

// AuthorizeDestroy checks that a destroy is permitted.
//
// Destroy is privileged in the same way extension is: it ends a preview early and
// returns money, so it needs an identified actor and a stated reason.
func (g *Gate) AuthorizeDestroy(_ context.Context, environmentID, actor, reason string) error {
	switch {
	case environmentID == "":
		return fmt.Errorf("%w: a destroy must name the environment", ErrRefused)
	case actor == "":
		return fmt.Errorf("%w: a destroy requires an identified actor", ErrRefused)
	case reason == "":
		// An unexplained destroy discards a customer's preview and gives them nothing
		// to appeal with.
		return fmt.Errorf("%w: a destroy requires a reason", ErrRefused)
	}
	return nil
}
