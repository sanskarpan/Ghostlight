// Package subscription holds the lifecycle state machine behind a paid plan: trial,
// active, grace, frozen and cancelled.
//
// ADR G-037, G7.3. Where entitlements decides what a plan may do, this decides what a
// subscription may do right now, given the facts recorded about it.
//
// The design has one asymmetry, and it is the whole point of the package. Admitting
// work depends on payment state. Destroying work never does. A cancelled subscription
// cannot start a preview and can always destroy one, because a customer who cannot
// delete the environments they are being billed for is the worst outcome this system
// can produce, and a "payment required" wall in front of a teardown button is how
// resources leak into a bill nobody owns.
//
// Phase is a pure function of recorded facts and time, not a mutable field advanced by
// transitions. Deriving it means a subscription cannot enter an impossible state
// through a missed or reordered event, and every rule below is a table test rather
// than a sequence test.
package subscription

import (
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/entitlements"
)

// Phase is where a subscription stands.
type Phase string

const (
	// PhaseTrialing is a bounded evaluation that has not converted.
	PhaseTrialing Phase = "trialing"
	// PhaseActive is a paid subscription in good standing.
	PhaseActive Phase = "active"
	// PhaseGrace follows a payment failure. Service continues for a bounded window
	// so a card expiring mid-month does not kill a customer's review in progress.
	PhaseGrace Phase = "grace"
	// PhaseFrozen stops new admissions. Existing environments finish on their
	// existing schedule and can always be destroyed.
	PhaseFrozen Phase = "frozen"
	// PhaseCancelled is ended. Nothing new may start; everything can be destroyed.
	PhaseCancelled Phase = "cancelled"
)

// GraceDays is how long a payment failure leaves a subscription usable. It is a
// constant rather than a plan field because a customer should not be able to buy a
// longer grace period, and a plan field would let them.
const GraceDays = 7

// RuleVersion identifies the entitlement rules a period was billed under. Usage must
// be metered under the rules in effect when it occurred; applying today's rules to a
// closed period produces an invoice nobody can defend.
const RuleVersion = "g037-v1"

// Errors returned by this package.
var (
	// ErrInvalidFact means recorded timestamps contradict each other.
	ErrInvalidFact = errors.New("subscription facts are inconsistent")
	// ErrNotConverted means a trial has not been converted.
	ErrNotConverted = errors.New("trial has not been converted")
	// ErrAlreadyCancelled means the subscription is already ended.
	ErrAlreadyCancelled = errors.New("subscription is already cancelled")
	// ErrAcknowledgementRequired means a plan change needs explicit confirmation
	// before it can be applied.
	ErrAcknowledgementRequired = errors.New("plan change requires acknowledgement")
	// ErrUnknownSnapshot means no period has been opened.
	ErrUnknownSnapshot = errors.New("no open billing period")
)

// Subscription is the recorded lifecycle of one paid subscription.
type Subscription struct {
	ID         string
	CustomerID string

	// Plan is the entitlement set in force. It changes only at a period boundary.
	Plan entitlements.Plan
	// PendingPlan is a requested change that takes effect at the next boundary.
	PendingPlan *entitlements.Plan
	// PendingRequestedAt is when that change was requested. An acknowledgement dated
	// before the request belongs to some earlier decision and is not consent to this
	// one.
	PendingRequestedAt time.Time
	// DowngradeAcknowledgedAt records the confirmation for a change that would
	// otherwise strand running environments.
	DowngradeAcknowledgedAt *time.Time

	StartedAt         time.Time
	TrialEndsAt       time.Time
	ConvertedAt       time.Time
	PaymentFailedAt   time.Time
	GraceEndsAt       time.Time
	CancelledAt       time.Time
	CancelAtPeriodEnd bool

	// PeriodStart and PeriodEnd bound the current billing period.
	PeriodStart time.Time
	PeriodEnd   time.Time

	// Snapshot is the entitlement set and rule version the current period is billed
	// under, captured when the period opened.
	Snapshot PeriodSnapshot

	// OverageOptIn is the customer's consent to be billed past the included
	// allowance. Without it, overage is refused rather than charged.
	OverageOptIn bool
}

// PeriodSnapshot is what a period was billed under. It is captured, not recomputed,
// so a later plan change or rule change cannot rewrite a period that is already
// being invoiced.
type PeriodSnapshot struct {
	PlanID      entitlements.PlanID
	RuleVersion string
	OpenedAt    time.Time
}

// New returns a subscription starting on a plan, with an optional trial.
func New(id, customerID string, plan entitlements.Plan, startedAt time.Time, trialDays int) (Subscription, error) {
	if err := plan.Validate(); err != nil {
		return Subscription{}, err
	}
	if startedAt.IsZero() {
		return Subscription{}, fmt.Errorf("%w: no start time", ErrInvalidFact)
	}
	s := Subscription{
		ID: id, CustomerID: customerID, Plan: plan,
		StartedAt: startedAt.UTC(),
	}
	if trialDays > 0 {
		s.TrialEndsAt = startedAt.AddDate(0, 0, trialDays).UTC()
		s.PeriodEnd = s.TrialEndsAt
	} else {
		// A paid subscription still has a period boundary, or plan changes could
		// never take effect and no period could ever be closed and invoiced.
		s.PeriodEnd = startedAt.AddDate(0, 1, 0).UTC()
	}
	s.openPeriod(startedAt)
	return s, nil
}

// openPeriod captures the entitlement snapshot a period is billed under.
func (s *Subscription) openPeriod(at time.Time) {
	s.PeriodStart = at.UTC()
	s.Snapshot = PeriodSnapshot{
		PlanID:      s.Plan.ID,
		RuleVersion: RuleVersion,
		OpenedAt:    at.UTC(),
	}
}

// Phase derives where the subscription stands from recorded facts and time.
func (s Subscription) Phase(now time.Time) Phase {
	now = now.UTC()
	if !s.CancelledAt.IsZero() && !now.Before(s.CancelledAt) {
		return PhaseCancelled
	}
	if !s.PaymentFailedAt.IsZero() {
		if !s.GraceEndsAt.IsZero() && !now.Before(s.GraceEndsAt) {
			return PhaseFrozen
		}
		return PhaseGrace
	}
	// A conversion is a recorded fact, but it is not effective until it happens: a
	// trial converted after it expired was frozen the whole time it looked converted,
	// and pretending otherwise would admit work the customer never paid for.
	if !s.ConvertedAt.IsZero() && !now.Before(s.ConvertedAt) {
		return PhaseActive
	}
	// A trial that ended without converting freezes. It does not become active
	// quietly, and a late conversion does not resurrect work that was already
	// refused: the customer may convert, but the freeze stands until they do.
	if !s.TrialEndsAt.IsZero() && !now.Before(s.TrialEndsAt) {
		return PhaseFrozen
	}
	if !s.TrialEndsAt.IsZero() {
		return PhaseTrialing
	}
	return PhaseActive
}

// Access is what the customer may do right now.
type Access struct {
	// Admit reports whether new work may start.
	Admit bool
	// Read reports whether the console and previews are viewable.
	Read bool
	// Abort and Cleanup are unconditional. They are true in every phase,
	// including cancellation, and a future change that made them conditional would
	// strand the customer's own resources.
	Abort   bool
	Cleanup bool
	// Trial reports whether the subscription is still an evaluation.
	Trial bool
	// Phase is the phase access was derived from.
	Phase Phase
	// Reason explains a refusal in words a customer can be shown.
	Reason string
}

// Access derives permissions from the current phase.
func (s Subscription) Access(now time.Time) Access {
	p := s.Phase(now)
	a := Access{Read: true, Abort: true, Cleanup: true, Phase: p, Trial: p == PhaseTrialing}
	switch p {
	case PhaseActive, PhaseTrialing, PhaseGrace:
		a.Admit = true
	case PhaseFrozen:
		a.Reason = "this subscription is frozen; destroy and cleanup remain available"
	case PhaseCancelled:
		a.Reason = "this subscription has ended; destroy and cleanup remain available"
	}
	if p == PhaseGrace && !s.GraceEndsAt.IsZero() {
		// Grace admits, but the customer is owed a warning with a date on it: a
		// warning nobody can act on is not a warning.
		a.Reason = fmt.Sprintf("payment failed; access continues until %s",
			s.GraceEndsAt.Format("2 January 2006"))
	}
	return a
}

// MaxTTL is the longest an environment started now may live.
//
// In grace the remaining lifetime is clamped to the end of the grace window. Without
// that clamp a customer whose card failed could keep a fleet running for the maximum
// lifetime on the last day of a seven day grace period, which is precisely the unpaid
// usage the grace period exists to bound.
func (s Subscription) MaxTTL(now time.Time) time.Duration {
	ttl := s.Plan.MaxTTLDuration
	if s.Phase(now) == PhaseGrace && !s.GraceEndsAt.IsZero() {
		if remaining := s.GraceEndsAt.Sub(now.UTC()); remaining < ttl {
			return remaining
		}
	}
	return ttl
}

// RecordConversion marks a trial as converted to a paid plan.
func (s *Subscription) RecordConversion(at time.Time, plan entitlements.Plan) error {
	if !s.TrialEndsAt.IsZero() {
		if at.IsZero() {
			return fmt.Errorf("%w: no conversion time", ErrInvalidFact)
		}
		if at.Before(s.StartedAt) {
			return fmt.Errorf("%w: conversion %s precedes the start %s", ErrInvalidFact, at, s.StartedAt)
		}
		if err := plan.Validate(); err != nil {
			return err
		}
	}
	if !s.ConvertedAt.IsZero() {
		return fmt.Errorf("%w: already converted", ErrInvalidFact)
	}
	s.ConvertedAt = at.UTC()
	if err := plan.Validate(); err == nil {
		s.Plan = plan
	}
	return nil
}

// RecordPaymentFailure starts the grace window and returns the end of it.
func (s *Subscription) RecordPaymentFailure(at time.Time, grace time.Duration) (time.Time, error) {
	if at.IsZero() {
		return time.Time{}, fmt.Errorf("%w: no failure time", ErrInvalidFact)
	}
	if at.Before(s.StartedAt) {
		return time.Time{}, fmt.Errorf("%w: failure %s precedes the start %s", ErrInvalidFact, at, s.StartedAt)
	}
	if grace <= 0 {
		grace = GraceDays * 24 * time.Hour
	}
	if grace > GraceDays*24*time.Hour {
		return time.Time{}, fmt.Errorf("%w: a grace window of %s exceeds the %d day maximum",
			ErrInvalidFact, grace, GraceDays)
	}
	s.PaymentFailedAt = at.UTC()
	s.GraceEndsAt = at.Add(grace).UTC()
	return s.GraceEndsAt, nil
}

// RecordPaymentRestored clears a payment failure. Restoration is a fact about money,
// not a judgement: a customer whose card works is active again.
func (s *Subscription) RecordPaymentRestored(at time.Time) error {
	if s.PaymentFailedAt.IsZero() {
		return fmt.Errorf("%w: no recorded payment failure", ErrInvalidFact)
	}
	if at.Before(s.PaymentFailedAt) {
		return fmt.Errorf("%w: restoration %s precedes the failure %s", ErrInvalidFact, at, s.PaymentFailedAt)
	}
	s.PaymentFailedAt = time.Time{}
	s.GraceEndsAt = time.Time{}
	return nil
}

// RecordCancellation ends the subscription at a time.
func (s *Subscription) RecordCancellation(at time.Time) error {
	if !s.CancelledAt.IsZero() {
		return ErrAlreadyCancelled
	}
	if at.IsZero() {
		return fmt.Errorf("%w: no cancellation time", ErrInvalidFact)
	}
	if at.Before(s.StartedAt) {
		return fmt.Errorf("%w: cancellation %s precedes the start %s", ErrInvalidFact, at, s.StartedAt)
	}
	s.CancelledAt = at.UTC()
	s.CancelAtPeriodEnd = false
	return nil
}

// RequestCancelAtPeriodEnd schedules cancellation for the end of the current period,
// so a customer who has already paid for the month keeps what they paid for.
func (s *Subscription) RequestCancelAtPeriodEnd(at time.Time) error {
	if !s.CancelledAt.IsZero() {
		return ErrAlreadyCancelled
	}
	if s.PeriodEnd.IsZero() {
		return fmt.Errorf("%w: no period end recorded", ErrInvalidFact)
	}
	if at.Before(s.StartedAt) {
		return fmt.Errorf("%w: request %s precedes the start %s", ErrInvalidFact, at, s.StartedAt)
	}
	s.CancelAtPeriodEnd = true
	s.CancelledAt = s.PeriodEnd.UTC()
	return nil
}

// PlanChange is a requested move to another plan.
type PlanChange struct {
	// From and To are the plans involved.
	From entitlements.Plan
	To   entitlements.Plan
	// AcknowledgementRequired reports that running environments outlive the target's
	// rules and a customer must confirm before the change is applied.
	AcknowledgementRequired bool
	// Notes explain the change to the customer.
	Notes []string
}

// RequestPlanChange records a move to another plan, effective at the next period
// boundary. It refuses a change that cannot be confirmed rather than applying it and
// hoping nobody is using previews.
func (s *Subscription) RequestPlanChange(to entitlements.Plan, running int, at time.Time) (PlanChange, error) {
	if err := to.Validate(); err != nil {
		return PlanChange{}, err
	}
	if to.ID == s.Plan.ID {
		return PlanChange{}, fmt.Errorf("%w: already on %s", ErrInvalidFact, to.ID)
	}
	if !s.CancelledAt.IsZero() && !at.UTC().Before(s.CancelledAt) {
		return PlanChange{}, ErrAlreadyCancelled
	}
	m, err := s.Plan.Downgrade(to, entitlements.Usage{RunningEnvironments: running})
	if err != nil {
		return PlanChange{}, err
	}
	change := PlanChange{From: s.Plan, To: to, Notes: m.Notes, AcknowledgementRequired: m.AcknowledgementRequired}
	s.PendingPlan = &to
	s.PendingRequestedAt = at.UTC()
	// A new request invalidates any earlier acknowledgement: consent to move from
	// Team to Growth is not consent to move from Enterprise to Growth.
	s.DowngradeAcknowledgedAt = nil
	return change, nil
}

// AcknowledgePlanChange confirms a change that needs it. Without this the change
// cannot be applied.
func (s *Subscription) AcknowledgePlanChange(at time.Time) error {
	if s.PendingPlan == nil {
		return fmt.Errorf("%w: no change requested", ErrInvalidFact)
	}
	if at.IsZero() {
		return fmt.Errorf("%w: no acknowledgement time", ErrInvalidFact)
	}
	t := at.UTC()
	if t.Before(s.PendingRequestedAt) {
		return fmt.Errorf("%w: acknowledged %s, before the change was requested %s",
			ErrInvalidFact, t, s.PendingRequestedAt)
	}
	s.DowngradeAcknowledgedAt = &t
	return nil
}

// RollPeriod opens the next billing period, applying a pending plan change only when
// the change was acknowledged if it needed to be, and capturing a fresh entitlement
// snapshot. The closed period's snapshot is untouched: a period already being invoiced
// cannot be rewritten by a change made after the fact.
func (s *Subscription) RollPeriod(at time.Time) (PeriodSnapshot, error) {
	if s.PeriodEnd.IsZero() {
		return PeriodSnapshot{}, ErrUnknownSnapshot
	}
	if at.Before(s.PeriodEnd) {
		return PeriodSnapshot{}, fmt.Errorf("%w: %s is before the period ends %s", ErrInvalidFact, at, s.PeriodEnd)
	}
	if s.PendingPlan != nil {
		// A change that shortens the maximum lifetime affects environments already
		// running, so it needs consent recorded after the request and before the
		// change is applied.
		needsConsent := s.PendingPlan.MaxTTLDuration < s.Plan.MaxTTLDuration
		if needsConsent {
			ack := s.DowngradeAcknowledgedAt
			if ack == nil {
				return PeriodSnapshot{}, fmt.Errorf("%w: %s shortens the maximum lifetime from %s to %s",
					ErrAcknowledgementRequired, s.PendingPlan.ID, s.Plan.MaxTTLDuration, s.PendingPlan.MaxTTLDuration)
			}
			if ack.After(at.UTC()) {
				return PeriodSnapshot{}, fmt.Errorf("%w: acknowledged %s, after the change applies %s",
					ErrAcknowledgementRequired, ack, at.UTC())
			}
		}
		s.Plan = *s.PendingPlan
		s.PendingPlan = nil
		s.PendingRequestedAt = time.Time{}
		s.DowngradeAcknowledgedAt = nil
	}
	closed := s.Snapshot
	s.openPeriod(at.UTC())
	return closed, nil
}

// PeriodSnapshot returns the entitlement snapshot the open period is billed under.
func (s Subscription) PeriodSnapshot() (PeriodSnapshot, error) {
	if s.Snapshot.OpenedAt.IsZero() {
		return PeriodSnapshot{}, ErrUnknownSnapshot
	}
	return s.Snapshot, nil
}
