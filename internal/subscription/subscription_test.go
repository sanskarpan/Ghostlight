package subscription

import (
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/entitlements"
)

var start = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func plan(t *testing.T, id entitlements.PlanID) entitlements.Plan {
	t.Helper()
	p, err := entitlements.Lookup(id)
	if err != nil {
		t.Fatalf("plan %s: %v", id, err)
	}
	return p
}

func mustErr(t *testing.T, err error, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

func newTrial(t *testing.T) Subscription {
	t.Helper()
	s, err := New("sub_1", "cus_1", plan(t, entitlements.PlanTeam), start, 14)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return s
}

func newPaid(t *testing.T) Subscription {
	t.Helper()
	s, err := New("sub_1", "cus_1", plan(t, entitlements.PlanTeam), start, 0)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return s
}

// The load-bearing invariant of the package. A cancelled or frozen customer who
// cannot delete their own previews is the worst outcome this system can produce.
func TestDestroyAndCleanupAreAvailableInEveryPhase(t *testing.T) {
	s := newPaid(t)

	before := s.Access(start)
	if !before.Abort || !before.Cleanup || !before.Admit {
		t.Fatalf("a healthy subscription cannot admit, abort or clean up: %+v", before)
	}

	if _, err := s.RecordPaymentFailure(start.AddDate(0, 0, 3), 0); err != nil {
		t.Fatalf("failure: %v", err)
	}
	failing := s.Access(start.AddDate(0, 0, 3))
	if !failing.Admit {
		t.Fatal("grace must keep the service alive; that is what grace is for")
	}

	frozen := s.Access(start.AddDate(0, 0, 11))
	if frozen.Phase != PhaseFrozen {
		t.Fatalf("expected frozen after grace expired, got %s", frozen.Phase)
	}
	if frozen.Admit {
		t.Fatal("a frozen subscription must not admit new work")
	}

	if err := s.RecordCancellation(start.AddDate(0, 0, 12)); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	cancelled := s.Access(start.AddDate(0, 0, 13))
	if cancelled.Phase != PhaseCancelled {
		t.Fatalf("expected cancelled, got %s", cancelled.Phase)
	}
	if cancelled.Admit {
		t.Fatal("a cancelled subscription must not admit new work")
	}

	for name, a := range map[string]Access{"frozen": frozen, "cancelled": cancelled, "grace": failing} {
		if !a.Abort || !a.Cleanup || !a.Read {
			t.Fatalf("%s phase refuses to destroy or show the customer's own work: %+v", name, a)
		}
		if a.Reason == "" {
			t.Fatalf("%s phase refuses without explaining why: %+v", name, a)
		}
	}
}

func TestATrialFreezesRatherThanExpiringQuietly(t *testing.T) {
	s := newTrial(t)
	if got := s.Phase(start.AddDate(0, 0, 5)); got != PhaseTrialing {
		t.Fatalf("day 5 phase %s, want trialing", got)
	}
	if got := s.Phase(start.AddDate(0, 0, 15)); got != PhaseFrozen {
		t.Fatalf("day 15 phase %s, want frozen", got)
	}
	a := s.Access(start.AddDate(0, 0, 15))
	if a.Admit || !a.Abort {
		t.Fatalf("an expired trial must stop admitting but still allow cleanup: %+v", a)
	}
}

// A late conversion must not resurrect work that was already refused. The customer may
// convert, but the freeze stands until they do.
func TestALateConversionDoesNotResurrectAnExpiredTrial(t *testing.T) {
	s := newTrial(t)
	if err := s.RecordConversion(start.AddDate(0, 0, 20), plan(t, entitlements.PlanTeam)); err != nil {
		t.Fatalf("convert: %v", err)
	}
	if got := s.Phase(start.AddDate(0, 0, 15)); got != PhaseFrozen {
		t.Fatalf("phase after a late conversion is %s, want frozen", got)
	}
	if got := s.Phase(start.AddDate(0, 0, 21)); got != PhaseActive {
		t.Fatalf("phase once converted is %s, want active", got)
	}
}

func TestConversionBeforeTrialEndIsActiveImmediately(t *testing.T) {
	s := newTrial(t)
	if err := s.RecordConversion(start.AddDate(0, 0, 10), plan(t, entitlements.PlanGrowth)); err != nil {
		t.Fatalf("convert: %v", err)
	}
	if got := s.Phase(start.AddDate(0, 0, 10)); got != PhaseActive {
		t.Fatalf("phase %s, want active", got)
	}
	if s.Plan.ID != entitlements.PlanGrowth {
		t.Fatalf("conversion moved to %s, want growth", s.Plan.ID)
	}
}

func TestConversionCannotBeRecordedTwice(t *testing.T) {
	s := newTrial(t)
	if err := s.RecordConversion(start.AddDate(0, 0, 10), plan(t, entitlements.PlanTeam)); err != nil {
		t.Fatalf("convert: %v", err)
	}
	mustErr(t, s.RecordConversion(start.AddDate(0, 0, 11), plan(t, entitlements.PlanTeam)), ErrInvalidFact, "second conversion")
}

func TestGraceIsBoundedAndCannotBeBoughtLonger(t *testing.T) {
	s := newPaid(t)
	// A customer-chosen window inside the maximum is honoured.
	end, err := s.RecordPaymentFailure(start.AddDate(0, 0, 3), 5*24*time.Hour)
	if err != nil {
		t.Fatalf("failure: %v", err)
	}
	if got := end.Sub(start.AddDate(0, 0, 3)); got != 5*24*time.Hour {
		t.Fatalf("grace ends in %s", got)
	}
	// A customer should not be able to buy a longer grace period.
	s2 := newPaid(t)
	_, err = s2.RecordPaymentFailure(start.AddDate(0, 0, 3), 30*24*time.Hour)
	mustErr(t, err, ErrInvalidFact, "grace beyond the maximum")

	// The default is the maximum, not zero: nobody fails a payment and is cut off
	// in the same second.
	s3 := newPaid(t)
	def, err := s3.RecordPaymentFailure(start.AddDate(0, 0, 3), 0)
	if err != nil {
		t.Fatalf("default grace: %v", err)
	}
	if got := def.Sub(start.AddDate(0, 0, 3)); got != GraceDays*24*time.Hour {
		t.Fatalf("default grace is %s, want %d days", got, GraceDays)
	}
}

// Without clamping, a failed card on the last day of grace could keep a full fleet
// running for the maximum lifetime — exactly the unpaid usage grace exists to bound.
func TestGraceClampsTheLifetimeToWhatIsLeftOfIt(t *testing.T) {
	s := newPaid(t)
	if _, err := s.RecordPaymentFailure(start.AddDate(0, 0, 3), 7*24*time.Hour); err != nil {
		t.Fatalf("failure: %v", err)
	}
	day3 := start.AddDate(0, 0, 3)
	if got := s.MaxTTL(day3); got != 24*time.Hour {
		t.Fatalf("with six days of grace left the lifetime is %s, want the plan's 24h", got)
	}
	day9 := start.AddDate(0, 0, 9)
	if got := s.MaxTTL(day9); got != 24*time.Hour {
		t.Fatalf("on day 9 of a grace ending day 10 the lifetime is %s, want 24h", got)
	}
	// The last hour of grace is clamped rather than refused: abort stays available.
	lastHour := s.GraceEndsAt.Add(-time.Hour)
	if got := s.MaxTTL(lastHour); got != time.Hour {
		t.Fatalf("in the final hour of grace the lifetime is %s, want 1h", got)
	}
}

func TestAnActiveSubscriptionKeepsThePlanLifetime(t *testing.T) {
	s := newPaid(t)
	if got := s.MaxTTL(start); got != 24*time.Hour {
		t.Fatalf("an active subscription allows %s, want the plan's 24h", got)
	}
}

func TestPaymentRestorationIsAFactNotAJudgement(t *testing.T) {
	s := newPaid(t)
	if _, err := s.RecordPaymentFailure(start.AddDate(0, 0, 3), 0); err != nil {
		t.Fatalf("failure: %v", err)
	}
	if err := s.RecordPaymentRestored(start.AddDate(0, 0, 4)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := s.Phase(start.AddDate(0, 0, 4)); got != PhaseActive {
		t.Fatalf("phase %s after a working card, want active", got)
	}
}

func TestPaymentRestorationBeforeTheFailureIsRefused(t *testing.T) {
	s := newPaid(t)
	if _, err := s.RecordPaymentFailure(start.AddDate(0, 0, 3), 0); err != nil {
		t.Fatalf("failure: %v", err)
	}
	mustErr(t, s.RecordPaymentRestored(start.AddDate(0, 0, 2)), ErrInvalidFact, "restoration before failure")
}

func TestRestoringWhenNothingFailedIsRefused(t *testing.T) {
	s := newPaid(t)
	mustErr(t, s.RecordPaymentRestored(start), ErrInvalidFact, "restoration with no failure")
}

// A customer who has already paid for the month keeps what they paid for.
func TestCancellationAtPeriodEndKeepsThePeriod(t *testing.T) {
	s := newPaid(t)
	s.PeriodEnd = start.AddDate(0, 1, 1)
	if err := s.RequestCancelAtPeriodEnd(start.AddDate(0, 0, 20)); err != nil {
		t.Fatalf("request: %v", err)
	}
	if got := s.Phase(start.AddDate(0, 0, 25)); got != PhaseActive {
		t.Fatalf("phase %s before the period ends, want active", got)
	}
	if got := s.Phase(start.AddDate(0, 1, 1)); got != PhaseCancelled {
		t.Fatalf("phase %s at the period end, want cancelled", got)
	}
	a := s.Access(start.AddDate(0, 1, 2))
	if a.Admit || !a.Abort || !a.Cleanup {
		t.Fatalf("after the period ended: %+v", a)
	}
}

func TestImmediateCancellationEndsAdmissionsAtOnce(t *testing.T) {
	s := newPaid(t)
	if err := s.RecordCancellation(start.AddDate(0, 0, 10)); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if got := s.Phase(start.AddDate(0, 0, 9)); got != PhaseActive {
		t.Fatalf("phase %s before cancellation, want active", got)
	}
	if got := s.Phase(start.AddDate(0, 0, 10)); got != PhaseCancelled {
		t.Fatalf("phase %s at cancellation, want cancelled", got)
	}
}

func TestCancellationCannotBeRecordedTwice(t *testing.T) {
	s := newPaid(t)
	if err := s.RecordCancellation(start.AddDate(0, 0, 10)); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	mustErr(t, s.RecordCancellation(start.AddDate(0, 0, 11)), ErrAlreadyCancelled, "second cancellation")
}

func TestCancellationBeforeTheStartIsRefused(t *testing.T) {
	s := newPaid(t)
	mustErr(t, s.RecordCancellation(start.AddDate(0, 0, -1)), ErrInvalidFact, "cancellation before start")
}

// A downgrade that cannot host running previews is refused, not applied and regretted.
func TestADowngradeThatWouldStrandWorkIsRefused(t *testing.T) {
	s := newPaid(t)
	if _, err := s.RequestPlanChange(plan(t, entitlements.PlanTrial), 12, start); err == nil {
		t.Fatal("moving twelve running previews onto a two slot trial must be refused")
	} else {
		mustErr(t, err, entitlements.ErrDowngradeStrandsWork, "stranding downgrade")
	}
}

func TestADowngradeNeedsAcknowledgementWhenItShortensTheLifetime(t *testing.T) {
	s := newPaid(t)
	if err := s.RecordConversion(start.AddDate(0, 0, 5), plan(t, entitlements.PlanEnterprise)); err != nil {
		t.Fatalf("convert: %v", err)
	}
	s.Plan = plan(t, entitlements.PlanEnterprise)

	change, err := s.RequestPlanChange(plan(t, entitlements.PlanTeam), 1, start.AddDate(0, 0, 6))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if !change.AcknowledgementRequired {
		t.Fatal("72h to 24h must require an explicit confirmation")
	}
	if len(change.Notes) == 0 {
		t.Fatal("the customer must be told what happens to running environments")
	}

	// Rolling the period without acknowledging must refuse to apply the change.
	periodEnd := s.PeriodEnd.Add(24 * time.Hour)
	_, err = s.RollPeriod(periodEnd)
	if !errors.Is(err, ErrAcknowledgementRequired) {
		t.Fatalf("unacknowledged downgrade: got %v", err)
	}

	if err := s.AcknowledgePlanChange(start.AddDate(0, 0, 7)); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if _, err := s.RollPeriod(periodEnd); err != nil {
		t.Fatalf("acknowledged downgrade should apply: %v", err)
	}
	if s.Plan.ID != entitlements.PlanTeam {
		t.Fatalf("plan is %s after an acknowledged downgrade, want team", s.Plan.ID)
	}
}

func TestAcknowledgementMustFollowTheRequestItConfirms(t *testing.T) {
	s := newPaid(t)
	if err := s.RecordConversion(start.AddDate(0, 0, 5), plan(t, entitlements.PlanEnterprise)); err != nil {
		t.Fatalf("convert: %v", err)
	}
	s.Plan = plan(t, entitlements.PlanEnterprise)

	requested := start.AddDate(0, 0, 6)
	if _, err := s.RequestPlanChange(plan(t, entitlements.PlanTeam), 1, requested); err != nil {
		t.Fatalf("request: %v", err)
	}
	// Consent to an earlier decision is not consent to this one.
	mustErr(t, s.AcknowledgePlanChange(requested.Add(-24*time.Hour)), ErrInvalidFact, "premature acknowledgement")

	if err := s.AcknowledgePlanChange(requested.Add(time.Hour)); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
}

func TestANewRequestInvalidatesAnEarlierAcknowledgement(t *testing.T) {
	s := newPaid(t)
	if err := s.RecordConversion(start.AddDate(0, 0, 5), plan(t, entitlements.PlanEnterprise)); err != nil {
		t.Fatalf("convert: %v", err)
	}
	s.Plan = plan(t, entitlements.PlanEnterprise)

	if _, err := s.RequestPlanChange(plan(t, entitlements.PlanTeam), 1, start.AddDate(0, 0, 6)); err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := s.AcknowledgePlanChange(start.AddDate(0, 0, 7)); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	// Asking for something different again must not inherit the old consent.
	if _, err := s.RequestPlanChange(plan(t, entitlements.PlanGrowth), 1, start.AddDate(0, 0, 8)); err != nil {
		t.Fatalf("second request: %v", err)
	}
	_, err := s.RollPeriod(s.PeriodEnd.Add(time.Hour))
	mustErr(t, err, ErrAcknowledgementRequired, "change inherited from a superseded request")
}

func TestAChangeThatDoesNotStrandAnythingNeedsNoAcknowledgement(t *testing.T) {
	s := newPaid(t)
	change, err := s.RequestPlanChange(plan(t, entitlements.PlanGrowth), 1, start)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if change.AcknowledgementRequired {
		t.Fatal("widening a plan strands nothing")
	}
	if _, err := s.RollPeriod(s.PeriodEnd.Add(time.Hour)); err != nil {
		t.Fatalf("roll: %v", err)
	}
	if s.Plan.ID != entitlements.PlanGrowth {
		t.Fatalf("plan is %s, want growth", s.Plan.ID)
	}
}

// A period already being invoiced cannot be rewritten by a change made after the fact.
func TestAClosedPeriodKeepsTheSnapshotItWasBilledUnder(t *testing.T) {
	s := newPaid(t)
	before, err := s.PeriodSnapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if before.PlanID != entitlements.PlanTeam || before.RuleVersion != RuleVersion {
		t.Fatalf("snapshot %+v", before)
	}
	if _, err := s.RequestPlanChange(plan(t, entitlements.PlanGrowth), 0, start); err != nil {
		t.Fatalf("request: %v", err)
	}
	closed, err := s.RollPeriod(s.PeriodEnd.Add(time.Hour))
	if err != nil {
		t.Fatalf("roll: %v", err)
	}
	if closed.PlanID != entitlements.PlanTeam {
		t.Fatalf("the closed period was rebilled as %s, want team", closed.PlanID)
	}
	now, err := s.PeriodSnapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if now.PlanID != entitlements.PlanGrowth {
		t.Fatalf("the open period is %s, want growth", now.PlanID)
	}
	if now.OpenedAt.Equal(before.OpenedAt) {
		t.Fatal("the new period kept the old opening time")
	}
}

func TestRollingBackwardsInTimeIsRefused(t *testing.T) {
	s := newPaid(t)
	_, err := s.RollPeriod(start.Add(-time.Hour))
	mustErr(t, err, ErrInvalidFact, "rolling before the period end")
}

func TestRequestingThePlanYouAlreadyHaveIsRefused(t *testing.T) {
	s := newPaid(t)
	_, err := s.RequestPlanChange(plan(t, entitlements.PlanTeam), 0, start)
	mustErr(t, err, ErrInvalidFact, "no-op change")
}

func TestChangingPlanAfterCancellationIsRefused(t *testing.T) {
	s := newPaid(t)
	if err := s.RecordCancellation(start.AddDate(0, 0, 10)); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	_, err := s.RequestPlanChange(plan(t, entitlements.PlanGrowth), 0, start.AddDate(0, 0, 11))
	mustErr(t, err, ErrAlreadyCancelled, "plan change after cancellation")
}

func TestAnInconsistentPlanCannotBeSubscribedTo(t *testing.T) {
	broken := entitlements.Plan{ID: "broken", ConcurrencySlots: 0, MaxTTLDuration: time.Hour}
	_, err := New("sub_1", "cus_1", broken, start, 0)
	mustErr(t, err, entitlements.ErrPlanInconsistent, "plan with no slots")
}

func TestASubscriptionWithNoStartTimeIsRefused(t *testing.T) {
	_, err := New("sub_1", "cus_1", plan(t, entitlements.PlanTeam), time.Time{}, 0)
	mustErr(t, err, ErrInvalidFact, "no start time")
}

func TestAnUnknownSnapshotIsRefused(t *testing.T) {
	var s Subscription
	_, err := s.PeriodSnapshot()
	mustErr(t, err, ErrUnknownSnapshot, "empty subscription")
}

// Entitlement and lifecycle compose: the subscription decides whether work may start
// at all, and the plan decides whether there is room and whether it may be paid for.
func TestAccessComposesWithThePlan(t *testing.T) {
	s := newPaid(t)
	if _, err := s.RecordPaymentFailure(start.AddDate(0, 0, 3), 0); err != nil {
		t.Fatalf("failure: %v", err)
	}
	now := start.AddDate(0, 0, 11)
	a := s.Access(now)
	if a.Phase != PhaseFrozen {
		t.Fatalf("phase %s after the 7 day grace expired, want frozen", a.Phase)
	}
	// Even with a frozen subscription the plan still answers capacity questions, so
	// a caller cannot mistake "frozen" for "unlimited".
	if _, err := s.Plan.Admit(entitlements.Usage{RunningEnvironments: 99}); err == nil {
		t.Fatal("the plan must still refuse beyond its licensed slots")
	}
}
