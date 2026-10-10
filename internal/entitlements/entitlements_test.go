package entitlements

import (
	"errors"
	"testing"
	"time"
)

func mustPlan(t *testing.T, id PlanID) Plan {
	t.Helper()
	p, err := Lookup(id)
	if err != nil {
		t.Fatalf("lookup %s: %v", id, err)
	}
	return p
}

func mustErr(t *testing.T, err error, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

func TestTheCatalogIsInternallyConsistent(t *testing.T) {
	if err := ValidateCatalog(); err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(Catalog()) != 4 {
		t.Fatalf("catalog holds %d plans, want 4", len(Catalog()))
	}
}

// A plan with zero licensed slots is not a cheap plan, it is a plan that cannot run
// anything. Treating that as a discount is how a customer pays for nothing.
func TestAPlanWithNoConcurrencySlotsIsRefused(t *testing.T) {
	bad := Plan{ID: "broken", Name: "Broken", ConcurrencySlots: 0, MaxTTLDuration: time.Hour}
	mustErr(t, bad.Validate(), ErrPlanInconsistent, "zero slots")
}

func TestAPlanWithNoLifetimeIsRefused(t *testing.T) {
	bad := Plan{ID: "broken", ConcurrencySlots: 1}
	mustErr(t, bad.Validate(), ErrPlanInconsistent, "no lifetime")
}

// "Discount" that charges more is a price rise with a misleading label.
func TestADiscountThatIsNotADiscountIsRefused(t *testing.T) {
	bad := Plan{ID: "broken", ConcurrencySlots: 1, MaxTTLDuration: time.Hour,
		IncludedEnvHours: 100, VolumeDiscount: 1.5, VolumeThresholdHours: 200}
	mustErr(t, bad.Validate(), ErrPlanInconsistent, "discount above 100%")
}

func TestADiscountThresholdInsideTheAllowanceIsRefused(t *testing.T) {
	bad := Plan{ID: "broken", ConcurrencySlots: 1, MaxTTLDuration: time.Hour,
		IncludedEnvHours: 1000, VolumeDiscount: 0.15, VolumeThresholdHours: 500}
	mustErr(t, bad.Validate(), ErrPlanInconsistent, "discount inside the allowance")
}

// Netlify and Render both retreated from per-seat pricing after customers objected to
// paying for collaborators. Adding a seat may never reduce what a customer gets.
func TestNoSeatCountCanMakeTheAllowancePunitive(t *testing.T) {
	for _, p := range Catalog() {
		if p.Seats == 0 || p.IncludedEnvHours == 0 {
			continue
		}
		if p.ID == PlanTrial || p.ID == PlanEnterprise {
			continue
		}
		floor := float64(p.Seats) * MinIncludedHoursPerSeat
		if p.IncludedEnvHours < floor {
			t.Fatalf("%s gives %v hours across %d seats, under the %v hour floor",
				p.ID, p.IncludedEnvHours, p.Seats, floor)
		}
	}
}

func TestATrialThatWouldBillIsRefused(t *testing.T) {
	bad := Plan{ID: "trial-like", ConcurrencySlots: 1, MaxTTLDuration: time.Hour,
		TrialDays: 14, SubscriptionCents: 29900, FreezeOnExhaustion: true}
	mustErr(t, bad.Validate(), ErrPlanInconsistent, "trial that charges")
}

func TestATrialThatWouldNotFreezeIsRefused(t *testing.T) {
	bad := Plan{ID: "trial-like", ConcurrencySlots: 1, MaxTTLDuration: time.Hour,
		TrialDays: 14, FreezeOnExhaustion: false}
	mustErr(t, bad.Validate(), ErrPlanInconsistent, "trial that bills past its cap")
}

func TestAlertsMustBeOrderedFractions(t *testing.T) {
	bad := Plan{ID: "broken", ConcurrencySlots: 1, MaxTTLDuration: time.Hour,
		AlertFractions: []float64{0.75, 0.5, 1.0}}
	mustErr(t, bad.Validate(), ErrPlanInconsistent, "unordered alerts")

	worse := Plan{ID: "broken", ConcurrencySlots: 1, MaxTTLDuration: time.Hour,
		AlertFractions: []float64{0, 1.0}}
	mustErr(t, worse.Validate(), ErrPlanInconsistent, "zero alert fraction")
}

func TestLicensedSlotsAreTheApprovedCounts(t *testing.T) {
	cases := map[PlanID]int{PlanTrial: 2, PlanTeam: 5, PlanGrowth: 20, PlanEnterprise: 20}
	for id, want := range cases {
		if got := mustPlan(t, id).ConcurrencySlots; got != want {
			t.Fatalf("%s licenses %d slots, want %d", id, got, want)
		}
	}
}

func TestAdmissionStopsAtTheLicensedSlotCount(t *testing.T) {
	team := mustPlan(t, PlanTeam)
	for running := 0; running < 5; running++ {
		d, err := team.Admit(Usage{RunningEnvironments: running})
		if err != nil {
			t.Fatalf("%d running: %v", running, err)
		}
		if !d.Allowed {
			t.Fatalf("%d running: refused while a slot was free", running)
		}
		if d.RemainingSlots != 4-running {
			t.Fatalf("%d running: %d slots left, want %d", running, d.RemainingSlots, 4-running)
		}
	}
	_, err := team.Admit(Usage{RunningEnvironments: 5})
	mustErr(t, err, ErrConcurrentAtCapacity, "sixth environment on five slots")
}

// Overage is off until the customer turns it on. Silently billing past a limit nobody
// agreed to is the complaint that made spend management notorious.
func TestNothingIsSpentWithoutConsent(t *testing.T) {
	team := mustPlan(t, PlanTeam)
	if team.DefaultOverageLimitCents != 0 {
		t.Fatalf("Team ships with a %d cent default overage limit", team.DefaultOverageLimitCents)
	}
	_, err := team.Admit(Usage{EnvHours: 500, RunningEnvironments: 0})
	mustErr(t, err, ErrOverageNotPermitted, "usage past the allowance with overage off")

	// Inside the allowance the same plan admits freely.
	if _, err := team.Admit(Usage{EnvHours: 499, RunningEnvironments: 0}); err != nil {
		t.Fatalf("inside the allowance: %v", err)
	}
}

func TestTheTrialFreezesRatherThanBills(t *testing.T) {
	trial := mustPlan(t, PlanTrial)
	if _, err := trial.Admit(Usage{EnvHours: 49, RunningEnvironments: 0}); err != nil {
		t.Fatalf("inside the trial allowance: %v", err)
	}
	_, err := trial.Admit(Usage{EnvHours: 50, RunningEnvironments: 0})
	mustErr(t, err, ErrFrozen, "trial past its cap")
	if c := trial.Quote(1000); c.TotalCents != 0 {
		t.Fatalf("a trial quoted %d cents", c.TotalCents)
	}
}

func TestTheTrialMatchesTheApprovedNumbers(t *testing.T) {
	trial := mustPlan(t, PlanTrial)
	if trial.ConcurrencySlots != 2 || trial.HardEnvHourCap != 50 || trial.MaxTTLDuration != 24*time.Hour {
		t.Fatalf("trial is %d slots, %v hours, %s lifetime", trial.ConcurrencySlots, trial.HardEnvHourCap, trial.MaxTTLDuration)
	}
	if trial.TrialDays != 14 {
		t.Fatalf("trial lasts %d days", trial.TrialDays)
	}
}

func TestLifetimeIsBoundedByThePlan(t *testing.T) {
	trial := mustPlan(t, PlanTrial)
	if err := trial.CheckTTL(24 * time.Hour); err != nil {
		t.Fatalf("24 hours should be allowed on a trial: %v", err)
	}
	mustErr(t, trial.CheckTTL(25*time.Hour), ErrTTLEceedsPlan, "25 hours on a trial")
	mustErr(t, trial.CheckTTL(0), ErrTTLEceedsPlan, "no lifetime")

	ent := mustPlan(t, PlanEnterprise)
	if err := ent.CheckTTL(72 * time.Hour); err != nil {
		t.Fatalf("enterprise should allow 72 hours: %v", err)
	}
}

func TestTheIncludedAllowanceCostsNothing(t *testing.T) {
	team := mustPlan(t, PlanTeam)
	// A light month costs the fee and nothing more: the fee is what covers the
	// foundation, and there is no rebate for unused allowance.
	for _, hours := range []float64{0, 1, 100, 499, 500} {
		c := team.Quote(hours)
		if c.TotalCents != team.SubscriptionCents {
			t.Fatalf("%v hours totals %d cents, want the %d cent fee", hours, c.TotalCents, team.SubscriptionCents)
		}
		if c.BillableHours != 0 {
			t.Fatalf("%v hours billed %v as overage", hours, c.BillableHours)
		}
		if c.OverageCents != 0 {
			t.Fatalf("%v hours billed %d cents of overage", hours, c.OverageCents)
		}
	}
}

func TestOverageIsChargedAtTheApprovedRate(t *testing.T) {
	team := mustPlan(t, PlanTeam)
	// 100 hours past the 500 hour allowance at 35 cents, on top of the fee.
	c := team.Quote(600)
	if c.BillableHours != 100 {
		t.Fatalf("billable %v hours, want 100", c.BillableHours)
	}
	if c.OverageCents != 3500 {
		t.Fatalf("overage %d cents, want 3500", c.OverageCents)
	}
	if c.TotalCents != team.SubscriptionCents+3500 {
		t.Fatalf("total %d cents, want the fee plus 3500", c.TotalCents)
	}
}

// The load-bearing commercial property. Volume-based tiers combined with thresholds
// are documented to reduce an invoice as a customer crosses into a cheaper tier,
// crediting them money they did not ask for. Growth has a discount and must still
// never charge less for more usage.
func TestTheTotalNeverFallsAsUsageGrows(t *testing.T) {
	for _, id := range []PlanID{PlanTrial, PlanTeam, PlanGrowth} {
		p := mustPlan(t, id)
		prev := Cents(-1)
		for hours := 0.0; hours <= 20000; hours += 7.5 {
			c := p.Quote(hours)
			if c.TotalCents < prev {
				t.Fatalf("%s: %v hours totals %d cents, less than %d at lower usage", id, hours, c.TotalCents, prev)
			}
			prev = c.TotalCents
		}
	}
}

func TestTheDiscountAppliesToTheMarginalRateOnly(t *testing.T) {
	growth := mustPlan(t, PlanGrowth)
	// Just past the threshold the whole allowance is still free; only the marginal
	// hours past 5000 are discounted.
	before := growth.Quote(growth.VolumeThresholdHours)
	after := growth.Quote(growth.VolumeThresholdHours + 100)
	delta := after.TotalCents - before.TotalCents
	// 100 marginal hours at 35 cents less 15%.
	if delta != 2975 {
		t.Fatalf("the 100 hours past the threshold cost %d cents, want 2975", delta)
	}
	if growth.VolumeDiscount != 0.15 {
		t.Fatalf("discount is %v, want 0.15", growth.VolumeDiscount)
	}
}

func TestTheCeilingIsPublishedNotEstimated(t *testing.T) {
	growth := mustPlan(t, PlanGrowth)
	// The $10,172.23 worst-case month for the 20 slot reference profile.
	if growth.HardCeilingCents != 1017223 {
		t.Fatalf("Growth ceiling is %d cents, want 1017223", growth.HardCeilingCents)
	}
	team := mustPlan(t, PlanTeam)
	if team.HardCeilingCents == 0 {
		t.Fatal("Team must publish a ceiling")
	}
	if team.HardCeilingCents >= growth.HardCeilingCents {
		t.Fatalf("five slots must not carry a 20 slot ceiling: %d vs %d", team.HardCeilingCents, growth.HardCeilingCents)
	}

	c := growth.Quote(100000)
	if !c.Capped {
		t.Fatal("usage past the ceiling was not flagged as capped")
	}
	if c.TotalCents != growth.HardCeilingCents {
		t.Fatalf("capped total %d cents, want the %d cent ceiling", c.TotalCents, growth.HardCeilingCents)
	}
}

// A negative invoice means paying customers for destroying their own previews. The
// credit model that would produce one was removed rather than clamped.
func TestNoUsageEverProducesARebate(t *testing.T) {
	for _, p := range Catalog() {
		for hours := 0.0; hours <= 5000; hours += 25 {
			c := p.Quote(hours)
			if c.TotalCents < 0 {
				t.Fatalf("%s: %v hours produced a negative total of %d", p.ID, hours, c.TotalCents)
			}
			if c.TotalCents < c.SubscriptionCents && !c.Frozen {
				t.Fatalf("%s: %v hours totalled %d, below the %d cent fee",
					p.ID, hours, c.TotalCents, c.SubscriptionCents)
			}
		}
	}
}

func TestAFrozenTrialProducesNoInvoice(t *testing.T) {
	trial := mustPlan(t, PlanTrial)
	c := trial.Quote(10000)
	if !c.Frozen {
		t.Fatal("a trial past its cap must report that it froze")
	}
	if c.TotalCents != 0 || c.OverageCents != 0 {
		t.Fatalf("a frozen trial produced an invoice: total %d, overage %d", c.TotalCents, c.OverageCents)
	}
}

func TestNegativeUsageIsTreatedAsZero(t *testing.T) {
	team := mustPlan(t, PlanTeam)
	if got := team.Quote(-500).TotalCents; got != team.SubscriptionCents {
		t.Fatalf("negative usage totalled %d cents", got)
	}
}

func TestAlertsFireAtFiftySeventyFiveAndOneHundred(t *testing.T) {
	team := mustPlan(t, PlanTeam)
	cases := []struct {
		hours float64
		want  int
	}{
		{0, 0},
		{249, 0},
		{250, 1},
		{375, 2},
		{500, 3},
		{4000, 3},
	}
	for _, c := range cases {
		got := team.Alerts(c.hours)
		if len(got) != c.want {
			t.Fatalf("%v hours raised %d alerts, want %d", c.hours, len(got), c.want)
		}
		if len(got) > 0 && got[len(got)-1].Fraction == 1.0 && c.hours < 500 {
			t.Fatalf("%v hours reported the 100%% alert", c.hours)
		}
	}
}

// A plan with no allowance must not divide by zero and claim the customer is over.
func TestAPlanWithoutAnAllowanceAlertsOnNothing(t *testing.T) {
	ent := mustPlan(t, PlanEnterprise)
	if got := ent.Alerts(10000); len(got) != 0 {
		t.Fatalf("enterprise with no allowance raised %d alerts", len(got))
	}
}

func TestADowngradeIsRefusedWhenItWouldStrandRunningWork(t *testing.T) {
	growth := mustPlan(t, PlanGrowth)
	team := mustPlan(t, PlanTeam)
	_, err := growth.Downgrade(team, Usage{RunningEnvironments: 12})
	mustErr(t, err, ErrDowngradeStrandsWork, "twelve running against five slots")

	m, err := growth.Downgrade(team, Usage{RunningEnvironments: 3})
	if err != nil {
		t.Fatalf("a downgrade that fits should be permitted: %v", err)
	}
	if m.AcknowledgementRequired {
		t.Fatalf("a same-lifetime downgrade needs no acknowledgment: %v", m.Notes)
	}
}

// Cleanup is always available, including after cancellation. A customer who cannot
// destroy what they are being billed for is the worst outcome this system has.
func TestAbortAndCleanupSurviveEveryPlan(t *testing.T) {
	for _, p := range Catalog() {
		if !p.AbortAlwaysAvailable() {
			t.Fatalf("%s makes teardown conditional on payment", p.ID)
		}
	}
}

func TestAShorterTargetLifetimeRequiresAcknowledgement(t *testing.T) {
	ent := mustPlan(t, PlanEnterprise)
	team := mustPlan(t, PlanTeam)
	m, err := ent.Downgrade(team, Usage{RunningEnvironments: 0})
	if err != nil {
		t.Fatalf("an enterprise downgrade should be permitted: %v", err)
	}
	if !m.AcknowledgementRequired {
		t.Fatal("dropping from 72h to 24h must require an explicit confirmation")
	}
	if len(m.Notes) == 0 {
		t.Fatal("the customer must be told what the change does to running environments")
	}
}

func TestDowngradingIntoAnAlreadyFrozenAllowanceRequiresAcknowledgement(t *testing.T) {
	team := mustPlan(t, PlanTeam)
	trial := mustPlan(t, PlanTrial)
	m, err := team.Downgrade(trial, Usage{EnvHours: 50})
	if err != nil {
		t.Fatalf("downgrade to trial: %v", err)
	}
	if !m.AcknowledgementRequired {
		t.Fatal("downgrading at the trial's freeze cap must require confirmation")
	}
}

func TestDowngradeToAnInconsistentPlanIsRefused(t *testing.T) {
	team := mustPlan(t, PlanTeam)
	broken := Plan{ID: "broken", ConcurrencySlots: 0, MaxTTLDuration: time.Hour}
	_, err := team.Downgrade(broken, Usage{})
	mustErr(t, err, ErrPlanInconsistent, "downgrade to a plan that cannot run anything")
}

func TestOnlyEnterpriseOffersBringYourOwnCloud(t *testing.T) {
	for _, p := range Catalog() {
		if p.AllowsBYOC && p.ID != PlanEnterprise {
			t.Fatalf("%s offers BYOC; the floor analysis makes it the enterprise escape valve only", p.ID)
		}
	}
}

func TestAnUnknownPlanIsRefused(t *testing.T) {
	_, err := Lookup("platinum-imaginary")
	mustErr(t, err, ErrUnknownPlan, "imaginary plan")
}
