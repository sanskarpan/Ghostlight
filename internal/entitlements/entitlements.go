// Package entitlements decides what a subscription may do, and what it costs.
//
// ADR G-036 and G-037, COST-MODEL.md §6.1. This package is where the commercial
// decisions stop being prose: a plan's licensed concurrency, its included allowance,
// its overage behaviour and its freeze conditions are values here, so the numbers
// approved on 10 October 2026 cannot drift from the numbers the code enforces.
//
// Four properties are load-bearing.
//
// Concurrency is licensed capacity, never usage. There is deliberately no way to
// bill concurrency here: a gauge that rises and falls cannot be invoiced, and every
// vendor that sells concurrency sells a limit. Concurrency appears only as a cap and
// only in admission decisions.
//
// Overages are graduated and the total never falls as usage grows. Volume-based tiers
// combined with thresholds are documented to reduce an invoice when a customer crosses
// into a cheaper tier, crediting them money they did not ask for. Monotonicity is
// therefore a tested property, not a hope.
//
// Nothing is spent without consent. The default overage limit is zero, so exceeding
// the included allowance stops work rather than silently billing it.
//
// A downgrade may not strand running environments. Abort and cleanup stay available
// under every plan including a cancelled one, because a customer who cannot destroy
// what they are being billed for is the worst outcome this system has.
package entitlements

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

// PlanID identifies a subscription tier.
type PlanID string

const (
	// PlanTrial is the bounded evaluation tier. It freezes rather than bills.
	PlanTrial PlanID = "trial"
	// PlanTeam is the entry paid tier.
	PlanTeam PlanID = "team"
	// PlanGrowth is the scale paid tier.
	PlanGrowth PlanID = "growth"
	// PlanEnterprise is annual with a bring-your-own-cloud option.
	PlanEnterprise PlanID = "enterprise"
)

// Cents avoids float money. A price is an integer number of cents, and a plan that
// stores $0.35 as a float will eventually invoice $0.34999999.
type Cents int64

// Plan is the entitlement set attached to a subscription.
type Plan struct {
	// ID and Name identify the tier.
	ID   PlanID
	Name string

	// SubscriptionCents is the recurring fee before usage.
	SubscriptionCents Cents
	// Seats is the licensed seat count.
	Seats int
	// ConcurrencySlots is licensed capacity, enforced at admission. It is a limit,
	// not a quantity, and is never multiplied by anything to produce a charge.
	ConcurrencySlots int
	// IncludedEnvHours is the monthly allowance.
	IncludedEnvHours float64
	// OverageCentsPerEnvHour prices usage beyond the allowance.
	OverageCentsPerEnvHour Cents
	// VolumeDiscount applies a lower rate to usage past VolumeThresholdEnvHours. It
	// is a discount on the marginal rate and never reduces the total.
	VolumeDiscount       float64
	VolumeThresholdHours float64

	// DefaultOverageLimitCents is the most a customer can be charged for overage
	// without opting in. Zero means overage is off until they turn it on, which is
	// the default for every plan: silently billing past a limit is the complaint
	// that made spend management notorious.
	DefaultOverageLimitCents Cents
	// HardCeilingCents is the contractual maximum for the billing period. The
	// published $10,172 reference-profile maximum is this number.
	HardCeilingCents Cents

	// MaxTTLDuration bounds how long an environment may live.
	MaxTTLDuration time.Duration
	// HardEnvHourCap freezes the plan once this many environment-hours are consumed
	// in a period. Zero means no cap beyond the ceiling.
	HardEnvHourCap float64

	// AlertFractions are the usage fractions that raise a notification. They are
	// evaluated against the allowance, and each fires at most once per period.
	AlertFractions []float64

	// TrialDays is the evaluation length. Zero for paid plans.
	TrialDays int
	// FreezeOnExhaustion stops new admissions when a cap is reached.
	FreezeOnExhaustion bool
	// AllowsBYOC permits the customer to run against their own cloud.
	AllowsBYOC bool
}

// MinIncludedHoursPerSeat is the floor on included usage per licensed seat.
//
// Netlify and Render both retreated from per-seat pricing in 2026 after customers
// objected to being charged for adding collaborators. The seat line is worth keeping
// as an expansion signal, but only while adding a seat never reduces what the
// customer already gets — so the allowance scales with seats and can never fall below
// this floor per seat.
const MinIncludedHoursPerSeat = 100.0

// catalog is the approved plan set. Changing a number here changes what customers are
// charged, which is why Validate refuses an internally inconsistent plan rather than
// letting an attractive typo through.
var catalog = []Plan{
	{
		ID: PlanTrial, Name: "Trial",
		SubscriptionCents: 0,
		Seats:             2,
		ConcurrencySlots:  2,
		IncludedEnvHours:  50,
		// A trial has no overage rate because it never charges for overage; it
		// freezes. The rate is set to the Team rate so a conversion quotes the same
		// number the trial would have cost had it billed.
		OverageCentsPerEnvHour: 35,
		MaxTTLDuration:         24 * time.Hour,
		HardEnvHourCap:         50,
		AlertFractions:         []float64{0.5, 0.75, 1.0},
		TrialDays:              14,
		FreezeOnExhaustion:     true,
	},
	{
		ID: PlanTeam, Name: "Team",
		SubscriptionCents:        29900,
		Seats:                    5,
		ConcurrencySlots:         5,
		IncludedEnvHours:         500,
		OverageCentsPerEnvHour:   35,
		DefaultOverageLimitCents: 0,
		// A quarter of the 20-slot reference maximum, because the ceiling is
		// measured per licensed slot and Team licenses five.
		HardCeilingCents: 254323,
		MaxTTLDuration:   24 * time.Hour,
		AlertFractions:   []float64{0.5, 0.75, 1.0},
	},
	{
		ID: PlanGrowth, Name: "Growth",
		SubscriptionCents:        99900,
		Seats:                    20,
		ConcurrencySlots:         20,
		IncludedEnvHours:         2500,
		OverageCentsPerEnvHour:   35,
		VolumeDiscount:           0.15,
		VolumeThresholdHours:     5000,
		DefaultOverageLimitCents: 0,
		// The published $10,172.23 worst-case month for the 20-slot reference
		// profile, published as a contractual ceiling rather than an estimate.
		HardCeilingCents: 1017223,
		MaxTTLDuration:   24 * time.Hour,
		AlertFractions:   []float64{0.5, 0.75, 1.0},
	},
	{
		ID: PlanEnterprise, Name: "Enterprise",
		SubscriptionCents:        0,
		Seats:                    0,
		ConcurrencySlots:         20,
		IncludedEnvHours:         0,
		OverageCentsPerEnvHour:   35,
		DefaultOverageLimitCents: 0,
		// A negotiated ceiling: zero means the contract sets it.
		HardCeilingCents: 0,
		MaxTTLDuration:   72 * time.Hour,
		AlertFractions:   []float64{0.5, 0.75, 1.0},
		AllowsBYOC:       true,
	},
}

// Errors returned by this package.
var (
	// ErrUnknownPlan means no plan has that identifier.
	ErrUnknownPlan = errors.New("unknown plan")
	// ErrPlanInconsistent means a plan's own numbers contradict each other.
	ErrPlanInconsistent = errors.New("plan is internally inconsistent")
	// ErrConcurrentAtCapacity means every licensed slot is in use.
	ErrConcurrentAtCapacity = errors.New("no concurrency slot available")
	// ErrFrozen means the plan has stopped admitting work.
	ErrFrozen = errors.New("plan is frozen")
	// ErrOverageNotPermitted means usage is past the allowance and the customer has
	// not opted into overage.
	ErrOverageNotPermitted = errors.New("overage is not enabled for this subscription")
	// ErrWouldExceedCeiling means admitting would push the period past the
	// contractual maximum.
	ErrWouldExceedCeiling = errors.New("admission would exceed the contractual ceiling")
	// ErrDowngradeStrandsWork means the target plan cannot host environments that
	// are already running.
	ErrDowngradeStrandsWork = errors.New("downgrade would strand running environments")
	// ErrTTLEceedsPlan means a requested lifetime is longer than the plan allows.
	ErrTTLEceedsPlan = errors.New("requested lifetime exceeds the plan maximum")
)

// Lookup returns a plan by identifier.
func Lookup(id PlanID) (Plan, error) {
	for _, p := range catalog {
		if p.ID == id {
			return p, nil
		}
	}
	return Plan{}, fmt.Errorf("%w: %s", ErrUnknownPlan, id)
}

// Catalog returns every plan, ordered from cheapest to most capable.
func Catalog() []Plan {
	out := make([]Plan, len(catalog))
	copy(out, catalog)
	sort.Slice(out, func(i, j int) bool { return out[i].SubscriptionCents < out[j].SubscriptionCents })
	return out
}

// Validate checks that a plan's numbers can be enforced.
//
// The concurrency check is the one worth stating plainly: a plan with zero licensed
// slots is not a cheap plan, it is a plan that cannot run anything, and treating that
// as a discount rather than a mistake is how a customer ends up paying for nothing.
func (p Plan) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("%w: no identifier", ErrPlanInconsistent)
	}
	if p.ConcurrencySlots <= 0 {
		return fmt.Errorf("%w: %s licenses %d concurrency slots", ErrPlanInconsistent, p.ID, p.ConcurrencySlots)
	}
	if p.Seats < 0 {
		return fmt.Errorf("%w: %s has %d seats", ErrPlanInconsistent, p.ID, p.Seats)
	}
	if p.IncludedEnvHours < 0 {
		return fmt.Errorf("%w: %s includes %v hours", ErrPlanInconsistent, p.ID, p.IncludedEnvHours)
	}
	if p.OverageCentsPerEnvHour < 0 {
		return fmt.Errorf("%w: %s prices overage at %d", ErrPlanInconsistent, p.ID, p.OverageCentsPerEnvHour)
	}
	if p.MaxTTLDuration <= 0 {
		return fmt.Errorf("%w: %s allows no lifetime", ErrPlanInconsistent, p.ID)
	}
	if p.DefaultOverageLimitCents < 0 {
		return fmt.Errorf("%w: %s has a negative overage limit", ErrPlanInconsistent, p.ID)
	}
	if p.HardCeilingCents < 0 {
		return fmt.Errorf("%w: %s has a negative ceiling", ErrPlanInconsistent, p.ID)
	}
	// A discount must be a discount. A rate at or above the base rate would be
	// advertised as a discount and bill more.
	if p.VolumeDiscount < 0 || p.VolumeDiscount >= 1 {
		return fmt.Errorf("%w: %s discounts by %v", ErrPlanInconsistent, p.ID, p.VolumeDiscount)
	}
	if p.VolumeDiscount > 0 && p.VolumeThresholdHours <= p.IncludedEnvHours {
		return fmt.Errorf("%w: %s discounts at %v hours, inside its %v hour allowance",
			ErrPlanInconsistent, p.ID, p.VolumeThresholdHours, p.IncludedEnvHours)
	}
	if p.HardEnvHourCap > 0 && p.IncludedEnvHours > p.HardEnvHourCap {
		return fmt.Errorf("%w: %s caps at %v hours but includes %v",
			ErrPlanInconsistent, p.ID, p.HardEnvHourCap, p.IncludedEnvHours)
	}
	if p.TrialDays > 0 && p.SubscriptionCents != 0 {
		return fmt.Errorf("%w: %s is a trial and charges %d", ErrPlanInconsistent, p.ID, p.SubscriptionCents)
	}
	if p.TrialDays > 0 && !p.FreezeOnExhaustion {
		return fmt.Errorf("%w: %s is a trial and would bill past its cap", ErrPlanInconsistent, p.ID)
	}
	var prev float64
	for i, f := range p.AlertFractions {
		if f <= 0 || f > 1 {
			return fmt.Errorf("%w: %s alerts at %v", ErrPlanInconsistent, p.ID, f)
		}
		if i > 0 && f <= prev {
			return fmt.Errorf("%w: %s alerts out of order at %v", ErrPlanInconsistent, p.ID, f)
		}
		prev = f
	}
	if p.Seats > 0 && p.IncludedEnvHours > 0 &&
		p.IncludedEnvHours < float64(p.Seats)*MinIncludedHoursPerSeat && p.ID != PlanTrial && p.ID != PlanEnterprise {
		return fmt.Errorf("%w: %s gives %v hours across %d seats, under the %v hour floor",
			ErrPlanInconsistent, p.ID, p.IncludedEnvHours, p.Seats, MinIncludedHoursPerSeat)
	}
	return nil
}

// ValidateCatalog validates every plan.
func ValidateCatalog() error {
	for _, p := range catalog {
		if err := p.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Usage is what a customer has consumed in the current period.
type Usage struct {
	EnvHours            float64
	RunningEnvironments int
}

// Decision is the outcome of an admission check.
type Decision struct {
	// Allowed reports whether the environment may start.
	Allowed bool
	// Reason explains a refusal in words a customer can be shown.
	Reason string
	// RemainingSlots is the licensed capacity left after this admission.
	RemainingSlots int
}

// Admit decides whether one more environment may start.
//
// The order of the checks is the policy. Capacity first, because a licensed slot is
// the thing a customer bought; then the period cap, because exceeding a published
// ceiling is worse than refusing; then overage consent, because we do not bill past a
// limit nobody agreed to.
func (p Plan) Admit(u Usage) (Decision, error) {
	if u.RunningEnvironments >= p.ConcurrencySlots {
		return Decision{Reason: fmt.Sprintf("all %d concurrency slots are in use", p.ConcurrencySlots)},
			ErrConcurrentAtCapacity
	}
	if p.HardEnvHourCap > 0 && u.EnvHours >= p.HardEnvHourCap {
		return Decision{Reason: fmt.Sprintf("the plan's %v environment-hour cap is reached", p.HardEnvHourCap)},
			ErrFrozen
	}
	if u.EnvHours >= p.IncludedEnvHours && p.DefaultOverageLimitCents == 0 && !p.FreezeOnExhaustion {
		return Decision{Reason: "the included allowance is used up and overage is not enabled"},
			ErrOverageNotPermitted
	}
	return Decision{
		Allowed:        true,
		RemainingSlots: p.ConcurrencySlots - u.RunningEnvironments - 1,
	}, nil
}

// CheckTTL refuses a lifetime the plan does not sell. The trial's 24-hour cap is a
// cost control, not a technical limit, which is why it is expressed as an entitlement
// rather than buried in the scheduler.
func (p Plan) CheckTTL(requested time.Duration) error {
	if requested <= 0 {
		return fmt.Errorf("%w: no lifetime requested", ErrTTLEceedsPlan)
	}
	if requested > p.MaxTTLDuration {
		return fmt.Errorf("%w: %s allows %s, requested %s", ErrTTLEceedsPlan, p.ID, p.MaxTTLDuration, requested)
	}
	return nil
}

// Charge is a computed line for one billing period.
type Charge struct {
	SubscriptionCents Cents
	// IncludedHours is the allowance consumed, which costs nothing.
	IncludedHours float64
	// BillableHours is usage past the allowance.
	BillableHours float64
	// OverageCents is the usage charge, before the ceiling is applied.
	OverageCents Cents
	// TotalCents is what is owed: the fee plus usage, never above HardCeilingCents.
	TotalCents Cents
	// Capped reports that the contractual ceiling truncated the charge.
	Capped bool
	// Frozen reports that the plan stopped rather than billed, which is what a trial
	// does. A frozen period produces no invoice at all.
	Frozen bool
}

// Quote computes the period charge from metered usage.
//
// Concurrency is absent by construction. A peak cannot be invoiced and must not be
// estimated here, so there is no parameter for it and no way for a future caller to
// smuggle one in.
//
// The total is the fee plus usage. There is deliberately no credit against the fee and
// no rebate for unused allowance: a light month costs the plan fee, which already
// covers its share of the foundation, and selling prepaid credits introduces refund
// and breakage rules that a provider of ephemeral infrastructure has no use for. A
// negative invoice is money we would have to pay a customer for destroying their own
// preview environments.
func (p Plan) Quote(envHours float64) Charge {
	if envHours < 0 {
		envHours = 0
	}
	c := Charge{SubscriptionCents: p.SubscriptionCents}
	c.IncludedHours = minFloat(envHours, p.IncludedEnvHours)
	c.BillableHours = maxFloat(envHours-p.IncludedEnvHours, 0)
	overage := Cents(mathRound(c.BillableHours * float64(p.OverageCentsPerEnvHour)))

	// The discount applies to the marginal rate beyond the threshold and never
	// reduces the total. Applying it to the whole bill would make a larger customer
	// pay less in absolute terms than a smaller one for the same usage.
	if p.VolumeDiscount > 0 && envHours > p.VolumeThresholdHours {
		discountable := minFloat(c.BillableHours, envHours-p.VolumeThresholdHours)
		overage -= Cents(mathRound(discountable * float64(p.OverageCentsPerEnvHour) * p.VolumeDiscount))
	}
	if overage < 0 {
		overage = 0
	}

	// An opted-in overage limit truncates the usage charge before the total is
	// formed, so the ceiling is applied to a number that already respects it.
	if p.DefaultOverageLimitCents > 0 && overage > p.DefaultOverageLimitCents {
		overage = p.DefaultOverageLimitCents
	}

	// A trial freezes rather than bills. Quoting it as though it billed would put an
	// invoice in front of a customer whose plan explicitly promises not to charge.
	if p.TrialDays > 0 {
		c.OverageCents = 0
		c.TotalCents = 0
		c.Frozen = true
		return c
	}

	c.OverageCents = overage
	total := p.SubscriptionCents + overage
	if p.HardCeilingCents > 0 && total > p.HardCeilingCents {
		total = p.HardCeilingCents
		c.Capped = true
	}
	c.TotalCents = total
	return c
}

// Alert names a notification to send.
type Alert struct {
	Fraction float64
	Message  string
}

// Alerts returns the threshold notifications newly crossed at this usage level, so a
// caller can record which have fired and avoid repeating them every hour. Thresholds
// are reported against the allowance, and a plan with no allowance alerts on nothing
// rather than dividing by zero.
func (p Plan) Alerts(envHours float64) []Alert {
	if p.IncludedEnvHours <= 0 {
		return nil
	}
	used := envHours / p.IncludedEnvHours
	var out []Alert
	for _, f := range p.AlertFractions {
		if used >= f {
			out = append(out, Alert{
				Fraction: f,
				Message: fmt.Sprintf("%s: %v%% of the %v included environment-hours used",
					p.Name, mathRound(used*100), p.IncludedEnvHours),
			})
		}
	}
	return out
}

// Migration is the result of checking a plan change.
type Migration struct {
	// AcknowledgementRequired reports that the change is permitted but needs a
	// deliberate confirmation, because environments already in flight will outlive
	// the target plan's rules.
	AcknowledgementRequired bool
	// Notes are the facts a customer should see before confirming.
	Notes []string
}

// Downgrade checks that moving to a target plan does not strand work in flight.
//
// Environments already running must fit inside the target's licensed capacity; if
// they do not, the change is refused rather than killing previews a customer is
// actively using. A shorter maximum lifetime is not a refusal — cleanup stays
// available under every plan — but it does require explicit confirmation, because a
// downgrade that silently truncates a running preview's life is how a customer
// learns to distrust the billing page.
func (p Plan) Downgrade(target Plan, u Usage) (Migration, error) {
	if err := target.Validate(); err != nil {
		return Migration{}, err
	}
	if u.RunningEnvironments > target.ConcurrencySlots {
		return Migration{}, fmt.Errorf("%w: %d running against %s's %d licensed slots",
			ErrDowngradeStrandsWork, u.RunningEnvironments, target.ID, target.ConcurrencySlots)
	}
	var m Migration
	if target.MaxTTLDuration < p.MaxTTLDuration {
		m.AcknowledgementRequired = true
		m.Notes = append(m.Notes, fmt.Sprintf(
			"environments already running may live up to %s, longer than %s's %s maximum; they will be cleaned up on their existing schedule",
			p.MaxTTLDuration, target.ID, target.MaxTTLDuration))
	}
	if target.HardEnvHourCap > 0 && u.EnvHours >= target.HardEnvHourCap {
		m.AcknowledgementRequired = true
		m.Notes = append(m.Notes, fmt.Sprintf(
			"%v environment-hours are already used, which meets %s's %v hour freeze cap",
			u.EnvHours, target.ID, target.HardEnvHourCap))
	}
	if !m.AcknowledgementRequired {
		m.Notes = append(m.Notes, "no running environment is affected")
	}
	return m, nil
}

// AbortAlwaysAvailable records the invariant that cancellation does not remove the
// ability to destroy resources. It exists as a function so the rule is testable and
// so no future path can make teardown conditional on payment.
func (p Plan) AbortAlwaysAvailable() bool { return true }

// mathRound rounds to the nearest integer for money. Half-up, because a customer
// billed a cent less because of a banker's rounding rule is a support ticket.
func mathRound(f float64) float64 {
	if f < 0 {
		return -mathRound(-f)
	}
	return math.Floor(f + 0.5)
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func minCents(a, b Cents) Cents {
	if a < b {
		return a
	}
	return b
}
