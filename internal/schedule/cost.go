package schedule

import (
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/costmodel"
	"github.com/sanskarpan/Ghostlight/internal/meters"
)

// Errors returned by this package's cost and lifetime rules.
var (
	// ErrNegativeDuration means a duration that cannot describe an elapsed time
	// was supplied. A negative interval is a clock error, and rounding it to zero
	// would quietly turn a broken caller into a legal-looking answer.
	ErrNegativeDuration = errors.New("duration must not be negative")

	// ErrInvalidQuantity means a byte count that cannot describe retained data.
	ErrInvalidQuantity = errors.New("quantity must not be negative")

	// ErrInvalidRetention means the retention window is not a positive duration.
	//
	// Zero is refused rather than treated as "no retention" because a zero
	// retention is not a retention policy, it is immediate destruction wearing a
	// policy's name. A caller who wants the data gone must say so through the purge
	// path, where it is recorded, rather than inferring it from a field left unset.
	ErrInvalidRetention = errors.New("retention must be a positive duration; zero retention is immediate destruction and must be requested as such")

	// ErrUnpricedRate means a rate this calculation depends on is missing or not
	// positive. An unpriced cost is refused rather than reported as free, which is
	// the same rule costmodel applies to a line the price dataset cannot resolve.
	ErrUnpricedRate = errors.New("rate is missing or not positive; an unpriced cost is refused rather than billed as free")

	// ErrNoTTL means the environment has no positive lifetime. A zero lifetime is
	// not a lifetime, and treating it as one would either destroy the environment
	// immediately or make it permanent, depending on which reading the code took.
	ErrNoTTL = errors.New("environment has no positive lifetime")

	// ErrBeyondRetention means a suspension outlived its retention window, so the
	// retained data must already have been destroyed and there is nothing to wake.
	ErrBeyondRetention = errors.New("suspension outlived its retention window")
)

// HoursPerMonth is the month used to annualise retained storage.
//
// It is the cost model's constant rather than a local copy, because a second copy
// is a second number and two numbers for one month is how a customer ends up
// billed two different amounts for the same bytes.
const HoursPerMonth = costmodel.HoursPerMonth

// BytesPerGigabyte is decimal gigabytes, matching the unit storage is priced and
// metered in. A binary interpretation would over-bill by 7.4% on every suspended
// environment, which is precisely the population most likely to read the invoice.
const BytesPerGigabyte = meters.BytesPerGigabyte

// Retention is how long a suspended environment's data is kept before it must be
// destroyed.
type Retention time.Duration

// DefaultRetention is a week of suspension.
//
// A week is chosen because it is the shortest window that survives the two
// interruptions a suspended preview actually suffers: a weekend and a holiday, and
// a reviewer who forgets about it. It is a default rather than a maximum because
// retention is a customer-visible promise, and a promise nobody can shorten is a
// promise the platform cannot honour when capacity is tight.
const DefaultRetention = Retention(7 * 24 * time.Hour)

// Validate refuses a retention window that is not a positive duration.
func (r Retention) Validate() error {
	if r <= 0 {
		return fmt.Errorf("%w: got %s", ErrInvalidRetention, time.Duration(r))
	}
	return nil
}

// NewRetention builds a retention window, refusing one that is not positive.
func NewRetention(d time.Duration) (Retention, error) {
	r := Retention(d)
	if err := r.Validate(); err != nil {
		return 0, err
	}
	return r, nil
}

// Duration returns the window as a plain duration.
func (r Retention) Duration() time.Duration { return time.Duration(r) }

// Rates prices what a suspended environment costs.
//
// No rate is defaulted here. Prices in this system come from the captured price
// reference dataset through costmodel.Table, and a number written into this file
// would be a number with no source URL, no publication date and nobody able to
// say why it changed. A caller that has no rate must be told so.
type Rates struct {
	// EnvironmentUSDPerHour prices a running environment-hour. A suspended
	// environment bills none of them, so this rate is context rather than an
	// input to the residual cost, and zero is a legal value here: it cannot
	// corrupt a number that is zero by construction.
	EnvironmentUSDPerHour float64
	// StorageUSDPerGBMonth prices retained storage in decimal gigabytes. This is
	// the rate the residual cost is made of, so it must be priced.
	StorageUSDPerGBMonth float64
}

// Validate refuses rates this package cannot honestly compute with.
func (r Rates) Validate() error {
	if r.EnvironmentUSDPerHour < 0 {
		return fmt.Errorf("%w: environment-hours priced at %v", ErrUnpricedRate, r.EnvironmentUSDPerHour)
	}
	if r.StorageUSDPerGBMonth <= 0 {
		return fmt.Errorf("%w: storage priced at %v", ErrUnpricedRate, r.StorageUSDPerGBMonth)
	}
	return nil
}

// RatesFromTable reads the storage rate from a captured price dataset.
//
// Only the storage rate is read. Pricing an environment-hour requires the node
// shape's per-vCPU amortisation, which belongs to costmodel and already exists
// there; duplicating that arithmetic here would be a second definition of a cost
// line that is already defined once.
func RatesFromTable(t *costmodel.Table) (Rates, error) {
	if t == nil {
		return Rates{}, fmt.Errorf("%w: no price dataset was loaded", ErrUnpricedRate)
	}
	storage, _, err := t.MonthlyGB("AmazonS3", "")
	if err != nil {
		return Rates{}, fmt.Errorf("%w: %v", ErrUnpricedRate, err)
	}
	return Rates{StorageUSDPerGBMonth: storage}, nil
}

// Cost is what one suspension has cost so far.
//
// The shape is deliberately asymmetric: EnvironmentHours is present, and is
// always zero. It is there so that a caller reading a bill line can see the
// quantity and its absence rather than infer one from a missing field.
type Cost struct {
	// SuspendedFor is the elapsed suspension the cost covers.
	SuspendedFor time.Duration
	// Retention is the window the data was promised for.
	Retention Retention
	// Bytes is the retained data size.
	Bytes int64
	// EnvironmentHours is the billable running time. Always zero: a suspended
	// environment is not running, so it occupied no compute, and charging it would
	// bill a stopped machine for having stopped.
	EnvironmentHours float64
	// StorageGBHours is the retained data measured over time.
	StorageGBHours float64
	// StorageUSD is the storage charge.
	StorageUSD float64
	// TotalUSD is everything owed for this suspension.
	TotalUSD float64
	// BeyondRetention reports that the suspension has already outlived its
	// retention window. It is a fault report, not a billing signal: an environment
	// in this state should have been destroyed, and its cost is capped at the
	// retention window because charging past a window that says the data is gone
	// would bill for bytes policy says no longer exist.
	BeyondRetention bool
}

// Residual computes the residual cost of a suspended environment.
//
// Storage accrues for the suspension because the bytes are still there: a
// suspended preview keeps its volumes, its object state and its snapshot, and
// every one of those is billed by the provider whether or not anybody is looking
// at the environment. Environment-hours do not accrue, because the runtime is
// stopped and stopping is the entire purpose of the suspension.
//
// The cost is capped at the retention window. Past that point the data was
// promised destroyed, so the honest number stops growing and the caller is told
// instead, through BeyondRetention: a residual cost that grows forever after the
// window has expired is a way to bill for a purge that failed to happen.
func Residual(suspendedFor time.Duration, retention Retention, bytes int64, rates Rates) (Cost, error) {
	if suspendedFor < 0 {
		return Cost{}, fmt.Errorf("%w: suspended for %s", ErrNegativeDuration, suspendedFor)
	}
	if err := retention.Validate(); err != nil {
		return Cost{}, err
	}
	if bytes < 0 {
		return Cost{}, fmt.Errorf("%w: retained %d bytes", ErrInvalidQuantity, bytes)
	}
	if err := rates.Validate(); err != nil {
		return Cost{}, err
	}

	c := Cost{SuspendedFor: suspendedFor, Retention: retention, Bytes: bytes}
	billed := suspendedFor
	if billed > retention.Duration() {
		billed = retention.Duration()
		c.BeyondRetention = true
	}

	c.StorageGBHours = float64(bytes) / BytesPerGigabyte * billed.Hours()
	c.StorageUSD = c.StorageGBHours / HoursPerMonth * rates.StorageUSDPerGBMonth
	c.TotalUSD = c.StorageUSD
	return c, nil
}

// Decision is what must happen to a suspended environment.
type Decision string

const (
	// DecisionHold means the environment stays suspended with its data retained.
	// Suspension is not destruction: it preserves ownership and TTL while the
	// compute stops, and holding is the state in which a reviewer can come back
	// tomorrow and find their environment.
	DecisionHold Decision = "hold"
	// DecisionPurge means the retention window has run out and the data must be
	// destroyed.
	DecisionPurge Decision = "purge"
)

// Decide answers whether a suspension must be purged.
//
// The boundary is INCLUSIVE: a suspension of exactly the retention duration is
// already a purge. This matches the watchdog's own expiry test, which fires at the
// expiry instant rather than after it, and it matches what a customer reads off a
// policy that says "retained for 7 days" — after seven days the data is gone, not
// gone for seven days plus a scheduling tick. An exclusive boundary would keep one
// extra window of data for every suspended environment in the fleet, which is the
// wrong direction for a promise about retention.
//
// A suspension that has not reached the window is never a purge. That is the whole
// point of the boundary being a maximum rather than a target.
func Decide(suspendedFor time.Duration, retention Retention) (Decision, error) {
	if suspendedFor < 0 {
		return "", fmt.Errorf("%w: suspended for %s", ErrNegativeDuration, suspendedFor)
	}
	if err := retention.Validate(); err != nil {
		return "", err
	}
	if suspendedFor >= retention.Duration() {
		return DecisionPurge, nil
	}
	return DecisionHold, nil
}

// DecideAt answers for a suspension that began at a moment.
func DecideAt(suspendedAt, now time.Time, retention Retention) (Decision, error) {
	if now.Before(suspendedAt) {
		return "", fmt.Errorf("%w: %s is before the suspension began at %s", ErrNegativeDuration,
			now.Format(time.RFC3339), suspendedAt.Format(time.RFC3339))
	}
	return Decide(now.Sub(suspendedAt), retention)
}

// PurgeAt returns the moment a suspension must be destroyed.
func PurgeAt(suspendedAt time.Time, retention Retention) (time.Time, error) {
	if err := retention.Validate(); err != nil {
		return time.Time{}, err
	}
	return suspendedAt.Add(retention.Duration()), nil
}

// Remaining returns the TTL left, which suspension does not consume.
//
// This is the function whose signature argues for itself: suspendedFor is read
// only to be validated, and deliberately has no effect on the answer. The
// alternative — the obvious one, where Remaining subtracts the suspension — makes
// suspension a way to buy more time than the plan sells, which is the bug this
// function exists to make impossible. Waking a preview must never be a way to
// reset its expiry, so the budget is whatever it was when the environment started
// and stays that way.
func Remaining(envTTL, suspendedFor time.Duration) (time.Duration, error) {
	if envTTL <= 0 {
		return 0, fmt.Errorf("%w: requested %s", ErrNoTTL, envTTL)
	}
	if suspendedFor < 0 {
		return 0, fmt.Errorf("%w: suspended for %s", ErrNegativeDuration, suspendedFor)
	}
	return envTTL, nil
}

// ExpiresAt returns the absolute moment the environment expires.
//
// It is unchanged by suspension, which is what makes it safe to store: a stored
// expiry computed before a suspension is still the expiry after the resume, and
// no path has to recompute or extend it.
func ExpiresAt(startedAt time.Time, envTTL, suspendedFor time.Duration) (time.Time, error) {
	remaining, err := Remaining(envTTL, suspendedFor)
	if err != nil {
		return time.Time{}, err
	}
	return startedAt.Add(remaining), nil
}

// ResumeDecision is what a resume request must satisfy before it runs.
type ResumeDecision struct {
	// RequiresAdmission reports that capacity must be re-acquired before this
	// environment starts.
	//
	// It is true for any non-zero suspension. Capacity is licensed, not reserved
	// forever: while this environment was stopped, the slot it was holding was
	// free and was almost certainly given to somebody else. Resuming without
	// asking would oversubscribe the fleet, and the oversubscription would only be
	// discovered as a second environment that will not start.
	//
	// A zero suspension does not require admission, because nothing was released:
	// the environment never stopped, so it is resuming in name only.
	RequiresAdmission bool
	// Reason explains the decision in words an operator can act on.
	Reason string
	// TTLRemaining is the lifetime left after the resume. It is never extended.
	TTLRemaining time.Duration
}

// Resume decides what a resume must do.
func Resume(envTTL, suspendedFor time.Duration) (ResumeDecision, error) {
	remaining, err := Remaining(envTTL, suspendedFor)
	if err != nil {
		return ResumeDecision{}, err
	}
	if suspendedFor == 0 {
		return ResumeDecision{
			Reason:       "the environment never stopped, so there is no capacity to re-acquire and no TTL to restore",
			TTLRemaining: remaining,
		}, nil
	}
	return ResumeDecision{
		RequiresAdmission: true,
		Reason: fmt.Sprintf(
			"the environment was suspended for %s, and capacity consumed by other environments while it was stopped must be re-checked",
			suspendedFor),
		TTLRemaining: remaining,
	}, nil
}

// CanResume reports whether there is anything left to wake.
func CanResume(suspendedFor time.Duration, retention Retention) (bool, error) {
	d, err := Decide(suspendedFor, retention)
	if err != nil {
		return false, err
	}
	if d == DecisionPurge {
		return false, fmt.Errorf("%w: suspended for %s against a retention window of %s",
			ErrBeyondRetention, suspendedFor, retention.Duration())
	}
	return true, nil
}
