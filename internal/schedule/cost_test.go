package schedule_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/costmodel"
	"github.com/sanskarpan/Ghostlight/internal/meters"
	"github.com/sanskarpan/Ghostlight/internal/schedule"
)

// rates are the two prices a residual cost is made of. They are stated here
// rather than defaulted in the package because a price invented inside a cost
// function is a price nobody can trace to a publication date.
func rates() schedule.Rates {
	return schedule.Rates{EnvironmentUSDPerHour: 0.044625, StorageUSDPerGBMonth: 0.021}
}

func oneGB() int64 { return 1_000_000_000 }

func week() schedule.Retention { return schedule.DefaultRetention }

// TestResidualBillsStorageAndNotEnvironmentHours is the suspension cost rule: a
// suspended environment is not running, so it occupied no compute, but its bytes
// are still on a provider's disk and are still billed.
func TestResidualBillsStorageAndNotEnvironmentHours(t *testing.T) {
	c, err := schedule.Residual(48*time.Hour, week(), oneGB(), rates())
	if err != nil {
		t.Fatalf("residual: %v", err)
	}
	if c.EnvironmentHours != 0 {
		t.Fatalf("a suspended environment must accrue no environment-hours, got %v", c.EnvironmentHours)
	}
	if c.StorageGBHours != 48 {
		t.Fatalf("one decimal gigabyte for 48 hours is 48 GB-hours, got %v", c.StorageGBHours)
	}
	want := 48 / schedule.HoursPerMonth * 0.021
	if diff := c.StorageUSD - want; diff > 1e-12 || diff < -1e-12 {
		t.Fatalf("storage cost is %v, expected %v", c.StorageUSD, want)
	}
	if c.TotalUSD != c.StorageUSD {
		t.Fatalf("the total must be the storage charge, got %v", c.TotalUSD)
	}
	if c.BeyondRetention {
		t.Fatal("two days is inside a week's retention")
	}

	// The environment-hour rate is present in the input and is still not applied.
	expensive := rates()
	expensive.EnvironmentUSDPerHour = 12
	c2, err := schedule.Residual(48*time.Hour, week(), oneGB(), expensive)
	if err != nil {
		t.Fatalf("residual: %v", err)
	}
	if c2.TotalUSD != c.TotalUSD {
		t.Fatalf("a running rate must not reach a suspended environment: %v vs %v", c2.TotalUSD, c.TotalUSD)
	}
}

// TestResidualUsesTheCostModelMonthAndDecimalGigabytes: the unit a suspended
// environment is billed in has to be the same unit the rest of the system meters
// and prices in, or a suspended preview costs a different amount from a running
// one holding the same bytes.
func TestResidualUsesTheCostModelMonthAndDecimalGigabytes(t *testing.T) {
	if schedule.HoursPerMonth != costmodel.HoursPerMonth {
		t.Fatalf("the billing month must be the cost model's %v, got %v", costmodel.HoursPerMonth, schedule.HoursPerMonth)
	}
	if schedule.BytesPerGigabyte != meters.BytesPerGigabyte {
		t.Fatalf("a gigabyte must be the metered %v bytes, got %v", meters.BytesPerGigabyte, schedule.BytesPerGigabyte)
	}

	month := time.Duration(schedule.HoursPerMonth * float64(time.Hour))
	// The retention has to exceed the billing month, because a residual cost is
	// capped at the retention window and a week's window would cap this case.
	long, err := schedule.NewRetention(60 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("retention: %v", err)
	}

	// One gigabyte held for exactly one billing month is one GB-month of storage.
	c, err := schedule.Residual(month, long, oneGB(), rates())
	if err != nil {
		t.Fatalf("residual: %v", err)
	}
	if diff := c.StorageUSD - 0.021; diff > 1e-12 || diff < -1e-12 {
		t.Fatalf("a gigabyte-month must cost the storage rate exactly, got %v", c.StorageUSD)
	}

	// Binary gigabytes are 1.07 decimal ones, so a 1 GiB retention costs more than
	// a 1 GB retention. This is the 7.4% the meters package refuses to lose.
	giB := int64(1) << 30
	big, err := schedule.Residual(month, long, giB, rates())
	if err != nil {
		t.Fatalf("residual: %v", err)
	}
	if ratio := big.StorageUSD / c.StorageUSD; ratio < 1.07 || ratio > 1.08 {
		t.Fatalf("a gibibyte must price at 1.074 decimal gigabytes, got %v", ratio)
	}
}

// TestResidualAccruesLinearlyWithSuspendedTime: storage is a product of bytes and
// time, so doubling the suspension doubles the cost, and the total never falls as
// a suspension grows.
func TestResidualAccruesLinearlyWithSuspendedTime(t *testing.T) {
	prev := -1.0
	for _, hours := range []float64{0, 1, 6, 24, 72, 168} {
		c, err := schedule.Residual(time.Duration(hours*float64(time.Hour)), week(), oneGB(), rates())
		if err != nil {
			t.Fatalf("residual at %vh: %v", hours, err)
		}
		if c.StorageUSD < prev {
			t.Fatalf("storage cost fell from %v to %v at %vh", prev, c.StorageUSD, hours)
		}
		prev = c.StorageUSD
	}
	c1, _ := schedule.Residual(time.Hour, week(), oneGB(), rates())
	c2, _ := schedule.Residual(2*time.Hour, week(), oneGB(), rates())
	if diff := c2.StorageUSD - 2*c1.StorageUSD; diff > 1e-12 || diff < -1e-12 {
		t.Fatalf("two hours must cost twice one hour, got %v and %v", c1.StorageUSD, c2.StorageUSD)
	}
}

// TestResidualIsCappedAtTheRetentionWindow: past retention the data was promised
// destroyed, so charging for it further would bill for bytes that policy says no
// longer exist, and the caller is told instead.
func TestResidualIsCappedAtTheRetentionWindow(t *testing.T) {
	inside, err := schedule.Residual(week().Duration(), week(), oneGB(), rates())
	if err != nil {
		t.Fatalf("residual: %v", err)
	}
	beyond, err := schedule.Residual(30*24*time.Hour, week(), oneGB(), rates())
	if err != nil {
		t.Fatalf("residual: %v", err)
	}
	if beyond.StorageUSD != inside.StorageUSD {
		t.Fatalf("a suspension past retention must not bill past retention: %v vs %v", beyond.StorageUSD, inside.StorageUSD)
	}
	if !beyond.BeyondRetention {
		t.Fatal("a suspension past retention must be reported, because the purge did not happen")
	}
	if inside.BeyondRetention {
		t.Fatal("a suspension of exactly the retention window is inside it for costing")
	}
	if beyond.SuspendedFor != 30*24*time.Hour {
		t.Fatalf("the elapsed suspension must still be reported, got %s", beyond.SuspendedFor)
	}
}

// TestAZeroRetentionIsRefused: zero retention is immediate destruction wearing a
// policy's name, and it must be asked for through the purge path.
func TestAZeroRetentionIsRefused(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Hour} {
		if _, err := schedule.NewRetention(d); !errors.Is(err, schedule.ErrInvalidRetention) {
			t.Errorf("NewRetention(%s) must be refused, got %v", d, err)
		}
		if _, err := schedule.Residual(time.Hour, schedule.Retention(d), oneGB(), rates()); !errors.Is(err, schedule.ErrInvalidRetention) {
			t.Errorf("Residual with a %s retention must be refused, got %v", d, err)
		}
		if _, err := schedule.Decide(time.Hour, schedule.Retention(d)); !errors.Is(err, schedule.ErrInvalidRetention) {
			t.Errorf("Decide with a %s retention must be refused, got %v", d, err)
		}
		if _, err := schedule.PurgeAt(time.Unix(0, 0), schedule.Retention(d)); !errors.Is(err, schedule.ErrInvalidRetention) {
			t.Errorf("PurgeAt with a %s retention must be refused, got %v", d, err)
		}
	}
	if _, err := schedule.NewRetention(time.Hour); err != nil {
		t.Fatalf("an hour of retention is legitimate: %v", err)
	}
}

// TestANegativeQuantityIsRefused: a clock or counter error must not be rounded
// into a legal-looking answer.
func TestANegativeQuantityIsRefused(t *testing.T) {
	if _, err := schedule.Residual(time.Hour, week(), -1, rates()); !errors.Is(err, schedule.ErrInvalidQuantity) {
		t.Fatalf("negative bytes must be refused, got %v", err)
	}
	for _, d := range []time.Duration{-time.Nanosecond, -time.Hour} {
		if _, err := schedule.Residual(d, week(), oneGB(), rates()); !errors.Is(err, schedule.ErrNegativeDuration) {
			t.Errorf("Residual with a %s suspension must be refused, got %v", d, err)
		}
		if _, err := schedule.Decide(d, week()); !errors.Is(err, schedule.ErrNegativeDuration) {
			t.Errorf("Decide with a %s suspension must be refused, got %v", d, err)
		}
	}
	// An empty environment is free, not an error: it is a real state.
	c, err := schedule.Residual(time.Hour, week(), 0, rates())
	if err != nil {
		t.Fatalf("no retained bytes is a legal state: %v", err)
	}
	if c.StorageUSD != 0 || c.EnvironmentHours != 0 {
		t.Fatalf("nothing retained must cost nothing, got %+v", c)
	}
}

// TestAnUnpricedRateIsRefused: a cost that cannot be priced is refused rather than
// reported as free, which is the same rule the cost model applies to a line its
// dataset cannot resolve.
func TestAnUnpricedRateIsRefused(t *testing.T) {
	noStorage := schedule.Rates{EnvironmentUSDPerHour: 0.044625}
	if _, err := schedule.Residual(time.Hour, week(), oneGB(), noStorage); !errors.Is(err, schedule.ErrUnpricedRate) {
		t.Fatalf("an unpriced storage rate must be refused, got %v", err)
	}
	negative := schedule.Rates{EnvironmentUSDPerHour: -1, StorageUSDPerGBMonth: 0.021}
	if _, err := schedule.Residual(time.Hour, week(), oneGB(), negative); !errors.Is(err, schedule.ErrUnpricedRate) {
		t.Fatalf("a negative rate must be refused, got %v", err)
	}
	// An absent environment-hour rate is legal, because a suspended environment
	// bills none of them and so cannot be corrupted by one.
	if _, err := schedule.Residual(time.Hour, week(), oneGB(), schedule.Rates{StorageUSDPerGBMonth: 0.021}); err != nil {
		t.Fatalf("an absent running rate must not be fatal: %v", err)
	}
}

// TestTheStorageRateComesFromTheCapturedPriceDataset: the price is read from the
// reference dataset rather than written here, so it carries a source URL and a
// publication date.
func TestTheStorageRateComesFromTheCapturedPriceDataset(t *testing.T) {
	p := filepath.Join("..", "..", "catalog", "pricing", "aws-us-east-1.json")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("price reference not present at %s; run: go run ./tools/pricing", p)
	}
	tbl, err := costmodel.Load(p)
	if err != nil {
		t.Fatalf("load prices: %v", err)
	}

	r, err := schedule.RatesFromTable(tbl)
	if err != nil {
		t.Fatalf("rates from table: %v", err)
	}
	// S3 Standard storage, us-east-1, as captured on 2026-10-07.
	if diff := r.StorageUSDPerGBMonth - 0.021; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("the captured S3 storage rate is 0.021 per GB-month, got %v", r.StorageUSDPerGBMonth)
	}
	if _, err := schedule.RatesFromTable(nil); !errors.Is(err, schedule.ErrUnpricedRate) {
		t.Fatalf("an absent dataset must be refused, got %v", err)
	}
}

// TestTheRetentionBoundaryIsInclusive is the boundary convention stated once and
// pinned on both sides: at exactly the retention the data is already gone.
func TestTheRetentionBoundaryIsInclusive(t *testing.T) {
	window := schedule.DefaultRetention

	before, err := schedule.Decide(window.Duration()-time.Nanosecond, window)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if before != schedule.DecisionHold {
		t.Fatalf("a nanosecond inside the window must hold, got %s", before)
	}

	at, err := schedule.Decide(window.Duration(), window)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if at != schedule.DecisionPurge {
		t.Fatalf("the boundary itself must purge, got %s", at)
	}

	after, err := schedule.Decide(window.Duration()+time.Nanosecond, window)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if after != schedule.DecisionPurge {
		t.Fatalf("past the window must purge, got %s", after)
	}

	// An environment that is not suspended has nothing to purge.
	if _, err := schedule.Decide(-time.Nanosecond, window); !errors.Is(err, schedule.ErrNegativeDuration) {
		t.Fatalf("a negative suspension must be refused, got %v", err)
	}
	if got := mustHold(t, 0, window); got != schedule.DecisionHold {
		t.Fatalf("an environment that is not suspended must never be purged, got %s", got)
	}
}

// mustHold is the assertion that a suspension inside its window is never a purge,
// written once so the boundary test reads as a boundary test.
func mustHold(t *testing.T, suspendedFor time.Duration, retention schedule.Retention) schedule.Decision {
	t.Helper()
	d, err := schedule.Decide(suspendedFor, retention)
	if err != nil {
		t.Fatalf("decide %s: %v", suspendedFor, err)
	}
	return d
}

// TestASuspensionInsideItsWindowIsNeverPurge is the property, sampled rather than
// enumerated: retention exists to be a maximum, and an implementation that drifts
// towards purging early destroys previews somebody is coming back to.
func TestASuspensionInsideItsWindowIsNeverPurge(t *testing.T) {
	window := schedule.DefaultRetention
	for _, suspendedFor := range []time.Duration{
		0, time.Nanosecond, time.Second, time.Minute, time.Hour,
		24 * time.Hour, 3 * 24 * time.Hour, window.Duration() - time.Nanosecond,
	} {
		if got := mustHold(t, suspendedFor, window); got != schedule.DecisionHold {
			t.Fatalf("a suspension of %s must be held, got %s", suspendedFor, got)
		}
	}
	for _, suspendedFor := range []time.Duration{
		window.Duration(), window.Duration() + time.Nanosecond, 30 * 24 * time.Hour,
	} {
		d, err := schedule.Decide(suspendedFor, window)
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
		if d != schedule.DecisionPurge {
			t.Fatalf("a suspension of %s must purge, got %s", suspendedFor, d)
		}
	}
}

// TestTheDefaultRetentionIsAWeekAndHonoursIt: the default has to be a usable
// window, and it has to behave like every other retention.
func TestTheDefaultRetentionIsAWeekAndHonoursIt(t *testing.T) {
	if week().Duration() != 7*24*time.Hour {
		t.Fatalf("the default retention is a week, got %s", week().Duration())
	}
	if err := week().Validate(); err != nil {
		t.Fatalf("the default retention must be valid: %v", err)
	}
	if got := mustHold(t, week().Duration()-time.Second, week()); got != schedule.DecisionHold {
		t.Fatalf("a second inside the default window must hold, got %s", got)
	}
	d, err := schedule.Decide(week().Duration(), week())
	if err != nil || d != schedule.DecisionPurge {
		t.Fatalf("the default window must purge at its end, got %s (%v)", d, err)
	}
}

// TestThePurgeMomentIsTheEndOfTheWindow: the moment is derived, not tracked, so a
// suspended environment's data is not retained for a window plus a scheduling tick.
func TestThePurgeMomentIsTheEndOfTheWindow(t *testing.T) {
	suspendedAt := time.Date(2026, 7, 4, 9, 30, 0, 0, time.UTC)
	at, err := schedule.PurgeAt(suspendedAt, week())
	if err != nil {
		t.Fatalf("purge at: %v", err)
	}
	if !at.Equal(suspendedAt.Add(7 * 24 * time.Hour)) {
		t.Fatalf("the purge moment must be the end of the window, got %s", at)
	}
	if d, err := schedule.DecideAt(suspendedAt, at.Add(-time.Nanosecond), week()); err != nil || d != schedule.DecisionHold {
		t.Fatalf("a nanosecond before the purge moment must hold, got %s (%v)", d, err)
	}
	if d, err := schedule.DecideAt(suspendedAt, at, week()); err != nil || d != schedule.DecisionPurge {
		t.Fatalf("the purge moment itself must purge, got %s (%v)", d, err)
	}
	if _, err := schedule.DecideAt(suspendedAt, suspendedAt.Add(-time.Hour), week()); !errors.Is(err, schedule.ErrNegativeDuration) {
		t.Fatalf("a clock that runs backwards must be refused, got %v", err)
	}
}

// TestSuspensionDoesNotConsumeTTL is the requirement most likely to be got wrong:
// an environment suspended for thirty days on a twenty-four hour lifetime must
// still have its whole twenty-four hours when it wakes. The obvious
// implementation — subtracting the suspension from the remaining budget — makes
// suspension a way to buy time the plan does not sell.
func TestSuspensionDoesNotConsumeTTL(t *testing.T) {
	const ttl = 24 * time.Hour

	remaining, err := schedule.Remaining(ttl, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("remaining: %v", err)
	}
	if remaining != ttl {
		t.Fatalf("30 days of suspension must leave 24h of TTL, got %s", remaining)
	}

	d, err := schedule.Resume(ttl, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if d.TTLRemaining != ttl {
		t.Fatalf("a resume must not restart the clock, got %s remaining", d.TTLRemaining)
	}
}

// TestTheAbsoluteExpiryIsIdenticalAcrossASuspendResumeCycle: the expiry a customer
// was shown before the suspension is the expiry that applies after the wake, so no
// stored deadline has to be recomputed or extended on the resume path.
func TestTheAbsoluteExpiryIsIdenticalAcrossASuspendResumeCycle(t *testing.T) {
	started := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	const ttl = 24 * time.Hour

	before, err := schedule.ExpiresAt(started, ttl, 0)
	if err != nil {
		t.Fatalf("expiry before suspension: %v", err)
	}
	if !before.Equal(started.Add(ttl)) {
		t.Fatalf("expiry must be start plus TTL, got %s", before)
	}

	for _, suspendedFor := range []time.Duration{time.Second, 30 * 24 * time.Hour, 365 * 24 * time.Hour} {
		after, err := schedule.ExpiresAt(started, ttl, suspendedFor)
		if err != nil {
			t.Fatalf("expiry after %s of suspension: %v", suspendedFor, err)
		}
		if !after.Equal(before) {
			t.Fatalf("a %s suspension moved the expiry from %s to %s", suspendedFor, before, after)
		}
	}
}

// TestRemainingIsInvariantInTheSuspension is the property, sampled across the
// range that matters: from not-yet-suspended to several years of suspension.
func TestRemainingIsInvariantInTheSuspension(t *testing.T) {
	const ttl = 24 * time.Hour
	for _, suspendedFor := range []time.Duration{
		0, time.Nanosecond, time.Second, time.Minute, 12 * time.Hour,
		ttl - time.Nanosecond, ttl, 30 * 24 * time.Hour, 10 * 365 * 24 * time.Hour,
	} {
		got, err := schedule.Remaining(ttl, suspendedFor)
		if err != nil {
			t.Fatalf("remaining after %s: %v", suspendedFor, err)
		}
		if got != ttl {
			t.Fatalf("a %s suspension changed the remaining TTL to %s", suspendedFor, got)
		}
	}
}

// TestAMissingLifetimeIsRefused: a zero lifetime is not a lifetime, and both
// readings of it are harmful.
func TestAMissingLifetimeIsRefused(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Hour} {
		if _, err := schedule.Remaining(ttl, 0); !errors.Is(err, schedule.ErrNoTTL) {
			t.Errorf("Remaining with a %s lifetime must be refused, got %v", ttl, err)
		}
		if _, err := schedule.ExpiresAt(time.Unix(0, 0), ttl, 0); !errors.Is(err, schedule.ErrNoTTL) {
			t.Errorf("ExpiresAt with a %s lifetime must be refused, got %v", ttl, err)
		}
		if _, err := schedule.Resume(ttl, time.Hour); !errors.Is(err, schedule.ErrNoTTL) {
			t.Errorf("Resume with a %s lifetime must be refused, got %v", ttl, err)
		}
	}
	if _, err := schedule.Remaining(time.Hour, -time.Second); !errors.Is(err, schedule.ErrNegativeDuration) {
		t.Fatalf("a negative suspension must be refused, got %v", err)
	}
}

// TestResumeRequiresAdmissionAfterAnyNonZeroSuspension: capacity is licensed, not
// reserved forever, so any environment that actually stopped has to re-check it.
// A zero suspension released nothing and therefore re-acquires nothing.
func TestResumeRequiresAdmissionAfterAnyNonZeroSuspension(t *testing.T) {
	cases := []struct {
		name         string
		suspendedFor time.Duration
		want         bool
	}{
		{"never suspended", 0, false},
		{"one nanosecond", time.Nanosecond, true},
		{"one second", time.Second, true},
		{"a month", 30 * 24 * time.Hour, true},
		{"a year", 365 * 24 * time.Hour, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := schedule.Resume(24*time.Hour, c.suspendedFor)
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			if d.RequiresAdmission != c.want {
				t.Fatalf("RequiresAdmission = %v, want %v (%s)", d.RequiresAdmission, c.want, d.Reason)
			}
			if d.Reason == "" {
				t.Fatal("a resume decision must explain itself")
			}
			if d.TTLRemaining != 24*time.Hour {
				t.Fatalf("the TTL must be untouched, got %s", d.TTLRemaining)
			}
		})
	}
}

// TestThereIsNothingToWakePastRetention: a resume after the window has closed is
// refused, because the environment it would wake no longer exists.
func TestThereIsNothingToWakePastRetention(t *testing.T) {
	ok, err := schedule.CanResume(week().Duration()-time.Nanosecond, week())
	if err != nil || !ok {
		t.Fatalf("a suspension inside its window must be resumable, got %v (%v)", ok, err)
	}
	if _, err := schedule.CanResume(week().Duration(), week()); !errors.Is(err, schedule.ErrBeyondRetention) {
		t.Fatalf("the boundary itself has nothing left to wake, got %v", err)
	}
	if _, err := schedule.CanResume(30*24*time.Hour, week()); !errors.Is(err, schedule.ErrBeyondRetention) {
		t.Fatalf("a month past retention must be refused, got %v", err)
	}
	if _, err := schedule.CanResume(-time.Second, week()); !errors.Is(err, schedule.ErrNegativeDuration) {
		t.Fatalf("a negative suspension must be refused, got %v", err)
	}
	if _, err := schedule.CanResume(time.Hour, 0); !errors.Is(err, schedule.ErrInvalidRetention) {
		t.Fatalf("a zero retention must be refused, got %v", err)
	}
}
