package meters

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// clock is a settable provider clock. Every time-dependent rule in this package is
// stated against provider time rather than the host clock, so a host with a skewed
// clock cannot push an event outside the provider's window.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock(t time.Time) *clock { return &clock{t: t} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var base = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func envInput(c *clock, env, gen string, value float64, at time.Time) EventInput {
	return EventInput{
		Meter:       MeterEnvironmentHours,
		CustomerID:  "cus_1",
		DedupParts:  []string{env, gen, at.UTC().Format("2006-01-02T15")},
		Value:       value,
		OccurredAt:  at,
		WindowStart: at.Add(-time.Hour),
		WindowEnd:   at,
	}
}

func TestARetryRecordsNothingNew(t *testing.T) {
	c := newClock(base)
	l := NewLedger(c.Now)
	in := envInput(c, "env_1", "gen_1", 2, base.Add(-time.Minute))

	first, inserted, err := l.Append(in)
	if err != nil || !inserted {
		t.Fatalf("first append: %v inserted=%v", err, inserted)
	}
	second, inserted, err := l.Append(in)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if inserted {
		t.Fatal("a retry recorded a second event")
	}
	if second.ID != first.ID {
		t.Fatalf("retry produced a different identifier: %s then %s", first.ID, second.ID)
	}
	if l.Len() != 1 {
		t.Fatalf("ledger holds %d events, want 1", l.Len())
	}
}

// The provider deduplicates for roughly 24 hours, which is shorter than our retry
// horizon, so concurrency in the ledger is the real guarantee.
func TestConcurrentRetriesProduceOneEvent(t *testing.T) {
	c := newClock(base)
	l := NewLedger(c.Now)
	in := envInput(c, "env_1", "gen_1", 2, base.Add(-time.Minute))

	var wg sync.WaitGroup
	var mu sync.Mutex
	insertedCount := 0
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, inserted, err := l.Append(in)
			if err != nil {
				t.Errorf("append: %v", err)
				return
			}
			if inserted {
				mu.Lock()
				insertedCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if insertedCount != 1 {
		t.Fatalf("%d concurrent retries inserted, want 1", insertedCount)
	}
	if l.Len() != 1 {
		t.Fatalf("ledger holds %d events, want 1", l.Len())
	}
}

func TestAnUnreportableEventIsRefusedRatherThanDropped(t *testing.T) {
	c := newClock(base)
	l := NewLedger(c.Now)
	_, _, err := l.Append(envInput(c, "env_1", "gen_1", 2, base.Add(-36*24*time.Hour)))
	mustErr(t, err, ErrTimestampTooOld, "an event the provider would reject")
	if l.Len() != 0 {
		t.Fatalf("ledger holds %d events, want 0", l.Len())
	}
}

func TestRollupsAreRecomputedNotIncremented(t *testing.T) {
	c := newClock(base)
	l := NewLedger(c.Now)
	start := base.Add(-24 * time.Hour)
	for i := 1; i <= 3; i++ {
		if _, _, err := l.Append(envInput(c, "env_1", fmt.Sprintf("gen_%d", i), float64(i), start.Add(time.Duration(i)*time.Hour))); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	first, err := l.Rollup("cus_1", MeterEnvironmentHours, start, base)
	if err != nil {
		t.Fatalf("rollup: %v", err)
	}
	if first.Value != 6 {
		t.Fatalf("rollup %v, want 6", first.Value)
	}
	// Recomputing after any restatement must be self-healing: same answer, every time.
	for i := 0; i < 3; i++ {
		again, err := l.Rollup("cus_1", MeterEnvironmentHours, start, base)
		if err != nil {
			t.Fatalf("rollup: %v", err)
		}
		if again != first {
			t.Fatalf("rollup drifted: %+v then %+v", first, again)
		}
	}
}

// Summing a gauge produces a total that grows with the length of the month rather
// than with anything a customer did.
func TestConcurrencyRollsUpToItsPeakNotItsSum(t *testing.T) {
	c := newClock(base)
	l := NewLedger(c.Now)
	spec := mustSpec(t, MeterConcurrencyPeak)
	for i, v := range []float64{3, 9, 4} {
		at := base.Add(-time.Duration(3-i) * time.Hour)
		if _, _, err := l.Append(EventInput{
			Meter: MeterConcurrencyPeak, CustomerID: "cus_1",
			DedupParts: []string{at.UTC().Format("2006-01-02T15")},
			Value:      v, OccurredAt: at,
			WindowStart: at, WindowEnd: at.Add(time.Hour),
		}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	_ = spec
	r, err := l.Rollup("cus_1", MeterConcurrencyPeak, base.Add(-24*time.Hour), base)
	if err != nil {
		t.Fatalf("rollup: %v", err)
	}
	if r.Value != 9 {
		t.Fatalf("peak %v, want 9 (the sum would be 16)", r.Value)
	}
	if r.Samples != 3 {
		t.Fatalf("samples %d, want 3", r.Samples)
	}
}

func TestRollupsAreScopedToOneCustomerAndMeter(t *testing.T) {
	c := newClock(base)
	l := NewLedger(c.Now)
	at := base.Add(-time.Hour)
	if _, _, err := l.Append(envInput(c, "env_1", "gen_1", 2, at)); err != nil {
		t.Fatalf("append: %v", err)
	}
	other := envInput(c, "env_2", "gen_1", 7, at)
	other.CustomerID = "cus_2"
	if _, _, err := l.Append(other); err != nil {
		t.Fatalf("append: %v", err)
	}
	r, err := l.Rollup("cus_1", MeterEnvironmentHours, base.Add(-24*time.Hour), base)
	if err != nil {
		t.Fatalf("rollup: %v", err)
	}
	if r.Value != 2 {
		t.Fatalf("cus_1 rollup %v, want 2", r.Value)
	}
}

func TestACorrectionReferencesTheOriginalAndAdjustsTheTotal(t *testing.T) {
	c := newClock(base)
	l := NewLedger(c.Now)
	at := base.Add(-time.Hour)
	original, _, err := l.Append(envInput(c, "env_1", "gen_1", 6, at))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	fix, inserted, err := Correct(l, original.ID, -1.5, "cleanup verified 90 minutes early", base.Add(-time.Minute))
	if err != nil || !inserted {
		t.Fatalf("correction: %v inserted=%v", err, inserted)
	}
	if !fix.Correction() || fix.Supersedes != original.ID {
		t.Fatalf("correction does not reference the original: %+v", fix)
	}
	r, err := l.Rollup("cus_1", MeterEnvironmentHours, base.Add(-24*time.Hour), base)
	if err != nil {
		t.Fatalf("rollup: %v", err)
	}
	if r.Value != 4.5 {
		t.Fatalf("corrected rollup %v, want 4.5", r.Value)
	}
	// The original row is untouched: a disputed invoice must be replayable.
	if l.Len() != 2 {
		t.Fatalf("ledger holds %d events, want 2 (the original plus the correction)", l.Len())
	}
}

func TestACorrectionWithoutAReasonOrOriginalIsRefused(t *testing.T) {
	c := newClock(base)
	l := NewLedger(c.Now)
	original, _, err := l.Append(envInput(c, "env_1", "gen_1", 6, base.Add(-time.Hour)))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	// A correction without a reason is indistinguishable from a bug.
	_, _, err = Correct(l, original.ID, -1, "", base)
	mustErr(t, err, ErrCorrectionWithoutReason, "reasonless correction")

	_, _, err = Correct(l, original.ID, 0, "nothing actually changed", base)
	mustErr(t, err, ErrNonPositiveValue, "zero correction")

	_, _, err = Correct(l, "gl1_environment_hours_deadbeef", -1, "typo in the identifier", base)
	mustErr(t, err, ErrUnknownOriginal, "correction of an unknown event")

	if l.Len() != 1 {
		t.Fatalf("refused corrections left %d events, want 1", l.Len())
	}
}

func TestEventsReplayInAStableOrder(t *testing.T) {
	c := newClock(base)
	l := NewLedger(c.Now)
	at := base.Add(-time.Hour)
	for i := 0; i < 5; i++ {
		if _, _, err := l.Append(envInput(c, "env_1", fmt.Sprintf("gen_%d", i), 1, at)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	first := l.Events()
	for i := 0; i < 3; i++ {
		again := l.Events()
		for j := range first {
			if first[j].ID != again[j].ID {
				t.Fatalf("replay order drifted at %d", j)
			}
		}
	}
}

func TestTheOutboxDeliversEachEventOnce(t *testing.T) {
	c := newClock(base)
	l := NewLedger(c.Now)
	e, _, err := l.Append(envInput(c, "env_1", "gen_1", 2, base.Add(-time.Minute)))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	o := NewOutbox(c.Now)
	if err := o.Enqueue(e); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := o.Enqueue(e); err != nil {
		t.Fatalf("re-enqueue: %v", err)
	}
	if got := len(o.Ready()); got != 1 {
		t.Fatalf("outbox offers %d deliveries, want 1", got)
	}
	if err := o.MarkSent(e.ID); err != nil {
		t.Fatalf("mark sent: %v", err)
	}
	if got := len(o.Ready()); got != 0 {
		t.Fatalf("a sent event was offered again %d times", got)
	}
}

func TestAFailedDeliveryKeepsItsReasonAndTheSameIdentifier(t *testing.T) {
	c := newClock(base)
	l := NewLedger(c.Now)
	e, _, err := l.Append(envInput(c, "env_1", "gen_1", 2, base.Add(-time.Minute)))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	o := NewOutbox(c.Now)
	_ = o.Enqueue(e)
	if err := o.MarkFailed(e.ID, fmt.Errorf("409 too_many_concurrent_requests")); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	ready := o.Ready()
	if len(ready) != 1 {
		t.Fatalf("outbox offers %d deliveries, want 1", len(ready))
	}
	if !contains(ready[0].LastError, "409") {
		t.Fatalf("reason discarded: %q", ready[0].LastError)
	}
	// The identifier survives every retry, so the provider sees one fact, not many.
	if ready[0].Event.ID != e.ID {
		t.Fatalf("retry changed the identifier: %s then %s", e.ID, ready[0].Event.ID)
	}
	if ready[0].Status != StatusFailed {
		t.Fatalf("status %q, want %q", ready[0].Status, StatusFailed)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || len(needle) == 0 ||
		indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// Once the provider's deduplication window has lapsed, a retry is a genuinely new
// provider-side event. Flagging it keeps the outbox from pretending otherwise.
func TestALongOutageMarksDeliveriesAsReplayed(t *testing.T) {
	c := newClock(base)
	l := NewLedger(c.Now)
	e, _, err := l.Append(envInput(c, "env_1", "gen_1", 2, base.Add(-time.Minute)))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	o := NewOutbox(c.Now)
	_ = o.Enqueue(e)
	if err := o.MarkFailed(e.ID, fmt.Errorf("503")); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	if ready := o.Ready(); ready[0].Replayed {
		t.Fatal("a delivery inside the deduplication window was marked replayed")
	}
	c.Advance(30 * time.Hour)
	ready := o.Ready()
	if len(ready) != 1 || !ready[0].Replayed {
		t.Fatalf("after a 30 hour outage the delivery is not flagged as replayed: %+v", ready)
	}
	if ready[0].Event.ID != e.ID {
		t.Fatal("the replay changed the identifier")
	}
}

func TestBackoffGrowsAndIsBounded(t *testing.T) {
	if got := Backoff(0); got != 30*time.Second {
		t.Fatalf("first attempt waits %s, want 30s", got)
	}
	if got := Backoff(1); got != 30*time.Second {
		t.Fatalf("attempt 1 waits %s, want 30s", got)
	}
	if got := Backoff(2); got != time.Minute {
		t.Fatalf("attempt 2 waits %s, want 1m", got)
	}
	if got := Backoff(20); got != time.Hour {
		t.Fatalf("attempt 20 waits %s, want the 1h cap", got)
	}
}

func readyFacts(f Facts) Facts {
	f.CustomerID = "cus_1"
	f.Environment = "env_1"
	f.Generation = "gen_1"
	f.AdmittedAt = base.Add(-time.Hour)
	f.CleanedUpAt = base
	return f
}

func TestAnEnvironmentRefusedAtAdmissionBillsNothing(t *testing.T) {
	// Nothing was provisioned, so nothing is charged. Charging for work never done is
	// the fastest way to lose a customer.
	f := readyFacts(Facts{Admitted: false})
	charges, err := Charges(f, func() time.Time { return base })
	if err != nil {
		t.Fatalf("charges: %v", err)
	}
	if len(charges) != 0 {
		t.Fatalf("an admission failure produced %d charges: %+v", len(charges), charges)
	}
}

func TestACustomerSideGateFailureStillBillsConsumedCapacity(t *testing.T) {
	f := readyFacts(Facts{Admitted: true, GateRejected: true, RunID: "run_1"})
	charges, err := Charges(f, func() time.Time { return base })
	if err != nil {
		t.Fatalf("charges: %v", err)
	}
	if len(charges) != 1 || charges[0].Meter != MeterEnvironmentHours {
		t.Fatalf("a gate rejection produced %+v", charges)
	}
	// The distinction is whose fault the failure was, not whether capacity was used.
	for _, c := range charges {
		if c.Meter == MeterExperimentRuns {
			t.Fatal("a rejected gate admitted no experiment and must not be billed as one")
		}
	}
}

func TestASuccessfulGenerationBillsHoursStorageAndItsRun(t *testing.T) {
	f := readyFacts(Facts{Admitted: true, RunID: "run_1", RetainedBytes: 2 * BytesPerGigabyte})
	charges, err := Charges(f, func() time.Time { return base })
	if err != nil {
		t.Fatalf("charges: %v", err)
	}
	if len(charges) != 3 {
		t.Fatalf("expected three charges, got %+v", charges)
	}
	byMeter := map[Meter]float64{}
	for _, c := range charges {
		byMeter[c.Meter] = c.Value
	}
	if byMeter[MeterEnvironmentHours] != 1 {
		t.Fatalf("environment hours %v, want 1", byMeter[MeterEnvironmentHours])
	}
	if byMeter[MeterStorageGBHours] != 2 {
		t.Fatalf("storage %v GB-hours, want 2", byMeter[MeterStorageGBHours])
	}
	if byMeter[MeterExperimentRuns] != 1 {
		t.Fatalf("experiment runs %v, want 1", byMeter[MeterExperimentRuns])
	}
}

// Suspension is not destruction: retained resources cost money, a stopped machine
// does not.
func TestSuspensionBillsStorageButNotEnvironmentHours(t *testing.T) {
	f := readyFacts(Facts{
		Admitted: true, RunID: "run_1", RetainedBytes: BytesPerGigabyte,
		Suspended: []Interval{{Start: base.Add(-45 * time.Minute), End: base.Add(-15 * time.Minute)}},
	})
	charges, err := Charges(f, func() time.Time { return base })
	if err != nil {
		t.Fatalf("charges: %v", err)
	}
	byMeter := map[Meter]float64{}
	for _, c := range charges {
		byMeter[c.Meter] = c.Value
	}
	if byMeter[MeterEnvironmentHours] != 30.0/60.0 {
		t.Fatalf("live hours %v, want 0.5", byMeter[MeterEnvironmentHours])
	}
	// Storage covers the whole retained lifetime, suspension included.
	if byMeter[MeterStorageGBHours] != 1 {
		t.Fatalf("storage %v GB-hours, want 1 for the full hour retained", byMeter[MeterStorageGBHours])
	}
}

func TestShortGenerationsBillTheMinimumIncrementEndToEnd(t *testing.T) {
	f := readyFacts(Facts{Admitted: true, RunID: "run_1"})
	f.AdmittedAt = base.Add(-3 * time.Second)
	charges, err := Charges(f, func() time.Time { return base })
	if err != nil {
		t.Fatalf("charges: %v", err)
	}
	if charges[0].Value != 5.0/60.0 {
		t.Fatalf("a three-second environment billed %v hours, want the 5 minute minimum", charges[0].Value)
	}
}

// The counting rule is admission to verified cleanup. Billing earlier charges for
// teardown that has not been proven and would double-count when cleanup lands.
func TestAGenerationIsNotBilledBeforeVerifiedCleanup(t *testing.T) {
	f := readyFacts(Facts{Admitted: true, RunID: "run_1"})
	f.CleanedUpAt = time.Time{}
	_, err := Charges(f, func() time.Time { return base })
	mustErr(t, err, ErrUncleanedGeneration, "billing before cleanup")

	f.CleanedUpAt = f.AdmittedAt.Add(-time.Hour)
	_, err = Charges(f, func() time.Time { return base })
	mustErr(t, err, ErrUncleanedGeneration, "cleanup before admission")
}

func TestChargesAreRefusedWhenTheProviderWouldRejectTheWindow(t *testing.T) {
	f := readyFacts(Facts{Admitted: true, RunID: "run_1", RetainedBytes: BytesPerGigabyte})
	f.AdmittedAt = base.Add(-40 * 24 * time.Hour)
	f.CleanedUpAt = base.Add(-39 * 24 * time.Hour)
	_, err := Charges(f, func() time.Time { return base })
	mustErr(t, err, ErrTimestampTooOld, "a charge the provider would reject")
}

// Billability is decided once, at the terminal transition, and the decision is stored.
// Re-deriving it at invoice time would let a policy change rewrite history.
func TestTheSameFactsAlwaysProduceTheSameCharges(t *testing.T) {
	f := readyFacts(Facts{Admitted: true, RunID: "run_1", RetainedBytes: 3 * BytesPerGigabyte})
	first, err := Charges(f, func() time.Time { return base })
	if err != nil {
		t.Fatalf("charges: %v", err)
	}
	c := newClock(base)
	c.Advance(72 * time.Hour)
	again, err := Charges(f, c.Now)
	if err != nil {
		t.Fatalf("charges three days later: %v", err)
	}
	for i := range first {
		if first[i].DedupParts != nil && fmt.Sprint(first[i].DedupParts) != fmt.Sprint(again[i].DedupParts) {
			t.Fatalf("charge %d changed identity: %v then %v", i, first[i].DedupParts, again[i].DedupParts)
		}
	}
}
