package meters

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

// mustSpec fails the test rather than returning a zero spec, so a missing meter is
// reported as a missing meter instead of as a cascade of nil dereferences.
func mustSpec(t *testing.T, m Meter) Spec {
	t.Helper()
	s, ok := Lookup(m)
	if !ok {
		t.Fatalf("no spec for %s", m)
	}
	return s
}

func mustErr(t *testing.T, err error, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

func TestTheRegistryIsInternallyConsistent(t *testing.T) {
	if err := ValidateRegistry(); err != nil {
		t.Fatalf("registry: %v", err)
	}
}

func TestExactlyThreeMetersAreBilled(t *testing.T) {
	got := BilledMeters()
	want := []Meter{MeterEnvironmentHours, MeterExperimentRuns, MeterStorageGBHours}
	if len(got) != len(want) {
		t.Fatalf("billed meters: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("billed meters: got %v, want %v", got, want)
		}
	}
}

// The whole point of ADR G-036: concurrency is licensed capacity. If a future edit
// reclassifies it as billable, this fails before a customer sees the line.
func TestConcurrencyIsLicensedCapacityNotUsage(t *testing.T) {
	spec := mustSpec(t, MeterConcurrencyPeak)
	if spec.Billed {
		t.Fatal("concurrency_peak must not be billable")
	}
	if _, err := spec.BuildPayload(Payload{CustomerID: "cus_1", Value: 7}); !errors.Is(err, ErrNotBillable) {
		t.Fatalf("billable payload for a gauge: got %v, want %v", err, ErrNotBillable)
	}
}

func TestAGaugeMayNeverAggregateBySum(t *testing.T) {
	bad := Spec{Meter: "made_up", Formula: FormulaSum, Shape: ShapeGauge, Billed: true, KeyFields: []string{"window"}}
	mustErr(t, bad.Validate(), ErrGaugeAggregatedAsSum, "gauge summed")

	for _, m := range Meters() {
		s := mustSpec(t, m)
		if s.Shape == ShapeGauge && s.Formula == FormulaSum {
			t.Fatalf("%s sums a gauge", m)
		}
	}
}

func TestACounterAggregatedByLastWouldDiscardUsage(t *testing.T) {
	bad := Spec{Meter: "made_up", Formula: FormulaLast, Shape: ShapeCounter, Billed: true, KeyFields: []string{"window"}}
	if err := bad.Validate(); err == nil {
		t.Fatal("a counter aggregated by last must be refused: every earlier value is discarded")
	}
}

func TestKeysAreComposedFromDomainFactsOnly(t *testing.T) {
	spec := mustSpec(t, MeterEnvironmentHours)
	key, err := spec.Key("env_1", "gen_4", "2026-10-10T15")
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	// A key that embeds send time makes every retry a fresh billable event.
	for _, forbidden := range []string{time.Now().Format(time.RFC3339), "sent", "retry"} {
		if strings.Contains(key, forbidden) {
			t.Fatalf("key %q contains send-time data", key)
		}
	}
}

func TestTheSameFactsAlwaysProduceTheSameIdentifier(t *testing.T) {
	spec := mustSpec(t, MeterStorageGBHours)
	key, err := spec.Key("env_1", "2026-10-10T15")
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	first, err := spec.Identifier(key)
	if err != nil {
		t.Fatalf("identifier: %v", err)
	}
	// Three days and a thousand retries later the identifier must be unchanged: it is
	// read back from the ledger row, never regenerated.
	for i := 0; i < 3; i++ {
		again, err := spec.Identifier(key)
		if err != nil {
			t.Fatalf("identifier: %v", err)
		}
		if again != first {
			t.Fatalf("identifier drifted between retries: %s then %s", first, again)
		}
	}
}

func TestIdentifiersCannotCollideAcrossMeters(t *testing.T) {
	envKey, _ := mustSpec(t, MeterEnvironmentHours).Key("env_1", "gen_1", "w")
	storageKey, _ := mustSpec(t, MeterStorageGBHours).Key("env_1", "w")
	envID, _ := mustSpec(t, MeterEnvironmentHours).Identifier(envKey)
	storageID, _ := mustSpec(t, MeterStorageGBHours).Identifier(storageKey)
	if envID == storageID {
		t.Fatal("two meters produced the same identifier from different facts")
	}
}

func TestIdentifiersFitTheProviderLimit(t *testing.T) {
	for _, m := range Meters() {
		spec := mustSpec(t, m)
		parts := make([]string, len(spec.KeyFields))
		for i := range parts {
			parts[i] = strings.Repeat("x", 200)
		}
		key, err := spec.Key(parts...)
		if err != nil {
			t.Fatalf("%s key: %v", m, err)
		}
		id, err := spec.Identifier(key)
		if err != nil {
			t.Fatalf("%s identifier: %v", m, err)
		}
		if len(id) > MaxIdentifierLength {
			t.Fatalf("%s identifier is %d characters, over %d", m, len(id), MaxIdentifierLength)
		}
	}
}

func TestAnIncompleteKeyIsRefused(t *testing.T) {
	spec := mustSpec(t, MeterEnvironmentHours)
	_, err := spec.Key("env_1", "gen_1")
	mustErr(t, err, ErrDeduplicationKeyIncomplete, "short key")

	_, err = spec.Key("env_1", "", "w")
	mustErr(t, err, ErrDeduplicationKeyIncomplete, "empty part")
}

func TestPayloadCarriesOnlyCustomerAndValue(t *testing.T) {
	spec := mustSpec(t, MeterEnvironmentHours)
	got, err := spec.BuildPayload(Payload{CustomerID: "cus_1", Value: 3.5})
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	// 100 unique dimension combinations per customer per meter is the provider's
	// budget; environment and generation identity stays in our ledger.
	if len(got) != 2 || got["stripe_customer_id"] != "cus_1" || got["value"] != "3.500000" {
		t.Fatalf("payload: %v", got)
	}
}

func TestWholeNumbersAreNotRenderedWithDecimalNoise(t *testing.T) {
	spec := mustSpec(t, MeterExperimentRuns)
	got, err := spec.BuildPayload(Payload{CustomerID: "cus_1", Value: 1})
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	if got["value"] != "1" {
		t.Fatalf("value %q invites an argument about arithmetic", got["value"])
	}
}

func TestAZeroOrNegativeOrdinaryEventIsRefused(t *testing.T) {
	spec := mustSpec(t, MeterEnvironmentHours)
	// A zero-concurrency hour is a measurement error, not a measurement.
	for _, v := range []float64{0, -1} {
		_, err := spec.BuildPayload(Payload{CustomerID: "cus_1", Value: v})
		mustErr(t, err, ErrNonPositiveValue, "non-positive value")
	}
}

func TestACorrectionMayBeNegativeButMayNotBeZero(t *testing.T) {
	spec := mustSpec(t, MeterEnvironmentHours)
	if _, err := spec.BuildPayload(Payload{CustomerID: "cus_1", Value: -2, Correction: true}); err != nil {
		t.Fatalf("negative correction: %v", err)
	}
	_, err := spec.BuildPayload(Payload{CustomerID: "cus_1", Value: 0, Correction: true})
	mustErr(t, err, ErrNonPositiveValue, "zero correction")
}

func TestEventsOutsideTheProviderWindowAreRefusedNotDropped(t *testing.T) {
	spec := mustSpec(t, MeterEnvironmentHours)
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

	mustErr(t, spec.CheckTimestamp(now.Add(-36*24*time.Hour), now), ErrTimestampTooOld, "too old")
	mustErr(t, spec.CheckTimestamp(now.Add(6*time.Minute), now), ErrTimestampInFuture, "too far ahead")

	if err := spec.CheckTimestamp(now.Add(-35*24*time.Hour), now); err != nil {
		t.Fatalf("35 days old is inside the window: %v", err)
	}
	if err := spec.CheckTimestamp(now.Add(5*time.Minute), now); err != nil {
		t.Fatalf("5 minutes of clock skew is tolerated: %v", err)
	}
}

func TestShortEnvironmentsBillTheMinimumIncrement(t *testing.T) {
	spec := mustSpec(t, MeterEnvironmentHours)
	cases := []struct {
		elapsed time.Duration
		want    time.Duration
	}{
		{0, 0},
		{-time.Minute, 0},
		{3 * time.Second, 5 * time.Minute},
		{5 * time.Minute, 5 * time.Minute},
		{5*time.Minute + time.Second, 10 * time.Minute},
		{24 * time.Hour, 24 * time.Hour},
	}
	for _, c := range cases {
		if got := spec.BillableDuration(c.elapsed); got != c.want {
			t.Fatalf("elapsed %s: billed %s, want %s", c.elapsed, got, c.want)
		}
	}
}

// Rounding per generation, not per period: a customer who creates thousands of short
// previews must not have their charges absorbed by one long environment's remainder.
func TestEachGenerationRoundsIndependently(t *testing.T) {
	spec := mustSpec(t, MeterEnvironmentHours)
	shorts := 1000
	total := float64(0)
	for i := 0; i < shorts; i++ {
		total += spec.BillableHours(2 * time.Second)
	}
	want := float64(shorts) * 5.0 / 60.0
	if math.Abs(total-want) > 1e-9 {
		t.Fatalf("total %v hours, want %v", total, want)
	}
}

// A generation that ran entirely suspended occupied no compute. Charging it the
// minimum would bill a stopped machine for having stopped.
func TestAnEntirelySuspendedGenerationBillsNoHours(t *testing.T) {
	spec := mustSpec(t, MeterEnvironmentHours)
	if got := spec.BillableHours(0); got != 0 {
		t.Fatalf("zero live time billed %v hours", got)
	}
}

func TestStorageIsNotRoundedUpIntoStorageThatWasNeverRetained(t *testing.T) {
	spec := mustSpec(t, MeterStorageGBHours)
	if got := spec.BillableDuration(1500 * time.Millisecond); got != 1500*time.Millisecond {
		t.Fatalf("storage was rounded to %s", got)
	}
}

func TestStorageUsesDecimalGigabytes(t *testing.T) {
	// A binary interpretation would silently over-bill every storage meter by 7.4%.
	got := StorageGBHours(BytesPerGigabyte, 3*time.Hour)
	if got != 3 {
		t.Fatalf("1 GB for 3 hours is %v GB-hours, want 3", got)
	}
	if got := StorageGBHours(0, time.Hour); got != 0 {
		t.Fatalf("nothing retained billed %v", got)
	}
	if got := StorageGBHours(BytesPerGigabyte, 0); got != 0 {
		t.Fatalf("no time billed %v", got)
	}
}
