// Package meters records billable usage as an append-only ledger that can be
// recomputed, and refuses to emit anything that would be wrong on an invoice.
//
// ADR G-036, COST-MODEL.md §4 and §4.1. Three meters are billed —
// environment_hours, storage_gb_hours and experiment_runs — and concurrency_peak is
// recorded for reporting and alerting only.
//
// The central rule is that our ledger is the source of truth and any billing
// provider's aggregate is a disposable projection of it. A customer's disputed
// invoice has to be replayable from the event sequence that produced the number, so
// rollups are recomputed rather than incremented and corrections are new events that
// reference the original instead of edits to it.
//
// The second rule is that a gauge is never metered as if it were a counter.
// concurrency_peak measures simultaneous ready environments; it rises and falls.
// Summing it produces a number that grows with the length of the month rather than
// with anything the customer did, and every vendor that sells concurrency sells a
// limit rather than an accumulation. So concurrency is licensed capacity enforced at
// admission, and this package will not build a billable payload for it even if asked.
package meters

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Meter is the name of a metered quantity.
type Meter string

const (
	// MeterEnvironmentHours counts live environment time from admission to verified
	// cleanup, per generation.
	MeterEnvironmentHours Meter = "environment_hours"
	// MeterStorageGBHours counts retained bytes over time in decimal gigabytes
	// (10^9 bytes, matching S3 pricing), including time spent suspended.
	MeterStorageGBHours Meter = "storage_gb_hours"
	// MeterExperimentRuns counts admitted experiments.
	MeterExperimentRuns Meter = "experiment_runs"
	// MeterConcurrencyPeak samples the maximum number of simultaneously ready
	// environments. Recorded for reporting and alerting; never billed.
	MeterConcurrencyPeak Meter = "concurrency_peak"
)

// Formula is how a provider aggregates the values in a billing period.
type Formula string

const (
	// FormulaSum adds every value in the period.
	FormulaSum Formula = "sum"
	// FormulaCount counts the values in the period, ignoring their magnitude.
	FormulaCount Formula = "count"
	// FormulaLast takes the most recently received value for the period. It is
	// arrival-ordered, which is why it is unusable across many buckets; see
	// MeterConcurrencyPeak, which is not billed for exactly that reason.
	FormulaLast Formula = "last"
)

// Shape is whether a quantity can decrease over time.
type Shape int

const (
	// ShapeCounter is monotonic: it only accumulates. Summing is meaningful.
	ShapeCounter Shape = iota
	// ShapeGauge can go up and down, like the number of environments currently
	// running. It must never be summed.
	ShapeGauge
)

// BytesPerGigabyte is decimal gigabytes. S3 prices in decimal gigabytes and a
// binary interpretation would silently over-bill by 7.4% on every storage meter.
const BytesPerGigabyte = 1_000_000_000

// Spec is everything known about one meter.
type Spec struct {
	// Meter is the name reported to the provider.
	Meter Meter
	// Unit is the provider's unit for this meter's values.
	Unit string
	// Formula is how the provider aggregates a billing period.
	Formula Formula
	// Shape is whether the quantity can decrease.
	Shape Shape
	// Billed reports whether this meter may produce an invoice line. A false here is
	// enforced, not advisory: BuildPayload refuses.
	Billed bool
	// KeyFields names the parts composed into the deduplication key, in order. They
	// are domain facts, never send-time values, so a retry reproduces the key.
	KeyFields []string
	// MinQuantum is the smallest billable value for one record, applied here rather
	// than by the provider. Zero means no minimum.
	MinQuantum time.Duration
}

// registry is the single source of truth for meter configuration. Provider-side
// meter creation reads from this map so the two cannot drift apart.
var registry = map[Meter]Spec{
	MeterEnvironmentHours: {
		Meter:     MeterEnvironmentHours,
		Unit:      "hour",
		Formula:   FormulaSum,
		Shape:     ShapeCounter,
		Billed:    true,
		KeyFields: []string{"environment", "generation", "window"},
		// A three-second environment still occupied a slot, a NAT gateway and a
		// ledger row. Rounding each generation up to five minutes also stops a long
		// environment's remainder from being used to absorb a short one's free time.
		MinQuantum: MinBillableIncrement,
	},
	MeterStorageGBHours: {
		Meter:     MeterStorageGBHours,
		Unit:      "GB-hour",
		Formula:   FormulaSum,
		Shape:     ShapeCounter,
		Billed:    true,
		KeyFields: []string{"environment", "window"},
		// No minimum: the value is a product of bytes and time, so rounding it up
		// would invent storage that was never retained.
		MinQuantum: 0,
	},
	MeterExperimentRuns: {
		Meter:      MeterExperimentRuns,
		Unit:       "run",
		Formula:    FormulaCount,
		Shape:      ShapeCounter,
		Billed:     true,
		KeyFields:  []string{"run"},
		MinQuantum: 0,
	},
	MeterConcurrencyPeak: {
		Meter:     MeterConcurrencyPeak,
		Unit:      "count",
		Formula:   FormulaLast,
		Shape:     ShapeGauge,
		Billed:    false,
		KeyFields: []string{"window"},
	},
}

// MinBillableIncrement is the smallest environment duration that can be billed, in
// whole increments of itself.
const MinBillableIncrement = 5 * time.Minute

// Errors returned by this package.
var (
	// ErrUnknownMeter means no spec exists for that name.
	ErrUnknownMeter = errors.New("unknown meter")
	// ErrGaugeAggregatedAsSum means a meter whose shape is a gauge declares a
	// summing formula. Such a meter would grow with the length of the month.
	ErrGaugeAggregatedAsSum = errors.New("gauge meter may not aggregate by sum")
	// ErrNotBillable means a billable payload was requested for a meter that is
	// licensed capacity, not usage.
	ErrNotBillable = errors.New("meter is not billable")
	// ErrTimestampTooOld means the event falls outside the provider's accepted
	// window. It is surfaced rather than dropped so the gap is visible.
	ErrTimestampTooOld = errors.New("event timestamp is older than the provider accepts")
	// ErrTimestampInFuture means the event is too far ahead of provider time.
	ErrTimestampInFuture = errors.New("event timestamp is too far in the future")
	// ErrNonPositiveValue means a meter that counts occurrences received a value
	// that cannot describe one.
	ErrNonPositiveValue = errors.New("value must be positive")
	// ErrDeduplicationKeyIncomplete means the record is missing a field that its
	// meter's key is composed from.
	ErrDeduplicationKeyIncomplete = errors.New("deduplication key is incomplete")
	// ErrUnknownOriginal means a correction referenced an event that does not exist.
	ErrUnknownOriginal = errors.New("correction references an unknown event")
	// ErrCorrectionWithoutReason means a correction carried no explanation.
	ErrCorrectionWithoutReason = errors.New("correction requires a reason")
)

// Provider bounds. Stripe accepts meter events within 35 calendar days in the past
// and 5 minutes in the future for clock drift; both are checked here so an
// unreportable event raises an error instead of vanishing into a provider log.
const (
	// MaxEventAge is how far in the past an event may be reported.
	MaxEventAge = 35 * 24 * time.Hour
	// MaxClockSkew is how far ahead of provider time an event may be reported.
	MaxClockSkew = 5 * time.Minute
	// MaxIdentifierLength is the provider's limit on a meter event identifier.
	MaxIdentifierLength = 100
)

// Lookup returns the spec for a meter.
func Lookup(m Meter) (Spec, bool) {
	s, ok := registry[m]
	return s, ok
}

// Meters returns every known meter name, sorted.
func Meters() []Meter {
	out := make([]Meter, 0, len(registry))
	for m := range registry {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// BilledMeters returns the meters that may produce an invoice line, sorted.
func BilledMeters() []Meter {
	var out []Meter
	for _, m := range Meters() {
		if registry[m].Billed {
			out = append(out, m)
		}
	}
	return out
}

// Validate checks that one spec's shape and formula agree. It exists because the
// registry is data: nothing at compile time stops a future edit from declaring a
// gauge as a sum, and the failure would be an invoice nobody could explain.
func (s Spec) Validate() error {
	if s.Meter == "" {
		return fmt.Errorf("%w: empty name", ErrUnknownMeter)
	}
	if s.Shape == ShapeGauge && s.Formula == FormulaSum {
		return fmt.Errorf("%w: %s", ErrGaugeAggregatedAsSum, s.Meter)
	}
	if s.Shape == ShapeCounter && s.Formula == FormulaLast {
		return fmt.Errorf("%s: a counter aggregated by last silently discards every earlier value", s.Meter)
	}
	if s.Shape == ShapeGauge && s.Billed {
		return fmt.Errorf("%s: a gauge may not be a billable meter", s.Meter)
	}
	if len(s.KeyFields) == 0 {
		return fmt.Errorf("%s: no deduplication key fields", s.Meter)
	}
	return nil
}

// ValidateRegistry validates every spec, returning the first failure.
func ValidateRegistry() error {
	for _, m := range Meters() {
		if err := registry[m].Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Key composes a meter's deduplication key from domain facts. The parts must be the
// same on every retry: a key that embeds the send time turns each retry into a fresh
// billable event, which is the documented failure mode of timestamp-derived keys.
func (s Spec) Key(parts ...string) (string, error) {
	if len(parts) != len(s.KeyFields) {
		return "", fmt.Errorf("%w: %s needs %d parts (%s), got %d",
			ErrDeduplicationKeyIncomplete, s.Meter, len(s.KeyFields),
			strings.Join(s.KeyFields, "+"), len(parts))
	}
	for i, p := range parts {
		if p == "" {
			return "", fmt.Errorf("%w: %s.%s is empty", ErrDeduplicationKeyIncomplete, s.Meter, s.KeyFields[i])
		}
	}
	return string(s.Meter) + "|" + strings.Join(parts, "|"), nil
}

// Identifier derives the deterministic provider identifier for an event. It is the
// hash of the deduplication key rather than the key itself so it fits the provider's
// 100-character limit regardless of how long environment identifiers grow, and it
// cannot collide across meters because the meter name is hashed in too.
func (s Spec) Identifier(dedupKey string) (string, error) {
	if dedupKey == "" {
		return "", fmt.Errorf("%w: %s", ErrDeduplicationKeyIncomplete, s.Meter)
	}
	sum := sha256.Sum256([]byte(dedupKey))
	id := "gl1_" + string(s.Meter) + "_" + hex.EncodeToString(sum[:16])
	if len(id) > MaxIdentifierLength {
		return "", fmt.Errorf("identifier for %s is %d characters, over the provider limit of %d",
			s.Meter, len(id), MaxIdentifierLength)
	}
	return id, nil
}

// Payload is the customer and value a provider event carries.
type Payload struct {
	CustomerID string
	Value      float64
	// Correction marks a signed adjustment that references an original event.
	Correction bool
}

// BuildPayload renders the provider payload for one event. Only the customer
// identifier and the value are included: the provider accepts 100 unique dimension
// combinations per customer per meter, and environment, generation and region
// identity stays in our ledger where it costs nothing and can be audited.
//
// A correction may carry a negative value, which is how an over-report is reversed.
// An ordinary event may not be zero or negative: a metered hour of nothing is a
// measurement error, and a zero-valued sample of a count meter is rejected by the
// provider anyway, so it is refused here where the reason can still be read.
func (s Spec) BuildPayload(p Payload) (map[string]string, error) {
	if !s.Billed {
		return nil, fmt.Errorf("%w: %s", ErrNotBillable, s.Meter)
	}
	if p.CustomerID == "" {
		return nil, fmt.Errorf("%w: %s has no customer", ErrDeduplicationKeyIncomplete, s.Meter)
	}
	if p.Value == 0 || (!p.Correction && p.Value < 0) {
		return nil, fmt.Errorf("%w: %s cannot record %v", ErrNonPositiveValue, s.Meter, p.Value)
	}
	return map[string]string{
		"stripe_customer_id": p.CustomerID,
		"value":              formatValue(p.Value),
	}, nil
}

// CheckTimestamp enforces the provider's accepted reporting window against provider
// time. Callers pass the provider's notion of now, not the local clock, so a host
// with a skewed clock cannot push events outside the window.
func (s Spec) CheckTimestamp(occurredAt, providerNow time.Time) error {
	if occurredAt.After(providerNow.Add(MaxClockSkew)) {
		return fmt.Errorf("%w: %s is %s ahead", ErrTimestampInFuture, s.Meter, occurredAt.Sub(providerNow).Round(time.Second))
	}
	if occurredAt.Before(providerNow.Add(-MaxEventAge)) {
		return fmt.Errorf("%w: %s is %s old, limit %s", ErrTimestampTooOld, s.Meter,
			providerNow.Sub(occurredAt).Round(time.Hour), MaxEventAge)
	}
	return nil
}

// BillableDuration rounds an elapsed duration up to the meter's minimum quantum.
// Zero elapsed time bills zero: a generation that ran entirely suspended occupied no
// compute, and charging it the minimum would bill a stopped machine for having
// stopped. Any nonzero elapsed time is rounded up, so a generation cleaned up after
// three seconds is still billed five minutes — the slot, the gateway and the ledger
// row existed. Rounding here rather than asking the provider to round a period total
// matters, because a period-total rule lets one long environment's remainder absorb a
// short environment's free time, which systematically under-bills customers who
// create many small previews.
func (s Spec) BillableDuration(elapsed time.Duration) time.Duration {
	if elapsed <= 0 {
		return 0
	}
	q := s.MinQuantum
	if q <= 0 {
		return elapsed
	}
	steps := (elapsed + q - 1) / q
	return steps * q
}

// BillableHours is BillableDuration expressed in hours, the unit the meter reports.
func (s Spec) BillableHours(elapsed time.Duration) float64 {
	return float64(s.BillableDuration(elapsed)) / float64(time.Hour)
}

// StorageGBHours returns the GB-hours attributable to bytes retained for a duration.
func StorageGBHours(retainedBytes int64, retained time.Duration) float64 {
	if retainedBytes <= 0 || retained <= 0 {
		return 0
	}
	return float64(retainedBytes) / BytesPerGigabyte * retained.Hours()
}

// formatValue renders a meter value without floating-point noise. Integers stay
// integers because a count of "2.0000000001" on an invoice is an invitation to argue.
func formatValue(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%.6f", v)
}
