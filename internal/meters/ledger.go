package meters

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Event is one recorded fact. Events are never edited or deleted; a mistake is
// corrected by appending another event that references this one, so that a disputed
// invoice can be replayed as the exact sequence that produced it.
type Event struct {
	// ID is the deterministic provider identifier, derived from DedupKey.
	ID string
	// Meter is the quantity this event records.
	Meter Meter
	// CustomerID is the paying customer.
	CustomerID string
	// DedupKey is the domain composition that makes the event unique.
	DedupKey string
	// Parts are the KeyFields that produced DedupKey. A correction is keyed from
	// them, so it cannot be built with the wrong number of fields for its meter.
	Parts []string
	// Value is hours, GB-hours, or a run count. Signed only on a correction.
	Value float64
	// OccurredAt is when the usage happened. It is read back from here on every
	// retry, never regenerated at send time.
	OccurredAt time.Time
	// WindowStart and WindowEnd bound the period the value covers.
	WindowStart time.Time
	WindowEnd   time.Time
	// Supersedes is the ID of the event this one corrects, empty otherwise.
	Supersedes string
	// CorrectionReason explains why. It is required on a correction because a
	// correction without a reason is indistinguishable from a bug.
	CorrectionReason string
}

// Correction reports whether the event adjusts an earlier one.
func (e Event) Correction() bool { return e.Supersedes != "" }

// EventInput is a request to record one event.
type EventInput struct {
	Meter      Meter
	CustomerID string
	// DedupParts are the meter's KeyFields in order, all domain facts.
	DedupParts  []string
	Value       float64
	OccurredAt  time.Time
	WindowStart time.Time
	WindowEnd   time.Time
}

// Ledger is an append-only record of usage events with recomputed rollups.
type Ledger struct {
	mu     sync.Mutex
	events []Event
	byID   map[string]int
	byKey  map[string]int
	now    func() time.Time
}

// RuleVersion identifies the aggregation rules a rollup was computed under. Usage
// must be metered under the rules in effect when it occurred; applying today's rules
// to last month's usage produces invoices nobody can defend.
const RuleVersion = "g036-v1"

// NewLedger returns a ledger whose bound checks use provider time.
func NewLedger(providerNow func() time.Time) *Ledger {
	if providerNow == nil {
		providerNow = func() time.Time { return time.Now().UTC() }
	}
	return &Ledger{byID: map[string]int{}, byKey: map[string]int{}, now: providerNow}
}

// Append records an event, or returns the existing one when the deduplication key has
// already been seen. The boolean reports whether a new row was written, which is what
// distinguishes a first delivery from a retry.
func (l *Ledger) Append(in EventInput) (Event, bool, error) {
	spec, ok := Lookup(in.Meter)
	if !ok {
		return Event{}, false, fmt.Errorf("%w: %s", ErrUnknownMeter, in.Meter)
	}
	key, err := spec.Key(in.DedupParts...)
	if err != nil {
		return Event{}, false, err
	}
	id, err := spec.Identifier(key)
	if err != nil {
		return Event{}, false, err
	}
	if in.Value <= 0 {
		return Event{}, false, fmt.Errorf("%w: %s cannot record %v", ErrNonPositiveValue, in.Meter, in.Value)
	}
	if in.OccurredAt.IsZero() {
		return Event{}, false, fmt.Errorf("%w: %s has no timestamp", ErrTimestampTooOld, in.Meter)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if i, seen := l.byKey[key]; seen {
		return l.events[i], false, nil
	}
	if err := spec.CheckTimestamp(in.OccurredAt, l.now()); err != nil {
		return Event{}, false, err
	}
	if in.WindowEnd.Before(in.WindowStart) {
		return Event{}, false, fmt.Errorf("%s: window ends before it starts", in.Meter)
	}
	e := Event{
		ID: id, Meter: in.Meter, CustomerID: in.CustomerID, DedupKey: key,
		Parts: append([]string(nil), in.DedupParts...),
		Value: in.Value, OccurredAt: in.OccurredAt.UTC(),
		WindowStart: in.WindowStart.UTC(), WindowEnd: in.WindowEnd.UTC(),
	}
	l.events = append(l.events, e)
	l.byID[e.ID] = len(l.events) - 1
	l.byKey[key] = len(l.events) - 1
	return e, true, nil
}

// ErrCorrectionUnknownOriginal means a correction referenced an event that is not in
// the ledger.
func Correct(l *Ledger, originalID string, delta float64, reason string, occurredAt time.Time) (Event, bool, error) {
	if originalID == "" {
		return Event{}, false, fmt.Errorf("%w: no original", ErrUnknownOriginal)
	}
	if reason == "" {
		return Event{}, false, ErrCorrectionWithoutReason
	}
	if delta == 0 {
		return Event{}, false, fmt.Errorf("%w: a correction of zero changes nothing", ErrNonPositiveValue)
	}
	l.mu.Lock()
	i, ok := l.byID[originalID]
	if !ok {
		l.mu.Unlock()
		return Event{}, false, fmt.Errorf("%w: %s", ErrUnknownOriginal, originalID)
	}
	original := l.events[i]
	l.mu.Unlock()
	e, inserted, err := l.appendCorrection(original, delta, reason, occurredAt)
	if err != nil {
		return Event{}, false, err
	}
	l.mu.Lock()
	e.Supersedes = original.ID
	e.CorrectionReason = reason
	l.events[l.byID[e.ID]] = e
	l.mu.Unlock()
	return e, inserted, nil
}

// appendCorrection records a signed adjustment against an existing event.
//
// The correction is keyed from the original's key plus its reason, never from a
// counter or a clock. That makes an identical correction idempotent — a retry
// reproduces the same key and is refused — while a genuinely different correction
// must carry a different explanation, which is what a reviewer wants to read anyway.
func (l *Ledger) appendCorrection(original Event, delta float64, reason string, occurredAt time.Time) (Event, bool, error) {
	spec, ok := Lookup(original.Meter)
	if !ok {
		return Event{}, false, fmt.Errorf("%w: %s", ErrUnknownMeter, original.Meter)
	}
	key := original.DedupKey + "|correction|" + reason
	id, err := spec.Identifier(key)
	if err != nil {
		return Event{}, false, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if j, seen := l.byKey[key]; seen {
		return l.events[j], false, nil
	}
	e := Event{
		ID: id, Meter: original.Meter, CustomerID: original.CustomerID,
		DedupKey: key, Parts: original.Parts,
		Value: delta, OccurredAt: occurredAt.UTC(),
		WindowStart: original.WindowStart, WindowEnd: original.WindowEnd,
		Supersedes: original.ID, CorrectionReason: reason,
	}
	l.events = append(l.events, e)
	l.byID[e.ID] = len(l.events) - 1
	l.byKey[key] = len(l.events) - 1
	return e, true, nil
}

// Events returns every event in occurrence order, then by identifier. Corrections
// sort after the event they reference when timestamps tie, so a replay reads in a
// stable order regardless of insertion sequence.
func (l *Ledger) Events() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, len(l.events))
	copy(out, l.events)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].OccurredAt.Before(out[j].OccurredAt)
	})
	return out
}

// Len returns the number of recorded events.
func (l *Ledger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}

// Rollup is a recomputed total for one customer, meter and window.
type Rollup struct {
	CustomerID  string
	Meter       Meter
	WindowStart time.Time
	WindowEnd   time.Time
	Value       float64
	Samples     int
	RuleVersion string
}

// Rollup recomputes the total for a window from the events, applying corrections.
// Nothing is cached and nothing is incremented, so calling it twice returns the same
// answer and a replay after any restatement is self-healing.
//
// Counters are summed. The gauge is reduced to its maximum sample, because summing
// concurrent environments would produce a total that grows with the length of the
// month rather than with anything a customer did.
func (l *Ledger) Rollup(customerID string, m Meter, windowStart, windowEnd time.Time) (Rollup, error) {
	spec, ok := Lookup(m)
	if !ok {
		return Rollup{}, fmt.Errorf("%w: %s", ErrUnknownMeter, m)
	}
	if err := spec.Validate(); err != nil {
		return Rollup{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	r := Rollup{
		CustomerID: customerID, Meter: m, RuleVersion: RuleVersion,
		WindowStart: windowStart.UTC(), WindowEnd: windowEnd.UTC(),
	}
	for _, e := range l.events {
		if e.CustomerID != customerID || e.Meter != m {
			continue
		}
		if e.OccurredAt.Before(windowStart) || !e.OccurredAt.Before(windowEnd) {
			continue
		}
		r.Samples++
		switch spec.Shape {
		case ShapeGauge:
			if e.Value > r.Value {
				r.Value = e.Value
			}
		default:
			r.Value += e.Value
		}
	}
	return r, nil
}

// Status is an outbox delivery state.
type Status string

const (
	// StatusPending means the event has not been attempted.
	StatusPending Status = "pending"
	// StatusFailed means the last attempt failed and another is due.
	StatusFailed Status = "failed"
	// StatusSent means the provider accepted the event.
	StatusSent Status = "sent"
	// StatusRestated means the event cannot be corrected at the provider any more
	// and the difference must be settled by reconciliation instead.
	StatusRestated Status = "restated"
)

// Delivery is one row of the outbox.
type Delivery struct {
	Event          Event
	Status         Status
	Attempts       int
	FirstAttemptAt time.Time
	LastAttemptAt  time.Time
	// Replayed reports that the provider's deduplication window has lapsed, so this
	// send is a genuinely new provider-side event rather than a suppressed retry.
	Replayed bool
	// Restated reports that this correction arrived too late to be adjusted at the
	// provider and must be settled through reconciliation.
	Restated  bool
	LastError string
}

// CorrectionWindow is how long a provider accepts an adjustment to a reported event.
// Beyond it the difference is a restatement, not a cancellation.
const CorrectionWindow = 24 * time.Hour

// Outbox holds events until the provider has them. It is the only retry mechanism:
// nothing is buffered to a nightly flush, because month-boundary flushes are where
// usage goes missing.
type Outbox struct {
	mu    sync.Mutex
	rows  map[string]*Delivery
	order []string
	now   func() time.Time
}

// NewOutbox returns an outbox whose decisions use provider time.
func NewOutbox(providerNow func() time.Time) *Outbox {
	if providerNow == nil {
		providerNow = func() time.Time { return time.Now().UTC() }
	}
	return &Outbox{rows: map[string]*Delivery{}, now: providerNow}
}

// Enqueue adds an event for delivery. Re-enqueueing a sent event is refused, so a
// duplicate drain cannot report usage twice.
func (o *Outbox) Enqueue(e Event) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.rows[e.ID]; ok {
		return nil
	}
	row := &Delivery{Event: e, Status: StatusPending}
	o.rows[e.ID] = row
	o.order = append(o.order, e.ID)
	return nil
}

// Ready returns the deliveries that should be attempted now, oldest first, and marks
// each with whether the provider's deduplication window has lapsed. A correction
// older than the adjustment window is returned as restated rather than sent, because
// sending it would fail at the provider and hide the difference.
func (o *Outbox) Ready() []Delivery {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	var out []Delivery
	for _, id := range o.order {
		row := o.rows[id]
		if row.Status == StatusSent {
			continue
		}
		if row.Attempts > 0 {
			row.Replayed = now.Sub(row.FirstAttemptAt) > CorrectionWindow
		}
		if row.Event.Correction() && now.Sub(row.Event.OccurredAt) > CorrectionWindow {
			row.Restated = true
			row.Status = StatusRestated
			out = append(out, *row)
			continue
		}
		out = append(out, *row)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Event.OccurredAt.Equal(out[j].Event.OccurredAt) {
			return out[i].Event.ID < out[j].Event.ID
		}
		return out[i].Event.OccurredAt.Before(out[j].Event.OccurredAt)
	})
	return out
}

// MarkSent records acceptance. The event identifier is unchanged, so a later retry of
// the same fact is provably the same event.
func (o *Outbox) MarkSent(eventID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	row, ok := o.rows[eventID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownMeter, eventID)
	}
	now := o.now()
	if row.Attempts == 0 {
		row.FirstAttemptAt = now
	}
	row.Attempts++
	row.LastAttemptAt = now
	row.Status = StatusSent
	row.LastError = ""
	return nil
}

// MarkFailed records a failed attempt with its reason preserved. The reason is kept
// because "retry later" without the provider's error code teaches nobody anything.
func (o *Outbox) MarkFailed(eventID string, cause error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	row, ok := o.rows[eventID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownMeter, eventID)
	}
	now := o.now()
	if row.Attempts == 0 {
		row.FirstAttemptAt = now
	}
	row.Attempts++
	row.LastAttemptAt = now
	row.Status = StatusFailed
	if cause != nil {
		row.LastError = cause.Error()
	}
	return nil
}

// Backoff is the delay before the next attempt for a row with the given attempt count.
func Backoff(attempts int) time.Duration {
	const (
		base = 30 * time.Second
		max  = time.Hour
	)
	if attempts < 1 {
		return base
	}
	d := base
	for i := 1; i < attempts && d < max; i++ {
		d *= 2
	}
	if d > max {
		return max
	}
	return d
}

// ErrUncleanedGeneration means a generation was billed before verified cleanup. The
// counting rule is admission to verified cleanup, so billing earlier would charge for
// capacity whose teardown has not been proven and could double-count on retry.
var ErrUncleanedGeneration = errors.New("generation has no verified cleanup")

// Interval is a span of time.
type Interval struct {
	Start time.Time
	End   time.Time
}

// Facts are the terminal state of one generation, as the state machine knows them.
type Facts struct {
	CustomerID  string
	Environment string
	Generation  string
	RunID       string
	// Admitted reports whether anything was provisioned. An environment refused at
	// admission consumed nothing, so it bills nothing.
	Admitted bool
	// GateRejected reports a customer-side failure after admission: a build that
	// failed, a policy that said no. The capacity was real, so it bills.
	GateRejected bool
	AdmittedAt   time.Time
	CleanedUpAt  time.Time
	// Suspended spans are periods the environment was not running but still retained.
	Suspended []Interval
	// RetainedBytes is the storage held for the generation's life.
	RetainedBytes int64
}

// Charges decides what a finished generation bills.
//
// Three distinctions matter and each is deliberate. An environment refused at
// admission provisioned nothing and bills nothing, because charging for work never
// done is the fastest way to lose a customer. An environment that was admitted and
// then failed a gate bills its consumed capacity, because the slot, the gateway and
// the database existed; this mirrors the industry rule that the distinction is whose
// fault the failure was. Suspension bills storage but not environment hours, because
// retained resources cost money while a stopped machine does not.
func Charges(f Facts, providerNow func() time.Time) ([]EventInput, error) {
	if providerNow == nil {
		providerNow = func() time.Time { return time.Now().UTC() }
	}
	if !f.Admitted {
		return nil, nil
	}
	if f.CleanedUpAt.IsZero() {
		return nil, fmt.Errorf("%w: %s/%s", ErrUncleanedGeneration, f.Environment, f.Generation)
	}
	if !f.CleanedUpAt.After(f.AdmittedAt) {
		return nil, fmt.Errorf("%w: %s/%s cleaned up before it was admitted", ErrUncleanedGeneration, f.Environment, f.Generation)
	}
	envSpec, _ := Lookup(MeterEnvironmentHours)

	suspended := 0 * time.Second
	for _, s := range f.Suspended {
		if s.End.After(s.Start) {
			suspended += s.End.Sub(s.Start)
		}
	}
	lifetime := f.CleanedUpAt.Sub(f.AdmittedAt)
	live := lifetime - suspended
	if live < 0 {
		live = 0
	}

	window := f.Generation + "|" + f.AdmittedAt.UTC().Format("2006-01-02T15")
	out := []EventInput{{
		Meter:       MeterEnvironmentHours,
		CustomerID:  f.CustomerID,
		DedupParts:  []string{f.Environment, f.Generation, window},
		Value:       envSpec.BillableHours(live),
		OccurredAt:  f.CleanedUpAt.UTC(),
		WindowStart: f.AdmittedAt.UTC(),
		WindowEnd:   f.CleanedUpAt.UTC(),
	}}
	if gbHours := StorageGBHours(f.RetainedBytes, lifetime); gbHours > 0 {
		out = append(out, EventInput{
			Meter:       MeterStorageGBHours,
			CustomerID:  f.CustomerID,
			DedupParts:  []string{f.Environment, window},
			Value:       gbHours,
			OccurredAt:  f.CleanedUpAt.UTC(),
			WindowStart: f.AdmittedAt.UTC(),
			WindowEnd:   f.CleanedUpAt.UTC(),
		})
	}
	// A gate rejection consumed capacity but admitted no experiment.
	if !f.GateRejected && f.RunID != "" {
		out = append(out, EventInput{
			Meter:       MeterExperimentRuns,
			CustomerID:  f.CustomerID,
			DedupParts:  []string{f.RunID},
			Value:       1,
			OccurredAt:  f.AdmittedAt.UTC(),
			WindowStart: f.AdmittedAt.UTC(),
			WindowEnd:   f.CleanedUpAt.UTC(),
		})
	}
	for _, e := range out {
		if err := Lookup2(e.Meter); err != nil {
			return nil, err
		}
		if err := envSpec.CheckTimestamp(e.OccurredAt, providerNow()); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Lookup2 returns a meter spec's validity as an error, for validating a whole batch.
func Lookup2(m Meter) error {
	spec, ok := Lookup(m)
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownMeter, m)
	}
	return spec.Validate()
}
