// Package schedule expands a recurring preview schedule into concrete instants,
// and decides what a suspension costs and when it must end.
//
// A schedule here is a promise about *wall-clock* time: "every day at 02:30 in
// Europe/Berlin" is the thing a customer actually asks for, and it is the only
// form of the promise that survives being read by a human six months later. That
// choice is the source of the package's hardest problem, because a wall clock is
// not a function of time. Twice a year the mapping from local fields to instants
// is not injective — a time can be nonexistent, or it can happen twice — and any
// scheduler that ignores this fires a preview at the wrong hour or fires it twice,
// silently.
//
// So the rules are explicit, default to the specification, and are tested both
// ways rather than left to the standard library's normalisation:
//
//   - A nonexistent local time (spring forward) moves to the next valid instant,
//     shifting forward by exactly the width of the gap. PRODUCT-SPEC.md §5 states
//     this as the initial rule, and it is the honest reading of "at 02:30 daily":
//     the customer asked for a time that morning and gets the nearest instant to
//     it. The alternative — dropping the occurrence — is available as GapSkip and
//     is arguably quieter, because a preview that appears an hour late is
//     surprising in a way a review simply never happens. It is a policy, not the
//     default, and the sentinel ErrNonexistentLocalTime reports every skip so a
//     skipped wake is visible instead of inferred from a missing one.
//
//   - A repeated local time (fall back) executes exactly once, at the FIRST of the
//     two instants. The alternative resolutions are worse: firing twice charges a
//     customer for two wake-ups they asked for one of, and firing at the second is
//     an hour later than every other firing of the same schedule. Refusing instead
//     is available as OverlapRefuse for a deployment that would rather escalate
//     than assume; ErrAmbiguousLocalTime exists for it.
//
// Beyond arithmetic, this package carries three rules that are easy to get wrong
// and expensive to discover late:
//
//   - Occurrence sets are bounded. MaxOccurrences exists because an unbounded
//     recurrence in a scheduler is a runaway allocation and an unbounded bill, and
//     a refusal is a message a person can act on while a truncated list is a lie.
//
//   - Suspension does not consume the TTL. A suspended environment accrues
//     storage and no environment-hours, and waking it neither restarts nor
//     extends its lifetime. See cost.go.
//
//   - Waking re-checks admission. Capacity licensed to an environment that has
//     been stopped for a month has almost certainly been consumed by somebody
//     else, and resuming without asking would oversubscribe the fleet.
package schedule

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package.
var (
	// ErrUnknownLocation means no such IANA time zone exists. A schedule that
	// silently falls back to the server's locale is a schedule whose meaning
	// depends on which host happened to run it.
	ErrUnknownLocation = errors.New("unknown IANA time zone")

	// ErrImplicitLocation means the caller did not name a zone explicitly. "UTC",
	// "Local" and the empty string are all refused: each one is a way of saying
	// "I did not think about the time zone", and accepting them makes a customer
	// schedule depend on a server configuration instead of on what they asked for.
	ErrImplicitLocation = errors.New("time zone must be an explicit IANA zone name")

	// ErrInvalidCadence means the recurrence rule itself is not usable.
	ErrInvalidCadence = errors.New("invalid cadence")

	// ErrTooManyOccurrences means the request exceeds the occurrence bound.
	ErrTooManyOccurrences = errors.New("too many occurrences requested")

	// ErrInvalidWindow means the expansion window cannot contain a moment.
	ErrInvalidWindow = errors.New("invalid expansion window")

	// ErrNonexistentLocalTime means a requested wall-clock time does not exist on
	// its date, because a spring-forward transition skipped over it.
	ErrNonexistentLocalTime = errors.New("requested local time does not exist on that date")

	// ErrAmbiguousLocalTime means a requested wall-clock time occurs twice on its
	// date, because a fall-back transition repeated it.
	ErrAmbiguousLocalTime = errors.New("requested local time occurs twice on that date")
)

// MaxOccurrences bounds how many occurrences one expansion may produce, and how
// many one cadence may ever claim.
//
// The bound is deliberately small and deliberately refused rather than truncated.
// Every occurrence here corresponds to starting or stopping a real preview
// environment, so a caller asking for a thousand of them has a problem that a
// thousand-element slice would only hide; and an unbounded recurrence in a
// scheduler is the classic runaway allocation, which in this system is also an
// unbounded bill.
const MaxOccurrences = 100

// MaxWindowDays bounds how many calendar days one expansion will examine.
//
// It exists to keep the expansion itself bounded: an occurrence bound cannot stop
// a loop that has to walk a window before it can count anything. At the daily
// cadence this is a little under two years of dates, and at the weekly cadence the
// same wall of dates is a little under two years of firings.
const MaxWindowDays = 7 * MaxOccurrences

// MinEvery is the shortest interval an interval cadence may use.
//
// Sub-minute recurrence is refused rather than supported because a preview
// environment cannot usefully be started more than once a minute — a start is a
// dependency create, a deploy and a gate run — and because a cadence this short
// turns expansion into a hot loop.
const MinEvery = time.Minute

// Location is a named IANA time zone.
//
// It is a named zone and never time.Local, because "the server's locale" is not a
// schedule. The same customer-facing schedule would mean different instants on
// two hosts with different TZ settings, neither of which is wrong, and there is
// then no answer to the question a support engineer has to answer: when did this
// environment actually start? The zone is resolved once at construction so that
// expansion cannot fail halfway through on a timezone database that has since
// changed.
type Location struct {
	name string
	zone *time.Location
}

// NewLocation resolves an explicit IANA zone name.
//
// The empty string, "Local" and "UTC" are refused as implicit choices rather than
// as conveniences. "UTC" looks harmless and is not: it is indistinguishable from
// a caller who never considered the customer at all, and a schedule stated in UTC
// is read by an operator as a local time. Accepting it would let the ambiguity
// into the stored rule instead of surfacing it here.
func NewLocation(name string) (Location, error) {
	trimmed := strings.TrimSpace(name)
	switch strings.ToLower(trimmed) {
	case "", "local", "utc":
		return Location{}, fmt.Errorf("%w: %q is not a choice of zone; name one, for example America/New_York", ErrImplicitLocation, name)
	}
	zone, err := time.LoadLocation(trimmed)
	if err != nil {
		return Location{}, fmt.Errorf("%w: %q is not a zone this deployment can resolve", ErrUnknownLocation, trimmed)
	}
	if zone == time.Local {
		// Defensive: "Local" is already refused above, but a zero or aliased name
		// resolving to the process locale must not reach expansion.
		return Location{}, fmt.Errorf("%w: %q resolves to the process locale", ErrImplicitLocation, trimmed)
	}
	return Location{name: trimmed, zone: zone}, nil
}

// Name returns the IANA zone name as it was requested.
func (l Location) Name() string { return l.name }

// String renders the zone name.
func (l Location) String() string { return l.name }

// Load returns the resolved zone, refusing a Location that was never built by
// NewLocation. A zero Location is treated as an implicit zone, because that is
// what it is: no name at all.
func (l Location) Load() (*time.Location, error) {
	if l.zone == nil {
		return nil, fmt.Errorf("%w: no zone name was set; build the location with NewLocation", ErrImplicitLocation)
	}
	return l.zone, nil
}

// Every builds an interval cadence in this zone.
//
// An interval is absolute time, not wall-clock time, and the difference is
// load-bearing across a DST transition: every 6h keeps firing six hours apart,
// so the local hour of the firing drifts by an hour twice a year. That is the
// correct behaviour for "every six hours" and the wrong one for "at 09:00", which
// is why both exist rather than one being derived from the other.
func (l Location) Every(d time.Duration) Schedule {
	return Schedule{Name: "every", Location: l, Cadence: Cadence{Kind: KindEvery, Every: d}}
}

// Daily builds a cadence that fires every day at a local wall-clock time.
func (l Location) Daily(at ClockTime) Schedule {
	return Schedule{Name: "daily", Location: l, Cadence: Cadence{Kind: KindDaily, At: at}}
}

// Weekly builds a cadence that fires on one weekday at a local wall-clock time.
func (l Location) Weekly(on time.Weekday, at ClockTime) Schedule {
	return Schedule{Name: "weekly", Location: l, Cadence: Cadence{Kind: KindWeekly, On: on, At: at}}
}

// ClockTime is a time of day as a person states it, with no zone attached.
//
// It carries no location on purpose: the same 02:30 in two zones is two different
// instants, and attaching a zone here would make the ambiguity invisible at the
// point where the caller is still in a position to answer it.
type ClockTime struct {
	Hour   int
	Minute int
	Second int
}

// Clock builds a whole-minute clock time.
func Clock(hour, minute int) ClockTime { return ClockTime{Hour: hour, Minute: minute} }

// Validate refuses a clock time that cannot exist on any date.
func (c ClockTime) Validate() error {
	switch {
	case c.Hour < 0 || c.Hour > 23:
		return fmt.Errorf("%w: hour %d is outside 00-23", ErrInvalidCadence, c.Hour)
	case c.Minute < 0 || c.Minute > 59:
		return fmt.Errorf("%w: minute %d is outside 00-59", ErrInvalidCadence, c.Minute)
	case c.Second < 0 || c.Second > 59:
		return fmt.Errorf("%w: second %d is outside 00-59", ErrInvalidCadence, c.Second)
	}
	return nil
}

// String renders the clock time in the form a customer wrote it.
func (c ClockTime) String() string { return fmt.Sprintf("%02d:%02d:%02d", c.Hour, c.Minute, c.Second) }

// clockDuration is the offset from midnight used to build a civil wall-clock
// time. It is a plain offset rather than a duration-based construction because the
// result is calendar arithmetic, not elapsed time.
func (c ClockTime) clockDuration() time.Duration {
	return time.Duration(c.Hour)*time.Hour + time.Duration(c.Minute)*time.Minute + time.Duration(c.Second)*time.Second
}

// Kind names a recurrence rule.
type Kind string

const (
	// KindEvery is an absolute interval, unaffected by DST transitions.
	KindEvery Kind = "every"
	// KindDaily is a local wall-clock time on every day.
	KindDaily Kind = "daily"
	// KindWeekly is a local wall-clock time on one weekday.
	KindWeekly Kind = "weekly"
)

// Cadence is the recurrence rule.
//
// Count is the occurrence budget the cadence claims for a single expansion.
// Zero means MaxOccurrences. It exists so that a schedule stored for years cannot
// later be expanded into an unbounded set because a window was widened.
type Cadence struct {
	Kind Kind
	// Every is the interval for KindEvery, in absolute time.
	Every time.Duration
	// At is the local wall-clock time for KindDaily and KindWeekly.
	At ClockTime
	// On is the weekday for KindWeekly.
	On time.Weekday
	// Count is the maximum number of occurrences one expansion may produce.
	Count int
}

// Validate refuses a cadence that cannot be expanded, or that claims more
// occurrences than the bound allows.
func (c Cadence) Validate() error {
	switch c.Kind {
	case KindEvery:
		if c.Every <= 0 {
			return fmt.Errorf("%w: an interval cadence has no positive interval, got %s", ErrInvalidCadence, c.Every)
		}
		if c.Every < MinEvery {
			return fmt.Errorf("%w: an interval of %s is below the %s floor; a preview cannot usefully be started that often", ErrInvalidCadence, c.Every, MinEvery)
		}
	case KindDaily:
		if err := c.At.Validate(); err != nil {
			return err
		}
	case KindWeekly:
		if err := c.At.Validate(); err != nil {
			return err
		}
		if c.On < time.Sunday || c.On > time.Saturday {
			return fmt.Errorf("%w: weekday %d is not a day of the week", ErrInvalidCadence, int(c.On))
		}
	default:
		return fmt.Errorf("%w: unknown cadence kind %q", ErrInvalidCadence, c.Kind)
	}
	if c.Count < 0 {
		return fmt.Errorf("%w: a negative occurrence count of %d", ErrInvalidCadence, c.Count)
	}
	if c.Count > MaxOccurrences {
		return fmt.Errorf("%w: %d occurrences were requested and the bound is %d", ErrTooManyOccurrences, c.Count, MaxOccurrences)
	}
	return nil
}

// limit is the effective occurrence budget.
func (c Cadence) limit() int {
	if c.Count > 0 {
		return c.Count
	}
	return MaxOccurrences
}

// GapPolicy decides what happens to a local time that does not exist on its date.
type GapPolicy string

const (
	// GapShiftForward moves a nonexistent local time to the next valid instant,
	// shifting it forward by exactly the width of the transition's gap.
	//
	// This is the default and the rule PRODUCT-SPEC.md §5 states. It keeps the
	// promise "at 02:30 every day" true on every day the calendar has, and it
	// keeps the firing visibly close to what was asked for.
	GapShiftForward GapPolicy = "shift_forward"
	// GapSkip drops the occurrence and reports it, so the customer learns that a
	// wake did not happen instead of finding a preview that started an hour late
	// than the schedule says. Every skip is visible on Resolution.Skipped.
	GapSkip GapPolicy = "skip"
)

// OverlapPolicy decides what happens to a local time that occurs twice on its
// date.
type OverlapPolicy string

const (
	// OverlapFirst resolves an ambiguous local time to the first of its two
	// instants, and marks the occurrence Ambiguous.
	//
	// This is the default because it is the only resolution that keeps the
	// schedule firing once, at the hour a reader would name when they say "at
	// 01:30". The first instant is the one still under the pre-transition offset,
	// so it is also the earlier of the two and the one that keeps this firing in
	// step with every other firing of the same schedule.
	OverlapFirst OverlapPolicy = "first"
	// OverlapRefuse fails the expansion rather than choosing, for a deployment
	// that would escalate to a person instead of assuming which hour was meant.
	OverlapRefuse OverlapPolicy = "refuse"
)

// Schedule is a recurring rule: where, how often, and what to do about the two
// times a year when local time and real time disagree.
//
// The zero value is not a usable schedule: it names no zone. The policies are the
// exception, where the zero value means the documented default rather than an
// absent decision, because these are recorded preferences and an older stored
// schedule should keep meaning what it meant when it was written.
type Schedule struct {
	Name     string
	Location Location
	Cadence  Cadence
	// Gap is the nonexistent-local-time policy; empty means GapShiftForward.
	Gap GapPolicy
	// Overlap is the repeated-local-time policy; empty means OverlapFirst.
	Overlap OverlapPolicy
}

// Validate refuses a schedule that could not be expanded, or that names a policy
// this package does not implement.
func (s Schedule) Validate() error {
	if err := s.Cadence.Validate(); err != nil {
		return err
	}
	if _, err := s.Location.Load(); err != nil {
		return err
	}
	switch s.Gap {
	case "", GapShiftForward, GapSkip:
	default:
		return fmt.Errorf("%w: unknown gap policy %q", ErrInvalidCadence, s.Gap)
	}
	switch s.Overlap {
	case "", OverlapFirst, OverlapRefuse:
	default:
		return fmt.Errorf("%w: unknown overlap policy %q", ErrInvalidCadence, s.Overlap)
	}
	return nil
}

func (s Schedule) gapPolicy() GapPolicy {
	if s.Gap == "" {
		return GapShiftForward
	}
	return s.Gap
}

func (s Schedule) overlapPolicy() OverlapPolicy {
	if s.Overlap == "" {
		return OverlapFirst
	}
	return s.Overlap
}

// Occurrence is one resolved instant.
//
// Start is the truth: it is a UTC instant and it is what an environment would be
// started at. Requested is the wall-clock time the cadence asked for, rendered in
// UTC fields so it can be compared without a zone; where the two disagree, the
// DST policy did it, and Shifted and Ambiguous say so rather than leaving the
// difference to be discovered.
type Occurrence struct {
	// Index is the occurrence's position in the expansion, starting at zero.
	Index int
	// Start is the instant the occurrence fires, in UTC.
	Start time.Time
	// Requested is the civil wall-clock time the cadence asked for.
	Requested time.Time
	// Shifted is how far a nonexistent local time was moved forward. Zero for
	// every occurrence that was requested at a time which existed.
	Shifted time.Duration
	// Ambiguous reports that the requested local time occurred twice and this is
	// the first of the two instants.
	Ambiguous bool
}

// Local renders the occurrence in a zone, for display.
func (o Occurrence) Local(loc *time.Location) time.Time { return o.Start.In(loc) }

// Skipped is a requested wall-clock time that produced no occurrence, and why.
//
// It is a record rather than only an error because the caller that most needs to
// know is the one that is not currently failing: a schedule with a skipped wake
// is still a working schedule, and the only way it becomes visible is if the skip
// is carried forward with it.
type Skipped struct {
	// Requested is the civil wall-clock time that does not exist.
	Requested time.Time
	// Err wraps ErrNonexistentLocalTime.
	Err error
}

// Resolution is a full expansion: what fires, and what did not.
type Resolution struct {
	Occurrences []Occurrence
	// Skipped lists requested local times that do not exist on their date, under
	// GapSkip.
	Skipped []Skipped
}

// SkippedErr joins the reasons for every skipped occurrence, so a caller can
// surface them with one error while still reading the individual records.
func (r Resolution) SkippedErr() error {
	errs := make([]error, 0, len(r.Skipped))
	for _, s := range r.Skipped {
		if s.Err != nil {
			errs = append(errs, s.Err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// Resolve expands the cadence into the occurrences that fall in [from, until).
//
// The window is half-open, and deliberately so: a caller that slides a window
// forward by its own width must not fire every boundary occurrence twice, and an
// inclusive upper bound would make that the default behaviour.
//
// Resolve drops the skip report. Callers that need to know whether a wake was
// skipped — which is every caller that shows a customer anything about their
// schedule — must use ResolveReport.
func (s Schedule) Resolve(from, until time.Time) ([]Occurrence, error) {
	res, err := s.ResolveReport(from, until)
	if err != nil {
		return nil, err
	}
	return res.Occurrences, nil
}

// ResolveReport expands the cadence and reports what was skipped.
func (s Schedule) ResolveReport(from, until time.Time) (Resolution, error) {
	if err := s.Validate(); err != nil {
		return Resolution{}, err
	}
	if !until.After(from) {
		return Resolution{}, fmt.Errorf("%w: %s to %s is not a window", ErrInvalidWindow, from.Format(time.RFC3339), until.Format(time.RFC3339))
	}
	loc, err := s.Location.Load()
	if err != nil {
		return Resolution{}, err
	}
	limit := s.Cadence.limit()
	var res Resolution

	// record emits one resolved instant if it lands inside the window. The
	// occurrence bound is enforced here as well as in the pre-checks, so that a
	// policy which drops occurrences can never make the expansion cheaper to run
	// than the bound the caller asked for.
	record := func(inst time.Time, requested time.Time, kind wallKind) error {
		if inst.Before(from) || !inst.Before(until) {
			return nil
		}
		if len(res.Occurrences) >= limit {
			return fmt.Errorf("%w: the window holds more than the %d occurrences this cadence claims", ErrTooManyOccurrences, limit)
		}
		o := Occurrence{
			Index:     len(res.Occurrences),
			Start:     inst.UTC(),
			Requested: requested,
			Ambiguous: kind == wallFold,
		}
		if kind == wallGap {
			// The shift is measured, not assumed, so a zone with a transition that
			// is not a whole hour reports what actually happened to the local hour.
			o.Shifted = civil(inst.In(loc)).Sub(requested)
		}
		res.Occurrences = append(res.Occurrences, o)
		return nil
	}

	// emit resolves one civil wall-clock time, applies the documented DST
	// policies, and records or skips it.
	emit := func(wall time.Time) error {
		inst, kind := resolveWall(loc, wall)
		switch kind {
		case wallGap:
			if s.gapPolicy() == GapSkip {
				res.Skipped = append(res.Skipped, Skipped{
					Requested: wall,
					Err: fmt.Errorf("%w: %s is skipped by the schedule's %s policy",
						ErrNonexistentLocalTime, s.Cadence.At, GapSkip),
				})
				return nil
			}
		case wallFold:
			if s.overlapPolicy() == OverlapRefuse {
				return fmt.Errorf("%w: %s occurs twice on this date and the schedule refuses to choose",
					ErrAmbiguousLocalTime, s.Cadence.At)
			}
		}
		return record(inst, wall, kind)
	}

	switch s.Cadence.Kind {
	case KindEvery:
		// The interval case has no wall clock to resolve, so the candidate count is
		// exact rather than an upper bound and is checked before iterating.
		steps := int64(until.Sub(from)/s.Cadence.Every) + 1
		if steps > int64(limit) {
			return Resolution{}, fmt.Errorf("%w: %s at every %s is %d occurrences and the bound is %d",
				ErrTooManyOccurrences, from.Format(time.RFC3339), s.Cadence.Every, steps, limit)
		}
		for i := int64(0); i < steps; i++ {
			inst := from.Add(time.Duration(i) * s.Cadence.Every)
			if err := record(inst, civil(inst.In(loc)), wallUnique); err != nil {
				return Resolution{}, err
			}
		}

	case KindDaily, KindWeekly:
		first, last := civilDay(from.In(loc)), civilDay(until.In(loc))
		step := 1
		if s.Cadence.Kind == KindWeekly {
			step = 7
		}
		// The number of calendar days the window spans bounds how much this loop can
		// walk, which is what keeps a window of several years from becoming a few
		// million iterations before the occurrence bound is ever consulted.
		span := int(last.Sub(first)/(24*time.Hour)) + 1
		if span > MaxWindowDays {
			return Resolution{}, fmt.Errorf("%w: a %s window of %s spans %d days and this package examines at most %d",
				ErrTooManyOccurrences, s.Cadence.Kind, from.Format(time.RFC3339), span, MaxWindowDays)
		}

		// The occurrence bound is enforced in record, which refuses the moment one
		// more occurrence than the cadence claims would be produced. The window
		// walk above it is bounded by MaxWindowDays, so the expansion cannot become
		// a long loop before the bound is consulted, and the bound is exact rather
		// than a conservative estimate of what the window might hold.
		day := first
		if s.Cadence.Kind == KindWeekly {
			// At most six advances reach the first matching weekday, and the loop
			// below then steps a whole week at a time.
			for day.Weekday() != s.Cadence.On {
				day = day.AddDate(0, 0, 1)
			}
			for ; !day.After(last); day = day.AddDate(0, 0, step) {
				if !dayCanFire(loc, day, from, until) {
					continue
				}
				if err := emit(day.Add(s.Cadence.At.clockDuration())); err != nil {
					return Resolution{}, err
				}
			}
			return res, nil
		}
		for ; !day.After(last); day = day.AddDate(0, 0, step) {
			if !dayCanFire(loc, day, from, until) {
				continue
			}
			if err := emit(day.Add(s.Cadence.At.clockDuration())); err != nil {
				return Resolution{}, err
			}
		}
	}

	return res, nil
}

// GapSlack is the allowance given to a transition when deciding whether a local
// day can reach the expansion window.
//
// Some zones move their clock at local midnight, so the instant a local day starts
// is not the obvious one. The slack can only widen the set of dates considered
// possible, so a date is never skipped because of it; it costs nothing but makes
// the skip test safe to use as an optimisation.
const GapSlack = 2 * time.Hour

// dayCanFire reports whether an occurrence on a local date could land in the
// window.
//
// It compares instants rather than calendar fields because that is what the
// window is expressed in: a date is a candidate only if some instant inside that
// local day is inside [from, until). It is a skip test for the calendar walk, not
// the occurrence bound, which is enforced exactly where an occurrence is recorded.
func dayCanFire(loc *time.Location, day, from, until time.Time) bool {
	next := day.AddDate(0, 0, 1)
	_, openOffset := day.In(loc).Zone()
	_, closeOffset := next.In(loc).Zone()
	open := day.Add(-time.Duration(openOffset) * time.Second)
	closes := next.Add(-time.Duration(closeOffset) * time.Second)
	return !closes.Before(from.Add(-GapSlack)) && open.Before(until.Add(GapSlack))
}

// wallKind classifies a requested civil wall-clock time against real time.
type wallKind int

const (
	// wallUnique means the requested time occurs exactly once.
	wallUnique wallKind = iota
	// wallGap means the requested time does not exist on that date.
	wallGap
	// wallFold means the requested time occurs twice on that date.
	wallFold
)

// resolveWall maps a civil wall-clock time, rendered in UTC fields, onto the
// instant it denotes.
//
// The mapping is found by inverting rather than by trusting time.Date, because
// time.Date silently normalises both interesting cases: a nonexistent time comes
// back as some nearby time and an ambiguous time comes back as one of the two,
// with no indication that anything happened. Inverting here means the caller is
// told which of the three situations it is in and can apply the documented policy.
//
// Offsets are probed around the requested time rather than read from it, because
// the offset that applies to a wall clock inside a gap is exactly the question
// that cannot be answered by asking.
func resolveWall(loc *time.Location, wall time.Time) (time.Time, wallKind) {
	offsets := map[int]bool{}
	// A month either side covers every real transition, including the zones whose
	// DST period is shorter than that and the zones whose standard offset changed
	// within the year.
	for _, probe := range []time.Duration{0, -30 * 24 * time.Hour, 30 * 24 * time.Hour} {
		_, off := wall.Add(probe).In(loc).Zone()
		offsets[off] = true
	}
	sorted := make([]int, 0, len(offsets))
	for off := range offsets {
		sorted = append(sorted, off)
	}
	// Sorting is what makes this deterministic: the offsets come out of a map, and
	// an unsorted walk would let map iteration order pick which instant a repeated
	// time resolves to.
	sort.Ints(sorted)

	var valid []time.Time
	for _, off := range sorted {
		candidate := wall.Add(-time.Duration(off) * time.Second)
		if sameWall(candidate.In(loc), wall) {
			valid = append(valid, candidate)
		}
	}

	switch len(valid) {
	case 0:
		// Nonexistent: the transition jumped past this time. The smallest offset is
		// the one in force before the jump, so subtracting it lands the occurrence
		// after the transition by exactly the width of the gap.
		return wall.Add(-time.Duration(sorted[0]) * time.Second), wallGap
	case 1:
		return valid[0], wallUnique
	default:
		// Ambiguous: the largest offset is the one still in force at the first of
		// the two instants, so the last candidate in ascending offset order is the
		// earlier one and is the occurrence this schedule fires.
		return valid[len(valid)-1], wallFold
	}
}

// sameWall reports whether an instant renders as exactly these civil fields.
func sameWall(x, wall time.Time) bool {
	return x.Year() == wall.Year() && x.Month() == wall.Month() && x.Day() == wall.Day() &&
		x.Hour() == wall.Hour() && x.Minute() == wall.Minute() && x.Second() == wall.Second()
}

// civil renders a time's calendar fields as a UTC instant.
//
// Local calendar arithmetic is then plain UTC arithmetic, so iterating over "the
// days in this zone" cannot be perturbed by a transition in the middle of the
// window — and the weekday of the rendered date is the weekday of the local date,
// which is what the weekly cadence needs.
func civil(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
}

// civilDay renders a time as the calendar date it falls on, at midnight.
//
// Calendar iteration starts from the day, not from the instant the window happens
// to open at. A window opening at 20:00 local must still consider the whole of
// that date, because the schedule asked for a time of day and the window only
// bounds the result.
func civilDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}
