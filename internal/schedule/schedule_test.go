package schedule_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/schedule"
)

// ny is the zone the DST cases are pinned against. America/New_York springs
// forward on 2026-03-08 and falls back on 2026-11-01, and both transitions are
// whole hours, which is what makes them readable in a test failure.
func ny(t *testing.T) schedule.Location {
	t.Helper()
	loc, err := schedule.NewLocation("America/New_York")
	if err != nil {
		t.Fatalf("load America/New_York: %v", err)
	}
	return loc
}

func utc(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return v
}

func starts(t *testing.T, occ []schedule.Occurrence) []time.Time {
	t.Helper()
	out := make([]time.Time, len(occ))
	for i, o := range occ {
		out[i] = o.Start
	}
	return out
}

// TestALocationMustNameAZone: a schedule whose meaning depends on the server's
// locale is a schedule nobody can reason about, so an implicit zone is refused
// rather than defaulted.
func TestALocationMustNameAZone(t *testing.T) {
	for _, name := range []string{"", "   ", "Local", "local", "UTC", "utc"} {
		if _, err := schedule.NewLocation(name); !errors.Is(err, schedule.ErrImplicitLocation) {
			t.Errorf("NewLocation(%q) must refuse an implicit zone, got %v", name, err)
		}
	}
}

// TestAnUnknownZoneIsRefused: a zone this deployment cannot resolve must not fall
// back to something, because a fallback is a schedule that fires at a different
// hour on a different host.
func TestAnUnknownZoneIsRefused(t *testing.T) {
	for _, name := range []string{"Mars/Olympus_Mons", "America/Nowhere", "not a zone"} {
		loc, err := schedule.NewLocation(name)
		if !errors.Is(err, schedule.ErrUnknownLocation) {
			t.Fatalf("NewLocation(%q) must refuse an unknown zone, got %v", name, err)
		}
		if _, err := loc.Load(); !errors.Is(err, schedule.ErrImplicitLocation) {
			t.Fatalf("the refused location must not resolve later, got %v", err)
		}
	}
}

// TestAnExplicitZoneResolves: a named IANA zone is accepted, including zones with
// half-hour offsets and zones with a transition that is not a whole hour.
func TestAnExplicitZoneResolves(t *testing.T) {
	for _, name := range []string{
		"America/New_York", "Europe/London", "Europe/Berlin", "Asia/Kolkata",
		"Australia/Lord_Howe", "Pacific/Chatham", "Etc/UTC",
	} {
		loc, err := schedule.NewLocation(name)
		if err != nil {
			t.Fatalf("NewLocation(%q): %v", name, err)
		}
		if loc.Name() != name || loc.String() != name {
			t.Fatalf("the zone name must round-trip, got %q/%q", loc.Name(), loc.String())
		}
		zone, err := loc.Load()
		if err != nil || zone == nil {
			t.Fatalf("Load(%q) = %v", name, err)
		}
		if zone == time.Local {
			t.Fatalf("Load(%q) resolved to the process locale", name)
		}
	}
}

// TestDailyCadenceHoldsItsLocalHourAcrossEveryDay: the promise is a wall clock,
// so every day of the year must fire at the same local hour, DST days included.
func TestDailyCadenceHoldsItsLocalHourAcrossEveryDay(t *testing.T) {
	loc := ny(t)
	s := loc.Daily(schedule.Clock(2, 30))
	zone, _ := loc.Load()

	occ, err := s.Resolve(utc(t, "2026-01-01T00:00:00Z"), utc(t, "2026-12-01T00:00:00Z"))
	if err == nil {
		// A whole year is more candidates than the bound allows; the important
		// assertion below is that it is refused rather than silently truncated.
		t.Fatalf("a 335 day window must exceed the occurrence bound, got %d occurrences", len(occ))
	}
	if !errors.Is(err, schedule.ErrTooManyOccurrences) {
		t.Fatalf("want ErrTooManyOccurrences, got %v", err)
	}

	// Two bounded windows that stay inside the bound. The expected count is
	// spelled out because a window's bounds are UTC moments while the cadence's
	// are local dates, and the two do not line up: 02:30 in New York is 07:30Z, so
	// a window opening at midnight UTC already contains five local dates.
	for _, w := range []struct {
		from, until string
		want        int
	}{
		{"2026-01-01T00:00:00Z", "2026-01-05T12:00:00Z", 5},
		{"2026-12-20T00:00:00Z", "2026-12-24T12:00:00Z", 5},
	} {
		occ, err := s.Resolve(utc(t, w.from), utc(t, w.until))
		if err != nil {
			t.Fatalf("resolve %s: %v", w.from, err)
		}
		if len(occ) != w.want {
			t.Fatalf("expected %d daily occurrences, got %d", w.want, len(occ))
		}
		for _, o := range occ {
			l := o.Local(zone)
			if l.Hour() != 2 || l.Minute() != 30 {
				t.Fatalf("occurrence %s fired at local %s, not 02:30", o.Start, l)
			}
		}
	}
}

// TestSpringForwardShiftsANonexistentTimeForward is the load-bearing DST rule.
//
// 02:30 does not exist on 2026-03-08 in America/New_York: the clock jumps from
// 02:00 EST straight to 03:00 EDT. The documented policy shifts the occurrence
// forward by exactly the width of the gap, so the occurrence fires at 03:30 EDT,
// which is 07:30Z, and it says so in Shifted rather than pretending it was asked
// for 02:30.
func TestSpringForwardShiftsANonexistentTimeForward(t *testing.T) {
	loc := ny(t)
	zone, _ := loc.Load()
	s := loc.Daily(schedule.Clock(2, 30))

	occ, err := s.Resolve(utc(t, "2026-03-07T00:00:00Z"), utc(t, "2026-03-10T00:00:00Z"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(occ) != 3 {
		t.Fatalf("expected the 7th, 8th and 9th, got %d occurrences", len(occ))
	}

	gap := occ[1]
	if gap.Index != 1 || !gap.Start.Equal(utc(t, "2026-03-08T07:30:00Z")) {
		t.Fatalf("the gap occurrence must fire at 07:30Z, got %s", gap.Start)
	}
	if gap.Shifted != time.Hour {
		t.Fatalf("the shift must be reported as one hour, got %s", gap.Shifted)
	}
	if l := gap.Local(zone); l.Hour() != 3 || l.Minute() != 30 {
		t.Fatalf("the shifted occurrence must read 03:30 local, got %s", l)
	}
	// The requested wall clock is still recorded, so an operator can see what the
	// customer asked for even though the instant is an hour later.
	if !gap.Requested.Equal(utc(t, "2026-03-08T02:30:00Z")) {
		t.Fatalf("the requested wall clock must be preserved, got %s", gap.Requested)
	}
	if gap.Ambiguous {
		t.Fatal("a gap is not an ambiguity")
	}

	// Its neighbours are untouched: the shift is local to the day that had the
	// transition, not a permanent change of hour for the schedule.
	for _, i := range []int{0, 2} {
		if occ[i].Shifted != 0 {
			t.Fatalf("occurrence %d was shifted by %s on a day with no transition", i, occ[i].Shifted)
		}
		if h := occ[i].Local(zone).Hour(); h != 2 {
			t.Fatalf("occurrence %d fired at local hour %d, expected 02", i, h)
		}
	}
}

// TestSpringForwardCanBeSkippedAndReported: the alternative policy is available
// and is visible. A skipped wake nobody was told about is indistinguishable from a
// wake that never existed, so the skip travels with the resolution.
func TestSpringForwardCanBeSkippedAndReported(t *testing.T) {
	loc := ny(t)
	s := loc.Daily(schedule.Clock(2, 30))
	s.Gap = schedule.GapSkip

	res, err := s.ResolveReport(utc(t, "2026-03-07T00:00:00Z"), utc(t, "2026-03-10T00:00:00Z"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(res.Occurrences) != 2 {
		t.Fatalf("the gap day must not produce an occurrence, got %d", len(res.Occurrences))
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("the gap day must be reported, got %+v", res.Skipped)
	}
	if !res.Skipped[0].Requested.Equal(utc(t, "2026-03-08T02:30:00Z")) {
		t.Fatalf("the skip must name the wall clock it dropped, got %s", res.Skipped[0].Requested)
	}
	if !errors.Is(res.Skipped[0].Err, schedule.ErrNonexistentLocalTime) {
		t.Fatalf("the skip must carry ErrNonexistentLocalTime, got %v", res.Skipped[0].Err)
	}
	if !errors.Is(res.SkippedErr(), schedule.ErrNonexistentLocalTime) {
		t.Fatalf("SkippedErr must surface the sentinel, got %v", res.SkippedErr())
	}

	// Resolve drops the report but must not invent the occurrence.
	occ, err := s.Resolve(utc(t, "2026-03-07T00:00:00Z"), utc(t, "2026-03-10T00:00:00Z"))
	if err != nil || len(occ) != 2 {
		t.Fatalf("Resolve must agree with ResolveReport, got %d occurrences (%v)", len(occ), err)
	}
}

// TestFallBackFiresOnceAtTheFirstInstant: 01:30 happens twice on 2026-11-01 in
// America/New_York, once at 05:30Z under EDT and again at 06:30Z under EST. The
// documented policy fires the first of the two and only that one, because firing
// twice charges a customer for two wake-ups they asked for one of.
func TestFallBackFiresOnceAtTheFirstInstant(t *testing.T) {
	loc := ny(t)
	zone, _ := loc.Load()
	s := loc.Daily(schedule.Clock(1, 30))

	// The window is deliberately wider than the repeated hour so that both
	// instants are inside it. Only one occurrence may come back.
	res, err := s.ResolveReport(utc(t, "2026-10-31T00:00:00Z"), utc(t, "2026-11-02T12:00:00Z"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(res.Occurrences) != 3 {
		t.Fatalf("expected three occurrences across the 31st and 1st, got %d", len(res.Occurrences))
	}

	ambiguous := res.Occurrences[1]
	if !ambiguous.Start.Equal(utc(t, "2026-11-01T05:30:00Z")) {
		t.Fatalf("the repeated time must fire at the first instant, 05:30Z, got %s", ambiguous.Start)
	}
	if !ambiguous.Ambiguous {
		t.Fatal("an occurrence resolved from a repeated local time must be marked ambiguous")
	}
	if ambiguous.Shifted != 0 {
		t.Fatalf("a repeated time is not shifted, got %s", ambiguous.Shifted)
	}
	if l := ambiguous.Local(zone); l.Hour() != 1 || l.Minute() != 30 {
		t.Fatalf("the occurrence must still read 01:30 local, got %s", l)
	}
	for _, o := range res.Occurrences {
		if o.Start.Equal(utc(t, "2026-11-01T06:30:00Z")) {
			t.Fatal("the repeated local time fired twice")
		}
	}
}

// TestFallBackAmbiguityCanBeRefused: a deployment that would rather escalate than
// assume gets ErrAmbiguousLocalTime instead of a guess.
func TestFallBackAmbiguityCanBeRefused(t *testing.T) {
	loc := ny(t)
	s := loc.Daily(schedule.Clock(1, 30))
	s.Overlap = schedule.OverlapRefuse

	if _, err := s.Resolve(utc(t, "2026-10-31T00:00:00Z"), utc(t, "2026-11-02T12:00:00Z")); !errors.Is(err, schedule.ErrAmbiguousLocalTime) {
		t.Fatalf("want ErrAmbiguousLocalTime, got %v", err)
	}

	// The same schedule resolves once the ambiguity is behind it: refusing must not
	// poison the schedule for every other day.
	if _, err := s.Resolve(utc(t, "2026-11-03T00:00:00Z"), utc(t, "2026-11-05T12:00:00Z")); err != nil {
		t.Fatalf("an unambiguous window must still resolve: %v", err)
	}
}

// TestARepeatedLocalTimeResolvesToTheSameInstantEveryTime: the choice among two
// valid instants must not depend on map iteration order, which is the failure a
// "mostly works" DST implementation exhibits only under load.
func TestARepeatedLocalTimeResolvesToTheSameInstantEveryTime(t *testing.T) {
	loc := ny(t)
	s := loc.Daily(schedule.Clock(1, 30))
	from, until := utc(t, "2026-11-01T00:00:00Z"), utc(t, "2026-11-01T12:00:00Z")

	first, err := s.Resolve(from, until)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for i := 0; i < 200; i++ {
		again, err := s.Resolve(from, until)
		if err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("resolution %d differed: %v vs %v", i, first, again)
		}
	}
}

// TestAGapOfHalfAnHourShiftsByHalfAnHour: the shift is measured, not assumed to
// be an hour. Australia/Lord_Howe springs forward by thirty minutes on 2026-10-04,
// so 02:15 does not exist and the occurrence must land at 02:45.
func TestAGapOfHalfAnHourShiftsByHalfAnHour(t *testing.T) {
	loc, err := schedule.NewLocation("Australia/Lord_Howe")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	zone, _ := loc.Load()
	s := loc.Daily(schedule.Clock(2, 15))

	occ, err := s.Resolve(utc(t, "2026-10-03T00:00:00Z"), utc(t, "2026-10-06T00:00:00Z"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(occ) != 3 {
		t.Fatalf("expected three occurrences, got %d", len(occ))
	}
	gap := occ[0]
	if gap.Shifted != 30*time.Minute {
		t.Fatalf("the shift must be the width of the gap, got %s", gap.Shifted)
	}
	if l := gap.Local(zone); l.Day() != 4 || l.Hour() != 2 || l.Minute() != 45 {
		t.Fatalf("the shifted occurrence must read 02:45 on the 4th, got %s", l)
	}
}

// TestAFoldThatIsNotAWholeHourStillFiresOnce: Australia/Lord_Howe falls back by
// thirty minutes on 2026-04-05, so 01:45 happens twice at 14:45Z and 15:15Z. The
// first-instant rule is about instants, not about hours, and this is the case that
// proves it.
func TestAFoldThatIsNotAWholeHourStillFiresOnce(t *testing.T) {
	loc, err := schedule.NewLocation("Australia/Lord_Howe")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	s := loc.Daily(schedule.ClockTime{Hour: 1, Minute: 45})

	occ, err := s.Resolve(utc(t, "2026-04-04T00:00:00Z"), utc(t, "2026-04-06T00:00:00Z"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(occ) != 2 {
		t.Fatalf("expected two occurrences across the 4th and 5th, got %d", len(occ))
	}
	fold := occ[0]
	if !fold.Start.Equal(utc(t, "2026-04-04T14:45:00Z")) {
		t.Fatalf("the repeated 01:45 must fire at the first instant, 14:45Z, got %s", fold.Start)
	}
	if !fold.Ambiguous || fold.Shifted != 0 {
		t.Fatalf("a fold must be reported as ambiguous and unshifted, got %+v", fold)
	}

	// Refusing is available for the same case, and reports the sentinel.
	s.Overlap = schedule.OverlapRefuse
	if _, err := s.Resolve(utc(t, "2026-04-04T00:00:00Z"), utc(t, "2026-04-06T00:00:00Z")); !errors.Is(err, schedule.ErrAmbiguousLocalTime) {
		t.Fatalf("want ErrAmbiguousLocalTime, got %v", err)
	}
}

// TestEveryResolvedOccurrenceIsARealInstantOrADocumentedShift is the property that
// pins the whole DST implementation: for a year of daily occurrences in three
// awkward zones, every instant either renders as the requested wall clock or is
// reported as having been shifted forward by the transition that caused it.
func TestEveryResolvedOccurrenceIsARealInstantOrADocumentedShift(t *testing.T) {
	zones := []string{"America/New_York", "Europe/Berlin", "Australia/Lord_Howe"}
	for _, name := range zones {
		loc, err := schedule.NewLocation(name)
		if err != nil {
			t.Fatalf("NewLocation(%q): %v", name, err)
		}
		zone, _ := loc.Load()
		s := loc.Daily(schedule.Clock(2, 30))

		from := utc(t, "2026-01-01T00:00:00Z")
		for month := 0; month < 12; month++ {
			until := from.AddDate(0, 0, 20)
			occ, err := s.Resolve(from, until)
			if err != nil {
				t.Fatalf("%s resolve from %s: %v", name, from, err)
			}
			if len(occ) == 0 {
				t.Fatalf("%s produced no occurrences at all", name)
			}
			for _, o := range occ {
				local := o.Local(zone)
				if o.Shifted == 0 {
					if local.Hour() != o.Requested.Hour() || local.Minute() != o.Requested.Minute() {
						t.Fatalf("%s %s fired at %s, not the requested %02d:%02d",
							name, o.Start, local, o.Requested.Hour(), o.Requested.Minute())
					}
					continue
				}
				if o.Shifted <= 0 {
					t.Fatalf("%s %s reports a non-forward shift of %s", name, o.Start, o.Shifted)
				}
				want := o.Requested.Add(o.Shifted)
				if local.Year() != want.Year() || local.YearDay() != want.YearDay() ||
					local.Hour() != want.Hour() || local.Minute() != want.Minute() {
					t.Fatalf("%s %s shifted to %s, not to the reported %s", name, o.Start, local, want)
				}
			}
			from = until
		}
	}
}

// TestResolveIsDeterministic: the same schedule and window must produce an
// identical slice every time, because a scheduler that reorders its own output
// cannot be tested, paged on, or compared between two runs.
func TestResolveIsDeterministic(t *testing.T) {
	loc := ny(t)
	s := loc.Daily(schedule.Clock(2, 30))
	from, until := utc(t, "2026-03-06T00:00:00Z"), utc(t, "2026-03-11T00:00:00Z")

	first, err := s.ResolveReport(from, until)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for i := 0; i < 100; i++ {
		again, err := s.ResolveReport(from, until)
		if err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d differed: %+v vs %+v", i, first, again)
		}
	}
}

// TestOccurrencesAreOrderedAndIndexed: expansion returns a sequence, and a
// sequence that is not ordered is a sequence nobody can consume.
func TestOccurrencesAreOrderedAndIndexed(t *testing.T) {
	loc := ny(t)
	zone, _ := loc.Load()
	s := loc.Weekly(time.Wednesday, schedule.Clock(9, 0))

	occ, err := s.Resolve(utc(t, "2026-01-01T00:00:00Z"), utc(t, "2026-02-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(occ) != 4 {
		t.Fatalf("expected the four Wednesdays of January, got %d", len(occ))
	}
	for i, o := range occ {
		if o.Index != i {
			t.Fatalf("occurrence %d carries index %d", i, o.Index)
		}
		if i > 0 && !o.Start.After(occ[i-1].Start) {
			t.Fatalf("occurrence %d (%s) is not after %s", i, o.Start, occ[i-1].Start)
		}
		if o.Start.Location() != time.UTC {
			t.Fatalf("occurrence %d must be in UTC, got %s", i, o.Start.Location())
		}
		if o.Local(zone).Weekday() != time.Wednesday {
			t.Fatalf("occurrence %d fired on %s", i, o.Local(zone).Weekday())
		}
	}
}

// TestWeeklyOnFiresOnlyOnThatWeekday: a weekly cadence across the spring-forward
// week must not drift onto Thursday, which is what naive local arithmetic does.
func TestWeeklyOnFiresOnlyOnThatWeekday(t *testing.T) {
	loc := ny(t)
	zone, _ := loc.Load()
	s := loc.Weekly(time.Sunday, schedule.Clock(2, 30))

	occ, err := s.Resolve(utc(t, "2026-03-01T00:00:00Z"), utc(t, "2026-03-15T00:00:00Z"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(occ) != 2 {
		t.Fatalf("expected two Sundays, got %d", len(occ))
	}
	for _, o := range occ {
		if o.Local(zone).Weekday() != time.Sunday {
			t.Fatalf("%s fired on %s, not Sunday", o.Start, o.Local(zone).Weekday())
		}
	}
	// 2026-03-08 is the gap Sunday, so it fires shifted and it still fires.
	if occ[1].Shifted != time.Hour {
		t.Fatalf("the gap Sunday must be shifted by an hour, got %s", occ[1].Shifted)
	}
}

// TestAWindowWithNoOccurrencesIsEmptyNotAnError: a caller asking about a
// two-minute window of a daily schedule wants the truth, not a failure.
func TestAWindowWithNoOccurrencesIsEmptyNotAnError(t *testing.T) {
	loc := ny(t)
	s := loc.Daily(schedule.Clock(2, 30))

	res, err := s.ResolveReport(utc(t, "2026-06-10T00:00:00Z"), utc(t, "2026-06-10T00:02:00Z"))
	if err != nil {
		t.Fatalf("an empty window is not a failure: %v", err)
	}
	if len(res.Occurrences) != 0 {
		t.Fatalf("expected no occurrences, got %d", len(res.Occurrences))
	}
	if res.SkippedErr() != nil {
		t.Fatalf("nothing was skipped, so no skip error: %v", res.SkippedErr())
	}
}

// TestTheWindowIsHalfOpen: a caller sliding a window forward by its own width must
// not fire every boundary occurrence twice, so the upper bound is exclusive and
// the lower bound inclusive.
func TestTheWindowIsHalfOpen(t *testing.T) {
	loc := ny(t)
	zone, _ := loc.Load()
	s := loc.Daily(schedule.Clock(9, 0))

	// 09:00 in America/New_York on 2026-06-10 is 13:00Z.
	occurrence := utc(t, "2026-06-10T13:00:00Z")

	occ, err := s.Resolve(occurrence, occurrence.Add(time.Minute))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(occ) != 1 || !occ[0].Start.Equal(occurrence) {
		t.Fatalf("the lower bound must be inclusive, got %v", starts(t, occ))
	}

	occ, err = s.Resolve(occurrence.Add(time.Nanosecond), utc(t, "2026-06-11T13:00:00Z"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(occ) != 0 {
		t.Fatalf("the upper bound must be exclusive, got %v", starts(t, occ))
	}

	occ, err = s.Resolve(utc(t, "2026-06-10T00:00:00Z"), utc(t, "2026-06-11T12:00:00Z"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(occ) != 1 || occ[0].Local(zone).Day() != 10 {
		t.Fatalf("the window must contain exactly the 10th, got %v", starts(t, occ))
	}
}

// TestMoreThanMaxOccurrencesIsRefused: an unbounded expansion is refused rather
// than truncated, because a truncated list is a lie about what will happen.
func TestMoreThanMaxOccurrencesIsRefused(t *testing.T) {
	loc := ny(t)
	s := loc.Daily(schedule.Clock(9, 0))
	s.Cadence.Count = schedule.MaxOccurrences + 1

	if err := s.Validate(); !errors.Is(err, schedule.ErrTooManyOccurrences) {
		t.Fatalf("Validate must refuse a count above the bound, got %v", err)
	}
	if _, err := s.Resolve(utc(t, "2026-06-01T00:00:00Z"), utc(t, "2026-06-03T00:00:00Z")); !errors.Is(err, schedule.ErrTooManyOccurrences) {
		t.Fatalf("Resolve must refuse it too, got %v", err)
	}

	// The bound itself is legal, and a window that fits inside it resolves.
	ok := loc.Daily(schedule.Clock(9, 0))
	ok.Cadence.Count = schedule.MaxOccurrences
	if err := ok.Validate(); err != nil {
		t.Fatalf("a cadence at the bound must be legal: %v", err)
	}
	occ, err := ok.Resolve(utc(t, "2026-06-01T00:00:00Z"), utc(t, "2026-06-11T00:00:00Z"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(occ) != 10 {
		t.Fatalf("expected ten occurrences, got %d", len(occ))
	}
}

// TestAWideWindowIsRefusedNotTruncated: a cadence that claims fewer occurrences
// than the window can hold is a question that must be answered by refusing.
func TestAWideWindowIsRefusedNotTruncated(t *testing.T) {
	loc, err := schedule.NewLocation("Etc/UTC")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	s := loc.Daily(schedule.Clock(9, 0))
	s.Cadence.Count = 3

	_, err = s.Resolve(utc(t, "2026-06-01T00:00:00Z"), utc(t, "2026-06-11T00:00:00Z"))
	if !errors.Is(err, schedule.ErrTooManyOccurrences) {
		t.Fatalf("a ten day window against a three occurrence claim must be refused, got %v", err)
	}

	occ, err := s.Resolve(utc(t, "2026-06-01T00:00:00Z"), utc(t, "2026-06-04T00:00:00Z"))
	if err != nil {
		t.Fatalf("a window inside the claim must resolve: %v", err)
	}
	if len(occ) != 3 {
		t.Fatalf("expected the claimed three, got %d", len(occ))
	}

	// The bound counts occurrences that actually fall in the window, so a window
	// whose trailing local date cannot fire resolves rather than being refused for
	// a candidate it was never going to produce.
	occ, err = s.Resolve(utc(t, "2026-06-01T09:00:00Z"), utc(t, "2026-06-04T09:00:00Z"))
	if err != nil {
		t.Fatalf("a window of three occurrences must resolve: %v", err)
	}
	if len(occ) != 3 {
		t.Fatalf("expected three occurrences, got %d", len(occ))
	}
}

// TestAnIntervalCadenceIsAbsoluteTimeAndUnaffectedByDST: "every six hours" means
// six hours, so the local hour of the firing drifts across a transition. That is
// the correct behaviour for an interval and the reason it is a separate kind.
func TestAnIntervalCadenceIsAbsoluteTimeAndUnaffectedByDST(t *testing.T) {
	loc := ny(t)
	s := loc.Every(6 * time.Hour)

	occ, err := s.Resolve(utc(t, "2026-03-08T00:00:00Z"), utc(t, "2026-03-08T18:00:00Z"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(occ) != 3 {
		t.Fatalf("expected three firings, got %d", len(occ))
	}
	for i := 1; i < len(occ); i++ {
		if got := occ[i].Start.Sub(occ[i-1].Start); got != 6*time.Hour {
			t.Fatalf("interval %d is %s apart, not six hours", i, got)
		}
	}
	for _, o := range occ {
		if o.Shifted != 0 || o.Ambiguous {
			t.Fatalf("an interval cadence has no wall clock to shift: %+v", o)
		}
	}
}

// TestAWideIntervalWindowIsRefused: the interval case computes its candidate count
// exactly, and refuses before expanding rather than during.
func TestAWideIntervalWindowIsRefused(t *testing.T) {
	loc := ny(t)
	s := loc.Every(time.Minute)

	_, err := s.Resolve(utc(t, "2026-06-01T00:00:00Z"), utc(t, "2026-06-01T05:00:00Z"))
	if !errors.Is(err, schedule.ErrTooManyOccurrences) {
		t.Fatalf("301 occurrences must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "bound") {
		t.Fatalf("the refusal must state the bound, got %q", err)
	}
}

// TestAnInvalidCadenceIsRefused: a rule that cannot be expanded is refused at the
// point it is stored, not at 02:30 on the day it fails.
func TestAnInvalidCadenceIsRefused(t *testing.T) {
	loc := ny(t)
	cases := []struct {
		name string
		mut  func(*schedule.Schedule)
	}{
		{"unknown kind", func(s *schedule.Schedule) { s.Cadence.Kind = "fortnightly" }},
		{"zero interval", func(s *schedule.Schedule) { s.Cadence.Kind, s.Cadence.Every = schedule.KindEvery, 0 }},
		{"negative interval", func(s *schedule.Schedule) { s.Cadence.Kind, s.Cadence.Every = schedule.KindEvery, -time.Hour }},
		{"sub-minute interval", func(s *schedule.Schedule) { s.Cadence.Kind, s.Cadence.Every = schedule.KindEvery, time.Second }},
		{"hour out of range", func(s *schedule.Schedule) {
			s.Cadence.Kind, s.Cadence.At = schedule.KindDaily, schedule.ClockTime{Hour: 24}
		}},
		{"negative hour", func(s *schedule.Schedule) {
			s.Cadence.Kind, s.Cadence.At = schedule.KindDaily, schedule.ClockTime{Hour: -1}
		}},
		{"minute out of range", func(s *schedule.Schedule) {
			s.Cadence.Kind, s.Cadence.At = schedule.KindDaily, schedule.ClockTime{Hour: 1, Minute: 60}
		}},
		{"second out of range", func(s *schedule.Schedule) {
			s.Cadence.Kind, s.Cadence.At = schedule.KindDaily, schedule.ClockTime{Hour: 1, Second: 60}
		}},
		{"weekday out of range", func(s *schedule.Schedule) {
			s.Cadence = schedule.Cadence{Kind: schedule.KindWeekly, On: time.Weekday(9), At: schedule.Clock(1, 0)}
		}},
		{"negative count", func(s *schedule.Schedule) { s.Cadence.Count = -1 }},
		{"unknown gap policy", func(s *schedule.Schedule) { s.Gap = "round_down" }},
		{"unknown overlap policy", func(s *schedule.Schedule) { s.Overlap = "last" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := loc.Daily(schedule.Clock(9, 0))
			c.mut(&s)
			if err := s.Validate(); err == nil {
				t.Fatal("an unusable cadence must be refused")
			}
			if _, err := s.Resolve(utc(t, "2026-06-01T00:00:00Z"), utc(t, "2026-06-02T00:00:00Z")); err == nil {
				t.Fatal("an unusable cadence must not expand")
			}
		})
	}
}

// TestAWindowMustContainAMoment: an inverted window is a caller bug, and silently
// expanding it would return nothing at all.
func TestAWindowMustContainAMoment(t *testing.T) {
	loc := ny(t)
	s := loc.Daily(schedule.Clock(9, 0))
	at := utc(t, "2026-06-01T00:00:00Z")

	for _, w := range [][2]time.Time{{at, at}, {at, at.Add(-time.Hour)}} {
		if _, err := s.Resolve(w[0], w[1]); !errors.Is(err, schedule.ErrInvalidWindow) {
			t.Fatalf("window %s..%s must be refused, got %v", w[0], w[1], err)
		}
	}
}

// TestTheSameCadenceInTwoZonesIsTwoSchedules: the zone is part of the promise, so
// an identical clock time in two zones must not resolve to the same instant.
func TestTheSameCadenceInTwoZonesIsTwoSchedules(t *testing.T) {
	tokyo, err := schedule.NewLocation("Asia/Tokyo")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	from := utc(t, "2026-06-01T00:00:00Z")
	until := utc(t, "2026-06-02T00:00:00Z")

	inNY, err := ny(t).Daily(schedule.Clock(9, 0)).Resolve(from, until)
	if err != nil {
		t.Fatalf("resolve new york: %v", err)
	}
	inTokyo, err := tokyo.Daily(schedule.Clock(9, 0)).Resolve(from, until)
	if err != nil {
		t.Fatalf("resolve tokyo: %v", err)
	}
	if len(inNY) != 1 || len(inTokyo) != 1 {
		t.Fatalf("expected one occurrence each, got %d and %d", len(inNY), len(inTokyo))
	}
	if inNY[0].Start.Equal(inTokyo[0].Start) {
		t.Fatal("the same wall clock in two zones must be two instants")
	}
	if got := inNY[0].Start.Sub(inTokyo[0].Start); got != 13*time.Hour {
		t.Fatalf("the two instants are %s apart, expected the zone offsets to explain it", got)
	}
}

// TestTheZeroScheduleNamesNoZone: a Schedule built by hand rather than from a
// Location must not expand, because the alternative is the server's locale.
func TestTheZeroScheduleNamesNoZone(t *testing.T) {
	var s schedule.Schedule
	s.Cadence = schedule.Cadence{Kind: schedule.KindDaily, At: schedule.Clock(9, 0)}

	if err := s.Validate(); !errors.Is(err, schedule.ErrImplicitLocation) {
		t.Fatalf("want ErrImplicitLocation, got %v", err)
	}
	if _, err := s.Resolve(utc(t, "2026-06-01T00:00:00Z"), utc(t, "2026-06-02T00:00:00Z")); err == nil {
		t.Fatal("a schedule naming no zone must not expand")
	}
}

// TestTheStoredPoliciesDefaultToTheSpecification: an older stored schedule with no
// recorded policy must keep meaning what it meant, which is the documented
// PRODUCT-SEC.md rule.
func TestTheStoredPoliciesDefaultToTheSpecification(t *testing.T) {
	loc := ny(t)
	s := loc.Daily(schedule.Clock(2, 30))
	if s.Gap != "" || s.Overlap != "" {
		t.Fatal("the constructors must leave the policies unset so the defaults apply")
	}
	occ, err := s.Resolve(utc(t, "2026-03-08T00:00:00Z"), utc(t, "2026-03-09T00:00:00Z"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(occ) != 1 || occ[0].Shifted != time.Hour {
		t.Fatalf("the default gap policy must shift forward, got %+v", occ)
	}

	fold := loc.Daily(schedule.Clock(1, 30))
	foldOcc, err := fold.Resolve(utc(t, "2026-11-01T00:00:00Z"), utc(t, "2026-11-02T00:00:00Z"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(foldOcc) != 1 || !foldOcc[0].Ambiguous ||
		!foldOcc[0].Start.Equal(utc(t, "2026-11-01T05:30:00Z")) {
		t.Fatalf("the default overlap policy must take the first instant, got %+v", foldOcc)
	}
}

// TestAClockTimeRendersAsWritten: the schedule a customer reads back must be the
// schedule they wrote.
func TestAClockTimeRendersAsWritten(t *testing.T) {
	cases := map[string]schedule.ClockTime{
		"09:00:00": schedule.Clock(9, 0),
		"00:00:00": schedule.ClockTime{},
		"23:59:59": schedule.ClockTime{Hour: 23, Minute: 59, Second: 59},
	}
	for want, c := range cases {
		if got := c.String(); got != want {
			t.Errorf("ClockTime %+v rendered %q, want %q", c, got, want)
		}
	}
}
