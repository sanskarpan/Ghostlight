package scheduling

import (
	"errors"
	"testing"
	"time"
)

var base = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func at(hours int) time.Time { return base.Add(time.Duration(hours) * time.Hour) }

func win(from, to int) Window { return Window{Start: at(from), End: at(to)} }

func mustErr(t *testing.T, err error, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

func state(pool int, teams ...Team) *State {
	return &State{PoolSize: pool, Teams: teams}
}

func team(id string, weight, maxConcurrent int) Team {
	return Team{ID: id, Weight: weight, MaxConcurrent: maxConcurrent}
}

// A half-open interval: two windows sharing only an endpoint do not overlap, and
// treating them as overlapping would make back-to-back reservations impossible.
func TestWindowsAreHalfOpen(t *testing.T) {
	if win(0, 2).Overlaps(win(2, 4)) {
		t.Fatal("back-to-back windows are reported as overlapping")
	}
	if !win(0, 3).Overlaps(win(2, 4)) {
		t.Fatal("windows sharing an hour are reported as disjoint")
	}
	if win(0, 2).Overlaps(win(4, 6)) {
		t.Fatal("disjoint windows are reported as overlapping")
	}
	if (Window{Start: base, End: base}).Valid() {
		t.Fatal("an empty window is treated as valid")
	}
}

// THE RULE THE PACKAGE EXISTS FOR, first direction. Three reservations in three
// disjoint windows never contend, so a pool of two must admit all three. A scheduler
// that checked against the sum of everything reserved would refuse the second and third
// and call the pool full while nothing was running.
func TestDisjointWindowsDoNotConsumeEachOthersCapacity(t *testing.T) {
	s := state(2, team("a", 1, 0))
	for _, w := range []Window{win(0, 2), win(2, 4), win(4, 6)} {
		if _, _, err := s.Reserve(Request{ID: "r-" + w.Start.Format("15"), TeamID: "a", Window: w, Slots: 2}); err != nil {
			t.Fatalf("reserving %s to %s: %v", w.Start, w.End, err)
		}
	}
	if len(s.Reservations) != 3 {
		t.Fatalf("%d reservations, want 3", len(s.Reservations))
	}
	// And each window is genuinely at capacity, so the admission above was not merely
	// permissive because nothing counted.
	if got := s.PeakUsage(win(0, 2)); got != 2 {
		t.Fatalf("peak usage in the first window is %d, want 2", got)
	}
}

// Second direction: reservations that overlap do contend, even when they were made at
// different moments. This is the case a total-based check gets wrong the other way.
func TestOverlappingWindowsCannotOverbookThePool(t *testing.T) {
	s := state(2, team("a", 1, 0))
	if _, _, err := s.Reserve(Request{ID: "r1", TeamID: "a", Window: win(0, 4), Slots: 2}); err != nil {
		t.Fatalf("first reservation: %v", err)
	}
	// One overlapping hour is enough.
	_, _, err := s.Reserve(Request{ID: "r2", TeamID: "a", Window: win(3, 8), Slots: 1})
	mustErr(t, err, ErrPoolExhausted, "an overlapping reservation")
	if len(s.Reservations) != 1 {
		t.Fatal("a refused reservation was recorded")
	}
}

// A reservation that fits beside an existing one in time fits, and one that overlaps
// partially does not. The boundary is the interesting part: an hour of overlap is
// overlap.
func TestPartialOverlapAtTheBoundary(t *testing.T) {
	cases := []struct {
		name string
		w    Window
		ok   bool
	}{
		{"entirely before", win(-4, 0), true},
		{"entirely after", win(4, 8), true},
		{"touching at the end", win(4, 6), true},
		{"touching at the start", win(-2, 0), true},
		{"one hour in", win(3, 6), false},
		{"one hour before", win(-2, 1), false},
		{"contained", win(1, 2), false},
		{"containing", win(-2, 6), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := state(1, team("a", 1, 0))
			if _, _, err := s.Reserve(Request{ID: "held", TeamID: "a", Window: win(0, 4), Slots: 1}); err != nil {
				t.Fatalf("holding reservation: %v", err)
			}
			_, _, err := s.Reserve(Request{ID: "candidate", TeamID: "a", Window: c.w, Slots: 1})
			if c.ok && err != nil {
				t.Fatalf("should have been admitted: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("should have been refused")
			}
		})
	}
}

// A release inside a window gives capacity back from that moment, not from the start of
// the window. Crediting the whole window would invent capacity nobody held.
func TestAReleaseFreesCapacityFromTheMomentItHappened(t *testing.T) {
	s := state(1, team("a", 1, 0))
	if _, _, err := s.Reserve(Request{ID: "early", TeamID: "a", Window: win(0, 8), Slots: 1}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if err := s.Release("early", at(4)); err != nil {
		t.Fatalf("release: %v", err)
	}
	// Before the release the slot is still taken.
	_, _, err := s.Reserve(Request{ID: "before", TeamID: "a", Window: win(1, 3), Slots: 1})
	mustErr(t, err, ErrPoolExhausted, "a window before the release")
	// After it, the slot is free.
	if _, _, err := s.Reserve(Request{ID: "after", TeamID: "a", Window: win(5, 7), Slots: 1}); err != nil {
		t.Fatalf("a window after the release should fit: %v", err)
	}
}

// The quieter half of overbooking: the pool regains the slots twice and the next
// reservation that fits is one the platform cannot run.
func TestReleasingTwiceIsRefusedRatherThanDoubleCounted(t *testing.T) {
	s := state(1, team("a", 1, 0))
	if _, _, err := s.Reserve(Request{ID: "r1", TeamID: "a", Window: win(0, 4), Slots: 1}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if err := s.Release("r1", at(1)); err != nil {
		t.Fatalf("release: %v", err)
	}
	err := s.Release("r1", at(2))
	mustErr(t, err, ErrAlreadyReleased, "a second release")
	mustErr(t, s.Release("never-existed", at(2)), ErrUnknownReservation, "releasing an unknown reservation")
}

// A team's own ceiling binds before the pool in some windows and after it in others, and
// the refusal must name whichever bound. A refusal that does not say what bound is a
// support ticket rather than an answer.
func TestTheTeamCeilingBindsIndependentlyOfThePool(t *testing.T) {
	s := state(10, team("a", 1, 2), team("b", 1, 0))
	if _, _, err := s.Reserve(Request{ID: "r1", TeamID: "a", Window: win(0, 4), Slots: 2}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	_, d, err := s.Reserve(Request{ID: "r2", TeamID: "a", Window: win(0, 4), Slots: 1})
	mustErr(t, err, ErrTeamQuotaExceeded, "a request over the team ceiling")
	if d.Reason == "" {
		t.Fatal("the refusal named no bound")
	}
	// The pool is nowhere near full, so the reason must be about the team.
	if s.PeakUsage(win(0, 4)) != 2 {
		t.Fatalf("peak usage is %d, want the team's 2", s.PeakUsage(win(0, 4)))
	}
	// Another team is unaffected.
	if _, _, err := s.Reserve(Request{ID: "r3", TeamID: "b", Window: win(0, 4), Slots: 1}); err != nil {
		t.Fatalf("another team should fit: %v", err)
	}
}

// The pool binds first when it is smaller than any team's ceiling.
func TestThePoolRefusalNamesThePool(t *testing.T) {
	s := state(1, team("a", 1, 5))
	if _, _, err := s.Reserve(Request{ID: "r1", TeamID: "a", Window: win(0, 4), Slots: 1}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, _, err := s.Reserve(Request{ID: "r2", TeamID: "a", Window: win(1, 2), Slots: 1}); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("got %v, want the pool refusal", err)
	}
}

func TestRequestsAreValidated(t *testing.T) {
	s := state(2, team("a", 1, 0))
	cases := map[string]Request{
		"no team":        {ID: "r", TeamID: "", Window: win(0, 1), Slots: 1},
		"unknown team":   {ID: "r", TeamID: "ghost", Window: win(0, 1), Slots: 1},
		"no slots":       {ID: "r", TeamID: "a", Window: win(0, 1), Slots: 0},
		"negative slots": {ID: "r", TeamID: "a", Window: win(0, 1), Slots: -1},
		"backwards":      {ID: "r", TeamID: "a", Window: win(2, 1), Slots: 1},
		"empty window":   {ID: "r", TeamID: "a", Window: win(1, 1), Slots: 1},
		"too long":       {ID: "r", TeamID: "a", Window: Window{Start: base, End: base.Add(MaxWindow + time.Hour)}, Slots: 1},
	}
	for name, req := range cases {
		if _, err := s.Admit(req); err == nil {
			t.Fatalf("%s: an invalid request was admitted", name)
		}
	}
}

func TestADuplicateReservationIdIsRefused(t *testing.T) {
	s := state(4, team("a", 1, 0))
	if _, _, err := s.Reserve(Request{ID: "same", TeamID: "a", Window: win(0, 2), Slots: 1}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	_, _, err := s.Reserve(Request{ID: "same", TeamID: "a", Window: win(4, 6), Slots: 1})
	mustErr(t, err, ErrInvalidRequest, "a duplicate id in a disjoint window")
}

// Admitting and recording are one call, because a caller that admits and then fails to
// record has booked capacity nobody holds.
func TestARefusedReservationIsNeverRecorded(t *testing.T) {
	s := state(1, team("a", 1, 0))
	if _, _, err := s.Reserve(Request{ID: "r1", TeamID: "a", Window: win(0, 2), Slots: 1}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	before := len(s.Reservations)
	if _, _, err := s.Reserve(Request{ID: "r2", TeamID: "a", Window: win(1, 3), Slots: 1}); err == nil {
		t.Fatal("an overbooked request was admitted")
	}
	if len(s.Reservations) != before {
		t.Fatalf("the table grew from %d to %d on a refusal", before, len(s.Reservations))
	}
}

// An unbounded promise: every reservation looked fine when it was accepted.
func TestTheReservationTableIsBounded(t *testing.T) {
	s := state(1, team("a", 1, 0))
	// Fill the table directly, because a realistic loop would take too long and the
	// bound is what is under test rather than the admission path.
	for i := 0; i < MaxReservations; i++ {
		s.Reservations = append(s.Reservations, Reservation{
			ID: "r" + itoa(i), TeamID: "a", Window: win(0, 1), Slots: 0,
		})
	}
	_, _, err := s.Reserve(Request{ID: "one-more", TeamID: "a", Window: win(100, 101), Slots: 1})
	mustErr(t, err, ErrTooManyReservations, "a full table")
}

// Fair share is proportional, deterministic, and never gives a team nothing.
func TestFairShareIsProportionalAndDeterministic(t *testing.T) {
	teams := []Team{team("a", 1, 0), team("b", 2, 0)}
	got, err := FairShare(teams, 3)
	if err != nil {
		t.Fatalf("fair share: %v", err)
	}
	if got["a"] != 1 || got["b"] != 2 {
		t.Fatalf("allocation %v, want a=1 b=2", got)
	}
	// Deterministic across repeated calls and across input order.
	for i := 0; i < 20; i++ {
		again, err := FairShare(teams, 3)
		if err != nil {
			t.Fatalf("fair share: %v", err)
		}
		if again["a"] != got["a"] || again["b"] != got["b"] {
			t.Fatalf("allocation varies between runs: %v then %v", got, again)
		}
	}
	reversed := []Team{team("b", 2, 0), team("a", 1, 0)}
	again, err := FairShare(reversed, 3)
	if err != nil {
		t.Fatalf("fair share: %v", err)
	}
	if again["a"] != 1 || again["b"] != 2 {
		t.Fatalf("input order changed the allocation: %v", again)
	}
}

// The remainder goes to the largest fraction, and a tie is broken by id so the same
// demand always produces the same allocation. A fair-share algorithm that varies between
// runs cannot be told apart from an unfair one.
func TestFairShareRemainderIsResolvedDeterministically(t *testing.T) {
	// Three equal weights over two slots: two teams get one and one gets none, and
	// which one is decided by id rather than by map order.
	teams := []Team{team("c", 1, 0), team("a", 1, 0), team("b", 1, 0)}
	first, err := FairShare(teams, 2)
	if err != nil {
		t.Fatalf("fair share: %v", err)
	}
	total := 0
	for _, v := range first {
		total += v
	}
	if total != 2 {
		t.Fatalf("allocation %v totals %d, want the whole pool of 2", first, total)
	}
	for i := 0; i < 20; i++ {
		again, err := FairShare(teams, 2)
		if err != nil {
			t.Fatalf("fair share: %v", err)
		}
		for k, v := range first {
			if again[k] != v {
				t.Fatalf("allocation changed between runs: %v then %v", first, again)
			}
		}
	}
}

func TestFairShareRefusesWhatItCannotSplit(t *testing.T) {
	if _, err := FairShare(nil, 4); err == nil {
		t.Fatal("sharing a pool with nobody was accepted")
	}
	if _, err := FairShare([]Team{team("a", 1, 0)}, 0); err == nil {
		t.Fatal("a pool of zero was accepted")
	}
	// A zero-weight team can never be allocated anything, so a team that exists but can
	// never run is a configuration mistake rather than a policy.
	if _, err := FairShare([]Team{team("a", 0, 0)}, 4); err == nil {
		t.Fatal("a zero-weight team was accepted")
	}
	if _, err := FairShare([]Team{team("a", 1, 0), team("a", 1, 0)}, 4); err == nil {
		t.Fatal("a duplicated team was accepted")
	}
	if _, err := FairShare([]Team{{ID: "", Weight: 1}}, 4); err == nil {
		t.Fatal("a team with no id was accepted")
	}
}

// Peak usage is a question about a moment, and it must agree with what admission
// enforces — a metric that disagrees with the gate is worse than no metric.
func TestPeakUsageAgreesWithAdmission(t *testing.T) {
	s := state(3, team("a", 1, 0))
	for i, w := range []Window{win(0, 10), win(2, 6), win(4, 8)} {
		if _, _, err := s.Reserve(Request{ID: "r" + itoa(i), TeamID: "a", Window: w, Slots: 1}); err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
	}
	// At hour 5 all three hold, so the peak is the pool and no fourth fits there.
	if got := s.PeakUsage(win(4, 6)); got != 3 {
		t.Fatalf("peak at hour 5 is %d, want 3", got)
	}
	if _, _, err := s.Reserve(Request{ID: "fourth", TeamID: "a", Window: win(4, 5), Slots: 1}); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("a fourth overlapping slot: %v", err)
	}
	// At hour 9 only the first holds, so there is room.
	if got := s.PeakUsage(win(8, 10)); got != 1 {
		t.Fatalf("peak at hour 9 is %d, want 1", got)
	}
	if _, _, err := s.Reserve(Request{ID: "later", TeamID: "a", Window: win(8, 10), Slots: 2}); err != nil {
		t.Fatalf("a slot beside one holder: %v", err)
	}
}

// The end-to-end shape: several teams reserving around each other, with the pool never
// exceeded at any instant and the disjoint-window case still admitted.
func TestManyTeamsReserveWithoutOverbooking(t *testing.T) {
	s := state(4, team("a", 1, 0), team("b", 1, 0), team("c", 1, 0))
	plan := []struct {
		id   string
		team string
		w    Window
		ok   bool
	}{
		{"a1", "a", win(0, 4), true},
		{"b1", "b", win(0, 4), true},
		{"c1", "c", win(0, 4), true},
		{"a2", "a", win(0, 4), true},  // the pool is exactly full at hour 1
		{"b2", "b", win(1, 2), false}, // one more inside the full window does not fit
		{"c2", "c", win(4, 8), true},  // back-to-back is not overlap
		{"a3", "a", win(2, 6), false}, // overlaps the full window by two hours
		{"b3", "b", win(8, 12), true}, // entirely after everything
	}
	for _, p := range plan {
		_, _, err := s.Reserve(Request{ID: p.id, TeamID: p.team, Window: p.w, Slots: 1})
		if p.ok && err != nil {
			t.Fatalf("%s should have been admitted: %v", p.id, err)
		}
		if !p.ok && err == nil {
			t.Fatalf("%s should have been refused", p.id)
		}
	}
	// The invariant, checked after the fact: no instant in the whole span exceeds the
	// pool.
	if got := s.PeakUsage(win(-1, 14)); got > s.PoolSize {
		t.Fatalf("the pool reached %d over %d after the whole plan", got, s.PoolSize)
	}
}

// itoa keeps the generators readable without pulling strconv in for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
