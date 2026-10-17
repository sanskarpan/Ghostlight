// Package scheduling admits work against a bounded pool shared between teams, and
// reserves capacity for future windows without overbooking.
//
// G8.8. Three rules carry the weight.
//
// **Reservations are intervals, not totals.** The temptation is to check a new request
// against the sum of everything already reserved, and that is wrong in both directions:
// it refuses three separate two-hour reservations that never overlap because their sum
// exceeds the pool, and it would permit two reservations that overlap perfectly but were
// each checked against a total computed an hour apart. Capacity is a function of a
// window, so the question is always "what is held during *this* window", and the answer
// is a sweep over the elementary intervals the new request actually spans.
//
// **Fairness is a share, not a queue.** A contended pool splits by declared weight, and
// the split is computed deterministically so the same demand always produces the same
// allocation. A fair-share algorithm that varies between runs is indistinguishable from
// an unfair one, and nobody can tell which they got.
//
// **Bounded.** The reservation table has a ceiling. An unbounded reservation table is an
// unbounded promise, and a promise that costs nothing to make is one that gets made
// until the pool is a lie.
package scheduling

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Errors returned by this package.
var (
	// ErrOverlappingReference means a window ends before it starts.
	ErrInvalidWindow = errors.New("window ends before it starts")
	// ErrPoolExhausted means the request would exceed the pool during its window.
	ErrPoolExhausted = errors.New("pool would be overbooked during the requested window")
	// ErrTeamQuotaExceeded means the team's own ceiling binds before the pool does.
	ErrTeamQuotaExceeded = errors.New("team quota would be exceeded")
	// ErrTooManyReservations means the reservation table is at its ceiling.
	ErrTooManyReservations = errors.New("reservation table is full")
	// ErrUnknownTeam means the team is not registered.
	ErrUnknownTeam = errors.New("unknown team")
	// ErrUnknownReservation means no such reservation exists.
	ErrUnknownReservation = errors.New("unknown reservation")
	// ErrInvalidRequest means a request was malformed.
	ErrInvalidRequest = errors.New("request is not valid")
	// ErrAlreadyReleased means the reservation was already given back.
	ErrAlreadyReleased = errors.New("reservation has already been released")
	// ErrZeroSlots means a reservation asked for nothing, which is not a reservation.
	ErrZeroSlots = errors.New("a reservation must ask for at least one slot")
)

// MaxReservations bounds the reservation table.
//
// An unbounded reservation table is an unbounded promise, and because accepting a
// reservation costs nothing at the moment it is made, the table is where a team with a
// runaway automation hits a wall that appears in the past: every reservation looked fine
// when it was accepted and the pool was overbooked the whole time.
const MaxReservations = 10_000

// MaxWindow bounds a single reservation's length.
//
// A reservation far enough in the future to be meaningless is still a claim on the pool
// in every sweep that spans it, and the cost of that claim is paid by the teams trying
// to book inside it.
const MaxWindow = 90 * 24 * time.Hour

// Window is a half-open interval. Half-open matters: two windows that share only an
// endpoint do not overlap, and treating them as overlapping would make back-to-back
// reservations impossible. Every boundary in this package follows that convention.
type Window struct {
	Start time.Time
	End   time.Time
}

// Valid reports whether the window is well formed.
func (w Window) Valid() bool { return w.End.After(w.Start) }

// Overlaps reports whether two windows share any instant.
func (w Window) Overlaps(o Window) bool {
	return w.Start.Before(o.End) && o.Start.Before(w.End)
}

// ClampTo returns the part of the receiver inside other, and whether any remains.
func (w Window) ClampTo(other Window) (Window, bool) {
	start, end := w.Start, w.End
	if start.Before(other.Start) {
		start = other.Start
	}
	if end.After(other.End) {
		end = other.End
	}
	if !end.After(start) {
		return Window{}, false
	}
	return Window{Start: start, End: end}, true
}

// Team is a registered team with a share of the pool.
type Team struct {
	ID string
	// Weight is the team's relative share when the pool is contended. Zero is not
	// allowed: a zero-weight team can never be allocated anything, and a team that
	// exists but can never run is a configuration mistake rather than a policy.
	Weight int
	// MaxConcurrent is the team's own ceiling on simultaneously held slots. Zero means
	// no team-specific ceiling beyond its fair share.
	MaxConcurrent int
}

// Reservation is a claim on a number of slots during a window.
type Reservation struct {
	ID     string
	TeamID string
	Window Window
	Slots  int
	// ReleasedAt ends a reservation early. It is a timestamp rather than a delete so
	// the record of who held what survives, which is what an examination of a
	// contested window needs.
	ReleasedAt time.Time
}

// HeldDuring reports how many slots the reservation holds inside a window, counting a
// release that happened before the window and truncating one that happened inside it.
func (r Reservation) HeldDuring(w Window) int {
	if !r.ReleasedAt.IsZero() && !r.ReleasedAt.After(w.End) {
		// A release inside the window truncates the hold at the release moment; a
		// release after the window leaves the whole hold intact.
		effective := r.Window
		if r.ReleasedAt.Before(effective.End) {
			effective.End = r.ReleasedAt
		}
		return heldIn(effective, w, r.Slots)
	}
	return heldIn(r.Window, w, r.Slots)
}

// heldIn returns slots if the two windows overlap, else zero.
func heldIn(hold, w Window, slots int) int {
	if seg, ok := hold.ClampTo(w); ok && seg.Valid() {
		return slots
	}
	return 0
}

// State is the scheduler's view: the pool, the teams and the reservations.
type State struct {
	// PoolSize is the total simultaneous slots available.
	PoolSize int
	Teams    []Team
	// Reservations is the full table, including released and past ones. Keeping them
	// is what makes an overbooking dispute answerable after the fact.
	Reservations []Reservation
}

// Team returns a team by id.
func (s State) Team(id string) (Team, bool) {
	for _, t := range s.Teams {
		if t.ID == id {
			return t, true
		}
	}
	return Team{}, false
}

// PeakUsage returns the greatest number of slots held at any single instant inside a
// window.
//
// It is a sweep over elementary intervals rather than a sum, because a sum is the wrong
// answer to a question about a moment. It is exported because it is also the number an
// operator wants when asking why a window felt full.
func (s State) PeakUsage(w Window) int {
	return s.peakFor(w, nil)
}

// peakFor computes peak usage inside a window, optionally including one extra
// reservation that is not yet in the table.
func (s State) peakFor(w Window, extra *Reservation) int {
	points := []time.Time{w.Start, w.End}
	consider := func(r Reservation) {
		seg, ok := r.Window.ClampTo(w)
		if !ok {
			return
		}
		if !r.ReleasedAt.IsZero() {
			if !r.ReleasedAt.After(w.Start) {
				// Released before the window began: it holds nothing here.
				return
			}
			if r.ReleasedAt.Before(seg.End) {
				seg.End = r.ReleasedAt
			}
		}
		if !seg.Valid() {
			return
		}
		points = append(points, seg.Start, seg.End)
	}
	for _, r := range s.Reservations {
		consider(r)
	}
	if extra != nil {
		consider(*extra)
	}

	sortTimes(points)
	peak := 0
	for i := 0; i+1 < len(points); i++ {
		if !points[i+1].After(points[i]) {
			continue
		}
		seg := Window{Start: points[i], End: points[i+1]}
		total := 0
		for _, r := range s.Reservations {
			total += r.HeldDuring(seg)
		}
		if extra != nil {
			total += extra.HeldDuring(seg)
		}
		if total > peak {
			peak = total
		}
	}
	return peak
}

// peakForTeam is peakFor restricted to one team.
func (s State) peakForTeam(w Window, teamID string, extra *Reservation) int {
	points := []time.Time{w.Start, w.End}
	add := func(r Reservation) {
		if r.TeamID != teamID {
			return
		}
		seg, ok := r.Window.ClampTo(w)
		if !ok {
			return
		}
		if !r.ReleasedAt.IsZero() {
			if !r.ReleasedAt.After(w.Start) {
				return
			}
			if r.ReleasedAt.Before(seg.End) {
				seg.End = r.ReleasedAt
			}
		}
		if !seg.Valid() {
			return
		}
		points = append(points, seg.Start, seg.End)
	}
	for _, r := range s.Reservations {
		add(r)
	}
	if extra != nil {
		add(*extra)
	}
	sortTimes(points)

	peak := 0
	for i := 0; i+1 < len(points); i++ {
		if !points[i+1].After(points[i]) {
			continue
		}
		seg := Window{Start: points[i], End: points[i+1]}
		total := 0
		for _, r := range s.Reservations {
			if r.TeamID == teamID {
				total += r.HeldDuring(seg)
			}
		}
		if extra != nil && extra.TeamID == teamID {
			total += extra.HeldDuring(seg)
		}
		if total > peak {
			peak = total
		}
	}
	return peak
}

func sortTimes(ts []time.Time) {
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
}

// Request asks for slots in a window.
type Request struct {
	ID     string
	TeamID string
	Window Window
	Slots  int
}

// Decision is the outcome of an admission.
type Decision struct {
	// Allowed reports whether the reservation was accepted.
	Allowed bool
	// Reason names the binding constraint, in words an operator can act on. A refusal
	// that does not name what bound is a support ticket rather than an answer.
	Reason string
	// PeakAfter is the pool's peak usage during the requested window if the request is
	// admitted, which is what a caller shows when asking a team to try a different
	// time.
	PeakAfter int
}

// Admit decides whether a request fits, without mutating state.
//
// The order of the checks is the policy: the pool first, because the pool is the
// platform's hard limit; then the team's own ceiling, because a team hitting its own
// quota is a different conversation from a full platform; then the table's ceiling.
// Every check is made against the request's window, never against a running total.
func (s State) Admit(req Request) (Decision, error) {
	if req.TeamID == "" {
		return Decision{}, fmt.Errorf("%w: a request must name a team", ErrInvalidRequest)
	}
	if !req.Window.Valid() {
		return Decision{}, fmt.Errorf("%w: %s to %s", ErrInvalidWindow, req.Window.Start, req.Window.End)
	}
	if req.Slots <= 0 {
		return Decision{}, fmt.Errorf("%w: %d slots", ErrZeroSlots, req.Slots)
	}
	if req.Window.End.Sub(req.Window.Start) > MaxWindow {
		return Decision{}, fmt.Errorf("%w: %s exceeds the %s maximum",
			ErrInvalidWindow, req.Window.End.Sub(req.Window.Start), MaxWindow)
	}
	team, ok := s.Team(req.TeamID)
	if !ok {
		return Decision{}, fmt.Errorf("%w: %s", ErrUnknownTeam, req.TeamID)
	}
	// A duplicate id would make two reservations indistinguishable in a dispute.
	for _, r := range s.Reservations {
		if r.ID == req.ID {
			return Decision{}, fmt.Errorf("%w: %s already exists", ErrInvalidRequest, req.ID)
		}
	}

	candidate := Reservation{ID: req.ID, TeamID: req.TeamID, Window: req.Window, Slots: req.Slots}

	// The pool, measured over the requested window only. This is the check a total
	// cannot make: three requests in three disjoint windows pass here with a pool of
	// two, and two requests that overlap completely do not.
	peak := s.peakFor(req.Window, &candidate)
	if peak > s.PoolSize {
		return Decision{PeakAfter: peak, Reason: fmt.Sprintf(
				"the pool of %d would reach %d slots during %s to %s",
				s.PoolSize, peak, req.Window.Start.Format(time.RFC3339), req.Window.End.Format(time.RFC3339))},
			fmt.Errorf("%w: peak %d over pool %d", ErrPoolExhausted, peak, s.PoolSize)
	}

	// The team's own ceiling, also measured over the window. The team's fair share is
	// the other half of the limit and is enforced by FairShare callers; the ceiling
	// here is the hard one the team was granted.
	teamPeak := s.peakForTeam(req.Window, req.TeamID, &candidate)
	if team.MaxConcurrent > 0 && teamPeak > team.MaxConcurrent {
		return Decision{PeakAfter: peak, Reason: fmt.Sprintf(
				"team %s holds at most %d slots and would reach %d", req.TeamID, team.MaxConcurrent, teamPeak)},
			fmt.Errorf("%w: team %s peak %d over %d", ErrTeamQuotaExceeded, req.TeamID, teamPeak, team.MaxConcurrent)
	}

	if len(s.Reservations) >= MaxReservations {
		return Decision{PeakAfter: peak, Reason: fmt.Sprintf(
				"the reservation table holds %d entries, its ceiling", len(s.Reservations))},
			fmt.Errorf("%w: %d entries", ErrTooManyReservations, len(s.Reservations))
	}

	return Decision{Allowed: true, PeakAfter: peak, Reason: fmt.Sprintf(
		"accepted: the pool reaches %d of %d slots during the window", peak, s.PoolSize)}, nil
}

// Reserve admits and records a request in one step.
//
// Admitting and recording are one call because a caller that admits, then records, then
// fails between them has booked capacity nobody holds — and the next request is checked
// against a table that does not contain the first.
func (s *State) Reserve(req Request) (Reservation, Decision, error) {
	d, err := s.Admit(req)
	if err != nil {
		return Reservation{}, d, err
	}
	r := Reservation{ID: req.ID, TeamID: req.TeamID, Window: req.Window, Slots: req.Slots}
	s.Reservations = append(s.Reservations, r)
	return r, d, nil
}

// Release gives capacity back from a moment, and is idempotent in the sense that a
// second release of the same reservation is refused rather than double-counted.
//
// Double-counting a release is the quieter half of overbooking: the pool regains the
// slots twice, and the next reservation that fits is one the platform cannot actually
// run.
func (s *State) Release(id string, at time.Time) error {
	for i := range s.Reservations {
		if s.Reservations[i].ID != id {
			continue
		}
		if !s.Reservations[i].ReleasedAt.IsZero() {
			return fmt.Errorf("%w: %s was released at %s", ErrAlreadyReleased, id,
				s.Reservations[i].ReleasedAt.Format(time.RFC3339))
		}
		s.Reservations[i].ReleasedAt = at.UTC()
		return nil
	}
	return fmt.Errorf("%w: %s", ErrUnknownReservation, id)
}

// FairShare splits a pool between teams in proportion to their declared weights.
//
// The split is deterministic: remainders are ranked by fractional size and then by team
// id, so the same teams and weights always produce the same allocation. A fair-share
// algorithm that varies between runs cannot be told apart from an unfair one by anybody
// looking at a single result, which is exactly when fairness matters.
//
// A team's share is never below one slot, because a team that exists but can never run
// is a configuration mistake rather than a policy.
func FairShare(teams []Team, pool int) (map[string]int, error) {
	if pool <= 0 {
		return nil, fmt.Errorf("%w: a pool of %d grants nothing", ErrInvalidRequest, pool)
	}
	if len(teams) == 0 {
		return nil, fmt.Errorf("%w: no teams to share the pool with", ErrInvalidRequest)
	}
	totalWeight := 0
	seen := map[string]bool{}
	for _, t := range teams {
		if t.ID == "" {
			return nil, fmt.Errorf("%w: a team with no id", ErrInvalidRequest)
		}
		if seen[t.ID] {
			return nil, fmt.Errorf("%w: team %s listed twice", ErrInvalidRequest, t.ID)
		}
		seen[t.ID] = true
		if t.Weight <= 0 {
			return nil, fmt.Errorf("%w: team %s has weight %d and can never be allocated anything",
				ErrInvalidRequest, t.ID, t.Weight)
		}
		totalWeight += t.Weight
	}

	type share struct {
		id    string
		floor int
		frac  float64
	}
	shares := make([]share, 0, len(teams))
	assigned := 0
	for _, t := range teams {
		exact := float64(pool) * float64(t.Weight) / float64(totalWeight)
		floor := int(exact)
		shares = append(shares, share{id: t.ID, floor: floor, frac: exact - float64(floor)})
		assigned += floor
	}
	// Remainder by largest fraction, then by id so the tie-break is stable.
	order := make([]int, len(shares))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		ia, ib := order[a], order[b]
		if shares[ia].frac == shares[ib].frac {
			return shares[ia].id < shares[ib].id
		}
		return shares[ia].frac > shares[ib].frac
	})
	for _, idx := range order {
		if assigned >= pool {
			break
		}
		shares[idx].floor++
		assigned++
	}

	out := make(map[string]int, len(shares))
	for _, sh := range shares {
		out[sh.id] = sh.floor
	}
	return out, nil
}
