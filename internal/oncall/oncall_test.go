package oncall

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// now is the moment every test in this file is written around.
var now = time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC)

// validShift is a shift that satisfies every rule, used as the base that each
// test breaks in one place.
func validShift(primary string, start, end time.Time) Shift {
	return Shift{
		Primary:                primary,
		Secondary:              primary + "-backup",
		StartsAt:               start,
		EndsAt:                 end,
		HandoverAcknowledgedBy: primary,
	}
}

// validShift is the first half of a covered window.
func firstShift() Shift {
	return validShift("ada", now, now.Add(6*time.Hour))
}

// secondShift is the second half of a covered window.
func secondShift() Shift {
	return validShift("linus", now.Add(6*time.Hour), now.Add(12*time.Hour))
}

// window is the period the roster tests ask about.
func window() (time.Time, time.Time) {
	return now, now.Add(12 * time.Hour)
}

// validOwnership is an ownership that covers every required duty.
func validOwnership() Ownership {
	ownership, err := AssignOwnership([]Assignment{
		{Duty: DutyLifecycleAndLeaks, Team: "platform", Owner: "ada"},
		{Duty: DutyCloudQuota, Team: "platform", Owner: "grace"},
		{Duty: DutyIdentityBoundaries, Team: "security", Owner: "linus"},
		{Duty: DutyExperimentAndAbort, Team: "reliability", Owner: "alan"},
		{Duty: DutyCost, Team: "finance", Owner: "katherine"},
	})
	if err != nil {
		panic(err)
	}
	return ownership
}

// validPlan is a plan that satisfies every rule for one kind.
func validPlan(kind KeyKind) RotationPlan {
	return RotationPlan{
		Kind:          kind,
		KeyID:         string(kind) + "-1",
		CurrentSecret: "old-secret",
		NewSecret:     "new-secret",
		CurrentScope:  []string{"read", "write"},
		NewScope:      []string{"read"},
		Reason:        "scheduled rotation",
		Actor:         "on-call",
		ScheduledAt:   now,
	}
}

// plansForEveryKind is a set of plans that covers every required kind.
func plansForEveryKind() []RotationPlan {
	plans := make([]RotationPlan, 0, len(RequiredKeyKinds()))
	for _, kind := range RequiredKeyKinds() {
		plans = append(plans, validPlan(kind))
	}
	return plans
}

// ---------------------------------------------------------------------------
// On-call roster
// ---------------------------------------------------------------------------

// A window in which every moment has a named primary is a roster that can be
// published.
func TestBuildRosterAcceptsAFullyCoveredWindow(t *testing.T) {
	from, to := window()
	roster, err := BuildRoster([]Shift{firstShift(), secondShift()}, from, to)
	if err != nil {
		t.Fatalf("BuildRoster: %v", err)
	}
	if len(roster.Shifts) != 2 {
		t.Fatalf("shifts = %d, want 2", len(roster.Shifts))
	}
	if roster.Shifts[0].Primary != "ada" || roster.Shifts[1].Primary != "linus" {
		t.Errorf("primaries = %q, %q, want ada, linus", roster.Shifts[0].Primary, roster.Shifts[1].Primary)
	}
}

// A gap is the failure this package exists to prevent, so it is refused and
// the refusal names the moment the gap opens and the moment it closes.
func TestBuildRosterRefusesAGapAndNamesIt(t *testing.T) {
	from, to := window()
	_, err := BuildRoster([]Shift{firstShift()}, from, to)
	if !errors.Is(err, ErrNoOnCallCoverage) {
		t.Fatalf("BuildRoster error = %v, want ErrNoOnCallCoverage", err)
	}
	message := err.Error()
	if !strings.Contains(message, "2026-05-04T15:00:00Z") {
		t.Errorf("refusal = %q, want the start of the gap named", message)
	}
	if !strings.Contains(message, "2026-05-04T21:00:00Z") {
		t.Errorf("refusal = %q, want the end of the gap named", message)
	}
}

// A gap in the middle of the window is refused in the same way, and the gap it
// names is the one in the middle rather than the end of the window.
func TestBuildRosterRefusesAGapInTheMiddleOfTheWindow(t *testing.T) {
	from, to := window()
	late := validShift("linus", now.Add(9*time.Hour), now.Add(12*time.Hour))
	_, err := BuildRoster([]Shift{firstShift(), late}, from, to)
	if !errors.Is(err, ErrNoOnCallCoverage) {
		t.Fatalf("BuildRoster error = %v, want ErrNoOnCallCoverage", err)
	}
	if !strings.Contains(err.Error(), "2026-05-04T15:00:00Z") {
		t.Errorf("refusal = %q, want the start of the gap named", err.Error())
	}
	if !strings.Contains(err.Error(), "2026-05-04T18:00:00Z") {
		t.Errorf("refusal = %q, want the end of the gap named", err.Error())
	}
}

// Two primaries at the same moment is ambiguous ownership, not redundancy.
func TestBuildRosterRefusesOverlappingShifts(t *testing.T) {
	from, to := window()
	overlapping := validShift("linus", now.Add(5*time.Hour), now.Add(12*time.Hour))
	_, err := BuildRoster([]Shift{firstShift(), overlapping}, from, to)
	if !errors.Is(err, ErrOverlappingShifts) {
		t.Fatalf("BuildRoster error = %v, want ErrOverlappingShifts", err)
	}
	if !strings.Contains(err.Error(), "linus") || !strings.Contains(err.Error(), "ada") {
		t.Errorf("refusal = %q, want both primaries named", err.Error())
	}
}

// A handover nobody accepted is not a handover.
func TestBuildRosterRefusesAShiftWithNoAcknowledgement(t *testing.T) {
	from, to := window()
	unacknowledged := firstShift()
	unacknowledged.HandoverAcknowledgedBy = "  "
	_, err := BuildRoster([]Shift{unacknowledged, secondShift()}, from, to)
	if !errors.Is(err, ErrHandoverNotAcknowledged) {
		t.Fatalf("BuildRoster error = %v, want ErrHandoverNotAcknowledged", err)
	}
}

// An acknowledgement from somebody other than the incoming primary records
// that the pager was picked up without recording who picked it up.
func TestBuildRosterRefusesAnAcknowledgementByTheWrongPerson(t *testing.T) {
	from, to := window()
	wrong := firstShift()
	wrong.HandoverAcknowledgedBy = "grace"
	_, err := BuildRoster([]Shift{wrong, secondShift()}, from, to)
	if !errors.Is(err, ErrHandoverAcknowledgedByWrong) {
		t.Fatalf("BuildRoster error = %v, want ErrHandoverAcknowledgedByWrong", err)
	}
}

// A shift with nobody on it is a shift where every page goes unanswered.
func TestBuildRosterRefusesAShiftWithNoPrimary(t *testing.T) {
	from, to := window()
	nameless := firstShift()
	nameless.Primary = "   "
	_, err := BuildRoster([]Shift{nameless, secondShift()}, from, to)
	if !errors.Is(err, ErrNoPrimary) {
		t.Fatalf("BuildRoster error = %v, want ErrNoPrimary", err)
	}
}

// A shift with no secondary is a shift where the primary cannot go anywhere.
func TestBuildRosterRefusesAShiftWithNoSecondary(t *testing.T) {
	from, to := window()
	alone := firstShift()
	alone.Secondary = ""
	_, err := BuildRoster([]Shift{alone, secondShift()}, from, to)
	if !errors.Is(err, ErrNoSecondary) {
		t.Fatalf("BuildRoster error = %v, want ErrNoSecondary", err)
	}
}

// A shift that ends before it starts describes a window that never opened.
func TestBuildRosterRefusesAShiftThatEndsBeforeItStarts(t *testing.T) {
	from, to := window()
	backwards := firstShift()
	backwards.EndsAt = backwards.StartsAt.Add(-time.Hour)
	_, err := BuildRoster([]Shift{backwards, secondShift()}, from, to)
	if !errors.Is(err, ErrBadShiftWindow) {
		t.Fatalf("BuildRoster error = %v, want ErrBadShiftWindow", err)
	}
}

// A shift that never ends is not a shift.
func TestBuildRosterRefusesAShiftThatNeverEnds(t *testing.T) {
	from, to := window()
	endless := firstShift()
	endless.EndsAt = time.Time{}
	_, err := BuildRoster([]Shift{endless, secondShift()}, from, to)
	if !errors.Is(err, ErrUnboundedShift) {
		t.Fatalf("BuildRoster error = %v, want ErrUnboundedShift", err)
	}
}

// A window that never opened cannot be covered.
func TestBuildRosterRefusesAWindowThatDoesNotEndAfterItStarts(t *testing.T) {
	from, _ := window()
	_, err := BuildRoster([]Shift{firstShift()}, from, from)
	if !errors.Is(err, ErrBadShiftWindow) {
		t.Fatalf("BuildRoster error = %v, want ErrBadShiftWindow", err)
	}
}

// The roster is ordered by start time whatever order the shifts arrived in.
func TestBuildRosterSortsShiftsByStartTime(t *testing.T) {
	from, to := window()
	roster, err := BuildRoster([]Shift{secondShift(), firstShift()}, from, to)
	if err != nil {
		t.Fatalf("BuildRoster: %v", err)
	}
	if roster.Shifts[0].Primary != "ada" || roster.Shifts[1].Primary != "linus" {
		t.Errorf("primaries = %q, %q, want ada, linus", roster.Shifts[0].Primary, roster.Shifts[1].Primary)
	}
}

// The caller's slice is not the roster's business.
func TestBuildRosterDoesNotModifyTheCallersSlice(t *testing.T) {
	from, to := window()
	shifts := []Shift{secondShift(), firstShift()}
	original := append([]Shift(nil), shifts...)
	if _, err := BuildRoster(shifts, from, to); err != nil {
		t.Fatalf("BuildRoster: %v", err)
	}
	if !reflect.DeepEqual(shifts, original) {
		t.Errorf("the caller's slice was changed: %+v, want %+v", shifts, original)
	}
}

// The same shifts always produce the same roster.
func TestBuildRosterIsDeterministic(t *testing.T) {
	from, to := window()
	first, err := BuildRoster([]Shift{firstShift(), secondShift()}, from, to)
	if err != nil {
		t.Fatalf("BuildRoster: %v", err)
	}
	second, err := BuildRoster([]Shift{secondShift(), firstShift()}, from, to)
	if err != nil {
		t.Fatalf("BuildRoster: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Errorf("BuildRoster is not deterministic: %+v and %+v", first, second)
	}
}

// A shift that starts before the window still covers the beginning of it.
func TestBuildRosterAcceptsAShiftThatStartsBeforeTheWindow(t *testing.T) {
	from, to := window()
	early := validShift("ada", now.Add(-time.Hour), now.Add(6*time.Hour))
	roster, err := BuildRoster([]Shift{early, secondShift()}, from, to)
	if err != nil {
		t.Fatalf("BuildRoster: %v", err)
	}
	shift, ok := roster.PrimaryAt(from)
	if !ok {
		t.Fatal("no primary at the start of the window")
	}
	if shift.Primary != "ada" {
		t.Errorf("primary = %q, want ada", shift.Primary)
	}
}

// The moment a shift ends belongs to whoever took over.
func TestPrimaryAtNamesThePrimaryOnCall(t *testing.T) {
	from, to := window()
	roster, err := BuildRoster([]Shift{firstShift(), secondShift()}, from, to)
	if err != nil {
		t.Fatalf("BuildRoster: %v", err)
	}
	cases := map[string]struct {
		at   time.Time
		want string
	}{
		"at the start of the first shift":  {at: now, want: "ada"},
		"in the middle of the first shift": {at: now.Add(3 * time.Hour), want: "ada"},
		"at the handover":                  {at: now.Add(6 * time.Hour), want: "linus"},
		"at the end of the window":         {at: to.Add(-time.Nanosecond), want: "linus"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			shift, ok := roster.PrimaryAt(tc.at)
			if !ok {
				t.Fatalf("PrimaryAt(%s) reports no primary", tc.at)
			}
			if shift.Primary != tc.want {
				t.Errorf("primary = %q, want %q", shift.Primary, tc.want)
			}
		})
	}
}

// A moment that no shift covers has no primary, and that is reported as an
// absence rather than as a guess.
func TestPrimaryAtReportsNobodyOutsideAShift(t *testing.T) {
	from, to := window()
	roster, err := BuildRoster([]Shift{firstShift(), secondShift()}, from, to)
	if err != nil {
		t.Fatalf("BuildRoster: %v", err)
	}
	if _, ok := roster.PrimaryAt(to); ok {
		t.Error("a moment outside every shift reports a primary")
	}
	if _, ok := roster.PrimaryAt(now.Add(-time.Hour)); ok {
		t.Error("a moment before the roster reports a primary")
	}
}

// ---------------------------------------------------------------------------
// Ownership by domain
// ---------------------------------------------------------------------------

// Every duty in the set fixed by SRE.md is held by a named team and a named
// owner.
func TestAssignOwnershipAcceptsTheFullSetOfDuties(t *testing.T) {
	ownership := validOwnership()
	if len(ownership.Assignments) != len(RequiredDuties()) {
		t.Fatalf("assignments = %d, want %d", len(ownership.Assignments), len(RequiredDuties()))
	}
	if err := CheckCoverage(ownership); err != nil {
		t.Errorf("CheckCoverage error = %v, want none", err)
	}
}

// The assignments are ordered by duty, whatever order they arrived in.
func TestAssignOwnershipIsDeterministic(t *testing.T) {
	assignments := []Assignment{
		{Duty: DutyCost, Team: "finance", Owner: "katherine"},
		{Duty: DutyCloudQuota, Team: "platform", Owner: "grace"},
		{Duty: DutyLifecycleAndLeaks, Team: "platform", Owner: "ada"},
	}
	ownership, err := AssignOwnership(assignments)
	if err != nil {
		t.Fatalf("AssignOwnership: %v", err)
	}
	first := ownership.Assignments[0].Duty
	if first != DutyLifecycleAndLeaks {
		t.Errorf("first duty = %q, want %q", first, DutyLifecycleAndLeaks)
	}
	reversed, err := AssignOwnership([]Assignment{assignments[2], assignments[1], assignments[0]})
	if err != nil {
		t.Fatalf("AssignOwnership: %v", err)
	}
	if !reflect.DeepEqual(ownership.Assignments, reversed.Assignments) {
		t.Errorf("AssignOwnership is not deterministic: %+v and %+v", ownership.Assignments, reversed.Assignments)
	}
}

// A duty that is "the team's" is owned by nobody.
func TestAssignOwnershipRefusesADutyWithNoOwner(t *testing.T) {
	_, err := AssignOwnership([]Assignment{{Duty: DutyCost, Team: "finance"}})
	if !errors.Is(err, ErrNoDutyOwner) {
		t.Fatalf("AssignOwnership error = %v, want ErrNoDutyOwner", err)
	}
}

// A duty without a team has nowhere to escalate to.
func TestAssignOwnershipRefusesADutyWithNoTeam(t *testing.T) {
	_, err := AssignOwnership([]Assignment{{Duty: DutyCost, Owner: "katherine"}})
	if !errors.Is(err, ErrNoDutyTeam) {
		t.Fatalf("AssignOwnership error = %v, want ErrNoDutyTeam", err)
	}
}

// Two holders of one duty is the same ambiguity as two primaries in one shift.
func TestAssignOwnershipRefusesADuplicateDuty(t *testing.T) {
	_, err := AssignOwnership([]Assignment{
		{Duty: DutyCost, Team: "finance", Owner: "katherine"},
		{Duty: DutyCost, Team: "platform", Owner: "ada"},
	})
	if !errors.Is(err, ErrDuplicateDuty) {
		t.Fatalf("AssignOwnership error = %v, want ErrDuplicateDuty", err)
	}
}

// The ownership set is fixed by SRE.md, so a duty outside it belongs to
// somebody else's roster.
func TestAssignOwnershipRefusesAnUnknownDuty(t *testing.T) {
	_, err := AssignOwnership([]Assignment{{Duty: Duty("marketing"), Team: "platform", Owner: "ada"}})
	if !errors.Is(err, ErrUnknownDuty) {
		t.Fatalf("AssignOwnership error = %v, want ErrUnknownDuty", err)
	}
}

// The owner of a duty is the person who holds it.
func TestOwnerOfNamesTheHolder(t *testing.T) {
	ownership := validOwnership()
	assignment, ok := ownership.OwnerOf(DutyIdentityBoundaries)
	if !ok {
		t.Fatal("OwnerOf reports no holder for a duty that is held")
	}
	if assignment.Owner != "linus" || assignment.Team != "security" {
		t.Errorf("assignment = %+v, want security and linus", assignment)
	}
}

// A duty nobody holds is an absence rather than an empty assignment.
func TestOwnerOfReportsNoHolderForAnUnknownDuty(t *testing.T) {
	ownership := validOwnership()
	if _, ok := ownership.OwnerOf(Duty("marketing")); ok {
		t.Error("OwnerOf reports a holder for a duty that is not ours")
	}
}

// The ownership set of SRE.md is fixed, so a missing duty is a gap in the
// roster rather than a preference, and the gap is named.
func TestCheckCoverageRefusesAnOwnershipMissingARequiredDuty(t *testing.T) {
	ownership, err := AssignOwnership([]Assignment{
		{Duty: DutyLifecycleAndLeaks, Team: "platform", Owner: "ada"},
		{Duty: DutyCloudQuota, Team: "platform", Owner: "grace"},
		{Duty: DutyIdentityBoundaries, Team: "security", Owner: "linus"},
		{Duty: DutyExperimentAndAbort, Team: "reliability", Owner: "alan"},
	})
	if err != nil {
		t.Fatalf("AssignOwnership: %v", err)
	}
	err = CheckCoverage(ownership)
	if !errors.Is(err, ErrUncoveredDuty) {
		t.Fatalf("CheckCoverage error = %v, want ErrUncoveredDuty", err)
	}
	if !strings.Contains(err.Error(), string(DutyCost)) {
		t.Errorf("refusal = %q, want the missing duty named", err.Error())
	}
}

// A duty that names a team but no owner is held by nobody, and it would
// otherwise pass the coverage check.
func TestCheckCoverageRefusesADutyHeldByNobody(t *testing.T) {
	ownership, err := AssignOwnership([]Assignment{
		{Duty: DutyLifecycleAndLeaks, Team: "platform", Owner: "ada"},
		{Duty: DutyCloudQuota, Team: "platform", Owner: "grace"},
		{Duty: DutyIdentityBoundaries, Team: "security", Owner: "linus"},
		{Duty: DutyExperimentAndAbort, Team: "reliability", Owner: "alan"},
	})
	if err != nil {
		t.Fatalf("AssignOwnership: %v", err)
	}
	ownership.Assignments = append(ownership.Assignments, Assignment{Duty: DutyCost, Team: "finance"})
	if err := CheckCoverage(ownership); !errors.Is(err, ErrNoDutyOwner) {
		t.Fatalf("CheckCoverage error = %v, want ErrNoDutyOwner", err)
	}
}

// A fully covered ownership passes the coverage check.
func TestCheckCoverageAcceptsAFullyCoveredOwnership(t *testing.T) {
	if err := CheckCoverage(validOwnership()); err != nil {
		t.Fatalf("CheckCoverage error = %v, want none", err)
	}
}

// The required duties are the ones SRE.md names, and the list handed to a
// caller is a copy.
func TestRequiredDutiesCoversEveryDutyAndIsACopy(t *testing.T) {
	duties := RequiredDuties()
	if len(duties) != 5 {
		t.Fatalf("duties = %d, want 5", len(duties))
	}
	want := map[Duty]bool{
		DutyLifecycleAndLeaks:  false,
		DutyCloudQuota:         false,
		DutyIdentityBoundaries: false,
		DutyExperimentAndAbort: false,
		DutyCost:               false,
	}
	for _, d := range duties {
		want[d] = true
	}
	for d, seen := range want {
		if !seen {
			t.Errorf("duty %q is not in the required set", d)
		}
	}
	duties[0] = Duty("mutated")
	if RequiredDuties()[0] == Duty("mutated") {
		t.Error("RequiredDuties returned the live list")
	}
}

// A handover moves the duty and keeps the holder it came from.
func TestHandOverMovesADutyAndRecordsThePreviousHolder(t *testing.T) {
	ownership := validOwnership()
	handed, err := HandOver(ownership, DutyCost, "finance-platform", "dorothy", "ada", "the cost owner is on leave", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("HandOver: %v", err)
	}
	assignment, ok := handed.OwnerOf(DutyCost)
	if !ok {
		t.Fatal("the duty is no longer held")
	}
	if assignment.Team != "finance-platform" || assignment.Owner != "dorothy" {
		t.Errorf("assignment = %+v, want finance-platform and dorothy", assignment)
	}
	if len(assignment.History) != 1 {
		t.Fatalf("history = %d, want 1", len(assignment.History))
	}
	entry := assignment.History[0]
	if entry.FromTeam != "finance" || entry.FromOwner != "katherine" {
		t.Errorf("history entry = %+v, want the previous holder recorded", entry)
	}
	if entry.ToOwner != "dorothy" || entry.Actor != "ada" {
		t.Errorf("history entry = %+v, want the new holder and the actor recorded", entry)
	}
	if !strings.Contains(entry.Reason, "on leave") {
		t.Errorf("history entry = %+v, want the reason recorded", entry)
	}
}

// A handover without an actor is a change nobody can be asked about.
func TestHandOverRefusesWithoutAnActor(t *testing.T) {
	_, err := HandOver(validOwnership(), DutyCost, "finance", "dorothy", "  ", "the cost owner is on leave", now.Add(time.Hour))
	if !errors.Is(err, ErrNoActor) {
		t.Fatalf("HandOver error = %v, want ErrNoActor", err)
	}
}

// A handover without a reason is a change that cannot be defended.
func TestHandOverRefusesWithoutAReason(t *testing.T) {
	_, err := HandOver(validOwnership(), DutyCost, "finance", "dorothy", "ada", "   ", now.Add(time.Hour))
	if !errors.Is(err, ErrNoReason) {
		t.Fatalf("HandOver error = %v, want ErrNoReason", err)
	}
}

// There is nothing to hand over that is not one of our duties.
func TestHandOverRefusesAnUnknownDuty(t *testing.T) {
	_, err := HandOver(validOwnership(), Duty("marketing"), "finance", "dorothy", "ada", "a change of plan", now.Add(time.Hour))
	if !errors.Is(err, ErrUnknownDuty) {
		t.Fatalf("HandOver error = %v, want ErrUnknownDuty", err)
	}
}

// Handing a duty to nobody leaves the gap this package exists to close.
func TestHandOverRefusesAnEmptyIncomingTeamOrOwner(t *testing.T) {
	if _, err := HandOver(validOwnership(), DutyCost, "  ", "dorothy", "ada", "a change of plan", now.Add(time.Hour)); !errors.Is(err, ErrNoDutyTeam) {
		t.Fatalf("HandOver error = %v, want ErrNoDutyTeam", err)
	}
	if _, err := HandOver(validOwnership(), DutyCost, "finance", " ", "ada", "a change of plan", now.Add(time.Hour)); !errors.Is(err, ErrNoDutyOwner) {
		t.Fatalf("HandOver error = %v, want ErrNoDutyOwner", err)
	}
}

// There is no previous holder to record when the duty has none.
func TestHandOverRefusesADutyNobodyHolds(t *testing.T) {
	ownership, err := AssignOwnership([]Assignment{{Duty: DutyCost, Team: "finance", Owner: "katherine"}})
	if err != nil {
		t.Fatalf("AssignOwnership: %v", err)
	}
	if _, err := HandOver(ownership, DutyLifecycleAndLeaks, "platform", "ada", "ada", "a change of plan", now.Add(time.Hour)); !errors.Is(err, ErrUncoveredDuty) {
		t.Fatalf("HandOver error = %v, want ErrUncoveredDuty", err)
	}
}

// The ownership handed in is not the ownership that is handed back.
func TestHandOverDoesNotModifyTheOriginalOwnership(t *testing.T) {
	ownership := validOwnership()
	before, ok := ownership.OwnerOf(DutyCost)
	if !ok {
		t.Fatal("the duty is not held")
	}
	if _, err := HandOver(ownership, DutyCost, "finance-platform", "dorothy", "ada", "the cost owner is on leave", now.Add(time.Hour)); err != nil {
		t.Fatalf("HandOver: %v", err)
	}
	after, ok := ownership.OwnerOf(DutyCost)
	if !ok {
		t.Fatal("the duty is no longer held")
	}
	if !reflect.DeepEqual(before, after) {
		t.Errorf("the original ownership was changed: %+v, want %+v", after, before)
	}
}

// The second handover keeps the first one's record.
func TestHandOverKeepsTheEarlierHistory(t *testing.T) {
	ownership := validOwnership()
	once, err := HandOver(ownership, DutyCost, "finance-platform", "dorothy", "ada", "the cost owner is on leave", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("HandOver: %v", err)
	}
	twice, err := HandOver(once, DutyCost, "finance", "katherine", "ada", "the cost owner is back", now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("HandOver: %v", err)
	}
	assignment, ok := twice.OwnerOf(DutyCost)
	if !ok {
		t.Fatal("the duty is no longer held")
	}
	if len(assignment.History) != 2 {
		t.Fatalf("history = %d, want 2", len(assignment.History))
	}
	if assignment.History[0].ToOwner != "dorothy" || assignment.History[1].ToOwner != "katherine" {
		t.Errorf("history = %+v, want both handovers recorded in order", assignment.History)
	}
}

// ---------------------------------------------------------------------------
// Key rotation
// ---------------------------------------------------------------------------

// A plan that covers every kind is a plan that can be worked.
func TestPlanRotationAcceptsAPlanCoveringEveryKind(t *testing.T) {
	plans, err := PlanRotation(plansForEveryKind())
	if err != nil {
		t.Fatalf("PlanRotation: %v", err)
	}
	if len(plans) != len(RequiredKeyKinds()) {
		t.Fatalf("plans = %d, want %d", len(plans), len(RequiredKeyKinds()))
	}
}

// A rotation that quietly leaves one kind behind is a rotation that has
// rotated the part somebody remembered, so the missing kinds are named.
func TestPlanRotationRefusesAPlanMissingARequiredKindAndNamesIt(t *testing.T) {
	plans := plansForEveryKind()
	plans = plans[:len(plans)-1]
	_, err := PlanRotation(plans)
	if !errors.Is(err, ErrKindNotRotated) {
		t.Fatalf("PlanRotation error = %v, want ErrKindNotRotated", err)
	}
	if !strings.Contains(err.Error(), string(KeyPreviewSecrets)) {
		t.Errorf("refusal = %q, want the missing kind named", err.Error())
	}
}

// An empty plan is the absence of one.
func TestPlanRotationRefusesAnEmptyPlan(t *testing.T) {
	if _, err := PlanRotation(nil); !errors.Is(err, ErrEmptyRotationPlan) {
		t.Fatalf("PlanRotation error = %v, want ErrEmptyRotationPlan", err)
	}
}

// A kind outside the rotation vocabulary is a credential no rule here reaches.
func TestPlanRotationRefusesAnUnknownKind(t *testing.T) {
	plans := plansForEveryKind()
	plans[0].Kind = KeyKind("magic-link")
	if _, err := PlanRotation(plans); !errors.Is(err, ErrUnknownKeyKind) {
		t.Fatalf("PlanRotation error = %v, want ErrUnknownKeyKind", err)
	}
}

// A rotation nobody performed cannot be reviewed afterwards.
func TestPlanRotationRefusesAPlanWithoutAnActor(t *testing.T) {
	plans := plansForEveryKind()
	plans[0].Actor = " "
	if _, err := PlanRotation(plans); !errors.Is(err, ErrNoActor) {
		t.Fatalf("PlanRotation error = %v, want ErrNoActor", err)
	}
}

// A rotation without a reason is a rotation nobody can review afterwards.
func TestPlanRotationRefusesAPlanWithoutAReason(t *testing.T) {
	plans := plansForEveryKind()
	plans[0].Reason = ""
	if _, err := PlanRotation(plans); !errors.Is(err, ErrNoReason) {
		t.Fatalf("PlanRotation error = %v, want ErrNoReason", err)
	}
}

// A rotation of an unnamed key cannot be retired afterwards.
func TestPlanRotationRefusesAPlanWithNoKeyID(t *testing.T) {
	plans := plansForEveryKind()
	plans[0].KeyID = "  "
	if _, err := PlanRotation(plans); !errors.Is(err, ErrNoKeyID) {
		t.Fatalf("PlanRotation error = %v, want ErrNoKeyID", err)
	}
}

// A rotation that does not change the secret is not a rotation.
func TestRotateRefusesASecretThatDoesNotChange(t *testing.T) {
	plan := validPlan(KeyGitHubApp)
	plan.NewSecret = plan.CurrentSecret
	if _, err := Rotate(plan, now); !errors.Is(err, ErrNotRotated) {
		t.Fatalf("Rotate error = %v, want ErrNotRotated", err)
	}
}

// A rotation to an empty secret installs nothing, so it is not a rotation
// either.
func TestRotateRefusesAnEmptyNewSecret(t *testing.T) {
	plan := validPlan(KeyGitHubApp)
	plan.NewSecret = ""
	if _, err := Rotate(plan, now); !errors.Is(err, ErrNotRotated) {
		t.Fatalf("Rotate error = %v, want ErrNotRotated", err)
	}
}

// A rotation that widens the scope is a privilege escalation dressed as
// maintenance.
func TestRotateRefusesAScopeThatWidensPrivilege(t *testing.T) {
	plan := validPlan(KeyPreviewSecrets)
	plan.NewScope = []string{"read", "admin"}
	if _, err := Rotate(plan, now); !errors.Is(err, ErrPrivilegeWidened) {
		t.Fatalf("Rotate error = %v, want ErrPrivilegeWidened", err)
	}
}

// The plan set is checked plan by plan, so a scope that widens is refused
// there too.
func TestPlanRotationRefusesAScopeThatWidensPrivilege(t *testing.T) {
	plans := plansForEveryKind()
	plans[0].NewScope = []string{"read", "admin"}
	if _, err := PlanRotation(plans); !errors.Is(err, ErrPrivilegeWidened) {
		t.Fatalf("PlanRotation error = %v, want ErrPrivilegeWidened", err)
	}
}

// A refresh that stays inside the scope it already had is the whole point of
// a refresh.
func TestRotateAcceptsANarrowedScope(t *testing.T) {
	plan := validPlan(KeyStateKMS)
	plan.NewScope = []string{"read"}
	rotation, err := Rotate(plan, now)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !reflect.DeepEqual(rotation.Plan.NewScope, []string{"read"}) {
		t.Errorf("new scope = %v, want [read]", rotation.Plan.NewScope)
	}
}

// A scope that is not recorded grants nothing, so any new scope widens it.
func TestRotateRefusesAScopeOnTopOfAnEmptyCurrentScope(t *testing.T) {
	plan := validPlan(KeyEvidenceKMS)
	plan.CurrentScope = nil
	plan.NewScope = []string{"read"}
	if _, err := Rotate(plan, now); !errors.Is(err, ErrPrivilegeWidened) {
		t.Fatalf("Rotate error = %v, want ErrPrivilegeWidened", err)
	}
}

// The rotation records the moment it happened and the credential it replaced.
func TestRotateRecordsTheMomentAndThePreviousKeyID(t *testing.T) {
	plan := validPlan(KeyOIDCTrust)
	rotation, err := Rotate(plan, now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !rotation.RotatedAt.Equal(now.Add(5 * time.Minute)) {
		t.Errorf("rotated at = %s, want %s", rotation.RotatedAt, now.Add(5*time.Minute))
	}
	if rotation.PreviousKeyID != plan.KeyID {
		t.Errorf("previous key id = %q, want %q", rotation.PreviousKeyID, plan.KeyID)
	}
	if rotation.Plan.Kind != KeyOIDCTrust {
		t.Errorf("kind = %q, want %q", rotation.Plan.Kind, KeyOIDCTrust)
	}
}

// The plan handed in is not the plan that was applied, so a later edit of the
// caller's plan cannot rewrite the record.
func TestRotateDoesNotModifyThePlan(t *testing.T) {
	plan := validPlan(KeyGitHubApp)
	rotation, err := Rotate(plan, now)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if plan.NewSecret != "new-secret" || plan.KeyID != "github-app-1" {
		t.Errorf("the plan was changed: %+v", plan)
	}
	rotation.Plan.NewScope[0] = "admin"
	if plan.NewScope[0] != "read" {
		t.Error("the rotation and the plan share a scope slice")
	}
}

// A rotation is verified before it is trusted.
func TestVerifyRotationAcceptsAMatchingSecret(t *testing.T) {
	rotation, err := Rotate(validPlan(KeyAllocatorCredentials), now)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := VerifyRotation(rotation, "new-secret"); err != nil {
		t.Fatalf("VerifyRotation error = %v, want none", err)
	}
}

// A rotation nobody verified is a rotation nobody knows worked.
func TestVerifyRotationRefusesAMismatchedSecret(t *testing.T) {
	rotation, err := Rotate(validPlan(KeyAllocatorCredentials), now)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := VerifyRotation(rotation, "some-other-secret"); !errors.Is(err, ErrRotationNotVerified) {
		t.Fatalf("VerifyRotation error = %v, want ErrRotationNotVerified", err)
	}
}

// The kinds a rotation has to cover are the ones SRE.md lists.
func TestRequiredKeyKindsCoversEveryKindAndIsACopy(t *testing.T) {
	kinds := RequiredKeyKinds()
	if len(kinds) != 7 {
		t.Fatalf("kinds = %d, want 7", len(kinds))
	}
	want := map[KeyKind]bool{
		KeyGitHubApp:            false,
		KeyOIDCTrust:            false,
		KeyOIDCSigning:          false,
		KeyStateKMS:             false,
		KeyEvidenceKMS:          false,
		KeyAllocatorCredentials: false,
		KeyPreviewSecrets:       false,
	}
	for _, k := range kinds {
		want[k] = true
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("kind %q is not in the required set", k)
		}
	}
	kinds[0] = KeyKind("mutated")
	if RequiredKeyKinds()[0] == KeyKind("mutated") {
		t.Error("RequiredKeyKinds returned the live list")
	}
}

// ---------------------------------------------------------------------------
// The rotation record
// ---------------------------------------------------------------------------

// A record that has rotated every kind is complete.
func TestRecordCompleteAcceptsARecordCoveringEveryKind(t *testing.T) {
	record := Record{}
	for _, kind := range RequiredKeyKinds() {
		rotation, err := Rotate(validPlan(kind), now)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		record.Rotations = append(record.Rotations, rotation)
	}
	if err := record.Complete(); err != nil {
		t.Fatalf("Complete error = %v, want none", err)
	}
}

// Completeness is checked against what actually happened, so a kind that was
// planned and not rotated is the kind somebody will believe was rotated.
func TestRecordCompleteRefusesARecordMissingAKind(t *testing.T) {
	record := Record{}
	for _, kind := range RequiredKeyKinds() {
		if kind == KeyPreviewSecrets {
			continue
		}
		rotation, err := Rotate(validPlan(kind), now)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		record.Rotations = append(record.Rotations, rotation)
	}
	err := record.Complete()
	if !errors.Is(err, ErrKindNotRotated) {
		t.Fatalf("Complete error = %v, want ErrKindNotRotated", err)
	}
	if !strings.Contains(err.Error(), string(KeyPreviewSecrets)) {
		t.Errorf("refusal = %q, want the missing kind named", err.Error())
	}
}

// The latest rotation of a kind is the one that describes the credential in
// use now.
func TestLastRotationOfReturnsTheMostRecentRotation(t *testing.T) {
	early, err := Rotate(validPlan(KeyOIDCTrust), now)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	latePlan := validPlan(KeyOIDCTrust)
	latePlan.KeyID = "oidc-trust-2"
	late, err := Rotate(latePlan, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	record := Record{Rotations: []Rotation{early, late}}
	latest, ok := record.LastRotationOf(KeyOIDCTrust)
	if !ok {
		t.Fatal("LastRotationOf reports no rotation for a kind that was rotated")
	}
	if latest.PreviousKeyID != "oidc-trust-2" {
		t.Errorf("previous key id = %q, want oidc-trust-2", latest.PreviousKeyID)
	}
}

// A kind that was never rotated has no last rotation.
func TestLastRotationOfReportsNoRotationForAKind(t *testing.T) {
	rotation, err := Rotate(validPlan(KeyStateKMS), now)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	record := Record{Rotations: []Rotation{rotation}}
	if _, ok := record.LastRotationOf(KeyEvidenceKMS); ok {
		t.Error("LastRotationOf reports a rotation for a kind that was never rotated")
	}
}

// The record keeps the duty handovers that happened, each with the history
// that explains how the duty got there.
func TestRecordKeepsTheDutyHandovers(t *testing.T) {
	ownership := validOwnership()
	handed, err := HandOver(ownership, DutyCloudQuota, "platform-infra", "grace", "ada", "the quota owner is on leave", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("HandOver: %v", err)
	}
	assignment, ok := handed.OwnerOf(DutyCloudQuota)
	if !ok {
		t.Fatal("the duty is no longer held")
	}
	record := Record{Handovers: []Assignment{assignment}}
	if len(record.Handovers) != 1 {
		t.Fatalf("handovers = %d, want 1", len(record.Handovers))
	}
	if len(record.Handovers[0].History) != 1 {
		t.Errorf("history = %d, want 1", len(record.Handovers[0].History))
	}
}

// ---------------------------------------------------------------------------
// The sentinels themselves
// ---------------------------------------------------------------------------

// Every refusal is its own error, so a caller can tell the gaps apart.
func TestEverySentinelIsDistinctAndNamed(t *testing.T) {
	sentinels := map[string]error{
		"ErrNoOnCallCoverage":            ErrNoOnCallCoverage,
		"ErrNoPrimary":                   ErrNoPrimary,
		"ErrNoSecondary":                 ErrNoSecondary,
		"ErrBadShiftWindow":              ErrBadShiftWindow,
		"ErrUnboundedShift":              ErrUnboundedShift,
		"ErrOverlappingShifts":           ErrOverlappingShifts,
		"ErrHandoverNotAcknowledged":     ErrHandoverNotAcknowledged,
		"ErrHandoverAcknowledgedByWrong": ErrHandoverAcknowledgedByWrong,
		"ErrNoDutyOwner":                 ErrNoDutyOwner,
		"ErrNoDutyTeam":                  ErrNoDutyTeam,
		"ErrDuplicateDuty":               ErrDuplicateDuty,
		"ErrUnknownDuty":                 ErrUnknownDuty,
		"ErrUncoveredDuty":               ErrUncoveredDuty,
		"ErrNoActor":                     ErrNoActor,
		"ErrNoReason":                    ErrNoReason,
		"ErrKindNotRotated":              ErrKindNotRotated,
		"ErrEmptyRotationPlan":           ErrEmptyRotationPlan,
		"ErrPrivilegeWidened":            ErrPrivilegeWidened,
		"ErrUnknownKeyKind":              ErrUnknownKeyKind,
		"ErrNotRotated":                  ErrNotRotated,
		"ErrNoKeyID":                     ErrNoKeyID,
		"ErrRotationNotVerified":         ErrRotationNotVerified,
	}
	seen := map[string]string{}
	for name, err := range sentinels {
		if err == nil {
			t.Errorf("%s is nil", name)
			continue
		}
		if err.Error() == "" {
			t.Errorf("%s carries no message", name)
		}
		if otherName, clash := seen[err.Error()]; clash {
			t.Errorf("%s and %s carry the same message", name, otherName)
		}
		seen[err.Error()] = name
	}
}

// The refusals carry enough context to be acted on without reading the code.
func TestRefusalsNameWhatWasWrong(t *testing.T) {
	from, to := window()
	_, err := BuildRoster([]Shift{firstShift()}, from, to)
	if err == nil {
		t.Fatal("BuildRoster accepted a roster with a gap")
	}
	if !strings.Contains(err.Error(), ErrNoOnCallCoverage.Error()) {
		t.Errorf("refusal = %q, want it to name the refusal", err.Error())
	}
	plan := validPlan(KeyStateKMS)
	plan.Kind = KeyKind("magic-link")
	_, err = Rotate(plan, now)
	if err == nil {
		t.Fatal("Rotate accepted a plan for an unknown kind")
	}
	if !strings.Contains(err.Error(), "magic-link") {
		t.Errorf("refusal = %q, want the kind named", err.Error())
	}
}

// The whole path works: a roster covers its window, the ownership map covers
// every duty, the plan covers every kind and the record is complete.
func TestTheWholeOnCallPathWorks(t *testing.T) {
	from, to := window()
	roster, err := BuildRoster([]Shift{secondShift(), firstShift()}, from, to)
	if err != nil {
		t.Fatalf("BuildRoster: %v", err)
	}
	shift, ok := roster.PrimaryAt(now.Add(time.Hour))
	if !ok {
		t.Fatal("no primary an hour into the window")
	}
	if shift.Secondary != "ada-backup" {
		t.Errorf("secondary = %q, want ada-backup", shift.Secondary)
	}

	ownership := validOwnership()
	if err := CheckCoverage(ownership); err != nil {
		t.Fatalf("CheckCoverage: %v", err)
	}
	handed, err := HandOver(ownership, DutyExperimentAndAbort, "reliability-oncall", "alan", "ada", "the reliability owner is on leave", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("HandOver: %v", err)
	}
	if err := CheckCoverage(handed); err != nil {
		t.Fatalf("CheckCoverage after the handover: %v", err)
	}

	plans, err := PlanRotation(plansForEveryKind())
	if err != nil {
		t.Fatalf("PlanRotation: %v", err)
	}
	record := Record{}
	for _, plan := range plans {
		rotation, err := Rotate(plan, now)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if err := VerifyRotation(rotation, plan.NewSecret); err != nil {
			t.Fatalf("VerifyRotation: %v", err)
		}
		record.Rotations = append(record.Rotations, rotation)
	}
	if err := record.Complete(); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if fmt.Sprint(len(record.Rotations)) != fmt.Sprint(len(RequiredKeyKinds())) {
		t.Errorf("rotations = %d, want %d", len(record.Rotations), len(RequiredKeyKinds()))
	}
}
