// Package oncall implements the rotation and ownership half of checklist row
// G6.4: the on-call roster, the ownership map that says which team answers for
// what, and the key rotations that keep the platform's credentials moving. The
// communications half of the same row lives in internal/communications.
//
// docs/SRE.md sets the two rules this package exists to make checkable.
//
// The first is about rotations. "Key rotations cover GitHub App, OIDC trust/
// signing, state/evidence KMS, dependency allocator credentials and scoped
// preview secrets. Refresh does not grant runtime new privilege." A rotation
// that quietly leaves one kind behind is a rotation that has rotated the part
// somebody remembered, and a rotation that widens a scope is a privilege
// escalation dressed as maintenance, executed at exactly the moment nobody is
// reading the scope. So a plan has to name every kind, and a refresh has to
// stay inside the scope it already had.
//
// The second is about ownership. "Platform on-call owns lifecycle/state/leaks
// and cloud quota. Security owns untrusted-code/identity boundaries.
// Reliability owns experiment/gate methodology and abort. Cost owner reviews
// fixed/variable spend and profile forecasts." A duty that is "the team's" is
// owned by nobody, and a duty owned by nobody is met whenever somebody
// remembers. So every duty names a team and an owner, and a handover is an
// explicit act with an actor and a reason rather than a silent reassignment.
//
// The theme running through both is that **coverage is the thing that breaks
// incident response**. A window with a gap in it is not a window with an
// inconvenient hole: it is a window in which a page goes to nobody, and "on-call
// changed at some point" is not an answer an operator can act on, which is why
// the refusal for a gap names the moment the gap opens and the moment it
// closes. The same shape shows up everywhere else here. Two primaries at the
// same moment are not a redundancy but an ambiguity, and ambiguity is how nobody
// ends up owning anything. A handover nobody accepted is not a handover. A
// rotation nobody verified is a rotation nobody knows worked.
//
// The rules are refusals rather than warnings because each one describes a
// moment where the absence of a rule becomes the default, and the default is
// always silence: a gap nobody filled, a duty nobody holds, a key nobody
// rotated, a scope nobody checked.
package oncall

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package's on-call rules.
var (
	// ErrNoOnCallCoverage means a moment in the requested window has no named
	// primary. This is the central refusal of the package: a page that goes
	// to nobody during a gap is an incident nobody is working on, and the
	// refusal names the start and the end of the gap because "on-call changed
	// at some point" is not something an operator can act on.
	ErrNoOnCallCoverage = errors.New("no on-call coverage")
	// ErrNoPrimary means a shift names no primary. A shift with nobody on it
	// is a shift where every page goes unanswered, and it is not a smaller
	// version of a covered shift: it is no shift at all.
	ErrNoPrimary = errors.New("shift must name a primary")
	// ErrNoSecondary means a shift names no secondary. A shift with no
	// secondary is a shift where the primary cannot go anywhere, so the
	// first thing an incident needs is already missing.
	ErrNoSecondary = errors.New("shift must name a secondary")
	// ErrBadShiftWindow means a shift does not end after it starts, or that
	// the requested roster window does not end after it starts. A window that
	// never opened describes a period in which nobody was on call, which is
	// exactly the period the roster exists to cover.
	ErrBadShiftWindow = errors.New("shift window must end after it starts")
	// ErrUnboundedShift means a shift never ends. A shift that never ends is
	// not a shift: it is a way of refusing to say when somebody stops being
	// on call, and it is how a roster grows a hole nobody can point at.
	ErrUnboundedShift = errors.New("shift must be bounded")
	// ErrOverlappingShifts means two shifts cover the same moment. Two
	// primaries at the same moment is ambiguous ownership, and ambiguous
	// ownership is how nobody ends up owning it.
	ErrOverlappingShifts = errors.New("shifts may not overlap")
	// ErrHandoverNotAcknowledged means a shift was never accepted by anybody.
	// A handover nobody accepted is not a handover, and the engineer who
	// believes they are on call has been told nothing.
	ErrHandoverNotAcknowledged = errors.New("shift handover was not acknowledged")
	// ErrHandoverAcknowledgedByWrong means a shift was acknowledged by
	// somebody other than its incoming primary. An acknowledgement from the
	// wrong person records that the pager was picked up without recording
	// who picked it up, which is the failure the acknowledgement exists to
	// prevent.
	ErrHandoverAcknowledgedByWrong = errors.New("shift handover was acknowledged by the wrong person")
	// ErrNoDutyOwner means a duty names no owner. A duty that is "the
	// team's" is owned by nobody, and a duty owned by nobody is met whenever
	// somebody remembers.
	ErrNoDutyOwner = errors.New("duty must name an owner")
	// ErrNoDutyTeam means a duty names no team. A duty without a team has
	// nowhere to escalate to, so the escalation path ends at the person who
	// forgot to name it.
	ErrNoDutyTeam = errors.New("duty must name a team")
	// ErrDuplicateDuty means a duty is assigned twice. Two holders of one
	// duty is the same ambiguity as two primaries in one shift: everybody
	// assumes somebody else has it.
	ErrDuplicateDuty = errors.New("duty is already assigned")
	// ErrUnknownDuty means a duty is not one this platform defines. The
	// ownership set is fixed by SRE.md, so a duty outside it belongs to
	// somebody else's roster rather than to this one.
	ErrUnknownDuty = errors.New("unknown duty")
	// ErrUncoveredDuty means a duty has no holder at all. The platform's
	// ownership set is fixed by SRE.md, so a missing duty is a gap in the
	// roster rather than a preference, and it is refused rather than
	// reported as a note.
	ErrUncoveredDuty = errors.New("duty has no owner")
	// ErrNoActor means an act names nobody who performed it. A handover or a
	// rotation by nobody is a change that cannot be asked about later.
	ErrNoActor = errors.New("change must carry an actor")
	// ErrNoReason means an act names no reason. A rotation without a reason
	// is a rotation nobody can review afterwards, and a handover without one
	// is a change that cannot be defended.
	ErrNoReason = errors.New("change must carry a reason")
	// ErrKindNotRotated means a key kind was left behind. SRE.md lists what
	// a rotation covers, and a rotation that quietly leaves one kind behind
	// is a rotation that has rotated the part somebody remembered. The
	// refusal names the kinds that were missed, because "not all of them" is
	// not an answer an operator can act on either.
	ErrKindNotRotated = errors.New("key kind was not rotated")
	// ErrEmptyRotationPlan means no plans were given at all. An empty plan
	// is not a plan for a rotation nobody needed; it is the absence of one.
	ErrEmptyRotationPlan = errors.New("rotation plan is empty")
	// ErrPrivilegeWidened means a refresh grants more than the current
	// secret had. A rotation that widens the scope is a privilege escalation
	// dressed as maintenance, and a rotation is exactly when nobody is
	// looking at the scope.
	ErrPrivilegeWidened = errors.New("rotation widens privilege")
	// ErrUnknownKeyKind means a plan names a kind this package does not
	// define. A kind outside the rotation vocabulary has no required
	// treatment, so it would never be rotated by a rule that only knows the
	// listed kinds.
	ErrUnknownKeyKind = errors.New("unknown key kind")
	// ErrNotRotated means the new secret does not differ from the current
	// one. A rotation that does not change the secret is not a rotation, and
	// recording it as one is how a stale credential comes to look current.
	ErrNotRotated = errors.New("rotation does not change the secret")
	// ErrNoKeyID means a plan names no key. A rotation of an unnamed key
	// cannot be retired afterwards, because there is nothing to say which
	// credential was replaced.
	ErrNoKeyID = errors.New("rotation plan must carry a key identifier")
	// ErrRotationNotVerified means a rotation's new secret does not match
	// the secret that was expected. A rotation nobody verified is a rotation
	// nobody knows worked, and the credential may well be the one that was
	// already broken.
	ErrRotationNotVerified = errors.New("rotation was not verified")
)

// Shift is one stretch of on-call duty.
//
// The shift is half-open: it covers StartsAt up to but not including EndsAt,
// so two shifts that meet at a moment do not overlap at that moment.
type Shift struct {
	// Primary is the engineer on call for this stretch.
	Primary string
	// Secondary is the engineer the primary escalates to.
	Secondary string
	// StartsAt is when the shift begins.
	StartsAt time.Time
	// EndsAt is when the shift ends. It is never zero: a shift that never
	// ends is not a shift.
	EndsAt time.Time
	// HandoverAcknowledgedBy names the engineer who accepted this shift.
	// It is the incoming primary, because an acknowledgement from anybody
	// else does not say who is on call.
	HandoverAcknowledgedBy string
}

// Roster is a set of shifts.
type Roster struct {
	// Shifts are the shifts, ordered by start time.
	Shifts []Shift
}

// BuildRoster builds the roster for a window and refuses a roster that cannot
// answer a page.
//
// The window is the period the caller cares about, and the rule that governs
// everything else is that **every moment in it has a named primary**. A gap is
// refused, and the refusal names the start and the end of the gap, because
// "on-call changed at some point" is not an answer an operator can act on.
//
// The order of the checks is the policy. The window comes first, because a
// window that never opened cannot be covered. Then each shift is checked for
// its own shape, because a shift with no primary or no secondary is broken
// before anything else is asked of it. Then the shifts are checked against each
// other for overlap, because two primaries at one moment is ambiguity rather
// than redundancy. Then the window is checked for coverage, which is the
// refusal the whole package exists for.
//
// The caller's slice is never modified: the roster is a copy, sorted by start
// time, so the same shifts always produce the same roster whatever order they
// arrived in.
func BuildRoster(shifts []Shift, from, to time.Time) (Roster, error) {
	if !to.After(from) {
		return Roster{}, fmt.Errorf("%w: the requested window starts at %s and ends at %s",
			ErrBadShiftWindow, from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
	}

	ordered := make([]Shift, len(shifts))
	copy(ordered, shifts)
	for _, s := range ordered {
		if err := validateShift(s); err != nil {
			return Roster{}, err
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if !ordered[i].StartsAt.Equal(ordered[j].StartsAt) {
			return ordered[i].StartsAt.Before(ordered[j].StartsAt)
		}
		return ordered[i].Primary < ordered[j].Primary
	})
	if err := checkOverlaps(ordered); err != nil {
		return Roster{}, err
	}
	if err := checkCoverage(ordered, from, to); err != nil {
		return Roster{}, err
	}
	return Roster{Shifts: ordered}, nil
}

// validateShift refuses a shift that could not be worked.
func validateShift(s Shift) error {
	if strings.TrimSpace(s.Primary) == "" {
		return fmt.Errorf("%w: the shift starting at %s names no primary",
			ErrNoPrimary, s.StartsAt.UTC().Format(time.RFC3339))
	}
	if strings.TrimSpace(s.Secondary) == "" {
		return fmt.Errorf("%w: the shift for %q names no secondary", ErrNoSecondary, s.Primary)
	}
	if s.EndsAt.IsZero() {
		return fmt.Errorf("%w: the shift for %q starting at %s never ends",
			ErrUnboundedShift, s.Primary, s.StartsAt.UTC().Format(time.RFC3339))
	}
	if !s.EndsAt.After(s.StartsAt) {
		return fmt.Errorf("%w: the shift for %q starts at %s and ends at %s",
			ErrBadShiftWindow, s.Primary,
			s.StartsAt.UTC().Format(time.RFC3339), s.EndsAt.UTC().Format(time.RFC3339))
	}
	if strings.TrimSpace(s.HandoverAcknowledgedBy) == "" {
		return fmt.Errorf("%w: the shift for %q starting at %s was never acknowledged",
			ErrHandoverNotAcknowledged, s.Primary, s.StartsAt.UTC().Format(time.RFC3339))
	}
	if strings.TrimSpace(s.HandoverAcknowledgedBy) != strings.TrimSpace(s.Primary) {
		return fmt.Errorf("%w: the shift for %q was acknowledged by %q",
			ErrHandoverAcknowledgedByWrong, s.Primary, s.HandoverAcknowledgedBy)
	}
	return nil
}

// checkOverlaps refuses two shifts that cover the same moment.
//
// The shifts are sorted by start time, so it is enough to compare each shift
// with the one before it: if no two consecutive shifts overlap, then no two
// shifts overlap at all, because each shift ends before the next one starts
// and the ends and starts are in order.
func checkOverlaps(ordered []Shift) error {
	for i := 1; i < len(ordered); i++ {
		prev := ordered[i-1]
		cur := ordered[i]
		if cur.StartsAt.Before(prev.EndsAt) {
			return fmt.Errorf("%w: the shift for %q (%s to %s) overlaps the shift for %q (%s to %s)",
				ErrOverlappingShifts,
				cur.Primary,
				cur.StartsAt.UTC().Format(time.RFC3339), cur.EndsAt.UTC().Format(time.RFC3339),
				prev.Primary,
				prev.StartsAt.UTC().Format(time.RFC3339), prev.EndsAt.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

// checkCoverage refuses a window in which some moment has no primary.
//
// The walk follows the covered region from the start of the window. A shift
// that starts after the region ends opens a gap, and the gap is named. A shift
// that starts inside the region extends it, and a shift that ends before the
// region reaches it adds nothing.
func checkCoverage(ordered []Shift, from, to time.Time) error {
	cursor := from
	for _, s := range ordered {
		if !cursor.Before(to) {
			return nil
		}
		if !s.EndsAt.After(cursor) {
			// The shift is entirely behind the covered region. It is not
			// refused here because a shift that overlaps another one was
			// already refused; here it simply contributes nothing.
			continue
		}
		if s.StartsAt.After(cursor) {
			return gapError(cursor, s.StartsAt, to)
		}
		cursor = s.EndsAt
	}
	if cursor.Before(to) {
		return gapError(cursor, to, to)
	}
	return nil
}

// gapError refuses a gap, naming the moment it opens and the moment it closes.
//
// The end of the gap is capped at the end of the requested window, because a
// gap that runs past the window is a gap inside the window and the operator
// only needs to know where it begins.
func gapError(from, to, windowEnd time.Time) error {
	end := to
	if end.After(windowEnd) {
		end = windowEnd
	}
	return fmt.Errorf("%w: no primary between %s and %s",
		ErrNoOnCallCoverage,
		from.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
}

// PrimaryAt returns the shift whose primary was on call at a moment.
//
// The moment is tested against the half-open window of each shift, so the
// moment a shift ends belongs to whoever took over, not to the person who just
// finished. A moment that no shift covers has no primary, and that is
// reported as the absence of one rather than as a guess.
func (r Roster) PrimaryAt(at time.Time) (Shift, bool) {
	for _, s := range r.Shifts {
		if at.Before(s.StartsAt) {
			continue
		}
		if !at.Before(s.EndsAt) {
			continue
		}
		return s, true
	}
	return Shift{}, false
}

// Duty is a piece of the platform somebody is accountable for.
//
// The set of duties is fixed by docs/SRE.md, and the names follow the wording
// of the ownership paragraph there: platform on-call owns lifecycle, state and
// leaks; security owns untrusted code and identity boundaries; reliability
// owns experiment and gate methodology and abort; and a cost owner reviews
// fixed and variable spend and profile forecasts.
type Duty string

const (
	// DutyLifecycleAndLeaks is the duty of platform on-call over the
	// lifecycle of environments, the state that records them and the leaks
	// that outlive them.
	DutyLifecycleAndLeaks Duty = "lifecycle-and-leaks"
	// DutyCloudQuota is the duty of platform on-call over the cloud quota
	// the platform spends.
	DutyCloudQuota Duty = "cloud-quota"
	// DutyIdentityBoundaries is the duty of security over the boundaries
	// where untrusted code meets identity.
	DutyIdentityBoundaries Duty = "identity-boundaries"
	// DutyExperimentAndAbort is the duty of reliability over experiment and
	// gate methodology and over abort.
	DutyExperimentAndAbort Duty = "experiment-and-abort"
	// DutyCost is the duty of the cost owner over fixed and variable spend
	// and profile forecasts.
	DutyCost Duty = "cost"
)

// RequiredDuties returns every duty the platform must have an owner for.
//
// The list is the ownership set of docs/SRE.md and it is returned fresh every
// call, so a caller that reorders it cannot change what the next caller sees.
func RequiredDuties() []Duty {
	return []Duty{
		DutyLifecycleAndLeaks,
		DutyCloudQuota,
		DutyIdentityBoundaries,
		DutyExperimentAndAbort,
		DutyCost,
	}
}

// knownDuty reports whether a duty is one this platform defines.
func knownDuty(d Duty) bool {
	for _, known := range RequiredDuties() {
		if known == d {
			return true
		}
	}
	return false
}

// HandoverRecord is one change of hands of a duty.
//
// The previous holder is part of the record rather than a field that is
// overwritten, because a duty that changes hands silently leaves nobody able
// to say who was holding it when.
type HandoverRecord struct {
	// At is when the handover happened.
	At time.Time
	// FromTeam is the team that held the duty before.
	FromTeam string
	// FromOwner is the person who held the duty before.
	FromOwner string
	// ToTeam is the team that holds the duty now.
	ToTeam string
	// ToOwner is the person who holds the duty now.
	ToOwner string
	// Actor is who performed the handover.
	Actor string
	// Reason is why the duty changed hands.
	Reason string
}

// Assignment is one duty and the team and person that hold it.
type Assignment struct {
	// Duty is the duty being held.
	Duty Duty
	// Team is the team that holds it.
	Team string
	// Owner is the person who holds it. A duty that is "the team's" is
	// owned by nobody.
	Owner string
	// History is the record of every handover of this duty, oldest first.
	History []HandoverRecord
}

// Ownership is the set of duties and who holds them.
type Ownership struct {
	// Assignments are the assignments, ordered by duty.
	Assignments []Assignment
}

// AssignOwnership builds the ownership map and refuses an assignment that
// leaves a duty unheld.
//
// The order of the checks is the policy. The duty comes first, because a duty
// outside the set fixed by SRE.md belongs to somebody else's roster. Then the
// duplicate, because two holders of one duty is ambiguity rather than
// redundancy, and it is a problem whatever the two assignments say. Then the
// team and the owner, because a duty with a team but no owner is a duty that
// is met whenever somebody remembers.
//
// The caller's slice is never modified: the assignments are copied and ordered
// by duty, so the same assignments always produce the same ownership.
func AssignOwnership(assignments []Assignment) (Ownership, error) {
	seen := make(map[Duty]bool, len(assignments))
	out := make([]Assignment, 0, len(assignments))
	for _, a := range assignments {
		if !knownDuty(a.Duty) {
			return Ownership{}, fmt.Errorf("%w: %q", ErrUnknownDuty, a.Duty)
		}
		if seen[a.Duty] {
			return Ownership{}, fmt.Errorf("%w: %q", ErrDuplicateDuty, a.Duty)
		}
		seen[a.Duty] = true
		if strings.TrimSpace(a.Team) == "" {
			return Ownership{}, fmt.Errorf("%w: duty %q names no team", ErrNoDutyTeam, a.Duty)
		}
		if strings.TrimSpace(a.Owner) == "" {
			return Ownership{}, fmt.Errorf("%w: duty %q names no owner", ErrNoDutyOwner, a.Duty)
		}
		copied := a
		copied.History = append([]HandoverRecord(nil), a.History...)
		out = append(out, copied)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return dutyOrder(out[i].Duty) < dutyOrder(out[j].Duty)
	})
	return Ownership{Assignments: out}, nil
}

// dutyOrder returns the position of a duty in the canonical order.
func dutyOrder(d Duty) int {
	for i, known := range RequiredDuties() {
		if known == d {
			return i
		}
	}
	return len(RequiredDuties())
}

// OwnerOf returns the assignment that holds a duty.
//
// A duty nobody holds is reported as an absence rather than as an empty
// assignment, so that "held by nobody" cannot be mistaken for "held by a team
// with no name".
func (o Ownership) OwnerOf(d Duty) (Assignment, bool) {
	for _, a := range o.Assignments {
		if a.Duty == d {
			return a, true
		}
	}
	return Assignment{}, false
}

// CheckCoverage refuses an ownership that leaves a required duty unheld.
//
// The ownership set of docs/SRE.md is fixed, so a missing duty is a gap in the
// roster rather than a preference. The missing duties are named, because
// "somebody is missing" is not an answer an operator can act on.
//
// The duties that are held are checked too: a duty that names a team but no
// owner is held by nobody, and it would otherwise pass this check while
// being the same gap the check exists to find.
func CheckCoverage(o Ownership) error {
	held := make(map[Duty]bool, len(o.Assignments))
	for _, a := range o.Assignments {
		held[a.Duty] = true
	}
	var missing []string
	for _, d := range RequiredDuties() {
		if !held[d] {
			missing = append(missing, string(d))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrUncoveredDuty, strings.Join(missing, ", "))
	}
	for _, a := range o.Assignments {
		if strings.TrimSpace(a.Team) == "" {
			return fmt.Errorf("%w: duty %q names no team", ErrNoDutyTeam, a.Duty)
		}
		if strings.TrimSpace(a.Owner) == "" {
			return fmt.Errorf("%w: duty %q names no owner", ErrNoDutyOwner, a.Duty)
		}
	}
	return nil
}

// HandOver moves a duty to a new team and owner and records how it got there.
//
// A handover is an explicit act: it names who did it, why, and when, and it
// keeps the previous holder in the duty's history. A duty that changed hands
// silently leaves nobody able to say who was holding it when the incident
// happened, which is the moment the question is asked.
//
// The order of the checks is the policy. The duty comes first, because there
// is nothing to hand over that is not one of ours. Then the actor and the
// reason, because a handover without them is a change nobody can defend.
// Then the incoming team and owner, because handing a duty to nobody leaves
// the gap this package exists to close. Then the duty's presence, because
// there is no previous holder to record when the duty has none.
//
// The ownership handed in is never modified: the assignments are copied and
// only the one that changed is replaced.
func HandOver(o Ownership, d Duty, toTeam, toOwner, actor, reason string, at time.Time) (Ownership, error) {
	if !knownDuty(d) {
		return o, fmt.Errorf("%w: %q", ErrUnknownDuty, d)
	}
	if strings.TrimSpace(actor) == "" {
		return o, fmt.Errorf("%w: handover of duty %q", ErrNoActor, d)
	}
	if strings.TrimSpace(reason) == "" {
		return o, fmt.Errorf("%w: handover of duty %q", ErrNoReason, d)
	}
	if strings.TrimSpace(toTeam) == "" {
		return o, fmt.Errorf("%w: the incoming holder of duty %q names no team", ErrNoDutyTeam, d)
	}
	if strings.TrimSpace(toOwner) == "" {
		return o, fmt.Errorf("%w: the incoming holder of duty %q names no owner", ErrNoDutyOwner, d)
	}
	index := -1
	for i, a := range o.Assignments {
		if a.Duty == d {
			index = i
			break
		}
	}
	if index < 0 {
		return o, fmt.Errorf("%w: duty %q has no current holder to hand over from", ErrUncoveredDuty, d)
	}

	out := o
	out.Assignments = make([]Assignment, len(o.Assignments))
	copy(out.Assignments, o.Assignments)
	current := out.Assignments[index]
	entry := HandoverRecord{
		At:        at,
		FromTeam:  current.Team,
		FromOwner: current.Owner,
		ToTeam:    strings.TrimSpace(toTeam),
		ToOwner:   strings.TrimSpace(toOwner),
		Actor:     strings.TrimSpace(actor),
		Reason:    strings.TrimSpace(reason),
	}
	updated := current
	updated.Team = entry.ToTeam
	updated.Owner = entry.ToOwner
	updated.History = append(append([]HandoverRecord{}, current.History...), entry)
	out.Assignments[index] = updated
	return out, nil
}

// KeyKind is a kind of credential a rotation covers.
//
// The kinds are the ones docs/SRE.md lists for key rotations: GitHub App, OIDC
// trust and signing, state and evidence KMS, dependency allocator credentials
// and scoped preview secrets.
type KeyKind string

const (
	// KeyGitHubApp is the GitHub App credential.
	KeyGitHubApp KeyKind = "github-app"
	// KeyOIDCTrust is the key that platform workloads trust to talk to the
	// control plane.
	KeyOIDCTrust KeyKind = "oidc-trust"
	// KeyOIDCSigning is the key that signs control plane responses.
	KeyOIDCSigning KeyKind = "oidc-signing"
	// KeyStateKMS is the key that encrypts the state store.
	KeyStateKMS KeyKind = "state-kms"
	// KeyEvidenceKMS is the key that encrypts the evidence store.
	KeyEvidenceKMS KeyKind = "evidence-kms"
	// KeyAllocatorCredentials are the credentials the dependency allocator
	// uses to fetch dependencies.
	KeyAllocatorCredentials KeyKind = "allocator-credentials"
	// KeyPreviewSecrets are the scoped secrets handed to previews.
	KeyPreviewSecrets KeyKind = "preview-secrets"
)

// RequiredKeyKinds returns every kind a rotation has to cover.
//
// The list comes from docs/SRE.md and it is returned fresh every call, so a
// caller that reorders it cannot change what the next caller sees.
func RequiredKeyKinds() []KeyKind {
	return []KeyKind{
		KeyGitHubApp,
		KeyOIDCTrust,
		KeyOIDCSigning,
		KeyStateKMS,
		KeyEvidenceKMS,
		KeyAllocatorCredentials,
		KeyPreviewSecrets,
	}
}

// knownKeyKind reports whether a kind is one this platform rotates.
func knownKeyKind(k KeyKind) bool {
	for _, known := range RequiredKeyKinds() {
		if known == k {
			return true
		}
	}
	return false
}

// keyKindOrder returns the position of a kind in the canonical order.
func keyKindOrder(k KeyKind) int {
	for i, known := range RequiredKeyKinds() {
		if known == k {
			return i
		}
	}
	return len(RequiredKeyKinds())
}

// RotationPlan is an intention to replace one credential.
//
// The plan carries both the current secret and the new one, because the rule
// it has to satisfy is a comparison between the two: the new scope has to fit
// inside the current one. A plan that carried only the new secret could not
// be checked for privilege widening at all.
type RotationPlan struct {
	// Kind is the kind of credential being rotated.
	Kind KeyKind
	// KeyID names the credential being rotated, so that it can be retired
	// afterwards.
	KeyID string
	// CurrentSecret is the secret in use now.
	CurrentSecret string
	// NewSecret is the secret to install.
	NewSecret string
	// CurrentScope is what the current secret is allowed to do.
	CurrentScope []string
	// NewScope is what the new secret is allowed to do. It has to be a
	// subset of CurrentScope.
	NewScope []string
	// Reason is why the rotation is happening.
	Reason string
	// Actor is who is rotating it.
	Actor string
	// ScheduledAt is when the rotation is planned for.
	ScheduledAt time.Time
}

// Rotation is a rotation that happened.
type Rotation struct {
	// Plan is the plan that was applied. It is kept whole so that the
	// record shows what was intended as well as what was done.
	Plan RotationPlan
	// RotatedAt is when the rotation happened.
	RotatedAt time.Time
	// PreviousKeyID is the identifier of the credential that was replaced.
	// It is what has to be retired afterwards, so it is kept where the
	// reader of the record will find it.
	PreviousKeyID string
}

// validatePlan refuses a plan that could not be applied.
//
// The order of the checks is the policy. The kind comes first, because a kind
// outside the rotation vocabulary is a credential no rule in this package
// reaches. Then the key identifier, because a rotation of an unnamed key
// cannot be retired afterwards. Then the actor and the reason, because a
// rotation nobody performed and nobody justified cannot be reviewed
// afterwards. Then the secret, because a rotation that does not change the
// secret is not a rotation. Then the scope, because that is the check the
// whole plan exists for.
func validatePlan(p RotationPlan) error {
	if !knownKeyKind(p.Kind) {
		return fmt.Errorf("%w: %q", ErrUnknownKeyKind, p.Kind)
	}
	if strings.TrimSpace(p.KeyID) == "" {
		return fmt.Errorf("%w: the plan for %q", ErrNoKeyID, p.Kind)
	}
	if strings.TrimSpace(p.Actor) == "" {
		return fmt.Errorf("%w: the plan for %q", ErrNoActor, p.Kind)
	}
	if strings.TrimSpace(p.Reason) == "" {
		return fmt.Errorf("%w: the plan for %q", ErrNoReason, p.Kind)
	}
	if strings.TrimSpace(p.NewSecret) == "" || p.NewSecret == p.CurrentSecret {
		return fmt.Errorf("%w: the plan for %q carries the current secret as its new one", ErrNotRotated, p.Kind)
	}
	if !scopeIsSubset(p.CurrentScope, p.NewScope) {
		return fmt.Errorf("%w: the plan for %q would grant %v on top of %v",
			ErrPrivilegeWidened, p.Kind, p.NewScope, p.CurrentScope)
	}
	return nil
}

// scopeIsSubset reports whether a new scope stays inside the current one.
//
// The comparison is set-shaped: what matters is whether every permission in
// the new scope was already granted. An empty current scope grants nothing,
// so any new scope widens it.
func scopeIsSubset(current, next []string) bool {
	granted := make(map[string]bool, len(current))
	for _, s := range current {
		granted[strings.TrimSpace(s)] = true
	}
	for _, s := range next {
		if !granted[strings.TrimSpace(s)] {
			return false
		}
	}
	return true
}

// Rotate applies a plan and records what happened.
//
// The rotation records the moment it happened and the identifier of the
// credential it replaced, because that identifier is what has to be retired
// afterwards and a rotation record without it cannot retire anything.
//
// The plan is not modified: the copy kept in the rotation has its own scope
// slices, so a caller that later edits the plan it passed in cannot rewrite
// what the record says was applied.
func Rotate(plan RotationPlan, at time.Time) (Rotation, error) {
	if err := validatePlan(plan); err != nil {
		return Rotation{}, err
	}
	applied := plan
	applied.CurrentScope = append([]string(nil), plan.CurrentScope...)
	applied.NewScope = append([]string(nil), plan.NewScope...)
	return Rotation{
		Plan:          applied,
		RotatedAt:     at,
		PreviousKeyID: strings.TrimSpace(plan.KeyID),
	}, nil
}

// PlanRotation checks a set of plans as a whole and refuses an incomplete one.
//
// SRE.md lists what a rotation covers, and a rotation that quietly leaves one
// kind behind is a rotation that has rotated the part somebody remembered. So
// the plan has to name every kind, and the refusal names the kinds that were
// missed.
//
// Every plan is checked on its own before the set is judged, because a plan
// that could not be applied is a more immediate problem than a plan that is
// missing, and an operator needs to know about both.
//
// The plans are returned ordered by kind, so the same plans always produce the
// same schedule whatever order they arrived in.
func PlanRotation(plans []RotationPlan) ([]RotationPlan, error) {
	if len(plans) == 0 {
		return nil, ErrEmptyRotationPlan
	}
	for _, p := range plans {
		if err := validatePlan(p); err != nil {
			return nil, err
		}
	}
	covered := make(map[KeyKind]bool, len(plans))
	for _, p := range plans {
		covered[p.Kind] = true
	}
	var missing []string
	for _, k := range RequiredKeyKinds() {
		if !covered[k] {
			missing = append(missing, string(k))
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrKindNotRotated, strings.Join(missing, ", "))
	}
	out := make([]RotationPlan, len(plans))
	copy(out, plans)
	sort.SliceStable(out, func(i, j int) bool {
		return keyKindOrder(out[i].Kind) < keyKindOrder(out[j].Kind)
	})
	return out, nil
}

// VerifyRotation checks that a rotation produced the secret that was expected.
//
// A rotation nobody verified is a rotation nobody knows worked: the credential
// may well be the one that was already broken, and the record would say the
// rotation happened either way. So verification is a separate act, and a
// rotation that does not match what was expected is refused.
func VerifyRotation(r Rotation, expectedNewSecret string) error {
	if r.Plan.NewSecret != expectedNewSecret {
		return fmt.Errorf("%w: the rotation of %q did not produce the expected secret",
			ErrRotationNotVerified, r.Plan.Kind)
	}
	return nil
}

// Record is what actually happened: the rotations that were carried out and the
// duties that changed hands.
//
// The record is the point of the package. A plan says what was intended, and
// an intention is not evidence, so completeness is checked against what
// happened rather than against what was meant to happen.
type Record struct {
	// Rotations are the rotations that were carried out.
	Rotations []Rotation
	// Handovers are the duty handovers that happened. Each entry is the
	// assignment as it stood after the handover, carrying the duty's
	// history including the holder it came from.
	Handovers []Assignment
}

// LastRotationOf returns the most recent rotation of a kind.
//
// When a kind is rotated more than once, the later rotation is the one that
// describes the credential in use now, so the one that is returned is the
// latest by the moment it happened.
func (r Record) LastRotationOf(kind KeyKind) (Rotation, bool) {
	var latest Rotation
	found := false
	for _, rot := range r.Rotations {
		if rot.Plan.Kind != kind {
			continue
		}
		if !found || rot.RotatedAt.After(latest.RotatedAt) {
			latest = rot
			found = true
		}
	}
	return latest, found
}

// Complete refuses a record in which some required kind was never rotated.
//
// This is the same rule as the plan's, applied to what actually happened
// rather than to what was intended. A kind that was planned and not rotated
// is exactly the kind somebody will believe was rotated, so the missing kinds
// are named.
func (r Record) Complete() error {
	var missing []string
	for _, k := range RequiredKeyKinds() {
		if _, ok := r.LastRotationOf(k); !ok {
			missing = append(missing, string(k))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrKindNotRotated, strings.Join(missing, ", "))
	}
	return nil
}
