// Package reviewer implements the reviewer room: resource-authorized threads and
// findings, the generation feedback that makes an old finding historical, and the
// rules that keep a reviewer's judgement separate from the platform's evidence.
//
// The reviewer room is where a human looks at a preview and says something about it.
// Three properties follow from that, and each has a wrong obvious implementation.
//
// The first is that a thread belongs to a **resource**, and access to it is derived
// from the reviewer's grant rather than from anything in the request. A thread about
// one repository must not be readable by somebody granted another, and the refusal
// names the scope that was needed, because an authorization failure a developer
// cannot act on is one that gets worked around.
//
// The second is that **a new generation makes prior feedback historical**. When the
// code changes, the comments about the old code are still true and no longer apply,
// and pretending otherwise is how a preview shows six open findings that were fixed
// three commits ago. But "historical" is not "closed": the finding is retained, with
// its original provenance, and it is read-only, because nobody may resolve a finding
// about code that no longer exists.
//
// **Carry-forward is explicit.** A finding that still applies across the change is
// carried forward by a named person, with a reason, and it keeps the provenance of the
// original — the generation it was raised against, the author, and the moment. A
// carried-forward finding that lost its provenance is a new finding wearing an old
// one's clothes, and the reviewer who reads it cannot tell that they are looking at
// something raised against different code.
//
// The third is that **a reviewer's checklist acceptance is not evidence**. A reviewer
// ticking a box is a human saying "I looked and it seemed fine". It is not an
// invariant result, it is not a gate pass, and it does not grant production
// permission. The distinction is structural here: checklist acceptances live in their
// own field, and the function that produces invariant results only ever reads signed
// gate runs. There is deliberately no conversion between them, because the tempting
// implementation is a function that turns "a human approved this" into "the isolation
// invariant held", and that function would be the hole through which a preview would
// pass itself.
//
// Attachments are bounded and scanned. An oversized attachment is refused rather than
// truncated, and an attachment that has not been scanned is refused rather than
// served, because an unscanned screenshot is an unexamined file from an untrusted
// pull request.
package reviewer

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package's reviewer rules.
var (
	// ErrNoThreadID means a thread carries no identifier.
	ErrNoThreadID = errors.New("thread must carry an identifier")
	// ErrNoResourceID means a thread names no resource.
	ErrNoResourceID = errors.New("thread must name a resource")
	// ErrNoScope means a thread carries no scope.
	ErrNoScope = errors.New("thread must carry a scope")
	// ErrNoTitle means a thread carries no title.
	ErrNoTitle = errors.New("thread must carry a title")
	// ErrNoAuthor means a thread names no author.
	ErrNoAuthor = errors.New("thread must name an author")
	// ErrNoFindingID means a finding carries no identifier.
	ErrNoFindingID = errors.New("finding must carry an identifier")
	// ErrDuplicateFinding means two findings share an identifier.
	ErrDuplicateFinding = errors.New("finding identifier is already in use")
	// ErrUnknownFinding means a finding does not exist in the thread.
	ErrUnknownFinding = errors.New("no such finding")
	// ErrNoPrincipal means a request named no principal.
	ErrNoPrincipal = errors.New("request must name a principal")
	// ErrNotAuthorized means the principal's grants do not cover the thread's
	// scope.
	ErrNotAuthorized = errors.New("principal is not authorized in that scope")
	// ErrNoGeneration means a thread carries no generation.
	ErrNoGeneration = errors.New("thread must carry a generation")
	// ErrGenerationMismatch means a finding was raised against a different
	// generation than the thread's.
	ErrGenerationMismatch = errors.New("finding belongs to another generation")
	// ErrNoBody means a finding carries no body.
	ErrNoBody = errors.New("finding must carry a body")
	// ErrNoOwner means a finding has no owner.
	ErrNoOwner = errors.New("finding must carry an owner")
	// ErrNoReason means an act with consequences carried no reason.
	ErrNoReason = errors.New("reason must be stated")
	// ErrNoActor means an act with consequences named no actor.
	ErrNoActor = errors.New("act must name an actor")
	// ErrAlreadyResolved means a finding was resolved twice.
	ErrAlreadyResolved = errors.New("finding is already resolved")
	// ErrHistorical means a historical finding was written to. Nobody may resolve
	// a finding about code that no longer exists.
	ErrHistorical = errors.New("finding is historical and is read-only")
	// ErrNotCarriedForward means a finding was not carried forward, so a new
	// generation makes it historical.
	ErrNotCarriedForward = errors.New("finding was not carried forward")
	// ErrNoProvenance means a carried-forward finding has no original
	// provenance. A carried finding that lost its provenance is a new finding
	// wearing an old one's clothes.
	ErrNoProvenance = errors.New("carried-forward finding must retain its provenance")
	// ErrAttachmentTooLarge means an attachment exceeded the size bound.
	ErrAttachmentTooLarge = errors.New("attachment exceeds the size bound")
	// ErrUnscannedAttachment means an attachment has not been scanned.
	ErrUnscannedAttachment = errors.New("attachment has not been scanned")
	// ErrNoAttachmentID means an attachment carries no identifier.
	ErrNoAttachmentID = errors.New("attachment must carry an identifier")
	// ErrTooManyAttachments means a finding has more attachments than the bound.
	ErrTooManyAttachments = errors.New("finding exceeds the attachment bound")
	// ErrNoChecklistID means a checklist acceptance names no checklist.
	ErrNoChecklistID = errors.New("checklist acceptance must name a checklist")
	// ErrNoSignature means an invariant result carried no signed gate run.
	ErrNoSignature = errors.New("invariant result must reference a signed gate run")
	// ErrNoSigner means an invariant result named no signer.
	ErrNoSigner = errors.New("invariant result must name a signer")
	// ErrNoInvariant means an invariant result names no invariant.
	ErrNoInvariant = errors.New("invariant result must name an invariant")
	// ErrNoRunID means an invariant result names no gate run.
	ErrNoRunID = errors.New("invariant result must name a gate run")
)

// Bounds on a reviewer's content.
const (
	// MaxAttachments is the largest number of attachments one finding may carry.
	MaxAttachments = 10
	// MaxAttachmentBytes is the largest attachment a finding may carry. An
	// oversized attachment is refused rather than truncated: a truncated
	// screenshot is a screenshot that lies about what it shows.
	MaxAttachmentBytes = 8 * 1024 * 1024
)

// Principal is an authenticated reviewer.
type Principal struct {
	// ID identifies the reviewer.
	ID string
	// Grants are the scopes the reviewer may act in.
	Grants []string
}

// Covers reports whether the principal's grants cover a scope.
//
// A grant covers the scope it names and any scope beneath it, written with a slash.
// A grant of "repo:acme" covers "repo:acme/api" but not "repo:acme-other" — that is
// a different repository with a similar name, and plain prefix matching is how one
// repository's data reaches another.
func (p Principal) Covers(scope string) bool {
	for _, grant := range p.Grants {
		if grant == scope {
			return true
		}
		if strings.HasPrefix(scope, grant+"/") {
			return true
		}
	}
	return false
}

// FindingState is where a finding stands.
type FindingState string

const (
	// StateOpen means the finding is live against the current generation.
	StateOpen FindingState = "open"
	// StateResolved means somebody closed it.
	StateResolved FindingState = "resolved"
	// StateCarriedForward means it still applies across a generation change and
	// keeps its original provenance.
	StateCarriedForward FindingState = "carried-forward"
	// StateHistorical means the code it was raised against has been superseded. It
	// is retained and read-only.
	StateHistorical FindingState = "historical"
)

// Provenance records where a finding came from.
type Provenance struct {
	// Generation is the generation the finding was originally raised against.
	Generation int
	// Author is who raised it.
	Author string
	// RaisedAt is when.
	RaisedAt time.Time
	// OriginalID is the finding's identifier in its original thread.
	OriginalID string
}

// Attachment is a file attached to a finding.
type Attachment struct {
	// ID identifies the attachment.
	ID string
	// Kind names the file kind, such as "screenshot".
	Kind string
	// Bytes is its size.
	Bytes int
	// ContentType is its media type.
	ContentType string
	// Scanned reports that the attachment has been scanned. An unscanned
	// attachment is refused rather than served: it is an unexamined file from an
	// untrusted pull request.
	Scanned bool
}

// Finding is one observation a reviewer made.
type Finding struct {
	// ID identifies the finding.
	ID string
	// ThreadID is the thread it belongs to.
	ThreadID string
	// Generation is the generation it was raised against.
	Generation int
	// Kind names what it refers to: "page", "test" or "request". It may be
	// empty, because a reviewer may raise a general observation.
	Kind string
	// Reference is the optional page, test or request reference.
	Reference string
	// Body is what the reviewer said.
	Body string
	// Owner is who is accountable for it.
	Owner string
	// State is where the finding stands.
	State FindingState
	// Provenance is where the finding came from. A carried-forward finding
	// retains the provenance of the original.
	Provenance Provenance
	// RaisedAt is when the finding was raised.
	RaisedAt time.Time
	// ResolvedAt is when it was closed.
	ResolvedAt time.Time
	// Attachments are the files attached to it.
	Attachments []Attachment
	// CarriedFrom is the generation the finding was carried forward from, when it
	// was carried.
	CarriedFrom int
}

// ChecklistAcceptance records a reviewer's approval of a checklist.
//
// It is deliberately a different type from an invariant result, and there is no
// conversion between them. A reviewer ticking a box is a human saying "I looked and it
// seemed fine"; it is not an invariant holding, not a gate pass, and not permission
// to deploy.
type ChecklistAcceptance struct {
	// ChecklistID identifies the checklist.
	ChecklistID string
	// AcceptedBy names the reviewer.
	AcceptedBy string
	// AcceptedAt is when.
	AcceptedAt time.Time
	// Note is the reviewer's own words.
	Note string
}

// InvariantResult is an authoritative result about an invariant.
//
// It exists only alongside a signed gate run. There is no way to construct one from
// a checklist acceptance, and that is the point: the tempting implementation is a
// function that turns "a human approved this" into "the isolation invariant held",
// and that function would be the hole through which a preview would pass itself.
type InvariantResult struct {
	// Invariant names the invariant, such as "isolation".
	Invariant string
	// Result is the outcome: pass, fail or inconclusive.
	Result string
	// GateRunID is the signed gate run that produced it.
	GateRunID string
	// Signer names the signer of that run.
	Signer string
	// At is when it was recorded.
	At time.Time
}

// Thread is a conversation about one resource in one generation.
type Thread struct {
	// ID identifies the thread.
	ID string
	// ResourceID is the resource the thread is about.
	ResourceID string
	// Scope is the scope the resource belongs to, and the scope a reviewer's
	// grant must cover.
	Scope string
	// Generation is the generation the thread is about.
	Generation int
	// Title is the thread's headline.
	Title string
	// CreatedBy names who opened it.
	CreatedBy string
	// CreatedAt is when.
	CreatedAt time.Time
	// Findings are the observations.
	Findings []Finding
	// Checklists are the reviewer's checklist acceptances. They are not
	// evidence.
	Checklists []ChecklistAcceptance
	// Results are the authoritative invariant results, each from a signed gate
	// run.
	Results []InvariantResult
}

// Room is a set of threads.
type Room struct {
	// Threads are the room's threads.
	Threads []Thread
}

// thread looks a thread up by identifier.
func (r Room) thread(id string) (Thread, bool) {
	for _, t := range r.Threads {
		if t.ID == id {
			return t, true
		}
	}
	return Thread{}, false
}

// OpenThread opens a thread.
//
// The thread is created against a generation, because a conversation about code that
// is not the current code is a conversation about the wrong thing.
func (r Room) OpenThread(t Thread, p Principal, at time.Time) (Room, error) {
	if strings.TrimSpace(t.ID) == "" {
		return r, ErrNoThreadID
	}
	if strings.TrimSpace(t.ResourceID) == "" {
		return r, ErrNoResourceID
	}
	if strings.TrimSpace(t.Scope) == "" {
		return r, ErrNoScope
	}
	if strings.TrimSpace(t.Title) == "" {
		return r, ErrNoTitle
	}
	if strings.TrimSpace(t.CreatedBy) == "" {
		return r, ErrNoAuthor
	}
	if t.Generation <= 0 {
		return r, ErrNoGeneration
	}
	if strings.TrimSpace(p.ID) == "" {
		return r, ErrNoPrincipal
	}
	if !p.Covers(t.Scope) {
		return r, fmt.Errorf("%w: %q needs scope %q", ErrNotAuthorized, t.ID, t.Scope)
	}
	for _, existing := range r.Threads {
		if existing.ID == t.ID {
			return r, fmt.Errorf("%w: thread %q", ErrDuplicateFinding, t.ID)
		}
	}
	t.CreatedAt = at
	r.Threads = append(r.Threads, t)
	return r, nil
}

// Raise adds a finding to a thread.
//
// The finding must be raised against the thread's own generation. A finding against
// another generation would be a conversation about the wrong code, and it would be
// invisible to the generation-change machinery that makes prior feedback historical.
func (r Room) Raise(threadID string, f Finding, p Principal, at time.Time) (Room, error) {
	t, ok := r.thread(threadID)
	if !ok {
		return r, fmt.Errorf("%w: thread %q", ErrUnknownFinding, threadID)
	}
	if strings.TrimSpace(p.ID) == "" {
		return r, ErrNoPrincipal
	}
	if !p.Covers(t.Scope) {
		return r, fmt.Errorf("%w: %q needs scope %q", ErrNotAuthorized, t.ID, t.Scope)
	}
	if strings.TrimSpace(f.ID) == "" {
		return r, ErrNoFindingID
	}
	if strings.TrimSpace(f.Body) == "" {
		return r, ErrNoBody
	}
	if strings.TrimSpace(f.Owner) == "" {
		return r, ErrNoOwner
	}
	if f.Generation != t.Generation {
		return r, fmt.Errorf("%w: finding %q is generation %d, thread is %d",
			ErrGenerationMismatch, f.ID, f.Generation, t.Generation)
	}
	for _, existing := range t.Findings {
		if existing.ID == f.ID {
			return r, fmt.Errorf("%w: %q", ErrDuplicateFinding, f.ID)
		}
	}
	if len(f.Attachments) > MaxAttachments {
		return r, fmt.Errorf("%w: finding %q has %d", ErrTooManyAttachments, f.ID, len(f.Attachments))
	}
	for _, a := range f.Attachments {
		if strings.TrimSpace(a.ID) == "" {
			return r, ErrNoAttachmentID
		}
		if a.Bytes > MaxAttachmentBytes {
			return r, fmt.Errorf("%w: attachment %q is %d bytes", ErrAttachmentTooLarge, a.ID, a.Bytes)
		}
		if a.Bytes < 0 {
			return r, fmt.Errorf("%w: attachment %q", ErrAttachmentTooLarge, a.ID)
		}
		if !a.Scanned {
			return r, fmt.Errorf("%w: attachment %q", ErrUnscannedAttachment, a.ID)
		}
	}
	f.State = StateOpen
	f.RaisedAt = at
	f.Provenance = Provenance{
		Generation: t.Generation,
		Author:     f.Owner,
		RaisedAt:   at,
		OriginalID: f.ID,
	}
	t.Findings = append(t.Findings, f)
	for i := range r.Threads {
		if r.Threads[i].ID == threadID {
			r.Threads[i] = t
		}
	}
	return r, nil
}

// Resolve closes a finding.
//
// A historical finding is read-only. Nobody may resolve a finding about code that no
// longer exists — it is not wrong, it is about something else now, and marking it
// resolved would put a false closure in the record.
func (r Room) Resolve(threadID, findingID, actor, reason string, at time.Time) (Room, error) {
	t, ok := r.thread(threadID)
	if !ok {
		return r, fmt.Errorf("%w: thread %q", ErrUnknownFinding, threadID)
	}
	if strings.TrimSpace(actor) == "" {
		return r, ErrNoActor
	}
	if strings.TrimSpace(reason) == "" {
		return r, ErrNoReason
	}
	for i := range t.Findings {
		if t.Findings[i].ID != findingID {
			continue
		}
		switch t.Findings[i].State {
		case StateHistorical:
			return r, fmt.Errorf("%w: %q", ErrHistorical, findingID)
		case StateResolved:
			return r, fmt.Errorf("%w: %q", ErrAlreadyResolved, findingID)
		}
		t.Findings[i].State = StateResolved
		t.Findings[i].ResolvedAt = at
		for j := range r.Threads {
			if r.Threads[j].ID == threadID {
				r.Threads[j] = t
			}
		}
		return r, nil
	}
	return r, fmt.Errorf("%w: %q", ErrUnknownFinding, findingID)
}

// CarryForward marks a finding as still applying across a generation change.
//
// It requires a named actor and a reason, and the finding keeps its original
// provenance. A carry-forward is a judgement that a specific observation still holds
// against different code, and that judgement is worth recording — with the person who
// made it and the reason they made it.
func (r Room) CarryForward(threadID, findingID, actor, reason string, at time.Time) (Room, error) {
	t, ok := r.thread(threadID)
	if !ok {
		return r, fmt.Errorf("%w: thread %q", ErrUnknownFinding, threadID)
	}
	if strings.TrimSpace(actor) == "" {
		return r, ErrNoActor
	}
	if strings.TrimSpace(reason) == "" {
		return r, ErrNoReason
	}
	for i := range t.Findings {
		if t.Findings[i].ID != findingID {
			continue
		}
		if t.Findings[i].State == StateHistorical {
			return r, fmt.Errorf("%w: %q", ErrHistorical, findingID)
		}
		if t.Findings[i].State == StateResolved {
			return r, fmt.Errorf("%w: %q", ErrAlreadyResolved, findingID)
		}
		if t.Findings[i].Provenance.OriginalID == "" {
			return r, fmt.Errorf("%w: %q", ErrNoProvenance, findingID)
		}
		t.Findings[i].State = StateCarriedForward
		t.Findings[i].CarriedFrom = t.Findings[i].Provenance.Generation
		for j := range r.Threads {
			if r.Threads[j].ID == threadID {
				r.Threads[j] = t
			}
		}
		return r, nil
	}
	return r, fmt.Errorf("%w: %q", ErrUnknownFinding, findingID)
}

// AdmitGeneration moves a thread to a new generation.
//
// Prior findings become historical, because the code they describe has been
// superseded and the comments are still true and no longer apply. A finding that was
// explicitly carried forward survives with its provenance intact. Nothing is deleted:
// a historical finding is still the record that somebody once saw a problem, and
// deleting it would erase the reason the current code is shaped the way it is.
func (r Room) AdmitGeneration(threadID string, generation int, actor string, at time.Time) (Room, error) {
	t, ok := r.thread(threadID)
	if !ok {
		return r, fmt.Errorf("%w: thread %q", ErrUnknownFinding, threadID)
	}
	if strings.TrimSpace(actor) == "" {
		return r, ErrNoActor
	}
	if generation <= 0 {
		return r, ErrNoGeneration
	}
	if generation <= t.Generation {
		return r, fmt.Errorf("%w: generation %d is not newer than %d", ErrGenerationMismatch, generation, t.Generation)
	}
	for i := range t.Findings {
		if t.Findings[i].State == StateOpen {
			t.Findings[i].State = StateHistorical
		}
	}
	t.Generation = generation
	for j := range r.Threads {
		if r.Threads[j].ID == threadID {
			r.Threads[j] = t
		}
	}
	return r, nil
}

// AcceptChecklist records a reviewer's approval of a checklist.
//
// This is a reviewer's judgement and nothing more. It is stored in its own field, it
// is not an invariant result, and there is no way to turn it into one.
func (r Room) AcceptChecklist(threadID, checklistID, actor, note string, p Principal, at time.Time) (Room, error) {
	t, ok := r.thread(threadID)
	if !ok {
		return r, fmt.Errorf("%w: thread %q", ErrUnknownFinding, threadID)
	}
	if strings.TrimSpace(checklistID) == "" {
		return r, ErrNoChecklistID
	}
	if strings.TrimSpace(actor) == "" {
		return r, ErrNoActor
	}
	if strings.TrimSpace(p.ID) == "" {
		return r, ErrNoPrincipal
	}
	if !p.Covers(t.Scope) {
		return r, fmt.Errorf("%w: %q needs scope %q", ErrNotAuthorized, t.ID, t.Scope)
	}
	t.Checklists = append(t.Checklists, ChecklistAcceptance{
		ChecklistID: checklistID,
		AcceptedBy:  actor,
		AcceptedAt:  at,
		Note:        note,
	})
	for j := range r.Threads {
		if r.Threads[j].ID == threadID {
			r.Threads[j] = t
		}
	}
	return r, nil
}

// RecordResult records an authoritative invariant result from a signed gate run.
func (r Room) RecordResult(threadID string, res InvariantResult, p Principal, at time.Time) (Room, error) {
	t, ok := r.thread(threadID)
	if !ok {
		return r, fmt.Errorf("%w: thread %q", ErrUnknownFinding, threadID)
	}
	if strings.TrimSpace(p.ID) == "" {
		return r, ErrNoPrincipal
	}
	if !p.Covers(t.Scope) {
		return r, fmt.Errorf("%w: %q needs scope %q", ErrNotAuthorized, t.ID, t.Scope)
	}
	if strings.TrimSpace(res.Invariant) == "" {
		return r, ErrNoInvariant
	}
	if strings.TrimSpace(res.GateRunID) == "" {
		return r, ErrNoRunID
	}
	if strings.TrimSpace(res.Signer) == "" {
		return r, ErrNoSigner
	}
	res.At = at
	t.Results = append(t.Results, res)
	for j := range r.Threads {
		if r.Threads[j].ID == threadID {
			r.Threads[j] = t
		}
	}
	return r, nil
}

// Findings returns a thread's findings, sorted by identifier.
func (r Room) Findings(threadID string) []Finding {
	t, ok := r.thread(threadID)
	if !ok {
		return nil
	}
	out := make([]Finding, len(t.Findings))
	copy(out, t.Findings)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// OpenFindings returns a thread's findings that are still live.
func (r Room) OpenFindings(threadID string) []Finding {
	var out []Finding
	for _, f := range r.Findings(threadID) {
		if f.State == StateOpen || f.State == StateCarriedForward {
			out = append(out, f)
		}
	}
	return out
}

// InvariantResults returns a thread's authoritative invariant results.
//
// It reads only the results field, which is populated exclusively from signed gate
// runs. A checklist acceptance cannot appear here, because a checklist acceptance is
// a human saying "I looked and it seemed fine" and not a statement about an
// invariant.
func (r Room) InvariantResults(threadID string) []InvariantResult {
	t, ok := r.thread(threadID)
	if !ok {
		return nil
	}
	out := make([]InvariantResult, len(t.Results))
	copy(out, t.Results)
	sort.Slice(out, func(i, j int) bool { return out[i].Invariant < out[j].Invariant })
	return out
}
