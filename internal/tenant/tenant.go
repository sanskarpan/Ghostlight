// Package tenant holds the parts of a customer account that outlive any one preview:
// the audit trail, bounded data export, and resource-verified organization closure.
//
// G7.8. Closure is the load-bearing item, and its rule is short: **an organization
// closes only when nothing it owns still exists, and closure never destroys
// anything.** Verified cleanup already destroys; a second path that deletes would mean
// two code paths with authority to remove a customer's data and only one of them
// carrying the ledger's evidence requirements.
//
// Audit records are append-only and carry digests rather than payloads. An audit log
// that can be edited is not evidence, and one that stores payloads becomes the place
// secrets end up.
//
// Export is bounded and refuses rather than truncating. A truncated export that looks
// complete is worse than no export: it is what a data-subject request is answered
// with, and answering one with a partial file is a different kind of failure from
// answering it slowly.
package tenant

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package.
var (
	// ErrAuditRequired means an action must record an entry.
	ErrAuditRequired = errors.New("an audit entry is required")
	// ErrExportTooLarge means the requested export exceeds the bound.
	ErrExportTooLarge = errors.New("export exceeds the permitted bound")
	// ErrExportTooOld means the requested window starts before retention allows.
	ErrExportTooOld = errors.New("export window predates retention")
	// ErrNotEmpty means the organization still holds resources.
	ErrNotEmpty = errors.New("organization still holds resources")
	// ErrAlreadyClosed means closure already happened.
	ErrAlreadyClosed = errors.New("organization is already closed")
	// ErrUnknownResource means an audit entry named something without a kind.
	ErrUnknownResource = errors.New("resource reference is incomplete")
	// ErrInvalidInput means a request was malformed.
	ErrInvalidInput = errors.New("input is not valid")
)

// Entry is one append-only audit record.
type Entry struct {
	OrganizationID string
	OccurredAt     time.Time
	ActorRef       string
	Action         string
	ResourceType   string
	ResourceRef    string
	// InputDigest and OutputDigest are digests, never payloads. The audit log is not
	// a secret store, and a payload here ends up in every log pipeline downstream.
	InputDigest    string
	OutputDigest   string
	CorrelationRef string
}

// Validate refuses a record that could not be acted on later.
//
// An audit entry with no actor cannot answer "who did this", and one with no action
// cannot answer "what did they do". Both are refused at write time, because an audit
// trail is only useful if every row in it is complete.
func (e Entry) Validate() error {
	if e.OrganizationID == "" || e.ActorRef == "" || e.Action == "" {
		return fmt.Errorf("%w: an entry needs an organization, an actor and an action", ErrAuditRequired)
	}
	if e.OccurredAt.IsZero() {
		return fmt.Errorf("%w: an entry needs a moment", ErrAuditRequired)
	}
	if (e.ResourceType == "") != (e.ResourceRef == "") {
		// A type without a reference, or a reference without a type, cannot be resolved
		// back to the thing it describes, which is the only reason to record it.
		return fmt.Errorf("%w: resource type and reference must be given together", ErrUnknownResource)
	}
	return nil
}

// Audit is an append-only trail.
type Audit struct {
	entries []Entry
}

// Record appends an entry.
//
// There is deliberately no update and no delete. A trail that can be edited is not
// evidence, and the only question a retention policy legitimately asks is "how far
// back do we keep this", which is a bound on reads rather than a licence to rewrite.
func (a *Audit) Record(e Entry) error {
	if err := e.Validate(); err != nil {
		return err
	}
	a.entries = append(a.entries, e)
	return nil
}

// All returns entries in recorded order.
func (a *Audit) All() []Entry {
	out := make([]Entry, len(a.entries))
	copy(out, a.entries)
	return out
}

// Len reports how many entries exist.
func (a *Audit) Len() int { return len(a.entries) }

// For returns the entries naming a resource, in recorded order.
func (a *Audit) For(resourceType, resourceRef string) []Entry {
	var out []Entry
	for _, e := range a.entries {
		if e.ResourceType == resourceType && e.ResourceRef == resourceRef {
			out = append(out, e)
		}
	}
	return out
}

// Actor returns the distinct actors, sorted, for a resource. "Who touched this" is the
// question an audit trail exists to answer, and it should not require reading every row.
func (a *Audit) Actor(resourceType, resourceRef string) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range a.For(resourceType, resourceRef) {
		if !seen[e.ActorRef] {
			seen[e.ActorRef] = true
			out = append(out, e.ActorRef)
		}
	}
	sort.Strings(out)
	return out
}

// Retention is how far back a trail is kept.
const Retention = 400 * 24 * time.Hour

// Export bounds.
//
// The limits are what make an export safe to hand to somebody: an unbounded export is
// a denial of service against our own database, and an export that silently truncates
// is a compliance failure dressed as a feature.
type ExportBounds struct {
	// MaxRecords is the most rows one export may contain.
	MaxRecords int
	// MaxBytes is the largest payload one export may produce.
	MaxBytes int64
	// Window is the oldest moment that may be exported, derived from retention.
	Window time.Duration
}

// DefaultExportBounds are the bounds a self-serve export runs under.
func DefaultExportBounds() ExportBounds {
	return ExportBounds{MaxRecords: 50_000, MaxBytes: 256 << 20, Window: Retention}
}

// ExportRequest asks for a tenant's data.
type ExportRequest struct {
	OrganizationID string
	Since          time.Time
	Now            time.Time
}

// Plan is a validated export, or a refusal with its reason.
type Plan struct {
	OrganizationID string
	From           time.Time
	To             time.Time
	Entries        []Entry
	Bytes          int64
}

// PlanExport validates a request and materialises what it would return.
//
// It refuses rather than truncating, and names which bound was hit. A caller that
// receives fewer rows than exist must be able to tell, because the alternative is
// answering a data-subject request with a partial file and calling it complete.
func (a *Audit) PlanExport(req ExportRequest, b ExportBounds) (Plan, error) {
	if req.OrganizationID == "" {
		return Plan{}, fmt.Errorf("%w: an organization is required", ErrInvalidInput)
	}
	if req.Now.IsZero() {
		return Plan{}, fmt.Errorf("%w: a request needs a moment", ErrInvalidInput)
	}
	if b.MaxRecords <= 0 || b.MaxBytes <= 0 || b.Window <= 0 {
		return Plan{}, fmt.Errorf("%w: export bounds must be positive", ErrInvalidInput)
	}
	oldest := req.Now.Add(-b.Window)
	if !req.Since.IsZero() && req.Since.Before(oldest) {
		return Plan{}, fmt.Errorf("%w: %s is before %s", ErrExportTooOld, req.Since.Format("2006-01-02"), oldest.Format("2006-01-02"))
	}

	p := Plan{OrganizationID: req.OrganizationID, From: req.Since, To: req.Now}
	for _, e := range a.entries {
		if e.OrganizationID != req.OrganizationID {
			continue
		}
		if !req.Since.IsZero() && e.OccurredAt.Before(req.Since) {
			continue
		}
		if !e.OccurredAt.Before(req.Now) {
			continue
		}
		p.Entries = append(p.Entries, e)
		p.Bytes += entrySize(e)
		if len(p.Entries) > b.MaxRecords {
			return Plan{}, fmt.Errorf("%w: more than %d records", ErrExportTooLarge, b.MaxRecords)
		}
		if p.Bytes > b.MaxBytes {
			return Plan{}, fmt.Errorf("%w: more than %d bytes", ErrExportTooLarge, b.MaxBytes)
		}
	}
	return p, nil
}

// entrySize is a rough encoded size, used only to enforce the byte bound.
func entrySize(e Entry) int64 {
	return int64(len(e.ActorRef) + len(e.Action) + len(e.ResourceType) +
		len(e.ResourceRef) + len(e.InputDigest) + len(e.OutputDigest) + len(e.CorrelationRef) + 64)
}

// Occupation is what an organization still holds.
type Occupation struct {
	Environments int
	// UndeletedAllocations counts ledger rows with no verified-deletion tombstone.
	UndeletedAllocations int
	// RunningSessions counts authenticated sessions.
	RunningSessions int
}

// Empty reports whether nothing is left behind.
func (o Occupation) Empty() bool {
	return o.Environments == 0 && o.UndeletedAllocations == 0 && o.RunningSessions == 0
}

// Describe names what is in the way, because "cannot close" without a reason is a
// support ticket rather than a refusal.
func (o Occupation) Describe() string {
	parts := []string{}
	if o.Environments > 0 {
		parts = append(parts, fmt.Sprintf("%d environments", o.Environments))
	}
	if o.UndeletedAllocations > 0 {
		parts = append(parts, fmt.Sprintf("%d resources not verified deleted", o.UndeletedAllocations))
	}
	if o.RunningSessions > 0 {
		parts = append(parts, fmt.Sprintf("%d sessions", o.RunningSessions))
	}
	if len(parts) == 0 {
		return "nothing remains"
	}
	return strings.Join(parts, ", ")
}

// OrgState is the lifecycle of an organization.
type OrgState string

const (
	// OrgOpen is a working organization.
	OrgOpen OrgState = "open"
	// OrgClosing has been asked to close and is draining.
	OrgClosing OrgState = "closing"
	// OrgClosed has been closed against a verified empty occupation.
	OrgClosed OrgState = "closed"
)

// Closer drives organization closure.
type Closer struct {
	state OrgState
	// verifiedEmpty is recorded at the moment closure was proved, so a later
	// accounting change cannot silently reopen a closed organization.
	verifiedEmpty Occupation
	closedAt      time.Time
}

// NewCloser returns a closer for an open organization.
func NewCloser() *Closer { return &Closer{state: OrgOpen} }

// State reports the current lifecycle state.
func (c *Closer) State() OrgState { return c.state }

// BeginClose moves an organization into closing without destroying anything.
//
// This is the only thing closure is allowed to do on its own. It records an intent;
// it does not remove a single resource, because destruction is verified cleanup's job
// and a second path that deletes is a second path that can delete something it should
// not.
func (c *Closer) BeginClose(actor string) error {
	if actor == "" {
		return fmt.Errorf("%w: an actor is required", ErrAuditRequired)
	}
	if c.state != OrgOpen {
		return fmt.Errorf("%w: %s", ErrAlreadyClosed, c.state)
	}
	c.state = OrgClosing
	return nil
}

// Close completes closure once nothing remains.
//
// Refused while anything is left, and it names what. Completion records the empty
// occupation it was proved against, so the proof is a fact about the moment closure
// happened rather than a claim about the present.
func (c *Closer) Close(o Occupation, now time.Time) error {
	if c.state == OrgClosed {
		return ErrAlreadyClosed
	}
	if c.state != OrgClosing {
		return fmt.Errorf("%w: closure must be begun first", ErrInvalidInput)
	}
	if !o.Empty() {
		return fmt.Errorf("%w: %s", ErrNotEmpty, o.Describe())
	}
	c.state = OrgClosed
	c.verifiedEmpty = o
	c.closedAt = now.UTC()
	return nil
}

// ClosedAt reports when closure completed.
func (c *Closer) ClosedAt() time.Time { return c.closedAt }

// VerifiedAgainst returns the occupation closure was proved against.
func (c *Closer) VerifiedAgainst() Occupation { return c.verifiedEmpty }

// A closed organization does not reopen. If it could, every guarantee that made closure
// safe — nothing left behind — would be reversible by whoever asked.
func (c *Closer) Reopen() error {
	if c.state == OrgClosed {
		return ErrAlreadyClosed
	}
	c.state = OrgOpen
	return nil
}

// Closer is constructed over an occupation reader so it cannot be asked to close an
// organization it has not looked at.
type OccupationReader func(ctx context.Context, orgID string) (Occupation, error)

// CloseVerified reads the occupation and closes only if it is empty.
//
// Reading and deciding are one call on purpose: a caller that reads, then decides, then
// closes can be pointed at a different organization in between, or at the same
// organization after somebody created something.
func CloseVerified(ctx context.Context, read OccupationReader, c *Closer, orgID string, now time.Time) error {
	if read == nil {
		return fmt.Errorf("%w: an occupation reader is required", ErrInvalidInput)
	}
	o, err := read(ctx, orgID)
	if err != nil {
		return fmt.Errorf("read occupation: %w", err)
	}
	return c.Close(o, now)
}
