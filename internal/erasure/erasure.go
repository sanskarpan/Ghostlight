// Package erasure implements the erasure job that organization closure requires, and
// the replay that proves an erasure survived a restore.
//
// Closure policy exists elsewhere. This package is the part that actually removes
// things, which is exactly the part where a policy and an implementation can
// disagree. A closure that "passed" because it recorded an intent and never ran a
// job has erased nothing, and a data-subject request answered by such a closure is
// answered with a lie.
//
// Four rules shape the job, and each of them is about what happens when something goes
// wrong.
//
// The first is that erasure is **a plan, not a scramble**. The job computes what must
// be erased and in what order, and refuses to erase anything whose order is unknown.
// Dependencies matter: a database that still has a table referencing an erased
// identity is a broken database, so the job erases in dependency order and refuses a
// plan it cannot order.
//
// The second is that erasure is **verified, not assumed**. A provider can accept a
// delete and not apply it, which is the same lesson `internal/resource` learned about
// destroys. So every erasure is confirmed absent before the job moves on, and a delete
// that returned successfully is not evidence. An item whose erasure cannot be
// confirmed is **not** marked erased; it stays outstanding and the job reports it.
//
// The third is that a partial erasure is reported honestly. A job that erased four of
// five items and failed the fifth has erased four, and the report says four. It does
// not round up to "done", because a closure that reports success over a partial
// erasure is the specific failure this row exists to prevent.
//
// The fourth is that erasure is **idempotent and resumable**. A job that was
// interrupted half way is re-run: the items already erased are recognised as erased
// and skipped, and the rest are attempted. Erasing twice is harmless; erasing a
// half-erased set and reporting success is not.
//
// And the replay is the part that catches the worst case. If the platform is restored
// from a backup, records that were erased after the backup was taken come back —
// because they were in the backup, and the erasure happened afterwards. The replay
// detects exactly that: it compares the restored state against the erasure journal,
// finds records that should not exist any more, and erases them again. A closure that
// survives a restore is a closure that was real.
package erasure

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package's erasure rules.
var (
	// ErrNoJobID means a job carries no identifier.
	ErrNoJobID = errors.New("erasure job must carry an identifier")
	// ErrDuplicateJob means two jobs share an identifier.
	ErrDuplicateJob = errors.New("erasure job identifier is already in use")
	// ErrNoOrganization means a job names no organization.
	ErrNoOrganization = errors.New("erasure job must carry an organization")
	// ErrNoActor means a job names no actor.
	ErrNoActor = errors.New("erasure job must name an actor")
	// ErrNoItems means a job has nothing to erase.
	ErrNoItems = errors.New("erasure job has nothing to erase")
	// ErrUnknownItem means an item names no record.
	ErrUnknownItem = errors.New("erasure item must carry a record identifier")
	// ErrDuplicateItem means two items name the same record.
	ErrDuplicateItem = errors.New("erasure item is listed twice")
	// ErrUnknownDependency means an item depends on a record the job does not
	// erase. Erasing a dependent while its dependency survives leaves a broken
	// reference, so the job refuses rather than guessing.
	ErrUnknownDependency = errors.New("erasure item depends on a record outside the job")
	// ErrDependencyCycle means the items cannot be ordered.
	ErrDependencyCycle = errors.New("erasure items depend on each other in a cycle")
	// ErrUnknownOrganization means a journal names an organization that is not
	// being erased.
	ErrUnknownOrganization = errors.New("no erasure journal for that organization")
	// ErrAlreadyErased means a record is recorded as already erased.
	ErrAlreadyErased = errors.New("record is already erased")
	// ErrVerificationFailed means an erasure could not be confirmed. The record
	// stays outstanding, because a delete that returned successfully is not
	// evidence.
	ErrVerificationFailed = errors.New("erasure could not be confirmed")
	// ErrNoReason means an act with consequences carried no reason.
	ErrNoReason = errors.New("reason must be stated")
)

// ItemKind classifies a thing to be erased.
type ItemKind string

const (
	// KindDatabase is a database or schema.
	KindDatabase ItemKind = "database"
	// KindTable is a table.
	KindTable ItemKind = "table"
	// KindObject is a stored object such as a file or a bucket.
	KindObject ItemKind = "object"
	// KindRecord is a row or a document.
	KindRecord ItemKind = "record"
	// KindCredential is a secret, a token or a key.
	KindCredential ItemKind = "credential"
)

// Eraser removes one item and reports what it observed.
type Eraser interface {
	// Erase removes the record and reports whether its absence was confirmed.
	// A provider can accept a delete and not apply it, so the boolean is a
	// confirmation and not a success flag.
	Erase(kind ItemKind, recordID string) (confirmed bool, err error)
}

// Item is one thing the job erases.
type Item struct {
	// RecordID identifies the record.
	RecordID string
	// Kind classifies it.
	Kind ItemKind
	// DependsOn names records that must be erased first. A dependent is erased
	// after its dependencies, never before.
	DependsOn []string
	// Label describes it for the operator reading the report.
	Label string
}

// Job is an erasure job.
type Job struct {
	// ID identifies the job.
	ID string
	// Organization is the tenant being erased.
	Organization string
	// RequestedBy names who asked for the erasure.
	RequestedBy string
	// Reason states why.
	Reason string
	// Items are the things to erase.
	Items []Item
	// RequestedAt is when the job was created.
	RequestedAt time.Time
}

// Journal records what an erasure did, and is what the replay is checked against.
type Journal struct {
	// Organization is the tenant the journal covers.
	Organization string
	// Erased maps a record identifier to the moment its erasure was confirmed.
	Erased map[string]time.Time
	// Outstanding names records whose erasure was never confirmed.
	Outstanding map[string]string
}

// NewJournal returns an empty journal for an organization.
func NewJournal(organization string) Journal {
	return Journal{
		Organization: organization,
		Erased:       map[string]time.Time{},
		Outstanding:  map[string]string{},
	}
}

// validate checks the job's shape and that its dependencies are resolvable.
func (j Job) validate() error {
	if strings.TrimSpace(j.ID) == "" {
		return ErrNoJobID
	}
	if strings.TrimSpace(j.Organization) == "" {
		return ErrNoOrganization
	}
	if strings.TrimSpace(j.RequestedBy) == "" {
		return ErrNoActor
	}
	if len(j.Items) == 0 {
		return ErrNoItems
	}
	known := make(map[string]bool, len(j.Items))
	for _, item := range j.Items {
		if strings.TrimSpace(item.RecordID) == "" {
			return ErrUnknownItem
		}
		if known[item.RecordID] {
			return fmt.Errorf("%w: %q", ErrDuplicateItem, item.RecordID)
		}
		known[item.RecordID] = true
	}
	for _, item := range j.Items {
		for _, dep := range item.DependsOn {
			if !known[dep] {
				return fmt.Errorf("%w: %q depends on %q", ErrUnknownDependency, item.RecordID, dep)
			}
		}
	}
	return nil
}

// Order returns the items in the order they must be erased: dependencies first.
//
// The order is computed by a depth-first walk over the dependency graph, so a record
// is erased only after everything it depends on. A cycle is refused rather than
// broken arbitrarily, because an arbitrary break means one of the two records is
// erased while the other still refers to it, and neither of those states is a state
// anyone can describe.
func (j Job) Order() ([]Item, error) {
	if err := j.validate(); err != nil {
		return nil, err
	}
	byID := make(map[string]Item, len(j.Items))
	for _, item := range j.Items {
		byID[item.RecordID] = item
	}
	const (
		unvisited = 0
		visiting  = 1
		done      = 2
	)
	state := make(map[string]int, len(j.Items))
	var order []Item

	var visit func(id string, path []string) error
	visit = func(id string, path []string) error {
		switch state[id] {
		case done:
			return nil
		case visiting:
			return fmt.Errorf("%w: %s", ErrDependencyCycle, strings.Join(append(path, id), " -> "))
		}
		state[id] = visiting
		for _, dep := range byID[id].DependsOn {
			if err := visit(dep, append(path, id)); err != nil {
				return err
			}
		}
		state[id] = done
		order = append(order, byID[id])
		return nil
	}

	ids := make([]string, 0, len(j.Items))
	for _, item := range j.Items {
		ids = append(ids, item.RecordID)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := visit(id, nil); err != nil {
			return nil, err
		}
	}
	return order, nil
}

// Report is what a job did.
type Report struct {
	// JobID identifies the job.
	JobID string
	// Organization is the tenant.
	Organization string
	// Erased names the records whose erasure was confirmed.
	Erased []string
	// Outstanding names the records whose erasure was not confirmed, with the
	// reason.
	Outstanding map[string]string
	// StartedAt is when the job began.
	StartedAt time.Time
	// FinishedAt is when it ended.
	FinishedAt time.Time
	// Complete reports whether every item was erased. A job that erased four of
	// five is not complete, and the report says so.
	Complete bool
}

// Run executes the job.
//
// The job is idempotent: an item already recorded as erased is skipped, so a job
// interrupted half way is re-run and finishes the remainder. An item whose erasure
// could not be confirmed stays outstanding and is **not** counted as erased — a
// provider can accept a delete and not apply it, and treating the call's return value
// as evidence of absence is how a closure reports success over a partial erasure.
func Run(j Job, e Eraser, journal Journal, at time.Time) (Report, Journal, error) {
	if err := j.validate(); err != nil {
		return Report{}, journal, err
	}
	if e == nil {
		return Report{}, journal, fmt.Errorf("%w: no eraser", ErrNoReason)
	}
	if journal.Organization != j.Organization {
		return Report{}, journal, fmt.Errorf("%w: %q", ErrUnknownOrganization, j.Organization)
	}
	order, err := j.Order()
	if err != nil {
		return Report{}, journal, err
	}
	if journal.Erased == nil {
		journal.Erased = map[string]time.Time{}
	}
	if journal.Outstanding == nil {
		journal.Outstanding = map[string]string{}
	}

	report := Report{
		JobID:        j.ID,
		Organization: j.Organization,
		Outstanding:  map[string]string{},
		StartedAt:    at,
	}
	for _, item := range order {
		if _, already := journal.Erased[item.RecordID]; already {
			continue
		}
		confirmed, err := e.Erase(item.Kind, item.RecordID)
		if err != nil {
			journal.Outstanding[item.RecordID] = err.Error()
			report.Outstanding[item.RecordID] = err.Error()
			continue
		}
		if !confirmed {
			reason := "the erasure was not confirmed absent"
			journal.Outstanding[item.RecordID] = reason
			report.Outstanding[item.RecordID] = reason
			continue
		}
		journal.Erased[item.RecordID] = at
		delete(journal.Outstanding, item.RecordID)
		report.Erased = append(report.Erased, item.RecordID)
	}
	sort.Strings(report.Erased)
	report.FinishedAt = at
	// Completion is a property of the whole job, not of this run. A resumed job
	// skips the records an earlier run erased, so counting only what this run
	// erased would report a finished job as incomplete forever.
	report.Complete = len(report.Outstanding) == 0
	for _, item := range j.Items {
		if _, erased := journal.Erased[item.RecordID]; !erased {
			report.Complete = false
			break
		}
	}
	return report, journal, nil
}

// ReplayFinding is one record that came back.
type ReplayFinding struct {
	// RecordID is the record that reappeared.
	RecordID string
	// ErasedAt is when it was originally erased.
	ErasedAt time.Time
	// ReErasable reports whether the replay could erase it again. A record that
	// reappeared but cannot be erased is reported as unresolved rather than
	// quietly left.
	ReErasable bool
	// Reason explains an unresolved record.
	Reason string
}

// ReplayResult is what a post-recovery replay found.
type ReplayResult struct {
	// Organization is the tenant checked.
	Organization string
	// Findings are the records that came back.
	Findings []ReplayFinding
	// Resolved reports whether every reappeared record was erased again.
	Resolved bool
}

// Replay checks a restored state against the erasure journal and erases again what
// came back.
//
// This is the part that catches the worst case. A restore from a backup brings back
// everything that was in the backup, including records that were erased *after* the
// backup was taken. Those records are still erased in the journal, so the journal and
// the restored state disagree, and the disagreement is precisely the set of records
// that must go again. A closure that survives a restore is a closure that was real.
//
// A record that reappeared but could not be erased again is reported as unresolved.
// It is not counted as resolved, because "we tried" is not "we did", and a report that
// rounds a failure up to a success is the failure this whole package exists to
// prevent.
func Replay(journal Journal, restored []Item, e Eraser, at time.Time) (ReplayResult, Journal, error) {
	if journal.Organization == "" {
		return ReplayResult{}, journal, fmt.Errorf("%w: empty journal", ErrUnknownOrganization)
	}
	if e == nil {
		return ReplayResult{}, journal, fmt.Errorf("%w: no eraser", ErrNoReason)
	}
	result := ReplayResult{Organization: journal.Organization, Resolved: true}
	if journal.Erased == nil {
		journal.Erased = map[string]time.Time{}
	}
	if journal.Outstanding == nil {
		journal.Outstanding = map[string]string{}
	}

	for _, item := range restored {
		erasedAt, wasErased := journal.Erased[item.RecordID]
		if !wasErased {
			// Not in the journal, so it was never erased. Nothing to replay.
			continue
		}
		finding := ReplayFinding{RecordID: item.RecordID, ErasedAt: erasedAt}
		confirmed, err := e.Erase(item.Kind, item.RecordID)
		switch {
		case err != nil:
			finding.ReErasable = false
			finding.Reason = err.Error()
			journal.Outstanding[item.RecordID] = err.Error()
			result.Resolved = false
		case !confirmed:
			finding.ReErasable = false
			finding.Reason = "the re-erasure was not confirmed absent"
			journal.Outstanding[item.RecordID] = finding.Reason
			result.Resolved = false
		default:
			finding.ReErasable = true
			journal.Erased[item.RecordID] = at
			delete(journal.Outstanding, item.RecordID)
		}
		result.Findings = append(result.Findings, finding)
	}
	sort.Slice(result.Findings, func(i, j int) bool { return result.Findings[i].RecordID < result.Findings[j].RecordID })
	return result, journal, nil
}
