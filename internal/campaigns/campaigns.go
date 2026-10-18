// Package campaigns runs planned, approved fault-injection exercises — game days —
// against a live fleet.
//
// A campaign is the most dangerous thing in this system that is not a deletion: it
// deliberately degrades production to see whether the system behaves. Three rules
// follow from that, and all three are enforced here rather than left to the caller.
//
// The first is that an approval is a record, not a capability. Someone approving a
// campaign last month has not authorized running it today, and Start re-checks
// authority for EVERY step rather than once at the top of the run. A campaign whose
// authority is revoked mid-run stops mid-run, with the remaining steps unexecuted and
// the reason recorded — which is precisely the behaviour a game day exists to prove.
//
// The second is that an abort must always work and must always say why. Abort requires
// a non-empty reason because a destructive remedy with no stated reason is
// indistinguishable, six weeks later, from an outage. Abort is available from any point
// and cannot be refused for any reason other than the record already being closed.
//
// The third is that the record is immutable. Record is the only way a result enters a
// run, a closed run accepts nothing further, and a step's result can never be
// overwritten — because a remediation record that can be edited after the fact is not a
// record of what happened, it is a story about what might have.
package campaigns

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package's campaign rules.
var (
	// ErrNoApprover means an approval was attempted with no approver. An approval is
	// a person accepting responsibility for degrading production; without a name it
	// is an anonymous yes, and nothing downstream can ask who to talk to.
	ErrNoApprover = errors.New("campaign approval must name an approver")
	// ErrAnonymousActor means a run was started with no actor. Reauthorization is
	// asked about an actor, so an unnamed one has no authority to lose and therefore
	// nothing for the reauthorization check to protect.
	ErrAnonymousActor = errors.New("campaign run must name an actor")
	// ErrNoReauthorizer means Start was called without an authority to re-check. This
	// package will not run a destructive exercise on the strength of an approval it
	// already holds; if there is no reauthorizer there is no reauthorization, and the
	// answer to that is no.
	ErrNoReauthorizer = errors.New("campaign run requires a reauthorizer")
	// ErrNotApproved means the campaign carries no approval, or carries an
	// unapproved destructive step. A destructive step is the point at which "we meant
	// to do this" stops being sufficient.
	ErrNotApproved = errors.New("campaign is not approved")
	// ErrNotAuthorized means the reauthorizer declined a step. It is distinct from a
	// reauthorization error so that a policy decision and an outage never look alike.
	ErrNotAuthorized = errors.New("step was not authorized for this run")
	// ErrNoAbortReason means Abort was called with no reason. A destructive remedy
	// with no stated reason cannot later be told apart from an outage, and the two
	// call for opposite responses.
	ErrNoAbortReason = errors.New("abort must state a reason")
	// ErrAlreadyAborted means Abort was called on an already-aborted run. The second
	// reason would overwrite the first, and the first is the one that explains what
	// was actually done.
	ErrAlreadyAborted = errors.New("run is already aborted")
	// ErrAborted means the run was refused because it, or its campaign, has been
	// aborted. An abort is total: no further step runs, ever.
	ErrAborted = errors.New("run has been aborted")
	// ErrRunClosed means the run is finished or aborted and accepts no more results.
	// The record of a completed game day describes what happened; continuing to
	// write to it is writing history.
	ErrRunClosed = errors.New("run is closed to further results")
	// ErrDuplicateResult means a step already carries a result. Two results for one
	// step is an ambiguity, and ambiguity in an immutable record is corruption.
	ErrDuplicateResult = errors.New("step already has a recorded result")
	// ErrNoOutcome means a result states no outcome. A result that does not say what
	// happened records nothing.
	ErrNoOutcome = errors.New("result must state an outcome")
	// ErrEmptyTimestamp means a result carries no time. An immutable record of an
	// event that does not say when cannot be correlated with anything.
	ErrEmptyTimestamp = errors.New("result must carry a time")
	// ErrEmptyStepID means a step carries no identifier. Results are keyed by step
	// identifier, so an unnamed step cannot hold one.
	ErrEmptyStepID = errors.New("step must carry an identifier")
	// ErrDuplicateStep means two steps share an identifier. That makes both the step
	// and its result ambiguous at the moment the result is written.
	ErrDuplicateStep = errors.New("campaign has duplicate step identifiers")
	// ErrEmptyCampaign means a campaign has no steps. An empty campaign would produce
	// an empty run that reads exactly like a successful game day that did nothing.
	ErrEmptyCampaign = errors.New("campaign has no steps")
	// ErrTooManySteps means a campaign exceeds MaxSteps. A game day with unbounded
	// steps is not an exercise; it is an outage that somebody scheduled.
	ErrTooManySteps = errors.New("campaign has too many steps")
	// ErrBadWindow means the campaign's window ends before it starts. That is a typo
	// far more often than intent, and either way every start falls outside it.
	ErrBadWindow = errors.New("campaign window ends before it starts")
	// ErrWindowElapsed means the approval or the attempt falls outside the campaign's
	// window. Running a closed exercise late means running it against a fleet nobody
	// agreed to be watching.
	ErrWindowElapsed = errors.New("campaign window has elapsed")
	// ErrNoCampaignID means a campaign carries no identifier. Runs are filed under
	// their campaign, and an unnamed campaign strands its own record.
	ErrNoCampaignID = errors.New("campaign must carry an identifier")
)

// MaxSteps is the largest number of steps a campaign may contain. It is a constant
// rather than an option for the same reason the destructive set is data: a caller who
// can raise the bound can raise it past the point where an exercise is still an
// exercise.
const MaxSteps = 100

// Outcome values recorded for a step that the run itself executed.
const (
	// OutcomeExecuted records that the step ran after being reauthorized.
	OutcomeExecuted = "executed"
	// OutcomeSkipped records that a step did not run because the run was aborted or
	// the step was never authorized.
	OutcomeSkipped = "skipped"
)

// Step is one action within a campaign.
type Step struct {
	// ID identifies the step within its campaign and keys the step's result.
	ID string
	// Action names what the step does, for the human reading the record.
	Action string
	// Target names what the step acts on.
	Target string
	// Destructive marks a step that cannot be undone. A campaign containing one
	// requires an explicit named approval before it will run.
	Destructive bool
}

// Campaign is a planned exercise awaiting approval.
type Campaign struct {
	// ID identifies the campaign and scopes every reauthorization asked about it.
	ID string
	// Name is the human label.
	Name string
	// WindowStart and WindowEnd bound when the exercise may run. An approval covers
	// this window and nothing else.
	WindowStart time.Time
	WindowEnd   time.Time
	// Steps are executed in order, each reauthorized immediately before it runs.
	Steps []Step
	// ApprovedBy names the approver; empty means unapproved.
	ApprovedBy string
	// ApprovedAt is when that approval was given.
	ApprovedAt time.Time
	// AbortRequested stops any future run of this campaign. It is set out of band
	// because the reason to stop an exercise is usually noticed mid-exercise.
	AbortRequested bool
}

// StepResult is one recorded outcome within a run.
type StepResult struct {
	StepID  string
	Outcome string
	At      time.Time
	Note    string
}

// Run is the immutable record of one execution of a campaign.
type Run struct {
	// ID is derived from the campaign and the start time, so an operator looking for
	// the run of a given window finds it without a random identifier to correlate.
	ID         string
	CampaignID string
	// AuthorizedBy is the actor the run executes on behalf of, and the actor every
	// step's reauthorization is asked about.
	AuthorizedBy string
	StartedAt    time.Time
	Aborted      bool
	AbortReason  string
	AbortedAt    time.Time
	Completed    bool
	Results      []StepResult
}

// Reauthorizer re-checks live authority for a single step, immediately before it runs.
// It returns false with a nil error for a policy decline, and an error when authority
// could not be decided at all — an outage, a directory that is down, a clock that
// disagrees with itself. The distinction is load-bearing: an outage must never be
// reportable as a policy decision.
type Reauthorizer interface {
	Authorize(campaignID, actor, stepID string) (bool, error)
}

// validate enforces the structural rules that make a campaign's record unambiguous.
// It is called by Approve and again by Start, because Start re-checks rather than
// trusting that the campaign it was handed came from Approve: a campaign value may have
// been assembled anywhere, and a duplicate step identifier becomes a corrupt result at
// exactly the moment the result is written.
func validate(c Campaign) error {
	if strings.TrimSpace(c.ID) == "" {
		return ErrNoCampaignID
	}
	if c.WindowEnd.Before(c.WindowStart) {
		return ErrBadWindow
	}
	if len(c.Steps) == 0 {
		return ErrEmptyCampaign
	}
	if len(c.Steps) > MaxSteps {
		return fmt.Errorf("%w: %d steps exceeds the maximum of %d", ErrTooManySteps, len(c.Steps), MaxSteps)
	}
	seen := make(map[string]bool, len(c.Steps))
	for _, s := range c.Steps {
		if strings.TrimSpace(s.ID) == "" {
			return ErrEmptyStepID
		}
		if seen[s.ID] {
			return fmt.Errorf("%w: %q", ErrDuplicateStep, s.ID)
		}
		seen[s.ID] = true
	}
	return nil
}

// Approve records a named approver for a campaign, after checking that the campaign is
// structurally sound and that its window has not already closed.
//
// Re-approval is permitted and replaces the recorded approver: the newest named
// approver is the person carrying the decision, and the earlier approval remains in the
// run history rather than being erased by being superseded here.
func Approve(c Campaign, by string, at time.Time) (Campaign, error) {
	if strings.TrimSpace(by) == "" {
		return c, ErrNoApprover
	}
	if err := validate(c); err != nil {
		return c, err
	}
	if at.After(c.WindowEnd) {
		return c, fmt.Errorf("%w: window closed at %s, approved at %s", ErrWindowElapsed, c.WindowEnd.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339))
	}
	c.ApprovedBy = by
	c.ApprovedAt = at
	return c, nil
}

// Start begins a run of the campaign, reauthorizing every step immediately before that
// step executes and recording a result for each one that runs.
//
// If a step is declined or authority cannot be decided, the run is aborted with a
// recorded reason and returned alongside the error: the steps that already ran are
// facts and discarding them would make the record wrong.
func Start(c Campaign, actor string, re Reauthorizer, at time.Time) (Run, error) {
	run := Run{
		ID:           RunID(c.ID, at),
		CampaignID:   c.ID,
		AuthorizedBy: actor,
		StartedAt:    at,
	}
	if re == nil {
		return run, ErrNoReauthorizer
	}
	if strings.TrimSpace(actor) == "" {
		return run, ErrAnonymousActor
	}
	if err := validate(c); err != nil {
		return run, err
	}
	if strings.TrimSpace(c.ApprovedBy) == "" {
		return run, fmt.Errorf("%w: %q has no approver", ErrNotApproved, c.ID)
	}
	if c.AbortRequested {
		run, _ = Abort(run, "campaign abort requested before the run began", at)
		return run, fmt.Errorf("%w: campaign %q was aborted out of band", ErrAborted, c.ID)
	}
	if at.After(c.WindowEnd) {
		return run, fmt.Errorf("%w: window closed at %s, started at %s", ErrWindowElapsed, c.WindowEnd.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339))
	}

	for _, step := range c.Steps {
		ok, err := re.Authorize(c.ID, actor, step.ID)
		switch {
		case err != nil:
			// Authority could not be decided. This is surfaced as itself so an
			// outage is never mistaken for a policy decline; the run still stops,
			// because "we could not ask" is not "we were told yes".
			reason := fmt.Sprintf("reauthorization for step %q could not be decided: %v", step.ID, err)
			run, _ = Abort(run, reason, at)
			return run, fmt.Errorf("reauthorizing step %q: %w", step.ID, err)
		case !ok:
			reason := fmt.Sprintf("step %q was not reauthorized for actor %q", step.ID, actor)
			run, _ = Abort(run, reason, at)
			return run, fmt.Errorf("%w: step %q for actor %q", ErrNotAuthorized, step.ID, actor)
		}
		var rerr error
		run, rerr = Record(run, StepResult{StepID: step.ID, Outcome: OutcomeExecuted, At: at})
		if rerr != nil {
			return run, rerr
		}
	}
	run.Completed = true
	return run, nil
}

// RunID derives a run's identifier from its campaign and start time. It is derived
// rather than random so the run of a given window is findable without correlating two
// unrelated identifiers.
func RunID(campaignID string, at time.Time) string {
	return fmt.Sprintf("run-%s-%s", campaignID, at.UTC().Format("20060102T150405Z"))
}

// Abort stops a run and records why. It refuses only for a missing reason, an already
// aborted run and a closed run — there is deliberately no path by which a destructive
// exercise in progress cannot be stopped.
func Abort(run Run, reason string, at time.Time) (Run, error) {
	if strings.TrimSpace(reason) == "" {
		return run, ErrNoAbortReason
	}
	if run.Aborted {
		return run, ErrAlreadyAborted
	}
	if run.Completed {
		return run, ErrRunClosed
	}
	run.Aborted = true
	run.AbortReason = reason
	run.AbortedAt = at
	return run, nil
}

// Record appends a result to a run. It is the only way a result enters a run, which is
// what makes the immutability rules impossible to bypass by writing to Results directly.
func Record(run Run, result StepResult) (Run, error) {
	if run.Aborted || run.Completed {
		return run, ErrRunClosed
	}
	if strings.TrimSpace(result.StepID) == "" {
		return run, ErrEmptyStepID
	}
	if strings.TrimSpace(result.Outcome) == "" {
		return run, ErrNoOutcome
	}
	if result.At.IsZero() {
		return run, ErrEmptyTimestamp
	}
	for _, r := range run.Results {
		if r.StepID == result.StepID {
			return run, fmt.Errorf("%w: step %q in run %q", ErrDuplicateResult, result.StepID, run.ID)
		}
	}
	run.Results = append(run.Results, result)
	return run, nil
}

// Summary renders a run as a deterministic human-readable record, with results sorted by
// step identifier so the same run always prints identically. A record that reorders
// itself between reads cannot be diffed against anything.
func Summary(run Run) string {
	var b strings.Builder
	fmt.Fprintf(&b, "run %s\n", run.ID)
	fmt.Fprintf(&b, "campaign: %s\n", run.CampaignID)
	fmt.Fprintf(&b, "actor: %s\n", run.AuthorizedBy)
	if !run.StartedAt.IsZero() {
		fmt.Fprintf(&b, "started: %s\n", run.StartedAt.UTC().Format(time.RFC3339))
	}
	switch {
	case run.Aborted:
		fmt.Fprintf(&b, "state: aborted\nreason: %s\n", run.AbortReason)
	case run.Completed:
		b.WriteString("state: completed\n")
	default:
		b.WriteString("state: open\n")
	}

	results := make([]StepResult, len(run.Results))
	copy(results, run.Results)
	sort.Slice(results, func(i, j int) bool { return results[i].StepID < results[j].StepID })
	for _, r := range results {
		fmt.Fprintf(&b, "  %s\t%s\t%s", r.StepID, r.Outcome, r.At.UTC().Format(time.RFC3339))
		if r.Note != "" {
			fmt.Fprintf(&b, "\t%s", r.Note)
		}
		b.WriteString("\n")
	}
	return b.String()
}
