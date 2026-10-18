package campaigns

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// scripted records every reauthorization it is asked about, so a test can assert both
// what was asked and in what order. Revocation is modelled as a per-step denial because
// that is the case that matters: authority disappearing mid-run.
type scripted struct {
	deny  map[string]bool
	fail  map[string]error
	calls []string
}

func (s *scripted) Authorize(campaignID, actor, stepID string) (bool, error) {
	s.calls = append(s.calls, campaignID+"/"+actor+"/"+stepID)
	if err, ok := s.fail[stepID]; ok {
		return false, err
	}
	if s.deny[stepID] {
		return false, nil
	}
	return true, nil
}

// permissive answers yes to everything, which is the boring case every safety rule has
// to hold up against.
type permissive struct{}

func (permissive) Authorize(_, _, _ string) (bool, error) { return true, nil }

func quietCampaign() Campaign {
	return Campaign{
		ID:          "region-blackout",
		Name:        "Region blackout",
		WindowStart: now.Add(-time.Hour),
		WindowEnd:   now.Add(time.Hour),
		Steps: []Step{
			{ID: "scale-to-zero", Action: "scale", Target: "api"},
			{ID: "drop-cdn", Action: "purge", Target: "cdn", Destructive: true},
			{ID: "restore", Action: "scale", Target: "api"},
		},
	}
}

func approved(t *testing.T) Campaign {
	t.Helper()
	c, err := Approve(quietCampaign(), "grace", now)
	if err != nil {
		t.Fatalf("approving the fixture campaign: %v", err)
	}
	return c
}

func longCampaign(n int) Campaign {
	c := quietCampaign()
	c.Steps = nil
	for i := 0; i < n; i++ {
		c.Steps = append(c.Steps, Step{ID: fmt.Sprintf("step-%03d", i), Action: "scale"})
	}
	return c
}

// ---------------------------------------------------------------------------
// Approval
// ---------------------------------------------------------------------------

// An approval is a person accepting responsibility for degrading production. Without a
// name there is nobody to ask.
func TestApproveRequiresNamedApprover(t *testing.T) {
	for _, by := range []string{"", "   ", "\t"} {
		if _, err := Approve(quietCampaign(), by, now); !errors.Is(err, ErrNoApprover) {
			t.Errorf("Approve(%q) error = %v, want ErrNoApprover", by, err)
		}
	}
}

func TestApproveRecordsApproverAndTime(t *testing.T) {
	c, err := Approve(quietCampaign(), "grace", now)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if c.ApprovedBy != "grace" || !c.ApprovedAt.Equal(now) {
		t.Errorf("approval recorded as %q at %s, want grace at %s", c.ApprovedBy, c.ApprovedAt, now)
	}
}

// A structurally broken campaign is refused at approval, because every one of these
// defects corrupts the run record rather than merely looking untidy.
func TestApproveRefusesStructurallyInvalidCampaigns(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Campaign)
		want   error
	}{
		"no campaign identifier": {func(c *Campaign) { c.ID = "" }, ErrNoCampaignID},
		"window ends before it starts": {func(c *Campaign) {
			c.WindowEnd = c.WindowStart.Add(-time.Hour)
		}, ErrBadWindow},
		"no steps": {func(c *Campaign) { c.Steps = nil }, ErrEmptyCampaign},
		"duplicate step identifiers": {func(c *Campaign) {
			c.Steps[1].ID = c.Steps[0].ID
		}, ErrDuplicateStep},
		"blank step identifier": {func(c *Campaign) { c.Steps[2].ID = "  " }, ErrEmptyStepID},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := quietCampaign()
			tc.mutate(&c)
			if _, err := Approve(c, "grace", now); !errors.Is(err, tc.want) {
				t.Errorf("Approve error = %v, want %v", err, tc.want)
			}
		})
	}
}

// A campaign with more steps than the bound is not an exercise, it is a scheduled
// outage. The refusal happens at approval so it cannot be reached at run time.
func TestApproveRefusesCampaignOverStepBound(t *testing.T) {
	if _, err := Approve(longCampaign(MaxSteps), "grace", now); err != nil {
		t.Fatalf("a campaign of exactly MaxSteps must be approvable: %v", err)
	}
	if _, err := Approve(longCampaign(MaxSteps+1), "grace", now); !errors.Is(err, ErrTooManySteps) {
		t.Errorf("Approve error = %v, want ErrTooManySteps", err)
	}
}

// Approving after the window closed is approving something that did not happen.
func TestApproveRefusesElapsedWindow(t *testing.T) {
	c := quietCampaign()
	c.WindowStart = now.Add(-3 * time.Hour)
	c.WindowEnd = now.Add(-time.Hour)
	if _, err := Approve(c, "grace", now); !errors.Is(err, ErrWindowElapsed) {
		t.Errorf("Approve error = %v, want ErrWindowElapsed", err)
	}
}

// Re-approval is allowed and replaces the approver: the newest named approver is the
// person carrying the decision, and the prior approval is history rather than a
// competing claim.
func TestApproveAllowsReapprovalByAnotherApprover(t *testing.T) {
	c, err := Approve(approved(t), "alan", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("re-approval: %v", err)
	}
	if c.ApprovedBy != "alan" {
		t.Errorf("approver = %q, want alan", c.ApprovedBy)
	}
}

// ---------------------------------------------------------------------------
// Per-step reauthorization
// ---------------------------------------------------------------------------

func TestStartRequiresReauthorizer(t *testing.T) {
	if _, err := Start(approved(t), "grace", nil, now); !errors.Is(err, ErrNoReauthorizer) {
		t.Errorf("Start error = %v, want ErrNoReauthorizer", err)
	}
}

// Reauthorization is asked about an actor, so an unnamed one has no authority to lose
// and nothing for the check to protect.
func TestStartRequiresNamedActor(t *testing.T) {
	for _, actor := range []string{"", "  "} {
		if _, err := Start(approved(t), actor, permissive{}, now); !errors.Is(err, ErrAnonymousActor) {
			t.Errorf("Start(%q) error = %v, want ErrAnonymousActor", actor, err)
		}
	}
}

func TestStartRefusesUnapprovedCampaign(t *testing.T) {
	if _, err := Start(quietCampaign(), "grace", permissive{}, now); !errors.Is(err, ErrNotApproved) {
		t.Errorf("Start error = %v, want ErrNotApproved", err)
	}
}

// A destructive step is where "we meant to do this" stops being enough.
func TestDestructiveStepRequiresApproval(t *testing.T) {
	c := quietCampaign()
	c.ApprovedBy = ""
	c.Steps = []Step{{ID: "drop-cdn", Action: "purge", Target: "cdn", Destructive: true}}
	if _, err := Start(c, "grace", permissive{}, now); !errors.Is(err, ErrNotApproved) {
		t.Errorf("Start error = %v, want ErrNotApproved", err)
	}
}

// Running a closed exercise late means running it against a fleet nobody agreed to be
// watching, so the window is checked again at start and not only at approval.
func TestStartRefusesElapsedWindow(t *testing.T) {
	if _, err := Start(approved(t), "grace", permissive{}, now.Add(2*time.Hour)); !errors.Is(err, ErrWindowElapsed) {
		t.Errorf("Start error = %v, want ErrWindowElapsed", err)
	}
}

// Start re-validates rather than trusting that the campaign came from Approve: a
// campaign value may have been assembled anywhere.
func TestStartRefusesStructurallyInvalidCampaign(t *testing.T) {
	c := approved(t)
	c.Steps[1].ID = c.Steps[0].ID
	if _, err := Start(c, "grace", permissive{}, now); !errors.Is(err, ErrDuplicateStep) {
		t.Errorf("Start error = %v, want ErrDuplicateStep", err)
	}
}

// An abort noticed out of band stops the next run before any step executes.
func TestStartRefusesCampaignAbortedOutOfBand(t *testing.T) {
	c := approved(t)
	c.AbortRequested = true
	re := &scripted{}
	run, err := Start(c, "grace", re, now)
	if !errors.Is(err, ErrAborted) {
		t.Fatalf("Start error = %v, want ErrAborted", err)
	}
	if !run.Aborted {
		t.Error("run must be recorded as aborted")
	}
	if len(run.Results) != 0 {
		t.Errorf("no step may run after an out-of-band abort, got %d results", len(run.Results))
	}
	if len(re.calls) != 0 {
		t.Errorf("nothing may be reauthorized once the campaign is aborted, got %v", re.calls)
	}
}

// Every step is reauthorized, immediately before it runs, scoped to campaign and actor.
// An approval is a record that somebody said yes once — not a capability.
func TestEveryStepIsReauthorizedImmediatelyBeforeItRuns(t *testing.T) {
	re := &scripted{}
	run, err := Start(approved(t), "grace", re, now)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	want := []string{
		"region-blackout/grace/scale-to-zero",
		"region-blackout/grace/drop-cdn",
		"region-blackout/grace/restore",
	}
	if strings.Join(re.calls, ",") != strings.Join(want, ",") {
		t.Errorf("reauthorization order = %v, want %v", re.calls, want)
	}
	if len(run.Results) != len(want) {
		t.Errorf("recorded %d results, want %d", len(run.Results), len(want))
	}
}

// The case the whole design exists for: authority disappears between step one and step
// two. Step two and step three must not run, and the reason must be recorded.
func TestRevocationMidRunStopsRemainingSteps(t *testing.T) {
	re := &scripted{deny: map[string]bool{"drop-cdn": true}}
	run, err := Start(approved(t), "grace", re, now)
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Start error = %v, want ErrNotAuthorized", err)
	}
	if !run.Aborted {
		t.Fatal("run must be aborted when a step is not authorized")
	}
	if run.Completed {
		t.Error("an aborted run must not also be completed")
	}
	if len(run.Results) != 1 || run.Results[0].StepID != "scale-to-zero" {
		t.Errorf("results = %v, want only the step that ran before the revocation", run.Results)
	}
	if !strings.Contains(run.AbortReason, "drop-cdn") {
		t.Errorf("abort reason %q must name the step that was refused", run.AbortReason)
	}
}

// An outage must never be reportable as a policy decision, so a reauthorizer error
// surfaces as itself and never as ErrNotAuthorized. The run still stops, because "we
// could not ask" is not "we were told yes".
func TestReauthorizationErrorSurfacesAsItself(t *testing.T) {
	directoryDown := errors.New("directory unreachable")
	re := &scripted{fail: map[string]error{"drop-cdn": directoryDown}}
	run, err := Start(approved(t), "grace", re, now)
	if !errors.Is(err, directoryDown) {
		t.Errorf("Start error = %v, want the reauthorizer's own error", err)
	}
	if errors.Is(err, ErrNotAuthorized) {
		t.Error("an undecidable authorization must not be reported as a policy decline")
	}
	if !run.Aborted {
		t.Error("the run must stop when authority cannot be decided")
	}
	if len(run.Results) != 1 {
		t.Errorf("results = %v, want only the step that ran before the failure", run.Results)
	}
}

// ---------------------------------------------------------------------------
// Abort
// ---------------------------------------------------------------------------

// A destructive remedy with no stated reason cannot later be told apart from an
// outage, and the two call for opposite responses.
func TestAbortRequiresReason(t *testing.T) {
	run := Run{ID: "run-1"}
	for _, reason := range []string{"", "   "} {
		if _, err := Abort(run, reason, now); !errors.Is(err, ErrNoAbortReason) {
			t.Errorf("Abort(%q) error = %v, want ErrNoAbortReason", reason, err)
		}
	}
}

func TestAbortRecordsReasonAndTime(t *testing.T) {
	run, err := Abort(Run{ID: "run-1"}, "primary region is degraded", now)
	if err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if !run.Aborted || run.AbortReason != "primary region is degraded" || !run.AbortedAt.Equal(now) {
		t.Errorf("abort recorded as %+v, want aborted with reason and time", run)
	}
}

// A second reason would overwrite the first, and the first is the one that explains
// what was actually done.
func TestAbortRefusesSecondAbort(t *testing.T) {
	run, _ := Abort(Run{ID: "run-1"}, "first reason", now)
	if _, err := Abort(run, "second reason", now.Add(time.Minute)); !errors.Is(err, ErrAlreadyAborted) {
		t.Errorf("second Abort error = %v, want ErrAlreadyAborted", err)
	}
}

// A finished record describes what happened. Continuing to write to it is writing
// history, and the game day may no longer be stopped because it is over.
func TestAbortRefusesClosedRun(t *testing.T) {
	if _, err := Abort(Run{ID: "run-1", Completed: true}, "too late", now); !errors.Is(err, ErrRunClosed) {
		t.Errorf("Abort on a completed run = %v, want ErrRunClosed", err)
	}
}

// ---------------------------------------------------------------------------
// Record immutability
// ---------------------------------------------------------------------------

func TestRecordRefusesDuplicateResult(t *testing.T) {
	run, err := Record(Run{ID: "run-1"}, StepResult{StepID: "scale-to-zero", Outcome: OutcomeExecuted, At: now})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := Record(run, StepResult{StepID: "scale-to-zero", Outcome: OutcomeExecuted, At: now.Add(time.Minute)}); !errors.Is(err, ErrDuplicateResult) {
		t.Errorf("re-recording a step = %v, want ErrDuplicateResult", err)
	}
}

func TestRecordRefusesClosedRun(t *testing.T) {
	cases := map[string]Run{
		"aborted":   {ID: "run-1", Aborted: true, AbortReason: "done"},
		"completed": {ID: "run-1", Completed: true},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Record(run, StepResult{StepID: "scale-to-zero", Outcome: OutcomeExecuted, At: now})
			if !errors.Is(err, ErrRunClosed) {
				t.Errorf("Record error = %v, want ErrRunClosed", err)
			}
		})
	}
}

// A result that does not say what happened, when it happened, or which step it belongs
// to, records nothing at all.
func TestRecordRefusesIncompleteResults(t *testing.T) {
	cases := map[string]struct {
		result StepResult
		want   error
	}{
		"no step identifier": {StepResult{Outcome: OutcomeExecuted, At: now}, ErrEmptyStepID},
		"no outcome":         {StepResult{StepID: "scale-to-zero", At: now}, ErrNoOutcome},
		"no time":            {StepResult{StepID: "scale-to-zero", Outcome: OutcomeExecuted}, ErrEmptyTimestamp},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Record(Run{ID: "run-1"}, tc.result); !errors.Is(err, tc.want) {
				t.Errorf("Record error = %v, want %v", err, tc.want)
			}
		})
	}
}

// Record is the only path a result takes into a run, so every executed step appears
// exactly once and nothing is written behind the immutability checks.
func TestExecutedStepsAppearExactlyOnceInOrder(t *testing.T) {
	run, err := Start(approved(t), "grace", permissive{}, now)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	var got []string
	for _, r := range run.Results {
		got = append(got, r.StepID+"="+r.Outcome)
	}
	want := "scale-to-zero=executed,drop-cdn=executed,restore=executed"
	if strings.Join(got, ",") != want {
		t.Errorf("recorded results = %v, want %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

// The run identifier is derived rather than random so the run of a given window is
// findable without correlating two unrelated identifiers.
func TestRunIDIsDerivedFromCampaignAndStart(t *testing.T) {
	first := RunID("region-blackout", now)
	if first != RunID("region-blackout", now) {
		t.Error("the same campaign and start time must produce the same run identifier")
	}
	if first == RunID("region-blackout", now.Add(time.Hour)) {
		t.Error("a different start time must produce a different run identifier")
	}
	if first == RunID("other", now) {
		t.Error("a different campaign must produce a different run identifier")
	}
}

// A record that reorders itself between reads cannot be diffed against anything.
func TestSummaryIsDeterministicUnderResultOrdering(t *testing.T) {
	forward, err := Record(Run{ID: "run-1"}, StepResult{StepID: "alpha", Outcome: OutcomeExecuted, At: now})
	if err != nil {
		t.Fatalf("Record alpha: %v", err)
	}
	forward, err = Record(forward, StepResult{StepID: "beta", Outcome: OutcomeExecuted, At: now})
	if err != nil {
		t.Fatalf("Record beta: %v", err)
	}
	backward, err := Record(Run{ID: "run-1"}, StepResult{StepID: "beta", Outcome: OutcomeExecuted, At: now})
	if err != nil {
		t.Fatalf("Record beta: %v", err)
	}
	backward, err = Record(backward, StepResult{StepID: "alpha", Outcome: OutcomeExecuted, At: now})
	if err != nil {
		t.Fatalf("Record alpha: %v", err)
	}
	if Summary(forward) != Summary(backward) {
		t.Errorf("summaries differ by insertion order:\n%s\n---\n%s", Summary(forward), Summary(backward))
	}
}

func TestSummaryReportsStateAndAbortReason(t *testing.T) {
	run, err := Start(approved(t), "grace", &scripted{deny: map[string]bool{"drop-cdn": true}}, now)
	if err == nil {
		t.Fatal("expected the run to be refused")
	}
	got := Summary(run)
	for _, want := range []string{"state: aborted", "step \"drop-cdn\" was not reauthorized", "campaign: region-blackout"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary is missing %q:\n%s", want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

// Approve, start with a reauthorizer that says yes, record every step, complete — and
// then find the record closed to further edits.
func TestHappyPathCompletesAndClosesTheRecord(t *testing.T) {
	c := approved(t)
	run, err := Start(c, "grace", permissive{}, now)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !run.Completed || run.Aborted {
		t.Fatalf("run = %+v, want completed and not aborted", run)
	}
	if run.ID != RunID(c.ID, now) || run.AuthorizedBy != "grace" || !run.StartedAt.Equal(now) {
		t.Errorf("run header = %+v, want the derived identifier, actor and start time", run)
	}
	if len(run.Results) != len(c.Steps) {
		t.Errorf("recorded %d results, want %d", len(run.Results), len(c.Steps))
	}
	for _, r := range run.Results {
		if r.Outcome != OutcomeExecuted || !r.At.Equal(now) {
			t.Errorf("result %+v, want executed at %s", r, now)
		}
	}
	// The record is now closed in both directions: no further results, and no abort.
	if _, err := Record(run, StepResult{StepID: "late", Outcome: OutcomeExecuted, At: now}); !errors.Is(err, ErrRunClosed) {
		t.Errorf("recording after completion = %v, want ErrRunClosed", err)
	}
	if _, err := Abort(run, "regret", now.Add(time.Minute)); !errors.Is(err, ErrRunClosed) {
		t.Errorf("aborting a completed run = %v, want ErrRunClosed", err)
	}
	if s := Summary(run); !strings.Contains(s, "state: completed") {
		t.Errorf("summary does not report completion:\n%s", s)
	}
}
