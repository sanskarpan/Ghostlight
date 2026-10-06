package actions

import (
	"errors"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func newAction(t *testing.T) *Action {
	t.Helper()
	a, err := New("env-01HQ", 7, TypeAllocate, "alloc-pg", "sha256:aa", []string{"dep/postgres"}, now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

var lease = Lease{Owner: "controller-a", Epoch: 3}

func TestNewRequiresIdempotencyInputs(t *testing.T) {
	if _, err := New("", 1, TypeAllocate, "k", "d", nil, now); err == nil {
		t.Fatal("environment id is required")
	}
	if _, err := New("env", 1, TypeAllocate, "", "d", nil, now); err == nil {
		t.Fatal("logical key is required; it is part of the idempotency key")
	}
	// A retry with different arguments must be a distinct action, not a resend.
	if _, err := New("env", 1, TypeAllocate, "k", "", nil, now); err == nil {
		t.Fatal("input digest is required")
	}
}

func TestClaimMovesPlannedToRunning(t *testing.T) {
	a := newAction(t)
	if err := a.Claim(lease, now); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if a.State != StateRunning {
		t.Fatalf("expected running, got %s", a.State)
	}
	if a.Attempts != 1 {
		t.Fatalf("expected 1 attempt, got %d", a.Attempts)
	}
	if a.Fencing.Epoch != lease.Epoch || a.Fencing.Owner != lease.Owner {
		t.Fatal("claim must record owner and epoch")
	}
}

func TestClaimRespectsBackoffSchedule(t *testing.T) {
	a := newAction(t)
	if err := a.Claim(lease, now); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	next := a.ScheduleRetry(now, 0.5)
	if !next.After(now) {
		t.Fatal("retry must be scheduled in the future")
	}
	if err := a.Claim(lease, now.Add(time.Millisecond)); err == nil {
		t.Fatal("claim before the scheduled time must be refused")
	}
	if err := a.Claim(lease, next.Add(time.Second)); err != nil {
		t.Fatalf("claim after the scheduled time must succeed: %v", err)
	}
}

func TestStaleCompletionCannotMarkNewerGenerationReady(t *testing.T) {
	a := newAction(t)
	if err := a.Claim(lease, now); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	// The environment moved to generation 8 while this action was in flight.
	err := a.AcceptResult(lease, 8, StateSucceeded, nil, now)
	if !errors.Is(err, ErrFenced) {
		t.Fatalf("a completion for a newer generation must be refused, got %v", err)
	}
	if a.State == StateSucceeded {
		t.Fatal("a stale completion must not mark the action succeeded")
	}
}

func TestStaleEpochCannotCommit(t *testing.T) {
	a := newAction(t)
	if err := a.Claim(lease, now); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	stale := Lease{Owner: "controller-a", Epoch: 2}
	if err := a.AcceptResult(stale, 7, StateSucceeded, nil, now); !errors.Is(err, ErrFenced) {
		t.Fatalf("a stale epoch must be refused, got %v", err)
	}
}

func TestDifferentOwnerCannotCommit(t *testing.T) {
	a := newAction(t)
	if err := a.Claim(lease, now); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	other := Lease{Owner: "controller-b", Epoch: 3}
	if err := a.AcceptResult(other, 7, StateSucceeded, nil, now); !errors.Is(err, ErrFenced) {
		t.Fatalf("a different owner must be refused, got %v", err)
	}
}

func TestCorrectLeaseCommits(t *testing.T) {
	a := newAction(t)
	if err := a.Claim(lease, now); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	ref := map[string]string{"opaque": "provider-handle-1"}
	if err := a.AcceptResult(lease, 7, StateSucceeded, ref, now); err != nil {
		t.Fatalf("matching fence must commit: %v", err)
	}
	if a.State != StateSucceeded {
		t.Fatalf("expected succeeded, got %s", a.State)
	}
	if a.ExternalRef["opaque"] != "provider-handle-1" {
		t.Fatal("provider reference must be recorded")
	}
}

func TestTimeoutBecomesUncertainNotFailed(t *testing.T) {
	// This is the central rule: failure to receive a response is not proof that
	// creation failed.
	a := newAction(t)
	if err := a.Claim(lease, now); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := a.MarkUncertain(lease, 7, "read timeout", now.Add(time.Minute), now); err != nil {
		t.Fatalf("MarkUncertain: %v", err)
	}
	if a.State != StateUncertain {
		t.Fatalf("timeout must yield uncertain, got %s", a.State)
	}
	if a.State == StateFailed {
		t.Fatal("a timeout must never be recorded as a definitive failure")
	}
}

func TestUncertainActionCannotBeReclaimedWithoutObservation(t *testing.T) {
	// Blind retry of an uncertain create can duplicate a resource that already
	// exists, so claiming is refused until it is observed.
	a := newAction(t)
	_ = a.Claim(lease, now)
	_ = a.MarkUncertain(lease, 7, "read timeout", time.Time{}, now)
	if !a.NeedsObservation() {
		t.Fatal("action must require observation")
	}
	if err := a.Claim(lease, now.Add(time.Hour)); err == nil {
		t.Fatal("an uncertain action must not be claimable before observation")
	}
}

func TestObservationFindingExistenceMeansItSucceeded(t *testing.T) {
	a := newAction(t)
	_ = a.Claim(lease, now)
	_ = a.MarkUncertain(lease, 7, "read timeout", time.Time{}, now)

	obs := Observe{Existed: true, Reference: map[string]string{"opaque": "provider-handle-9"}}
	if err := a.ResolveUncertain(obs, now); err != nil {
		t.Fatalf("ResolveUncertain: %v", err)
	}
	if a.State != StateSucceeded {
		t.Fatalf("an existing resource means the call succeeded, got %s", a.State)
	}
	if a.ExternalRef["opaque"] != "provider-handle-9" {
		t.Fatal("observed ownership reference must be recorded")
	}
}

func TestObservationFindingAbsenceMeansRetryIsSafe(t *testing.T) {
	a := newAction(t)
	_ = a.Claim(lease, now)
	_ = a.MarkUncertain(lease, 7, "read timeout", time.Time{}, now)

	obs := Observe{Existed: false, Gone: true, Reason: "absent in account and region"}
	if err := a.ResolveUncertain(obs, now); err != nil {
		t.Fatalf("ResolveUncertain: %v", err)
	}
	// Verified absence returns the action to planned, not to a terminal failure:
	// the observation that made a retry safe must not also prevent it.
	if a.State != StatePlanned {
		t.Fatalf("verified absence should return to planned, got %s", a.State)
	}
	if err := a.Claim(lease, now.Add(time.Hour)); err != nil {
		t.Fatalf("a verified-absent action may be retried: %v", err)
	}
}

func TestUnresolvedObservationKeepsActionUncertain(t *testing.T) {
	// Staying uncertain is correct. Guessing absence would risk a duplicate or
	// an orphaned resource.
	a := newAction(t)
	_ = a.Claim(lease, now)
	_ = a.MarkUncertain(lease, 7, "read timeout", time.Time{}, now)

	obs := Observe{Existed: false, Gone: false, Reason: "permission denied; not absence"}
	err := a.ResolveUncertain(obs, now)
	if !errors.Is(err, ErrUnresolvedObservation) {
		t.Fatalf("expected ErrUnresolvedObservation, got %v", err)
	}
	if a.State != StateUncertain {
		t.Fatalf("a permission failure is not absence; state must remain uncertain, got %s", a.State)
	}
}

func TestTerminalActionsAreImmutable(t *testing.T) {
	a := newAction(t)
	_ = a.Claim(lease, now)
	if err := a.AcceptResult(lease, 7, StateSucceeded, nil, now); err != nil {
		t.Fatalf("AcceptResult: %v", err)
	}
	if !a.State.Terminal() {
		t.Fatal("succeeded must be terminal")
	}
	if err := a.Claim(lease, now.Add(time.Hour)); !errors.Is(err, ErrTerminal) {
		t.Fatalf("a terminal action must not be reclaimed, got %v", err)
	}
	before := a.NextAttemptAt
	after := a.ScheduleRetry(now.Add(time.Hour), 0.5)
	if !after.Equal(before) {
		t.Fatalf("a terminal action must not be rescheduled: %v -> %v", before, after)
	}
}

func TestOnlyTerminalStatesMayBeCommittedAsResults(t *testing.T) {
	a := newAction(t)
	_ = a.Claim(lease, now)
	if err := a.AcceptResult(lease, 7, StateRunning, nil, now); err == nil {
		t.Fatal("running is not a committable result")
	}
	if err := a.AcceptResult(lease, 7, StateUncertain, nil, now); err == nil {
		t.Fatal("uncertain must be recorded via MarkUncertain, not as a result")
	}
}

func TestBackoffIsBoundedAndJittered(t *testing.T) {
	a := newAction(t)
	var last time.Duration
	for i := 1; i <= 12; i++ {
		a.Attempts = i
		lo := a.ScheduleRetry(now, 0)
		hi := a.ScheduleRetry(now, 1)
		if lo.After(hi) {
			t.Fatalf("attempt %d: low jitter %v must not exceed high jitter %v", i, lo.Sub(now), hi.Sub(now))
		}
		d := hi.Sub(now)
		if d > BackoffCeiling {
			t.Fatalf("attempt %d: backoff %v exceeds ceiling %v", i, d, BackoffCeiling)
		}
		last = d
	}
	if last == 0 {
		t.Fatal("backoff must be positive")
	}
}

func TestGenerationIsPartOfTheFence(t *testing.T) {
	a := newAction(t)
	if a.Generation != a.Fencing.ExpectedGeneration {
		t.Fatal("expected generation must be initialised from the action generation")
	}
	_ = a.Claim(lease, now)
	// Even with a correct owner and epoch, the generation must match.
	if err := a.AcceptResult(lease, a.Generation+1, StateSucceeded, nil, now); !errors.Is(err, ErrFenced) {
		t.Fatalf("generation mismatch must be refused, got %v", err)
	}
}
