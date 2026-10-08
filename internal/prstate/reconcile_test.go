package prstate_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/prstate"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

const (
	headV1 = "1111111111111111111111111111111111111111"
	headV2 = "2222222222222222222222222222222222222222"
	headV3 = "3333333333333333333333333333333333333333"
)

// lookup is a fixed authenticated-source snapshot.
type lookup struct {
	snap prstate.Snapshot
	err  error
}

func (l lookup) CurrentPullRequest(context.Context, string, int) (prstate.Snapshot, error) {
	return l.snap, l.err
}

func openSnapshot(head string) prstate.Snapshot {
	return prstate.Snapshot{
		RepositoryRef: "repo/acme/app",
		Number:        142,
		State:         prstate.StateOpen,
		HeadSHA:       head,
		BaseSHA:       "aaaa",
		ObservedAt:    now,
	}
}

func reconcile(t *testing.T, snap prstate.Snapshot, e prstate.Event, binding *prstate.EnvironmentBinding) prstate.Decisions {
	t.Helper()
	r := prstate.NewReconciler(lookup{snap: snap})
	d, err := r.Reconcile(context.Background(), e, binding, now)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return d
}

func TestFirstEventCreatesEnvironment(t *testing.T) {
	d := reconcile(t, openSnapshot(headV1),
		prstate.Event{RepositoryRef: "repo/acme/app", Number: 142, HeadSHA: headV1, Action: "opened"},
		nil)
	if d.Action != prstate.ActionCreate {
		t.Fatalf("expected create with no binding, got %s", d.Action)
	}
	if d.Reason == "" {
		t.Fatal("a decision must carry a reason")
	}
}

// TestDestroyedEnvironmentIsNotResurrected is the rule this package exists for.
func TestDestroyedEnvironmentIsNotResurrected(t *testing.T) {
	// A reopened or synchronize event arrives after teardown completed.
	d := reconcile(t, openSnapshot(headV2),
		prstate.Event{RepositoryRef: "repo/acme/app", Number: 142, HeadSHA: headV2, Action: "reopened"},
		&prstate.EnvironmentBinding{
			EnvironmentID: "env-01HQ",
			Generation:    1,
			Destroyed:     true,
			Slug:          "pr-142-a7d32c",
		})

	if d.Action != prstate.ActionCreate {
		t.Fatalf("a destroyed environment must produce a new environment, got %s", d.Action)
	}
	if !strings.Contains(d.Reason, "terminal") {
		t.Fatalf("the reason must state that the identifier is terminal, got %q", d.Reason)
	}
	if strings.Contains(d.Reason, headV2[:8]) {
		t.Fatal("the reason should reference the identity, not the candidate")
	}
}

func TestLiveEnvironmentTakesANewGeneration(t *testing.T) {
	d := reconcile(t, openSnapshot(headV2),
		prstate.Event{RepositoryRef: "repo/acme/app", Number: 142, HeadSHA: headV2, Action: "synchronize"},
		&prstate.EnvironmentBinding{EnvironmentID: "env-01HQ", Generation: 1})
	if d.Action != prstate.ActionUpdate {
		t.Fatalf("a live environment with a new head must update, got %s", d.Action)
	}
	if !strings.Contains(d.Reason, "generation 1") {
		t.Fatalf("the reason should name the current generation, got %q", d.Reason)
	}
}

// TestStaleEventIsIgnored is the out-of-order delivery case. Arrival order is not
// authoritative, so an event describing an older head must not produce a candidate.
func TestStaleEventIsIgnored(t *testing.T) {
	d := reconcile(t, openSnapshot(headV3),
		prstate.Event{RepositoryRef: "repo/acme/app", Number: 142, HeadSHA: headV1, Action: "synchronize"},
		&prstate.EnvironmentBinding{EnvironmentID: "env-01HQ", Generation: 2})

	if !d.StaleEvent {
		t.Fatal("an event describing a non-current head must be recognised as stale")
	}
	if d.Action != prstate.ActionNone {
		t.Fatalf("a stale event must cause no lifecycle change, got %s", d.Action)
	}
	if !strings.Contains(d.Reason, "not current") {
		t.Fatalf("the reason must explain staleness, got %q", d.Reason)
	}
}

func TestClosedPullRequestTearsDown(t *testing.T) {
	snap := openSnapshot(headV1)
	snap.State = prstate.StateClosed

	d := reconcile(t, snap,
		prstate.Event{RepositoryRef: "repo/acme/app", Number: 142, HeadSHA: headV1, Action: "closed"},
		&prstate.EnvironmentBinding{EnvironmentID: "env-01HQ", Generation: 1})
	if d.Action != prstate.ActionTeardown {
		t.Fatalf("a closed pull request must tear down, got %s", d.Action)
	}
}

func TestMergedPullRequestAlsoTearsDown(t *testing.T) {
	snap := openSnapshot(headV1)
	snap.State = prstate.StateMerged
	d := reconcile(t, snap,
		prstate.Event{RepositoryRef: "repo/acme/app", Number: 142, Action: "closed"},
		&prstate.EnvironmentBinding{EnvironmentID: "env-01HQ", Generation: 1})
	if d.Action != prstate.ActionTeardown {
		t.Fatalf("a merged pull request must tear down, got %s", d.Action)
	}
}

// TestCloseWinsEvenIfEventClaimsOpen is the priority rule: resolved state decides,
// not the event's claim.
func TestCloseWinsEvenIfEventClaimsOpen(t *testing.T) {
	snap := openSnapshot(headV1)
	snap.State = prstate.StateClosed
	d := reconcile(t, snap,
		prstate.Event{RepositoryRef: "repo/acme/app", Number: 142, HeadSHA: headV1, Action: "reopened"},
		&prstate.EnvironmentBinding{EnvironmentID: "env-01HQ", Generation: 1})
	if d.Action != prstate.ActionTeardown {
		t.Fatalf("resolved closed state must win over a reopened claim, got %s", d.Action)
	}
}

// TestUnresolvableStateCausesNoChange is the safety property: when the provider
// cannot be reached, a verified event must not drive a lifecycle change on the
// strength of its own claims.
func TestUnresolvableStateCausesNoChange(t *testing.T) {
	r := prstate.NewReconciler(lookup{err: errors.New("provider unreachable")})
	d, err := r.Reconcile(context.Background(),
		prstate.Event{RepositoryRef: "repo/acme/app", Number: 142, HeadSHA: headV2, Action: "synchronize"},
		&prstate.EnvironmentBinding{EnvironmentID: "env-01HQ", Generation: 1}, now)
	if err == nil {
		t.Fatal("a lookup failure must be reported")
	}
	if d.Action != prstate.ActionNone {
		t.Fatalf("an unresolvable state must cause no change, got %s", d.Action)
	}
	if d.Resolved {
		t.Fatal("a failed lookup must not report as resolved")
	}
	if d.Reason == "" {
		t.Fatal("the decision must explain why nothing happened")
	}
}

func TestEventWithoutHeadIsNotTreatedAsStale(t *testing.T) {
	// Not every event carries a head. Absence is not staleness.
	d := reconcile(t, openSnapshot(headV2),
		prstate.Event{RepositoryRef: "repo/acme/app", Number: 142, Action: "labeled"},
		&prstate.EnvironmentBinding{EnvironmentID: "env-01HQ", Generation: 1})
	if d.StaleEvent {
		t.Fatal("an event with no head must not be called stale")
	}
}

func TestSnapshotObservationTimeIsCarried(t *testing.T) {
	// The observation time is what lets a later comparison distinguish a stale
	// delivery from a current one without relying on arrival order.
	snap := openSnapshot(headV2)
	snap.ObservedAt = now.Add(-time.Minute)

	r := prstate.NewReconciler(lookup{snap: snap})
	d, err := r.Reconcile(context.Background(),
		prstate.Event{RepositoryRef: "repo/acme/app", Number: 142, HeadSHA: headV1},
		&prstate.EnvironmentBinding{EnvironmentID: "env-01HQ", Generation: 1}, now)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !d.Snapshot.ObservedAt.Equal(snap.ObservedAt) {
		t.Fatal("the observation time must be carried into the decision")
	}
	if !d.StaleEvent {
		t.Fatal("a recent snapshot makes the older event stale")
	}
}

// TestAncientSnapshotDefersToEvent covers the tolerance window: if the lookup
// itself is very old, its head cannot be used to reject a newer event.
func TestAncientSnapshotDefersToEvent(t *testing.T) {
	snap := openSnapshot(headV1)
	snap.ObservedAt = now.Add(-24 * time.Hour)

	r := prstate.NewReconciler(lookup{snap: snap})
	d, err := r.Reconcile(context.Background(),
		prstate.Event{RepositoryRef: "repo/acme/app", Number: 142, HeadSHA: headV2, Action: "synchronize"},
		&prstate.EnvironmentBinding{EnvironmentID: "env-01HQ", Generation: 1}, now)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if d.StaleEvent {
		t.Fatal("a day-old snapshot must not be used to reject a newer event")
	}
	if d.Action != prstate.ActionUpdate {
		t.Fatalf("expected update, got %s", d.Action)
	}
}

func TestEveryDecisionCarriesAReason(t *testing.T) {
	// An unexplained decision is undiagnosable in production.
	binding := &prstate.EnvironmentBinding{EnvironmentID: "env-01HQ", Generation: 1}
	destroyed := &prstate.EnvironmentBinding{EnvironmentID: "env-01HQ", Generation: 1, Destroyed: true}

	cases := []struct {
		name    string
		snap    prstate.Snapshot
		event   prstate.Event
		binding *prstate.EnvironmentBinding
	}{
		{"create", openSnapshot(headV1), prstate.Event{HeadSHA: headV1}, nil},
		{"update", openSnapshot(headV2), prstate.Event{HeadSHA: headV2}, binding},
		{"stale", openSnapshot(headV3), prstate.Event{HeadSHA: headV1}, binding},
		{"teardown", prstate.Snapshot{State: prstate.StateClosed, HeadSHA: headV1, ObservedAt: now}, prstate.Event{HeadSHA: headV1}, binding},
		{"resurrect", openSnapshot(headV2), prstate.Event{HeadSHA: headV2}, destroyed},
	}
	for _, c := range cases {
		d := reconcile(t, c.snap, c.event, c.binding)
		if strings.TrimSpace(d.Reason) == "" {
			t.Errorf("%s: decision %s has no reason", c.name, d.Action)
		}
		if d.Action == "" {
			t.Errorf("%s: decision has no action", c.name)
		}
	}
}

func TestShortHashesDoNotPanic(t *testing.T) {
	r := prstate.NewReconciler(lookup{snap: prstate.Snapshot{
		State: prstate.StateOpen, HeadSHA: "abc", ObservedAt: now,
	}})
	d, err := r.Reconcile(context.Background(),
		prstate.Event{HeadSHA: "abcdef"}, nil, now)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if strings.Contains(d.Reason, "abcdef") && len(d.Reason) == 0 {
		t.Fatal("reason formatting must handle short hashes")
	}
}
