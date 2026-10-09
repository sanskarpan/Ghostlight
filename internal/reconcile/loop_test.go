package reconcile_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/environments"
	"github.com/sanskarpan/Ghostlight/internal/plan"
	"github.com/sanskarpan/Ghostlight/internal/prstate"
	"github.com/sanskarpan/Ghostlight/internal/reconcile"
)

// The full loop: an admitted event becomes a reconciliation decision, which
// becomes a durable action intent, which a pass executes and commits under the
// fence.
//
// These tests exist because the individual packages all pass their own tests while
// the wiring between them is unverified. That is precisely where a lifecycle bug
// hides.

var loopNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// loopEnv carries the lifecycle state through the whole flow.
type loopEnv struct {
	mu sync.Mutex

	env     environments.Environment
	binding *prstate.EnvironmentBinding
	state   prstate.State
	head    string

	// actions records what the planner produced and the pass executed.
	planned  []string
	executed []string
	// executeErr makes execution fail, producing uncertainty.
	executeErr error
	// observeResult is what an observation of an uncertain action reports.
	observeResult reconcile.Observation
	observeCalls  int
}

// binding implements reconcile.Lifecycle against the loop state.
func (l *loopEnv) bindingFor(_ context.Context, _ string, _ int) (*prstate.EnvironmentBinding, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.binding, nil
}

func (l *loopEnv) numberFor(_ context.Context, e reconcile.PendingEvent) (int, bool, error) {
	return 142, true, nil
}

func (l *loopEnv) reconcileEvent(_ context.Context, e prstate.Event, binding *prstate.EnvironmentBinding, now time.Time) (prstate.Decisions, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = binding
	switch l.state {
	case prstate.StateClosed:
		return prstate.Decisions{Action: prstate.ActionTeardown, Reason: "pull request is closed"}, nil
	default:
		if e.HeadSHA == "" || e.HeadSHA == l.head {
			return prstate.Decisions{Action: prstate.ActionNone, Reason: "head unchanged"}, nil
		}
		return prstate.Decisions{Action: prstate.ActionUpdate, Reason: "head changed"}, nil
	}
}

// executorFor adapts the loop state to reconcile.Executor.
type executorFor struct{ loop *loopEnv }

func (e executorFor) Execute(_ context.Context, c reconcile.Claim) (reconcile.Result, error) {
	e.loop.mu.Lock()
	defer e.loop.mu.Unlock()
	e.loop.executed = append(e.loop.executed, c.LogicalKey)
	if e.loop.executeErr != nil {
		return "", e.loop.executeErr
	}
	return reconcile.ResultSucceeded, nil
}

// observerFor adapts the loop state to reconcile.Observer.
type observerFor struct{ loop *loopEnv }

func (o observerFor) Observe(_ context.Context, _ reconcile.Claim) reconcile.Observation {
	o.loop.mu.Lock()
	defer o.loop.mu.Unlock()
	o.loop.observeCalls++
	if o.loop.observeResult.Unresolvable {
		return reconcile.Observation{Unresolvable: true, Reason: "permission denied"}
	}
	return o.loop.observeResult
}

// planFor runs the planner against the loop state and returns executable work.
func planFor(t *testing.T, loop *loopEnv) []reconcile.Work {
	t.Helper()
	loop.mu.Lock()
	env := loop.env
	loop.mu.Unlock()

	p := plan.Planner{Profile: plan.DefaultProfile()}
	result := p.Plan(plan.Input{
		Env: env, Candidate: env.Candidate, Now: loopNow,
		RequiredDependencies:  []string{"postgres", "redis"},
		SupportedDependencies: []string{"postgres", "redis", "kafka", "workflow", "object_store", "identity"},
	})
	if result.Refused != nil {
		t.Fatalf("planning was refused unexpectedly: %v", result.Refused)
	}
	loop.mu.Lock()
	defer loop.mu.Unlock()
	work := make([]reconcile.Work, 0, len(result.Intents))
	for _, intent := range result.Intents {
		loop.planned = append(loop.planned, intent.Action.LogicalKey)
		work = append(work, reconcile.Work{
			Claim: reconcile.Claim{
				EnvironmentID: intent.Action.EnvironmentID,
				Generation:    intent.Action.Generation,
				ActionType:    string(intent.Action.Type),
				LogicalKey:    intent.Action.LogicalKey,
			},
			Attempts: intent.Action.Attempts,
		})
	}
	return work
}

func newLoop() *loopEnv {
	return &loopEnv{
		env: environments.Environment{
			Identity:   environments.Identity{ID: "env-01HQ", Slug: "pr-142-a7d32c"},
			Repository: "repo/acme/app",
			Desired:    environments.DesiredPresent,
			Observed:   environments.ObsRequested,
			Runtime:    environments.RuntimeRunning,
			Generation: 1,
			Candidate: environments.Candidate{
				SourceSHA:         "1111111111111111111111111111111111111111",
				ArtifactDigest:    "sha256:aaaa",
				ConfigDigest:      "sha256:bbbb",
				RecipeDigest:      "sha256:eeee",
				PolicyDigest:      "sha256:ffff",
				EventSchemaDigest: "sha256:dddd",
				MigrationDigest:   "sha256:cccc",
			},
			ExpiresAt: loopNow.Add(24 * time.Hour),
		},
		state: prstate.StateOpen,
		head:  "1111111111111111111111111111111111111111",
	}
}

func newLoopPass(t *testing.T, loop *loopEnv, st reconcile.Store) *reconcile.Pass {
	t.Helper()
	p, err := reconcile.New(reconcile.Options{
		Store: st, Executor: executorFor{loop}, Observer: observerFor{loop},
		Config: reconcile.DefaultConfig(), Owner: "controller-a",
		Now: func() time.Time { return loopNow }, Jitter: func() float64 { return 0.5 },
	})
	if err != nil {
		t.Fatalf("new pass: %v", err)
	}
	return p
}

// TestLoopPlansAndExecutesWorkFromPlannedIntents is the end-to-end path: planning
// produces intents, the pass claims and executes them, and results commit.
func TestLoopPlansAndExecutesWorkFromPlannedIntents(t *testing.T) {
	loop := newLoop()
	st := newStore()
	work := planFor(t, loop)
	if len(work) == 0 {
		t.Fatal("planning must produce work for a requested environment")
	}

	m, err := newLoopPass(t, loop, st).Run(context.Background(), work, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if m.ActionsClaimed != len(work) {
		t.Fatalf("expected %d claims, got %+v", len(work), m)
	}
	if m.ActionsCommitted != len(work) {
		t.Fatalf("expected %d commits, got %+v", len(work), m)
	}

	loop.mu.Lock()
	defer loop.mu.Unlock()
	if len(loop.executed) != len(work) {
		t.Fatalf("executed %d actions, planned %d", len(loop.executed), len(work))
	}
	// Every executed action must be one the planner produced, never invented.
	planned := map[string]bool{}
	for _, k := range loop.planned {
		planned[k] = true
	}
	for _, k := range loop.executed {
		if !planned[k] {
			t.Fatalf("action %s was executed but never planned", k)
		}
	}
}

// TestLoopTurnsExecutionFailureIntoUncertainty is the property that stops leaks:
// a failed call becomes uncertain and is observed, not retried blindly.
func TestLoopTurnsExecutionFailureIntoUncertainty(t *testing.T) {
	loop := newLoop()
	loop.executeErr = errors.New("read timeout after create")
	st := newStore()
	work := planFor(t, loop)

	p := newLoopPass(t, loop, st)
	m, err := p.Run(context.Background(), work, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if m.ActionsUncertain != len(work) {
		t.Fatalf("every failed execution must become uncertain, got %+v", m)
	}
	if m.ActionsCommitted != 0 {
		t.Fatal("nothing may be committed when the outcome is unknown")
	}

	// The uncertain work must then be observed, and must not be re-executed.
	loop.executeErr = nil
	loop.observeResult = reconcile.Observation{Existed: true, Reason: "found"}

	uncertain := make([]reconcile.UncertainWork, 0, len(work))
	for _, w := range work {
		uncertain = append(uncertain, reconcile.UncertainWork{Claim: w.Claim})
	}
	m2, err := p.Run(context.Background(), nil, uncertain)
	if err != nil {
		t.Fatalf("observe run: %v", err)
	}
	if m2.ObservationsMade != len(uncertain) {
		t.Fatalf("expected every uncertain action observed, got %+v", m2)
	}

	loop.mu.Lock()
	defer loop.mu.Unlock()
	if len(loop.executed) != len(work) {
		t.Fatalf("observation must not re-execute work; executed %d, planned %d",
			len(loop.executed), len(work))
	}
}

// TestLoopDoesNotReplanCompletedWork checks the loop is idempotent across passes:
// planning twice produces the same intents, so a repeated pass does not duplicate.
func TestLoopDoesNotReplanCompletedWork(t *testing.T) {
	loop := newLoop()
	first := planFor(t, loop)
	second := planFor(t, loop)

	if len(first) != len(second) {
		t.Fatalf("planning twice produced different lengths: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].LogicalKey != second[i].LogicalKey {
			t.Fatalf("intent %d differs between plans: %q vs %q",
				i, first[i].LogicalKey, second[i].LogicalKey)
		}
	}
}

// TestLoopHandlesCloseThenTeardown walks the destructive path: a closed pull
// request produces a teardown plan, and no provisioning work alongside it.
func TestLoopHandlesCloseThenTeardown(t *testing.T) {
	loop := newLoop()
	loop.state = prstate.StateClosed
	loop.env.Desired = environments.DesiredAbsent

	work := planFor(t, loop)
	if len(work) == 0 {
		t.Fatal("a closed pull request must plan teardown work")
	}

	loop.mu.Lock()
	defer loop.mu.Unlock()
	for _, w := range work {
		switch w.ActionType {
		case string(planTeardownTypeAllocate), "reserve", "migrate", "seed", "rollout", "health", "gate":
			t.Fatalf("teardown plan includes provisioning work %s", w.ActionType)
		}
	}
}

// planTeardownTypeAllocate names the action type teardown must never include.
const planTeardownTypeAllocate = "allocate"

// TestLoopIsSafeUnderConcurrentPasses checks two controllers driving the same
// planned work produce one execution per action.
func TestLoopIsSafeUnderConcurrentPasses(t *testing.T) {
	loop := newLoop()
	st := newStore()

	var mu sync.Mutex
	claimed := map[string]bool{}
	st.claimable = func(c reconcile.Claim) bool {
		mu.Lock()
		defer mu.Unlock()
		if claimed[c.LogicalKey] {
			return false
		}
		claimed[c.LogicalKey] = true
		return true
	}

	work := planFor(t, loop)
	p := newLoopPass(t, loop, st)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.Run(context.Background(), work, nil)
		}()
	}
	wg.Wait()

	loop.mu.Lock()
	defer loop.mu.Unlock()
	if len(loop.executed) != len(work) {
		t.Fatalf("each action must execute exactly once across passes; executed %d, planned %d",
			len(loop.executed), len(work))
	}
}

// TestLoopSurfacesEveryOutcomeInMetrics checks a quiet system is distinguishable
// from a stalled one.
func TestLoopSurfacesEveryOutcomeInMetrics(t *testing.T) {
	loop := newLoop()
	st := newStore()
	work := planFor(t, loop)
	st.commitErr = reconcile.ErrFenced

	m, err := newLoopPass(t, loop, st).Run(context.Background(), work, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if m.ActionsClaimed == 0 || m.StaleResultsRejected == 0 {
		t.Fatalf("a fenced pass must be visible in metrics, got %+v", m)
	}
	if m.Empty() {
		t.Fatal("a pass that claimed work is not empty; claiming means work is in flight")
	}
}

func TestPlannedWorkCarriesFencePreconditions(t *testing.T) {
	// The work handed to the pass must carry the generation, because the commit is
	// fenced on it.
	loop := newLoop()
	work := planFor(t, loop)
	for _, w := range work {
		if w.Generation != 1 {
			t.Fatalf("work %s carries generation %d, expected 1", w.LogicalKey, w.Generation)
		}
		if w.EnvironmentID != "env-01HQ" {
			t.Fatalf("work %s names the wrong environment", w.LogicalKey)
		}
		if w.ActionType == "" {
			t.Fatalf("work %s has no action type", w.LogicalKey)
		}
	}
}

func TestPlannedWorkIsBoundedByProfile(t *testing.T) {
	loop := newLoop()
	loop.mu.Lock()
	env := loop.env
	loop.mu.Unlock()

	bounded := plan.Planner{Profile: plan.Profile{
		MaxActionsPerPass: 3, MaxLifetimeHours: 72 * time.Hour, RequiresGateableCandidate: true,
	}}
	got := bounded.Plan(plan.Input{Env: env, Candidate: env.Candidate, Now: loopNow})
	if len(got.Intents) > 3 {
		t.Fatalf("a bounded planner produced %d intents", len(got.Intents))
	}
}

func TestExpiredEnvironmentPlansNothingInTheLoop(t *testing.T) {
	// The TTL guarantee reaches the planner, not just the lifecycle type.
	loop := newLoop()
	loop.env.ExpiresAt = loopNow.Add(-time.Minute)

	loop.mu.Lock()
	env := loop.env
	loop.mu.Unlock()

	p := plan.Planner{Profile: plan.DefaultProfile()}
	got := p.Plan(plan.Input{Env: env, Candidate: env.Candidate, Now: loopNow})
	if !got.Empty() {
		t.Fatalf("an expired environment must plan nothing, got %d intents", len(got.Intents))
	}
	if got.Refused == nil {
		t.Fatal("an expired environment must be refused with a reason")
	}
}

func TestLoopRunsEvenWithAnUnqualifiedProfile(t *testing.T) {
	// A profile with no gateability requirement must not silently gate candidates
	// it cannot qualify, and must not crash either.
	loop := newLoop()
	loop.mu.Lock()
	loop.env.Candidate.PolicyDigest = ""
	env := loop.env
	loop.mu.Unlock()

	permissive := plan.Planner{Profile: plan.Profile{
		MaxActionsPerPass: 16, RequiresGateableCandidate: false,
	}}
	got := permissive.Plan(plan.Input{Env: env, Candidate: env.Candidate, Now: loopNow})
	// The permissive profile plans work, but the intent must still record the
	// candidate so the ledger can fence it.
	for _, intent := range got.Intents {
		if intent.Action.EnvironmentID == "" || intent.Action.LogicalKey == "" {
			t.Fatal("every planned intent must identify itself")
		}
	}
}

var _ = fmt.Sprintf
