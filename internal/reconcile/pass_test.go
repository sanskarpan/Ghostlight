package reconcile_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/reconcile"
)

var passNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// fakeStore records what the pass did and can be made to fail or fence.
type fakeStore struct {
	mu sync.Mutex

	claimed      []reconcile.Claim
	committed    []reconcile.Claim
	uncertain    []reconcile.Claim
	resolved     []reconcile.Observation
	commitErr    error
	uncertainErr error

	// claimable decides whether a claim succeeds. An action already held by
	// another owner returns false.
	claimable func(reconcile.Claim) bool
}

func newStore() *fakeStore { return &fakeStore{} }

func (f *fakeStore) ClaimAction(_ context.Context, envID string, gen uint64, actionType, logicalKey, owner string) (reconcile.Claim, error) {
	c := reconcile.Claim{
		EnvironmentID: envID, Generation: gen, Owner: owner, Epoch: 1,
		ActionType: actionType, LogicalKey: logicalKey,
	}
	if f.claimable != nil && !f.claimable(c) {
		return reconcile.Claim{}, errors.New("already claimed")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claimed = append(f.claimed, c)
	return c, nil
}

func (f *fakeStore) CommitResult(_ context.Context, c reconcile.Claim, _ reconcile.Result) error {
	if f.commitErr != nil {
		return f.commitErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.committed = append(f.committed, c)
	return nil
}

func (f *fakeStore) MarkUncertain(_ context.Context, c reconcile.Claim, _ string, _ time.Time) error {
	if f.uncertainErr != nil {
		return f.uncertainErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uncertain = append(f.uncertain, c)
	return nil
}

func (f *fakeStore) ResolveObservation(_ context.Context, _ string, _ uint64, obs reconcile.Observation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = append(f.resolved, obs)
	return nil
}

func (f *fakeStore) counts() (claimed, committed, uncertain, resolved int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.claimed), len(f.committed), len(f.uncertain), len(f.resolved)
}

// executor returns a scripted outcome per logical key.
type executor struct {
	mu       sync.Mutex
	results  map[string]reconcile.Result
	errs     map[string]error
	calls    []string
	blocking chan struct{}
}

func newExecutor() *executor {
	return &executor{results: map[string]reconcile.Result{}, errs: map[string]error{}}
}

func (e *executor) Execute(ctx context.Context, c reconcile.Claim) (reconcile.Result, error) {
	if e.blocking != nil {
		<-e.blocking
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, c.LogicalKey)
	if err, ok := e.errs[c.LogicalKey]; ok {
		return "", err
	}
	if r, ok := e.results[c.LogicalKey]; ok {
		return r, nil
	}
	return reconcile.ResultSucceeded, nil
}

func (e *executor) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.calls)
}

// observer returns scripted observations per logical key.
type observer struct {
	mu    sync.Mutex
	byKey map[string]reconcile.Observation
	calls []string
}

func newObserver() *observer {
	return &observer{byKey: map[string]reconcile.Observation{}}
}

func (o *observer) Observe(_ context.Context, c reconcile.Claim) reconcile.Observation {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, c.LogicalKey)
	if obs, ok := o.byKey[c.LogicalKey]; ok {
		return obs
	}
	return reconcile.Observation{Unresolvable: true, Reason: "no scripted observation"}
}

func (o *observer) callCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.calls)
}

// watchdog records expiry calls.
type watchdog struct {
	mu      sync.Mutex
	expired int
	err     error
	calls   int
}

func (w *watchdog) ExpireDue(context.Context, int) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	return w.expired, w.err
}

func (w *watchdog) callCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.calls
}

func work(key string, gen uint64) reconcile.Work {
	return reconcile.Work{Claim: reconcile.Claim{
		EnvironmentID: "env-01HQ", Generation: gen,
		ActionType: "allocate", LogicalKey: key,
	}}
}

func uncertain(key string, gen uint64) reconcile.UncertainWork {
	return reconcile.UncertainWork{Claim: reconcile.Claim{
		EnvironmentID: "env-01HQ", Generation: gen,
		ActionType: "allocate", LogicalKey: key,
	}}
}

func newPass(t *testing.T, s reconcile.Store, e reconcile.Executor, o reconcile.Observer, w reconcile.Watchdog, cfg reconcile.Config) *reconcile.Pass {
	t.Helper()
	p, err := reconcile.New(reconcile.Options{
		Store: s, Executor: e, Observer: o, Watchdog: w, Config: cfg,
		Owner:  "controller-a",
		Now:    func() time.Time { return passNow },
		Jitter: func() float64 { return 0.5 },
	})
	if err != nil {
		t.Fatalf("new pass: %v", err)
	}
	return p
}

func TestPassCommitsSuccessfulWork(t *testing.T) {
	st, ex, wd := newStore(), newExecutor(), &watchdog{}
	p := newPass(t, st, ex, nil, wd, reconcile.DefaultConfig())

	m, err := p.Run(context.Background(), []reconcile.Work{work("alloc-pg", 1)}, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if m.ActionsClaimed != 1 || m.ActionsCommitted != 1 {
		t.Fatalf("expected one claim and one commit, got %+v", m)
	}
	claimed, committed, uncertainCount, _ := st.counts()
	if claimed != 1 || committed != 1 || uncertainCount != 0 {
		t.Fatalf("store recorded claimed=%d committed=%d uncertain=%d", claimed, committed, uncertainCount)
	}
}

// TestExecutorErrorBecomesUncertainNotFailed is the central rule: a call whose
// outcome is unknown is not a failure, and treating it as one is how resources leak.
func TestExecutorErrorBecomesUncertainNotFailed(t *testing.T) {
	st, ex, wd := newStore(), newExecutor(), &watchdog{}
	ex.errs["alloc-pg"] = errors.New("read timeout after create")
	p := newPass(t, st, ex, nil, wd, reconcile.DefaultConfig())

	m, err := p.Run(context.Background(), []reconcile.Work{work("alloc-pg", 1)}, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if m.ActionsUncertain != 1 {
		t.Fatalf("an executor error must produce uncertainty, got %+v", m)
	}
	if m.ActionsCommitted != 0 {
		t.Fatal("an uncertain action must not be committed as a result")
	}
	_, committed, uncertainCount, _ := st.counts()
	if committed != 0 {
		t.Fatal("nothing may be committed when the outcome is unknown")
	}
	if uncertainCount != 1 {
		t.Fatalf("expected one uncertain action, got %d", uncertainCount)
	}
}

// TestFencedCommitIsCountedNotRetried is the property that stops duplicate work: the
// external effect happened, the ledger write did not, and retrying would redo it.
func TestFencedCommitIsCountedNotRetried(t *testing.T) {
	st, ex, wd := newStore(), newExecutor(), &watchdog{}
	st.commitErr = reconcile.ErrFenced
	p := newPass(t, st, ex, nil, wd, reconcile.DefaultConfig())

	m, err := p.Run(context.Background(), []reconcile.Work{work("alloc-pg", 1)}, nil)
	if err != nil {
		t.Fatalf("a fenced commit is expected and not a pass error: %v", err)
	}
	if m.StaleResultsRejected != 1 {
		t.Fatalf("a fenced commit must be counted, got %+v", m)
	}
	// It must NOT count as committed: the ledger never recorded the result, so
	// counting it would tell an operator work landed when it did not.
	if m.ActionsCommitted != 0 {
		t.Fatalf("a fenced commit must not count as committed, got %+v", m)
	}
	if ex.callCount() != 1 {
		t.Fatalf("the executor must be called exactly once, got %d", ex.callCount())
	}
}

func TestUnclaimableWorkIsSkippedWithoutError(t *testing.T) {
	// A busy fleet looks like this constantly. Not claiming is normal operation.
	st, ex, wd := newStore(), newExecutor(), &watchdog{}
	st.claimable = func(reconcile.Claim) bool { return false }
	p := newPass(t, st, ex, nil, wd, reconcile.DefaultConfig())

	m, err := p.Run(context.Background(), []reconcile.Work{work("alloc-pg", 1)}, nil)
	if err != nil {
		t.Fatalf("an unclaimable action must not be an error: %v", err)
	}
	if m.ActionsClaimed != 0 {
		t.Fatalf("nothing may be claimed, got %+v", m)
	}
	if ex.callCount() != 0 {
		t.Fatal("the executor must not run for an action this pass does not hold")
	}
}

// TestObservationRunsBeforeWork is the ordering guarantee: an unresolved uncertain
// action can leak a resource, so it outranks starting new work.
func TestObservationRunsBeforeWork(t *testing.T) {
	st, ex, ob, wd := newStore(), newExecutor(), newObserver(), &watchdog{}
	var order []string

	ob.byKey["alloc-old"] = reconcile.Observation{Existed: true, Reason: "found"}

	p := newPass(t, st, &orderExecutor{inner: ex, order: &order, label: "execute"},
		&orderObserver{inner: ob, order: &order, label: "observe"}, wd, reconcile.DefaultConfig())

	if _, err := p.Run(context.Background(),
		[]reconcile.Work{work("alloc-new", 1)},
		[]reconcile.UncertainWork{uncertain("alloc-old", 1)}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(order) < 2 {
		t.Fatalf("expected both stages to run, got %v", order)
	}
	if order[0] != "observe" {
		t.Fatalf("observation must run before work, got order %v", order)
	}
}

type orderExecutor struct {
	inner *executor
	order *[]string
	label string
}

func (o *orderExecutor) Execute(ctx context.Context, c reconcile.Claim) (reconcile.Result, error) {
	*o.order = append(*o.order, o.label)
	return o.inner.Execute(ctx, c)
}

type orderObserver struct {
	inner *observer
	order *[]string
	label string
}

func (o *orderObserver) Observe(ctx context.Context, c reconcile.Claim) reconcile.Observation {
	*o.order = append(*o.order, o.label)
	return o.inner.Observe(ctx, c)
}

// TestUnresolvableObservationLeavesActionUncertain is the safety property. Concluding
// absence from an inspection that could not complete causes a duplicate or a leak.
func TestUnresolvableObservationLeavesActionUncertain(t *testing.T) {
	st, ob, wd := newStore(), newObserver(), &watchdog{}
	ob.byKey["alloc-pg"] = reconcile.Observation{Unresolvable: true, Reason: "permission denied"}

	p := newPass(t, st, nil, ob, wd, reconcile.DefaultConfig())
	m, err := p.Run(context.Background(), nil, []reconcile.UncertainWork{uncertain("alloc-pg", 1)})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if m.ObservationsUnresolved != 1 {
		t.Fatalf("an unresolvable observation must be counted, got %+v", m)
	}
	if m.ActionsCommitted != 0 {
		t.Fatal("an unresolvable observation must not resolve the action")
	}
	if _, _, _, resolved := st.counts(); resolved != 0 {
		t.Fatal("nothing may be resolved from an unresolvable observation")
	}
}

func TestObservationFindingExistenceResolves(t *testing.T) {
	st, ob, wd := newStore(), newObserver(), &watchdog{}
	ob.byKey["alloc-pg"] = reconcile.Observation{Existed: true, Reason: "found"}

	p := newPass(t, st, nil, ob, wd, reconcile.DefaultConfig())
	m, err := p.Run(context.Background(), nil, []reconcile.UncertainWork{uncertain("alloc-pg", 1)})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if m.ActionsCommitted != 1 || m.ObservationsUnresolved != 0 {
		t.Fatalf("existence must resolve the action, got %+v", m)
	}
}

// TestExpiryRunsEvenWhenWorkFails is the safety ordering: a controller that cannot
// reach its provider must still expire environments.
func TestExpiryRunsEvenWhenWorkFails(t *testing.T) {
	st, ex, wd := newStore(), newExecutor(), &watchdog{}
	wd.expired = 3
	st.claimable = func(reconcile.Claim) bool { return false }
	st.commitErr = errors.New("commit unavailable")

	p := newPass(t, st, ex, nil, wd, reconcile.DefaultConfig())
	m, err := p.Run(context.Background(), []reconcile.Work{work("alloc-pg", 1)}, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if wd.callCount() == 0 {
		t.Fatal("expiry must run even when other stages do nothing useful")
	}
	if m.EnvironmentsExpired != 3 {
		t.Fatalf("expected 3 expiries, got %d", m.EnvironmentsExpired)
	}
}

// TestStageFailuresAreCollectedNotFatal checks one broken stage does not stop the
// others.
func TestStageFailuresAreCollectedNotFatal(t *testing.T) {
	st, ex, ob, wd := newStore(), newExecutor(), newObserver(), &watchdog{}
	wd.err = errors.New("watchdog unavailable")
	ob.byKey["alloc-old"] = reconcile.Observation{Existed: true}

	p := newPass(t, st, ex, ob, wd, reconcile.DefaultConfig())
	m, err := p.Run(context.Background(),
		[]reconcile.Work{work("alloc-new", 1)},
		[]reconcile.UncertainWork{uncertain("alloc-old", 1)})
	if err == nil {
		t.Fatal("a failing stage must be reported")
	}
	if !strings.Contains(err.Error(), "watchdog") {
		t.Fatalf("the failing stage must be named, got %v", err)
	}
	// The other stages still ran.
	if m.ActionsCommitted == 0 {
		t.Fatal("a watchdog failure must not prevent observation from resolving")
	}
}

func TestWatchdogErrorIsNamed(t *testing.T) {
	st, wd := newStore(), &watchdog{}
	wd.err = errors.New("provider unavailable")
	p := newPass(t, st, nil, nil, wd, reconcile.DefaultConfig())

	_, err := p.Run(context.Background(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "expire") {
		t.Fatalf("expected a named expiry failure, got %v", err)
	}
}

// TestClaimLimitBoundsOnePass stops a large backlog monopolising a controller.
func TestClaimLimitBoundsOnePass(t *testing.T) {
	st, ex, wd := newStore(), newExecutor(), &watchdog{}
	cfg := reconcile.DefaultConfig()
	cfg.ClaimLimit = 2
	p := newPass(t, st, ex, nil, wd, cfg)

	var batch []reconcile.Work
	for i := 0; i < 10; i++ {
		batch = append(batch, work(fmt.Sprintf("alloc-%d", i), 1))
	}
	m, err := p.Run(context.Background(), batch, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if m.ActionsClaimed != 2 {
		t.Fatalf("claim limit must bound the pass, claimed %d", m.ActionsClaimed)
	}
}

// TestObservationLimitCannotBeZero guards against starving uncertain work, which is
// the only state that can leak a resource.
func TestObservationLimitCannotBeZero(t *testing.T) {
	cfg := reconcile.DefaultConfig()
	cfg.ObservationLimit = 0
	st := newStore()
	if _, err := reconcile.New(reconcile.Options{Store: st, Owner: "c", Config: cfg}); err == nil {
		t.Fatal("a zero observation limit must be refused")
	}
}

func TestPassRequiresOwner(t *testing.T) {
	// An unattributed lease cannot be released or audited.
	st := newStore()
	_, err := reconcile.New(reconcile.Options{Store: st})
	if err == nil {
		t.Fatal("a pass without an owner must be refused")
	}
	if !strings.Contains(err.Error(), "owner") {
		t.Fatalf("the reason must name the missing owner, got %v", err)
	}
}

func TestPassRequiresStore(t *testing.T) {
	_, err := reconcile.New(reconcile.Options{Owner: "c"})
	if err == nil {
		t.Fatal("a pass without a store must be refused")
	}
}

func TestNonTerminalResultIsRejected(t *testing.T) {
	// An executor that returns a non-terminal result has not decided anything, and
	// committing it would record a decision that was never made.
	st, ex, wd := newStore(), newExecutor(), &watchdog{}
	ex.results["alloc-pg"] = reconcile.Result("running")

	p := newPass(t, st, ex, nil, wd, reconcile.DefaultConfig())
	_, err := p.Run(context.Background(), []reconcile.Work{work("alloc-pg", 1)}, nil)
	if err == nil || !strings.Contains(err.Error(), "non-terminal") {
		t.Fatalf("a non-terminal result must be rejected, got %v", err)
	}
	if _, committed, _, _ := st.counts(); committed != 0 {
		t.Fatal("a non-terminal result must not be committed")
	}
}

func TestTerminalResultClassification(t *testing.T) {
	terminal := []reconcile.Result{reconcile.ResultSucceeded, reconcile.ResultFailed, reconcile.ResultCanceled}
	for _, r := range terminal {
		if !r.Terminal() {
			t.Errorf("%s must be terminal", r)
		}
	}
	for _, r := range []reconcile.Result{"", "running", "uncertain", "planned"} {
		if r.Terminal() {
			t.Errorf("%q must not be terminal", r)
		}
	}
}

func TestPassIsIdleWithNoWork(t *testing.T) {
	st, ex, ob, wd := newStore(), newExecutor(), newObserver(), &watchdog{}
	p := newPass(t, st, ex, ob, wd, reconcile.DefaultConfig())

	m, err := p.Run(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !m.Empty() {
		t.Fatalf("a pass with no work must be empty, got %+v", m)
	}
	if ob.callCount() != 0 || ex.callCount() != 0 {
		t.Fatal("no stage may run work when there is none")
	}
}

func TestBackoffIsBoundedAndJittered(t *testing.T) {
	// A long-lived failure must not produce an unbounded delay.
	var observed []time.Duration
	st, ex := newStore(), newExecutor()
	ex.errs["alloc-pg"] = errors.New("always fails")
	capture := &captureStore{inner: st, delays: &observed}

	var store reconcile.Store = capture
	p, err := reconcile.New(reconcile.Options{
		Store: store, Executor: ex, Config: reconcile.DefaultConfig(),
		Owner:  "controller-a",
		Now:    func() time.Time { return passNow },
		Jitter: func() float64 { return 1.0 },
	})
	if err != nil {
		t.Fatalf("new pass: %v", err)
	}

	for i := 0; i < 30; i++ {
		if _, err := p.Run(context.Background(), []reconcile.Work{{
			Claim: reconcile.Claim{EnvironmentID: "env-1", Generation: 1,
				ActionType: "allocate", LogicalKey: "alloc-pg"},
			Attempts: i,
		}}, nil); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	for i, d := range observed {
		if d <= 0 {
			t.Fatalf("attempt %d: delay must be positive, got %v", i, d)
		}
		if d > reconcile.MaxBackoff {
			t.Fatalf("attempt %d: delay %v exceeds the ceiling %v", i, d, reconcile.MaxBackoff)
		}
	}
	if len(observed) < 30 {
		t.Fatalf("expected a delay per attempt, got %d", len(observed))
	}
}

type captureStore struct {
	inner  *fakeStore
	delays *[]time.Duration
	now    time.Time
}

func (c *captureStore) ClaimAction(ctx context.Context, envID string, gen uint64, actionType, logicalKey, owner string) (reconcile.Claim, error) {
	return c.inner.ClaimAction(ctx, envID, gen, actionType, logicalKey, owner)
}

func (c *captureStore) CommitResult(ctx context.Context, claim reconcile.Claim, r reconcile.Result) error {
	return c.inner.CommitResult(ctx, claim, r)
}

func (c *captureStore) MarkUncertain(_ context.Context, claim reconcile.Claim, _ string, next time.Time) error {
	*c.delays = append(*c.delays, next.Sub(passNow))
	return c.inner.MarkUncertain(context.Background(), claim, "", next)
}

func (c *captureStore) ResolveObservation(ctx context.Context, envID string, gen uint64, obs reconcile.Observation) error {
	return c.inner.ResolveObservation(ctx, envID, gen, obs)
}

// TestConcurrentPassesDoNotDoubleExecuteTwo controllers must not both run the same
// action. The store arbitrates the claim; this asserts the pass does not defeat it
// by executing work it failed to claim.
func TestConcurrentPassesDoNotDoubleExecute(t *testing.T) {
	st := newStore()
	claimed := map[string]bool{}
	var mu sync.Mutex

	st.claimable = func(c reconcile.Claim) bool {
		mu.Lock()
		defer mu.Unlock()
		if claimed[c.LogicalKey] {
			return false
		}
		claimed[c.LogicalKey] = true
		return true
	}

	var calls int
	var callMu sync.Mutex
	exec := &countingExecutor{calls: &calls, mu: &callMu}
	wd := &watchdog{}

	p := newPass(t, st, exec, nil, wd, reconcile.DefaultConfig())

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.Run(context.Background(), []reconcile.Work{work("alloc-pg", 1)}, nil)
		}()
	}
	wg.Wait()

	callMu.Lock()
	defer callMu.Unlock()
	if calls != 1 {
		t.Fatalf("an action may be executed once across concurrent passes, got %d", calls)
	}
}

type countingExecutor struct {
	calls *int
	mu    *sync.Mutex
}

func (e *countingExecutor) Execute(context.Context, reconcile.Claim) (reconcile.Result, error) {
	e.mu.Lock()
	*e.calls++
	e.mu.Unlock()
	return reconcile.ResultSucceeded, nil
}

func TestMetricsMerge(t *testing.T) {
	var a, b reconcile.Metrics
	a.ActionsClaimed = 2
	a.ObservationsMade = 1
	b.ActionsCommitted = 3
	b.EnvironmentsExpired = 4
	a.Add(b)
	if a.ActionsClaimed != 2 || a.ObservationsMade != 1 || a.ActionsCommitted != 3 || a.EnvironmentsExpired != 4 {
		t.Fatalf("metrics did not merge: %+v", a)
	}
}

func TestContextCancellationStopsWork(t *testing.T) {
	st, ex, wd := newStore(), newExecutor(), &watchdog{}
	p := newPass(t, st, ex, nil, wd, reconcile.DefaultConfig())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.Run(ctx, []reconcile.Work{work("alloc-pg", 1)}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled context must stop the pass, got %v", err)
	}
}
