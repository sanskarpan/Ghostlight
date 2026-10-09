package reconcile_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/prstate"
	"github.com/sanskarpan/Ghostlight/internal/reconcile"
)

// fakeQueue records intake outcomes.
type fakeQueue struct {
	mu sync.Mutex

	items   []reconcile.PendingEvent
	pending error

	processed []string
	ignored   map[string]string
	failed    map[string]string
	// failRetry makes Failed itself fail, which is how a queue that cannot record
	// an outcome is modelled.
	failRetry bool
}

func newQueue() *fakeQueue {
	return &fakeQueue{ignored: map[string]string{}, failed: map[string]string{}}
}

func (f *fakeQueue) Pending(_ context.Context, limit int) ([]reconcile.PendingEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pending != nil {
		return nil, f.pending
	}
	// The bound is part of the contract: a queue that returned everything would let
	// one backlog monopolise a controller and never drain.
	if limit > 0 && len(f.items) > limit {
		return f.items[:limit], nil
	}
	return f.items, nil
}

func (f *fakeQueue) Processed(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.processed = append(f.processed, id)
	return nil
}

func (f *fakeQueue) Ignored(_ context.Context, id, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ignored[id] = reason
	return nil
}

func (f *fakeQueue) Failed(_ context.Context, id, reason string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRetry {
		return errors.New("queue unavailable")
	}
	f.failed[id] = reason
	return nil
}

func (f *fakeQueue) outcome(id string) (processed bool, ignored, failed string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.processed {
		if p == id {
			processed = true
		}
	}
	return processed, f.ignored[id], f.failed[id]
}

// fakeLifecycle scripts reconciliation decisions.
type fakeLifecycle struct {
	mu sync.Mutex

	decisions map[string]prstate.Decisions
	errs      map[string]error
	bindings  map[string]*prstate.EnvironmentBinding
	noNumber  map[string]bool
	numberErr map[string]error

	reconcileCalls []string
	bindCalls      []string
}

func newLifecycle() *fakeLifecycle {
	return &fakeLifecycle{
		decisions: map[string]prstate.Decisions{},
		errs:      map[string]error{},
		bindings:  map[string]*prstate.EnvironmentBinding{},
		noNumber:  map[string]bool{},
		numberErr: map[string]error{},
	}
}

func (f *fakeLifecycle) NumberFor(_ context.Context, e reconcile.PendingEvent) (int, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.numberErr[e.DeliveryID]; ok {
		return 0, false, err
	}
	if f.noNumber[e.DeliveryID] {
		return 0, false, nil
	}
	return 142, true, nil
}

func (f *fakeLifecycle) Binding(_ context.Context, repoRef string, _ int) (*prstate.EnvironmentBinding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bindCalls = append(f.bindCalls, repoRef)
	return f.bindings[repoRef], nil
}

func (f *fakeLifecycle) Reconcile(_ context.Context, e prstate.Event, _ *prstate.EnvironmentBinding, _ time.Time) (prstate.Decisions, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reconcileCalls = append(f.reconcileCalls, e.RepositoryRef)
	if err, ok := f.errs[e.RepositoryRef]; ok {
		return prstate.Decisions{}, err
	}
	return f.decisions[e.RepositoryRef], nil
}

func (f *fakeLifecycle) reconcileCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reconcileCalls)
}

func event(id string) reconcile.PendingEvent {
	return reconcile.PendingEvent{
		DeliveryID: id, EventType: "pull_request", Repository: "repo/acme/app",
	}
}

func passWithIntake(t *testing.T, q reconcile.IntakeQueue, lc reconcile.Lifecycle) *reconcile.Pass {
	t.Helper()
	p, err := reconcile.New(reconcile.Options{
		Store: newStore(), Queue: q, Lifecycle: lc,
		Config: reconcile.DefaultConfig(),
		Owner:  "controller-a",
		Now:    func() time.Time { return passNow },
		Jitter: func() float64 { return 0.5 },
	})
	if err != nil {
		t.Fatalf("new pass: %v", err)
	}
	return p
}

func TestIntakeProcessesAnEventThatCausesCreate(t *testing.T) {
	q, lc := newQueue(), newLifecycle()
	q.items = []reconcile.PendingEvent{event("e-create")}
	lc.decisions["repo/acme/app"] = prstate.Decisions{
		Action: prstate.ActionCreate, Reason: "no environment bound",
	}

	m, err := passWithIntake(t, q, lc).Run(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if m.EventsProcessed != 1 {
		t.Fatalf("expected one processed event, got %+v", m)
	}
	if m.EnvironmentsMoved != 1 {
		t.Fatalf("expected one environment change, got %+v", m)
	}
	if processed, _, _ := q.outcome("e-create"); !processed {
		t.Fatal("the event must be recorded processed")
	}
}

func TestStaleEventIsIgnoredNotFailed(t *testing.T) {
	// Stale data is not broken data. Failing it would retry something that should
	// never be applied.
	q, lc := newQueue(), newLifecycle()
	q.items = []reconcile.PendingEvent{event("e-stale")}
	lc.decisions["repo/acme/app"] = prstate.Decisions{
		Action: prstate.ActionNone, StaleEvent: true,
		Reason: "event head is not current head",
	}

	m, err := passWithIntake(t, q, lc).Run(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if m.EventsFailed != 0 {
		t.Fatalf("a stale event must not be recorded as failed, got %+v", m)
	}
	_, ignored, failed := q.outcome("e-stale")
	if failed != "" {
		t.Fatal("a stale event must not be scheduled for retry")
	}
	if !strings.Contains(ignored, "not current") {
		t.Fatalf("the ignore reason must explain staleness, got %q", ignored)
	}
	if m.EventsProcessed != 0 {
		t.Fatal("a stale event is not processed; it is deliberately not applied")
	}
}

// TestUnresolvableStateCausesNoLifecycleChange is the safety property: an event must
// never drive a lifecycle change on its own claims.
func TestUnresolvableStateCausesNoLifecycleChange(t *testing.T) {
	q, lc := newQueue(), newLifecycle()
	q.items = []reconcile.PendingEvent{event("e-unresolvable")}
	lc.errs["repo/acme/app"] = errors.New("provider unreachable")

	m, err := passWithIntake(t, q, lc).Run(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if m.EnvironmentsMoved != 0 {
		t.Fatalf("an unresolvable state must cause no lifecycle change, got %+v", m)
	}
	processed, _, failed := q.outcome("e-unresolvable")
	if processed {
		t.Fatal("an unresolvable event must not be recorded processed")
	}
	if !strings.Contains(failed, "provider unreachable") {
		t.Fatalf("the retry reason must name the cause, got %q", failed)
	}
}

func TestEventWithoutPullRequestIsIgnored(t *testing.T) {
	q, lc := newQueue(), newLifecycle()
	q.items = []reconcile.PendingEvent{event("e-nopr")}
	lc.noNumber["e-nopr"] = true

	m, err := passWithIntake(t, q, lc).Run(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if m.EventsProcessed != 0 {
		t.Fatal("an event with no pull request must not be processed")
	}
	_, ignored, _ := q.outcome("e-nopr")
	if !strings.Contains(ignored, "no pull request") {
		t.Fatalf("the ignore reason must explain why, got %q", ignored)
	}
	if lc.reconcileCount() != 0 {
		t.Fatal("an event with no pull request must not be reconciled")
	}
}

func TestUnparseableEventIsRetriedWithItsReason(t *testing.T) {
	// A payload that cannot be read is a real failure and must be retried with the
	// reason recorded, rather than silently dropped.
	q, lc := newQueue(), newLifecycle()
	q.items = []reconcile.PendingEvent{event("e-badnum")}
	lc.numberErr["e-badnum"] = errors.New("payload unreadable")

	m, err := passWithIntake(t, q, lc).Run(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if m.EventsFailed != 1 {
		t.Fatalf("an unreadable payload must be a failure, got %+v", m)
	}
	_, _, failed := q.outcome("e-badnum")
	if !strings.Contains(failed, "payload unreadable") {
		t.Fatalf("the failure reason must be visible, got %q", failed)
	}
}

// TestEveryEventResolvesItsRow is the durability rule: an event that cannot record
// its outcome would retry forever with no recorded reason.
func TestEveryEventResolvesItsRow(t *testing.T) {
	// Every event must reach exactly one terminal outcome. An event whose row is
	// left pending would retry forever with nothing recorded, which is how a queue
	// silently grows forever.
	q, lc := newQueue(), newLifecycle()
	q.items = []reconcile.PendingEvent{event("a"), event("b"), event("c")}
	// Distinct repositories so each exercises a different path.
	q.items[0].Repository = "repo/a"
	q.items[1].Repository = "repo/b"
	q.items[2].Repository = "repo/c"
	lc.decisions["repo/a"] = prstate.Decisions{Action: prstate.ActionCreate, Reason: "create"}
	lc.decisions["repo/b"] = prstate.Decisions{Action: prstate.ActionNone, StaleEvent: true, Reason: "stale"}
	lc.errs["repo/c"] = errors.New("unreachable")

	if _, err := passWithIntake(t, q, lc).Run(context.Background(), nil, nil); err != nil {
		t.Fatalf("run: %v", err)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.processed)+len(q.ignored)+len(q.failed) != 3 {
		t.Fatalf("expected 3 resolved outcomes, got %d processed, %d ignored, %d failed",
			len(q.processed), len(q.ignored), len(q.failed))
	}
	if _, ok := q.ignored["b"]; !ok {
		t.Error("the stale event must be ignored with a reason, not retried")
	}
	if reason, ok := q.failed["c"]; !ok || reason == "" {
		t.Error("the unresolvable event must be scheduled for retry with a reason")
	}
	if len(q.processed) != 1 || q.processed[0] != "a" {
		t.Errorf("only the create event may be processed, got %v", q.processed)
	}
}

func TestTeardownDecisionIsCounted(t *testing.T) {
	q, lc := newQueue(), newLifecycle()
	q.items = []reconcile.PendingEvent{event("e-close")}
	lc.decisions["repo/acme/app"] = prstate.Decisions{
		Action: prstate.ActionTeardown, Reason: "pull request is closed",
	}
	m, err := passWithIntake(t, q, lc).Run(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if m.EnvironmentsMoved != 1 || m.EventsProcessed != 1 {
		t.Fatalf("a close must produce a teardown and be processed, got %+v", m)
	}
}

// TestIntakeRunsBeforeObservationAndWork is the ordering guarantee.
func TestIntakeRunsBeforeObservationAndWork(t *testing.T) {
	var order []string

	q := newQueue()
	q.items = []reconcile.PendingEvent{event("e-order")}
	lc := &orderingLifecycle{order: &order, label: "intake"}
	ob := &orderObserver{inner: newObserver(), order: &order, label: "observe"}
	ob.inner.byKey["k"] = reconcile.Observation{Existed: true}
	ex := &orderExecutor{inner: newExecutor(), order: &order, label: "execute"}

	p, err := reconcile.New(reconcile.Options{
		Store: newStore(), Queue: q, Lifecycle: lc, Observer: ob, Executor: ex,
		Config: reconcile.DefaultConfig(), Owner: "controller-a",
		Now: func() time.Time { return passNow }, Jitter: func() float64 { return 0.5 },
	})
	if err != nil {
		t.Fatalf("new pass: %v", err)
	}
	if _, err := p.Run(context.Background(),
		[]reconcile.Work{work("k", 1)},
		[]reconcile.UncertainWork{uncertain("k", 1)}); err != nil {
		t.Fatalf("run: %v", err)
	}

	seen := map[string]bool{}
	for _, s := range order {
		seen[s] = true
	}
	for _, want := range []string{"intake", "observe", "execute"} {
		if !seen[want] {
			t.Fatalf("stage %q did not run; order was %v", want, order)
		}
	}
	if order[0] != "intake" {
		t.Fatalf("intake must run first, got %v", order)
	}
}

// orderingLifecycle records when reconciliation is invoked.
type orderingLifecycle struct {
	order *[]string
	label string
}

func (o *orderingLifecycle) NumberFor(context.Context, reconcile.PendingEvent) (int, bool, error) {
	return 142, true, nil
}

func (o *orderingLifecycle) Binding(context.Context, string, int) (*prstate.EnvironmentBinding, error) {
	return nil, nil
}

func (o *orderingLifecycle) Reconcile(context.Context, prstate.Event, *prstate.EnvironmentBinding, time.Time) (prstate.Decisions, error) {
	*o.order = append(*o.order, o.label)
	return prstate.Decisions{Action: prstate.ActionCreate, Reason: "create"}, nil
}

func TestQueueFailureIsReportedNotSwallowed(t *testing.T) {
	q, lc := newQueue(), newLifecycle()
	q.pending = errors.New("queue unavailable")

	_, err := passWithIntake(t, q, lc).Run(context.Background(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "queue") {
		t.Fatalf("a queue read failure must be reported, got %v", err)
	}
}

func TestIntakeQueueRequiresLifecycle(t *testing.T) {
	// A queue with nothing able to decide what events mean would drain into
	// nothing. That must fail at construction, not silently.
	_, err := reconcile.New(reconcile.Options{
		Store: newStore(), Queue: newQueue(), Owner: "controller-a",
	})
	if err == nil {
		t.Fatal("a queue without a lifecycle must be refused")
	}
	if !strings.Contains(err.Error(), "lifecycle") {
		t.Fatalf("the reason must name the missing lifecycle, got %v", err)
	}
}

func TestLifecycleRequiresQueue(t *testing.T) {
	_, err := reconcile.New(reconcile.Options{
		Store: newStore(), Lifecycle: newLifecycle(), Owner: "controller-a",
	})
	if err == nil {
		t.Fatal("a lifecycle without a queue must be refused")
	}
	if !strings.Contains(err.Error(), "queue") {
		t.Fatalf("the reason must name the missing queue, got %v", err)
	}
}

func TestIntakeSummaryIsPublished(t *testing.T) {
	q, lc := newQueue(), newLifecycle()
	q.items = []reconcile.PendingEvent{event("s1"), event("s2")}
	q.items[0].Repository = "repo/x"
	q.items[1].Repository = "repo/y"
	lc.decisions["repo/x"] = prstate.Decisions{Action: prstate.ActionCreate, Reason: "create"}
	lc.decisions["repo/y"] = prstate.Decisions{Action: prstate.ActionUpdate, Reason: "update"}

	p := passWithIntake(t, q, lc)
	if _, err := p.Run(context.Background(), nil, nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	sum := p.LastIntake()
	if sum.Processed != 2 {
		t.Fatalf("expected two processed events in the summary, got %+v", sum)
	}
	if sum.EnvironmentsCreated != 1 || sum.EnvironmentsUpdated != 1 {
		t.Fatalf("summary must distinguish created from updated, got %+v", sum)
	}
}

func TestIntakeIsBounded(t *testing.T) {
	q, lc := newQueue(), newLifecycle()
	for i := 0; i < 5; i++ {
		q.items = append(q.items, event("b"+string(rune('a'+i))))
	}
	lc.decisions["repo/acme/app"] = prstate.Decisions{Action: prstate.ActionCreate, Reason: "create"}

	cfg := reconcile.DefaultConfig()
	cfg.EventLimit = 2
	p, err := reconcile.New(reconcile.Options{
		Store: newStore(), Queue: q, Lifecycle: lc, Config: cfg, Owner: "controller-a",
		Now: func() time.Time { return passNow },
	})
	if err != nil {
		t.Fatalf("new pass: %v", err)
	}
	if _, err := p.Run(context.Background(), nil, nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	if p.LastIntake().Processed != 2 {
		t.Fatalf("the event limit must bound one pass, processed %d", p.LastIntake().Processed)
	}
}

// TestIntakeDoesNotPreventWorkWhenItFails checks stage independence.
func TestIntakeDoesNotPreventWorkWhenItFails(t *testing.T) {
	q, lc := newQueue(), newLifecycle()
	q.pending = errors.New("queue unavailable")
	ex := newExecutor()

	p, err := reconcile.New(reconcile.Options{
		Store: newStore(), Queue: q, Lifecycle: lc, Executor: ex,
		Config: reconcile.DefaultConfig(), Owner: "controller-a",
		Now: func() time.Time { return passNow },
	})
	if err != nil {
		t.Fatalf("new pass: %v", err)
	}
	m, err := p.Run(context.Background(), []reconcile.Work{work("k", 1)}, nil)
	if err == nil {
		t.Fatal("the intake failure must still be reported")
	}
	if m.ActionsCommitted != 1 {
		t.Fatalf("an intake failure must not prevent work, got %+v", m)
	}
}

func TestContextCancellationStopsIntake(t *testing.T) {
	q, lc := newQueue(), newLifecycle()
	q.items = []reconcile.PendingEvent{event("e-cancel")}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := passWithIntake(t, q, lc).Run(ctx, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled context must stop intake, got %v", err)
	}
}
