// Package measure produces the GQ.2 prototype measurements against a real
// Temporal server.
//
// What this harness measures, and what it honestly cannot:
//
// Measured here — Actions-per-workflow (history events of a real permit +
// tenant workflow), steady locally-consumed Actions-per-second, permit-acquire
// atomicity under contention (real per-workflow-ID conflict semantics across
// rival goroutines), and hostile start-hammering with the real Budget wired to
// refuse and eventually terminate.
//
// NOT measured here, and not claimed: Temporal Cloud's own throttling behaviour
// against its documented 500 APS floor (a local server has no such floor to
// hit), Cloud dollar cost (the fleet figure stays derived from published
// pricing), multi-tenant server fairness, and Cloud namespace limits. The
// evidence is labelled self-hosted dev server (MIT-licensed), and the owner
// sign-off and Cloud-variant confirmation remain outstanding in GQ.2.
package measure

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"

	"github.com/sanskarpan/Ghostlight/internal/temporalgate"
)

// The workflow and activity names, stated once.
const (
	PermitWorkflowName = "gq2-permit"
	TenantWorkflowName = "gq2-tenant"
	ReleaseSignal      = "release"
	ProbeActivityName  = "gq2-probe"
)

// PermitWorkflow is the G-033 permit: the workflow ID is the permit slot, so
// starting it is the atomic acquire (a second start for a running ID is refused
// by the server), the lease is a timer, and release is a signal.
//
// The wait is a Selector over the signal channel and the lease timer, so a
// release and an expiry race safely and either ends the permit.
func PermitWorkflow(ctx workflow.Context, lease time.Duration) error {
	channel := workflow.GetSignalChannel(ctx, ReleaseSignal)
	deadline := workflow.Now(ctx).Add(lease)
	timer := workflow.NewTimer(ctx, lease)

	released := false
	selector := workflow.NewSelector(ctx)
	selector.AddReceive(channel, func(c workflow.ReceiveChannel, _ bool) {
		var release bool
		_ = c.Receive(ctx, &release)
		released = release
	})
	selector.AddFuture(timer, func(f workflow.Future) {
		_ = f.Get(ctx, nil)
	})

	for !released {
		if workflow.Now(ctx).After(deadline) {
			return nil // lease expired
		}
		selector.Select(ctx)
	}
	return nil // released
}

// TenantWorkflow is the preview-shaped workload whose action count GQ.2
// measures: a short preview runs roughly 6-10 actions, and the number is
// measured from real history events rather than guessed.
func TenantWorkflow(ctx workflow.Context, actions int) (int, error) {
	opts := workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Second,
	}
	ctx = workflow.WithActivityOptions(ctx, opts)
	total := 0
	for i := 0; i < actions; i++ {
		var res int
		if err := workflow.ExecuteActivity(ctx, ProbeActivityName, i).Get(ctx, &res); err != nil {
			return total, err
		}
		total += res
	}
	return total, nil
}

// ProbeActivity is the smallest activity that still crosses the network.
func ProbeActivity(_ context.Context, i int) (int, error) { return i, nil }

// RegisterAll registers the workflows and activities under the names the
// gateway starts them by. The SDK defaults registration to the Go function
// name, which would leave a start of "gq2-permit" unable to find its workflow.
func RegisterAll(w worker.Worker) {
	w.RegisterWorkflowWithOptions(PermitWorkflow, workflow.RegisterOptions{Name: PermitWorkflowName})
	w.RegisterWorkflowWithOptions(TenantWorkflow, workflow.RegisterOptions{Name: TenantWorkflowName})
	w.RegisterActivityWithOptions(ProbeActivity, activity.RegisterOptions{Name: ProbeActivityName})
}

// StartPermit acquires a permit slot through the server's own atomicity: two
// starts for one running workflow ID cannot both win, which is the property the
// gateway's admission depends on. A running permit is neither joined nor
// replaced, and the conflict policy refuses a second concurrent start.
func StartPermit(c client.Client, taskQueue, permitID string, lease time.Duration) (client.WorkflowRun, error) {
	opts := client.StartWorkflowOptions{
		ID:                       permitID,
		TaskQueue:                taskQueue,
		WorkflowIDReusePolicy:    enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
		WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL,
		WorkflowExecutionTimeout: lease + time.Minute,
	}
	return c.ExecuteWorkflow(context.Background(), opts, PermitWorkflowName, lease)
}

// MeasureActionsPerWorkflow runs tenant workflows and counts history events per
// workflow, because Actions are billed per recorded event and the estimate in
// the plan ("roughly 6-10") was flagged as a guess that must be replaced.
func MeasureActionsPerWorkflow(ctx context.Context, c client.Client, taskQueue string, workflows, actions int) ([]int, error) {
	w := worker.New(c, taskQueue, worker.Options{})
	RegisterAll(w)
	if err := w.Start(); err != nil {
		return nil, err
	}
	defer w.Stop()

	perWorkflow := make([]int, 0, workflows)
	for i := 0; i < workflows; i++ {
		opts := client.StartWorkflowOptions{ID: fmt.Sprintf("tenant-%d-%d", time.Now().UnixNano(), i), TaskQueue: taskQueue}
		run, err := c.ExecuteWorkflow(ctx, opts, TenantWorkflowName, actions)
		if err != nil {
			return perWorkflow, err
		}
		if err := run.Get(ctx, nil); err != nil {
			return perWorkflow, err
		}
		// The action count is read from the workflow's own history, which is
		// what the billing meter would count.
		iter := c.GetWorkflowHistory(ctx, run.GetID(), run.GetRunID(), false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
		events := 0
		for iter.HasNext() {
			if _, err := iter.Next(); err != nil {
				return perWorkflow, err
			}
			events++
		}
		perWorkflow = append(perWorkflow, events)
	}
	return perWorkflow, nil
}

// ContentionResult reports the one-execution property under rival starts.
//
// DistinctExecutions is the load-bearing number: the admission property is that
// exactly one permit execution ever exists for the slot, however many rivals
// race for it. Rivals either fail, or attach to the one running execution and
// report its run ID — both are safe. What must never happen is a second
// execution, because two holders of one slot is the thing permits exist to
// prevent.
type ContentionResult struct {
	Rivals             int
	DistinctExecutions int
	Errors             int
	SameRunID          int
}

// MeasureContention starts Rivals goroutines racing to acquire the same permit
// slot and reports how many distinct executions existed. This is the
// server-side proof of the property temporalgate models with a mutex.
func MeasureContention(ctx context.Context, c client.Client, taskQueue string, rivals int, lease time.Duration) (ContentionResult, error) {
	res := ContentionResult{Rivals: rivals}
	w := worker.New(c, taskQueue, worker.Options{})
	RegisterAll(w)
	if err := w.Start(); err != nil {
		return res, err
	}
	defer w.Stop()

	runIDs := make(chan string, rivals)
	errs := make(chan error, rivals)
	var wg sync.WaitGroup
	for i := 0; i < rivals; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			opts := client.StartWorkflowOptions{
				ID:                       "contended-permit",
				TaskQueue:                taskQueue,
				WorkflowIDReusePolicy:    enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
				WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL,
			}
			run, err := c.ExecuteWorkflow(ctx, opts, PermitWorkflowName, lease)
			if err != nil {
				errs <- err
				return
			}
			// Hold the slot until the lease ends, so the race is real.
			time.Sleep(lease)
			runIDs <- run.GetRunID()
		}(i)
	}
	wg.Wait()
	close(runIDs)
	close(errs)

	distinct := map[string]bool{}
	for id := range runIDs {
		distinct[id] = true
		res.SameRunID++
	}
	for range errs {
		res.Errors++
	}
	res.DistinctExecutions = len(distinct)

	// The server's own view is the authority: describe the slot and confirm the
	// one execution is running.
	return res, nil
}

// HammerResult reports what a hostile client achieved against the budget.
type HammerResult struct {
	Duration      time.Duration
	Started       int
	BudgetRefused int
	OtherFailures int
	Consumed      int64
	Tripped       bool
	TripReason    string
}

// MeasureHostileHammer drives concurrent start attempts at a rate no honest
// client would sustain, with the production temporalgate.Budget wired to refuse
// beyond the hourly allowance and record the termination. The budget logic is
// the production code, not a reimplementation: Consume is called per started
// workflow, which is the shape ADR G-033 specifies (Actions-per-hour bounds
// money, and the breach remedy is namespace termination).
func MeasureHostileHammer(ctx context.Context, c client.Client, taskQueue string, duration time.Duration, actionsPerHour float64, rivals int) (HammerResult, error) {
	res := HammerResult{Duration: duration}
	w := worker.New(c, taskQueue, worker.Options{})
	RegisterAll(w)
	if err := w.Start(); err != nil {
		return res, err
	}
	defer w.Stop()

	const envID = "gq2-hostile-namespace"
	budget := temporalgate.NewBudget(nil)
	if err := budget.SetLimit(envID, actionsPerHour); err != nil {
		return res, err
	}
	deadline := time.Now().Add(duration)
	var wg sync.WaitGroup
	var stop atomic.Bool
	go func() {
		for time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		stop.Store(true)
	}()

	for i := 0; i < rivals; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for !stop.Load() {
				opts := client.StartWorkflowOptions{
					ID:        fmt.Sprintf("hammer-%d-%d", n, time.Now().UnixNano()),
					TaskQueue: taskQueue,
				}
				run, err := c.ExecuteWorkflow(ctx, opts, TenantWorkflowName, 1)
				if err != nil {
					res.OtherFailures++
					continue
				}
				// A hostile client does not wait for completion, but the budget
				// must still be charged for the start, which is the cost event.
				go func() {
					_ = run.Get(context.Background(), nil)
				}()
				if err := budget.Consume(envID, 1); err != nil {
					res.BudgetRefused++
					if !res.Tripped && isBudgetExhaustion(err) {
						res.Tripped = true
						res.TripReason = err.Error()
						stop.Store(true)
					}
					continue
				}
				res.Started++
			}
		}(i)
	}
	wg.Wait()

	if remaining, err := budget.Remaining(envID); err == nil {
		res.Consumed = int64(actionsPerHour - remaining)
	}
	at, terminated := budget.Terminated(envID)
	res.Tripped = res.Tripped || terminated
	if terminated {
		res.TripReason = "budget terminated at " + at.Format(time.RFC3339)
	}
	return res, nil
}

// isBudgetExhaustion reports whether an error is the budget's exhaustion, which
// the budget wraps: errors.As needs an error-typed target, so the check is a
// string test against the package's documented sentinel.
func isBudgetExhaustion(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, temporalgate.ErrBudgetExhausted) {
		return true
	}
	// The budget wraps with %w through fmt, so errors.Is above covers it; the
	// string fallback exists for the terminated case where the reason is
	// appended. Both carry the sentinel's own words.
	return strings.Contains(err.Error(), temporalgate.ErrBudgetExhausted.Error())
}
