package measure_test

// The GQ.2 measurement run. Gated behind GHOSTLIGHT_GQ2=1 because the dev
// server downloads the Temporal CLI binary on first use, which CI must not do
// and which takes minutes the first time. Run it with:
//
//	GHOSTLIGHT_GQ2=1 go test ./internal/temporalgate/measure -run TestMeasure -v --timeout 30m
//
// The output lines are transcribed into docs/GQ2-MEASUREMENTS.md, which is the
// evidence the GQ.2 row cites.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.temporal.io/sdk/worker"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"

	"github.com/sanskarpan/Ghostlight/internal/temporalgate/measure"
)

func newDevServer(t *testing.T) (client.Client, func()) {
	t.Helper()
	srv, err := testsuite.StartDevServer(context.Background(), testsuite.DevServerOptions{
		LogLevel: "error",
	})
	if err != nil {
		t.Fatalf("dev server: %v", err)
	}
	return srv.Client(), func() { _ = srv.Stop() }
}

func pctl(values []int, p float64) int {
	sorted := append([]int(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

// The headline number: Actions-per-workflow measured from real history events,
// replacing the plan's "roughly 6-10" guess.
func TestMeasureActionsPerWorkflow(t *testing.T) {
	if os.Getenv("GHOSTLIGHT_GQ2") != "1" {
		t.Skip("measurement run: set GHOSTLIGHT_GQ2=1 (downloads the Temporal dev server on first use)")
	}
	c, stop := newDevServer(t)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	const workflows, actions = 20, 8
	perWorkflow, err := measure.MeasureActionsPerWorkflow(ctx, c, "gq2-actions", workflows, actions)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	min, max := perWorkflow[0], perWorkflow[0]
	sum := 0
	for _, v := range perWorkflow {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
		sum += v
	}
	fmt.Printf("GQ2-RESULT actions-per-workflow: workflows=%d activities=%d min=%d p50=%d p95=%d max=%d mean=%.1f\n",
		workflows, actions, min, pctl(perWorkflow, 0.5), pctl(perWorkflow, 0.95), max,
		float64(sum)/float64(len(perWorkflow)))
}

// Steady consumed APS against the documented Cloud floor: measured locally as
// consumption, compared arithmetically, never claimed as Cloud throttling.
func TestMeasureSteadyAPS(t *testing.T) {
	if os.Getenv("GHOSTLIGHT_GQ2") != "1" {
		t.Skip("measurement run: set GHOSTLIGHT_GQ2=1")
	}
	c, stop := newDevServer(t)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	ww := worker.New(c, "gq2-aps", worker.Options{})
	measure.RegisterAll(ww)
	if err := ww.Start(); err != nil {
		t.Fatalf("worker: %v", err)
	}
	defer ww.Stop()

	var started atomic.Int64
	deadline := time.Now().Add(20 * time.Second)
	var failures atomic.Int64
	for time.Now().Before(deadline) {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				opts := client.StartWorkflowOptions{
					ID:        fmt.Sprintf("aps-%d-%d", time.Now().UnixNano(), n),
					TaskQueue: "gq2-aps",
				}
				run, err := c.ExecuteWorkflow(ctx, opts, measure.TenantWorkflowName, 1)
				if err != nil {
					failures.Add(1)
					return
				}
				started.Add(1)
				go func() { _ = run.Get(context.Background(), nil) }()
			}(i)
			wg.Wait()
		}
	}
	elapsed := 20.0
	aps := float64(started.Load()) / elapsed
	fmt.Printf("GQ2-RESULT steady-aps: started=%d seconds=%.0f consumed-aps=%.1f failures=%d (cloud documented floor: 500 APS; local consumption is compared to it arithmetically, not as throttling)\n",
		started.Load(), elapsed, aps, failures.Load())
	_ = cancel
}

// The one-winner property, proven against the real server's per-workflow-ID
// conflict semantics across rival starts. This is the server-side proof of what
// temporalgate models with a mutex.
func TestMeasureContention(t *testing.T) {
	if os.Getenv("GHOSTLIGHT_GQ2") != "1" {
		t.Skip("measurement run: set GHOSTLIGHT_GQ2=1")
	}
	c, stop := newDevServer(t)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	res, err := measure.MeasureContention(ctx, c, "gq2-contention", 24, 2*time.Second)
	if err != nil {
		t.Fatalf("contention: %v", err)
	}
	fmt.Printf("GQ2-RESULT contention: rivals=%d distinct-executions=%d same-run-id=%d start-errors=%d\n",
		res.Rivals, res.DistinctExecutions, res.SameRunID, res.Errors)
	if res.DistinctExecutions != 1 {
		t.Errorf("distinct executions = %d, want exactly 1: two holders of one permit slot is the thing permits exist to prevent", res.DistinctExecutions)
	}
}

// The hostile hammer against the production Budget: the allowance is exceeded,
// consumption stops, and the termination is recorded with its reason.
func TestMeasureHostileHammer(t *testing.T) {
	if os.Getenv("GHOSTLIGHT_GQ2") != "1" {
		t.Skip("measurement run: set GHOSTLIGHT_GQ2=1")
	}
	c, stop := newDevServer(t)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	res, err := measure.MeasureHostileHammer(ctx, c, "gq2-hostile", 15*time.Second, 500, 16)
	if err != nil {
		t.Fatalf("hammer: %v", err)
	}
	fmt.Printf("GQ2-RESULT hostile-hammer: duration=%s started=%d budget-refused=%d other-failures=%d consumed=%d tripped=%v reason=%q\n",
		res.Duration, res.Started, res.BudgetRefused, res.OtherFailures, res.Consumed, res.Tripped, res.TripReason)
	if !res.Tripped {
		t.Error("the hammer must trip the budget: 16 rivals against a 500/hour allowance exceeds it within the window")
	}
	if res.Consumed < 500 {
		t.Errorf("consumed = %d, want at least the 500 allowance before the trip", res.Consumed)
	}
}
