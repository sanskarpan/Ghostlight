package measure_test

import (
	"context"
	"testing"
	"time"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"

	"github.com/sanskarpan/Ghostlight/internal/temporalgate/measure"
)

func TestProbeDoubleStart(t *testing.T) {
	srv, err := testsuite.StartDevServer(context.Background(), testsuite.DevServerOptions{LogLevel: "error"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	c := srv.Client()
	ctx := context.Background()
	q := "probe-q"

	w := worker.New(c, q, worker.Options{})
	measure.RegisterAll(w)
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	opts := client.StartWorkflowOptions{
		ID:                       "probe-permit",
		TaskQueue:                q,
		WorkflowIDReusePolicy:    3, // REJECT_DUPLICATE
		WorkflowIDConflictPolicy: 1, // FAIL
		WorkflowExecutionTimeout: 5 * time.Minute,
	}
	run1, err := c.ExecuteWorkflow(ctx, opts, measure.PermitWorkflowName, 60*time.Second)
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // let the winner's task start
	if d1, derr := c.DescribeWorkflowExecution(ctx, "probe-permit", ""); derr == nil && d1.WorkflowExecutionInfo != nil {
		t.Logf("before 2nd start: status=%s runID=%s", d1.WorkflowExecutionInfo.Status, d1.WorkflowExecutionInfo.Execution.RunId)
	}
	run2, err := c.ExecuteWorkflow(ctx, opts, measure.PermitWorkflowName, 60*time.Second)
	t.Logf("second start err=%v run2ID=%s", err, run2.GetRunID())
	t.Logf("first runID=%s", run1.GetRunID())
	if err == nil {
		t.Logf("second start SUCCEEDED — describing both")
		desc, derr := c.DescribeWorkflowExecution(ctx, "probe-permit", "")
		if derr == nil && desc.WorkflowExecutionInfo != nil {
			t.Logf("status=%s firstRunID=%s", desc.WorkflowExecutionInfo.Status, desc.WorkflowExecutionInfo.Execution.RunId)
		}
		_ = run2
	}
	_ = run1
}
