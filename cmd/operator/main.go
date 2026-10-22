// Command operator is the operator-facing tool for checklist row G6.4.
//
// It reads the on-call roster, the rotation plans, the coverage registry and
// the status checks, and reports what the library rules say about them. The
// rules live in internal/oncall, internal/coverage and internal/communications;
// this command only wires the terminal to them.
//
// Usage:
//
//	operator oncall check --shifts <file> --from <RFC3339> --to <RFC3339>
//	operator rotation plan --file <file>
//	operator rotation verify --file <file> --secret-file <file>
//	operator coverage scorecard --file <file>
//	operator status page --file <file> [--max-age <duration>]
//
// Every command takes --json for a machine-readable report.
//
// The exit code says what happened. Zero means the report was produced and the
// state is acceptable, one means the command was asked for wrongly, two means a
// library rule refused the state, and three means the tool could not read its
// input. The tool does not rotate a key against anything: there is no
// credential plane to rotate it against, and a tool that claimed to while only
// printing a plan would be worse than no tool.
package main

import (
	"os"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/operator"
)

func main() {
	ctx := operator.Context{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Now:    time.Now(),
	}
	os.Exit(int(operator.Dispatch(ctx, os.Args[1:])))
}
