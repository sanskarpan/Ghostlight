// Package envpage builds the console's environment detail page from a stored
// environment.
//
// This is the join between the two halves of the project that had never met:
// the environment store the API reads from, and the console renderer that
// produces accessible HTML. The frontend plan (docs/FRONTEND-PLAN.md §6b) fixes
// the order and the requirements, and this package's job is to satisfy them
// from real records rather than from fixtures the way cmd/consoledemo does.
//
// The rules it enforces:
//
// The first is that **the timeline comes from the recorded actions, not from a
// lifecycle state.** A lifecycle state cannot say how far a degraded run got;
// the ledger can, and console.BuildTimeline already refuses to pretend
// otherwise. Deriving the timeline from anything else would make "ready" a
// guess.
//
// The second is that **a phase that is uncertain says why and what to do.**
// The console model refuses an uncertain action with no reason, and an action
// the operator must act on with no recovery. This package does not get to
// invent a reassuring answer where the ledger recorded an unknown: it surfaces
// the recorded reason and the standard recovery line for an uncertain native
// outcome, which is to check the provider before retrying.
//
// The third is that **the page never contains another tenant's data.** The
// caller passes the already-scoped environment; this package does not receive
// a store and cannot look one up by a caller-supplied id. Scope is checked
// before the page is built, and a miss is a 404 rather than a 403, because
// presence must not leak.
package envpage

import (
	"errors"
	"strings"
	"time"

	"github.com/sanskarpan/Ghostlight/api"
	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
)

// ErrNoTitle means the environment has no identifier to title the page with. A
// page without a title is a page a screen-reader user cannot identify among
// tabs, so a title is required rather than defaulted.
var ErrNoTitle = errors.New("envpage: environment has no identifier for a page title")

// RecoveryUncertain is the next step offered for an action whose native
// outcome never reported back.
//
// The wording matches internal/console's default for an uncertain state rather
// than being invented here: the console already owns that sentence, and two
// surfaces giving an operator two slightly different next steps is how a
// recovery instruction stops being trusted. This constant exists so the page
// builder can pass it explicitly, not so it can differ.
const RecoveryUncertain = "check the provider's own state before retrying"

// Build renders the detail page for one already-scoped environment.
//
// now is the page's notion of "as of", which the renderer prints beside every
// timestamp. Passing it in rather than reading the clock keeps the page
// deterministic in tests and honest in production.
func Build(env api.Environment, now time.Time) (consolerender.Page, error) {
	if strings.TrimSpace(env.ID) == "" {
		return consolerender.Page{}, ErrNoTitle
	}

	page := consolerender.Page{
		Title:    env.ID,
		Screen:   screen(env),
		Timeline: console.BuildTimeline(env.Actions),
		Actions:  actions(env.Actions),
		Now:      now,
	}
	return page, nil
}

// screen is the page's controls and live regions.
//
// Abort is focus order 1 because stopping a burning run is the urgent task, and
// the console model refuses a screen whose live region obscures the abort
// control. That refusal is why Covers is left unset: there is nothing to
// cover, and claiming coverage that does not exist would be worse than not
// claiming.
func screen(env api.Environment) console.Screen {
	return console.Screen{
		Title: env.ID,
		Regions: []console.Region{{
			Name:             "progress",
			Live:             true,
			Covers:           nil,
			DeclaresCoverage: true,
			Announces:        "run status changed",
		}},
		Controls: []console.Control{
			{Name: "abort", AccessibleName: "Abort the run", FocusOrder: 1, KeyboardReachable: true},
			{Name: "review", AccessibleName: "Review the candidate", FocusOrder: 2, KeyboardReachable: true},
			{Name: "refresh", AccessibleName: "Refresh", FocusOrder: 3, KeyboardReachable: true},
		},
		AbortControl: "abort",
	}
}

// actions maps recorded actions to the view the page shows.
//
// The mapping goes through console.ResolveDetail rather than a switch written
// here, because that function already encodes the rule that matters most: there
// is no path from an uncertain outcome to a success, and an outcome the console
// does not recognise becomes uncertain rather than successful. A second mapping
// in this package could drift from it, and the drift would surface as a run
// reported ready when nobody knows whether it is.
//
// Only actions that are not plain successes appear: a list of every succeeded
// action on a long run buries the one an operator needs. A success still
// contributes to the timeline, which is where progress belongs.
func actions(recorded []console.RecordedAction) []console.ActionView {
	out := make([]console.ActionView, 0, len(recorded))
	for _, a := range recorded {
		view := console.ResolveDetail(a.Outcome, strings.TrimSpace(a.Detail), RecoveryUncertain)
		if view.State == console.StateSucceeded {
			continue
		}
		view.ActionID = a.ID
		view.Label = label(a.Phase)
		view.OperationID = a.ID
		view.Version = 1
		out = append(out, view)
	}
	return out
}

// label is the human name for a phase, matching the renderer's own vocabulary.
func label(p console.Phase) string {
	switch p {
	case console.PhaseArtifactBuild:
		return "Artifact build"
	case console.PhaseFoundationWarmup:
		return "Foundation warmup"
	case console.PhaseDependencyAllocation:
		return "Dependency allocation"
	case console.PhaseMigration:
		return "Migration"
	case console.PhaseGates:
		return "Gates"
	}
	return string(p)
}
