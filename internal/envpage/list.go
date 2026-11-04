// Overview and environment-list pages.
//
// These are the pages that make the console navigable: without them an operator
// has to already know an environment id, which is not a user interface, it is a
// URL bar with a stylesheet.
//
// The rules this file enforces:
//
// The first is that **a list is scoped before it is built.** The caller passes
// environments already filtered to the operator's grants; this package never
// receives a store and cannot widen a scope by querying. That is the same
// discipline the detail page follows, and it is the difference between a
// privacy bug and a privacy property.
//
// The second is that **an empty list says so.** An empty table renders as a
// blank area, and a blank area is indistinguishable from a failure to load. The
// console already refuses that elsewhere; here it says "No environments yet"
// and names what to do about it.
//
// The third is that **counts are honest about what they count.** "3 running"
// means three environments whose latest recorded phase is in flight, not three
// environments that exist. A counter that quietly means something else is worse
// than no counter, because it is read as a fact.
package envpage

import (
	"sort"
	"strconv"
	"time"

	"github.com/sanskarpan/Ghostlight/api"
	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
)

// ListColumns are the environments table's headings. They are declared here so
// the row builder and any test agree on the shape by construction.
var ListColumns = []string{"Environment", "Generation", "State", "Expires"}

// BuildList renders the environments list for an already-scoped set.
//
// The rows are sorted by identifier so the page is deterministic: a list that
// reorders between refreshes makes an operator lose their place, and it makes a
// screenshot impossible to compare with the last one.
func BuildList(envs []api.Environment, now time.Time) (consolerender.ListPage, error) {
	rows := make([][]string, 0, len(envs))
	ordered := append([]api.Environment(nil), envs...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	for _, env := range ordered {
		rows = append(rows, []string{
			env.ID,
			strconv.Itoa(env.Generation),
			stateWord(console.BuildTimeline(env.Actions)),
			expiry(env.ExpiresAt, now),
		})
	}

	page := consolerender.ListPage{
		Title: "Environments",
		Screen: console.Screen{
			Title: "Environments",
			Controls: []console.Control{
				{Name: "create", AccessibleName: "Create an environment", FocusOrder: 1, KeyboardReachable: true},
			},
		},
		Now:   now,
		Empty: "No environments yet. Create one to see it here.",
	}
	if len(rows) > 0 {
		page.Tables = []console.Table{{Title: "Environments", Columns: ListColumns, Rows: rows}}
	}
	return page, nil
}

// BuildOverview renders the landing page: how much needs attention, what is
// running, and what was touched most recently.
func BuildOverview(envs []api.Environment, now time.Time) (consolerender.ListPage, error) {
	ordered := append([]api.Environment(nil), envs...)
	sort.Slice(ordered, func(i, j int) bool {
		// Most recently touched first, then by id so ties are stable.
		li, lj := lastUpdate(ordered[i]), lastUpdate(ordered[j])
		if !li.Equal(lj) {
			return li.After(lj)
		}
		return ordered[i].ID < ordered[j].ID
	})
	if len(ordered) > 5 {
		ordered = ordered[:5]
	}

	rows := make([][]string, 0, len(ordered))
	for _, env := range ordered {
		rows = append(rows, []string{env.ID, stateWord(console.BuildTimeline(env.Actions))})
	}

	counts := Count(envs)
	page := consolerender.ListPage{
		Title:   "Overview",
		Summary: summaryLine(counts),
		Screen:  console.Screen{Title: "Overview"},
		Now:     now,
		Empty:   "No environments yet. Create one to see it here.",
	}
	if len(rows) > 0 {
		page.Tables = []console.Table{{Title: "Recent environments", Columns: []string{"Environment", "State"}, Rows: rows}}
	}
	return page, nil
}

// summaryLine states the counts in words, so a reader who cannot see the table
// still learns how much needs them.
func summaryLine(c Counts) string {
	if c.Total == 0 {
		return "Nothing to report."
	}
	attention := "nothing needs your attention"
	if c.NeedsLookAt > 0 {
		attention = countPhrase(c.NeedsLookAt, "environment needs", "environments need") + " your attention"
	}
	return countPhrase(c.Total, "environment", "environments") + " in total, " +
		countPhrase(c.Running, "running", "running") + ", " + attention + "."
}

// countPhrase renders "1 environment" or "4 environments" without the caller
// having to remember which form pairs with which count.
func countPhrase(n int, one, many string) string {
	word := many
	if n == 1 {
		word = one
	}
	return strconv.Itoa(n) + " " + word
}

// Counts is what the overview reports about a scoped set.
//
// The fields are separate rather than a formatted string so a caller can test
// them and a renderer can phrase them. "Needs attention" is deliberately its
// own count: an operator paging at 2am wants one number that means "look here",
// and deriving it from the others at call sites is how the two drift.
type Counts struct {
	Total       int
	Running     int
	NeedsLookAt int
}

// Count scopes a set into the overview's counts.
func Count(envs []api.Environment) Counts {
	counts := Counts{Total: len(envs)}
	for _, env := range envs {
		switch stateWord(console.BuildTimeline(env.Actions)) {
		case "Running":
			counts.Running++
		}
		if needsAttention(stateWord(console.BuildTimeline(env.Actions))) {
			counts.NeedsLookAt++
		}
	}
	return counts
}

// stateWord is the human word for a timeline's overall state.
//
// It reads the recorded actions rather than assuming: a timeline whose latest
// resolved phase is uncertain is "Uncertain" even if an earlier phase
// succeeded, because the run's state is the state of its least-settled step.
func stateWord(tl console.Timeline) string {
	var uncertain, failed, running bool
	for _, phase := range tl.Phases {
		switch phase.State {
		case console.PhaseUncertain:
			uncertain = true
		case console.PhaseFailed:
			failed = true
		case console.PhaseRunning:
			running = true
		}
	}
	switch {
	case failed:
		return "Failed"
	case uncertain:
		return "Uncertain"
	case running:
		return "Running"
	}
	if len(tl.Phases) == 0 {
		return "Unknown"
	}
	for _, phase := range tl.Phases {
		if phase.State != console.PhaseComplete && phase.State != console.PhasePending {
			return "Blocked"
		}
	}
	return "Complete"
}

// expiry is the time remaining, rounded down, or the fact that it has passed.
func expiry(at, now time.Time) string {
	if at.IsZero() {
		return "no expiry"
	}
	if !at.After(now) {
		return "expired"
	}
	remaining := at.Sub(now)
	hours := int(remaining.Hours())
	minutes := int(remaining.Minutes()) % 60
	return strconv.Itoa(hours) + "h " + strconv.Itoa(minutes) + "m"
}

// ExpiryForTest exposes the expiry phrasing. It is exported for tests only and
// named so that a reader cannot mistake it for part of the page API.
func ExpiryForTest(at, now time.Time) string { return expiry(at, now) }

// lastUpdate is the latest recorded action time, zero when none was recorded.
func lastUpdate(env api.Environment) time.Time {
	var latest time.Time
	for _, a := range env.Actions {
		if a.StartedAt.After(latest) {
			latest = a.StartedAt
		}
		if a.FinishedAt.After(latest) {
			latest = a.FinishedAt
		}
	}
	return latest
}

// needsAttention reports whether an environment's state is one an operator
// should look at. The predicate lives in one place so the overview counter and
// any future caller cannot disagree about what counts.
func needsAttention(state string) bool {
	return state == "Uncertain" || state == "Failed" || state == "Blocked"
}
