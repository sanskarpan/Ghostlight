package envpage_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/api"
	"github.com/sanskarpan/Ghostlight/internal/a11ygate"
	"github.com/sanskarpan/Ghostlight/internal/console"
	"github.com/sanskarpan/Ghostlight/internal/consolerender"
	"github.com/sanskarpan/Ghostlight/internal/envpage"
)

// envWithState builds an environment whose recorded actions put it in a given
// shape.
func envWithState(id string, outcome console.ActionOutcome, at time.Time) api.Environment {
	return api.Environment{
		ID: id, Scope: "org-a", Generation: 1,
		ExpiresAt: now.Add(3 * time.Hour),
		Actions: []console.RecordedAction{{
			ID: id + "-a1", Phase: console.PhaseFoundationWarmup,
			Outcome: outcome, StartedAt: at, Detail: "recorded",
		}},
	}
}

func render(t *testing.T, page consolerender.ListPage) string {
	t.Helper()
	doc, err := consolerender.RenderListPage(page)
	if err != nil {
		t.Fatalf("RenderListPage: %v", err)
	}
	return doc
}

// The list carries one row per scoped environment, with the columns it declares.
func TestBuildListRendersOneRowPerEnvironment(t *testing.T) {
	envs := []api.Environment{
		envWithState("env-b", console.OutcomeSucceeded, now.Add(-time.Minute)),
		envWithState("env-a", console.OutcomeUncertain, now.Add(-2*time.Minute)),
	}
	page, err := envpage.BuildList(envs, now)
	if err != nil {
		t.Fatalf("BuildList: %v", err)
	}
	if len(page.Tables) != 1 {
		t.Fatalf("tables = %d, want 1", len(page.Tables))
	}
	table := page.Tables[0]
	if len(table.Rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(table.Rows))
	}
	if len(table.Columns) != len(envpage.ListColumns) {
		t.Errorf("columns = %d, want %d", len(table.Columns), len(envpage.ListColumns))
	}
	for i, row := range table.Rows {
		if len(row) != len(table.Columns) {
			t.Errorf("row %d has %d cells, want %d", i, len(row), len(table.Columns))
		}
	}
}

// Rows are ordered by identifier, so the page is deterministic: a list that
// reorders between refreshes loses an operator's place.
func TestBuildListIsOrderedAndDeterministic(t *testing.T) {
	envs := []api.Environment{
		envWithState("env-c", console.OutcomeSucceeded, now),
		envWithState("env-a", console.OutcomeSucceeded, now),
		envWithState("env-b", console.OutcomeSucceeded, now),
	}
	first, err := envpage.BuildList(envs, now)
	if err != nil {
		t.Fatalf("BuildList: %v", err)
	}
	second, err := envpage.BuildList(envs, now)
	if err != nil {
		t.Fatalf("BuildList: %v", err)
	}
	if got := first.Tables[0].Rows[0][0]; got != "env-a" {
		t.Errorf("first row = %q, want env-a", got)
	}
	if render(t, first) != render(t, second) {
		t.Error("BuildList is not deterministic for the same input")
	}
}

// An empty list renders no table and states plainly that there is nothing to
// list. A blank area is indistinguishable from a failure to load.
func TestAnEmptyListStatesThereIsNothingToShow(t *testing.T) {
	page, err := envpage.BuildList(nil, now)
	if err != nil {
		t.Fatalf("BuildList: %v", err)
	}
	if len(page.Tables) != 0 {
		t.Errorf("tables = %d, want 0: an empty table reads as a missing one", len(page.Tables))
	}
	doc := render(t, page)
	if !strings.Contains(doc, "<title>Environments</title>") {
		t.Error("the page must still be titled")
	}
	rep, err := a11ygate.AuditDocument(doc)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(rep.Violations) != 0 {
		t.Errorf("the empty list violates %d accessibility rules", len(rep.Violations))
	}
}

// The state column names the run's least-settled step: an uncertain phase makes
// the environment Uncertain even when an earlier phase succeeded.
func TestTheStateColumnReflectsTheLeastSettledPhase(t *testing.T) {
	env := api.Environment{
		ID: "env-x", Scope: "org-a", Generation: 2,
		ExpiresAt: now.Add(time.Hour),
		Actions: []console.RecordedAction{
			{ID: "a1", Phase: console.PhaseArtifactBuild, Outcome: console.OutcomeSucceeded, StartedAt: now},
			{ID: "a2", Phase: console.PhaseFoundationWarmup, Outcome: console.OutcomeUncertain, StartedAt: now, Detail: "no answer"},
		},
	}
	page, err := envpage.BuildList([]api.Environment{env}, now)
	if err != nil {
		t.Fatalf("BuildList: %v", err)
	}
	row := page.Tables[0].Rows[0]
	state := row[2]
	if state != "Uncertain" {
		t.Errorf("state = %q, want Uncertain", state)
	}
	if strings.Contains(strings.ToLower(state), "complete") {
		t.Error("a run with an uncertain phase must not be listed as complete")
	}
}

// Expiry is stated as remaining time, and a passed expiry says so rather than
// showing a negative countdown.
func TestExpiryReadsAsRemainingTimeOrExpired(t *testing.T) {
	future := envpage.ExpiryForTest(now.Add(3*time.Hour+30*time.Minute), now)
	if !strings.Contains(future, "3h") {
		t.Errorf("expiry = %q, want it to read as remaining hours", future)
	}
	past := envpage.ExpiryForTest(now.Add(-time.Minute), now)
	if past != "expired" {
		t.Errorf("expiry = %q, want expired", past)
	}
	none := envpage.ExpiryForTest(time.Time{}, now)
	if none != "no expiry" {
		t.Errorf("expiry = %q, want no expiry", none)
	}
}

// The overview counts what it says it counts: running and needs-attention are
// separate, and attention includes uncertain, failed and blocked.
func TestOverviewCountsAreHonest(t *testing.T) {
	envs := []api.Environment{
		envWithState("run-1", console.OutcomeRunning, now),
		envWithState("unc-1", console.OutcomeUncertain, now),
		envWithState("fail-1", console.OutcomeFailed, now),
		envWithState("ok-1", console.OutcomeSucceeded, now),
	}
	counts := envpage.Count(envs)
	if counts.Total != 4 {
		t.Errorf("total = %d, want 4", counts.Total)
	}
	if counts.Running != 1 {
		t.Errorf("running = %d, want 1", counts.Running)
	}
	if counts.NeedsLookAt != 2 {
		t.Errorf("needs attention = %d, want 2 (uncertain + failed)", counts.NeedsLookAt)
	}
}

// The overview lists the five most recently touched environments, newest first.
func TestOverviewShowsFiveMostRecentNewestFirst(t *testing.T) {
	var envs []api.Environment
	for i := 0; i < 8; i++ {
		envs = append(envs, envWithState(
			"env-"+string(rune('a'+i)),
			console.OutcomeSucceeded,
			now.Add(-time.Duration(i)*time.Minute),
		))
	}
	page, err := envpage.BuildOverview(envs, now)
	if err != nil {
		t.Fatalf("BuildOverview: %v", err)
	}
	if len(page.Tables) != 1 {
		t.Fatalf("tables = %d, want 1", len(page.Tables))
	}
	rows := page.Tables[0].Rows
	if len(rows) != 5 {
		t.Fatalf("rows = %d, want 5", len(rows))
	}
	if rows[0][0] != "env-a" {
		t.Errorf("first row = %q, want env-a (most recently touched)", rows[0][0])
	}
}

// An overview with nothing to show renders no table rather than an empty one,
// and still passes the gate.
func TestAnEmptyOverviewRenders(t *testing.T) {
	page, err := envpage.BuildOverview(nil, now)
	if err != nil {
		t.Fatalf("BuildOverview: %v", err)
	}
	if len(page.Tables) != 0 {
		t.Errorf("tables = %d, want 0", len(page.Tables))
	}
	doc := render(t, page)
	rep, err := a11ygate.AuditDocument(doc)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(rep.Violations) != 0 {
		t.Errorf("the empty overview violates %d accessibility rules", len(rep.Violations))
	}
}

// Both pages pass the gate with content, which is what the served-bytes
// assertion will check in the server tests.
func TestListAndOverviewPassTheGateWithContent(t *testing.T) {
	envs := []api.Environment{
		envWithState("env-a", console.OutcomeUncertain, now.Add(-time.Minute)),
		envWithState("env-b", console.OutcomeSucceeded, now.Add(-2*time.Minute)),
	}
	for name, build := range map[string]func([]api.Environment, time.Time) (consolerender.ListPage, error){
		"list":     envpage.BuildList,
		"overview": envpage.BuildOverview,
	} {
		page, err := build(envs, now)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		doc := render(t, page)
		rep, err := a11ygate.AuditDocument(doc)
		if err != nil {
			t.Fatalf("%s audit: %v", name, err)
		}
		if len(rep.Violations) != 0 {
			t.Errorf("%s violates %d accessibility rules", name, len(rep.Violations))
			for _, v := range rep.Violations {
				t.Logf("  %s: %s", v.Rule, v.Detail)
			}
		}
	}
}
