package slo_test

import (
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/slo"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func objective() slo.Objective {
	return slo.Objective{
		Name: "preview-availability", Target: 0.999, Window: 30 * 24 * time.Hour,
		MinEvents: 100, FastBurnThreshold: 14.4, SlowBurnThreshold: 6,
	}
}

func tracker(t *testing.T) *slo.Tracker {
	t.Helper()
	tr, err := slo.NewTracker([]slo.Objective{objective()})
	if err != nil {
		t.Fatalf("tracker: %v", err)
	}
	return tr
}

// events builds n events ending now, spaced a minute apart, with f failures at the end.
func events(n, f int) []slo.Event {
	var out []slo.Event
	for i := 0; i < n; i++ {
		out = append(out, slo.Event{At: now.Add(-time.Duration(n-i) * time.Minute), Success: i >= f})
	}
	// Failures first would bias recency; spread them evenly instead.
	for i := range out {
		out[i].Success = true
	}
	for i := 0; i < f; i++ {
		out[(i*7+3)%n].Success = false
	}
	return out
}

// TestHealthyServiceIsQuiet is the ordinary path.
func TestHealthyServiceIsQuiet(t *testing.T) {
	tr := tracker(t)
	if err := tr.Record("preview-availability", events(1000, 0)...); err != nil {
		t.Fatalf("record: %v", err)
	}
	a, err := tr.Assess("preview-availability", now)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if a.Breached || a.FastBurning || a.SlowBurning {
		t.Fatalf("a healthy service must be quiet, got %+v", a)
	}
	if a.BudgetRemaining != 1 {
		t.Fatalf("a perfect window must hold its whole budget, got %f", a.BudgetRemaining)
	}
	if a.BurnRate != 0 {
		t.Fatalf("no failures must burn nothing, got %f", a.BurnRate)
	}
}

// TestExactTargetHoldsNoBudget: a window at exactly target has consumed everything.
func TestExactTargetHoldsNoBudget(t *testing.T) {
	tr := tracker(t)
	// 0.1% of 1000 = 1 failure lands exactly on a 0.999 target.
	if err := tr.Record("preview-availability", events(1000, 1)...); err != nil {
		t.Fatalf("record: %v", err)
	}
	a, err := tr.Assess("preview-availability", now)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if a.BudgetRemaining > 0.001 || a.BudgetRemaining < -0.001 {
		t.Fatalf("an on-target window must hold ~no budget, got %f", a.BudgetRemaining)
	}
	if a.BurnRate < 0.99 || a.BurnRate > 1.01 {
		t.Fatalf("an on-target window must burn at ~1.0, got %f", a.BurnRate)
	}
}

// TestFastBurnPages: sudden breakage must page, not ticket.
func TestFastBurnPages(t *testing.T) {
	tr := tracker(t)
	// 5% failures against a 0.1% budget = 50x burn.
	if err := tr.Record("preview-availability", events(1000, 50)...); err != nil {
		t.Fatalf("record: %v", err)
	}
	a, err := tr.Assess("preview-availability", now)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if !a.FastBurning {
		t.Fatalf("a 50x burn must page, got %+v", a)
	}
	if !a.Breached {
		t.Fatal("a 95% window against a 99.9% target is breached")
	}
}

// TestSlowBurnTicketsButDoesNotPage: gradual decay gets a ticket, not a page.
func TestSlowBurnTicketsButDoesNotPage(t *testing.T) {
	tr := tracker(t)
	// 8 failures in 1000 = 0.8% vs 0.1% budget = 8x burn: above slow (6), below fast (14.4).
	if err := tr.Record("preview-availability", events(1000, 8)...); err != nil {
		t.Fatalf("record: %v", err)
	}
	a, err := tr.Assess("preview-availability", now)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if !a.SlowBurning {
		t.Fatalf("an 8x burn must ticket, got %+v", a)
	}
	if a.FastBurning {
		t.Fatalf("an 8x burn must not page, got %+v", a)
	}
}

// TestSmallSampleRefusesToJudge: an alert from three events is noise with a pager
// attached.
func TestSmallSampleRefusesToJudge(t *testing.T) {
	tr := tracker(t)
	if err := tr.Record("preview-availability", events(3, 3)...); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, err := tr.Assess("preview-availability", now); !errors.Is(err, slo.ErrInsufficientData) {
		t.Fatalf("a 3-event window must refuse judgment, got %v", err)
	}
}

// TestEmptyWindowRefusesToJudge.
func TestEmptyWindowRefusesToJudge(t *testing.T) {
	tr := tracker(t)
	if _, err := tr.Assess("preview-availability", now); !errors.Is(err, slo.ErrInsufficientData) {
		t.Fatalf("an empty window must refuse judgment, got %v", err)
	}
}

// TestOldEventsLeaveTheWindow: the window bounds the verdict.
func TestOldEventsLeaveTheWindow(t *testing.T) {
	tr := tracker(t)
	old := slo.Event{At: now.Add(-60 * 24 * time.Hour), Success: false}
	if err := tr.Record("preview-availability", old); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := tr.Record("preview-availability", events(1000, 0)...); err != nil {
		t.Fatalf("record: %v", err)
	}
	a, err := tr.Assess("preview-availability", now)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if a.Events != 1000 || a.Failures != 0 {
		t.Fatalf("a 60-day-old failure must leave the 30-day window, got %+v", a)
	}
}

// TestLateEventsAreAccepted: telemetry arrives late, and refusing it would blind the
// window to the incidents most worth seeing.
func TestLateEventsAreAccepted(t *testing.T) {
	tr := tracker(t)
	fresh := events(100, 0)
	late := slo.Event{At: now.Add(-time.Hour), Success: false}
	// Record out of order: fresh first, then the late failure.
	if err := tr.Record("preview-availability", fresh...); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := tr.Record("preview-availability", late); err != nil {
		t.Fatalf("record late: %v", err)
	}
	a, err := tr.Assess("preview-availability", now)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if a.Events != 101 || a.Failures != 1 {
		t.Fatalf("the late event must count, got %+v", a)
	}
}

// TestUnknownObjectiveIsRefused.
func TestUnknownObjectiveIsRefused(t *testing.T) {
	tr := tracker(t)
	if err := tr.Record("nope", slo.Event{At: now}); !errors.Is(err, slo.ErrUnknownObjective) {
		t.Fatalf("recording to an unknown objective must be refused, got %v", err)
	}
	if _, err := tr.Assess("nope", now); !errors.Is(err, slo.ErrUnknownObjective) {
		t.Fatalf("assessing an unknown objective must be refused, got %v", err)
	}
}

// TestObjectiveValidation.
func TestObjectiveValidation(t *testing.T) {
	good := objective()
	for name, mutate := range map[string]func(*slo.Objective){
		"no name":    func(o *slo.Objective) { o.Name = "" },
		"bad target": func(o *slo.Objective) { o.Target = 1.5 },
		"no window":  func(o *slo.Objective) { o.Window = 0 },
		"no minimum": func(o *slo.Objective) { o.MinEvents = 0 },
		"crossed bars": func(o *slo.Objective) {
			o.SlowBurnThreshold, o.FastBurnThreshold = o.FastBurnThreshold, o.SlowBurnThreshold
		},
	} {
		o := good
		mutate(&o)
		if _, err := slo.NewTracker([]slo.Objective{o}); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
	if _, err := slo.NewTracker([]slo.Objective{good, good}); err == nil {
		t.Fatal("duplicate objectives must be refused")
	}
}

// TestBurnRateMath: 2x burn means exhausting in half the window.
func TestBurnRateMath(t *testing.T) {
	tr := tracker(t)
	// 0.2% failures vs 0.1% budget = 2x.
	if err := tr.Record("preview-availability", events(1000, 2)...); err != nil {
		t.Fatalf("record: %v", err)
	}
	a, err := tr.Assess("preview-availability", now)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if a.BurnRate < 1.99 || a.BurnRate > 2.01 {
		t.Fatalf("0.2%% vs 0.1%% budget must burn at 2x, got %f", a.BurnRate)
	}
	if !a.Breached {
		t.Fatalf("99.8%% is below a 99.9%% target, got %+v", a)
	}
	if a.FastBurning || a.SlowBurning {
		t.Fatalf("a 2x burn is neither fast nor slow alerting, got %+v", a)
	}
}

// TestWindowEventsAreSortedForExport.
func TestWindowEventsAreSortedForExport(t *testing.T) {
	tr := tracker(t)
	if err := tr.Record("preview-availability", events(50, 1)...); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, err := tr.WindowEvents("preview-availability", now)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 50 {
		t.Fatalf("expected 50 events, got %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].At.Before(got[i-1].At) {
			t.Fatal("exported events must be time-ordered")
		}
	}
}
