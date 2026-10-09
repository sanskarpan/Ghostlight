// Package slo tracks service-level objectives with burn-rate alerting.
//
// G3.7: "Install SLO instrumentation and metrics pipeline at G3."
//
// An SLO without burn-rate alerting is a dashboard, not an objective: it tells you
// after the month that the month was bad. Burn rate — how fast the error budget is
// being consumed relative to the rate that exactly exhausts it — turns "are we
// breaching?" into "will we breach, and how fast?", which is the question paging
// depends on.
//
// Two windows, because one window lies. A short window alone pages on every transient;
// a long window alone pages after the budget is gone. The fast-burn alert (short
// window, high threshold) catches sudden breakage; the slow-burn alert (long window,
// low threshold) catches gradual decay. Both must fire for their severity, and neither
// fires on insufficient data — an alert computed from three events is noise with a
// pager attached.
package slo

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Errors returned by this package.
var (
	// ErrInsufficientData means the window holds too few events to judge.
	ErrInsufficientData = errors.New("insufficient data to judge burn rate")
	// ErrUnknownObjective means no such SLO is defined.
	ErrUnknownObjective = errors.New("unknown service-level objective")
)

// Objective is one SLO definition.
type Objective struct {
	// Name identifies the objective.
	Name string
	// Target is the required success ratio over the window, such as 0.999.
	Target float64
	// Window bounds the compliance period.
	Window time.Duration
	// MinEvents is the smallest sample the window must hold before any verdict.
	MinEvents int
	// FastBurnThreshold is the burn rate that pages immediately.
	FastBurnThreshold float64
	// SlowBurnThreshold is the burn rate that tickets.
	SlowBurnThreshold float64
}

// Validate rejects an objective that cannot be judged.
func (o Objective) Validate() error {
	switch {
	case o.Name == "":
		return errors.New("an objective must be named")
	case o.Target <= 0 || o.Target >= 1:
		return fmt.Errorf("target %.4f is not a ratio in (0,1)", o.Target)
	case o.Window <= 0:
		return errors.New("an objective needs a compliance window")
	case o.MinEvents <= 0:
		return errors.New("an objective needs a minimum sample")
	case o.FastBurnThreshold <= 0 || o.SlowBurnThreshold <= 0:
		return errors.New("an objective needs positive burn thresholds")
	case o.SlowBurnThreshold >= o.FastBurnThreshold:
		return errors.New("the slow-burn threshold must sit below the fast-burn threshold")
	default:
		return nil
	}
}

// Event is one measured request.
type Event struct {
	// At is when it happened.
	At time.Time
	// Success reports the outcome.
	Success bool
}

// Assessment is what a window supports.
type Assessment struct {
	// Objective names what was judged.
	Objective string
	// Events counts what the window held.
	Events int
	// Failures counts what failed.
	Failures int
	// SuccessRatio is the observed ratio.
	SuccessRatio float64
	// BudgetRemaining is the fraction of error budget left, 1 at perfection.
	BudgetRemaining float64
	// BurnRate is budget consumption relative to the exactly-exhausting rate.
	BurnRate float64
	// FastBurning reports a page-worthy rate.
	FastBurning bool
	// SlowBurning reports a ticket-worthy rate.
	SlowBurning bool
	// Breached reports the window is already below target.
	Breached bool
	// WindowStart bounds the evaluated window.
	WindowStart time.Time
	// EvaluatedAt is when this was computed.
	EvaluatedAt time.Time
}

// Tracker records events and assesses objectives.
type Tracker struct {
	objectives map[string]Objective
	events     map[string][]Event
}

// NewTracker builds an empty tracker.
func NewTracker(objectives []Objective) (*Tracker, error) {
	t := &Tracker{objectives: map[string]Objective{}, events: map[string][]Event{}}
	for _, o := range objectives {
		if err := o.Validate(); err != nil {
			return nil, fmt.Errorf("objective %q: %w", o.Name, err)
		}
		if _, dup := t.objectives[o.Name]; dup {
			return nil, fmt.Errorf("duplicate objective %q", o.Name)
		}
		t.objectives[o.Name] = o
	}
	return t, nil
}

// Record adds events. Out-of-order events are accepted and sorted at assessment:
// telemetry arrives late, and refusing late data would blind the window to exactly
// the incidents most worth seeing.
func (t *Tracker) Record(objective string, events ...Event) error {
	if _, ok := t.objectives[objective]; !ok {
		return fmt.Errorf("%w: %q", ErrUnknownObjective, objective)
	}
	t.events[objective] = append(t.events[objective], events...)
	return nil
}

// Assess evaluates an objective as of a moment.
//
// The window holds the events inside [now-window, now]. Judging on fewer than the
// minimum is refused rather than guessed: an alert from three events is noise with a
// pager attached, and a quiet verdict from three events is a clean bill of health
// nobody earned.
func (t *Tracker) Assess(objective string, now time.Time) (Assessment, error) {
	def, ok := t.objectives[objective]
	if !ok {
		return Assessment{}, fmt.Errorf("%w: %q", ErrUnknownObjective, objective)
	}
	start := now.Add(-def.Window)
	var in []Event
	for _, e := range t.events[objective] {
		if !e.At.Before(start) && !e.At.After(now) {
			in = append(in, e)
		}
	}
	if len(in) < def.MinEvents {
		return Assessment{}, fmt.Errorf("%w: %s holds %d events, needs %d",
			ErrInsufficientData, objective, len(in), def.MinEvents)
	}

	var failures int
	for _, e := range in {
		if !e.Success {
			failures++
		}
	}
	n := float64(len(in))
	successRatio := 1 - float64(failures)/n
	// The budget is the allowed failure fraction; remaining is what is left of it.
	// A perfect window holds the whole budget; a window at exactly target holds none.
	budget := 1 - def.Target
	remaining := 1 - (float64(failures)/n)/budget
	// Burn rate is observed failure fraction over budgeted fraction. 1.0 consumes
	// exactly on schedule; above 1.0 exhausts early.
	burn := (float64(failures) / n) / budget

	a := Assessment{
		Objective: objective, Events: len(in), Failures: failures,
		SuccessRatio: successRatio, BudgetRemaining: remaining, BurnRate: burn,
		Breached:    successRatio < def.Target,
		WindowStart: start, EvaluatedAt: now,
	}
	// Fast burn pages: the budget is going fast enough to exhaust well before the
	// window ends. Slow burn tickets: sustainable for now, decaying over time.
	a.FastBurning = burn >= def.FastBurnThreshold
	a.SlowBurning = burn >= def.SlowBurnThreshold
	return a, nil
}

// Objectives lists defined objectives, stably ordered.
func (t *Tracker) Objectives() []string {
	out := make([]string, 0, len(t.objectives))
	for name := range t.objectives {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// WindowEvents returns the events inside the current window, for export to the
// metrics pipeline. The pipeline moves bytes; judgment stays here.
func (t *Tracker) WindowEvents(objective string, now time.Time) ([]Event, error) {
	def, ok := t.objectives[objective]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownObjective, objective)
	}
	start := now.Add(-def.Window)
	var out []Event
	for _, e := range t.events[objective] {
		if !e.At.Before(start) && !e.At.After(now) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}
