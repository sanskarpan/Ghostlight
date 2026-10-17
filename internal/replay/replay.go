// Package replay reproduces a recorded failure from a bounded, declared recipe.
//
// G8.6: "Implement bounded failure-replay recipes and investigation workspace without
// live external effects." The feature behind it is G-F21: "Reproducible failure
// recipes and investigation workspace — exact versions/seed, no side-effectful
// provider replay."
//
// Replaying a failure is the most persuasive debugging tool in this platform, which is
// exactly why it is the most dangerous one. An operator who has watched a preview fail
// twice will paste a URL into anything that offers to "just re-run it". If that
// re-run can make a network call, then the tool is one bad host, one copied branch,
// one phishing email from a colleague, and somebody's production from being poked by
// an operator who was debugging and therefore not reading closely. There is no
// mitigation that survives that scenario, because the operator is not adversarial and
// does not need to be: debugging is the state in which nobody reads the diff.
//
// So the boundary here is structural rather than procedural. It is not "please do not
// make external calls" and it is not a flag an operator sets to confirm they have
// thought about it. A step that declares an external effect is refused at validation
// time, before a plan exists, before an observer is called, and there is no constant,
// no option, and no override that relaxes it. The most a caller can do with an external
// step is learn that it is not allowed to build one. That is the entire point of this
// package: making the dangerous replay unrepresentable, not merely discouraged.
//
// Everything else in the package follows from the same posture. Steps are bounded in
// count and in time because a replay nobody can interrupt is a hung process holding an
// operator's only working session. Effects are a closed enum because a misspelled
// "external_mutate" that parsed as "no effect" would turn a refusal into a silent
// production mutation — failing closed on a typo is the only safe direction for a
// field whose absence of meaning is permission to act. Planning is deterministic so two
// runs of the same recipe are comparable at all, and simulation drives an injected
// observer so that this file contains no net, no os, and no exec, and neither does any
// test in this package.
package replay

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Errors returned by this package.
var (
	// ErrUnknownSchema means the recipe declares a schema version this platform does
	// not know. An unrecognised recipe cannot be checked against the effect rules, so
	// it is refused rather than assumed benign — the same direction as a misspelled
	// effect, and for the same reason.
	ErrUnknownSchema = errors.New("unknown replay recipe schema version")
	// ErrTooManySteps means the recipe declares more steps than a replay may run. An
	// unbounded replay is an unbounded queue: it consumes CPU, memory, operator
	// patience, and CI minutes with no upper edge to interrupt it at.
	ErrTooManySteps = errors.New("replay recipe exceeds the maximum step count")
	// ErrDurationExceedsBound means the summed step timeouts exceed the recipe's
	// declared total budget. Individual step bounds do not add up to a run bound on
	// their own, so the sum is checked separately; otherwise a recipe of sixty
	// individually reasonable steps is an hour-long "quick replay".
	ErrDurationExceedsBound = errors.New("replay recipe's step timeouts exceed its total duration bound")
	// ErrUnboundedStep means a step does not declare a bound. An unbounded step in a
	// replay is a hang with an operator watching, and the operator is watching
	// precisely because something is already wrong.
	ErrUnboundedStep = errors.New("replay step does not declare a bound")
	// ErrUntimedStep means a bounded step declares no timeout. "Bounded" without a
	// time bound means "known to terminate" with no stated budget, which is a claim
	// the platform cannot check and so must not accept.
	ErrUntimedStep = errors.New("bounded replay step declares no timeout")
	// ErrNegativeTimeout means a step declares a negative timeout, which is not a
	// tighter bound but a nonsensical one.
	ErrNegativeTimeout = errors.New("replay step declares a negative timeout")
	// ErrExternalEffectRefused means a step declares an effect that leaves this
	// process's own data. This is the package's central refusal: a replay that can
	// reach the outside world can be pointed at somebody's production, and the
	// operator running it is debugging, not testing, which is exactly the state in
	// which nobody reads the diff.
	ErrExternalEffectRefused = errors.New("external effects are refused in replay recipes")
	// ErrUnknownEffect means a step declares an effect outside the closed enum. The
	// failure is deliberately loud: a misspelled "external_mutate" must never
	// degrade into EffectNone, because unknown fields fail open everywhere else and
	// this is the one place where failing open means somebody's database.
	ErrUnknownEffect = errors.New("unknown replay effect")
	// ErrDuplicateStep means two steps share a name. Step names are how a failing
	// outcome identifies the step that failed, so a duplicate name makes that
	// identification ambiguous, and an ambiguous attribution in an investigation is
	// worse than no attribution because it looks like an answer.
	ErrDuplicateStep = errors.New("duplicate replay step name")
	// ErrIncomplete means a required declaration is missing: a nameless recipe, a
	// nameless step, or a recipe with no steps at all.
	ErrIncomplete = errors.New("replay recipe is missing a required declaration")
	// ErrOutcomeMismatch means the observer's reported outcome contradicts the plan's
	// report. A replay whose narration and ledger disagree has produced evidence that
	// would be believed, which is the failure mode this whole platform is built to
	// avoid.
	ErrOutcomeMismatch = errors.New("observer outcome contradicts the replay plan")
	// ErrStepExceedsBudget means one step's timeout exceeds what remains of the
	// recipe's total budget. A recipe can pass the summed-timeout check and still
	// contain a single step that could overrun the whole run, so the step is checked
	// against the budget in hand at that point in the plan.
	ErrStepExceedsBudget = errors.New("replay step exceeds the remaining total duration budget")
	// ErrClockRewound means a step completed before the step before it started. The
	// replay cannot claim a plan or an outcome about a sequence it could not observe,
	// and a non-monotonic clock is far more likely to be a broken clock than a real
	// result.
	ErrClockRewound = errors.New("replay clock rewound between steps")
	// ErrUnknownStep means a step in a plan is not declared by the recipe it came
	// from. It is unreachable through Plan and Simulate, which validate first, and it
	// exists because the safety arguments in this file assume a plan and its recipe
	// agree — an assumption worth checking rather than documenting, given that the
	// thing being protected is somebody's production.
	ErrUnknownStep = errors.New("replay plan names a step the recipe does not declare")
)

// CurrentSchema is the replay recipe schema version this platform validates.
const CurrentSchema = "ghostlight.replay/v1"

// Bounds on what a replay may consume. They are constants rather than fields for the
// same reason the effect rules are constants: a caller who can raise the bounds can
// also raise them past the point where the tool is safe to leave running.
const (
	// MaxSteps is the largest number of steps a replay recipe may declare. A replay is
	// an investigation aid, not a load test; a recipe with more steps than this is a
	// suite that belongs in the harness package.
	MaxSteps = 64
	// MaxTotalDuration is the ceiling on a recipe's declared total duration. Ten
	// minutes is long enough to reproduce a real failure and short enough that an
	// operator who has walked away comes back to a finished run.
	MaxTotalDuration = 10 * time.Minute
)

// Effect is the side effect a step might want. It is a closed enum with exactly one
// entry per class of thing a step could touch, and nothing outside it is accepted.
//
// The ordering is deliberate and load-bearing: unknown, harmless, local, external.
// An effect must sort higher than EffectLocal to be refused, so anything new that
// someone adds to this enum — a queue, a cache, a webhook — is external by default
// until someone argues otherwise in review. There is no third state in which a new
// effect is neither allowed nor refused.
type Effect string

const (
	// EffectNone means the step is pure computation: no I/O of any kind. It is
	// allowed only for a step that declares a bound anyway, because a step whose
	// author could not say what it touches is not a step anybody should run.
	EffectNone Effect = "none"
	// EffectRead means the step reads data this process already holds. Reads of
	// platform-owned data are recoverable by definition: nothing changed.
	EffectRead Effect = "read"
	// EffectWriteLocal means the step writes inside this process's own data: an
	// in-memory workspace, a temporary file, a sandbox scratch directory. It is
	// allowed because it is recoverable — the operator's own investigation state — and
	// it is the only permitted way to produce data during a replay.
	EffectWriteLocal Effect = "write_local"
	// EffectExternalNetwork means the step makes a network request. It is refused.
	EffectExternalNetwork Effect = "external_network"
	// EffectExternalMutate means the step changes something outside this process.
	// It is refused, and it is refused twice over: a network call that changes state
	// is both an external effect and a mutation, and the tool that has no path to it
	// is the tool that cannot be aimed at a production database.
	EffectExternalMutate Effect = "external_mutate"
)

// effectIsEffect reports whether an effect string names a member of the closed enum.
//
// The error names the offending value rather than saying "invalid", because the whole
// reason this check is loud is that a typo in this field is indistinguishable from a
// permission slip: "external_mutate" misspelled parses to nothing at all here, and a
// decoder that treated nothing as EffectNone would hand a production mutation a pass.
func effectIsEffect(e Effect) bool {
	switch e {
	case EffectNone, EffectRead, EffectWriteLocal, EffectExternalNetwork, EffectExternalMutate:
		return true
	}
	return false
}

// effectIsExternalEffect reports whether an effect reaches outside this process.
//
// This is an explicit membership test, and the version before it was not. That version
// compared `e > EffectWriteLocal`, on the assumption that a string-typed enum orders by
// declaration. It does not: Go compares strings lexicographically, so
// "external_network" > "write_local" is false because 'e' sorts before 'w'. Both
// external effects therefore reported as harmless, which made Validate's refusal of
// them unreachable and left the package's load-bearing security property inverted while
// reading as correct in review.
//
// The enumerating form is deliberate. "It grows automatically" is a virtue only when
// the automatic behaviour is the safe one, and here it silently was not, so a new
// effect must be classified by a person who has read this comment.
func effectIsExternalEffect(e Effect) bool {
	switch e {
	case EffectExternalNetwork, EffectExternalMutate:
		return true
	default:
		return false
	}
}

// RequiresIsolation reports whether an effect means the step must not touch the
// outside world.
//
// Every effect below the external line is reachable without an isolation boundary;
// every effect at or above it is not. That makes this the single question a caller
// needs answered before wiring a replay into anything else: if a step RequiresIsolation,
// this package will refuse to validate it, and refusing is not configurable.
func RequiresIsolation(e Effect) bool {
	return effectIsExternalEffect(e)
}

// Step is one named action in a replay recipe.
type Step struct {
	// Name identifies the step. A failing outcome names it, so it is how the operator
	// finds the thing that broke.
	Name string
	// Effect is what the step touches. It is mandatory: an omitted Effect is the zero
	// value, and the zero value of the field that decides whether a step can reach
	// production must not be "no effect" without a declaration saying so.
	Effect Effect
	// Timeout bounds the step. It is optional on the struct because omitting it is a
	// mistake worth naming, and Validate turns that mistake into ErrUntimedStep rather
	// than quietly substituting a default.
	Timeout time.Duration
	// Bounded declares that the step is known to terminate. It is not inferred from
	// Timeout: an author can write a timeout into a loop that never checks it, so the
	// bound is a claim the recipe makes explicitly and the platform records.
	Bounded bool
}

// Recipe is a named, versioned, ordered list of steps plus the bounds it declares.
type Recipe struct {
	// Name identifies the recipe in the catalog.
	Name string `json:"name"`
	// SchemaVersion is the contract version. An unknown one is refused, not coerced.
	SchemaVersion string `json:"schema_version"`
	// Steps are the actions, in order. Order is part of the recipe: a replay is a
	// reproduction, and a reproduction with shuffled steps is a different experiment.
	Steps []Step `json:"steps"`
	// MaxSteps is the recipe's declared step bound. Zero means the platform bound.
	MaxSteps int `json:"max_steps"`
	// MaxTotalDuration is the recipe's declared duration bound. Zero means the
	// platform bound.
	MaxTotalDuration time.Duration `json:"max_total_duration"`
	// Seed fixes whatever nondeterminism the replayed code has. A replay with an
	// unpinned seed is a coin flip that happens to have worked once.
	Seed int64 `json:"seed"`
	// Version identifies the artifact under replay. A reproduction of a different
	// build is an anecdote.
	Version string `json:"version"`
}

// stepBound resolves a recipe's declared step bound, defaulting to the platform bound.
func (r Recipe) stepBound() int {
	if r.MaxSteps > 0 {
		return r.MaxSteps
	}
	return MaxSteps
}

// durationBound resolves a recipe's declared duration bound, defaulting to the
// platform bound.
func (r Recipe) durationBound() time.Duration {
	if r.MaxTotalDuration > 0 {
		return r.MaxTotalDuration
	}
	return MaxTotalDuration
}

// Planned is one step resolved into what will actually be executed: its order, its
// effect, the budget it may use, and the clock window it must sit inside.
//
// Budget is the point of the type. A step's own timeout is what it *may* take; Budget
// is what it *can* take given where it sits in the plan. A recipe can pass the
// summed-timeout check and still put a single step at the front whose timeout exceeds
// everything after it, and without a per-step budget that recipe runs long.
type Planned struct {
	// Index is the step's position, starting at zero.
	Index int
	// Name identifies the step.
	Name string
	// Effect is the declared effect, already checked against the effect rules.
	Effect Effect
	// Timeout is the step's declared timeout.
	Timeout time.Duration
	// Budget is the smaller of the step's timeout and the total budget remaining
	// before this step, so the plan cannot overrun its own bound.
	Budget time.Duration
	// Deadline is when this step must be finished, measured from the start of the
	// run. It is what a caller uses to bound a real context, and it is why Plan needs
	// to know the start time.
	Deadline time.Time
	// Cumulative is the total timeout of every step up to and including this one. The
	// final entry equals the recipe's total declared duration.
	Cumulative time.Duration
	// Bounded restates the step's bound declaration in the plan, so a plan reviewed on
	// its own still shows whether the step terminates.
	Bounded bool
}

// validatePlan re-checks a resolved plan against the safety rules.
//
// It is called from both Plan and Simulate. The effect refusal is the load-bearing
// check and it runs on every planned step, which is what makes "no live external
// effects" a property of this package rather than a property of its only entry point:
// there is no way to obtain a plan containing an external step and have it accepted.
func validatePlan(plan []Planned) error {
	if len(plan) == 0 {
		return fmt.Errorf("%w: the plan has no steps", ErrIncomplete)
	}
	if len(plan) > MaxSteps {
		return fmt.Errorf("%w: %d steps exceeds %d", ErrTooManySteps, len(plan), MaxSteps)
	}
	var errs []error
	for _, p := range plan {
		if p.Name == "" {
			errs = append(errs, fmt.Errorf("%w: planned step %d has no name", ErrIncomplete, p.Index))
		}
		if !effectIsEffect(p.Effect) {
			errs = append(errs, fmt.Errorf("%w: step %q declared %q", ErrUnknownEffect, p.Name, p.Effect))
		}
		if !p.Bounded {
			errs = append(errs, fmt.Errorf("%w: step %q", ErrUnboundedStep, p.Name))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	// The external check is a single decision with a single sentinel, made after the
	// structural checks so that the operator fixing a recipe sees the ordinary
	// problems and the alarming one all at once.
	for _, p := range plan {
		if effectIsExternalEffect(p.Effect) {
			errs = append(errs, fmt.Errorf("%w: step %q declares %q", ErrExternalEffectRefused, p.Name, p.Effect))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// Validate checks a replay recipe against the platform's rules.
//
// Validation is total and every failure is reported at once, because the alternative
// is an operator fixing one problem per round trip while a preview is down and the
// recipe author is somewhere else. errors.Join keeps every sentinel intact so a caller
// can still ask whether the failure was an external effect or a typo without matching
// on strings.
//
// The order of the rules is the argument. Schema first, because an unrecognised
// recipe cannot be checked at all. Count and duration second, because a recipe that
// cannot be run in bounded time and space is not debuggable regardless of what it
// touches. Names and effects third. The external refusal last but unconditional —
// it is not a check that runs when everything else passes, it is a check that runs
// always, and it is joined with everything else rather than short-circuited, because
// the operator who gets one error message learns one fact.
func Validate(r Recipe) error {
	var errs []error

	if r.Name == "" {
		errs = append(errs, fmt.Errorf("%w: name", ErrIncomplete))
	}
	// A reproduction of a different build is an anecdote, so the artifact under replay
	// is required for the same reason the recipe is named.
	if r.Version == "" {
		errs = append(errs, fmt.Errorf("%w: version of the artifact under replay", ErrIncomplete))
	}
	if r.SchemaVersion != CurrentSchema {
		errs = append(errs, fmt.Errorf("%w: %q, expected %q", ErrUnknownSchema, r.SchemaVersion, CurrentSchema))
	}
	if len(r.Steps) == 0 {
		errs = append(errs, fmt.Errorf("%w: at least one step", ErrIncomplete))
	}

	// The platform's hard ceiling is checked against the recipe's own declared bound,
	// not only against the declared count. A recipe cannot raise its own limits: it
	// can only ask for less, and the smaller of the two wins.
	maxSteps := r.stepBound()
	if maxSteps > MaxSteps {
		errs = append(errs, fmt.Errorf("%w: recipe declares a bound of %d, above the platform ceiling of %d",
			ErrTooManySteps, maxSteps, MaxSteps))
	}
	if len(r.Steps) > maxSteps {
		errs = append(errs, fmt.Errorf("%w: %d steps exceeds %d", ErrTooManySteps, len(r.Steps), maxSteps))
	}

	maxDuration := r.durationBound()
	if maxDuration > MaxTotalDuration {
		errs = append(errs, fmt.Errorf("%w: recipe declares %s, above the platform ceiling of %s",
			ErrDurationExceedsBound, maxDuration, MaxTotalDuration))
	}

	// The summed-timeout check is separate from the per-step checks because a
	// per-step timeout is a promise about one step and says nothing about the sum. Sixty
	// steps that each take nine seconds is nine minutes of "quick replay", and it is
	// built entirely out of individually reasonable declarations.
	var total time.Duration
	for i, s := range r.Steps {
		if s.Name == "" {
			errs = append(errs, fmt.Errorf("%w: step %d has no name", ErrIncomplete, i))
		}
		if !effectIsEffect(s.Effect) {
			errs = append(errs, fmt.Errorf("%w: step %q declared %q", ErrUnknownEffect, s.Name, s.Effect))
		}
		if s.Timeout < 0 {
			errs = append(errs, fmt.Errorf("%w: step %q", ErrNegativeTimeout, s.Name))
		}
		if !s.Bounded {
			errs = append(errs, fmt.Errorf("%w: step %q", ErrUnboundedStep, s.Name))
			continue
		}
		if s.Timeout <= 0 {
			errs = append(errs, fmt.Errorf("%w: step %q", ErrUntimedStep, s.Name))
			continue
		}
		total += s.Timeout
	}
	if total > maxDuration {
		errs = append(errs, fmt.Errorf("%w: step timeouts sum to %s against a bound of %s",
			ErrDurationExceedsBound, total, maxDuration))
	}

	// Duplicate names go last among the per-step checks because they are the cheapest
	// to fix and the least alarming; the author rewrites a name and revalidates.
	seen := make(map[string]bool, len(r.Steps))
	for i, s := range r.Steps {
		if s.Name == "" {
			continue
		}
		if seen[s.Name] {
			errs = append(errs, fmt.Errorf("%w: %q at step %d", ErrDuplicateStep, s.Name, i))
			continue
		}
		seen[s.Name] = true
	}

	// The external refusal. It is not conditional on anything above having passed, and
	// it is not overridable: a recipe that names an external effect is rejected, and
	// the rejection names the step so the operator can see precisely which line of
	// their recipe is the problem.
	for i, s := range r.Steps {
		if effectIsExternalEffect(s.Effect) {
			errs = append(errs, fmt.Errorf("%w: step %q (index %d) declares %q; a replay reproduces a failure, it does not act on the world it reproduced it in",
				ErrExternalEffectRefused, s.Name, i, s.Effect))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// Plan resolves a recipe into the ordered plan it will be executed as.
//
// The plan is a pure function of the recipe and the supplied start time. No clock is
// read, no map is iterated without sorting, and no pointer identity leaks into the
// result, so two calls with equal inputs produce byte-identical plans. That is not
// tidiness: a replay is only reproducible if the thing that decided what to run is
// itself reproducible, and a plan that varies run to run cannot be diffed, cached, or
// compared between the run that reproduced the failure and the run that claims to have
// fixed it.
//
// The start time is a parameter rather than read from the clock so that determinism is
// achievable at all, and so a caller replaying yesterday's recipe can reproduce
// yesterday's deadlines.
func Plan(r Recipe, start time.Time) ([]Planned, error) {
	if err := Validate(r); err != nil {
		return nil, err
	}

	plan := make([]Planned, 0, len(r.Steps))
	remaining := r.durationBound()
	var cumulative time.Duration
	for i, s := range r.Steps {
		budget := s.Timeout
		if remaining < budget {
			// A recipe can pass the summed-timeout check and still leave a single step
			// unable to finish before the run ends. Clamping here is what makes the
			// per-step bound honest: the step is told the time that actually exists,
			// not the time the recipe hoped for.
			budget = remaining
		}
		cumulative += s.Timeout
		remaining -= s.Timeout
		plan = append(plan, Planned{
			Index:      i,
			Name:       s.Name,
			Effect:     s.Effect,
			Timeout:    s.Timeout,
			Budget:     budget,
			Deadline:   start.Add(cumulative),
			Cumulative: cumulative,
			Bounded:    s.Bounded,
		})
	}

	// The plan is checked against the same safety rules the recipe was. Cheap, and it
	// is what makes the guarantee survive a future code path that builds a Plan by
	// hand.
	if err := validatePlan(plan); err != nil {
		return nil, err
	}
	return plan, nil
}

// Simulated is what the observer reports for one step.
//
// The timestamps are the observer's, not this package's. A replay reads no clock while
// it runs, so the window each step claims is the one the thing being simulated
// reported, and a run whose steps report nothing has no duration to claim either.
type Simulated struct {
	// Outcome is the step's simulated result.
	Outcome SimulatedOutcome
	// Detail is operator-facing context.
	Detail string
	// StartedAt and FinishedAt bound the step as the observer saw it.
	StartedAt  time.Time
	FinishedAt time.Time
}

// Observer is the injected source of a simulation.
//
// It is an interface with no second implementation in this package on purpose. The
// caller supplies whatever the replay is being simulated against, and this package
// cannot do I/O on its own because it has no handle to anything: there is no file, no
// socket, and no process it could reach even if a caller wanted it to. The absence of
// net, os, and exec from these files is the enforcement, not a promise in a comment.
//
// A conforming observer records the attempt and refuses it. It reports a failure —
// ErrExternalEffectRefused is the right answer — and the replay names the step.
type Observer interface {
	// Simulate performs one step's simulated effect. Implementations must not perform
	// the effect itself; the effect declaration is what this package refuses, not
	// something the observer is trusted to honour.
	Simulate(ctx context.Context, step Planned) (Simulated, error)
}

// ObserverFunc adapts a function to Observer, matching the option style used elsewhere
// in this repository.
type ObserverFunc func(ctx context.Context, step Planned) (Simulated, error)

// Simulate implements Observer.
func (f ObserverFunc) Simulate(ctx context.Context, step Planned) (Simulated, error) {
	return f(ctx, step)
}

// Outcome is a replay verdict. The names follow SPEC.md section 9 so a replay verdict
// and a harness verdict read the same way in the same dashboard.
type Outcome string

const (
	// OutcomePass means every step simulated successfully.
	OutcomePass Outcome = "pass"
	// OutcomeFail means a step did not. FailedStep names it.
	OutcomeFail Outcome = "fail"
	// OutcomeInconclusive means the replay could not tell. It never passes, for the
	// same reason a harness inconclusive does: the platform would rather report
	// nothing than report something it cannot support.
	OutcomeInconclusive Outcome = "inconclusive"
	// OutcomeCanceled means the run stopped before a verdict.
	OutcomeCanceled Outcome = "canceled"
)

// SimulatedOutcome is the verdict of a single simulated step.
type SimulatedOutcome string

const (
	// StepPass means the step simulated successfully.
	StepPass SimulatedOutcome = "pass"
	// StepFail means the step simulated a failure. This is what a replay of a failure
	// is looking for.
	StepFail SimulatedOutcome = "fail"
	// StepError means the step could not be simulated at all.
	StepError SimulatedOutcome = "error"
)

// Result is one simulated step's record.
type Result struct {
	// Step is the plan entry that ran.
	Step Planned
	// Outcome is the simulated result.
	Outcome SimulatedOutcome
	// Detail is operator-facing context.
	Detail string
	// Err is the observer's error, if any.
	Err error
	// StartedAt and FinishedAt bound the step.
	StartedAt  time.Time
	FinishedAt time.Time
}

// Attempt is one simulated effect.
type Attempt struct {
	// Index is the plan entry that was attempted.
	Index int
	// StepName identifies the step.
	StepName string
	// Effect is the effect the step declared.
	Effect Effect
	// Outcome is what the observer reported.
	Outcome SimulatedOutcome
	// Err is the observer's error, if any.
	Err error
}

// Report is what a replay run did and concluded.
type Report struct {
	// RecipeID identifies the recipe that was replayed.
	RecipeID string
	// Outcome is the run's verdict.
	Outcome Outcome
	// FailedStep names the step that failed, so the operator does not have to search
	// the plan for it.
	FailedStep string
	// Detail explains the verdict.
	Detail string
	// Attempts are the steps that were simulated, in order.
	Attempts []Attempt
	// StartedAt and FinishedAt bound the run.
	StartedAt  time.Time
	FinishedAt time.Time
	// DroppedSteps counts planned steps that never ran because the run had already
	// reached a verdict. It is reported rather than hidden, because "the replay passed"
	// must never mean "the replay stopped early and looked fine".
	DroppedSteps int
}

// Elapsed reports how long the run took.
func (r Report) Elapsed() time.Duration { return r.FinishedAt.Sub(r.StartedAt) }

// Simulate runs a recipe's plan against an injected observer and performs no I/O of
// any kind itself.
//
// The observer is the only thing that could touch the world, and this package has
// already refused any plan whose steps declare an external effect, so what reaches the
// observer is a plan made of reads and local writes. The run stops at the first
// failing step: a replay that continues past a failure is running steps under
// conditions the recipe never described, and its later results would be reported
// alongside a failure as though they were comparable.
//
// The returned error is non-nil only when the run could not produce a verdict. A step
// failing is a verdict — a failing one — and it is returned in the Report, because an
// operator debugging a failure needs the failure, not an exception.
func Simulate(r Recipe, obs Observer, start time.Time) (Report, error) {
	rep := Report{RecipeID: r.Name, StartedAt: start}

	// The plan is validated inside Plan, so a bad recipe never reaches the observer.
	// Re-validating through the plan keeps that property explicit at the point where
	// it matters: no observer call happens on an unvalidated plan.
	plan, err := Plan(r, start)
	if err != nil {
		rep.Outcome = OutcomeInconclusive
		rep.FinishedAt = start
		rep.Detail = "the recipe was refused, so nothing was replayed: " + err.Error()
		return rep, err
	}
	if obs == nil {
		rep.Outcome = OutcomeInconclusive
		rep.FinishedAt = start
		rep.Detail = "no observer to replay against"
		return rep, fmt.Errorf("%w: no observer", ErrIncomplete)
	}

	// The run's own budget is the plan's final cumulative timeout, which equals the
	// sum of the steps' timeouts and is already within the recipe's bound. A
	// replay that respects it cannot outlive the window the operator was promised.
	runBudget := plan[len(plan)-1].Cumulative
	ctx, cancel := context.WithTimeout(context.Background(), runBudget)
	defer cancel()

	// lastFinish is the newest end time any step reported. A run's window closes at
	// the end of its last step, and this package reads no clock of its own while a
	// replay runs — so if no step reported an end time, the run has none to claim and
	// falls back to its own declared budget.
	var lastFinish time.Time

	for _, p := range plan {
		sim, err := obs.Simulate(ctx, p)
		res := Result{
			Step: p, Outcome: sim.Outcome, Detail: sim.Detail, Err: err,
			StartedAt: sim.StartedAt, FinishedAt: sim.FinishedAt,
		}
		rep.Attempts = append(rep.Attempts, Attempt{
			Index: p.Index, StepName: p.Name, Effect: p.Effect, Outcome: sim.Outcome, Err: err,
		})

		if ctx.Err() == context.DeadlineExceeded {
			// The budget expired. Whether a step also failed is reported, but the
			// cancellation is the headline: a run that was cut off has not
			// demonstrated anything about the steps it never reached.
			rep.Outcome = OutcomeCanceled
			rep.FailedStep = p.Name
			rep.Detail = "the replay ran out of its declared budget during " + p.Name
			rep.FinishedAt = start.Add(runBudget)
			rep.DroppedSteps = len(plan) - 1 - p.Index
			return rep, nil
		}

		switch {
		case err != nil:
			// An observer that could not simulate a step is not a step that failed.
			// Reporting it as a failure would name a step the operator then reads, and
			// sends them to the wrong code — the package's own convention, borrowed
			// from the harness, is that inconclusive means the tooling could not tell
			// and never a softer fail.
			rep.Outcome = OutcomeInconclusive
			rep.Detail = "step " + p.Name + " could not be simulated: " + err.Error()
			rep.FinishedAt = res.FinishedAt
			rep.DroppedSteps = len(plan) - 1 - p.Index
			return rep, nil
		case sim.Outcome == StepPass:
			// Carry on. The clock check below runs for every step, including this one.
		case sim.Outcome == StepFail:
			rep.Outcome = OutcomeFail
			rep.FailedStep = p.Name
			rep.Detail = "step " + p.Name + " simulated a failure: " + sim.Detail
			rep.FinishedAt = res.FinishedAt
			rep.DroppedSteps = len(plan) - 1 - p.Index
			return rep, nil
		case sim.Outcome == StepError:
			// The observer said it could not simulate. That is the platform's own
			// machinery failing, not the replayed code failing, and reporting it as a
			// replay failure would blame the code for a broken harness.
			rep.Outcome = OutcomeInconclusive
			rep.FailedStep = p.Name
			rep.Detail = "step " + p.Name + " could not be evaluated: " + sim.Detail
			rep.FinishedAt = res.FinishedAt
			rep.DroppedSteps = len(plan) - 1 - p.Index
			return rep, nil
		default:
			// An unrecognised outcome is refused rather than counted as a pass. The
			// same fail-closed logic as an unknown effect applies: a step that returns
			// something nobody anticipated must not be allowed to look successful.
			rep.Outcome = OutcomeInconclusive
			rep.FailedStep = p.Name
			rep.Detail = fmt.Sprintf("step %q reported the unknown outcome %q, which is not a pass",
				p.Name, sim.Outcome)
			rep.FinishedAt = res.FinishedAt
			rep.DroppedSteps = len(plan) - 1 - p.Index
			return rep, nil
		}

		if res.FinishedAt.Before(res.StartedAt) {
			// The observer's clock went backwards mid-run. The report would claim a
			// sequence it did not observe, and a non-monotonic clock is far more
			// likely to be a broken clock than a genuine result.
			rep.Outcome = OutcomeInconclusive
			rep.FailedStep = p.Name
			rep.Detail = "step " + p.Name + " finished before it started: the replay cannot trust its own clock"
			rep.FinishedAt = res.StartedAt
			rep.DroppedSteps = len(plan) - 1 - p.Index
			return rep, nil
		}
	}

	rep.Outcome = OutcomePass
	// The run's window closes at the end of its last step, which is the only end time
	// this package has: it reads no clock of its own while a replay runs.
	if !lastFinish.IsZero() {
		rep.FinishedAt = lastFinish
	} else {
		rep.FinishedAt = start.Add(runBudget)
	}
	rep.Detail = fmt.Sprintf("every step of %s simulated successfully", r.Name)
	return rep, nil
}
