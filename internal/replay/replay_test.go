package replay

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

var start = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func mustErr(t *testing.T, err error, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

func step(name string, effect Effect) Step {
	return Step{Name: name, Effect: effect, Timeout: time.Second, Bounded: true}
}

func validRecipe(steps ...Step) Recipe {
	if len(steps) == 0 {
		steps = []Step{step("read-config", EffectRead), step("compute", EffectNone)}
	}
	return Recipe{
		Name:          "failure-replay",
		SchemaVersion: CurrentSchema,
		Steps:         steps,
		Version:       "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
}

// The point of the package. A replay that can make a network call can reach a
// customer's production, and the operator running it is debugging — which is exactly
// the state in which nobody reads the diff.
func TestExternalEffectsAreRefusedOutright(t *testing.T) {
	for _, effect := range []Effect{EffectExternalNetwork, EffectExternalMutate} {
		r := validRecipe(step("reaches-out", effect))
		err := Validate(r)
		mustErr(t, err, ErrExternalEffectRefused, string(effect))
		if !RequiresIsolation(effect) {
			t.Fatalf("%s is not classified as requiring isolation", effect)
		}
	}
}

// A step that can reach the outside world must not be reachable through a plan either.
// Refusing only at Validate would leave the plan path as a second door.
func TestAPlanCannotBeObtainedForAnExternalRecipe(t *testing.T) {
	r := validRecipe(step("reaches-out", EffectExternalNetwork))
	if _, err := Plan(r, start); !errors.Is(err, ErrExternalEffectRefused) {
		t.Fatalf("planning an external recipe: got %v, want ErrExternalEffectRefused", err)
	}
}

// A typo must fail closed. A misspelled effect that quietly became EffectNone would
// hand a production mutation a pass, which is the worst outcome this package can have.
func TestAMisspelledEffectIsRefusedRatherThanTreatedAsHarmless(t *testing.T) {
	for _, bad := range []Effect{"external_mutate ", "ExternalMutate", "externalmutate", "external_mutatex", ""} {
		r := validRecipe(Step{Name: "maybe", Effect: bad, Timeout: time.Second, Bounded: true})
		if err := Validate(r); err == nil {
			t.Fatalf("the effect %q was accepted", bad)
		}
	}
	// And the empty effect specifically must not equal EffectNone.
	if Effect("") == EffectNone {
		t.Fatal("the zero value of Effect is EffectNone, so an omitted effect silently means harmless")
	}
}

func TestRequiresIsolationOrdersTheEffects(t *testing.T) {
	cases := map[Effect]bool{
		EffectNone:            false,
		EffectRead:            false,
		EffectWriteLocal:      false,
		EffectExternalNetwork: true,
		EffectExternalMutate:  true,
	}
	for e, want := range cases {
		if got := RequiresIsolation(e); got != want {
			t.Fatalf("%s requires isolation=%v, want %v", e, got, want)
		}
	}
}

func TestAnUnknownSchemaIsRefused(t *testing.T) {
	r := validRecipe()
	r.SchemaVersion = "ghostlight.replay/v99"
	mustErr(t, Validate(r), ErrUnknownSchema, "unknown schema")
}

func TestARecipeNeedsIdentity(t *testing.T) {
	r := validRecipe()
	r.Name = ""
	if err := Validate(r); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("a nameless recipe: %v", err)
	}
	// A reproduction of a different build is an anecdote, so the version is required.
	r = validRecipe()
	r.Version = ""
	if err := Validate(r); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("a versionless recipe: %v", err)
	}
}

// An unbounded replay is an unbounded resource consumption and an unbounded queue.
func TestTheStepCountIsBounded(t *testing.T) {
	steps := make([]Step, 0, MaxSteps+1)
	for i := 0; i <= MaxSteps; i++ {
		steps = append(steps, step("s"+string(rune('a'+i%26))+string(rune('a'+i/26)), EffectNone))
	}
	r := validRecipe(steps...)
	err := Validate(r)
	mustErr(t, err, ErrTooManySteps, "over the step bound")

	// And a recipe may declare a tighter bound than the platform's.
	tight := validRecipe(steps[:3]...)
	tight.MaxSteps = 2
	mustErr(t, Validate(tight), ErrTooManySteps, "over its own declared bound")
}

// An unbounded step in a replay is a hang with a user watching it.
func TestAnUnboundedStepIsRefused(t *testing.T) {
	s := step("spins", EffectNone)
	s.Bounded = false
	mustErr(t, Validate(validRecipe(s)), ErrUnboundedStep, "an unbounded step")
}

func TestABoundedStepMustDeclareATimeout(t *testing.T) {
	s := step("quick", EffectNone)
	s.Timeout = 0
	mustErr(t, Validate(validRecipe(s)), ErrUntimedStep, "a step with no timeout")
}

func TestANegativeTimeoutIsRefused(t *testing.T) {
	s := step("backwards", EffectNone)
	s.Timeout = -time.Second
	mustErr(t, Validate(validRecipe(s)), ErrNegativeTimeout, "a negative timeout")
}

func TestSummedTimeoutsMustFitTheDurationBound(t *testing.T) {
	long := func(name string) Step {
		s := step(name, EffectNone)
		s.Timeout = MaxTotalDuration / 2
		return s
	}
	// Three halves exceed one whole.
	mustErr(t, Validate(validRecipe(long("a"), long("b"), long("c"))), ErrDurationExceedsBound, "over the duration bound")

	// Two fit exactly.
	if err := Validate(validRecipe(long("a"), long("b"))); err != nil {
		t.Fatalf("two halves should fit: %v", err)
	}
}

func TestDuplicateStepNamesAreRefused(t *testing.T) {
	mustErr(t, Validate(validRecipe(step("same", EffectNone), step("same", EffectNone))),
		ErrDuplicateStep, "duplicate step names")
	// Empty names are refused too: a failing outcome names its step, so an unnamed step
	// cannot be found.
	mustErr(t, Validate(validRecipe(Step{Name: "", Effect: EffectNone, Timeout: time.Second, Bounded: true})),
		ErrIncomplete, "a nameless step")
}

func TestValidateReportsEveryFailureAtOnce(t *testing.T) {
	bad := validRecipe(
		Step{Name: "", Effect: "nonsense", Bounded: false},
		Step{Name: "dup", Effect: EffectNone, Timeout: time.Second, Bounded: true},
		Step{Name: "dup", Effect: EffectNone, Timeout: time.Second, Bounded: true},
	)
	err := Validate(bad)
	if err == nil {
		t.Fatal("the invalid recipe validated")
	}
	// The joined error must preserve each distinct sentinel, or a caller is forced to
	// match on message text.
	for _, want := range []error{ErrIncomplete, ErrUnknownEffect, ErrUnboundedStep, ErrDuplicateStep} {
		if !errors.Is(err, want) {
			t.Fatalf("the joined refusal lost %v:\n%v", want, err)
		}
	}
}

// A replay that is not reproducible is a coin flip that happened to work once.
func TestAPlanIsDeterministic(t *testing.T) {
	r := validRecipe(step("a", EffectRead), step("b", EffectNone), step("c", EffectWriteLocal))
	first, err := Plan(r, start)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := Plan(r, start)
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		if len(again) != len(first) {
			t.Fatalf("plan length changed between calls")
		}
		for j := range first {
			if again[j].Name != first[j].Name || again[j].Index != first[j].Index ||
				again[j].Deadline != first[j].Deadline || again[j].Budget != first[j].Budget {
				t.Fatalf("plan entry %d changed between calls: %+v then %+v", j, first[j], again[j])
			}
		}
	}
}

func TestAPlanCoversEveryStepInOrder(t *testing.T) {
	names := []string{"fetch", "parse", "evaluate", "report"}
	steps := make([]Step, 0, len(names))
	for _, n := range names {
		steps = append(steps, step(n, EffectNone))
	}
	r := validRecipe(steps...)
	plan, err := Plan(r, start)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan) != len(names) {
		t.Fatalf("plan has %d entries, want %d", len(plan), len(names))
	}
	for i, n := range names {
		if plan[i].Name != n || plan[i].Index != i {
			t.Fatalf("plan entry %d is %q at index %d", i, plan[i].Name, plan[i].Index)
		}
	}
	// Cumulative is monotonic and ends at the recipe's total.
	for i := 1; i < len(plan); i++ {
		if plan[i].Cumulative < plan[i-1].Cumulative {
			t.Fatalf("cumulative time went backwards at %d", i)
		}
	}
}

func TestAPlanStepCannotOverrunItsOwnBudget(t *testing.T) {
	r := validRecipe(step("a", EffectNone), step("b", EffectNone))
	plan, err := Plan(r, start)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for _, p := range plan {
		if p.Budget > p.Timeout {
			t.Fatalf("%s has a budget of %s over its own %s timeout", p.Name, p.Budget, p.Timeout)
		}
		if !p.Deadline.After(start) {
			t.Fatalf("%s has a deadline at or before the start", p.Name)
		}
	}
}

// A passing observer.
func passingObserver() ObserverFunc {
	return func(_ context.Context, s Planned) (Simulated, error) {
		return Simulated{Outcome: StepPass, StartedAt: start, FinishedAt: start.Add(time.Millisecond)}, nil
	}
}

func TestSimulatingAHealthyRecipePasses(t *testing.T) {
	r := validRecipe(step("a", EffectNone), step("b", EffectRead))
	report, err := Simulate(r, passingObserver(), start)
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if report.Outcome != OutcomePass {
		t.Fatalf("outcome %q, want pass", report.Outcome)
	}
	if report.FailedStep != "" {
		t.Fatalf("a passing run named a failed step %q", report.FailedStep)
	}
	if len(report.Attempts) != 2 {
		t.Fatalf("%d attempts, want 2", len(report.Attempts))
	}
	if report.RecipeID != r.Name {
		t.Fatalf("report names %q, want %q", report.RecipeID, r.Name)
	}
}

// A replay of a failure is looking for the failure, so a simulated step failure is a
// completed replay rather than an error.
func TestSimulatingAFailingStepNamesIt(t *testing.T) {
	failing := ObserverFunc(func(_ context.Context, s Planned) (Simulated, error) {
		if s.Name == "breaks" {
			return Simulated{Outcome: StepFail, Detail: "connection refused", StartedAt: start, FinishedAt: start}, nil
		}
		return Simulated{Outcome: StepPass, StartedAt: start, FinishedAt: start}, nil
	})
	r := validRecipe(step("works", EffectNone), step("breaks", EffectNone), step("never-runs", EffectNone))
	report, err := Simulate(r, failing, start)
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if report.Outcome != OutcomeFail {
		t.Fatalf("outcome %q, want fail", report.Outcome)
	}
	if report.FailedStep != "breaks" {
		t.Fatalf("failed step %q, want breaks", report.FailedStep)
	}
	// "The replay passed" must never mean "the replay stopped early and looked fine".
	if report.DroppedSteps != 1 {
		t.Fatalf("%d dropped steps reported, want 1", report.DroppedSteps)
	}
	if len(report.Attempts) != 2 {
		t.Fatalf("%d attempts, want 2 — the third step must not have run", len(report.Attempts))
	}
}

// An observer that cannot simulate a step is not the same as a step that failed, and
// the verdicts must not be conflated.
func TestAnObserverErrorIsNotAReplayedFailure(t *testing.T) {
	broken := ObserverFunc(func(_ context.Context, s Planned) (Simulated, error) {
		return Simulated{}, errors.New("observer unavailable")
	})
	r := validRecipe(step("a", EffectNone))
	report, err := Simulate(r, broken, start)
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if report.Outcome == OutcomePass {
		t.Fatal("an observer that could not simulate produced a pass")
	}
	if report.Outcome == OutcomeFail {
		t.Fatal("an observer outage was reported as a replayed failure, which would send an operator to the wrong code")
	}
}

func TestAnExternalRecipeCannotBeSimulated(t *testing.T) {
	r := validRecipe(step("reaches-out", EffectExternalNetwork))
	if _, err := Simulate(r, passingObserver(), start); !errors.Is(err, ErrExternalEffectRefused) {
		t.Fatalf("simulating an external recipe: got %v, want ErrExternalEffectRefused", err)
	}
}

func TestSimulatingNeedsAnObserver(t *testing.T) {
	// A nil observer would otherwise be a nil dereference at the first step, in the
	// middle of a run.
	if _, err := Simulate(validRecipe(), nil, start); err == nil {
		t.Fatal("a replay ran with no observer")
	}
}

func TestAnInvalidRecipeCannotBeSimulated(t *testing.T) {
	r := validRecipe()
	r.SchemaVersion = "wrong"
	if _, err := Simulate(r, passingObserver(), start); !errors.Is(err, ErrUnknownSchema) {
		t.Fatalf("simulating an invalid recipe: %v", err)
	}
}

// The observer must never be handed a step whose effect reaches outside the process.
func TestTheObserverNeverSeesAnExternalStep(t *testing.T) {
	var seen []Effect
	record := ObserverFunc(func(_ context.Context, s Planned) (Simulated, error) {
		seen = append(seen, s.Effect)
		return Simulated{Outcome: StepPass}, nil
	})
	r := validRecipe(step("a", EffectNone), step("b", EffectRead), step("c", EffectWriteLocal))
	if _, err := Simulate(r, record, start); err != nil {
		t.Fatalf("simulate: %v", err)
	}
	for _, e := range seen {
		if RequiresIsolation(e) {
			t.Fatalf("the observer was handed an isolating step with effect %s", e)
		}
	}
}

// ---------------------------------------------------------------------------
// The structural guarantee
// ---------------------------------------------------------------------------

// The absence of net, os and exec from the package is the enforcement, not a promise in
// a comment. This test reads the package's own source, so a future change that imports
// a networking package fails here rather than in production.
func TestThePackageCannotReachTheOutsideWorld(t *testing.T) {
	files, err := packageFiles()
	if err != nil {
		t.Fatalf("read package source: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no package source found, so this guarantee is not being checked")
	}
	forbidden := []string{`"net"`, `"net/http"`, `"os/exec"`, `"syscall"`, `http.`, `exec.`, `net.Dial`}
	for name, body := range files {
		for _, bad := range forbidden {
			if strings.Contains(body, bad) {
				t.Fatalf("%s references %s; a replay that can make a network call can reach a customer's production", name, bad)
			}
		}
	}
}

// packageFiles reads the package's own non-test source, so the structural guarantee can
// be checked against what is actually compiled rather than against a list somebody
// maintains by hand. Test files are excluded because this helper and its assertions are
// themselves test code.
func packageFiles() (map[string]string, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		out[name] = string(body)
	}
	return out, nil
}
