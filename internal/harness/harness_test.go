package harness_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/harness"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func identity() harness.Identity {
	return harness.Identity{
		SourceSHA: "abc123", BaseSHA: "def456", ArtifactDigest: "sha256:aaa",
		ConfigDigest: "sha256:bbb", RecipeDigest: "sha256:ccc", PolicyDigest: "sha256:ddd",
		Generation: 2,
	}
}

func runner() *harness.Runner {
	return harness.NewRunner(func() time.Time { return now })
}

func scenario(kind harness.Kind) harness.Scenario {
	return harness.Scenario{Kind: kind, Identity: identity(), Timeout: time.Minute}
}

// TestSmokePasses is the ordinary path.
func TestSmokePasses(t *testing.T) {
	ev, err := runner().Run(context.Background(), scenario(harness.KindSmoke), harness.NewMockTarget(), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomePass {
		t.Fatalf("a healthy target must pass smoke, got %+v", ev)
	}
	if ev.Elapsed() != 0 {
		t.Fatalf("a frozen clock must report zero elapsed, got %v", ev.Elapsed())
	}
}

// TestSmokeFailureIsAFailNotInconclusive: the candidate did something wrong, so the
// verdict names the candidate rather than the harness.
func TestSmokeFailureIsAFailNotInconclusive(t *testing.T) {
	target := harness.NewMockTarget(harness.FailProbes(errors.New("connection refused")))
	ev, err := runner().Run(context.Background(), scenario(harness.KindSmoke), target, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomeFail {
		t.Fatalf("an unhealthy target must fail, got %+v", ev)
	}
	if !strings.Contains(ev.Detail, "connection refused") {
		t.Fatalf("the verdict must carry the cause, got %q", ev.Detail)
	}
}

// TestUnidentifiedCandidateIsInconclusive: a verdict bound to a partial identity would
// qualify code it never examined.
func TestUnidentifiedCandidateIsInconclusive(t *testing.T) {
	s := scenario(harness.KindSmoke)
	s.Identity = harness.Identity{SourceSHA: "abc123"}
	ev, err := runner().Run(context.Background(), s, harness.NewMockTarget(), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomeInconclusive {
		t.Fatalf("an unidentified candidate must be inconclusive, got %+v", ev)
	}
	if !strings.Contains(ev.Detail, "missing") {
		t.Fatalf("the verdict must name what is missing, got %q", ev.Detail)
	}
}

// TestIdentityMissingNamesEveryField.
func TestIdentityMissingNamesEveryField(t *testing.T) {
	missing := harness.Identity{}.Missing()
	if len(missing) != 6 {
		t.Fatalf("an empty identity must miss six fields, got %v", missing)
	}
	if identity().Complete() != true {
		t.Fatal("a full identity must be complete")
	}
	if (harness.Identity{SourceSHA: "x"}).Complete() {
		t.Fatal("a partial identity must not be complete")
	}
}

// TestIsolationPassesWhenSiblingsAreSeparate.
func TestIsolationPassesWhenSiblingsAreSeparate(t *testing.T) {
	ev, err := runner().Run(context.Background(), scenario(harness.KindIsolation),
		harness.NewMockTarget(), harness.NewMockTarget())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomePass {
		t.Fatalf("separate siblings must pass isolation, got %+v", ev)
	}
}

// TestIsolationFailsWhenTheSiblingSeesTheMarker.
func TestIsolationFailsWhenTheSiblingSeesTheMarker(t *testing.T) {
	// One shared target: whatever the primary writes, the "sibling" observes. That is
	// exactly a broken boundary.
	shared := harness.NewMockTarget()
	ev, err := runner().Run(context.Background(), scenario(harness.KindIsolation), shared, shared)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomeFail {
		t.Fatalf("a visible marker must fail isolation, got %+v", ev)
	}
}

// TestIsolationWithoutASiblingIsInconclusive: the scenario was not actually run.
func TestIsolationWithoutASiblingIsInconclusive(t *testing.T) {
	ev, err := runner().Run(context.Background(), scenario(harness.KindIsolation), harness.NewMockTarget(), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomeInconclusive {
		t.Fatalf("isolation with one target must be inconclusive, got %+v", ev)
	}
}

// TestReplayPassesForDeterministicTargets.
func TestReplayPassesForDeterministicTargets(t *testing.T) {
	ev, err := runner().Run(context.Background(), scenario(harness.KindReplay), harness.NewMockTarget(), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomePass {
		t.Fatalf("a deterministic target must pass replay, got %+v", ev)
	}
	if ev.Measurements["runs"] != 2 {
		t.Fatalf("replay must run twice, got %v", ev.Measurements)
	}
}

// TestReplayFailsForNondeterministicTargets.
func TestReplayFailsForNondeterministicTargets(t *testing.T) {
	ev, err := runner().Run(context.Background(), scenario(harness.KindReplay),
		harness.NewMockTarget(harness.Nondeterministic()), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomeFail {
		t.Fatalf("a nondeterministic target must fail replay, got %+v", ev)
	}
}

// TestSearchFindsTheSeededRecord.
func TestSearchFindsTheSeededRecord(t *testing.T) {
	ev, err := runner().Run(context.Background(), scenario(harness.KindSearch), harness.NewMockTarget(), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomePass {
		t.Fatalf("a working store must pass search, got %+v", ev)
	}
}

// TestSearchFailsWhenWritesAreLost: the store accepts writes and loses them silently,
// which is worse than failing loudly.
func TestSearchFailsWhenWritesAreLost(t *testing.T) {
	ev, err := runner().Run(context.Background(), scenario(harness.KindSearch),
		harness.NewMockTarget(harness.DropSeeds()), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomeFail {
		t.Fatalf("a store that loses writes must fail search, got %+v", ev)
	}
}

// TestLoadPassesWithinSLO.
func TestLoadPassesWithinSLO(t *testing.T) {
	s := scenario(harness.KindLoad)
	s.LoadRequests = 50
	s.LoadSLOms = 1000
	ev, err := runner().Run(context.Background(), s, harness.NewMockTarget(), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomePass {
		t.Fatalf("a healthy target must pass load, got %+v", ev)
	}
	if ev.Measurements["requests"] != 50 {
		t.Fatalf("load must run the bounded request count, got %v", ev.Measurements)
	}
}

// TestLoadFailsWhenErrorsExceedTolerance.
func TestLoadFailsWhenErrorsExceedTolerance(t *testing.T) {
	s := scenario(harness.KindLoad)
	s.LoadRequests = 20
	s.LoadMaxErrors = 0
	ev, err := runner().Run(context.Background(), s,
		harness.NewMockTarget(harness.FailProbes(errors.New("overloaded"))), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomeFail {
		t.Fatalf("an overloaded target must fail load, got %+v", ev)
	}
	if ev.Measurements["failed"] != 20 {
		t.Fatalf("every request must be counted failed, got %v", ev.Measurements)
	}
}

// TestLoadIsBounded: the request count is capped even when asked for more.
func TestLoadIsBounded(t *testing.T) {
	s := scenario(harness.KindLoad)
	s.LoadRequests = 0
	target := harness.NewMockTarget()
	ev, err := runner().Run(context.Background(), s, target, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomePass {
		t.Fatalf("a default load must pass, got %+v", ev)
	}
	if target.Probes() != 100 {
		t.Fatalf("an unbounded request must default to 100, got %d", target.Probes())
	}
}

// TestCanceledLoadIsInconclusive: a partial load run proves nothing.
func TestCanceledLoadIsInconclusive(t *testing.T) {
	s := scenario(harness.KindLoad)
	s.LoadRequests = 1000000
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ev, err := runner().Run(ctx, s, harness.NewMockTarget(), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomeInconclusive {
		t.Fatalf("a canceled load must be inconclusive, got %+v", ev)
	}
}

// TestUnknownHarnessIsInconclusive.
func TestUnknownHarnessIsInconclusive(t *testing.T) {
	s := scenario("telepathy")
	ev, err := runner().Run(context.Background(), s, harness.NewMockTarget(), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomeInconclusive {
		t.Fatalf("an unknown harness must be inconclusive, got %+v", ev)
	}
}

// TestTimeoutIsInconclusive: a harness that cannot finish cannot judge.
func TestTimeoutIsInconclusive(t *testing.T) {
	s := scenario(harness.KindLoad)
	s.Timeout = time.Nanosecond
	s.LoadRequests = 1000000
	// A canceled context from the start forces the timeout path deterministically.
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond)
	ev, err := runner().Run(ctx, s, harness.NewMockTarget(), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Outcome != harness.OutcomeInconclusive {
		t.Fatalf("a timed-out harness must be inconclusive, got %+v", ev)
	}
}

// TestEvidenceCarriesMeasurements: the verdict must rest on recorded values.
func TestEvidenceCarriesMeasurements(t *testing.T) {
	ev, err := runner().Run(context.Background(), scenario(harness.KindSmoke), harness.NewMockTarget(), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ev.Measurements["probes"] != 1 {
		t.Fatalf("smoke must record its probe, got %v", ev.Measurements)
	}
	if ev.Harness != harness.KindSmoke {
		t.Fatalf("evidence must name its harness, got %s", ev.Harness)
	}
	if ev.Identity.Generation != 2 {
		t.Fatal("evidence must carry the candidate identity")
	}
}

// TestOutcomesAreDistinct.
func TestOutcomesAreDistinct(t *testing.T) {
	seen := map[harness.Outcome]bool{}
	for _, o := range []harness.Outcome{
		harness.OutcomePass, harness.OutcomeFail, harness.OutcomeInconclusive, harness.OutcomeCanceled,
	} {
		if o == "" {
			t.Fatal("an outcome must be named")
		}
		if seen[o] {
			t.Fatalf("outcome %s is duplicated", o)
		}
		seen[o] = true
	}
}

// TestConcurrentRunsAreIndependent: harnesses share nothing.
func TestConcurrentRunsAreIndependent(t *testing.T) {
	var wg sync.WaitGroup
	outcomes := make([]harness.Outcome, 8)
	for i := range outcomes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ev, err := runner().Run(context.Background(), scenario(harness.KindSmoke), harness.NewMockTarget(), nil)
			if err != nil {
				return
			}
			outcomes[i] = ev.Outcome
		}(i)
	}
	wg.Wait()
	for i, o := range outcomes {
		if o != harness.OutcomePass {
			t.Fatalf("run %d must pass independently, got %s", i, o)
		}
	}
}
