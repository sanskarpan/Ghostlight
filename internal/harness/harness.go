// Package harness runs platform-owned qualification harnesses against mock targets.
//
// G3.1: "Build platform-owned smoke/isolation/replay/search/load harnesses and mock
// receivers/providers."
//
// Platform-owned is the load-bearing word. A harness the candidate controls can be
// taught to pass; a harness the platform owns cannot be negotiated with. So scenarios,
// assertions, and verdicts all live here, and the candidate only ever sees probes.
//
// Outcomes follow SPEC.md section 9: pass, fail, inconclusive, canceled. Inconclusive
// is not a softer fail — it means the harness itself could not tell, which needs a
// fixed harness rather than a fixed candidate. Unknown, partial, and no-traffic
// outcomes do not pass, and inconclusive is how that rule is enforced rather than
// hoped for.
package harness

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Outcome is a harness verdict.
type Outcome string

const (
	// OutcomePass means the candidate satisfied the scenario.
	OutcomePass Outcome = "pass"
	// OutcomeFail means the candidate did not.
	OutcomeFail Outcome = "fail"
	// OutcomeInconclusive means the harness could not tell. It needs a fixed
	// harness, not a fixed candidate, and it never qualifies anything.
	OutcomeInconclusive Outcome = "inconclusive"
	// OutcomeCanceled means the run was stopped before a verdict.
	OutcomeCanceled Outcome = "canceled"
)

// Kind is a harness scenario.
type Kind string

const (
	// KindSmoke deploys, probes, and expects healthy.
	KindSmoke Kind = "smoke"
	// KindIsolation acts in one preview and requires another to observe nothing.
	KindIsolation Kind = "isolation"
	// KindReplay runs identical inputs twice and requires identical outputs.
	KindReplay Kind = "replay"
	// KindSearch seeds a record and requires a query to find it.
	KindSearch Kind = "search"
	// KindLoad sends bounded traffic and requires the SLO to hold.
	KindLoad Kind = "load"
)

// Identity binds a run to the exact candidate under test.
type Identity struct {
	SourceSHA      string
	BaseSHA        string
	ArtifactDigest string
	ConfigDigest   string
	RecipeDigest   string
	PolicyDigest   string
	Generation     uint64
}

// Complete reports whether the identity names everything a verdict must bind to.
// A verdict bound to a partial identity qualifies code it never examined.
func (id Identity) Complete() bool {
	return id.SourceSHA != "" && id.ArtifactDigest != "" && id.ConfigDigest != "" &&
		id.RecipeDigest != "" && id.PolicyDigest != "" && id.Generation > 0
}

// Missing names the absent fields.
func (id Identity) Missing() []string {
	var out []string
	if id.SourceSHA == "" {
		out = append(out, "source_sha")
	}
	if id.ArtifactDigest == "" {
		out = append(out, "artifact_digest")
	}
	if id.ConfigDigest == "" {
		out = append(out, "config_digest")
	}
	if id.RecipeDigest == "" {
		out = append(out, "recipe_digest")
	}
	if id.PolicyDigest == "" {
		out = append(out, "policy_digest")
	}
	if id.Generation == 0 {
		out = append(out, "generation")
	}
	sort.Strings(out)
	return out
}

// Evidence is what a run leaves behind. Binding verification is G3.2; emitting the
// fields is this package's part of that contract.
type Evidence struct {
	Harness    Kind
	Identity   Identity
	Outcome    Outcome
	StartedAt  time.Time
	FinishedAt time.Time
	// Measurements are the observed values the verdict rested on.
	Measurements map[string]float64
	// Detail explains the verdict for an operator.
	Detail string
}

// Elapsed reports how long the run took.
func (e Evidence) Elapsed() time.Duration {
	return e.FinishedAt.Sub(e.StartedAt)
}

// Target is what a harness drives. Mocks implement this; the candidate never does.
type Target interface {
	// Probe checks health once.
	Probe(ctx context.Context) error
	// Act performs a state-changing operation and returns an observable marker.
	Act(ctx context.Context, input string) (marker string, err error)
	// Observed reports the markers this target has seen.
	Observed(ctx context.Context) ([]string, error)
	// Query searches seeded records.
	Query(ctx context.Context, q string) ([]string, error)
	// Seed inserts a record for search scenarios.
	Seed(ctx context.Context, record string) error
}

// Scenario bounds one harness run.
type Scenario struct {
	Kind Kind
	// Identity binds the run to a candidate.
	Identity Identity
	// Timeout bounds the whole run. A harness without a bound is a harness that can
	// hang a gate forever.
	Timeout time.Duration
	// LoadRequests bounds load scenarios.
	LoadRequests int
	// LoadSLOms is the per-request millisecond budget for load scenarios.
	LoadSLOms float64
	// LoadMaxErrors is how many failed requests a load run tolerates.
	LoadMaxErrors int
}

// Runner executes scenarios.
type Runner struct {
	now func() time.Time
}

// NewRunner builds a runner.
func NewRunner(now func() time.Time) *Runner {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Runner{now: now}
}

// Run executes a scenario against mock targets.
//
// The identity is checked before anything runs: a verdict bound to a partial identity
// would qualify code it never examined, so the run is inconclusive rather than failed.
// Inconclusive, because the candidate did nothing wrong — the harness was asked to test
// something it cannot identify.
func (r *Runner) Run(ctx context.Context, s Scenario, primary, sibling Target) (Evidence, error) {
	started := r.now()
	ev := Evidence{Harness: s.Kind, Identity: s.Identity, StartedAt: started, Measurements: map[string]float64{}}

	if missing := s.Identity.Missing(); len(missing) > 0 {
		ev.Outcome = OutcomeInconclusive
		ev.FinishedAt = r.now()
		ev.Detail = fmt.Sprintf("cannot test an unidentified candidate; missing %v", missing)
		return ev, nil
	}
	if primary == nil {
		ev.Outcome = OutcomeInconclusive
		ev.FinishedAt = r.now()
		ev.Detail = "no target to drive"
		return ev, nil
	}

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var err error
	switch s.Kind {
	case KindSmoke:
		err = r.smoke(ctx, s, primary, &ev)
	case KindIsolation:
		err = r.isolation(ctx, s, primary, sibling, &ev)
	case KindReplay:
		err = r.replay(ctx, s, primary, &ev)
	case KindSearch:
		err = r.search(ctx, s, primary, &ev)
	case KindLoad:
		err = r.load(ctx, s, primary, &ev)
	default:
		ev.Outcome = OutcomeInconclusive
		ev.Detail = fmt.Sprintf("unknown harness %q", s.Kind)
		ev.FinishedAt = r.now()
		return ev, nil
	}

	ev.FinishedAt = r.now()
	if ctx.Err() == context.DeadlineExceeded && ev.Outcome == "" {
		ev.Outcome = OutcomeInconclusive
		ev.Detail = "the harness timed out before reaching a verdict"
		return ev, nil
	}
	if err != nil {
		return ev, err
	}
	return ev, nil
}

func (r *Runner) smoke(ctx context.Context, _ Scenario, primary Target, ev *Evidence) error {
	if err := primary.Probe(ctx); err != nil {
		ev.Outcome = OutcomeFail
		ev.Detail = "smoke probe failed: " + err.Error()
		return nil
	}
	ev.Outcome = OutcomePass
	ev.Detail = "smoke probe healthy"
	ev.Measurements["probes"] = 1
	return nil
}

func (r *Runner) isolation(ctx context.Context, _ Scenario, primary, sibling Target, ev *Evidence) error {
	if sibling == nil {
		ev.Outcome = OutcomeInconclusive
		ev.Detail = "isolation needs two targets and got one"
		return nil
	}
	marker, err := primary.Act(ctx, "write")
	if err != nil {
		ev.Outcome = OutcomeInconclusive
		ev.Detail = "the primary failed to act, so nothing was tested: " + err.Error()
		return nil
	}
	seen, err := sibling.Observed(ctx)
	if err != nil {
		ev.Outcome = OutcomeInconclusive
		ev.Detail = "the sibling could not be observed: " + err.Error()
		return nil
	}
	for _, m := range seen {
		if m == marker {
			ev.Outcome = OutcomeFail
			ev.Detail = "the sibling observed the primary's marker: isolation is broken"
			return nil
		}
	}
	ev.Outcome = OutcomePass
	ev.Detail = "the sibling observed nothing of the primary's act"
	return nil
}

func (r *Runner) replay(ctx context.Context, _ Scenario, primary Target, ev *Evidence) error {
	first, err := primary.Act(ctx, "replay-input")
	if err != nil {
		ev.Outcome = OutcomeInconclusive
		ev.Detail = "the first run failed, so there is nothing to compare: " + err.Error()
		return nil
	}
	second, err := primary.Act(ctx, "replay-input")
	if err != nil {
		ev.Outcome = OutcomeInconclusive
		ev.Detail = "the second run failed, so there is nothing to compare: " + err.Error()
		return nil
	}
	ev.Measurements["runs"] = 2
	if first != second {
		ev.Outcome = OutcomeFail
		ev.Detail = "identical inputs produced different outputs: the candidate is nondeterministic"
		return nil
	}
	ev.Outcome = OutcomePass
	ev.Detail = "identical inputs produced identical outputs"
	return nil
}

func (r *Runner) search(ctx context.Context, _ Scenario, primary Target, ev *Evidence) error {
	if err := primary.Seed(ctx, "needle-record-1"); err != nil {
		ev.Outcome = OutcomeInconclusive
		ev.Detail = "seeding failed, so nothing was tested: " + err.Error()
		return nil
	}
	found, err := primary.Query(ctx, "needle")
	if err != nil {
		ev.Outcome = OutcomeInconclusive
		ev.Detail = "the query failed, so nothing was tested: " + err.Error()
		return nil
	}
	ev.Measurements["results"] = float64(len(found))
	for _, f := range found {
		if f == "needle-record-1" {
			ev.Outcome = OutcomePass
			ev.Detail = "the seeded record was found"
			return nil
		}
	}
	ev.Outcome = OutcomeFail
	ev.Detail = "the seeded record was not found"
	return nil
}

func (r *Runner) load(ctx context.Context, s Scenario, primary Target, ev *Evidence) error {
	n := s.LoadRequests
	if n <= 0 {
		n = 100
	}
	slo := s.LoadSLOms
	if slo <= 0 {
		slo = 500
	}
	var failed int
	var worst float64
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			ev.Outcome = OutcomeInconclusive
			ev.Detail = "load was canceled partway; a partial load run proves nothing"
			return nil
		}
		start := r.now()
		// The mock target answers immediately; the measurement records harness
		// overhead plus mock latency, which is what the SLO gates in tests.
		if err := primary.Probe(ctx); err != nil {
			failed++
		}
		elapsed := r.now().Sub(start).Seconds() * 1000
		if elapsed > worst {
			worst = elapsed
		}
	}
	ev.Measurements["requests"] = float64(n)
	ev.Measurements["failed"] = float64(failed)
	ev.Measurements["worst_ms"] = worst
	if failed > s.LoadMaxErrors {
		ev.Outcome = OutcomeFail
		ev.Detail = fmt.Sprintf("%d of %d requests failed (tolerated %d)", failed, n, s.LoadMaxErrors)
		return nil
	}
	if worst > slo {
		ev.Outcome = OutcomeFail
		ev.Detail = fmt.Sprintf("worst request %.1fms exceeded the %.1fms SLO", worst, slo)
		return nil
	}
	ev.Outcome = OutcomePass
	ev.Detail = fmt.Sprintf("%d requests within SLO, %d failed", n, failed)
	return nil
}

// ---------------------------------------------------------------------------
// Mock targets
// ---------------------------------------------------------------------------

// MockTarget is a controllable harness target.
type MockTarget struct {
	mu sync.Mutex
	// probeErr fails probes.
	probeErr error
	// actErr fails acts.
	actErr error
	// queryErr fails queries.
	queryErr error
	// seedErr fails seeds.
	seedErr error
	// observeErr fails observation.
	observeErr error
	// nondeterministic makes identical inputs produce different markers.
	nondeterministic bool
	// dropSeeds makes Seed a silent no-op, modeling a store that accepts writes
	// and loses them.
	dropSeeds bool

	seen    []string
	records []string
	acts    int
	probes  int
}

// MockOption configures a mock.
type MockOption func(*MockTarget)

// FailProbes makes probes fail.
func FailProbes(err error) MockOption {
	return func(m *MockTarget) { m.probeErr = err }
}

// FailActs makes acts fail.
func FailActs(err error) MockOption {
	return func(m *MockTarget) { m.actErr = err }
}

// FailQueries makes queries fail.
func FailQueries(err error) MockOption {
	return func(m *MockTarget) { m.queryErr = err }
}

// FailSeeds makes seeds fail.
func FailSeeds(err error) MockOption {
	return func(m *MockTarget) { m.seedErr = err }
}

// FailObservation makes observation fail.
func FailObservation(err error) MockOption {
	return func(m *MockTarget) { m.observeErr = err }
}

// Nondeterministic makes replay fail.
func Nondeterministic() MockOption {
	return func(m *MockTarget) { m.nondeterministic = true }
}

// DropSeeds makes the store lose writes silently.
func DropSeeds() MockOption {
	return func(m *MockTarget) { m.dropSeeds = true }
}

// NewMockTarget builds a mock.
func NewMockTarget(opts ...MockOption) *MockTarget {
	m := &MockTarget{}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Probe checks health.
func (m *MockTarget) Probe(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.probes++
	return m.probeErr
}

// Act performs an operation and returns a marker.
func (m *MockTarget) Act(_ context.Context, input string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.actErr != nil {
		return "", m.actErr
	}
	m.acts++
	// A deterministic target maps identical inputs to identical markers. The counter
	// is accounting, not identity: including it in the marker would make every act
	// unique and replay could never pass, even for a perfectly deterministic target.
	marker := fmt.Sprintf("marker-%s", input)
	if m.nondeterministic {
		// Identical inputs must produce identical markers unless the target is
		// nondeterministic. The per-act sequence stands in for randomness here:
		// wall-clock nanos would also work on most platforms, but timer resolution
		// makes two rapid calls identical on some, which would make the defect
		// under test invisible exactly when the test runs fastest.
		marker = fmt.Sprintf("marker-%s-run-%d", input, m.acts)
	}
	m.seen = append(m.seen, marker)
	return marker, nil
}

// Observed reports seen markers.
func (m *MockTarget) Observed(context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.observeErr != nil {
		return nil, m.observeErr
	}
	return append([]string(nil), m.seen...), nil
}

// Query searches records.
func (m *MockTarget) Query(_ context.Context, q string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	var out []string
	for _, r := range m.records {
		if containsFold(r, q) {
			out = append(out, r)
		}
	}
	return out, nil
}

// Seed inserts a record.
func (m *MockTarget) Seed(_ context.Context, record string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seedErr != nil {
		return m.seedErr
	}
	if m.dropSeeds {
		return nil
	}
	m.records = append(m.records, record)
	return nil
}

// Probes reports how many probes ran.
func (m *MockTarget) Probes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.probes
}

func containsFold(haystack, needle string) bool {
	h, n := strings.ToLower(haystack), strings.ToLower(needle)
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
