package operator

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/oncall"
)

// testNow is the moment every test in this file is written around.
var testNow = time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC)

// The window the roster tests ask about.
const (
	windowStart = "2026-05-04T09:00:00Z"
	windowEnd   = "2026-05-04T21:00:00Z"
)

// coveredShifts is a roster that covers every moment of the window.
const coveredShifts = `[
  {"primary":"ada","secondary":"grace","startsAt":"2026-05-04T09:00:00Z","endsAt":"2026-05-04T15:00:00Z","handoverAcknowledgedBy":"ada"},
  {"primary":"linus","secondary":"ada","startsAt":"2026-05-04T15:00:00Z","endsAt":"2026-05-04T21:00:00Z","handoverAcknowledgedBy":"linus"}
]`

// gappedShifts is a roster that leaves the second half of the window uncovered.
const gappedShifts = `[
  {"primary":"ada","secondary":"grace","startsAt":"2026-05-04T09:00:00Z","endsAt":"2026-05-04T15:00:00Z","handoverAcknowledgedBy":"ada"}
]`

// coverageFile is a registry, its evidence and the method it was computed
// under. The owner is named because the library refuses a scorecard that
// nobody is accountable for.
const coverageFile = `{
  "registry": {
    "invariants": [
      {"id":"inv-a","service":"api","weight":3,"requiredProfile":"e2e","evidenceMaxAge":"336h0m0s","required":true},
      {"id":"inv-b","service":"api","weight":1,"requiredProfile":"e2e","evidenceMaxAge":"336h0m0s","required":true}
    ],
    "owners": {"api":"ada"}
  },
  "evidence": [
    {"invariantID":"inv-a","profile":"e2e","testedAt":"2026-05-01T09:00:00Z","outcome":"pass"},
    {"invariantID":"inv-b","profile":"e2e","testedAt":"2026-05-01T09:00:00Z","outcome":"fail"}
  ],
  "methodology": {"version":"cov-1","effectiveFrom":"2026-01-01T00:00:00Z"}
}`

// ownerlessCoverageFile is a registry that names no owner for its service.
const ownerlessCoverageFile = `{
  "registry": {
    "invariants": [
      {"id":"inv-a","service":"api","weight":3,"requiredProfile":"e2e","evidenceMaxAge":"336h0m0s","required":true}
    ]
  },
  "evidence": [
    {"invariantID":"inv-a","profile":"e2e","testedAt":"2026-05-01T09:00:00Z","outcome":"pass"}
  ],
  "methodology": {"version":"cov-1","effectiveFrom":"2026-01-01T00:00:00Z"}
}`

// statusFile holds one fresh check and one that has gone stale.
const statusFile = `[
  {"component":"api","ok":true,"at":"2026-05-04T08:55:00Z"},
  {"component":"db","ok":true,"at":"2026-05-04T07:00:00Z"}
]`

// writeFixture writes a fixture file and returns its path.
func writeFixture(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// capture runs the tool and returns what it wrote and the code it returned.
func capture(t *testing.T, args ...string) (string, string, ExitCode) {
	t.Helper()
	return captureAt(t, testNow, args...)
}

// captureAt runs the tool at a given moment and returns what it wrote and the
// code it returned.
func captureAt(t *testing.T, now time.Time, args ...string) (string, string, ExitCode) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Dispatch(Context{Stdout: &stdout, Stderr: &stderr, Now: now}, args)
	return stdout.String(), stderr.String(), code
}

// newSecretFor is the secret a key kind is expected to produce.
//
// The marker in the name is what makes it easy to assert that no secret was
// printed: the tool must never print anything containing it.
func newSecretFor(kind oncall.KeyKind) string {
	return "s3cr3t-" + string(kind)
}

// currentSecretFor is the secret a key kind holds now.
func currentSecretFor(kind oncall.KeyKind) string {
	return "0ld-s3cr3t-" + string(kind)
}

// plansForEveryKind returns one plan for every required key kind.
func plansForEveryKind(t *testing.T) []oncall.RotationPlan {
	t.Helper()
	plans := make([]oncall.RotationPlan, 0, len(oncall.RequiredKeyKinds()))
	for _, kind := range oncall.RequiredKeyKinds() {
		plans = append(plans, planFor(t, kind))
	}
	return plans
}

// planFor is a plan that satisfies every rule for one key kind.
func planFor(t *testing.T, kind oncall.KeyKind) oncall.RotationPlan {
	t.Helper()
	return oncall.RotationPlan{
		Kind:          kind,
		KeyID:         string(kind) + "-1",
		CurrentSecret: currentSecretFor(kind),
		NewSecret:     newSecretFor(kind),
		CurrentScope:  []string{"read", "write"},
		NewScope:      []string{"read"},
		Reason:        "scheduled rotation",
		Actor:         "on-call",
		ScheduledAt:   testNow,
	}
}

// writePlans writes a set of plans as a JSON file.
func writePlans(t *testing.T, dir, name string, plans []oncall.RotationPlan) string {
	t.Helper()
	data, err := json.MarshalIndent(plans, "", "  ")
	if err != nil {
		t.Fatalf("marshal plans: %v", err)
	}
	return writeFixture(t, dir, name, string(data))
}

// writeExpectedSecrets writes the secret each key kind is expected to produce.
func writeExpectedSecrets(t *testing.T, dir, name string, plans []oncall.RotationPlan) string {
	t.Helper()
	expected := map[string]string{}
	for _, plan := range plans {
		expected[string(plan.Kind)] = plan.NewSecret
	}
	data, err := json.MarshalIndent(expected, "", "  ")
	if err != nil {
		t.Fatalf("marshal expected secrets: %v", err)
	}
	return writeFixture(t, dir, name, string(data))
}

// assertNoSecret fails when any secret material reached the operator.
func assertNoSecret(t *testing.T, stdout, stderr string) {
	t.Helper()
	for _, stream := range []struct {
		name string
		text string
	}{{"stdout", stdout}, {"stderr", stderr}} {
		if strings.Contains(stream.text, "s3cr3t") {
			t.Errorf("%s carries secret material: %q", stream.name, stream.text)
		}
	}
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

// An unknown command is a mistake in the invocation, not a judgement about the
// state, so it prints the usage and exits with the usage code.
func TestDispatchOnAnUnknownCommandPrintsUsageAndExitsUsage(t *testing.T) {
	stdout, stderr, code := capture(t, "bogus")
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "usage:") {
		t.Errorf("output = %q, want the usage printed", combined)
	}
	if !strings.Contains(combined, "oncall check") {
		t.Errorf("output = %q, want the command listing", combined)
	}
}

// A missing command is the same mistake as an unknown one.
func TestDispatchOnAMissingCommandPrintsUsageAndExitsUsage(t *testing.T) {
	stdout, stderr, code := capture(t)
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stdout+stderr, "usage:") {
		t.Errorf("output = %q, want the usage printed", stdout+stderr)
	}
}

// Asking for help is not a mistake, so it exits without a failure code.
func TestDispatchOnHelpPrintsUsageAndExitsOK(t *testing.T) {
	stdout, _, code := capture(t, "--help")
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout, "usage:") {
		t.Errorf("stdout = %q, want the usage printed", stdout)
	}
}

// Every command the tool lists has to be reachable by its own name.
func TestMatchFindsEveryListedCommand(t *testing.T) {
	wanted := map[string][]string{
		"oncall check":       {"oncall", "check"},
		"rotation plan":      {"rotation", "plan"},
		"rotation verify":    {"rotation", "verify"},
		"coverage scorecard": {"coverage", "scorecard"},
		"status page":        {"status", "page"},
	}
	for _, cmd := range Commands() {
		args, ok := wanted[cmd.Name]
		if !ok {
			t.Fatalf("command %q has no test for it", cmd.Name)
		}
		got, rest, found := match(args)
		if !found {
			t.Errorf("match(%v) did not find %q", args, cmd.Name)
			continue
		}
		if got.Name != cmd.Name {
			t.Errorf("match(%v) found %q, want %q", args, got.Name, cmd.Name)
		}
		if len(rest) != 0 {
			t.Errorf("match(%v) left %v, want nothing", args, rest)
		}
	}
}

// A refusal from a library is not a crash, and the exit code has to say so.
func TestDispatchRefusesWithExitRefused(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)[:5]
	path := writePlans(t, dir, "plans.json", plans)

	_, _, code := capture(t, "rotation", "plan", "--file", path)
	if code != ExitRefused {
		t.Fatalf("code = %d, want %d", code, ExitRefused)
	}
}

// An input the tool cannot read is a different thing from a refused plan, and
// the two have to be told apart.
func TestDispatchFailsWithExitFailureOnAnUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "not-there.json")

	_, _, code := capture(t, "rotation", "plan", "--file", missing)
	if code != ExitFailure {
		t.Fatalf("code = %d, want %d", code, ExitFailure)
	}
}

// The distinction is the point: the same command, the same exit code family,
// one refused plan and one unreadable file, and two different codes.
func TestARefusalAndAFailureAreDifferentCodes(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)[:5]
	planPath := writePlans(t, dir, "plans.json", plans)
	missingPath := filepath.Join(dir, "not-there.json")

	_, _, refused := capture(t, "rotation", "plan", "--file", planPath)
	_, _, failed := capture(t, "rotation", "plan", "--file", missingPath)

	if refused == failed {
		t.Fatalf("refused = %d and failed = %d, want two different codes", refused, failed)
	}
	if refused != ExitRefused {
		t.Errorf("refused = %d, want %d", refused, ExitRefused)
	}
	if failed != ExitFailure {
		t.Errorf("failed = %d, want %d", failed, ExitFailure)
	}
}

// A flag the command cannot read is a usage error, and a usage error says
// nothing about the state that would have been checked.
func TestABadFlagExitsUsage(t *testing.T) {
	_, _, code := capture(t, "oncall", "check", "--nonsense")
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

// A missing flag is a usage error too.
func TestAMissingFlagExitsUsage(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "shifts.json", coveredShifts)

	_, _, code := capture(t, "oncall", "check", "--shifts", path)
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

// A flag value the command cannot read is a usage error.
func TestAnUnreadableFlagValueExitsUsage(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "shifts.json", coveredShifts)

	_, _, code := capture(t, "oncall", "check", "--shifts", path, "--from", "yesterday", "--to", windowEnd)
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

// ---------------------------------------------------------------------------
// oncall check
// ---------------------------------------------------------------------------

// A roster that covers the window is reported, with the people on it.
func TestOncallCheckReportsTheRoster(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "shifts.json", coveredShifts)

	stdout, _, code := capture(t, "oncall", "check", "--shifts", path, "--from", windowStart, "--to", windowEnd)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	for _, want := range []string{"ada", "linus", "grace", windowStart, windowEnd} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout = %q, want it to name %q", stdout, want)
		}
	}
}

// A gap is refused, and the refusal names the moment the gap opens.
func TestOncallCheckRefusesAGapAndNamesIt(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "shifts.json", gappedShifts)

	stdout, stderr, code := capture(t, "oncall", "check", "--shifts", path, "--from", windowStart, "--to", windowEnd)
	if code != ExitRefused {
		t.Fatalf("code = %d, want %d", code, ExitRefused)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "2026-05-04T15:00:00Z") {
		t.Errorf("output = %q, want the start of the gap named", combined)
	}
	if !strings.Contains(combined, "2026-05-04T21:00:00Z") {
		t.Errorf("output = %q, want the end of the gap named", combined)
	}
}

// The JSON mode is JSON.
func TestOncallCheckJSONModeIsValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "shifts.json", coveredShifts)

	stdout, _, code := capture(t, "oncall", "check", "--shifts", path, "--from", windowStart, "--to", windowEnd, "--json")
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if report["status"] != "ok" {
		t.Errorf("status = %v, want ok", report["status"])
	}
	shifts, ok := report["shifts"].([]any)
	if !ok || len(shifts) != 2 {
		t.Errorf("shifts = %v, want two of them", report["shifts"])
	}
}

// ---------------------------------------------------------------------------
// rotation plan
// ---------------------------------------------------------------------------

// The kinds a plan left behind are named, because "not all of them" is not an
// answer an operator can act on.
func TestRotationPlanReportsTheMissingKeyKinds(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)[:5]
	path := writePlans(t, dir, "plans.json", plans)

	stdout, stderr, code := capture(t, "rotation", "plan", "--file", path)
	if code != ExitRefused {
		t.Fatalf("code = %d, want %d", code, ExitRefused)
	}
	combined := stdout + stderr
	for _, want := range []string{"allocator-credentials", "preview-secrets"} {
		if !strings.Contains(combined, want) {
			t.Errorf("output = %q, want it to name the missing kind %q", combined, want)
		}
	}
}

// A plan that covers every kind is accepted and says which kinds it covers.
func TestRotationPlanAcceptsACompletePlan(t *testing.T) {
	dir := t.TempDir()
	path := writePlans(t, dir, "plans.json", plansForEveryKind(t))

	stdout, _, code := capture(t, "rotation", "plan", "--file", path)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout, "missing key kinds: none") {
		t.Errorf("stdout = %q, want it to say that no kind was missed", stdout)
	}
	if !strings.Contains(stdout, "plan would widen privilege: no") {
		t.Errorf("stdout = %q, want it to say that no privilege was widened", stdout)
	}
}

// A plan that grants more than the current secret holds is refused, and the
// refusal says that privilege was widened.
func TestRotationPlanRefusesAPlanThatWidensPrivilege(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)
	plans[0].NewScope = []string{"read", "write", "admin"}
	path := writePlans(t, dir, "plans.json", plans)

	stdout, stderr, code := capture(t, "rotation", "plan", "--file", path)
	if code != ExitRefused {
		t.Fatalf("code = %d, want %d", code, ExitRefused)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "privilege") {
		t.Errorf("output = %q, want it to name the widened privilege", combined)
	}
}

// The JSON mode carries the reason for the refusal.
func TestRotationPlanJSONModeCarriesTheReason(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)[:5]
	path := writePlans(t, dir, "plans.json", plans)

	stdout, _, code := capture(t, "rotation", "plan", "--file", path, "--json")
	if code != ExitRefused {
		t.Fatalf("code = %d, want %d", code, ExitRefused)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	reason, ok := report["reason"].(string)
	if !ok || reason == "" {
		t.Fatalf("reason = %v, want the refusal reason", report["reason"])
	}
	if !strings.Contains(reason, "allocator-credentials") {
		t.Errorf("reason = %q, want it to name the missing kind", reason)
	}
}

// ---------------------------------------------------------------------------
// rotation verify
// ---------------------------------------------------------------------------

// A rotation that would produce the expected secret is verified.
func TestRotationVerifyVerifiesEveryPlan(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)
	planPath := writePlans(t, dir, "plans.json", plans)
	secretPath := writeExpectedSecrets(t, dir, "expected.json", plans)

	stdout, _, code := capture(t, "rotation", "verify", "--file", planPath, "--secret-file", secretPath)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout, "rotations verified: 7") {
		t.Errorf("stdout = %q, want the seven rotations verified", stdout)
	}
}

// The successful path prints no secret, neither the current one nor the new
// one.
func TestRotationVerifyNeverPrintsTheSecretOnSuccess(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)
	planPath := writePlans(t, dir, "plans.json", plans)
	secretPath := writeExpectedSecrets(t, dir, "expected.json", plans)

	stdout, stderr, code := capture(t, "rotation", "verify", "--file", planPath, "--secret-file", secretPath)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	assertNoSecret(t, stdout, stderr)
}

// The refusal path prints no secret either, and that is the path where a tool
// is most tempted to print what it was looking at.
func TestRotationVerifyNeverPrintsTheSecretOnRefusal(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)
	planPath := writePlans(t, dir, "plans.json", plans)

	expected := map[string]string{}
	for _, plan := range plans {
		expected[string(plan.Kind)] = "s3cr3t-wrong-" + string(plan.Kind)
	}
	data, err := json.MarshalIndent(expected, "", "  ")
	if err != nil {
		t.Fatalf("marshal expected secrets: %v", err)
	}
	secretPath := writeFixture(t, dir, "expected.json", string(data))

	stdout, stderr, code := capture(t, "rotation", "verify", "--file", planPath, "--secret-file", secretPath)
	if code != ExitRefused {
		t.Fatalf("code = %d, want %d", code, ExitRefused)
	}
	assertNoSecret(t, stdout, stderr)
	if !strings.Contains(stdout+stderr, "not verified") {
		t.Errorf("output = %q, want the refusal to say the rotation was not verified", stdout+stderr)
	}
}

// A plan that widens privilege is refused, and the refusal says so.
func TestRotationVerifyRefusesAPlanThatWidensPrivilege(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)
	plans[0].NewScope = []string{"read", "write", "admin"}
	planPath := writePlans(t, dir, "plans.json", plans)
	secretPath := writeExpectedSecrets(t, dir, "expected.json", plans)

	stdout, stderr, code := capture(t, "rotation", "verify", "--file", planPath, "--secret-file", secretPath)
	if code != ExitRefused {
		t.Fatalf("code = %d, want %d", code, ExitRefused)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "privilege") {
		t.Errorf("output = %q, want it to name the widened privilege", combined)
	}
	assertNoSecret(t, stdout, stderr)
}

// The JSON mode is JSON, and it carries no secret.
func TestRotationVerifyJSONModeCarriesNoSecret(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)
	planPath := writePlans(t, dir, "plans.json", plans)
	secretPath := writeExpectedSecrets(t, dir, "expected.json", plans)

	stdout, stderr, code := capture(t, "rotation", "verify", "--file", planPath, "--secret-file", secretPath, "--json")
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	rotations, ok := report["rotations"].([]any)
	if !ok || len(rotations) != len(plans) {
		t.Fatalf("rotations = %v, want one per plan", report["rotations"])
	}
	assertNoSecret(t, stdout, stderr)
}

// The expected secret is read from a file, never from the command line.
func TestRotationVerifyReadsTheSecretFromAFileNotTheCommandLine(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)
	planPath := writePlans(t, dir, "plans.json", plans)
	secretPath := writeExpectedSecrets(t, dir, "expected.json", plans)

	stdout, stderr, code := capture(t, "rotation", "verify", "--file", planPath, "--secret", "s3cr3t")
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stdout+stderr, "--secret-file") {
		t.Errorf("output = %q, want it to point at --secret-file", stdout+stderr)
	}
	assertNoSecret(t, stdout, stderr)

	// The file is the way in, and it works.
	_, _, code = capture(t, "rotation", "verify", "--file", planPath, "--secret-file", secretPath)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
}

// A file that holds one secret is read as the secret every kind is expected to
// produce, which is the shape a single-kind rotation takes.
func TestRotationVerifyReadsASingleSecretFile(t *testing.T) {
	dir := t.TempDir()
	plan := planFor(t, oncall.KeyGitHubApp)
	planPath := writePlans(t, dir, "plans.json", []oncall.RotationPlan{plan})
	secretPath := writeFixture(t, dir, "secret.txt", plan.NewSecret+"\n")

	stdout, stderr, code := capture(t, "rotation", "verify", "--file", planPath, "--secret-file", secretPath)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout, "rotations verified: 1") {
		t.Errorf("stdout = %q, want the rotation verified", stdout)
	}
	assertNoSecret(t, stdout, stderr)
}

// ---------------------------------------------------------------------------
// coverage scorecard
// ---------------------------------------------------------------------------

// The scorecard reports the score and the weights behind it.
func TestCoverageScorecardReportsTheScoreAndTheWeights(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "coverage.json", coverageFile)

	stdout, _, code := capture(t, "coverage", "scorecard", "--file", path)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	for _, want := range []string{"cov-1", "score: 3/4", "passed 3", "failed 1", "api"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout = %q, want it to carry %q", stdout, want)
		}
	}
}

// The scorecard in JSON carries the same facts.
func TestCoverageScorecardJSONModeCarriesTheScore(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "coverage.json", coverageFile)

	stdout, _, code := capture(t, "coverage", "scorecard", "--file", path, "--json")
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if report["score"] != 0.75 {
		t.Errorf("score = %v, want 0.75", report["score"])
	}
	if report["passedWeight"] != float64(3) {
		t.Errorf("passedWeight = %v, want 3", report["passedWeight"])
	}
	if report["totalWeight"] != float64(4) {
		t.Errorf("totalWeight = %v, want 4", report["totalWeight"])
	}
}

// A scorecard nobody is accountable for is refused, and the refusal is a
// refusal rather than a crash.
func TestCoverageScorecardRefusesARegistryWithoutAnOwner(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "coverage.json", ownerlessCoverageFile)

	stdout, stderr, code := capture(t, "coverage", "scorecard", "--file", path)
	if code != ExitRefused {
		t.Fatalf("code = %d, want %d", code, ExitRefused)
	}
	if !strings.Contains(stdout+stderr, "owner") {
		t.Errorf("output = %q, want it to name the missing owner", stdout+stderr)
	}
}

// ---------------------------------------------------------------------------
// status page
// ---------------------------------------------------------------------------

// A component whose only check is too old is unknown, and it is printed as
// unknown.
func TestStatusPagePrintsAnUnknownComponentAsUnknown(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "status.json", statusFile)

	stdout, _, code := capture(t, "status", "page", "--file", path)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout, "db: unknown") {
		t.Errorf("stdout = %q, want the stale component printed as unknown", stdout)
	}
	if !strings.Contains(stdout, "api: operational") {
		t.Errorf("stdout = %q, want the fresh component printed as operational", stdout)
	}
}

// The unknown component is never presented as an operational one.
func TestStatusPageNeverPresentsAnUnknownComponentAsOperational(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "status.json", statusFile)

	stdout, stderr, code := capture(t, "status", "page", "--file", path, "--json")
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	var report struct {
		Components []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	for _, component := range report.Components {
		if component.Name == "db" && component.Status != "unknown" {
			t.Errorf("db status = %q, want unknown", component.Status)
		}
		if component.Name == "api" && component.Status != "operational" {
			t.Errorf("api status = %q, want operational", component.Status)
		}
	}
	assertNoSecret(t, stdout, stderr)
}

// A component whose check never ran is unknown too.
func TestStatusPagePrintsAComponentWithNoCheckAsUnknown(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "status.json", `[{"component":"db","ok":true}]`)

	stdout, _, code := capture(t, "status", "page", "--file", path)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout, "db: unknown") {
		t.Errorf("stdout = %q, want the unchecked component printed as unknown", stdout)
	}
	if strings.Contains(stdout, "db: operational") {
		t.Errorf("stdout = %q, want the unchecked component not printed as operational", stdout)
	}
}

// The freshness bound is a flag, and it changes what the page says.
func TestStatusPageHonoursTheMaxAgeFlag(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "status.json", statusFile)

	stdout, _, code := capture(t, "status", "page", "--file", path, "--max-age", "3h")
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout, "db: operational") {
		t.Errorf("stdout = %q, want the stale check to count under a wider bound", stdout)
	}
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

// The same input has to produce the same bytes, twice. A report that changes
// when nobody changed anything cannot be diffed and cannot be trusted.
func TestOutputIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)
	planPath := writePlans(t, dir, "plans.json", plans)
	secretPath := writeExpectedSecrets(t, dir, "expected.json", plans)
	shiftPath := writeFixture(t, dir, "shifts.json", coveredShifts)
	coveragePath := writeFixture(t, dir, "coverage.json", coverageFile)
	statusPath := writeFixture(t, dir, "status.json", statusFile)

	invocations := [][]string{
		{"oncall", "check", "--shifts", shiftPath, "--from", windowStart, "--to", windowEnd},
		{"oncall", "check", "--shifts", shiftPath, "--from", windowStart, "--to", windowEnd, "--json"},
		{"rotation", "plan", "--file", planPath},
		{"rotation", "plan", "--file", planPath, "--json"},
		{"rotation", "verify", "--file", planPath, "--secret-file", secretPath},
		{"rotation", "verify", "--file", planPath, "--secret-file", secretPath, "--json"},
		{"coverage", "scorecard", "--file", coveragePath},
		{"coverage", "scorecard", "--file", coveragePath, "--json"},
		{"status", "page", "--file", statusPath},
		{"status", "page", "--file", statusPath, "--json"},
	}

	for _, args := range invocations {
		firstOut, firstErr, firstCode := capture(t, args...)
		secondOut, secondErr, secondCode := capture(t, args...)
		if firstOut != secondOut || firstErr != secondErr || firstCode != secondCode {
			t.Errorf("%v is not deterministic:\nfirst:  %q %q %d\nsecond: %q %q %d",
				args, firstOut, firstErr, firstCode, secondOut, secondErr, secondCode)
		}
	}
}

// Every command's JSON mode is JSON, and it is an object.
func TestJSONModeIsValidJSONForEveryCommand(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)
	planPath := writePlans(t, dir, "plans.json", plans)
	secretPath := writeExpectedSecrets(t, dir, "expected.json", plans)
	shiftPath := writeFixture(t, dir, "shifts.json", coveredShifts)
	coveragePath := writeFixture(t, dir, "coverage.json", coverageFile)
	statusPath := writeFixture(t, dir, "status.json", statusFile)

	invocations := [][]string{
		{"oncall", "check", "--shifts", shiftPath, "--from", windowStart, "--to", windowEnd, "--json"},
		{"rotation", "plan", "--file", planPath, "--json"},
		{"rotation", "verify", "--file", planPath, "--secret-file", secretPath, "--json"},
		{"coverage", "scorecard", "--file", coveragePath, "--json"},
		{"status", "page", "--file", statusPath, "--json"},
	}

	for _, args := range invocations {
		stdout, _, _ := capture(t, args...)
		var report map[string]any
		if err := json.Unmarshal([]byte(stdout), &report); err != nil {
			t.Errorf("%v did not produce JSON: %v\n%s", args, err, stdout)
			continue
		}
		if report["status"] != "ok" {
			t.Errorf("%v status = %v, want ok", args, report["status"])
		}
	}
}

// A refusal in the JSON mode carries its reason. A JSON mode that drops the
// reason is worse than no JSON mode.
func TestJSONModeCarriesTheReasonForARefusal(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)[:5]
	planPath := writePlans(t, dir, "plans.json", plans)
	shiftPath := writeFixture(t, dir, "shifts.json", gappedShifts)

	invocations := [][]string{
		{"rotation", "plan", "--file", planPath, "--json"},
		{"oncall", "check", "--shifts", shiftPath, "--from", windowStart, "--to", windowEnd, "--json"},
	}

	for _, args := range invocations {
		stdout, _, code := capture(t, args...)
		if code != ExitRefused {
			t.Fatalf("%v code = %d, want %d", args, code, ExitRefused)
		}
		var report map[string]any
		if err := json.Unmarshal([]byte(stdout), &report); err != nil {
			t.Errorf("%v did not produce JSON: %v\n%s", args, err, stdout)
			continue
		}
		reason, ok := report["reason"].(string)
		if !ok || reason == "" {
			t.Errorf("%v reason = %v, want the refusal reason", args, report["reason"])
		}
		if report["status"] != "refused" {
			t.Errorf("%v status = %v, want refused", args, report["status"])
		}
	}
}

// The reason for a refusal is in the text an operator reads, not only in the
// machine-readable one.
func TestTheHumanReadableOutputNamesTheReasonForARefusal(t *testing.T) {
	dir := t.TempDir()
	plans := plansForEveryKind(t)[:5]
	path := writePlans(t, dir, "plans.json", plans)

	stdout, stderr, code := capture(t, "rotation", "plan", "--file", path)
	if code != ExitRefused {
		t.Fatalf("code = %d, want %d", code, ExitRefused)
	}
	if !strings.Contains(stdout, "refused:") {
		t.Errorf("stdout = %q, want it to say the plan was refused", stdout)
	}
	if !strings.Contains(stdout, "allocator-credentials") {
		t.Errorf("stdout = %q, want it to name the missing kinds", stdout)
	}
	if !strings.Contains(stderr, "allocator-credentials") {
		t.Errorf("stderr = %q, want it to name the missing kinds", stderr)
	}
}

// Nothing prints the wall-clock time of the run, because a report that changes
// when nobody changed anything is a report nobody can diff.
func TestNoWallClockTimeIsPrinted(t *testing.T) {
	dir := t.TempDir()
	shiftPath := writeFixture(t, dir, "shifts.json", coveredShifts)
	coveragePath := writeFixture(t, dir, "coverage.json", coverageFile)
	statusPath := writeFixture(t, dir, "status.json", statusFile)

	invocations := [][]string{
		{"oncall", "check", "--shifts", shiftPath, "--from", windowStart, "--to", windowEnd},
		{"coverage", "scorecard", "--file", coveragePath},
		{"status", "page", "--file", statusPath},
	}
	// The moment of the run is a second past the moment the fixtures were
	// written around, so that it can be looked for in the output.
	later := testNow.Add(time.Second)
	for _, args := range invocations {
		stdout, stderr, _ := captureAt(t, later, args...)
		if strings.Contains(stdout+stderr, later.Format(time.RFC3339)) {
			t.Errorf("%v printed the moment of the run: %q", args, stdout+stderr)
		}
	}
}
