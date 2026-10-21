package coverage

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 5, 4, 10, 0, 0, 0, time.UTC)

// method is the methodology every scorecard in this file is computed under.
func method() Methodology {
	return Methodology{
		Version:       "cov-2026.1",
		EffectiveFrom: now.Add(-30 * 24 * time.Hour),
		Notes:         "evidence coverage only; not an outage probability",
	}
}

// fleet is a small but complete declaration: two services, three invariants, one of
// them about a dependency.
func registry(t *testing.T) Registry {
	t.Helper()
	var reg Registry
	add := func(inv Invariant) {
		var err error
		reg, err = Register(reg, inv)
		if err != nil {
			t.Fatalf("Register(%q): %v", inv.ID, err)
		}
	}
	add(Invariant{
		ID: "api-tls", Service: "api", Weight: 3,
		RequiredProfile: "e2e", EvidenceMaxAge: 14 * 24 * time.Hour, Required: true,
	})
	add(Invariant{
		ID: "api-authz", Service: "api", Weight: 2,
		RequiredProfile: "e2e", EvidenceMaxAge: 14 * 24 * time.Hour, Required: true,
	})
	add(Invariant{
		ID: "api-docs", Service: "api", Weight: 1,
		RequiredProfile: "unit", EvidenceMaxAge: 30 * 24 * time.Hour, Required: false,
	})
	add(Invariant{
		ID: "db-backup", Service: "db", Dependency: "postgres", Weight: 4,
		RequiredProfile: "e2e", EvidenceMaxAge: 7 * 24 * time.Hour, Required: true,
	})
	reg, err := SetOwner(reg, "api", "platform")
	if err != nil {
		t.Fatalf("SetOwner(api): %v", err)
	}
	reg, err = SetOwner(reg, "db", "data")
	if err != nil {
		t.Fatalf("SetOwner(db): %v", err)
	}
	return reg
}

func passing(id, profile string, age time.Duration) Evidence {
	return Evidence{InvariantID: id, Profile: profile, TestedAt: now.Add(-age), Outcome: OutcomePass}
}

func failing(id, profile string, age time.Duration) Evidence {
	return Evidence{InvariantID: id, Profile: profile, TestedAt: now.Add(-age), Outcome: OutcomeFail}
}

func card(t *testing.T, f Fleet, service string) ServiceScorecard {
	t.Helper()
	for _, c := range f.Services {
		if c.Service == service {
			return c
		}
	}
	t.Fatalf("no scorecard for service %q", service)
	return ServiceScorecard{}
}

// ---------------------------------------------------------------------------
// Declaration
// ---------------------------------------------------------------------------

// A declaration that cannot be scored, or that would be scored wrongly, is refused at
// registration rather than producing a misleading number later.
func TestRegisterRefusesUnscorableInvariants(t *testing.T) {
	base := Invariant{
		ID: "api-tls", Service: "api", Weight: 3,
		RequiredProfile: "e2e", EvidenceMaxAge: 14 * 24 * time.Hour, Required: true,
	}
	cases := map[string]struct {
		mutate func(*Invariant)
		want   error
	}{
		"no identifier":             {func(i *Invariant) { i.ID = "  " }, ErrNoInvariantID},
		"no service":                {func(i *Invariant) { i.Service = "" }, ErrNoService},
		"zero weight":               {func(i *Invariant) { i.Weight = 0 }, ErrNoWeight},
		"no profile":                {func(i *Invariant) { i.RequiredProfile = "" }, ErrNoProfile},
		"no max age":                {func(i *Invariant) { i.EvidenceMaxAge = 0 }, ErrNoMaxAge},
		"critical but not required": {func(i *Invariant) { i.Critical = true; i.Required = false }, ErrCriticalNotRequired},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			inv := base
			tc.mutate(&inv)
			if _, err := Register(Registry{}, inv); !errors.Is(err, tc.want) {
				t.Errorf("Register error = %v, want %v", err, tc.want)
			}
		})
	}
}

// A renamed invariant must not silently inherit its old identity.
func TestRegisterRefusesDuplicateIdentifiers(t *testing.T) {
	reg := registry(t)
	_, err := Register(reg, Invariant{
		ID: "api-tls", Service: "api", Weight: 1,
		RequiredProfile: "e2e", EvidenceMaxAge: time.Hour, Required: true,
	})
	if !errors.Is(err, ErrDuplicateInvariant) {
		t.Errorf("Register error = %v, want ErrDuplicateInvariant", err)
	}
}

// Coverage without an owner is a number nobody is accountable for.
func TestSetOwnerRequiresAName(t *testing.T) {
	if _, err := SetOwner(Registry{}, "api", "  "); !errors.Is(err, ErrEmptyOwner) {
		t.Errorf("SetOwner error = %v, want ErrEmptyOwner", err)
	}
	if _, err := SetOwner(Registry{}, "", "platform"); !errors.Is(err, ErrNoService) {
		t.Errorf("SetOwner error = %v, want ErrNoService", err)
	}
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

// The formula is fixed: passed-fresh applicable required weight over total applicable
// required weight.
func TestScoreIsPassedWeightOverTotalRequiredWeight(t *testing.T) {
	f, err := Build(registry(t), []Evidence{
		passing("api-tls", "e2e", time.Hour),
		passing("api-authz", "e2e", time.Hour),
		passing("db-backup", "e2e", time.Hour),
	}, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	api := card(t, f, "api")
	// api-tls weight 3 and api-authz weight 2 are required and passing; api-docs is
	// advisory and does not enter the denominator.
	if api.Breakdown.TotalWeight != 5 || api.Breakdown.PassedWeight != 5 {
		t.Errorf("api breakdown = %+v, want 5/5", api.Breakdown)
	}
	if api.Score != 1.0 {
		t.Errorf("api score = %v, want 1.0", api.Score)
	}
	db := card(t, f, "db")
	if db.Breakdown.TotalWeight != 4 || db.Score != 1.0 {
		t.Errorf("db breakdown = %+v, want 4/4", db.Breakdown)
	}
	if f.Breakdown.TotalWeight != 9 || f.Breakdown.PassedWeight != 9 || f.Score != 1.0 {
		t.Errorf("fleet breakdown = %+v, want 9/9", f.Breakdown)
	}
}

// An untested invariant drags the score down rather than being treated as neutral.
func TestUntestedInvariantIsNotGreen(t *testing.T) {
	f, err := Build(registry(t), []Evidence{
		passing("api-tls", "e2e", time.Hour),
	}, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	api := card(t, f, "api")
	if api.Breakdown.UntestedWeight != 2 {
		t.Errorf("untested weight = %d, want 2", api.Breakdown.UntestedWeight)
	}
	if api.Score != 0.6 {
		t.Errorf("api score = %v, want 0.6 (3 of 5)", api.Score)
	}
}

// Stale evidence proves nothing either way: it is not green, and it is not red.
func TestStaleEvidenceIsNeitherPassedNorFailed(t *testing.T) {
	f, err := Build(registry(t), []Evidence{
		passing("api-tls", "e2e", 30*24*time.Hour), // max age is 14 days
		failing("api-authz", "e2e", 30*24*time.Hour),
	}, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	api := card(t, f, "api")
	if api.Breakdown.StaleWeight != 5 {
		t.Errorf("stale weight = %d, want 5", api.Breakdown.StaleWeight)
	}
	if api.Breakdown.PassedWeight != 0 || api.Breakdown.FailedWeight != 0 {
		t.Errorf("stale evidence moved a passed or failed count: %+v", api.Breakdown)
	}
	if api.Score != 0 {
		t.Errorf("api score = %v, want 0", api.Score)
	}
}

// A stale failure is not a current failure, and must not veto the service.
func TestStaleFailureDoesNotBlock(t *testing.T) {
	reg, err := Register(registry(t), Invariant{
		ID: "api-quota", Service: "api", Weight: 1,
		RequiredProfile: "e2e", EvidenceMaxAge: 24 * time.Hour, Required: true, Critical: true,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	f, err := Build(reg, []Evidence{
		failing("api-quota", "e2e", 48*time.Hour),
	}, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	api := card(t, f, "api")
	if api.Blocked {
		t.Error("a stale failure must not block the service")
	}
	if len(api.UnverifiedCritical) != 1 || api.UnverifiedCritical[0] != "api-quota" {
		t.Errorf("unverified critical = %v, want the stale quota invariant listed", api.UnverifiedCritical)
	}
}

// A result from the wrong profile does not establish the invariant.
func TestWrongProfileIsInconclusive(t *testing.T) {
	f, err := Build(registry(t), []Evidence{
		passing("api-tls", "unit", time.Hour),
	}, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	api := card(t, f, "api")
	if api.Breakdown.InconclusiveWeight != 3 {
		t.Errorf("inconclusive weight = %d, want 3", api.Breakdown.InconclusiveWeight)
	}
	if api.Breakdown.PassedWeight != 0 {
		t.Errorf("a wrong-profile pass counted as passed: %+v", api.Breakdown)
	}
}

// An explicitly inconclusive run is not a pass.
func TestInconclusiveOutcomeIsNotGreen(t *testing.T) {
	f, err := Build(registry(t), []Evidence{
		{InvariantID: "api-tls", Profile: "e2e", TestedAt: now.Add(-time.Hour), Outcome: OutcomeInconclusive},
	}, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	api := card(t, f, "api")
	if api.Breakdown.InconclusiveWeight != 3 || api.Score != 0 {
		t.Errorf("breakdown = %+v, want the weight inconclusive and the score zero", api.Breakdown)
	}
}

// The newest evidence supersedes the older one.
func TestNewestEvidenceSupersedesOlder(t *testing.T) {
	f, err := Build(registry(t), []Evidence{
		failing("api-tls", "e2e", 48*time.Hour),
		passing("api-tls", "e2e", time.Hour),
	}, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	api := card(t, f, "api")
	if api.Breakdown.PassedWeight != 3 || api.Breakdown.FailedWeight != 0 {
		t.Errorf("breakdown = %+v, want the newer pass to win", api.Breakdown)
	}
}

// Two results for one invariant at the same instant, disagreeing, have no honest
// resolution.
func TestAmbiguousEvidenceIsRefused(t *testing.T) {
	at := now.Add(-time.Hour)
	_, err := Build(registry(t), []Evidence{
		{InvariantID: "api-tls", Profile: "e2e", TestedAt: at, Outcome: OutcomePass},
		{InvariantID: "api-tls", Profile: "e2e", TestedAt: at, Outcome: OutcomeFail},
	}, now, method())
	if !errors.Is(err, ErrAmbiguousEvidence) {
		t.Errorf("Build error = %v, want ErrAmbiguousEvidence", err)
	}
}

// Evidence for an invariant that does not exist is refused rather than ignored, because
// silently dropping it is how a renamed invariant keeps its old green score.
func TestEvidenceForAnUnknownInvariantIsRefused(t *testing.T) {
	_, err := Build(registry(t), []Evidence{passing("no-such-invariant", "e2e", time.Hour)}, now, method())
	if !errors.Is(err, ErrUnknownInvariant) {
		t.Errorf("Build error = %v, want ErrUnknownInvariant", err)
	}
}

// A future date is a skewed clock or a typo, and treating it as fresh would let a
// broken clock certify anything.
func TestFutureEvidenceIsRefused(t *testing.T) {
	_, err := Build(registry(t), []Evidence{
		{InvariantID: "api-tls", Profile: "e2e", TestedAt: now.Add(time.Hour), Outcome: OutcomePass},
	}, now, method())
	if !errors.Is(err, ErrFutureEvidence) {
		t.Errorf("Build error = %v, want ErrFutureEvidence", err)
	}
}

func TestUnknownOutcomeIsRefused(t *testing.T) {
	_, err := Build(registry(t), []Evidence{
		{InvariantID: "api-tls", Profile: "e2e", TestedAt: now.Add(-time.Hour), Outcome: Outcome("maybe")},
	}, now, method())
	if !errors.Is(err, ErrUnknownOutcome) {
		t.Errorf("Build error = %v, want ErrUnknownOutcome", err)
	}
}

// ---------------------------------------------------------------------------
// Blocking
// ---------------------------------------------------------------------------

// A service may hold a high coverage fraction and still be blocked by a single failed
// critical invariant. Coverage says the evidence exists; it says nothing about whether
// the evidence is good.
func TestFailedCriticalInvariantBlocksDespiteHighCoverage(t *testing.T) {
	reg, err := Register(registry(t), Invariant{
		ID: "api-quota", Service: "api", Weight: 1,
		RequiredProfile: "e2e", EvidenceMaxAge: 24 * time.Hour, Required: true, Critical: true,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	f, err := Build(reg, []Evidence{
		passing("api-tls", "e2e", time.Hour),
		passing("api-authz", "e2e", time.Hour),
		passing("db-backup", "e2e", time.Hour),
		failing("api-quota", "e2e", time.Hour),
	}, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	api := card(t, f, "api")
	if api.Score < 0.8 {
		t.Errorf("api score = %v, want a high fraction for this test to mean anything", api.Score)
	}
	if !api.Blocked {
		t.Fatal("a failed critical invariant must block the service")
	}
	if len(api.BlockingCritical) != 1 || api.BlockingCritical[0] != "api-quota" {
		t.Errorf("blocking critical = %v, want the failed quota invariant", api.BlockingCritical)
	}
}

// The blocked state and the score are separate. A blocked service's score still
// reports honestly.
func TestBlockedServiceStillReportsItsScore(t *testing.T) {
	reg, err := Register(registry(t), Invariant{
		ID: "api-quota", Service: "api", Weight: 1, Critical: true, Required: true,
		RequiredProfile: "e2e", EvidenceMaxAge: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	f, err := Build(reg, []Evidence{
		passing("api-tls", "e2e", time.Hour),
		passing("api-authz", "e2e", time.Hour),
		failing("api-quota", "e2e", time.Hour),
	}, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	api := card(t, f, "api")
	if !api.Blocked {
		t.Fatal("expected the service to be blocked")
	}
	if api.Breakdown.FailedWeight != 1 {
		t.Errorf("failed weight = %d, want 1", api.Breakdown.FailedWeight)
	}
	if api.Breakdown.PassedWeight != 5 {
		t.Errorf("passed weight = %d, want 5", api.Breakdown.PassedWeight)
	}
}

// ---------------------------------------------------------------------------
// Owners, scope and dependencies
// ---------------------------------------------------------------------------

// A service in scope with no owner cannot be reported.
func TestServiceInScopeMustHaveAnOwner(t *testing.T) {
	reg := registry(t)
	delete(reg.Owners, "db")
	_, err := Build(reg, nil, now, method())
	if !errors.Is(err, ErrNoOwner) {
		t.Errorf("Build error = %v, want ErrNoOwner", err)
	}
}

// A scorecard that covers less than the fleet says so.
func TestScopeExcludesServicesAndSaysWhich(t *testing.T) {
	reg := registry(t)
	reg.Scope = []string{"api"}
	f, err := Build(reg, []Evidence{
		passing("api-tls", "e2e", time.Hour),
	}, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(f.Services) != 1 || f.Services[0].Service != "api" {
		t.Errorf("services = %v, want only api", f.Services)
	}
	if len(f.OutOfScope) != 1 || f.OutOfScope[0] != "db" {
		t.Errorf("out of scope = %v, want db", f.OutOfScope)
	}
}

func TestScopeNamingAnUnknownServiceIsRefused(t *testing.T) {
	reg := registry(t)
	reg.Scope = []string{"nosuch"}
	if _, err := Build(reg, nil, now, method()); !errors.Is(err, ErrUnknownService) {
		t.Errorf("Build error = %v, want ErrUnknownService", err)
	}
}

// A service with no required invariant is reported as having no coverage, which is a
// different fact from covering nothing.
func TestServiceWithNoRequiredInvariantIsReportedAsNoCoverage(t *testing.T) {
	var reg Registry
	reg, err := Register(reg, Invariant{
		ID: "api-docs", Service: "api", Weight: 1, Required: false,
		RequiredProfile: "unit", EvidenceMaxAge: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	reg, err = SetOwner(reg, "api", "platform")
	if err != nil {
		t.Fatalf("SetOwner: %v", err)
	}
	f, err := Build(reg, nil, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	api := card(t, f, "api")
	if api.HasRequired {
		t.Error("a service with only advisory invariants has no required coverage")
	}
	if len(f.NoCoverage) != 1 || f.NoCoverage[0] != "api" {
		t.Errorf("no coverage = %v, want api", f.NoCoverage)
	}
}

// Dependencies get their own view, because coverage of a dependency is a different
// question from coverage of a service.
func TestDependencyCoverageIsReportedSeparately(t *testing.T) {
	f, err := Build(registry(t), []Evidence{
		passing("db-backup", "e2e", time.Hour),
	}, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(f.DependencyCoverage) != 1 {
		t.Fatalf("dependency coverage = %v, want one entry", f.DependencyCoverage)
	}
	dep := f.DependencyCoverage[0]
	if dep.Dependency != "postgres" || dep.TotalWeight != 4 || dep.PassedWeight != 4 || dep.Score != 1.0 {
		t.Errorf("dependency coverage = %+v, want postgres 4/4", dep)
	}
	if len(dep.Services) != 1 || dep.Services[0] != "db" {
		t.Errorf("dependency services = %v, want db", dep.Services)
	}
	db := card(t, f, "db")
	if len(db.Dependencies) != 1 || db.Dependencies[0] != "postgres" {
		t.Errorf("db dependencies = %v, want postgres", db.Dependencies)
	}
}

// ---------------------------------------------------------------------------
// Methodology and visibility
// ---------------------------------------------------------------------------

// A coverage number without its method cannot be compared to anything.
func TestMethodologyIsRequiredAndMustBeInEffect(t *testing.T) {
	if _, err := Build(registry(t), nil, now, Methodology{}); !errors.Is(err, ErrNoMethodology) {
		t.Errorf("Build error = %v, want ErrNoMethodology", err)
	}
	future := method()
	future.EffectiveFrom = now.Add(24 * time.Hour)
	if _, err := Build(registry(t), nil, now, future); !errors.Is(err, ErrMethodologyNotInEffect) {
		t.Errorf("Build error = %v, want ErrMethodologyNotInEffect", err)
	}
}

// The methodology version and the actual test dates are visible, because a coverage
// number nobody can check is a number nobody can argue with.
func TestMethodologyAndActualTestDatesAreVisible(t *testing.T) {
	f, err := Build(registry(t), []Evidence{
		passing("api-tls", "e2e", 3*time.Hour),
	}, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	api := card(t, f, "api")
	if api.MethodologyVersion != "cov-2026.1" {
		t.Errorf("methodology version = %q, want cov-2026.1", api.MethodologyVersion)
	}
	date, ok := api.EvidenceDates["api-tls"]
	if !ok {
		t.Fatal("the evidence date must be visible")
	}
	if !date.Equal(now.Add(-3 * time.Hour)) {
		t.Errorf("evidence date = %s, want the actual test time", date)
	}
	if _, ok := api.EvidenceDates["api-authz"]; ok {
		t.Error("an untested invariant must not carry an evidence date")
	}
	report := f.Report()
	for _, want := range []string{"cov-2026.1", "api-tls tested", "untested"} {
		if !strings.Contains(report, want) {
			t.Errorf("report is missing %q:\n%s", want, report)
		}
	}
}

// The report names a blocked service as blocked, so the number never stands alone.
func TestReportNamesBlockedServices(t *testing.T) {
	reg, err := Register(registry(t), Invariant{
		ID: "api-quota", Service: "api", Weight: 1, Critical: true, Required: true,
		RequiredProfile: "e2e", EvidenceMaxAge: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	f, err := Build(reg, []Evidence{failing("api-quota", "e2e", time.Hour)}, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	report := f.Report()
	if !strings.Contains(report, "BLOCKED") || !strings.Contains(report, "api-quota") {
		t.Errorf("report does not name the blocked invariant:\n%s", report)
	}
}

// The report is deterministic.
func TestReportIsDeterministic(t *testing.T) {
	ev := []Evidence{
		passing("api-tls", "e2e", time.Hour),
		passing("api-authz", "e2e", time.Hour),
		passing("db-backup", "e2e", time.Hour),
	}
	first, err := Build(registry(t), ev, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	second, err := Build(registry(t), ev, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if first.Report() != second.Report() {
		t.Error("two scorecards over identical inputs must render identically")
	}
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

// Two services, one dependency, one advisory invariant, a critical veto and a clean
// fleet — and the numbers are the ones the formula dictates.
func TestHappyPathFleetScorecard(t *testing.T) {
	reg, err := Register(registry(t), Invariant{
		ID: "api-quota", Service: "api", Weight: 1, Critical: true, Required: true,
		RequiredProfile: "e2e", EvidenceMaxAge: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	f, err := Build(reg, []Evidence{
		passing("api-tls", "e2e", time.Hour),
		passing("api-authz", "e2e", time.Hour),
		passing("api-quota", "e2e", time.Hour),
		passing("db-backup", "e2e", time.Hour),
		passing("api-docs", "unit", time.Hour),
	}, now, method())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if f.Score != 1.0 {
		t.Errorf("fleet score = %v, want 1.0", f.Score)
	}
	if f.Breakdown.TotalWeight != 10 {
		t.Errorf("total weight = %d, want 10", f.Breakdown.TotalWeight)
	}
	api := card(t, f, "api")
	if api.Blocked {
		t.Error("the critical invariant passed, so the service must not be blocked")
	}
	if len(api.Advisory) != 1 || api.Advisory[0] != "api-docs" {
		t.Errorf("advisory = %v, want the advisory invariant listed", api.Advisory)
	}
	if api.Breakdown.TotalWeight != 6 {
		t.Errorf("api total weight = %d, want 6 (the advisory invariant does not count)", api.Breakdown.TotalWeight)
	}
	if len(f.NoCoverage) != 0 {
		t.Errorf("no coverage = %v, want none", f.NoCoverage)
	}
	if !strings.Contains(f.Report(), fmt.Sprintf("methodology: %s", "cov-2026.1")) {
		t.Errorf("report does not name the methodology:\n%s", f.Report())
	}
}
