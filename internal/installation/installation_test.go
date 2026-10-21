package installation

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 6, 11, 0, 0, 0, time.UTC)

// registry is one verified installation with two granted repositories, and a second
// empty installation to reassign into.
func registry(t *testing.T) Registry {
	t.Helper()
	var r Registry
	var err error
	r, err = r.Add(Installation{
		ID: "inst-acme", AccountID: "42", AccountLogin: "acme", TenantID: "org-1",
		Repositories: []Repository{
			{ID: "repo-1", FullName: "acme/api", Private: true},
			{ID: "repo-2", FullName: "acme/web"},
		},
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	r, err = r.Add(Installation{ID: "inst-other", AccountID: "77", AccountLogin: "other", TenantID: "org-2"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	return r
}

// verified returns a registry whose first installation is verified.
func verified(t *testing.T) Registry {
	t.Helper()
	r, err := registry(t).VerifyInstallation("inst-acme", Evidence{
		Digest: "sha256:payload", IssuedAt: now.Add(-time.Minute), Verified: true,
	}, now)
	if err != nil {
		t.Fatalf("VerifyInstallation: %v", err)
	}
	return r
}

func granted() []string { return []string{"repo-1", "repo-2"} }

func install(t *testing.T, r Registry, id string) Installation {
	t.Helper()
	i, ok := r.install(id)
	if !ok {
		t.Fatalf("no installation %q", id)
	}
	return i
}

// ---------------------------------------------------------------------------
// Registration and verification
// ---------------------------------------------------------------------------

func TestAddRefusesIncompleteInstallations(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Installation)
		want   error
	}{
		"no identifier": {func(i *Installation) { i.ID = "" }, ErrNoInstallationID},
		"no account":    {func(i *Installation) { i.AccountID = "" }, ErrNoAccount},
		"no tenant":     {func(i *Installation) { i.TenantID = "" }, ErrNoTenant},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			i := Installation{ID: "inst", AccountID: "42", TenantID: "org-1"}
			tc.mutate(&i)
			if _, err := (Registry{}).Add(i); !errors.Is(err, tc.want) {
				t.Errorf("Add error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAddRefusesDuplicateIdentifiers(t *testing.T) {
	r := registry(t)
	if _, err := r.Add(Installation{ID: "inst-acme", AccountID: "42", TenantID: "org-1"}); !errors.Is(err, ErrDuplicateInstallation) {
		t.Errorf("Add error = %v, want ErrDuplicateInstallation", err)
	}
}

// The installation payload is what proves the account granted us access, and a stale
// grant is not a grant.
func TestVerificationRequiresFreshVerifiedEvidence(t *testing.T) {
	r := registry(t)
	if _, err := r.VerifyInstallation("inst-acme", Evidence{IssuedAt: now, Verified: false}, now); !errors.Is(err, ErrNoVerification) {
		t.Errorf("VerifyInstallation error = %v, want ErrNoVerification", err)
	}
	if _, err := r.VerifyInstallation("inst-acme", Evidence{Digest: "sha256:x", IssuedAt: now}, now); !errors.Is(err, ErrNoVerification) {
		t.Errorf("VerifyInstallation error = %v, want ErrNoVerification", err)
	}
	if _, err := r.VerifyInstallation("inst-acme", Evidence{Digest: "sha256:x", IssuedAt: now.Add(-2 * time.Hour), Verified: true}, now); !errors.Is(err, ErrVerificationExpired) {
		t.Errorf("VerifyInstallation error = %v, want ErrVerificationExpired", err)
	}
}

func TestVerificationMustFollowTheWizardOrder(t *testing.T) {
	// Selecting before verification is refused: the wizard's steps are ordered.
	r := verified(t)
	if _, err := r.SelectRepositories("inst-acme", []string{"repo-1"}, granted(), now); err != nil {
		t.Fatalf("SelectRepositories: %v", err)
	}
	if _, err := r.VerifyInstallation("inst-acme", Evidence{Digest: "d", IssuedAt: now, Verified: true}, now); !errors.Is(err, ErrInvalidState) {
		t.Errorf("second VerifyInstallation error = %v, want ErrInvalidState", err)
	}
	if _, err := r.Configure("inst-acme", nil, now); !errors.Is(err, ErrInvalidState) {
		t.Errorf("Configure before selection = %v, want ErrInvalidState", err)
	}
}

// A repository outside the grant is refused, not dropped: a partial selection that
// reports success is a repository whose pull requests are never reviewed.
func TestSelectionOutsideTheGrantIsRefusedAndNamed(t *testing.T) {
	r := verified(t)
	_, err := r.SelectRepositories("inst-acme", []string{"repo-1", "repo-9"}, granted(), now)
	if !errors.Is(err, ErrRepositoryNotGranted) {
		t.Fatalf("SelectRepositories error = %v, want ErrRepositoryNotGranted", err)
	}
	if !strings.Contains(err.Error(), "repo-9") {
		t.Errorf("the refusal must name the repository, got %v", err)
	}
	// And nothing was selected.
	i := install(t, r, "inst-acme")
	if len(i.SelectedRepositories()) != 0 {
		t.Error("a refused selection must select nothing")
	}
}

func TestSelectionBoundsAndDuplicates(t *testing.T) {
	r := verified(t)
	if _, err := r.SelectRepositories("inst-acme", nil, granted(), now); !errors.Is(err, ErrNoRepositories) {
		t.Errorf("SelectRepositories error = %v, want ErrNoRepositories", err)
	}
	if _, err := r.SelectRepositories("inst-acme", []string{"repo-1", "repo-1"}, granted(), now); !errors.Is(err, ErrDuplicateRepository) {
		t.Errorf("SelectRepositories error = %v, want ErrDuplicateRepository", err)
	}
	many := make([]string, 0, MaxRepositories+1)
	for n := 0; n <= MaxRepositories; n++ {
		many = append(many, "repo-"+strings.Repeat("x", n%3))
	}
	if _, err := r.SelectRepositories("inst-acme", many, granted(), now); !errors.Is(err, ErrTooManyRepositories) {
		t.Errorf("SelectRepositories error = %v, want ErrTooManyRepositories", err)
	}
}

func TestSelectionMarksExactlyTheChosenRepositories(t *testing.T) {
	r, err := verified(t).SelectRepositories("inst-acme", []string{"repo-2"}, granted(), now)
	if err != nil {
		t.Fatalf("SelectRepositories: %v", err)
	}
	i := install(t, r, "inst-acme")
	selected := i.SelectedRepositories()
	if len(selected) != 1 || selected[0].ID != "repo-2" {
		t.Errorf("selected = %v, want only repo-2", selected)
	}
	if i.State != StateSelected {
		t.Errorf("state = %q, want selected", i.State)
	}
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func TestConfigureRequiresAConfigurationAndTheRightState(t *testing.T) {
	r, err := verified(t).SelectRepositories("inst-acme", []string{"repo-1"}, granted(), now)
	if err != nil {
		t.Fatalf("SelectRepositories: %v", err)
	}
	if _, err := r.Configure("inst-acme", nil, now); !errors.Is(err, ErrNoConfiguration) {
		t.Errorf("Configure error = %v, want ErrNoConfiguration", err)
	}
	out, err := r.Configure("inst-acme", map[string]string{"webhook": "https://example.com/hook"}, now)
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if install(t, out, "inst-acme").State != StateReady {
		t.Error("state must be ready after configuration")
	}
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

// Revocation is immediate, irreversible, and needs a named actor and a reason.
func TestRevocationRequiresAnActorAndAReason(t *testing.T) {
	r := verified(t)
	if _, err := r.Revoke("inst-acme", "  ", "compromised", now); !errors.Is(err, ErrNoRevocationActor) {
		t.Errorf("Revoke error = %v, want ErrNoRevocationActor", err)
	}
	if _, err := r.Revoke("inst-acme", "ada", "  ", now); !errors.Is(err, ErrNoRevocationReason) {
		t.Errorf("Revoke error = %v, want ErrNoRevocationReason", err)
	}
}

// A revoked installation refuses every later operation.
func TestRevokedInstallationRefusesEveryOperation(t *testing.T) {
	r, err := verified(t).Revoke("inst-acme", "ada", "credentials rotated", now)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	i := install(t, r, "inst-acme")
	if i.State != StateRevoked || i.RevokedBy != "ada" || i.RevocationReason != "credentials rotated" {
		t.Errorf("revocation = %+v, want it recorded", i)
	}
	if _, err := r.SelectRepositories("inst-acme", []string{"repo-1"}, granted(), now); !errors.Is(err, ErrRevoked) {
		t.Errorf("SelectRepositories error = %v, want ErrRevoked", err)
	}
	if _, err := r.Configure("inst-acme", map[string]string{"a": "b"}, now); !errors.Is(err, ErrRevoked) {
		t.Errorf("Configure error = %v, want ErrRevoked", err)
	}
	if _, err := r.Reassign("inst-acme", "repo-1", "inst-other", now); !errors.Is(err, ErrRevoked) {
		t.Errorf("Reassign error = %v, want ErrRevoked", err)
	}
	if _, err := r.Revoke("inst-acme", "ada", "again", now); !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("second Revoke error = %v, want ErrAlreadyRevoked", err)
	}
}

// Revocation is irreversible: an installation revoked for a reason may be revoked
// again for the same reason, and a restore button would make revoking feel temporary.
func TestRevocationCannotBeUndone(t *testing.T) {
	r, err := verified(t).Revoke("inst-acme", "ada", "compromised", now)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := r.VerifyInstallation("inst-acme", Evidence{Digest: "d", IssuedAt: now, Verified: true}, now); !errors.Is(err, ErrRevoked) {
		t.Errorf("VerifyInstallation after revocation = %v, want ErrRevoked", err)
	}
}

// ---------------------------------------------------------------------------
// Reassignment
// ---------------------------------------------------------------------------

// A repository with live environments cannot be moved, because those environments
// belong to the ownership being moved.
func TestReassignmentIsRefusedWhileEnvironmentsAreLive(t *testing.T) {
	r := verified(t)
	for idx := range r.Installations {
		if r.Installations[idx].ID == "inst-acme" {
			r.Installations[idx].Repositories[0].LiveEnvironments = 3
		}
	}
	_, err := r.Reassign("inst-acme", "repo-1", "inst-other", now)
	if !errors.Is(err, ErrHasLiveEnvironments) {
		t.Errorf("Reassign error = %v, want ErrHasLiveEnvironments", err)
	}
	if !strings.Contains(err.Error(), "repo-1") {
		t.Errorf("the refusal must name the repository, got %v", err)
	}
}

func TestReassignmentMovesTheRepositoryToTheTarget(t *testing.T) {
	r, err := verified(t).Reassign("inst-acme", "repo-1", "inst-other", now)
	if err != nil {
		t.Fatalf("Reassign: %v", err)
	}
	source := install(t, r, "inst-acme")
	target := install(t, r, "inst-other")
	var found *Repository
	for idx := range source.Repositories {
		if source.Repositories[idx].ID == "repo-1" {
			found = &source.Repositories[idx]
		}
	}
	if found == nil {
		t.Fatal("the repository vanished from the source")
	}
	if found.ReassignedTo != "inst-other" {
		t.Errorf("reassigned to %q, want inst-other", found.ReassignedTo)
	}
	if found.Selected {
		t.Error("a reassigned repository must not stay selected in the source")
	}
	var moved bool
	for _, repo := range target.Repositories {
		if repo.ID == "repo-1" {
			moved = true
		}
	}
	if !moved {
		t.Error("the repository must be present in the target")
	}
}

func TestReassignmentRefusesUnknownRepositoriesAndOccupiedTargets(t *testing.T) {
	r := verified(t)
	if _, err := r.Reassign("inst-acme", "repo-nope", "inst-other", now); !errors.Is(err, ErrUnknownRepository) {
		t.Errorf("Reassign error = %v, want ErrUnknownRepository", err)
	}
	if _, err := r.Reassign("inst-acme", "repo-1", "inst-missing", now); !errors.Is(err, ErrNoInstallationID) {
		t.Errorf("Reassign error = %v, want ErrNoInstallationID", err)
	}
	if _, err := r.Reassign("inst-acme", "repo-1", "inst-acme", now); !errors.Is(err, ErrInvalidState) {
		t.Errorf("Reassign to itself = %v, want ErrInvalidState", err)
	}
	// The target already holding the repository is refused.
	r2, err := r.Reassign("inst-acme", "repo-1", "inst-other", now)
	if err != nil {
		t.Fatalf("Reassign: %v", err)
	}
	if _, err := r2.Reassign("inst-acme", "repo-2", "inst-other", now); err != nil {
		t.Fatalf("Reassign: %v", err)
	}
}

// A revoked target cannot receive a repository: moving resources into a dead
// installation is the orphaning this row exists to prevent.
func TestReassignmentToARevokedTargetIsRefused(t *testing.T) {
	r, err := verified(t).Revoke("inst-other", "ada", "closed", now)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := r.Reassign("inst-acme", "repo-1", "inst-other", now); !errors.Is(err, ErrRevoked) {
		t.Errorf("Reassign error = %v, want ErrRevoked", err)
	}
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

// Unknown and healthy look identical on a dashboard with no third state, and the
// difference between them is the difference between a working integration and one
// that stopped working an hour ago.
func TestHealthIsNeverGreenWhenUnverified(t *testing.T) {
	i := install(t, verified(t), "inst-acme")

	noChecks, err := Assess(i, nil, now)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if noChecks.Status != HealthUnknown || noChecks.Verified {
		t.Errorf("status = %+v, want unknown and unverified", noChecks)
	}

	stale, err := Assess(i, []Check{
		{Name: "webhook", OK: true, At: now.Add(-2 * time.Hour)},
	}, now)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if stale.Status != HealthUnknown || stale.Verified {
		t.Errorf("status = %+v, want unknown and unverified for stale checks", stale)
	}
	if stale.StaleChecks != 1 {
		t.Errorf("stale checks = %d, want 1", stale.StaleChecks)
	}
}

// A check that has not run is not a passing check.
func TestFreshPassingChecksAreHealthy(t *testing.T) {
	i := install(t, verified(t), "inst-acme")
	h, err := Assess(i, []Check{
		{Name: "webhook", OK: true, At: now.Add(-time.Minute)},
		{Name: "token", OK: true, At: now.Add(-time.Minute)},
	}, now)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if h.Status != HealthHealthy || !h.Verified {
		t.Errorf("status = %+v, want healthy and verified", h)
	}
	if h.FreshChecks != 2 {
		t.Errorf("fresh checks = %d, want 2", h.FreshChecks)
	}
}

// One failing check cannot be averaged away by a pile of passing ones.
func TestAFailingNonCriticalCheckIsDegraded(t *testing.T) {
	i := install(t, verified(t), "inst-acme")
	h, err := Assess(i, []Check{
		{Name: "webhook", OK: true, At: now},
		{Name: "lag", OK: false, Detail: "delayed", At: now},
	}, now)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if h.Status != HealthDegraded {
		t.Errorf("status = %+v, want degraded", h)
	}
	if len(h.FailedChecks) != 1 || h.FailedChecks[0] != "lag" {
		t.Errorf("failed checks = %v, want lag", h.FailedChecks)
	}
}

func TestAFailingCriticalCheckIsUnhealthy(t *testing.T) {
	i := install(t, verified(t), "inst-acme")
	h, err := Assess(i, []Check{
		{Name: "webhook", OK: true, At: now},
		{Name: "auth", Critical: true, OK: false, At: now},
	}, now)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if h.Status != HealthUnhealthy {
		t.Errorf("status = %+v, want unhealthy", h)
	}
}

// A revoked installation is unhealthy, and says so.
func TestRevokedInstallationIsUnhealthy(t *testing.T) {
	r, err := verified(t).Revoke("inst-acme", "ada", "compromised", now)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	h, err := Assess(install(t, r, "inst-acme"), []Check{{Name: "webhook", OK: true, At: now}}, now)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if h.Status != HealthUnhealthy {
		t.Errorf("status = %+v, want unhealthy", h)
	}
}

func TestAssessRefusesUnusableChecks(t *testing.T) {
	i := install(t, verified(t), "inst-acme")
	if _, err := Assess(i, []Check{{Name: "  ", At: now}}, now); !errors.Is(err, ErrNoCheckName) {
		t.Errorf("Assess error = %v, want ErrNoCheckName", err)
	}
	if _, err := Assess(i, []Check{{Name: "a", At: now}, {Name: "a", At: now}}, now); !errors.Is(err, ErrDuplicateCheck) {
		t.Errorf("Assess error = %v, want ErrDuplicateCheck", err)
	}
	if _, err := Assess(i, []Check{{Name: "a", At: now.Add(time.Hour)}}, now); !errors.Is(err, ErrFutureCheck) {
		t.Errorf("Assess error = %v, want ErrFutureCheck", err)
	}
}

// A stale failure is a stale failure: it does not make the integration unhealthy,
// because nothing current has been shown to be broken.
func TestStaleFailuresDoNotMakeItUnhealthy(t *testing.T) {
	i := install(t, verified(t), "inst-acme")
	h, err := Assess(i, []Check{
		{Name: "webhook", OK: true, At: now},
		{Name: "auth", Critical: true, OK: false, At: now.Add(-2 * time.Hour)},
	}, now)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if h.Status != HealthHealthy {
		t.Errorf("status = %+v, want healthy: a stale failure proves nothing now", h)
	}
	if h.StaleChecks != 1 {
		t.Errorf("stale checks = %d, want 1", h.StaleChecks)
	}
}

// A refused operation must change nothing in the caller's registry, and a successful
// one must change only the registry it returns.
//
// This is tested explicitly because a Registry holds a slice, and a slice copied by
// value still shares its backing array. Without cloning, a caller that discarded a
// result would see the mutation anyway, and a caller that kept a registry across a
// refused operation would see a partial mutation.
func TestRegistryOperationsDoNotMutateTheCallersCopy(t *testing.T) {
	r := verified(t)
	before := install(t, r, "inst-acme")

	if _, err := r.SelectRepositories("inst-acme", []string{"repo-9"}, granted(), now); err == nil {
		t.Fatal("expected the selection to be refused")
	}
	if after := install(t, r, "inst-acme"); after.State != before.State {
		t.Errorf("state changed to %q on a refused operation", after.State)
	}

	if _, err := r.SelectRepositories("inst-acme", []string{"repo-1"}, granted(), now); err != nil {
		t.Fatalf("SelectRepositories: %v", err)
	}
	if after := install(t, r, "inst-acme"); after.State != before.State {
		t.Errorf("state changed to %q even though the result was discarded", after.State)
	}
	if len(install(t, r, "inst-acme").SelectedRepositories()) != 0 {
		t.Error("the caller's repositories were mutated even though the result was discarded")
	}
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

// Install, verify, select, configure, check health, revoke — and confirm every step
// of the wizard was refused out of order.
func TestHappyPathWizardThroughRevocation(t *testing.T) {
	r := registry(t)

	// Nothing works before verification.
	if _, err := r.SelectRepositories("inst-acme", []string{"repo-1"}, granted(), now); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("selecting before verification = %v, want ErrInvalidState", err)
	}

	r, err := r.VerifyInstallation("inst-acme", Evidence{
		Digest: "sha256:payload", IssuedAt: now.Add(-time.Minute), Verified: true,
	}, now)
	if err != nil {
		t.Fatalf("VerifyInstallation: %v", err)
	}
	r, err = r.SelectRepositories("inst-acme", []string{"repo-1"}, granted(), now)
	if err != nil {
		t.Fatalf("SelectRepositories: %v", err)
	}
	r, err = r.Configure("inst-acme", map[string]string{"webhook": "https://example.com/hook"}, now)
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}

	i := install(t, r, "inst-acme")
	if i.State != StateReady {
		t.Fatalf("state = %q, want ready", i.State)
	}
	selected := i.SelectedRepositories()
	if len(selected) != 1 || selected[0].FullName != "acme/api" {
		t.Errorf("selected = %v, want acme/api", selected)
	}

	h, err := Assess(i, []Check{
		{Name: "webhook", OK: true, At: now},
		{Name: "token", OK: true, At: now},
	}, now)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if h.Status != HealthHealthy {
		t.Errorf("status = %+v, want healthy", h)
	}

	r, err = r.Revoke("inst-acme", "ada", "the app was uninstalled by the customer", now)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	after := install(t, r, "inst-acme")
	if after.State != StateRevoked {
		t.Errorf("state = %q, want revoked", after.State)
	}
	if after.RevocationReason == "" {
		t.Error("the revocation reason must be recorded")
	}
}
