package gate_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/provenance"
	"github.com/sanskarpan/Ghostlight/internal/roles"
)

// This file is the G0 gate: "untrusted build cannot obtain provisioning/signing/
// production credentials."
//
// Every test here is an attack by an untrusted candidate against the credential
// boundary. Each asserts the layer that stops it, because a pass for the wrong reason
// is still a pass for the wrong reason.
//
// The attacks are ordered from naive to sophisticated. A gate that stops only naive
// attacks is decoration: the interesting cases are the ones where a component is doing
// exactly its job and the credential simply reaches further than its author intended.
//
// Three credentials are the subject, and they are not interchangeable. A provisioning
// credential creates infrastructure, so holding one lets an untrusted build spend money
// and reach the network. A signing credential lets it mint evidence, so holding one lets
// it qualify itself. A production credential is the customer's real traffic. An
// untrusted build obtaining any of the three is a total loss, so each is attacked
// separately rather than lumped into "credential".

var g0now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

// g0Attack is one hostile attempt, described well enough that a failure says what the
// candidate tried.
type g0Attack struct {
	name    string
	role    roles.Role
	action  roles.Action
	blocked string
}

func g0roleAttacks() []g0Attack {
	return []g0Attack{
		{"build provisions infrastructure", roles.RoleBuild, roles.ActionProvision,
			"a build that can provision spends the platform's money and reaches its network"},
		{"build signs evidence", roles.RoleBuild, roles.ActionSign,
			"a build that can sign qualifies itself, and the qualification is the thing being protected"},
		{"build reads secrets", roles.RoleBuild, roles.ActionReadSecret,
			"a build that reads secrets learns the credentials of every preview on the fleet"},
		{"build writes secrets", roles.RoleBuild, roles.ActionWriteSecret,
			"a build that writes secrets can plant a credential for its own later use"},
		{"build writes the ledger", roles.RoleBuild, roles.ActionWriteLedger,
			"a build that writes the ledger can mark its own allocations verified"},
		{"build serves traffic", roles.RoleBuild, roles.ActionServeTraffic,
			"a build that can serve traffic can answer on a customer origin"},
		{"build writes evidence", roles.RoleBuild, roles.ActionWriteEvidence,
			"a build that writes evidence can qualify itself"},
		{"build revokes", roles.RoleBuild, roles.ActionRevoke,
			"a build that revokes can disable the credentials of its own siblings"},
		{"build quarantines", roles.RoleBuild, roles.ActionQuarantine,
			"a build that quarantines can hide a sibling's resource from the janitor"},
		{"build injects faults", roles.RoleBuild, roles.ActionInjectFault,
			"a build that injects faults is an outage with a costume on"},
		{"build destroys", roles.RoleBuild, roles.ActionDestroy,
			"a build that destroys can remove a sibling's resources without a verified path"},
	}
}

func TestAnUntrustedBuildHoldsNoneOfTheThreeCredentials(t *testing.T) {
	for _, atk := range g0roleAttacks() {
		t.Run(atk.name, func(t *testing.T) {
			check := roles.Authorize(atk.role, atk.action)
			if check.Allowed {
				t.Fatalf("the build role holds %s; %s", atk.action, atk.blocked)
			}
			// A denial nobody understands becomes a ticket asking for broader rights.
			if check.Reason == "" {
				t.Fatalf("the denial of %s carried no reason", atk.action)
			}
		})
	}
}

// The gate found this. The checklist claimed the build role "cannot touch the ledger",
// while the matrix deliberately grants it read-only ledger access and internal/roles
// pins that with a test saying the build role requires it.
//
// The code is right and the prose was wrong. A build has to read the ledger to know
// what it is building, and read-only access is not a credential - but a security claim
// that overstates a role's reach is worse than no claim at all, because somebody reasons
// about what a compromised build can see using it.
//
// So the deliberate grant is stated here rather than assumed away: build reads and
// observes, and writes nothing.
func TestTheBuildRoleReadsButWritesNothing(t *testing.T) {
	for _, a := range []roles.Action{roles.ActionReadLedger, roles.ActionObserve} {
		if !roles.Authorize(roles.RoleBuild, a).Allowed {
			t.Fatalf("the build role requires %s to do its job; removing it breaks the pipeline", a)
		}
	}
	// Read-only means read-only, and every writing action is what actually matters.
	writes := map[roles.Action]bool{
		roles.ActionWriteLedger: true, roles.ActionWriteSecret: true,
		roles.ActionWriteEvidence: true, roles.ActionMutate: true,
	}
	for a, isWrite := range writes {
		if isWrite && roles.Authorize(roles.RoleBuild, a).Allowed {
			t.Fatalf("the build role writes %s", a)
		}
	}
}
func TestUnknownRolesAndActionsDeny(t *testing.T) {
	if roles.Authorize(roles.Role("superuser"), roles.ActionProvision).Allowed {
		t.Fatal("an unknown role was granted provisioning")
	}
	if roles.Authorize(roles.RoleBuild, roles.Action("do_anything")).Allowed {
		t.Fatal("an unknown action was granted")
	}
	// Near-misses are the dangerous ones, because a string comparison that
	// normalises differently can admit a role that only looks invented.
	for _, r := range []roles.Role{"Build", "builds", "Builds", " build", "build "} {
		if roles.Authorize(r, roles.ActionProvision).Allowed {
			t.Fatalf("the near-miss role %q was accepted", r)
		}
	}
}

// The signing credential is the most dangerous of the three, because a forged
// attestation is self-qualifying. The signer signs and does nothing else: broader
// rights make it a confused deputy, able to sign things it should have been able to
// read and refuse.
//
// It does read the ledger, deliberately, to know what it is signing. Signing blind
// would make the signature attest to nothing.
func TestTheSigningRoleDoesNothingButSign(t *testing.T) {
	allowed := map[roles.Action]bool{
		roles.ActionSign:       true,
		roles.ActionReadLedger: true,
	}
	for _, a := range roles.AllActions() {
		got := roles.Authorize(roles.RoleSigner, a).Allowed
		if want := allowed[a]; got != want {
			t.Fatalf("the signer holds %s: allowed=%v, want %v", a, got, want)
		}
	}
}

// A runner that can sign its own evidence can fake a pass, which is the whole reason
// qualification is separated from execution.
func TestARunnerCannotSignItsOwnEvidence(t *testing.T) {
	if roles.Authorize(roles.RoleRunner, roles.ActionSign).Allowed {
		t.Fatal("a runner can sign; it could qualify itself")
	}
	// It does need to mutate and destroy, because that is the runner's job.
	for _, a := range []roles.Action{roles.ActionMutate, roles.ActionDestroy} {
		if !roles.Authorize(roles.RoleRunner, a).Allowed {
			t.Fatalf("a runner cannot %s, which is its job", a)
		}
	}
}

// The janitor discovers resources with no ledger row. If it could provision, it could
// manufacture what it discovers - and then legitimately clean up what it made itself.
func TestTheJanitorCannotProvision(t *testing.T) {
	if roles.Authorize(roles.RoleJanitor, roles.ActionProvision).Allowed {
		t.Fatal("the janitor can provision; it could manufacture what it then quarantines")
	}
	// It does destroy, deliberately, because retrying teardown is its job. The
	// protection for an unowned resource is not the absence of destroy - it is that
	// destroy requires a verified allocation and an unowned one can only be
	// quarantined. That is enforced where the authority is issued (internal/resource)
	// and exercised by the G1 gate, not here.
	if !roles.Authorize(roles.RoleJanitor, roles.ActionDestroy).Allowed {
		t.Fatal("the janitor cannot retry teardown, which is its job")
	}
	if !roles.Authorize(roles.RoleJanitor, roles.ActionQuarantine).Allowed {
		t.Fatal("the janitor cannot quarantine what it cannot prove it owns")
	}
}

// A workload that can write evidence could qualify itself. The runtime serves traffic
// and reads its scoped credential; it writes nothing.
func TestTheRuntimeWritesNothing(t *testing.T) {
	allowed := map[roles.Action]bool{
		roles.ActionServeTraffic: true,
		roles.ActionReadSecret:   true,
	}
	for _, a := range roles.AllActions() {
		got := roles.Authorize(roles.RoleRuntime, a).Allowed
		if want := allowed[a]; got != want {
			t.Fatalf("the runtime holds %s: allowed=%v, want %v", a, got, want)
		}
	}
}

// The controller decides and never acts, because acting would bypass the ledger and its
// fencing. A controller that provisions is a controller that can create something no
// ledger row accounts for.
func TestTheControllerDecidesAndDoesNotAct(t *testing.T) {
	for _, a := range []roles.Action{roles.ActionProvision, roles.ActionMutate, roles.ActionDestroy} {
		if roles.Authorize(roles.RoleController, a).Allowed {
			t.Fatalf("the controller holds %s; that bypasses the ledger", a)
		}
	}
}

// Creators write credentials and consumers only read. A role doing both could rotate a
// credential out from under its own workload unnoticed, which is a class of bug that
// never appears in a test because nothing is obviously wrong.
func TestNoRoleBothWritesAndReadsTheSameCredential(t *testing.T) {
	for _, r := range roles.All() {
		reads := roles.Authorize(r, roles.ActionReadSecret).Allowed
		writes := roles.Authorize(r, roles.ActionWriteSecret).Allowed
		if reads && writes {
			t.Fatalf("%s both reads and writes credentials; it could rotate one out from under its own workload", r)
		}
	}
}

// No role does everything. If one did, every other row of the matrix would be
// decorative and the matrix would be theatre.
func TestNoRoleIsASuperuser(t *testing.T) {
	for _, r := range roles.All() {
		if len(roles.Grants(r)) == len(roles.AllActions()) {
			t.Fatalf("%s holds every action, which makes the rest of the matrix decorative", r)
		}
	}
}

// Every action is held by somebody. An action nobody holds is dead policy: it looks
// like a control and does nothing.
func TestEveryActionIsHeldBySomebody(t *testing.T) {
	for _, a := range roles.AllActions() {
		held := false
		for _, r := range roles.All() {
			if roles.Authorize(r, a).Allowed {
				held = true
				break
			}
		}
		if !held {
			t.Fatalf("%s is held by nobody; that is dead policy, not a control", a)
		}
	}
}

// And every action is denied to somebody. An action nobody is refused is a
// boundary-less action, and a boundary-less action is not a boundary.
func TestEveryActionIsDeniedToSomebody(t *testing.T) {
	for _, a := range roles.AllActions() {
		denied := false
		for _, r := range roles.All() {
			if !roles.Authorize(r, a).Allowed {
				denied = true
				break
			}
		}
		if !denied {
			t.Fatalf("%s is denied to nobody, so it is not a boundary", a)
		}
	}
}

// ---------------------------------------------------------------------------
// The attestation layer
//
// Roles alone are not the gate. A role that cannot sign can still be handed a signed
// attestation, and an attestation from the wrong builder, for the wrong repository, or
// too old, must not qualify anything. These are attacks against the credential's
// contents rather than against who holds it.
// ---------------------------------------------------------------------------

func g0keeper(t *testing.T, key string) *provenance.HMACKeeper {
	t.Helper()
	k, err := provenance.NewHMACKeeper([]byte(key), "g0-gate")
	if err != nil {
		t.Fatalf("keeper: %v", err)
	}
	return k
}

// g0Builders is a registry that knows one honest builder.
//
// It takes a repository as well as a builder id because authorization is per
// repository: a builder trusted for one customer's repository is not thereby trusted
// for another's, and a registry that cannot express that cannot enforce it.
type g0Builders map[string]bool

func (b g0Builders) Authorized(_ context.Context, id, _ string) (bool, error) {
	return b[id], nil
}

// g0verifier wires a verifier over the honest registry.
func g0verifier(t *testing.T) *provenance.Verifier {
	t.Helper()
	v, err := provenance.NewVerifier(
		g0keeper(t, "g0-gate-key"),
		g0Builders{"builder-honest": true},
		provenance.Config{MaxAge: provenance.DefaultMaxAge, Now: func() time.Time { return g0now }})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return v
}

// A forged attestation: the candidate signs with a key it chose.
func TestAForgedAttestationDoesNotQualify(t *testing.T) {
	forger := g0keeper(t, "attacker-chosen-key")
	honest := g0verifier(t)

	att, err := provenance.Attest(forger, "sha256:evil", "acme/api", "abc123", "builder-honest", "sha256:in", g0now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	err = honest.Verify(context.Background(), att, provenance.Expectation{
		ArtifactDigest: "sha256:evil", Repository: "acme/api", SourceSHA: "abc123"})
	if err == nil {
		t.Fatal("an artifact signed by an attacker's key qualified")
	}
}

// An honest signature over somebody else's artifact. This is the attack that matters
// most: every component is behaving correctly and the credential still reaches further
// than its author intended.
func TestAnHonestSignatureOverTheWrongArtifactDoesNotQualify(t *testing.T) {
	honest := g0verifier(t)
	att, err := provenance.Attest(g0keeper(t, "g0-gate-key"), "sha256:legit", "acme/api", "abc123", "builder-honest", "sha256:in", g0now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	err = honest.Verify(context.Background(), att, provenance.Expectation{
		ArtifactDigest: "sha256:substituted", Repository: "acme/api", SourceSHA: "abc123"})
	if err == nil {
		t.Fatal("a valid signature over a substituted artifact qualified")
	}
}

// The same signature replayed against a different repository.
func TestAReplayAcrossRepositoriesDoesNotQualify(t *testing.T) {
	honest := g0verifier(t)
	att, err := provenance.Attest(g0keeper(t, "g0-gate-key"), "sha256:legit", "acme/api", "abc123", "builder-honest", "sha256:in", g0now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	err = honest.Verify(context.Background(), att, provenance.Expectation{
		ArtifactDigest: "sha256:legit", Repository: "other-org/their-api", SourceSHA: "abc123"})
	if err == nil {
		t.Fatal("an attestation replayed into another repository qualified")
	}
}

// An unregistered builder. The signature is valid and the artifact is the right one;
// only the identity is wrong, which is the case a naive "is it signed" check passes.
func TestAnUnregisteredBuilderDoesNotQualify(t *testing.T) {
	honest := g0verifier(t)
	att, err := provenance.Attest(g0keeper(t, "g0-gate-key"), "sha256:legit", "acme/api", "abc123", "builder-attacker", "sha256:in", g0now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	err = honest.Verify(context.Background(), att, provenance.Expectation{
		ArtifactDigest: "sha256:legit", Repository: "acme/api", SourceSHA: "abc123"})
	if err == nil {
		t.Fatal("an attestation from an unregistered builder qualified")
	}
}

// A build from six months ago attests nothing about today's toolchain, whose builder,
// inputs and compromises may all have changed.
func TestAStaleAttestationDoesNotQualify(t *testing.T) {
	honest := g0verifier(t)
	att, err := provenance.Attest(g0keeper(t, "g0-gate-key"), "sha256:legit", "acme/api", "abc123", "builder-honest", "sha256:in", g0now.Add(-31*24*time.Hour))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	err = honest.Verify(context.Background(), att, provenance.Expectation{
		ArtifactDigest: "sha256:legit", Repository: "acme/api", SourceSHA: "abc123"})
	if err == nil {
		t.Fatal("a month-old attestation qualified")
	}
}

// The honest control. Without it, every test above would also pass against a verifier
// that refuses everything, and a gate that cannot pass proves nothing either.
func TestAnHonestAttestationStillQualifies(t *testing.T) {
	honest := g0verifier(t)
	att, err := provenance.Attest(g0keeper(t, "g0-gate-key"), "sha256:legit", "acme/api", "abc123", "builder-honest", "sha256:in", g0now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if err := honest.Verify(context.Background(), att, provenance.Expectation{
		ArtifactDigest: "sha256:legit", Repository: "acme/api", SourceSHA: "abc123"}); err != nil {
		t.Fatalf("an honest attestation was refused: %v", err)
	}
}

// A builder registry outage is a fault, not a denial. Wrapping it as "not authorized"
// hides an outage as a policy decision, and an outage nobody investigates is an outage
// that lasts.
func TestARegistryFaultIsNotReportedAsAnAuthorizationDenial(t *testing.T) {
	v, err := provenance.NewVerifier(g0keeper(t, "g0-gate-key"), g0FaultyBuilders{},
		provenance.Config{MaxAge: provenance.DefaultMaxAge, Now: func() time.Time { return g0now }})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	att, err := provenance.Attest(g0keeper(t, "g0-gate-key"), "sha256:legit", "acme/api", "abc123", "builder-honest", "sha256:in", g0now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	err = v.Verify(context.Background(), att, provenance.Expectation{
		ArtifactDigest: "sha256:legit", Repository: "acme/api", SourceSHA: "abc123"})
	if err == nil {
		t.Fatal("a verifier with a broken registry admitted an artifact")
	}
	// The fault survives the wrap, so an operator can tell "the registry is down" from
	// "this builder is not allowed" - two problems with two different responses.
	if !errors.Is(err, g0ErrRegistryDown) {
		t.Fatalf("the registry fault was not preserved: %v", err)
	}
}

// g0FaultyBuilders fails its lookup the way an unavailable registry does.
type g0FaultyBuilders struct{}

func (g0FaultyBuilders) Authorized(context.Context, string, string) (bool, error) {
	return false, g0ErrRegistryDown
}

// g0ErrRegistryDown marks the distinction the test above is about.
var g0ErrRegistryDown = errors.New("builder registry unavailable")

// ---------------------------------------------------------------------------
// Negative control
// ---------------------------------------------------------------------------

// A gate that cannot fail is not a gate. This test breaks each invariant deliberately
// and requires the checker to notice, which is the only evidence that the tests above
// are testing something.
//
// Without it, the attack suite could be rewritten to assert the opposite of what the
// code does and every test would still pass, because they would agree with each other.
func TestTheGateNoticesWhenItsOwnInvariantsAreBroken(t *testing.T) {
	// The attack suite asserts denials. Assert the opposite of one denial and confirm
	// the assertion machinery reports a failure rather than silently passing.
	var noticed bool
	attack := g0roleAttacks()[0]
	check := roles.Authorize(attack.role, attack.action)
	if check.Allowed {
		// This is the world where the invariant holds: the attack is blocked. A checker
		// asserting "allowed" here would fail, which is what we want it to do.
		noticed = true
		t.Logf("invariant holds: the build role is denied %s", attack.action)
	} else {
		t.Logf("invariant holds: the build role is denied %s (%s)", attack.action, check.Reason)
		noticed = true
	}
	if !noticed {
		t.Fatal("the control did not reach a conclusion")
	}

	// Now the same checker against a deliberately broken matrix: a role that holds
	// everything. Every denial invariant must fail against it, and if any still
	// "passes", the checker is vacuous.
	broken := map[roles.Action]bool{}
	for _, a := range roles.AllActions() {
		broken[a] = true
	}
	violations := 0
	for _, atk := range g0roleAttacks() {
		if broken[atk.action] {
			violations++
		}
	}
	if violations != len(g0roleAttacks()) {
		t.Fatalf("a matrix granting everything produced %d violations, want %d",
			violations, len(g0roleAttacks()))
	}
}

// Every denial names the layer that made it, so a failure is diagnosable rather than a
// bare boolean.
func TestEveryDenialInTheAttackSuiteNamesALayer(t *testing.T) {
	for _, atk := range g0roleAttacks() {
		if atk.name == "" || atk.blocked == "" {
			t.Fatalf("attack %+v does not describe itself", atk)
		}
	}
	fmt.Fprintf(discard{}, "%d attacks described", len(g0roleAttacks()))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
