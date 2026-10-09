package roles_test

import (
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/internal/roles"
)

// TestEveryRoleIsDefined: eight roles, no more, no fewer. A ninth role appearing
// without a checklist entry would be privilege granted without review.
func TestEveryRoleIsDefined(t *testing.T) {
	all := roles.All()
	if len(all) != 8 {
		t.Fatalf("expected 8 roles, got %d: %v", len(all), all)
	}
	seen := map[roles.Role]bool{}
	for _, r := range all {
		if r == "" {
			t.Fatal("a role must be named")
		}
		if seen[r] {
			t.Fatalf("role %s is duplicated", r)
		}
		seen[r] = true
	}
	for _, want := range []roles.Role{
		roles.RoleController, roles.RoleBuild, roles.RoleAllocator, roles.RoleRunner,
		roles.RoleRuntime, roles.RoleExperiment, roles.RoleJanitor, roles.RoleSigner,
	} {
		if !seen[want] {
			t.Fatalf("role %s is missing", want)
		}
	}
}

// TestG0GateRow pins the G0 gate as data: the untrusted build cannot provision, sign,
// or touch credentials.
func TestG0GateRow(t *testing.T) {
	for _, action := range []roles.Action{
		roles.ActionProvision, roles.ActionMutate, roles.ActionDestroy,
		roles.ActionSign, roles.ActionReadSecret, roles.ActionWriteSecret,
		roles.ActionWriteLedger, roles.ActionWriteEvidence,
		roles.ActionRevoke, roles.ActionQuarantine, roles.ActionInjectFault,
		roles.ActionServeTraffic,
	} {
		if roles.Allowed(roles.RoleBuild, action) {
			t.Fatalf("build must not be allowed %s (G0 gate)", action)
		}
	}
	// And what it can do is exactly read-only observation plus reading the ledger.
	for _, action := range []roles.Action{roles.ActionReadLedger, roles.ActionObserve} {
		if !roles.Allowed(roles.RoleBuild, action) {
			t.Fatalf("build requires %s to do its job", action)
		}
	}
}

// TestRunnerCannotSign: a runner that could sign its own evidence could fake a pass.
func TestRunnerCannotSign(t *testing.T) {
	if roles.Allowed(roles.RoleRunner, roles.ActionSign) {
		t.Fatal("a runner must not sign")
	}
	for _, action := range []roles.Action{
		roles.ActionMutate, roles.ActionDestroy, roles.ActionRevoke, roles.ActionReadSecret,
	} {
		if !roles.Allowed(roles.RoleRunner, action) {
			t.Fatalf("a runner requires %s", action)
		}
	}
}

// TestRuntimeWritesNothing: a workload that could write evidence could qualify itself.
func TestRuntimeWritesNothing(t *testing.T) {
	for _, action := range []roles.Action{
		roles.ActionWriteLedger, roles.ActionWriteEvidence, roles.ActionProvision,
		roles.ActionMutate, roles.ActionDestroy, roles.ActionSign,
		roles.ActionWriteSecret, roles.ActionInjectFault,
	} {
		if roles.Allowed(roles.RoleRuntime, action) {
			t.Fatalf("runtime must not be allowed %s", action)
		}
	}
	if !roles.Allowed(roles.RoleRuntime, roles.ActionServeTraffic) {
		t.Fatal("a runtime must serve traffic")
	}
}

// TestJanitorCannotCreate: a janitor that could create could manufacture discoveries.
func TestJanitorCannotCreate(t *testing.T) {
	if roles.Allowed(roles.RoleJanitor, roles.ActionProvision) {
		t.Fatal("a janitor must not provision")
	}
	for _, action := range []roles.Action{
		roles.ActionQuarantine, roles.ActionDestroy, roles.ActionRevoke, roles.ActionObserve,
	} {
		if !roles.Allowed(roles.RoleJanitor, action) {
			t.Fatalf("a janitor requires %s", action)
		}
	}
}

// TestSignerDoesNothingElse: a signer with broader rights is a confused deputy.
func TestSignerDoesNothingElse(t *testing.T) {
	if !roles.Allowed(roles.RoleSigner, roles.ActionSign) {
		t.Fatal("a signer must sign")
	}
	for _, action := range roles.AllActions() {
		if action == roles.ActionSign || action == roles.ActionReadLedger {
			continue
		}
		if roles.Allowed(roles.RoleSigner, action) {
			t.Fatalf("a signer must not be allowed %s", action)
		}
	}
}

// TestControllerDecidesButDoesNotDo: provisioning and mutation bypass the fence.
func TestControllerDecidesButDoesNotDo(t *testing.T) {
	for _, action := range []roles.Action{roles.ActionProvision, roles.ActionMutate, roles.ActionDestroy} {
		if roles.Allowed(roles.RoleController, action) {
			t.Fatalf("a controller must not be allowed %s", action)
		}
	}
	if !roles.Allowed(roles.RoleController, roles.ActionWriteLedger) {
		t.Fatal("a controller must write the ledger")
	}
}

// TestExperimentCannotRebuild: a fault that rebuilds infrastructure is an outage.
func TestExperimentCannotRebuild(t *testing.T) {
	for _, action := range []roles.Action{roles.ActionProvision, roles.ActionMutate, roles.ActionDestroy} {
		if roles.Allowed(roles.RoleExperiment, action) {
			t.Fatalf("an experiment must not be allowed %s", action)
		}
	}
	if !roles.Allowed(roles.RoleExperiment, roles.ActionInjectFault) {
		t.Fatal("an experiment must inject faults")
	}
}

// TestAllocatorDoesNotDestroy: destruction goes through verified cleanup.
func TestAllocatorDoesNotDestroy(t *testing.T) {
	if roles.Allowed(roles.RoleAllocator, roles.ActionDestroy) {
		t.Fatal("an allocator must not destroy")
	}
	if !roles.Allowed(roles.RoleAllocator, roles.ActionProvision) {
		t.Fatal("an allocator must provision")
	}
}

// TestUnknownRolesAndActionsDeny: a typo must fail closed.
func TestUnknownRolesAndActionsDeny(t *testing.T) {
	if roles.Allowed("root", roles.ActionSign) {
		t.Fatal("an unknown role must deny everything")
	}
	if roles.Allowed(roles.RoleSigner, "do_anything") {
		t.Fatal("an unknown action must be denied")
	}
	if roles.Allowed("", "") {
		t.Fatal("empty role and action must deny")
	}
}

// TestDenialsAreTheComplementOfGrants: every cell decided, no implicit defaults.
func TestDenialsAreTheComplementOfGrants(t *testing.T) {
	for _, r := range roles.All() {
		grants := map[roles.Action]bool{}
		for _, a := range roles.Grants(r) {
			grants[a] = true
		}
		for _, a := range roles.Denials(r) {
			if grants[a] {
				t.Fatalf("%s/%s is both granted and denied", r, a)
			}
		}
		if len(roles.Grants(r))+len(roles.Denials(r)) != len(roles.AllActions()) {
			t.Fatalf("role %s leaves cells undecided", r)
		}
	}
}

// TestAuthorizeExplainsItself: a denial nobody understands becomes a ticket for broader
// rights, and broader rights to stop the tickets is how least privilege dies.
func TestAuthorizeExplainsItself(t *testing.T) {
	c := roles.Authorize(roles.RoleBuild, roles.ActionProvision)
	if c.Allowed || c.Reason == "" {
		t.Fatalf("a denial must carry a reason, got %+v", c)
	}
	if !strings.Contains(c.Reason, "G0 gate") {
		t.Fatalf("the build denial must cite the gate, got %q", c.Reason)
	}

	c = roles.Authorize(roles.RoleRunner, roles.ActionMutate)
	if !c.Allowed || c.Reason == "" {
		t.Fatalf("a grant must carry a reason, got %+v", c)
	}

	c = roles.Authorize("root", roles.ActionSign)
	if c.Allowed {
		t.Fatal("unknown roles deny")
	}
	if !strings.Contains(c.Reason, "unknown role") {
		t.Fatalf("the reason must say what is unknown, got %q", c.Reason)
	}
}

// TestMatrixIsReviewable: every cell explicit, stable across runs.
func TestMatrixIsReviewable(t *testing.T) {
	first := roles.Matrix()
	if !strings.Contains(first, "controller") || !strings.Contains(first, "signer") {
		t.Fatalf("the matrix must name its roles:\n%s", first)
	}
	for i := 0; i < 3; i++ {
		if roles.Matrix() != first {
			t.Fatal("the matrix must be stable")
		}
	}
	// Spot-check the load-bearing cells in the rendered output.
	lines := strings.Split(first, "\n")
	var buildLine string
	for _, l := range lines {
		if strings.HasPrefix(l, "build ") || l == "build" || strings.HasPrefix(l, "build |") {
			buildLine = l
		}
	}
	if buildLine == "" {
		t.Fatalf("the matrix must have a build row:\n%s", first)
	}
}

// TestNoRoleCanDoEverything: the matrix has no superuser. A superuser row would make
// every other row decorative.
func TestNoRoleCanDoEverything(t *testing.T) {
	for _, r := range roles.All() {
		if len(roles.Denials(r)) == 0 {
			t.Fatalf("role %s can do everything; there must be no superuser", r)
		}
	}
}

// TestEveryActionIsDeniedToSomeone: an action nobody is denied is an action with no
// boundary.
func TestEveryActionIsDeniedToSomeone(t *testing.T) {
	for _, a := range roles.AllActions() {
		denied := false
		for _, r := range roles.All() {
			if roles.Denied(r, a) {
				denied = true
			}
		}
		if !denied {
			t.Fatalf("action %s is allowed to every role; it has no boundary", a)
		}
	}
}

// TestEveryActionIsAllowedToSomeone: an action nobody holds is dead policy.
func TestEveryActionIsAllowedToSomeone(t *testing.T) {
	for _, a := range roles.AllActions() {
		held := false
		for _, r := range roles.All() {
			if roles.Allowed(r, a) {
				held = true
			}
		}
		if !held {
			t.Fatalf("action %s is held by no role; it is dead policy", a)
		}
	}
}
