package access

import (
	"errors"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func mustErr(t *testing.T, err error, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

// fixture builds two organizations that know nothing about each other, which is the
// arrangement a multi-tenant system is actually defending against.
func fixture() Snapshot {
	return Snapshot{
		Orgs: []Org{
			{ID: "org_a"},
			{ID: "org_b"},
		},
		Principals: []Principal{
			{ID: "u_owner", Kind: PrincipalHuman, Email: "owner@example.com"},
			{ID: "u_admin", Kind: PrincipalHuman, Email: "admin@example.com"},
			{ID: "u_member", Kind: PrincipalHuman, Email: "member@example.com"},
			{ID: "u_other", Kind: PrincipalHuman, Email: "other@example.com"},
			{ID: "sp_ci", Kind: PrincipalService, Email: "ci@example.com"},
			{ID: "u_new", Kind: PrincipalHuman, Email: "new@example.com"},
		},
		Memberships: []Membership{
			{PrincipalID: "u_owner", OrgID: "org_a", Role: RoleOwner},
			{PrincipalID: "u_admin", OrgID: "org_a", Role: RoleAdmin},
			{PrincipalID: "u_member", OrgID: "org_a", Role: RoleMember},
			{PrincipalID: "sp_ci", OrgID: "org_a", Role: RoleMember},
			{PrincipalID: "u_other", OrgID: "org_b", Role: RoleOwner},
		},
	}
}

func TestAnOwnerMayDoEverything(t *testing.T) {
	s := fixture()
	for _, p := range AllPermissions() {
		d, err := s.Authorize("u_owner", "org_a", "repo_1", p, now)
		if err != nil || !d.Allowed {
			t.Fatalf("owner refused %s: %v", p, err)
		}
	}
}

func TestAnAdminMayNotChangeBilling(t *testing.T) {
	s := fixture()
	// Billing write is separated from membership management so an admin cannot
	// redirect the subscription they were given authority over.
	if _, err := s.Authorize("u_admin", "org_a", "", PermBillingWrite, now); err == nil {
		t.Fatal("an admin must not change billing")
	}
	if _, err := s.Authorize("u_admin", "org_a", "", PermBillingRead, now); err != nil {
		t.Fatalf("an admin should see billing: %v", err)
	}
	if _, err := s.Authorize("u_admin", "org_a", "", PermMemberInvite, now); err != nil {
		t.Fatalf("an admin should invite: %v", err)
	}
}

// Joining an organization must not silently expose every repository in it.
func TestAMemberReachesOnlyWhatIsGranted(t *testing.T) {
	s := fixture()
	s.Grants = append(s.Grants, Grant{
		OrgID: "org_a", RepoID: "repo_granted", PrincipalID: "u_member", Permission: PermRepoWrite,
	})
	if _, err := s.Authorize("u_member", "org_a", "repo_granted", PermRepoWrite, now); err != nil {
		t.Fatalf("repository grant: %v", err)
	}
	if _, err := s.Authorize("u_member", "org_a", "repo_granted", PermEnvCreate, now); err != nil {
		t.Fatalf("members may create previews: %v", err)
	}
	if _, err := s.Authorize("u_member", "org_a", "repo_granted", PermRepoAdmin, now); err == nil {
		t.Fatal("a member must not administer a repository")
	}
	if _, err := s.Authorize("u_member", "org_a", "", PermBillingRead, now); err == nil {
		t.Fatal("a member must not read billing")
	}
	if _, err := s.Authorize("u_member", "org_a", "", PermMemberInvite, now); err == nil {
		t.Fatal("a member must not invite")
	}
}

// A deny is the more specific and more deliberate statement. If the broad grant won,
// the narrow exception would be decorative.
func TestAnExplicitDenyBeatsTheRoleGrant(t *testing.T) {
	s := fixture()
	s.Grants = append(s.Grants, Grant{
		OrgID: "org_a", RepoID: "repo_locked", PrincipalID: "u_admin",
		Permission: PermRepoWrite, Deny: true,
	})
	// The admin role grants repo:write.
	if _, err := s.Authorize("u_admin", "org_a", "repo_open", PermRepoWrite, now); err != nil {
		t.Fatalf("the same admin should write to another repository: %v", err)
	}
	_, err := s.Authorize("u_admin", "org_a", "repo_locked", PermRepoWrite, now)
	mustErr(t, err, ErrDenied, "admin on a denied repository")
}

// A member granted repo:write must still be refusable by a later deny.
func TestADenyOverridesAnEarlierGrant(t *testing.T) {
	s := fixture()
	s.Grants = []Grant{
		{OrgID: "org_a", RepoID: "repo_1", PrincipalID: "u_member", Permission: PermRepoWrite},
		{OrgID: "org_a", RepoID: "repo_1", PrincipalID: "u_member", Permission: PermRepoWrite, Deny: true},
	}
	_, err := s.Authorize("u_member", "org_a", "repo_1", PermRepoWrite, now)
	mustErr(t, err, ErrDenied, "allow and deny on the same pair")
}

// The load-bearing multi-tenant property. A membership in another organization must
// never authorize anything here.
func TestAccessCannotCrossOrganizations(t *testing.T) {
	s := fixture()
	s.Grants = append(s.Grants, Grant{
		OrgID: "org_b", RepoID: "repo_a_owned", PrincipalID: "u_other", Permission: PermRepoWrite,
	})
	// u_other owns org_b. That grants nothing in org_a.
	if _, err := s.Authorize("u_other", "org_a", "repo_a_owned", PermRepoWrite, now); err == nil {
		t.Fatal("an owner of another organization reached into this one")
	} else {
		mustErr(t, err, ErrNotAMember, "cross-organization access")
	}
	// And a member of org_a cannot use org_b's repository.
	_, err := s.Authorize("u_member", "org_b", "repo_b_owned", PermRepoRead, now)
	mustErr(t, err, ErrNotAMember, "cross-organization access the other way")
}

// A check that reports absence rather than refusal still leaks existence to anyone who
// can time the difference. This one refuses.
func TestAnUnknownRepositoryOwnerIsRefusedNotSilentlyEmpty(t *testing.T) {
	s := fixture()
	_, err := s.Authorize("u_owner", "org_nonexistent", "", PermRepoRead, now)
	mustErr(t, err, ErrNotAMember, "unknown organization")
}

func TestAnUnknownPermissionIsABugNotADenial(t *testing.T) {
	s := fixture()
	// Silently denying an unimplemented permission would let a typo look like a
	// correct authorization decision.
	_, err := s.Authorize("u_owner", "org_a", "repo_1", Permission("env:nuke"), now)
	mustErr(t, err, ErrUnknownPermission, "permission nobody implemented")
}

// Revocation is immediate: there is no session cache in this package and no way to
// add one without making every check here dishonest.
func TestRevocationStopsAccessOnTheNextCheck(t *testing.T) {
	s := fixture()
	if _, err := s.Authorize("u_member", "org_a", "repo_1", PermEnvCreate, now); err != nil {
		t.Fatalf("before revocation: %v", err)
	}
	for i := range s.Memberships {
		if s.Memberships[i].PrincipalID == "u_member" {
			s.Memberships[i].RevokedAt = now
		}
	}
	_, err := s.Authorize("u_member", "org_a", "repo_1", PermEnvCreate, now)
	mustErr(t, err, ErrRevoked, "revoked member")
	// The moment before revocation it still worked; there is no grace period that
	// silently extends access.
	if _, err := s.Authorize("u_member", "org_a", "repo_1", PermEnvCreate, now.Add(-time.Second)); err != nil {
		t.Fatalf("access before revocation: %v", err)
	}
}

func TestASuspendedMemberIsRefused(t *testing.T) {
	s := fixture()
	for i := range s.Memberships {
		if s.Memberships[i].PrincipalID == "u_member" {
			s.Memberships[i].Suspended = true
		}
	}
	_, err := s.Authorize("u_member", "org_a", "repo_1", PermEnvCreate, now)
	mustErr(t, err, ErrSuspended, "suspended member")
}

// The people who most need to delete a preview are the ones who stopped paying.
func TestTeardownSurvivesRevocationSuspensionAndOrganizationSuspension(t *testing.T) {
	s := fixture()
	s.Orgs[0].Suspended = true
	for i := range s.Memberships {
		if s.Memberships[i].PrincipalID == "u_member" {
			s.Memberships[i].RevokedAt = now
			s.Memberships[i].Suspended = true
		}
	}
	for _, perm := range TeardownPermissions {
		d, err := s.Authorize("u_member", "org_a", "repo_1", perm, now)
		if err != nil || !d.Allowed {
			t.Fatalf("a revoked, suspended member in a suspended organization refused %s: %v", perm, err)
		}
	}
	// But teardown is not a back door into everything else.
	if _, err := s.Authorize("u_member", "org_a", "repo_1", PermEnvCreate, now); err == nil {
		t.Fatal("teardown availability must not leak into other permissions")
	}
}

func TestTeardownDoesNotCrossOrganizations(t *testing.T) {
	s := fixture()
	// The teardown shortcut must not become a way to touch another tenant's work.
	_, err := s.Authorize("u_other", "org_a", "repo_a", PermEnvRead, now)
	mustErr(t, err, ErrNotAMember, "cross-organization teardown")
}

func TestASuspendedOrganizationStopsWorkButNotTeardown(t *testing.T) {
	s := fixture()
	s.Orgs[0].Suspended = true
	_, err := s.Authorize("u_owner", "org_a", "repo_1", PermEnvCreate, now)
	mustErr(t, err, ErrOrgSuspended, "suspended organization creating a preview")

	if _, err := s.Authorize("u_owner", "org_a", "repo_1", PermEnvAbort, now); err != nil {
		t.Fatalf("a suspended organization must still permit abort: %v", err)
	}
}

func TestAClosedOrganizationRefusesEverything(t *testing.T) {
	s := fixture()
	s.Orgs[0].Closed = true
	if _, err := s.Authorize("u_owner", "org_a", "repo_1", PermEnvCreate, now); err == nil {
		t.Fatal("a closed organization must not create previews")
	} else {
		mustErr(t, err, ErrOrgClosed, "closed organization")
	}
}

func TestGrantValidationRefusesCrossOrganizationAndUnknownGrants(t *testing.T) {
	s := fixture()
	if err := s.ValidateGrant(Grant{OrgID: "org_a", RepoID: "r1", PrincipalID: "u_member", Permission: PermRepoWrite}); err != nil {
		t.Fatalf("a legitimate grant was refused: %v", err)
	}
	// u_other is not a member of org_a.
	err := s.ValidateGrant(Grant{OrgID: "org_a", RepoID: "r1", PrincipalID: "u_other", Permission: PermRepoWrite})
	mustErr(t, err, ErrNotAMember, "grant to a non-member")
	err = s.ValidateGrant(Grant{OrgID: "org_a", RepoID: "r1", PrincipalID: "u_member", Permission: Permission("nope")})
	mustErr(t, err, ErrUnknownPermission, "grant of an unknown permission")
	// The schema enforces this with composite foreign keys; the code refuses it too.
	s.Orgs[0].Closed = true
	err = s.ValidateGrant(Grant{OrgID: "org_a", RepoID: "r1", PrincipalID: "u_member", Permission: PermRepoWrite})
	mustErr(t, err, ErrOrgClosed, "grant in a closed organization")
}

// An invitation that grants ownership would hand the holder untouchable power before
// anyone has decided they should have it.
func TestAnInvitationCannotGrantOwnership(t *testing.T) {
	_, err := CreateInvitation("org_a", "new@example.com", RoleOwner, "u_owner", "tok", now, 0)
	mustErr(t, err, ErrInvalidInvitation, "invitation granting ownership")
}

func TestAnInvitationStoresOnlyTheTokenHash(t *testing.T) {
	inv, err := CreateInvitation("org_a", "new@example.com", RoleMember, "u_owner", "secret-token", now, 0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if inv.TokenHash == "secret-token" {
		t.Fatal("the raw token was stored")
	}
	if inv.TokenHash != HashToken("secret-token") {
		t.Fatalf("token hash is not deterministic: %s", inv.TokenHash)
	}
	if inv.ExpiresAt != now.Add(14*24*time.Hour) {
		t.Fatalf("invitation expires %s, want 14 days", inv.ExpiresAt)
	}
}

func TestAnInvitationIsSingleUse(t *testing.T) {
	s := fixture()
	inv, err := CreateInvitation("org_a", "member@example.com", RoleMember, "u_owner", "tok", now, 0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	s.Invitations = append(s.Invitations, inv)

	if _, _, err := s.Accept("tok", now); err == nil {
		t.Fatal("an existing member must not be re-invited into the same organization")
	}

	// A fresh invite for somebody who is not yet a member.
	s.Principals = append(s.Principals, Principal{ID: "u_new", Kind: PrincipalHuman, Email: "new@example.com"})
	inv2, err := CreateInvitation("org_a", "new@example.com", RoleMember, "u_owner", "tok2", now, 0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	inv2.AcceptedAt = now
	s.Invitations = append(s.Invitations, inv2)
	_, _, err = s.Accept("tok2", now)
	mustErr(t, err, ErrInvitationUsed, "second acceptance")
}

func TestAnInvitationExpires(t *testing.T) {
	s := fixture()
	s.Principals = append(s.Principals, Principal{ID: "u_new", Kind: PrincipalHuman, Email: "new@example.com"})
	inv, err := CreateInvitation("org_a", "new@example.com", RoleMember, "u_owner", "tok", now, time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	s.Invitations = append(s.Invitations, inv)

	if _, _, err := s.Accept("tok", now.Add(30*time.Minute)); err != nil {
		t.Fatalf("within the window: %v", err)
	}
	_, _, err = s.Accept("tok", now.Add(2*time.Hour))
	mustErr(t, err, ErrInvitationExpired, "expired token")
}

// An invitation to an address nobody has proven is an open door with a delay on it.
func TestAnInvitationRequiresAVerifiedAccount(t *testing.T) {
	s := fixture()
	inv, err := CreateInvitation("org_a", "stranger@example.com", RoleMember, "u_owner", "tok", now, 0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	s.Invitations = append(s.Invitations, inv)
	_, _, err = s.Accept("tok", now)
	mustErr(t, err, ErrInvalidInvitation, "invitation to an unverified address")
}

// A token forwarded to a colleague must not create an account for the person who
// forwards it.
func TestAnInvitationIsBoundToTheInvitedEmail(t *testing.T) {
	s := fixture()
	inv, err := CreateInvitation("org_a", "new@example.com", RoleMember, "u_owner", "tok", now, 0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	s.Invitations = append(s.Invitations, inv)
	m, _, err := s.Accept("tok", now)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if m.PrincipalID != "u_new" || m.OrgID != "org_a" || m.Role != RoleMember {
		t.Fatalf("accepted as %+v", m)
	}
}

func TestAnUnknownTokenIsRefused(t *testing.T) {
	s := fixture()
	_, _, err := s.Accept("never-issued", now)
	mustErr(t, err, ErrInvalidInvitation, "unknown token")
}

// A credential that owns an organization can grant itself anything, and there is no
// human left to answer for it.
func TestAServicePrincipalCannotOwn(t *testing.T) {
	s := fixture()
	err := s.GrantOwnership("org_a", "sp_ci", "u_owner", now)
	mustErr(t, err, ErrServicePrincipalCannotOwn, "service principal ownership")

	if err := s.GrantOwnership("org_a", "u_member", "u_owner", now); err != nil {
		t.Fatalf("a human may be promoted: %v", err)
	}
}

func TestOnlyAnOwnerMayGrantOwnership(t *testing.T) {
	s := fixture()
	err := s.GrantOwnership("org_a", "u_member", "u_admin", now)
	mustErr(t, err, ErrNotAnOwner, "an admin granting ownership")
}

// Removing the last owner locks everybody out of billing and membership with no way
// back in but support.
func TestTheLastOwnerCannotBeRemoved(t *testing.T) {
	s := fixture()
	err := s.RemoveMember("org_a", "u_owner", "u_owner", now)
	mustErr(t, err, ErrLastOwner, "removing the last owner")
}

// An admin demoting an owner is a takeover.
func TestAnOwnerIsProtectedFromAdmins(t *testing.T) {
	s := fixture()
	err := s.RemoveMember("org_a", "u_owner", "u_admin", now)
	mustErr(t, err, ErrOwnerIsProtected, "admin removing an owner")

	// Two owners: one owner may remove the other.
	s.Memberships = append(s.Memberships, Membership{PrincipalID: "u_admin", OrgID: "org_a", Role: RoleOwner})
	if err := s.RemoveMember("org_a", "u_admin", "u_owner", now); err != nil {
		t.Fatalf("an owner removing another owner: %v", err)
	}
}

func TestAMemberCannotRemoveAnyone(t *testing.T) {
	s := fixture()
	err := s.RemoveMember("org_a", "u_member", "u_member", now)
	mustErr(t, err, ErrNotAnAdmin, "member removing another member")
}

func TestOwnersAreCountedConsistently(t *testing.T) {
	s := fixture()
	if got := s.Owners("org_a", now); got != 1 {
		t.Fatalf("org_a has %d owners, want 1", got)
	}
	for i := range s.Memberships {
		if s.Memberships[i].PrincipalID == "u_owner" {
			s.Memberships[i].RevokedAt = now
		}
	}
	if got := s.Owners("org_a", now); got != 0 {
		t.Fatalf("a revoked owner still counts: %d", got)
	}
}

func TestMemberListingIsStable(t *testing.T) {
	s := fixture()
	first := s.Members("org_a")
	for i := 0; i < 5; i++ {
		again := s.Members("org_a")
		for j := range first {
			if first[j].PrincipalID != again[j].PrincipalID {
				t.Fatalf("member order is not stable at %d", j)
			}
		}
	}
	if len(first) != 4 {
		t.Fatalf("org_a lists %d members, want 4", len(first))
	}
}

func TestMembershipActivityIsReportedCorrectly(t *testing.T) {
	m := Membership{PrincipalID: "u", OrgID: "o", Role: RoleMember}
	if !m.Active(now) {
		t.Fatal("a membership with no revocation is active")
	}
	m.RevokedAt = now
	if m.Active(now) {
		t.Fatal("a membership revoked now is active now")
	}
	if !m.Active(now.Add(-time.Hour)) {
		t.Fatal("a membership was active before it was revoked")
	}
}

// The always-available list is the one place in this package where widening it
// silently grants privilege. A destroy does push a teardown commit, so repo:write is
// the change most likely to be made by someone in a hurry — and it would hand push
// access to every repository the organization can see.
func TestTeardownCannotBeWidenedToAWritePermission(t *testing.T) {
	for _, p := range TeardownPermissions {
		if p == PermRepoWrite || p == PermRepoAdmin || p == PermMemberRevoke || p == PermBillingWrite {
			t.Fatalf("%s is in the always-available teardown list", p)
		}
	}
	if !isTeardown(PermEnvAbort) || !isTeardown(PermEnvRead) {
		t.Fatal("abort and evidence reading must remain always available")
	}
}
