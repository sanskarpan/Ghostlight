package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/access"
	"github.com/sanskarpan/Ghostlight/internal/postgres"
)

// accessOrg creates an organization and returns its id.
func accessOrg(t *testing.T, slug string) string {
	t.Helper()
	var id string
	if err := pgDB.QueryRow(
		`INSERT INTO organizations (slug, name, policy_version) VALUES ($1,$2,'v1') RETURNING id`,
		slug, slug).Scan(&id); err != nil {
		t.Fatalf("insert organization %s: %v", slug, err)
	}
	return id
}

func accessRepo(t *testing.T, orgID, ref string) string {
	t.Helper()
	var projectID, repoID string
	if err := pgDB.QueryRow(
		`INSERT INTO projects (organization_id, slug, name) VALUES ($1,$2,'p') RETURNING id`,
		orgID, ref+"-proj").Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if err := pgDB.QueryRow(
		`INSERT INTO repositories (organization_id, project_id, installation_ref, repository_ref)
		 VALUES ($1,$2,$3,$3) RETURNING id`, orgID, projectID, ref).Scan(&repoID); err != nil {
		t.Fatalf("insert repository: %v", err)
	}
	return repoID
}

func accessPrincipal(t *testing.T, subject, email string) string {
	t.Helper()
	var id string
	if err := pgDB.QueryRow(
		`INSERT INTO principals (identity_provider, provider_subject, email, email_verified_at)
		 VALUES ('test',$1,$2,now()) RETURNING id`, subject, email).Scan(&id); err != nil {
		t.Fatalf("insert principal: %v", err)
	}
	return id
}

func accessMember(t *testing.T, orgID, principalID, role string) {
	t.Helper()
	if _, err := pgDB.Exec(
		`INSERT INTO memberships (organization_id, principal_id, role) VALUES ($1,$2,$3)`,
		orgID, principalID, role); err != nil {
		t.Fatalf("insert membership: %v", err)
	}
}

func accessStore(t *testing.T) *postgres.AccessStore {
	t.Helper()
	s, err := postgres.NewAccessStore(pgDB)
	if err != nil {
		t.Fatalf("new access store: %v", err)
	}
	return s
}

// Every statement must run with app.organization_id set, because that is what makes
// the row level security policies apply. A store that forgot on one path would read
// every organization's rows, and would do so without an error.
func TestAQueryWithoutATenantIsRefused(t *testing.T) {
	s := accessStore(t)
	ctx := context.Background()
	for _, orgID := range []string{"", "   "} {
		if _, err := s.LoadSnapshot(ctx, orgID); err == nil {
			t.Fatalf("a snapshot load for tenant %q was allowed", orgID)
		}
	}
}

func TestAStoreRefusesToBeBuiltWithoutADatabase(t *testing.T) {
	// Wiring-time failure beats a nil dereference in the middle of a request on a
	// path nobody tested.
	if _, err := postgres.NewAccessStore(nil); err == nil {
		t.Fatal("a store must not be constructible without a database handle")
	}
}

func TestSnapshotLoadsOnlyTheTenantsOwnMembers(t *testing.T) {
	s := accessStore(t)
	ctx := context.Background()
	orgA := accessOrg(t, "acc-snap-a")
	orgB := accessOrg(t, "acc-snap-b")
	owner := accessPrincipal(t, "snap-owner", "snap-owner@example.com")
	outsider := accessPrincipal(t, "snap-outsider", "snap-outsider@example.com")
	accessMember(t, orgA, owner, string(access.RoleOwner))
	accessMember(t, orgB, outsider, string(access.RoleOwner))

	snap, err := s.LoadSnapshot(ctx, orgA)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(snap.Memberships) != 1 || snap.Memberships[0].PrincipalID != owner {
		t.Fatalf("organization A loaded %+v", snap.Memberships)
	}
	if _, err := snap.Authorize(outsider, orgA, "", access.PermRepoRead, time.Now()); err == nil {
		t.Fatal("a principal from another organization appears to be a member")
	}
}

func TestInviteIssuesAndRedemptionIsSingleUse(t *testing.T) {
	s := accessStore(t)
	ctx := context.Background()
	orgID := accessOrg(t, "acc-invite")
	owner := accessPrincipal(t, "inv-owner", "inv-owner@example.com")
	accessMember(t, orgID, owner, string(access.RoleOwner))
	newcomer := accessPrincipal(t, "inv-new", "inv-new@example.com")

	inv, err := s.Invite(ctx, orgID, "inv-new@example.com", owner, "tok-accept", access.RoleDeveloper, 0)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if inv.TokenHash == "tok-accept" {
		t.Fatal("the raw token was returned for storage")
	}

	if err := s.AcceptInvitation(ctx, orgID, inv.TokenHash, "inv-new@example.com", newcomer, access.RoleDeveloper, time.Now().UTC()); err != nil {
		t.Fatalf("accept: %v", err)
	}
	// The same token must not create a second membership, and must say so.
	if err := s.AcceptInvitation(ctx, orgID, inv.TokenHash, "inv-new@example.com", newcomer, access.RoleDeveloper, time.Now().UTC()); !errors.Is(err, access.ErrInvitationUsed) {
		t.Fatalf("second acceptance: got %v, want ErrInvitationUsed", err)
	}

	snap, err := s.LoadSnapshot(ctx, orgID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := len(snap.Memberships); got != 2 {
		t.Fatalf("organization has %d members after one redemption, want 2", got)
	}
}

func TestAnExpiredTokenCannotBeRedeemed(t *testing.T) {
	s := accessStore(t)
	ctx := context.Background()
	orgID := accessOrg(t, "acc-expired")
	owner := accessPrincipal(t, "exp-owner", "exp-owner@example.com")
	accessMember(t, orgID, owner, string(access.RoleOwner))
	newcomer := accessPrincipal(t, "exp-new", "exp-new@example.com")

	inv, err := s.Invite(ctx, orgID, "exp-new@example.com", owner, "tok-expired", access.RoleDeveloper, time.Hour)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	err = s.AcceptInvitation(ctx, orgID, inv.TokenHash, "exp-new@example.com", newcomer,
		access.RoleDeveloper, time.Now().UTC().Add(2*time.Hour))
	if !errors.Is(err, access.ErrInvitationExpired) {
		t.Fatalf("expired token: got %v, want ErrInvitationExpired", err)
	}
}

func TestAnOutsiderCannotInviteThroughTheStore(t *testing.T) {
	s := accessStore(t)
	ctx := context.Background()
	orgA := accessOrg(t, "acc-outsider-a")
	orgB := accessOrg(t, "acc-outsider-b")
	ownerA := accessPrincipal(t, "outs-owner-a", "outs-a@example.com")
	ownerB := accessPrincipal(t, "outs-owner-b", "outs-b@example.com")
	accessMember(t, orgA, ownerA, string(access.RoleOwner))
	accessMember(t, orgB, ownerB, string(access.RoleOwner))

	// The policy lives in internal/access and is applied here, so the store is not a
	// second, looser implementation of who may invite.
	if _, err := s.Invite(ctx, orgA, "x@example.com", ownerB, "tok-x", access.RoleDeveloper, 0); err == nil {
		t.Fatal("an owner of another organization invited into this one")
	}
	if _, err := s.Invite(ctx, orgA, "x@example.com", ownerA, "tok-x", access.RoleOwner, 0); err == nil {
		t.Fatal("an invitation granting ownership was issued")
	}
}

func TestRepositoryGrantsRoundTripAndDenyCanBeChanged(t *testing.T) {
	s := accessStore(t)
	ctx := context.Background()
	orgID := accessOrg(t, "acc-grants")
	repoID := accessRepo(t, orgID, "acc-grants-repo")
	developer := accessPrincipal(t, "grant-dev", "grant-dev@example.com")
	accessMember(t, orgID, developer, string(access.RoleDeveloper))

	if err := s.PutRepositoryGrant(ctx, orgID, repoID, developer, access.PermRepoWrite, false); err != nil {
		t.Fatalf("allow: %v", err)
	}
	// Changing a rule must be expressible without deleting first: a delete-then-insert
	// leaves a window where neither exists.
	if err := s.PutRepositoryGrant(ctx, orgID, repoID, developer, access.PermRepoWrite, true); err != nil {
		t.Fatalf("flip to deny: %v", err)
	}

	snap, err := s.LoadSnapshot(ctx, orgID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := snap.Authorize(developer, orgID, repoID, access.PermRepoWrite, time.Now()); !errors.Is(err, access.ErrDenied) {
		t.Fatalf("the deny was not applied: %v", err)
	}
}

func TestAGrantToANonMemberIsRefusedBeforeTheDatabaseSeesIt(t *testing.T) {
	s := accessStore(t)
	ctx := context.Background()
	orgA := accessOrg(t, "acc-grantee-a")
	orgB := accessOrg(t, "acc-grantee-b")
	repoA := accessRepo(t, orgA, "acc-grantee-repo")
	outsider := accessPrincipal(t, "grant-outsider", "grant-outsider@example.com")
	accessMember(t, orgB, outsider, string(access.RoleDeveloper))

	// ValidateGrant turns a constraint violation into a typed refusal.
	if err := s.PutRepositoryGrant(ctx, orgA, repoA, outsider, access.PermRepoRead, false); !errors.Is(err, access.ErrNotAMember) {
		t.Fatalf("grant to a non-member: got %v, want ErrNotAMember", err)
	}
}

func TestRevokingAMembershipRemovesItsGrants(t *testing.T) {
	s := accessStore(t)
	ctx := context.Background()
	orgID := accessOrg(t, "acc-revoke")
	repoID := accessRepo(t, orgID, "acc-revoke-repo")
	owner := accessPrincipal(t, "rev-owner", "rev-owner@example.com")
	developer := accessPrincipal(t, "rev-dev", "rev-dev@example.com")
	accessMember(t, orgID, owner, string(access.RoleOwner))
	accessMember(t, orgID, developer, string(access.RoleDeveloper))

	if err := s.PutRepositoryGrant(ctx, orgID, repoID, developer, access.PermRepoWrite, false); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := s.RevokeMember(ctx, orgID, developer, owner, time.Now().UTC()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	var n int
	if err := pgDB.QueryRow(
		`SELECT count(*) FROM repository_grants WHERE repository_id = $1`, repoID).Scan(&n); err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if n != 0 {
		t.Fatalf("%d grants survived the membership they depended on", n)
	}
}

// A revoked member can still destroy what is running, which is why revocation is a
// status on the membership rather than a deletion that cascades away the ability to
// check anything.
func TestARevokedMemberCanStillAbort(t *testing.T) {
	s := accessStore(t)
	ctx := context.Background()
	orgID := accessOrg(t, "acc-teardown")
	repoID := accessRepo(t, orgID, "acc-teardown-repo")
	owner := accessPrincipal(t, "td-owner", "td-owner@example.com")
	developer := accessPrincipal(t, "td-dev", "td-dev@example.com")
	accessMember(t, orgID, owner, string(access.RoleOwner))
	accessMember(t, orgID, developer, string(access.RoleDeveloper))

	if err := s.RevokeMember(ctx, orgID, developer, owner, time.Now().UTC()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	snap, err := s.LoadSnapshot(ctx, orgID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d, err := snap.Authorize(developer, orgID, repoID, access.PermEnvAbort, time.Now())
	if err != nil || !d.Allowed {
		t.Fatalf("a revoked member refused to abort: %v", err)
	}
	if _, err := snap.Authorize(developer, orgID, repoID, access.PermEnvCreate, time.Now()); err == nil {
		t.Fatal("a revoked member must not create new previews")
	}
}

func TestRevokingTheLastOwnerIsRefused(t *testing.T) {
	s := accessStore(t)
	ctx := context.Background()
	orgID := accessOrg(t, "acc-lastowner")
	owner := accessPrincipal(t, "lo-owner", "lo-owner@example.com")
	accessMember(t, orgID, owner, string(access.RoleOwner))

	if err := s.RevokeMember(ctx, orgID, owner, owner, time.Now().UTC()); !errors.Is(err, access.ErrLastOwner) {
		t.Fatalf("removing the last owner: got %v, want ErrLastOwner", err)
	}
}

func TestASuspendedOrganizationIsVisibleToTheStore(t *testing.T) {
	s := accessStore(t)
	ctx := context.Background()
	orgID := accessOrg(t, "acc-suspended")
	owner := accessPrincipal(t, "susp-owner", "susp-owner@example.com")
	repoID := accessRepo(t, orgID, "acc-suspended-repo")
	accessMember(t, orgID, owner, string(access.RoleOwner))

	if _, err := pgDB.Exec(`UPDATE organizations SET status = 'restricted' WHERE id = $1`, orgID); err != nil {
		t.Fatalf("restrict: %v", err)
	}
	snap, err := s.LoadSnapshot(ctx, orgID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(snap.Orgs) != 1 || !snap.Orgs[0].Suspended {
		t.Fatalf("suspension was not read back: %+v", snap.Orgs)
	}
	if _, err := snap.Authorize(owner, orgID, repoID, access.PermEnvCreate, time.Now()); !errors.Is(err, access.ErrOrgSuspended) {
		t.Fatalf("suspended organization admitted work: %v", err)
	}
	if _, err := snap.Authorize(owner, orgID, repoID, access.PermEnvAbort, time.Now()); err != nil {
		t.Fatalf("a suspended organization must still permit abort: %v", err)
	}
}

// Two simultaneous redemptions of one token produce one membership. Checking first and
// inserting afterwards would let both succeed.
func TestConcurrentRedemptionYieldsOneMembership(t *testing.T) {
	s := accessStore(t)
	ctx := context.Background()
	orgID := accessOrg(t, "acc-race")
	owner := accessPrincipal(t, "race-owner", "race-owner@example.com")
	newcomer := accessPrincipal(t, "race-new", "race-new@example.com")
	accessMember(t, orgID, owner, string(access.RoleOwner))

	inv, err := s.Invite(ctx, orgID, "race-new@example.com", owner, "tok-race", access.RoleDeveloper, 0)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	const attempts = 8
	errs := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			errs <- s.AcceptInvitation(ctx, orgID, inv.TokenHash, "race-new@example.com",
				newcomer, access.RoleDeveloper, time.Now().UTC())
		}()
	}
	accepted := 0
	for i := 0; i < attempts; i++ {
		if err := <-errs; err == nil {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("%d of %d concurrent redemptions succeeded, want 1", accepted, attempts)
	}
	var n int
	if err := pgDB.QueryRow(
		`SELECT count(*) FROM memberships WHERE organization_id=$1 AND principal_id=$2`,
		orgID, newcomer).Scan(&n); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if n != 1 {
		t.Fatalf("the newcomer holds %d memberships, want 1", n)
	}
}

var _ = sql.ErrNoRows

// The organizations lifecycle is richer than the two booleans the policy layer uses,
// so the mapping is derived in one place and tested against every status the schema
// allows rather than against the two that were thought of first.
func TestOrganizationStatusMapping(t *testing.T) {
	cases := []struct {
		status    string
		suspended bool
		closed    bool
		accepts   bool
	}{
		{"provisioning", false, false, false},
		{"trial", false, false, true},
		{"active", false, false, true},
		{"restricted", true, false, false},
		{"closing", true, false, false},
		{"closed", false, true, false},
	}
	for _, c := range cases {
		o := postgres.OrganizationFromStatus("org_1", c.status)
		if o.Suspended != c.suspended || o.Closed != c.closed {
			t.Fatalf("status %s mapped to suspended=%v closed=%v, want %v/%v",
				c.status, o.Suspended, o.Closed, c.suspended, c.closed)
		}
		if postgres.AcceptsWork(c.status) != c.accepts {
			t.Fatalf("status %s accepts work=%v, want %v", c.status, postgres.AcceptsWork(c.status), c.accepts)
		}
	}
	// An unknown status must not be read as a healthy organization.
	if postgres.AcceptsWork("something-new") {
		t.Fatal("an unrecognised lifecycle status must not admit work")
	}
	if len(postgres.OrganizationStatuses()) != 6 {
		t.Fatalf("the store lists %d lifecycle statuses, want the 6 the schema constrains",
			len(postgres.OrganizationStatuses()))
	}
}
