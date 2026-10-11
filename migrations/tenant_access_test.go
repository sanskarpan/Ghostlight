package migrations_test

import (
	"database/sql"
	"strings"
	"testing"
)

// insertPrincipalAndMember creates a principal and gives them a role in an org,
// returning the principal id.
func insertPrincipalAndMember(t *testing.T, db *sql.DB, orgID, subject, role string) string {
	t.Helper()
	var pid string
	if err := db.QueryRow(
		`INSERT INTO principals (identity_provider, provider_subject, email, email_verified_at)
		 VALUES ('test', $1, $1 || '@example.com', now()) RETURNING id`, subject).Scan(&pid); err != nil {
		t.Fatalf("insert principal: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO memberships (organization_id, principal_id, role) VALUES ($1, $2, $3)`,
		orgID, pid, role); err != nil {
		t.Fatalf("insert membership: %v", err)
	}
	return pid
}

// mustRefuse runs a statement that must be rejected and returns the error. A test
// that passes because the statement succeeded would be worse than no test.
func mustRefuse(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	_, err := db.Exec(query, args...)
	if err == nil {
		t.Fatal("the database accepted a statement it must refuse")
	}
	return err.Error()
}

func refuseMatching(t *testing.T, message, want string) {
	t.Helper()
	if !strings.Contains(message, want) {
		t.Fatalf("refused for the wrong reason:\n got: %s\nwant substring: %s", message, want)
	}
}

// This is the hole the migration closes. project_grants previously carried no
// organization column, so any principal from any tenant could be granted access to
// any project in any tenant. The application never did this; the schema allowed it.
func TestAGrantCannotNameAnotherOrganizationsProject(t *testing.T) {
	db := startPostgres(t)
	orgA, projectA, _ := seed(t, db, "org-grant-x", "repo-x")
	_, projectB, _ := seed(t, db, "org-grant-y", "repo-y")
	memberA := insertPrincipalAndMember(t, db, orgA, "grant-x-member", "developer")

	// The grant claims organization A while naming a project in organization B.
	msg := mustRefuse(t, db,
		`INSERT INTO project_grants (organization_id, project_id, principal_id)
		 VALUES ($1, $2, $3)`, orgA, projectB, memberA)
	refuseMatching(t, msg, "project_grants_organization_project_fkey")

	// And the honest form still works.
	if _, err := db.Exec(
		`INSERT INTO project_grants (organization_id, project_id, principal_id)
		 VALUES ($1, $2, $3)`, orgA, projectA, memberA); err != nil {
		t.Fatalf("a legitimate grant was refused: %v", err)
	}
}

// A grant to a non-member is an invitation that forgot to be one.
func TestAGrantCannotNameANonMember(t *testing.T) {
	db := startPostgres(t)
	orgA, projectA, _ := seed(t, db, "org-nonmember", "repo-nm")
	orgB, _, _ := seed(t, db, "org-outsider", "repo-out")
	outsider := insertPrincipalAndMember(t, db, orgB, "outsider", "developer")

	msg := mustRefuse(t, db,
		`INSERT INTO project_grants (organization_id, project_id, principal_id)
		 VALUES ($1, $2, $3)`, orgA, projectA, outsider)
	refuseMatching(t, msg, "project_grants_organization_principal_fkey")
}

func TestRevokingAMembershipRemovesItsGrants(t *testing.T) {
	db := startPostgres(t)
	orgA, projectA, _ := seed(t, db, "org-revoke", "repo-rev")
	member := insertPrincipalAndMember(t, db, orgA, "revoke-me", "developer")
	if _, err := db.Exec(
		`INSERT INTO project_grants (organization_id, project_id, principal_id)
		 VALUES ($1,$2,$3)`, orgA, projectA, member); err != nil {
		t.Fatalf("insert grant: %v", err)
	}
	// Deleting a membership must not leave an orphaned grant behind: access that
	// outlives the relationship it was granted by is access nobody can revoke.
	if _, err := db.Exec(
		`DELETE FROM memberships WHERE organization_id=$1 AND principal_id=$2`, orgA, member); err != nil {
		t.Fatalf("delete membership: %v", err)
	}
	var n int
	if err := db.QueryRow(
		`SELECT count(*) FROM project_grants WHERE organization_id=$1`, orgA).Scan(&n); err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if n != 0 {
		t.Fatalf("%d grants survived the membership they depended on", n)
	}
}

func TestRepositoryGrantsCarryDenyAsData(t *testing.T) {
	db := startPostgres(t)
	orgA, _, repoA := seed(t, db, "org-repo-grant", "repo-rg")
	member := insertPrincipalAndMember(t, db, orgA, "rg-member", "developer")

	if _, err := db.Exec(
		`INSERT INTO repository_grants (organization_id, repository_id, principal_id, permission, deny)
		 VALUES ($1,$2,$3,'repo:write', false)`, orgA, repoA, member); err != nil {
		t.Fatalf("insert allow: %v", err)
	}
	// An explicit deny and a missing grant are different intentions: one says never,
	// the other says not yet. Both must be representable.
	if _, err := db.Exec(
		`INSERT INTO repository_grants (organization_id, repository_id, principal_id, permission, deny)
		 VALUES ($1,$2,$3,'repo:write', true)`, orgA, repoA, member); err == nil {
		t.Fatal("a second grant for the same triple must be refused")
	}
}

func TestARepositoryGrantCannotCrossOrganizations(t *testing.T) {
	db := startPostgres(t)
	orgA, _, repoA := seed(t, db, "org-rg-a", "repo-rg-a")
	orgB, _, repoB := seed(t, db, "org-rg-b", "repo-rg-b")
	memberB := insertPrincipalAndMember(t, db, orgB, "rg-member-b", "developer")

	msg := mustRefuse(t, db,
		`INSERT INTO repository_grants (organization_id, repository_id, principal_id, permission)
		 VALUES ($1,$2,$3,'repo:read')`, orgA, repoB, memberB)
	refuseMatching(t, msg, "repository_grants_organization_repository_fkey")

	msg = mustRefuse(t, db,
		`INSERT INTO repository_grants (organization_id, repository_id, principal_id, permission)
		 VALUES ($1,$2,$3,'repo:read')`, orgB, repoA, memberB)
	refuseMatching(t, msg, "repository_grants_organization_repository_fkey")

	if _, err := db.Exec(
		`INSERT INTO repository_grants (organization_id, repository_id, principal_id, permission)
		 VALUES ($1,$2,$3,'repo:read')`, orgA, repoA, memberB); err == nil {
		t.Fatal("a grant to a non-member must be refused")
	}
}

func TestAnUnknownPermissionIsRefused(t *testing.T) {
	db := startPostgres(t)
	orgA, _, repoA := seed(t, db, "org-perm", "repo-perm")
	member := insertPrincipalAndMember(t, db, orgA, "perm-member", "developer")
	msg := mustRefuse(t, db,
		`INSERT INTO repository_grants (organization_id, repository_id, principal_id, permission)
		 VALUES ($1,$2,$3,'env:nuke')`, orgA, repoA, member)
	refuseMatching(t, msg, "repository_grants_permission_check")
}

// Abort must be representable as an ordinary permission so the always-available
// teardown list cannot widen into a write capability by naming it.
func TestAbortIsAPermissionItself(t *testing.T) {
	db := startPostgres(t)
	orgA, _, repoA := seed(t, db, "org-abort", "repo-abort")
	member := insertPrincipalAndMember(t, db, orgA, "abort-member", "developer")
	if _, err := db.Exec(
		`INSERT INTO repository_grants (organization_id, repository_id, principal_id, permission)
		 VALUES ($1,$2,$3,'env:abort')`, orgA, repoA, member); err != nil {
		t.Fatalf("env:abort must be grantable: %v", err)
	}
}

func TestAnInvitationCannotGrantOwnership(t *testing.T) {
	db := startPostgres(t)
	orgA, _, _ := seed(t, db, "org-inv", "repo-inv")
	inviter := insertPrincipalAndMember(t, db, orgA, "inviter", "owner")

	// A token that grants ownership makes its holder untouchable to administrators.
	msg := mustRefuse(t, db,
		`INSERT INTO invitations (organization_id, token_hash, email, role, invited_by, expires_at)
		 VALUES ($1, repeat('a',64), 'new@example.com', 'owner', $2, now())`, orgA, inviter)
	refuseMatching(t, msg, "invitations_role_check")

	// Platform staff roles must never be reachable through a customer invitation.
	for _, role := range []string{"platform_admin", "auditor", "support", "reliability_engineer"} {
		msg := mustRefuse(t, db,
			`INSERT INTO invitations (organization_id, token_hash, email, role, invited_by, expires_at)
			 VALUES ($1, repeat('b',64), 'x@example.com', $2, $3, now())`, orgA, role, inviter)
		refuseMatching(t, msg, "invitations_role_check")
	}

	// A customer role is accepted.
	if _, err := db.Exec(
		`INSERT INTO invitations (organization_id, token_hash, email, role, invited_by, expires_at)
		 VALUES ($1, repeat('c',64), 'new@example.com', 'member', $2, now())`, orgA, inviter); err != nil {
		t.Fatalf("a legitimate invitation was refused: %v", err)
	}
}

func TestAnInvitationMustComeFromAMemberOfItsOwnOrganization(t *testing.T) {
	db := startPostgres(t)
	orgA, _, _ := seed(t, db, "org-inv-a", "repo-inv-a")
	orgB, _, _ := seed(t, db, "org-inv-b", "repo-inv-b")
	outsider := insertPrincipalAndMember(t, db, orgB, "inv-outsider", "owner")

	msg := mustRefuse(t, db,
		`INSERT INTO invitations (organization_id, token_hash, email, role, invited_by, expires_at)
		 VALUES ($1, repeat('d',64), 'x@example.com', 'member', $2, now())`, orgA, outsider)
	refuseMatching(t, msg, "invitations_organization_invited_by_fkey")
}

func TestATokenHashMustBeASha256Digest(t *testing.T) {
	db := startPostgres(t)
	orgA, _, _ := seed(t, db, "org-hash", "repo-hash")
	inviter := insertPrincipalAndMember(t, db, orgA, "hash-inviter", "owner")

	// A raw token must not be storable, even if a future caller passes one.
	msg := mustRefuse(t, db,
		`INSERT INTO invitations (organization_id, token_hash, email, role, invited_by, expires_at)
		 VALUES ($1, 'plaintext-token', 'x@example.com', 'member', $2, now())`, orgA, inviter)
	refuseMatching(t, msg, "invitations_token_hash_check")
}

// The new tables are tenant-scoped, so a session pointed at one organization must not
// see another's rows. A policy that fails open is indistinguishable from no policy.
//
// The embedded database connects as a superuser, and a superuser bypasses row level
// security whatever the policy says. Asserting visibility as postgres would pass
// against a table with no policy at all, so the check runs as a non-superuser role
// inside a transaction that is rolled back, leaving no role or setting behind on the
// shared connection.
func TestTheNewTablesAreTenantIsolated(t *testing.T) {
	db := startPostgres(t)
	orgA, _, repoA := seed(t, db, "org-iso-a", "repo-iso-a")
	orgB, _, repoB := seed(t, db, "org-iso-b", "repo-iso-b")
	memberA := insertPrincipalAndMember(t, db, orgA, "iso-a-member", "developer")
	memberB := insertPrincipalAndMember(t, db, orgB, "iso-b-member", "developer")

	if _, err := db.Exec(
		`INSERT INTO repository_grants (organization_id, repository_id, principal_id, permission)
		 VALUES ($1,$2,$3,'repo:read'), ($1,$2,$3,'env:abort'), ($1,$2,$3,'billing:read')`,
		orgA, repoA, memberA); err != nil {
		t.Fatalf("insert grants for A: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO repository_grants (organization_id, repository_id, principal_id, permission)
		 VALUES ($1,$2,$3,'repo:read')`, orgB, repoB, memberB); err != nil {
		t.Fatalf("insert grants for B: %v", err)
	}
	if _, err := db.Exec(`DROP ROLE IF EXISTS ghostlight_tenant_reader`); err != nil {
		t.Fatalf("drop stale role: %v", err)
	}
	if _, err := db.Exec(`CREATE ROLE ghostlight_tenant_reader NOLOGIN NOBYPASSRLS`); err != nil {
		t.Fatalf("create reader role: %v", err)
	}
	if _, err := db.Exec(
		`GRANT SELECT ON repository_grants, project_grants, invitations TO ghostlight_tenant_reader`); err != nil {
		t.Fatalf("grant select: %v", err)
	}

	// visibleAs returns how many of the seeded repositories a tenant can see.
	visibleAs := func(orgID string) int {
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SET LOCAL ROLE ghostlight_tenant_reader`); err != nil {
			t.Fatalf("set role: %v", err)
		}
		if _, err := tx.Exec(`SELECT set_config('app.organization_id', $1, true)`, orgID); err != nil {
			t.Fatalf("set tenant: %v", err)
		}
		var n int
		if err := tx.QueryRow(
			`SELECT count(*) FROM repository_grants WHERE repository_id IN ($1, $2)`,
			repoA, repoB).Scan(&n); err != nil {
			t.Fatalf("count visible: %v", err)
		}
		return n
	}

	// Each tenant sees exactly its own three or one grants, never the other tenant's.
	if got := visibleAs(orgA); got != 3 {
		t.Fatalf("organization A sees %d seeded grants, want its own 3", got)
	}
	if got := visibleAs(orgB); got != 1 {
		t.Fatalf("organization B sees %d seeded grants, want its own 1", got)
	}
}

// Without this the isolation test above would pass against a table with no policy at
// all, because a superuser sees every row regardless.
func TestRowLevelSecurityIsForcedNotMerelyEnabled(t *testing.T) {
	db := startPostgres(t)
	for _, table := range []string{"project_grants", "repository_grants", "invitations"} {
		var enabled, forced bool
		err := db.QueryRow(`
			SELECT c.relrowsecurity, c.relforcerowsecurity
			  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			 WHERE n.nspname = 'public' AND c.relname = $1`, table).
			Scan(&enabled, &forced)
		if err != nil {
			t.Fatalf("read policy flags for %s: %v", table, err)
		}
		if !enabled {
			t.Fatalf("%s does not enable row level security", table)
		}
		// An owner that can bypass its own policy is exactly the connection an
		// attacker with a SQL injection reaches for.
		if !forced {
			t.Fatalf("%s does not FORCE row level security; the table owner bypasses it", table)
		}
	}
}

// An invitation records who invited, but an invitation must outlive the inviter's
// membership: deleting someone must not silently delete an outstanding invitation,
// and must not leave one pointing at a membership that no longer exists.
//
// Composite foreign keys with ON DELETE SET NULL only null the intended column from
// PostgreSQL 15 onward. On an older server the same clause would try to null
// organization_id as well, which is NOT NULL, and the delete would fail. This test
// states the required outcome so the version dependency cannot pass unnoticed.
func TestAnInvitationSurvivesTheInvitersDeparture(t *testing.T) {
	db := startPostgres(t)
	var version string
	if err := db.QueryRow(`SHOW server_version`).Scan(&version); err != nil {
		t.Fatalf("read server version: %v", err)
	}
	orgA, _, _ := seed(t, db, "org-inv-depart", "repo-inv-d")
	inviter := insertPrincipalAndMember(t, db, orgA, "departing-inviter", "owner")
	if _, err := db.Exec(
		`INSERT INTO invitations (organization_id, token_hash, email, role, invited_by, expires_at)
		 VALUES ($1, repeat('e',64), 'pending@example.com', 'member', $2, now())`, orgA, inviter); err != nil {
		t.Fatalf("insert invitation: %v", err)
	}
	if _, err := db.Exec(
		`DELETE FROM memberships WHERE organization_id=$1 AND principal_id=$2`, orgA, inviter); err != nil {
		t.Fatalf("deleting an inviter must not be blocked by their invitations: %v", err)
	}
	var inviterLeft sql.NullString
	if err := db.QueryRow(
		`SELECT invited_by::text FROM invitations WHERE organization_id=$1`, orgA).Scan(&inviterLeft); err != nil {
		t.Fatalf("the invitation was deleted along with its inviter: %v", err)
	}
	if inviterLeft.Valid {
		t.Fatalf("the invitation still points at %s, a membership that no longer exists", inviterLeft.String)
	}
	t.Logf("postgres server version %s", version)
}

func TestAServicePrincipalMustBeCreatedByAMemberOfItsOrganization(t *testing.T) {
	db := startPostgres(t)
	orgA, _, _ := seed(t, db, "org-sp", "repo-sp")
	orgB, _, _ := seed(t, db, "org-sp-other", "repo-sp-other")
	outsider := insertPrincipalAndMember(t, db, orgB, "sp-outsider", "owner")

	// A credential created inside another tenant's scope by somebody with no
	// relationship to that tenant.
	msg := mustRefuse(t, db,
		`INSERT INTO service_principals (organization_id, name, key_prefix, secret_hash, created_by)
		 VALUES ($1, 'rogue', 'rogue_', '{}', $2)`, orgA, outsider)
	refuseMatching(t, msg, "service_principals_creator_fkey")
}
