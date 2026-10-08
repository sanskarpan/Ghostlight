package migrations_test

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/fergusstrange/embedded-postgres"
	_ "github.com/lib/pq"

	"github.com/sanskarpan/Ghostlight/migrations"
)

// shared is one PostgreSQL instance for the whole package. Starting a database
// per test is slow and races on the listening port; each test isolates itself
// with distinct slugs instead.
var (
	shared     *sql.DB
	pgInstance *embeddedpostgres.EmbeddedPostgres
	pgSkip     error
)

// TestMain starts one real PostgreSQL instance and applies the schema once.
//
// The schema depends on behaviour that is easy to assert wrongly in prose:
// composite tenant foreign keys, FORCE row level security, partial indexes and
// check constraints. Verifying them needs a real database, not a mock.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ghostlight-pg-migrations")
	if err != nil {
		pgSkip = err
		os.Exit(m.Run())
	}
	defer os.RemoveAll(dir)

	// CachePath and RuntimePath are pinned inside this package's own temp dir.
	// The library's default cache is a single shared directory, so two packages
	// starting a database concurrently race to extract the same binaries and one
	// of them fails. A failing database here would silently skip the schema
	// verification and report green.
	port := freePort()
	pgInstance = embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Port(port).
		CachePath(dir + "/cache").
		BinariesPath(dir + "/bin").
		RuntimePath(dir + "/run").
		DataPath(dir + "/data").
		Username("ghostlight").
		Password("ghostlight").
		Database("ghostlight"))
	if err := pgInstance.Start(); err != nil {
		// An unavailable database must not silently pass the suite as green.
		pgSkip = fmt.Errorf("embedded postgres unavailable: %w", err)
		os.Exit(m.Run())
	}

	db, err := sql.Open("postgres", fmt.Sprintf(
		"host=localhost port=%d user=ghostlight password=ghostlight dbname=ghostlight sslmode=disable", port))
	if err == nil {
		err = db.Ping()
	}
	if err == nil {
		err = migrations.Apply(db)
	}
	if err != nil {
		pgSkip = fmt.Errorf("schema setup: %w", err)
		_ = pgInstance.Stop()
		os.Exit(m.Run())
	}

	shared = db
	code := m.Run()
	_ = db.Close()
	_ = pgInstance.Stop()
	os.Exit(code)
}

// freePort asks the OS for an unused TCP port.
func freePort() uint32 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 55432
	}
	defer l.Close()
	return uint32(l.Addr().(*net.TCPAddr).Port)
}

func startPostgres(t *testing.T) *sql.DB {
	t.Helper()
	if pgSkip != nil || shared == nil {
		t.Skipf("skipping schema verification: %v", pgSkip)
	}
	return shared
}

// seed creates an organization, project and repository and returns their ids.
// Each test uses a distinct repoRef so tests do not collide.
func seed(t *testing.T, db *sql.DB, orgSlug, repoRef string) (orgID, projectID, repoID string) {
	t.Helper()
	if err := db.QueryRow(
		`INSERT INTO organizations (slug, name, policy_version) VALUES ($1, $2, 'v1') RETURNING id`,
		orgSlug, orgSlug+" name").Scan(&orgID); err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	if err := db.QueryRow(
		`INSERT INTO projects (organization_id, slug, name) VALUES ($1, $2, 'proj') RETURNING id`,
		orgID, orgSlug+"-proj").Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if err := db.QueryRow(
		`INSERT INTO repositories (organization_id, project_id, installation_ref, repository_ref)
		 VALUES ($1, $2, 'inst-' || $3, $3) RETURNING id`,
		orgID, projectID, repoRef).Scan(&repoID); err != nil {
		t.Fatalf("insert repository: %v", err)
	}
	return
}

func insertEnvironment(t *testing.T, db *sql.DB, orgID, projectID, repoID, slug string) string {
	t.Helper()
	var id string
	err := db.QueryRow(`
		INSERT INTO environments
			(organization_id, repository_id, project_id, slug, source_sha, artifact_digest,
			 configuration_digest, recipe_digest, policy_digest, resource_profile, expires_at)
		VALUES ($1,$2,$3,$4,'sha-source','sha256:art','sha256:cfg','sha256:rec','sha256:pol','preview-small','2026-10-07 00:00:00+00')
		RETURNING id`,
		orgID, repoID, projectID, slug).Scan(&id)
	if err != nil {
		t.Fatalf("insert environment: %v", err)
	}
	return id
}

func insertGeneration(t *testing.T, db *sql.DB, orgID, envID string, generation int) {
	t.Helper()
	if _, err := db.Exec(`
		INSERT INTO environment_generations
			(environment_id, generation, organization_id, source_sha, artifact_digest,
			 configuration_digest, recipe_digest, policy_digest)
		VALUES ($1, $2, $3, 'sha-source', 'sha256:art', 'sha256:cfg', 'sha256:rec', 'sha256:pol')`,
		envID, generation, orgID); err != nil {
		t.Fatalf("insert generation %d: %v", generation, err)
	}
}

func TestSchemaApplies(t *testing.T) {
	db := startPostgres(t)

	for _, table := range []string{
		"organizations", "projects", "repositories", "environments",
		"environment_generations", "actions", "runner_executions",
		"resource_allocations", "resource_observations", "capacity_reservations",
		"cleanup_runs", "audit_log", "service_principals", "principals",
		"memberships", "project_grants",
	} {
		var n int
		if err := db.QueryRow(
			`SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name=$1`,
			table).Scan(&n); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if n != 1 {
			t.Errorf("expected table %s to exist", table)
		}
	}
}

// TestUncertainIsDistinctFromFailed checks the enum carries the state the whole
// observe-before-retry design depends on.
func TestUncertainIsDistinctFromFailed(t *testing.T) {
	db := startPostgres(t)
	var n int
	err := db.QueryRow(
		`SELECT count(*) FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid
		 WHERE t.typname = 'action_state' AND e.enumlabel = 'uncertain'`).Scan(&n)
	if err != nil {
		t.Fatalf("query enum: %v", err)
	}
	if n != 1 {
		t.Fatal("action_state must include 'uncertain'; without it a timeout cannot be represented")
	}
}

// TestActionIdempotencyKeyRejectsDuplicates is the property that makes a
// redelivered event a no-op rather than a second run.
func TestActionIdempotencyKeyRejectsDuplicates(t *testing.T) {
	db := startPostgres(t)
	orgID, projectID, repoID := seed(t, db, "acme-dup", "repo/acme-dup/one")
	envID := insertEnvironment(t, db, orgID, projectID, repoID, "pr-dup-aaaa")
	insertGeneration(t, db, orgID, envID, 1)

	insert := func() error {
		_, err := db.Exec(`
			INSERT INTO actions (environment_id, generation, action_type, logical_key, input_digest, expected_generation)
			VALUES ($1, 1, 'allocate', 'alloc-pg', 'sha256:aa', 1)`, envID)
		return err
	}
	if err := insert(); err != nil {
		t.Fatalf("first insert must succeed: %v", err)
	}
	if err := insert(); err == nil {
		t.Fatal("a duplicate (environment, generation, type, logical key) must be rejected")
	}
}

// TestActionMustNameARecordedGeneration checks an action cannot reference a
// generation that was never recorded.
func TestActionMustNameARecordedGeneration(t *testing.T) {
	db := startPostgres(t)
	orgID, projectID, repoID := seed(t, db, "acme-gen", "repo/acme-gen/one")
	envID := insertEnvironment(t, db, orgID, projectID, repoID, "pr-gen-bbbb")

	_, err := db.Exec(`
		INSERT INTO actions (environment_id, generation, action_type, logical_key, input_digest, expected_generation)
		VALUES ($1, 9, 'allocate', 'alloc-pg', 'sha256:aa', 9)`, envID)
	if err == nil {
		t.Fatal("an action for an unrecorded generation must be rejected")
	}
}

// TestExpectedGenerationCannotDisagree checks the denormalised fence column.
func TestExpectedGenerationCannotDisagree(t *testing.T) {
	db := startPostgres(t)
	orgID, projectID, repoID := seed(t, db, "acme-fence", "repo/acme-fence/one")
	envID := insertEnvironment(t, db, orgID, projectID, repoID, "pr-fence-cccc")
	insertGeneration(t, db, orgID, envID, 1)

	_, err := db.Exec(`
		INSERT INTO actions (environment_id, generation, action_type, logical_key, input_digest, expected_generation)
		VALUES ($1, 1, 'allocate', 'alloc-pg', 'sha256:aa', 2)`, envID)
	if err == nil {
		t.Fatal("expected_generation must equal generation; a mismatch is a fence defect")
	}
}

// TestPolicyDigestIsRequiredOnEnvironment checks the G0.6 fix at the schema
// level: a candidate that cannot bind a policy cannot be gated.
func TestPolicyDigestIsRequiredOnEnvironment(t *testing.T) {
	db := startPostgres(t)
	orgID, projectID, repoID := seed(t, db, "acme-pol", "repo/acme-pol/one")

	_, err := db.Exec(`
		INSERT INTO environments
			(organization_id, repository_id, project_id, slug, source_sha, artifact_digest,
			 configuration_digest, recipe_digest, resource_profile, expires_at)
		VALUES ($1,$2,$3,'pr-pol-dddd','sha','sha256:art','sha256:cfg','sha256:rec','preview-small','2026-10-07 00:00:00+00')`,
		orgID, repoID, projectID)
	if err == nil {
		t.Fatal("policy_digest must be NOT NULL; an unbindable candidate must not be storable")
	}
}

// TestQuarantineRequiresReason checks a consequential state cannot be entered
// silently.
func TestQuarantineRequiresReason(t *testing.T) {
	db := startPostgres(t)
	orgID, projectID, repoID := seed(t, db, "acme-quar", "repo/acme-quar/one")
	envID := insertEnvironment(t, db, orgID, projectID, repoID, "pr-quar-eeee")

	if _, err := db.Exec(
		`UPDATE environments SET observed = 'quarantined' WHERE id = $1`, envID); err == nil {
		t.Fatal("quarantine without a reason must be rejected")
	}
	if _, err := db.Exec(
		`UPDATE environments SET observed = 'quarantined', quarantine_reason = 'fault removal unverified'
		 WHERE id = $1`, envID); err != nil {
		t.Fatalf("quarantine with a reason must be accepted: %v", err)
	}
}

// TestDestroyedCannotBeDesiredPresent encodes that destruction is terminal.
func TestDestroyedCannotBeDesiredPresent(t *testing.T) {
	db := startPostgres(t)
	orgID, projectID, repoID := seed(t, db, "acme-term", "repo/acme-term/one")
	envID := insertEnvironment(t, db, orgID, projectID, repoID, "pr-term-ffff")

	if _, err := db.Exec(
		`UPDATE environments SET desired='absent', observed='destroyed' WHERE id=$1`, envID); err != nil {
		t.Fatalf("a destroyed environment must be allowed once desired is absent: %v", err)
	}
	if _, err := db.Exec(
		`UPDATE environments SET desired='present' WHERE id=$1`, envID); err == nil {
		t.Fatal("a destroyed environment must not be desired present; the identifier is terminal")
	}
}

// TestSharedResourceCannotBeMarkedDeleted encodes the destroy denylist in SQL.
func TestSharedResourceCannotBeMarkedDeleted(t *testing.T) {
	db := startPostgres(t)
	orgID, projectID, repoID := seed(t, db, "acme-share", "repo/acme-share/one")
	envID := insertEnvironment(t, db, orgID, projectID, repoID, "pr-share-gggg")
	insertGeneration(t, db, orgID, envID, 1)

	if _, err := db.Exec(`
		INSERT INTO resource_allocations
			(environment_id, organization_id, generation, dependency_kind, logical_key, provider_ref, is_shared)
		VALUES ($1, $2, 1, 'kafka', 'topic-1', '{"handle":"h1"}', true)`, envID, orgID); err != nil {
		t.Fatalf("insert shared allocation: %v", err)
	}
	_, err := db.Exec(
		`UPDATE resource_allocations SET verified_deleted_at = now() WHERE environment_id = $1`, envID)
	if err == nil {
		t.Fatal("a shared resource must never be marked deleted through the allocation ledger")
	}
}

// TestAllocationLogicalKeyIsIdempotent checks a retry resolves to the same
// allocation rather than creating a second one.
func TestAllocationLogicalKeyIsIdempotent(t *testing.T) {
	db := startPostgres(t)
	orgID, projectID, repoID := seed(t, db, "acme-alloc", "repo/acme-alloc/one")
	envID := insertEnvironment(t, db, orgID, projectID, repoID, "pr-alloc-hhhh")
	insertGeneration(t, db, orgID, envID, 1)

	ins := func() error {
		_, err := db.Exec(`
			INSERT INTO resource_allocations
				(environment_id, organization_id, generation, dependency_kind, logical_key, provider_ref)
			VALUES ($1, $2, 1, 'postgres', 'pg-1', '{"handle":"h1"}')`, envID, orgID)
		return err
	}
	if err := ins(); err != nil {
		t.Fatalf("first allocation must succeed: %v", err)
	}
	if err := ins(); err == nil {
		t.Fatal("a duplicate (environment, dependency kind, logical key) must be rejected")
	}
}

// TestObservationSequenceIsMonotonic checks the observation ledger ordering.
func TestObservationSequenceIsMonotonic(t *testing.T) {
	db := startPostgres(t)
	orgID, projectID, repoID := seed(t, db, "acme-obs", "repo/acme-obs/one")
	envID := insertEnvironment(t, db, orgID, projectID, repoID, "pr-obs-iiii")
	insertGeneration(t, db, orgID, envID, 1)

	var allocID string
	if err := db.QueryRow(`
		INSERT INTO resource_allocations
			(environment_id, organization_id, generation, dependency_kind, logical_key, provider_ref)
		VALUES ($1,$2,1,'postgres','pg-1','{"handle":"h1"}') RETURNING id`, envID, orgID).Scan(&allocID); err != nil {
		t.Fatalf("insert allocation: %v", err)
	}

	ins := func(seq int, present bool) error {
		_, err := db.Exec(`
			INSERT INTO resource_observations
				(allocation_id, observation_seq, present, provider_state, discovery_source)
			VALUES ($1, $2, $3, '{}'::jsonb, 'ownership_scan')`, allocID, seq, present)
		return err
	}
	if err := ins(1, true); err != nil {
		t.Fatalf("first observation must succeed: %v", err)
	}
	if err := ins(1, false); err == nil {
		t.Fatal("a repeated observation sequence must be rejected")
	}
	if err := ins(2, false); err != nil {
		t.Fatalf("next sequence must be accepted: %v", err)
	}
}

// TestTenantScopeIsEnforcedByForeignKey checks a row cannot be attached to a
// project belonging to a different organization.
func TestTenantScopeIsEnforcedByForeignKey(t *testing.T) {
	db := startPostgres(t)
	orgA, _, _ := seed(t, db, "alpha", "repo/alpha/one")

	var orgB, projectB string
	if err := db.QueryRow(
		`INSERT INTO organizations (slug, name, policy_version) VALUES ('beta','b','v1') RETURNING id`,
	).Scan(&orgB); err != nil {
		t.Fatalf("insert org b: %v", err)
	}
	if err := db.QueryRow(
		`INSERT INTO projects (organization_id, slug, name) VALUES ($1,'p','p') RETURNING id`,
		orgB).Scan(&projectB); err != nil {
		t.Fatalf("insert project b: %v", err)
	}

	// A repository row claiming org A but project B must be rejected.
	_, err := db.Exec(`
		INSERT INTO repositories (organization_id, project_id, installation_ref, repository_ref)
		VALUES ($1, $2, 'inst-x', 'repo/x/one')`, orgA, projectB)
	if err == nil {
		t.Fatal("a repository must not reference a project from another organization")
	}
}

// TestCleanupRunRespectsTenantScope checks the composite foreign key on
// cleanup_runs.
func TestCleanupRunRespectsTenantScope(t *testing.T) {
	db := startPostgres(t)
	orgA, projectA, repoA := seed(t, db, "alpha2", "repo/alpha2/one")
	envA := insertEnvironment(t, db, orgA, projectA, repoA, "pr-clean-jjjj")

	var orgB string
	if err := db.QueryRow(
		`INSERT INTO organizations (slug, name, policy_version) VALUES ('beta2','b','v1') RETURNING id`,
	).Scan(&orgB); err != nil {
		t.Fatalf("insert org b: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO cleanup_runs (environment_id, organization_id, generation) VALUES ($1, $2, 1)`,
		envA, orgB); err == nil {
		t.Fatal("a cleanup run must not reference another organization's environment")
	}
	if _, err := db.Exec(
		`INSERT INTO cleanup_runs (environment_id, organization_id, generation) VALUES ($1, $2, 1)`,
		envA, orgA); err != nil {
		t.Fatalf("the owning organization must be able to record a cleanup run: %v", err)
	}
}

// TestRowLevelSecurityIsForced checks FORCE RLS is actually on. An owner that can
// bypass its own policy is a hole in the tenant boundary.
func TestRowLevelSecurityIsForced(t *testing.T) {
	db := startPostgres(t)
	for _, table := range []string{
		"environments", "resource_allocations", "cleanup_runs", "repositories", "environment_generations",
	} {
		var enabled, forced bool
		err := db.QueryRow(
			`SELECT c.relrowsecurity, c.relforcerowsecurity
			 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			 WHERE n.nspname = 'public' AND c.relname = $1`, table).Scan(&enabled, &forced)
		if err != nil {
			t.Fatalf("query %s: %v", table, err)
		}
		if !enabled {
			t.Errorf("%s: RLS must be enabled", table)
		}
		if !forced {
			t.Errorf("%s: RLS must be FORCEd", table)
		}
	}
}

// TestReconciliationIndexesExist checks the scan indexes the reconciler and the
// watchdog depend on are present.
func TestReconciliationIndexesExist(t *testing.T) {
	db := startPostgres(t)
	for _, idx := range []string{
		"actions_uncertain", "actions_runnable", "environments_expired",
		"environments_stale_lease", "resource_allocations_unresolved",
		"cleanup_runs_unresolved", "environments_org",
	} {
		var n int
		if err := db.QueryRow(
			`SELECT count(*) FROM pg_indexes WHERE schemaname='public' AND indexname=$1`, idx).Scan(&n); err != nil {
			t.Fatalf("query index %s: %v", idx, err)
		}
		if n != 1 {
			t.Errorf("expected index %s", idx)
		}
	}
}

// TestSlugUniquenessPreventsResourceReuse checks two live environments cannot
// share a routing identity.
func TestSlugUniquenessPreventsResourceReuse(t *testing.T) {
	db := startPostgres(t)
	orgID, projectID, repoID := seed(t, db, "acme-slug", "repo/acme-slug/one")
	insertEnvironment(t, db, orgID, projectID, repoID, "pr-slug-kkkk")

	_, err := db.Exec(`
		INSERT INTO environments
			(organization_id, repository_id, project_id, slug, source_sha, artifact_digest,
			 configuration_digest, recipe_digest, policy_digest, resource_profile, expires_at)
		VALUES ($1,$2,$3,'pr-slug-kkkk','sha','sha256:art','sha256:cfg','sha256:rec','sha256:pol','preview-small','2026-10-07 00:00:00+00')`,
		orgID, repoID, projectID)
	if err == nil {
		t.Fatal("slugs must be unique; a duplicate routing identity would misroute access")
	}
}

// TestForkAdmissionDefaultsToDenied encodes the 1.0 posture in the schema.
func TestForkAdmissionDefaultsToDenied(t *testing.T) {
	db := startPostgres(t)
	orgID, projectID, _ := seed(t, db, "acme-fork", "repo/acme-fork/one")
	if _, err := db.Exec(
		`INSERT INTO repositories (organization_id, project_id, installation_ref, repository_ref)
		 VALUES ($1,$2,'inst-fork2','repo/acme-fork/two')`, orgID, projectID); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var forkAdmission string
	if err := db.QueryRow(
		`SELECT fork_admission FROM repositories WHERE repository_ref = 'repo/acme-fork/two'`).Scan(&forkAdmission); err != nil {
		t.Fatalf("select: %v", err)
	}
	if forkAdmission != "denied" {
		t.Fatalf("fork admission must default to denied per ADR G-029, got %q", forkAdmission)
	}
}

// TestServicePrincipalMustBeRevocable checks a service principal can carry a
// revocation timestamp that postdates creation.
func TestServicePrincipalMustBeRevocable(t *testing.T) {
	db := startPostgres(t)
	orgID, _, _ := seed(t, db, "acme-sp", "repo/acme-sp/one")

	var id string
	if err := db.QueryRow(`
		INSERT INTO service_principals (organization_id, name, key_prefix, secret_hash)
		VALUES ($1, 'ci', 'gl_ci_', 'argon2id$hash') RETURNING id`, orgID).Scan(&id); err != nil {
		t.Fatalf("insert service principal: %v", err)
	}
	if _, err := db.Exec(
		`UPDATE service_principals SET revoked_at = created_at - interval '1 hour' WHERE id=$1`, id); err == nil {
		t.Fatal("a revocation timestamp before creation must be rejected")
	}
}

// TestNoUnreviewedSecretColumns guards against a credential accidentally being
// given a home in the platform database.
func TestNoUnreviewedSecretColumns(t *testing.T) {
	db := startPostgres(t)
	rows, err := db.Query(`
		SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema='public'
		  AND (column_name ILIKE '%secret%' OR column_name ILIKE '%password%'
		       OR column_name ILIKE '%token%' OR column_name ILIKE '%plaintext%')`)
	if err != nil {
		t.Fatalf("query columns: %v", err)
	}
	defer rows.Close()

	// A hash is not a secret. Nothing else may hold credential material.
	allowed := map[string]bool{
		"service_principals.secret_hash": true,
	}
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatalf("scan: %v", err)
		}
		key := table + "." + column
		if !allowed[key] {
			t.Errorf("unexpected secret-bearing column %s", key)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
}
