package migrations_test

// The G6.3 real-upgrade exercise: an existing database, holding data, is
// migrated forward to the current schema — and the data survives.
//
// The rest of g63_upgrade_test.go proves the platform's *refusal* semantics:
// old recipe/fixture/replay/topology schemas are refused rather than coerced,
// and compatibility exists only where the catalog allowlist declares it.
// What it could not prove is the mechanical half the row still owed: that a
// real database with real rows in it can be upgraded to the current migration
// set without losing or corrupting what was there.
//
// This file proves that, against a real PostgreSQL 16 container (the version
// family ADR G-035 pins):
//
//  1. Apply the migration set as it stood at a cut point, in order.
//  2. Write rows through the old schema.
//  3. Apply the remaining migrations — the upgrade.
//  4. Assert the old rows are still there, still readable, and that the new
//     schema's constraints hold on them.
//
// What this does NOT prove, and does not claim: a rolling deployment with old
// runners serving traffic against the new platform. That needs the fleet.

import (
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/sanskarpan/Ghostlight/internal/pgtemp"
	"github.com/sanskarpan/Ghostlight/migrations"
)

// migrationFiles lists the embedded migrations in apply order.
func migrationFiles(t *testing.T) []string {
	t.Helper()
	out, err := migrations.Embedded()
	if err != nil {
		t.Fatalf("embedded migrations: %v", err)
	}
	// Embedded returns bodies in sorted-name order; re-derive names by reading
	// the directory so the test can slice by name.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("migrations dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) != len(out) {
		t.Fatalf("embedded %d migrations but found %d files", len(out), len(names))
	}
	return names
}

// TestG63RealUpgradePreservesExistingData is the mechanical upgrade exercise:
// data written at a cut point survives the migration to the current schema.
func TestG63RealUpgradePreservesExistingData(t *testing.T) {
	if !pgtemp.Available() {
		t.Skip("docker is not available: the real upgrade exercise needs a real PostgreSQL")
	}
	pg := pgtemp.Start(t)
	db, err := sql.Open("postgres", pg.DSN())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()

	names := migrationFiles(t)
	if len(names) < 3 {
		t.Fatalf("need at least 3 migrations for a cut point, found %d", len(names))
	}

	// The cut: apply everything except the last migration, the way a deployment
	// that is one release behind would sit.
	cut := names[:len(names)-1]
	for _, n := range cut {
		body, err := os.ReadFile(filepath.Join(".", n))
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("apply %s at the cut: %v", n, err)
		}
	}

	// Data written through the old schema. This is the row an upgrade must not
	// lose: a tenant with an environment, which is what every later migration's
	// foreign keys point at.
	seed := `
INSERT INTO organizations (id, slug, name, status, policy_version)
VALUES ('11111111-1111-1111-1111-111111111111', 'org-up', 'Org Upgrade', 'active', '2026-1');

INSERT INTO projects (id, organization_id, slug, name)
VALUES ('66666666-6666-6666-6666-666666666666',
        '11111111-1111-1111-1111-111111111111', 'proj-up', 'Project Upgrade');

INSERT INTO repositories (id, organization_id, project_id, installation_ref, repository_ref)
VALUES ('77777777-7777-7777-7777-777777777777',
        '11111111-1111-1111-1111-111111111111',
        '66666666-6666-6666-6666-666666666666', 'inst-up', 'repo-up');

INSERT INTO environments
  (id, organization_id, repository_id, project_id, slug, source_sha, artifact_digest,
   configuration_digest, recipe_digest, policy_digest, resource_profile, expires_at)
VALUES ('22222222-2222-2222-2222-222222222222',
        '11111111-1111-1111-1111-111111111111',
        '77777777-7777-7777-7777-777777777777',
        '66666666-6666-6666-6666-666666666666',
        'env-upgrade', 'sha-old', 'artifact-old', 'config-old', 'recipe-old', 'policy-old',
        'preview-small', now() + interval '1 day');
`
	if _, err := db.Exec(seed); err != nil {
		t.Fatalf("seed at the cut: %v", err)
	}

	// A snapshot of what the old row looked like, so the assertion is against
	// the data and not against the seed text.
	type envRow struct {
		slug, sourceSHA, recipeDigest, profile string
	}
	var before envRow
	if err := db.QueryRow(`SELECT slug, source_sha, recipe_digest, resource_profile
		FROM environments WHERE id = '22222222-2222-2222-2222-222222222222'`).
		Scan(&before.slug, &before.sourceSHA, &before.recipeDigest, &before.profile); err != nil {
		t.Fatalf("read before upgrade: %v", err)
	}

	// The upgrade: apply the remaining migration(s).
	for _, n := range names[len(cut):] {
		body, err := os.ReadFile(filepath.Join(".", n))
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("UPGRADE FAILED at %s: %v", n, err)
		}
	}

	// The old row is still there and unchanged, field for field.
	var after envRow
	if err := db.QueryRow(`SELECT slug, source_sha, recipe_digest, resource_profile
		FROM environments WHERE id = '22222222-2222-2222-2222-222222222222'`).
		Scan(&after.slug, &after.sourceSHA, &after.recipeDigest, &after.profile); err != nil {
		t.Fatalf("the upgraded schema lost the pre-existing environment: %v", err)
	}
	if after != before {
		t.Errorf("the upgrade changed the row: before=%+v after=%+v", before, after)
	}

	// The org survives with its identity intact.
	var slug, status, policyVersion string
	if err := db.QueryRow(`SELECT slug, status, policy_version FROM organizations
		WHERE id = '11111111-1111-1111-1111-111111111111'`).Scan(&slug, &status, &policyVersion); err != nil {
		t.Fatalf("the upgraded schema lost the organization: %v", err)
	}
	if slug != "org-up" || status != "active" || policyVersion != "2026-1" {
		t.Errorf("organization after upgrade = %q/%q/%q, want org-up/active/2026-1", slug, status, policyVersion)
	}

	// The new schema's constraints still hold on the old row: a violation is
	// refused rather than silently accepted.
	if _, err := db.Exec(`UPDATE environments SET observed = 'quarantined'
		WHERE id = '22222222-2222-2222-2222-222222222222'`); err == nil {
		t.Error("the upgraded schema admitted a quarantined environment with no reason: the CHECK constraint did not survive the upgrade")
	}
}
