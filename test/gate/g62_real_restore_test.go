package gate_test

// The G6.2 real-restore exercise: a genuine pg_dump and restore through real
// PostgreSQL binaries, not a simulated cut.
//
// The rest of g62_restore_test.go proves the reconciliation *logic* over the
// memory ledger. This file proves the mechanical half the row still owed: that
// the real schema can be dumped at a cut, restored into a fresh database, and
// that the restored rows are exactly the pre-cut rows — including a tombstone,
// the row whose loss would resurrect a deleted resource.
//
// Where the binaries come from: the embedded-postgres bundle ships only
// initdb/pg_ctl/postgres, with no pg_dump or psql, so the dump runs through a
// postgres:16 Docker container — real client tools on the version family ADR
// G-035 pins.
//
// What this proves: dump/restore fidelity of the ledger's durable state, and
// that a restore genuinely loses beyond-cut writes while preserving tombstones.
//
// What it does NOT prove, and this file does not claim: managed-database
// restore semantics — RDS point-in-time recovery to an arbitrary timestamp,
// snapshot latency, automated backup retention. Those need the fleet, and the
// checklist row keeps them named as remaining.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// dockerAvailable reports whether the Docker CLI can run a container.
func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// postgresContainer starts a real PostgreSQL 16 with the client tools and
// returns its host port and container name.
func postgresContainer(t *testing.T) (port int, name string) {
	t.Helper()
	name = fmt.Sprintf("g62-restore-%d", time.Now().UnixNano()%1_000_000)
	run := exec.Command("docker", "run", "-d", "--rm",
		"--name", name,
		"-e", "POSTGRES_PASSWORD=g62",
		"-e", "POSTGRES_USER=g62",
		"-e", "POSTGRES_DB=g62",
		"-p", "0:5432",
		"postgres:16")
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	pout, err := exec.Command("docker", "port", name, "5432/tcp").CombinedOutput()
	if err != nil {
		t.Fatalf("docker port: %v\n%s", err, pout)
	}
	spec := strings.TrimSpace(string(pout))
	idx := strings.LastIndex(spec, ":")
	if idx < 0 {
		t.Fatalf("cannot parse mapped port from %q", spec)
	}
	if _, err := fmt.Sscanf(spec[idx+1:], "%d", &port); err != nil {
		t.Fatalf("cannot parse port from %q: %v", spec, err)
	}

	dsn := fmt.Sprintf("host=127.0.0.1 port=%d user=g62 password=g62 dbname=g62 sslmode=disable", port)
	var lastErr error
	for i := 0; i < 40; i++ {
		db, err := sql.Open("postgres", dsn)
		if err == nil {
			if pingErr := db.PingContext(context.Background()); pingErr == nil {
				_ = db.Close()
				return port, name
			}
			lastErr = nil
			_ = db.Close()
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("postgres container never became ready: %v", lastErr)
	return 0, name
}

// execIn runs a command inside the container, which is where psql and pg_dump
// live. SQL is streamed on stdin so nothing is written to the host.
func execIn(t *testing.T, name string, stdin []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("docker", append([]string{"exec", "-i",
		"-e", "PGPASSWORD=g62", name}, args...)...)
	if stdin != nil {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %v: %v\n%s", args, err, out)
	}
	return out
}

// TestG62RealDumpRestorePreservesLedgerState is the mechanical proof: a real
// pg_dump at a cut, restored into a fresh database, carries exactly the pre-cut
// ledger state — including a tombstone.
func TestG62RealDumpRestorePreservesLedgerState(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker is not available: the real dump/restore needs pg_dump and psql, which the embedded-postgres bundle does not ship")
	}
	port, name := postgresContainer(t)

	dsn := fmt.Sprintf("host=127.0.0.1 port=%d user=g62 password=g62 dbname=g62 sslmode=disable", port)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()

	// Apply every migration in order, the way the runner does.
	files, err := filepath.Glob("../../migrations/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations: %v (%d files)", err, len(files))
	}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("apply %s: %v", filepath.Base(f), err)
		}
	}

	seed := `
INSERT INTO organizations (id, slug, name, status, policy_version)
VALUES ('11111111-1111-1111-1111-111111111111', 'org-a', 'Org A', 'active', '2026-1');

INSERT INTO projects (id, organization_id, slug, name)
VALUES ('66666666-6666-6666-6666-666666666666',
        '11111111-1111-1111-1111-111111111111', 'proj-a', 'Project A');

INSERT INTO repositories (id, organization_id, project_id, installation_ref, repository_ref)
VALUES ('77777777-7777-7777-7777-777777777777',
        '11111111-1111-1111-1111-111111111111',
        '66666666-6666-6666-6666-666666666666', 'inst-a', 'repo-a');

INSERT INTO environments
  (id, organization_id, repository_id, project_id, slug, source_sha, artifact_digest,
   configuration_digest, recipe_digest, policy_digest, resource_profile, expires_at)
VALUES ('22222222-2222-2222-2222-222222222222',
        '11111111-1111-1111-1111-111111111111',
        '77777777-7777-7777-7777-777777777777',
        '66666666-6666-6666-6666-666666666666',
        'env-42', 'sha-cut', 'artifact-a', 'config-a', 'recipe-a', 'policy-a',
        'preview-small', now() + interval '1 day');

INSERT INTO environment_generations
  (environment_id, generation, organization_id, source_sha, artifact_digest,
   configuration_digest, recipe_digest, policy_digest)
VALUES ('22222222-2222-2222-2222-222222222222', 1,
        '11111111-1111-1111-1111-111111111111', 'sha-cut', 'artifact-a',
        'config-a', 'recipe-a', 'policy-a');

INSERT INTO resource_allocations
  (id, environment_id, organization_id, generation, dependency_kind, logical_key, provider_ref)
VALUES ('33333333-3333-3333-3333-333333333333',
        '22222222-2222-2222-2222-222222222222',
        '11111111-1111-1111-1111-111111111111', 1, 'postgres', 'primary',
        '{"ref":"db-1"}'::jsonb);

INSERT INTO resource_allocations
  (id, environment_id, organization_id, generation, dependency_kind, logical_key, provider_ref, verified_deleted_at)
VALUES ('44444444-4444-4444-4444-444444444444',
        '22222222-2222-2222-2222-222222222222',
        '11111111-1111-1111-1111-111111111111', 1, 'redis', 'caches',
        '{"kv-ref":"kv-1"}'::jsonb, '2026-11-05 00:00:00+00');
`
	if _, err := db.Exec(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// A real pg_dump of the seeded state — the cut. The dump is written inside
	// the container and copied out.
	dumpPath := filepath.Join(t.TempDir(), "cut.sql")
	const dumpInContainer = "/tmp/cut.sql"
	execIn(t, name, nil, "pg_dump", "-U", "g62", "-d", "g62",
		"--no-owner", "--no-privileges", "-f", dumpInContainer)
	if out, err := exec.Command("docker", "cp", name+":"+dumpInContainer, dumpPath).CombinedOutput(); err != nil {
		t.Fatalf("docker cp: %v\n%s", err, out)
	}
	info, err := os.Stat(dumpPath)
	if err != nil || info.Size() == 0 {
		t.Fatalf("dump is empty or missing: %v", err)
	}

	// Beyond the cut: a write the restore must lose.
	if _, err := db.Exec(`
INSERT INTO resource_allocations
  (id, environment_id, organization_id, generation, dependency_kind, logical_key, provider_ref)
VALUES ('55555555-5555-5555-5555-555555555555',
        '22222222-2222-2222-2222-222222222222',
        '11111111-1111-1111-1111-111111111111', 1, 'object_store', 'beyond-cut',
        '{"ref":"beyond"}'::jsonb)`); err != nil {
		t.Fatalf("beyond-cut write: %v", err)
	}

	// Restore the dump into a FRESH database, the way a restore actually lands.
	execIn(t, name, nil, "psql", "-U", "g62", "-d", "postgres", "-c", "DROP DATABASE IF EXISTS g62_restored")
	execIn(t, name, nil, "psql", "-U", "g62", "-d", "postgres", "-c", "CREATE DATABASE g62_restored")
	dumpBody, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Fatalf("read dump: %v", err)
	}
	execIn(t, name, dumpBody, "psql", "-U", "g62", "-d", "g62_restored", "-v", "ON_ERROR_STOP=1", "-f", "-")

	restored, err := sql.Open("postgres",
		fmt.Sprintf("host=127.0.0.1 port=%d user=g62 password=g62 dbname=g62_restored sslmode=disable", port))
	if err != nil {
		t.Fatalf("connect restored: %v", err)
	}
	defer restored.Close()

	var live, tombstones, beyond int
	if err := restored.QueryRow(`SELECT
		count(*) FILTER (WHERE verified_deleted_at IS NULL),
		count(*) FILTER (WHERE verified_deleted_at IS NOT NULL),
		count(*) FILTER (WHERE logical_key = 'beyond-cut')
		FROM resource_allocations`).Scan(&live, &tombstones, &beyond); err != nil {
		t.Fatalf("restored query: %v", err)
	}
	if live != 1 {
		t.Errorf("live allocations = %d, want 1", live)
	}
	if tombstones != 1 {
		t.Errorf("tombstones = %d, want 1: a verified deletion lost in the restore resurrects a deleted resource", tombstones)
	}
	if beyond != 0 {
		t.Errorf("beyond-cut allocations = %d, want 0: the restore must return to the cut", beyond)
	}

	var ref string
	if err := restored.QueryRow(
		`SELECT provider_ref::text FROM resource_allocations WHERE logical_key = 'primary'`).Scan(&ref); err != nil {
		t.Fatalf("provider_ref read: %v", err)
	}
	if ref == "" {
		t.Error("the restored provider_ref is empty; the reconciler cannot identify the native resource")
	}
}
