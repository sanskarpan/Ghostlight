package migrations_test

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/sanskarpan/Ghostlight/migrations"
)

// TestMigrationsApplyAsNonSuperuser proves the deploy pre-step works with
// the least privilege a managed database grants: a LOGIN role that owns its
// database but is not a superuser. If any statement needed elevation, the
// preDeploy migration on hosted Postgres would fail exactly here, so this
// test fails the same way rather than discovering it at deploy time.
//
// The role owns its database (like a managed service account owns its
// database), which is what makes CREATE TABLE and CREATE EXTENSION IF NOT
// EXISTS reachable without superuser rights.
func TestMigrationsApplyAsNonSuperuser(t *testing.T) {
	if pgSkip != nil || shared == nil {
		t.Skipf("skipping: %v", pgSkip)
	}
	if _, err := shared.Exec(`DROP DATABASE IF EXISTS migrator_probe_db`); err != nil {
		t.Fatalf("drop test database: %v", err)
	}
	if _, err := shared.Exec(`DROP ROLE IF EXISTS migrator_probe`); err != nil {
		t.Fatalf("drop test role: %v", err)
	}
	if _, err := shared.Exec(`CREATE ROLE migrator_probe LOGIN PASSWORD 'migrator-probe-pw'`); err != nil {
		t.Fatalf("create role: %v", err)
	}
	if _, err := shared.Exec(`CREATE DATABASE migrator_probe_db OWNER migrator_probe`); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = shared.Exec(`DROP DATABASE IF EXISTS migrator_probe_db`)
		_, _ = shared.Exec(`DROP ROLE IF EXISTS migrator_probe`)
	})
	var port string
	if err := shared.QueryRow(`SELECT setting FROM pg_settings WHERE name = 'port'`).Scan(&port); err != nil {
		t.Fatalf("server port: %v", err)
	}
	db, err := sql.Open("postgres", fmt.Sprintf("host=localhost port=%s user=migrator_probe password=migrator-probe-pw dbname=migrator_probe_db sslmode=disable", port))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	applied, err := migrations.ApplyPending(db)
	if err != nil {
		t.Fatalf("ApplyPending as non-superuser owner: %v", err)
	}
	if len(applied) == 0 {
		t.Fatal("ApplyPending applied nothing on an empty database")
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM billing_delivery_ids`).Scan(&count); err != nil {
		t.Fatalf("billing tables missing after migrate: %v", err)
	}
}
