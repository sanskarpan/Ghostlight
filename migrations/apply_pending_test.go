package migrations_test

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/migrations"
)

// freshDB creates an empty database for ApplyPending tests. The shared test
// database is already migrated, so these tests need their own: ApplyPending
// on an already-migrated database is the no-op path, which needs an empty
// one to prove the first run applies everything.
func freshDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	if pgSkip != nil || shared == nil {
		t.Skipf("skipping ApplyPending tests: %v", pgSkip)
	}
	if _, err := shared.Exec(`DROP DATABASE IF EXISTS ` + name); err != nil {
		t.Fatalf("drop test database: %v", err)
	}
	if _, err := shared.Exec(`CREATE DATABASE ` + name); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	var port string
	if err := shared.QueryRow(`SELECT setting FROM pg_settings WHERE name = 'port'`).Scan(&port); err != nil {
		t.Fatalf("server port: %v", err)
	}
	db, err := sql.Open("postgres", fmt.Sprintf(
		"host=localhost port=%s user=ghostlight password=ghostlight dbname=%s sslmode=disable", port, name))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestApplyPendingAppliesOnceThenNoOps(t *testing.T) {
	db := freshDB(t, "pending_once")
	first, err := migrations.ApplyPending(db)
	if err != nil {
		t.Fatalf("first ApplyPending: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("first ApplyPending applied nothing on an empty database")
	}
	found := false
	for _, name := range first {
		if name == "0004_billing_subscriptions.sql" {
			found = true
		}
		if !strings.HasSuffix(name, ".sql") {
			t.Errorf("applied %q, want a migration file", name)
		}
	}
	if !found {
		t.Errorf("ApplyPending did not apply 0004_billing_subscriptions.sql: %v", first)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM billing_subscriptions`).Scan(&count); err != nil {
		t.Fatalf("billing table missing after migrate: %v", err)
	}
	second, err := migrations.ApplyPending(db)
	if err != nil {
		t.Fatalf("second ApplyPending: %v", err)
	}
	if len(second) != 0 {
		t.Errorf("second ApplyPending applied %v, want nothing: the pre-deploy step must be safe to re-run", second)
	}
}

func TestApplyPendingRefusesAnUntrackedDatabase(t *testing.T) {
	db := freshDB(t, "pending_untracked")
	if err := migrations.Apply(db); err != nil {
		t.Fatalf("legacy Apply: %v", err)
	}
	// The schema exists but no migration was ever recorded: ApplyPending
	// cannot tell a fresh database from a migrated one, so it must refuse
	// loudly rather than guess — guessing wrong means applying 0001 over
	// live tables.
	if _, err := migrations.ApplyPending(db); err == nil {
		t.Error("ApplyPending on an untracked migrated database: expected a refusal, got silent success")
	}
}
