// Package migrations applies the platform schema to a PostgreSQL database.
//
// The SQL lives in this same directory so there is exactly one canonical copy.
// It is embedded rather than read from disk so a compiled binary carries its
// schema, and so a migration cannot be skipped by a missing file.
//
// Migrations run in filename order, each in its own transaction. They are not
// written to be idempotent; they run once.
package migrations

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
)

//go:embed *.sql
var schemaFS embed.FS

// Apply runs every migration in filename order.
func Apply(db *sql.DB) error {
	names, err := filenames()
	if err != nil {
		return err
	}
	for _, name := range names {
		body, err := schemaFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if err := applyOne(db, name, string(body)); err != nil {
			return err
		}
	}
	return nil
}

func filenames() ([]string, error) {
	entries, err := fs.ReadDir(schemaFS, ".")
	if err != nil {
		return nil, fmt.Errorf("read schema directory: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func applyOne(db *sql.DB, name, body string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin for %s: %w", name, err)
	}
	if _, err := tx.Exec(body); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("apply %s: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s: %w", name, err)
	}
	return nil
}

// Embedded exposes the raw migration bodies, for review tooling that needs to
// assert on the schema text itself.
func Embedded() ([]string, error) {
	names, err := filenames()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		b, err := schemaFS.ReadFile(n)
		if err != nil {
			return nil, err
		}
		out = append(out, string(b))
	}
	return out, nil
}
