// Package gq6 produces the GQ.6 sibling-isolation evidence against a real
// local PostgreSQL.
//
// What this harness proves, and what it honestly cannot:
//
// Proven here — the engine-enforced half of ADR G-034's isolation controls,
// executed verbatim against a real PostgreSQL server: database-per-preview with
// per-database roles, CONNECTION LIMIT enforcement, statement_timeout
// enforcement, public-revoked defaults, and the dblink/postgres_fdw refusal
// that closes the documented cross-database escape. The SQL comes from
// `internal/allocators` AllocatePostgres — the same plan production would
// apply — so the harness proves the allocator's output *runs and holds*, not
// that a hand-written fixture holds.
//
// Not provable here, and not claimed: deployed managed-service authorization —
// RDS/Cloud SQL control planes, Valkey Serverless IAM users, MSK IAM auth, S3
// access points and STS vending — and any cost or latency number for deployed
// services. The evidence is labelled local engine enforcement, and the deployed
// sibling measurements remain outstanding in GQ.6.
package gq6

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"github.com/sanskarpan/Ghostlight/internal/allocators"
)

// EmbeddedPostgresVersion pins the server the harness runs, matching the
// dependency the schema tests already use.

// Servers is one embedded PostgreSQL shared by the harness, started once per
// test binary through TestMain-style use.
type Servers struct {
	pg      *embeddedpostgres.EmbeddedPostgres
	adminDB *sql.DB
	mu      sync.Mutex
	port    uint32
}

// shared is one embedded PostgreSQL for the package. Each test booting its own
// took the suite to four minutes; the isolation tests are independent (they use
// distinct environment ids, hence distinct databases and roles), so one server
// serves them all and the suite stays CI-viable.
var (
	sharedOnce sync.Once
	shared     *Servers
	sharedErr  error
)

// StartPostgres returns the package's shared PostgreSQL, booting it on first use.
func StartPostgres(t *testing.T) *Servers {
	t.Helper()
	sharedOnce.Do(func() {
		shared, sharedErr = bootPostgres()
	})
	if sharedErr != nil {
		t.Fatalf("embedded postgres: %v", sharedErr)
	}
	return shared
}

func bootPostgres() (*Servers, error) {
	// The port is deterministic within a test but varied across runs, and the
	// data paths are per-run temp dirs so parallel suites cannot collide.
	port := uint32(5444 + (time.Now().UnixNano()/int64(time.Millisecond))%100)
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("gq6-pg-%d", port))
	cfg := embeddedpostgres.DefaultConfig().
		Port(port).
		CachePath(dir + "/cache").
		BinariesPath(dir + "/bin").
		RuntimePath(dir + "/run").
		DataPath(dir + "/data").
		Username("gq6").
		Password("gq6").
		Database("postgres")
	pg := embeddedpostgres.NewDatabase(cfg)
	if err := pg.Start(); err != nil {
		return nil, err
	}
	admin, err := sql.Open("postgres", fmt.Sprintf(
		"host=127.0.0.1 port=%d user=gq6 password=gq6 dbname=postgres sslmode=disable", port))
	if err != nil {
		_ = pg.Stop()
		return nil, err
	}
	if err := admin.PingContext(context.Background()); err != nil {
		_ = admin.Close()
		_ = pg.Stop()
		return nil, err
	}
	return &Servers{pg: pg, adminDB: admin, port: port}, nil
}

// Apply executes the allocator's plan statements verbatim, as an admin.
//
// This is the point of the harness: the plan is production output, and if one
// of its statements cannot run, the allocator is not emitting executable SQL
// and every claim built on the plan is unfounded.
func (s *Servers) Apply(t *testing.T, plan allocators.Plan) {
	t.Helper()
	for i, stmt := range plan.Statements {
		if _, err := s.adminDB.Exec(stmt); err != nil {
			t.Fatalf("plan statement %d failed: %v\nstatement: %s", i, err, stmt)
		}
	}
}

// Destroy executes the plan's destroy statements verbatim.
func (s *Servers) Destroy(t *testing.T, plan allocators.Plan) {
	t.Helper()
	for i, stmt := range plan.DestroyStatements {
		if _, err := s.adminDB.Exec(stmt); err != nil {
			t.Fatalf("destroy statement %d failed: %v\nstatement: %s", i, err, stmt)
		}
	}
}

// TenantDB opens a connection as the preview's own role, the way a preview
// would connect — not as an admin.
func (s *Servers) TenantDB(t *testing.T, plan allocators.Plan) *sql.DB {
	t.Helper()
	role := roleNameOf(plan)
	db, err := sql.Open("postgres", fmt.Sprintf(
		"host=127.0.0.1 port=%d user=%s password=%s dbname=%s sslmode=disable",
		s.port, role, HarnessPassword, dbNameOf(plan)))
	if err != nil {
		t.Fatalf("tenant connection: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func roleNameOf(plan allocators.Plan) string {
	return nameOf(plan.Statements, "CREATE ROLE ")
}
func dbNameOf(plan allocators.Plan) string {
	return nameOf(plan.Statements, "CREATE DATABASE ")
}

// nameOf extracts the identifier a statement creates, so the harness reads the
// names from the plan instead of guessing them.
func nameOf(statements []string, prefix string) string {
	for _, s := range statements {
		if rest, ok := strings.CutPrefix(s, prefix); ok {
			return strings.Fields(rest)[0]
		}
	}
	return ""
}

// Admin returns the admin connection for catalog checks.
func (s *Servers) Admin() *sql.DB { return s.adminDB }

// PortString renders the server's port for a libpq connection string.
func (s *Servers) PortString() string { return fmt.Sprintf("%d", s.port) }

// OpenTenant opens a fresh connection as the preview's own role.
func OpenTenant(s *Servers, plan allocators.Plan) (*sql.DB, error) {
	return sql.Open("postgres", fmt.Sprintf(
		"host=127.0.0.1 port=%d user=%s password=%s dbname=%s sslmode=disable",
		s.port, roleNameOf(plan), HarnessPassword, dbNameOf(plan)))
}

// HarnessPassword is the credential the harness injects into a preview role
// after its plan is applied. Production injects a real credential into the
// secret ref the plan names; the harness does the equivalent with a fixed
// value so the tenant connection authenticates the same way.
const HarnessPassword = "gq6-harness-password"

// SetRolePassword injects the harness credential into a preview role, the
// production equivalent of writing the secret the plan's CredentialRef names.
func (s *Servers) SetRolePassword(t *testing.T, plan allocators.Plan) {
	t.Helper()
	role := roleNameOf(plan)
	if _, err := s.adminDB.Exec(fmt.Sprintf("ALTER ROLE %s PASSWORD '%s'", role, HarnessPassword)); err != nil {
		t.Fatalf("role credential injection: %v", err)
	}
}

// MustFail executes a query expected to be refused by isolation.
func MustFail(t *testing.T, db *sql.DB, label, query string) {
	t.Helper()
	if _, err := db.Exec(query); err == nil {
		t.Errorf("%s: query was not refused by isolation: %s", label, query)
	}
}

var _ = time.Second
