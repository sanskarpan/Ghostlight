// Package pgtemp starts a real PostgreSQL in a container for tests that need
// PostgreSQL client tools.
//
// It exists because the embedded-postgres bundle ships only initdb/pg_ctl/postgres
// — no pg_dump, no psql — so any test that needs a real dump, restore or client
// session cannot use it. The container is postgres:16, the version family ADR
// G-035 pins.
//
// The package is deliberately small and test-oriented: it starts one container,
// reports its host port, and cleans up. A caller that cannot run Docker skips
// rather than fails, because a missing container runtime is an environment
// fact, not a code defect.
package pgtemp

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Available reports whether Docker can run a container.
func Available() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// Container is a running PostgreSQL container.
type Container struct {
	// Name is the container name, for exec and cp.
	Name string
	// Port is the host port mapped to 5432.
	Port int
}

// DSN is the connection string for the default database as the default user.
func (c Container) DSN() string { return c.DSNFor("g62") }

// DSNFor is the connection string for a named database as the default user.
func (c Container) DSNFor(database string) string {
	return fmt.Sprintf("host=127.0.0.1 port=%d user=g62 password=g62 dbname=%s sslmode=disable",
		c.Port, database)
}

// Start boots a PostgreSQL container and waits for it to accept connections.
// It registers cleanup on t.
func Start(t *testing.T) Container {
	t.Helper()
	// The name carries the full nanosecond clock and the PID, because two test
	// packages starting containers in parallel must not collide: a truncated
	// timestamp modulo a million collides inside the same millisecond.
	name := fmt.Sprintf("ghostlight-pg-%d-%d", os.Getpid(), time.Now().UnixNano())
	if out, err := exec.Command("docker", "run", "-d", "--rm",
		"--name", name,
		"-e", "POSTGRES_PASSWORD=g62",
		"-e", "POSTGRES_USER=g62",
		"-e", "POSTGRES_DB=g62",
		"-p", "0:5432",
		"postgres:16").CombinedOutput(); err != nil {
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
	var port int
	if _, err := fmt.Sscanf(spec[idx+1:], "%d", &port); err != nil {
		t.Fatalf("cannot parse port from %q: %v", spec, err)
	}
	c := Container{Name: name, Port: port}

	dsn := c.DSN()
	var lastErr error
	for i := 0; i < 40; i++ {
		db, err := sql.Open("postgres", dsn)
		if err == nil {
			if pingErr := db.PingContext(context.Background()); pingErr == nil {
				_ = db.Close()
				return c
			}
			_ = db.Close()
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("postgres container never became ready: %v", lastErr)
	return c
}

// Exec runs a command inside the container, streaming stdin when non-nil.
// psql and pg_dump live there, not on the host.
func (c Container) Exec(t *testing.T, stdin []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("docker", append([]string{"exec", "-i",
		"-e", "PGPASSWORD=g62", c.Name}, args...)...)
	if stdin != nil {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %v: %v\n%s", args, err, out)
	}
	return out
}
