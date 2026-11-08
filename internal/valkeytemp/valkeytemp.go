// Package valkeytemp starts a real Valkey in a container for tests that need
// a live cache engine.
//
// It exists because GQ.6's isolation proofs are about what the ENGINE
// enforces, not what a plan says: an ACL rule on paper proves nothing until a
// sibling authenticated against a real server has tried to cross it. The
// container is valkey/valkey:8.1, the engine the allocator's plans target
// (the shared Valkey cache).
//
// The package carries a deliberately small RESP client rather than a
// dependency: the platform has not chosen a production Redis client yet, and
// a test harness should not make that choice for it. The client speaks the
// RESP2 subset a harness needs — arrays of bulk strings in, one reply parsed
// out — and is not a general-purpose client.
package valkeytemp

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// AdminPassword is the password the harness sets on the default user. It is
// dev-local only, like the rest of the fixture.
const AdminPassword = "gq6-valkey-admin"

// Container is a running Valkey container.
type Container struct {
	// Name is the container name.
	Name string
	// Port is the host port mapped to 6379.
	Port int
}

// Available reports whether Docker can run a container.
func Available() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// Start boots a Valkey container with a password on the default user and
// waits for it to answer PING. It registers cleanup on t.
func Start(t *testing.T) Container {
	t.Helper()
	name := fmt.Sprintf("ghostlight-valkey-%d-%d", os.Getpid(), time.Now().UnixNano())
	if out, err := exec.Command("docker", "run", "-d", "--rm",
		"--name", name,
		"-p", "0:6379",
		"valkey/valkey:8.1",
		"valkey-server", "--requirepass", AdminPassword).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	pout, err := exec.Command("docker", "port", name, "6379/tcp").CombinedOutput()
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

	// Wait for the engine to answer PING as the admin.
	for i := 0; i < 40; i++ {
		conn, err := Dial(t, c.Port, "default", AdminPassword)
		if err == nil {
			reply, err := conn.Do("PING")
			if err == nil && strings.Contains(reply, "PONG") {
				_ = conn.Close()
				return c
			}
			_ = conn.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("valkey container never became ready")
	return c
}

// Client is a minimal RESP2 connection.
type Client struct {
	conn net.Conn
	r    *bufio.Reader
}

// Dial connects and authenticates with AUTH. Both arguments are required: a
// connection without credentials is not the harness's business.
func Dial(t *testing.T, port int, username, password string) (*Client, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		return nil, err
	}
	c := &Client{conn: conn, r: bufio.NewReader(conn)}
	if password != "" {
		// A failed AUTH surfaces as the engine's own error (WRONGPASS / NOPERM).
		if username == "default" {
			_, err = c.Do("AUTH", password)
		} else {
			_, err = c.Do("AUTH", username, password)
		}
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return c, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Do sends a command as an array of bulk strings and returns the reply. An
// engine error reply (-ERR and friends) is returned as a Go error carrying
// the engine's own words, because the refusals ARE the evidence; a caller
// expecting a refusal uses DoErr instead.
func (c *Client) Do(args ...string) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := c.conn.Write([]byte(b.String())); err != nil {
		return "", err
	}
	return c.read()
}

// DoLine splits a plan statement on spaces and sends it as one command. Plan
// statements never carry quoted arguments, so a plain split is their exact
// shape — and sending a whole line as one bulk string is the mistake this
// helper exists to prevent.
func (c *Client) DoLine(stmt string) (string, error) {
	fields := strings.Fields(stmt)
	if len(fields) == 0 {
		return "", errors.New("empty statement")
	}
	return c.Do(fields...)
}

// DoErr sends a command and reports the engine's refusal. The first return
// is the engine's reply (its own words, for pinning); a non-nil error means
// the command SUCCEEDED when a refusal was expected.
func (c *Client) DoErr(args ...string) (string, error) {
	reply, err := c.Do(args...)
	if err != nil {
		return reply, nil
	}
	return reply, fmt.Errorf("expected a refusal, got %q", reply)
}

// read parses one RESP2 reply into a flat string. Arrays are flattened with
// newlines; bulk and simple strings are joined; integers render as decimal.
func (c *Client) read() (string, error) {
	line, err := c.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", errors.New("empty reply line")
	}
	switch line[0] {
	case '-':
		// The engine refused: its words are the evidence, carried as the error.
		return line, errors.New(strings.TrimPrefix(line, "-"))
	case '+', ':':
		return line, nil
	case '$':
		var n int
		if _, err := fmt.Sscanf(line[1:], "%d", &n); err != nil {
			return "", fmt.Errorf("bad bulk length %q", line)
		}
		if n == -1 {
			return "", nil // null bulk string
		}
		buf := make([]byte, n+2) // payload + trailing CRLF
		if _, err := readFull(c.r, buf); err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	case '*':
		var n int
		if _, err := fmt.Sscanf(line[1:], "%d", &n); err != nil {
			return "", fmt.Errorf("bad array length %q", line)
		}
		if n == -1 {
			return "", nil
		}
		var parts []string
		for i := 0; i < n; i++ {
			p, err := c.read()
			if err != nil {
				return "", err
			}
			parts = append(parts, p)
		}
		return strings.Join(parts, "\n"), nil
	default:
		return "", fmt.Errorf("unknown reply type %q", line)
	}
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
