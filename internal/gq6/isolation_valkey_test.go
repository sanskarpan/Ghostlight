package gq6

// The GQ.6 sibling-isolation proofs against a real local Valkey.
//
// The PostgreSQL leg proved database-per-preview with roles and grants; this
// leg proves the cache shape — one ACL user per preview, restricted to its
// key pattern. Every test drives the allocator's own plan statement and then
// tries to escape: across keyspaces, into administration, through the
// commands the plan grants (KEYS is a global command — the ACL must filter
// it). A refusal is the evidence; an escape is a finding.
//
// What this proves: the engine enforces the key pattern for reads, writes,
// and for the output of global commands; the plan's command set excludes
// administration; and tearing one sibling down touches only that sibling.
//
// What it does NOT claim, and does not hide: Redis/Valkey ACLs carry no
// per-user memory quota. The noisy-neighbour lever for the cache is the
// application watchdog, stated in the allocator's own comment — this leg
// proves the isolation shape, not a memory bound.

import (
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/internal/allocators"
	"github.com/sanskarpan/Ghostlight/internal/valkeytemp"
)

// valkeyApply threads the applier's own credential into the plan's ACL
// statement and executes it. It returns the credentials to authenticate with:
// the username comes from the statement itself, because the allocator
// sanitizes the environment id (a hyphen becomes an underscore) and dialling
// the raw id is a username that does not exist.
var valkeyPasswords = map[string]string{}

func valkeyApply(t *testing.T, admin *valkeytemp.Client, plan allocators.Plan) string {
	t.Helper()
	password := "acl-" + plan.EnvironmentID + "-pass"
	valkeyPasswords[plan.EnvironmentID] = password
	for _, stmt := range plan.Statements {
		if strings.HasPrefix(stmt, "ACL SETUSER") {
			// The credential is the applier's contribution: `on` gains the
			// password argument immediately after it.
			stmt = strings.Replace(stmt, " on ", " on >"+password+" ", 1)
		}
		if strings.HasPrefix(stmt, "CLIENT SETNAME") {
			continue // a client-level statement; it runs on the tenant connection
		}
		if _, err := admin.DoLine(stmt); err != nil {
			t.Fatalf("apply %q: %v", stmt, err)
		}
	}
	return password
}

// valkeyUser is the ACL username a plan created, read back from its own
// statement so the test cannot drift from the allocator's naming.
func valkeyUser(plan allocators.Plan) string {
	for _, stmt := range plan.Statements {
		if strings.HasPrefix(stmt, "ACL SETUSER") {
			return strings.Fields(stmt)[2]
		}
	}
	return ""
}

func valkeyTenants(t *testing.T) (*valkeytemp.Container, *valkeytemp.Client, *valkeytemp.Client, allocators.Plan, allocators.Plan) {
	t.Helper()
	if !valkeytemp.Available() {
		t.Skip("docker is not available: the Valkey isolation proofs need a real engine")
	}
	c := valkeytemp.Start(t)
	admin, err := valkeytemp.Dial(t, c.Port, "default", valkeytemp.AdminPassword)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	reqA := allocators.Request{EnvironmentID: "sib-aaaa", LogicalKey: "cache", Kind: allocators.KindRedis}
	reqB := allocators.Request{EnvironmentID: "sib-bbbb", LogicalKey: "cache", Kind: allocators.KindRedis}
	planA, err := allocators.Allocate(reqA)
	if err != nil {
		t.Fatalf("allocate A: %v", err)
	}
	planB, err := allocators.Allocate(reqB)
	if err != nil {
		t.Fatalf("allocate B: %v", err)
	}
	valkeyApply(t, admin, planA)
	valkeyApply(t, admin, planB)

	dial := func(plan allocators.Plan) *valkeytemp.Client {
		t.Helper()
		conn, err := valkeytemp.Dial(t, c.Port, valkeyUser(plan), valkeyPasswords[plan.EnvironmentID])
		if err != nil {
			t.Fatalf("dial %s: %v", plan.EnvironmentID, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	return &c, dial(planA), dial(planB), planA, planB
}

// A sibling works inside its own keyspace: every command the plan grants
// succeeds on the sibling's own prefix, including the narrow connection
// commands a client needs to stay connected.
func TestValkeySiblingWorksInsideItsOwnKeyspace(t *testing.T) {
	_, a, _, planA, _ := valkeyTenants(t)

	if reply, err := a.Do("PING"); err != nil || !strings.Contains(reply, "PONG") {
		t.Fatalf("PING = %q, %v", reply, err)
	}
	if reply, err := a.Do("CLIENT", "SETNAME", "probe-name"); err != nil || !strings.Contains(reply, "OK") {
		t.Fatalf("CLIENT SETNAME = %q, %v (the narrowed connection grant must keep clients working)", reply, err)
	}
	own := "preview-" + planA.EnvironmentID + ":session:1"
	if reply, err := a.Do("SET", own, "value-1"); err != nil || !strings.Contains(reply, "OK") {
		t.Fatalf("own SET = %q, %v", reply, err)
	}
	if reply, err := a.Do("GET", own); err != nil || reply != "value-1" {
		t.Fatalf("own GET = %q, %v", reply, err)
	}
	if reply, err := a.Do("INCR", "preview-"+planA.EnvironmentID+":counter"); err != nil || reply != ":1" {
		t.Fatalf("own INCR = %q, %v", reply, err)
	}
	if reply, err := a.Do("EXPIRE", own, "120"); err != nil || reply != ":1" {
		t.Fatalf("own EXPIRE = %q, %v", reply, err)
	}
}

// The headline property: a sibling cannot read or write another sibling's
// keys, and the engine's own error says why.
func TestValkeySiblingsCannotReachEachOthersKeys(t *testing.T) {
	_, a, b, planA, planB := valkeyTenants(t)

	keyA := "preview-" + planA.EnvironmentID + ":private-a"
	keyB := "preview-" + planB.EnvironmentID + ":private-b"
	if _, err := a.Do("SET", keyA, "a-secret"); err != nil {
		t.Fatalf("A's own set: %v", err)
	}
	if _, err := b.Do("SET", keyB, "b-secret"); err != nil {
		t.Fatalf("B's own set: %v", err)
	}

	for _, attempt := range []struct {
		name string
		args []string
	}{
		{"A reads B", []string{"GET", keyB}},
		{"A writes B", []string{"SET", keyB, "tampered"}},
		{"A deletes B", []string{"DEL", keyB}},
		{"A expires B", []string{"EXPIRE", keyB, "1"}},
	} {
		if _, err := a.Do(attempt.args...); err == nil {
			t.Errorf("%s: the engine allowed a sibling to cross the keyspace boundary", attempt.name)
		} else if !strings.Contains(err.Error(), "NOPERM") {
			t.Errorf("%s: refusal = %v, want NOPERM (the engine's own reason is the evidence)", attempt.name, err)
		}
	}
	// Symmetrically, B cannot read A.
	if _, err := b.Do("GET", keyA); err == nil {
		t.Error("B read A's key: the boundary is one-directional, which is no boundary")
	}
	// And A's own data is untouched by every refused write.
	if reply, err := a.Do("GET", keyA); err != nil || reply != "a-secret" {
		t.Fatalf("A's own value after refused crossings = %q, %v", reply, err)
	}
}

// KEYS and SCAN are enumeration commands, and the engine does NOT filter
// their output by the ACL key pattern: measured live on Valkey 8.1, a user
// with `+keys` and pattern ~preview-a:* received `KEYS *` output naming the
// sibling's keyspace in full. The plan therefore grants no enumeration at
// all — a preview addresses its own keys by name. This test pins the
// refusal; if a future engine starts filtering, this test still passes, and
// a plan change to re-grant KEYS would need the filter proven, not assumed.
func TestValkeyEnumerationIsRefusedNotFiltered(t *testing.T) {
	_, a, b, planA, planB := valkeyTenants(t)

	if _, err := a.Do("SET", "preview-"+planA.EnvironmentID+":mine", "1"); err != nil {
		t.Fatalf("A's own set: %v", err)
	}
	if _, err := b.Do("SET", "preview-"+planB.EnvironmentID+":theirs", "1"); err != nil {
		t.Fatalf("B's own set: %v", err)
	}

	if _, err := a.Do("KEYS", "*"); err == nil {
		t.Error("the plan's user was allowed KEYS: the engine does not filter its output by key pattern, so granting it leaks sibling key names")
	} else if !strings.Contains(err.Error(), "NOPERM") {
		t.Errorf("KEYS refusal = %v, want NOPERM", err)
	}
	if _, err := a.Do("SCAN", "0"); err == nil {
		t.Error("the plan's user was allowed SCAN: the cursor form of the same leak")
	} else if !strings.Contains(err.Error(), "NOPERM") {
		t.Errorf("SCAN refusal = %v, want NOPERM", err)
	}
}

// The plan's command set is data commands plus the narrow connection
// subcommands and nothing else: administration is not part of a preview's
// vocabulary. CONFIG, ACL and INFO are the levers that would undo the
// isolation itself, and CLIENT LIST — inside the blanket `@connection`
// category the plan no longer grants — enumerates every other tenant's
// connections.
func TestValkeySiblingCannotAdminister(t *testing.T) {
	_, a, _, _, _ := valkeyTenants(t)

	for _, attempt := range []struct {
		name string
		args []string
	}{
		{"read engine config", []string{"CONFIG", "GET", "maxmemory"}},
		{"change engine config", []string{"CONFIG", "SET", "maxmemory", "0"}},
		{"read the ACL roster", []string{"ACL", "LIST"}},
		{"rewrite own ACL", []string{"ACL", "SETUSER", "preview_sib_aaaa", "on", "~*"}},
		{"list other tenants' connections", []string{"CLIENT", "LIST"}},
		{"kill another client", []string{"CLIENT", "KILL", "ID", "1"}},
		{"engine info", []string{"INFO"}},
		{"run lua", []string{"EVAL", "return 1", "0"}},
	} {
		if _, err := a.Do(attempt.args...); err == nil {
			t.Errorf("%s: the engine allowed a sibling an administrative command", attempt.name)
		} else if !strings.Contains(err.Error(), "NOPERM") {
			t.Errorf("%s: refusal = %v, want NOPERM", attempt.name, err)
		}
	}
}

// The default user's keys — the shared foundation's own cache entries — are
// outside every sibling's pattern and must stay outside them.
func TestValkeyFoundationKeysStayOutsideEveryPattern(t *testing.T) {
	c, a, _, _, _ := valkeyTenants(t)
	admin, err := valkeytemp.Dial(t, c.Port, "default", valkeytemp.AdminPassword)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer admin.Close()

	if _, err := admin.Do("SET", "foundation:lease", "held"); err != nil {
		t.Fatalf("foundation set: %v", err)
	}
	if _, err := a.Do("GET", "foundation:lease"); err == nil {
		t.Error("a sibling read a foundation key")
	}
	if _, err := a.Do("SET", "foundation:lease", "usurped"); err == nil {
		t.Error("a sibling wrote a foundation key")
	}
	if reply, err := admin.Do("GET", "foundation:lease"); err != nil || reply != "held" {
		t.Fatalf("foundation value after refused crossings = %q, %v", reply, err)
	}
}

// Tearing one sibling down must touch only that sibling: A's keys are
// unlinked and its ACL user removed, while B's data and B's access both
// survive untouched.
func TestValkeyTeardownTouchesOnlyTheDestroyedSibling(t *testing.T) {
	c, a, b, planA, planB := valkeyTenants(t)
	admin, err := valkeytemp.Dial(t, c.Port, "default", valkeytemp.AdminPassword)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer admin.Close()

	keyA := "preview-" + planA.EnvironmentID + ":doomed"
	keyB := "preview-" + planB.EnvironmentID + ":survivor"
	if _, err := a.Do("SET", keyA, "a"); err != nil {
		t.Fatalf("A's own set: %v", err)
	}
	if _, err := b.Do("SET", keyB, "b"); err != nil {
		t.Fatalf("B's own set: %v", err)
	}

	// Destroy: the SCAN-DELETE loop is the applier's expansion of the plan's
	// pattern deletion (UNLINK takes key names; a pattern is not a key),
	// then ACL DELUSER ends the credential.
	pattern := "preview-" + planA.EnvironmentID + ":*"
	cursor := "0"
	for {
		reply, err := admin.Do("SCAN", cursor, "MATCH", pattern, "COUNT", "100")
		if err != nil {
			t.Fatalf("scan for teardown: %v", err)
		}
		lines := strings.Split(reply, "\n")
		if len(lines) < 2 {
			break
		}
		cursor = lines[0]
		for _, key := range strings.Split(lines[1], "\n") {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			if _, err := admin.Do("UNLINK", key); err != nil {
				t.Fatalf("unlink %q: %v", key, err)
			}
		}
		if cursor == "0" {
			break
		}
	}
	if _, err := admin.Do("ACL", "DELUSER", valkeyUser(planA)); err != nil {
		t.Fatalf("ACL DELUSER: %v", err)
	}

	// A's keyspace is gone and A's credential no longer authenticates.
	if reply, err := admin.Do("KEYS", "preview-"+planA.EnvironmentID+":*"); err != nil || reply != "" {
		t.Errorf("A's keys survived teardown: %q, %v", reply, err)
	}
	if _, err := valkeytemp.Dial(t, c.Port, valkeyUser(planA), valkeyPasswords[planA.EnvironmentID]); err == nil {
		t.Error("A's credential still authenticates after its ACL user was deleted")
	}
	// B's data survives and B's access still works.
	if reply, err := b.Do("GET", keyB); err != nil || reply != "b" {
		t.Fatalf("B's value after A's teardown = %q, %v", reply, err)
	}
	if _, err := b.Do("SET", "preview-"+planB.EnvironmentID+":after-teardown", "1"); err != nil {
		t.Errorf("B lost access after A's teardown: %v", err)
	}
}
