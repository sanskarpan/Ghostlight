package allocators_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/internal/allocators"
)

func request(kind allocators.Kind) allocators.Request {
	return allocators.Request{
		EnvironmentID: "env-1", Kind: kind, LogicalKey: "primary",
		Bounds: allocators.DefaultBounds(),
	}
}

// TestPostgresPlanIsScopedAndBounded.
func TestPostgresPlanIsScopedAndBounded(t *testing.T) {
	p, err := allocators.Allocate(request(allocators.KindPostgres))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	joined := strings.Join(p.Statements, "\n")
	for _, want := range []string{
		"CREATE DATABASE preview_env_1", "CREATE ROLE preview_env_1",
		"CONNECTION LIMIT 10", "statement_timeout = 30000",
		"REVOKE ALL ON DATABASE", "FROM PUBLIC",
		"REVOKE ALL ON EXTENSION dblink", "REVOKE ALL ON EXTENSION postgres_fdw",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("the plan must %q, got:\n%s", want, joined)
		}
	}
	// Destroy undoes in dependency-safe order: revoke access before dropping data.
	if len(p.DestroyStatements) != 3 {
		t.Fatalf("destroy must revoke, drop, and drop role, got %v", p.DestroyStatements)
	}
	if !strings.HasPrefix(p.DestroyStatements[0], "REVOKE CONNECT") {
		t.Fatalf("destruction must revoke access first, got %v", p.DestroyStatements)
	}
	if strings.Contains(joined+p.CredentialRef, "password") {
		t.Fatal("a plan must never carry a credential value")
	}
	if !strings.HasPrefix(p.CredentialRef, "secret://") {
		t.Fatalf("credentials travel by reference, got %q", p.CredentialRef)
	}
}

// TestPostgresRefusesBadBounds.
func TestPostgresRefusesBadBounds(t *testing.T) {
	r := request(allocators.KindPostgres)
	r.Bounds.MaxConnections = 0
	if _, err := allocators.Allocate(r); !errors.Is(err, allocators.ErrBeyondBounds) {
		t.Fatalf("zero connections must be refused, got %v", err)
	}
	r = request(allocators.KindPostgres)
	r.EnvironmentID = ""
	if _, err := allocators.Allocate(r); !errors.Is(err, allocators.ErrMissingIdentity) {
		t.Fatalf("an anonymous allocation must be refused, got %v", err)
	}
}

// TestInjectionPrimitivesBecomeUnderscores: names are identifiers, and an identifier
// carrying quotes or semicolons is injection, not a name.
func TestInjectionPrimitivesBecomeUnderscores(t *testing.T) {
	r := request(allocators.KindPostgres)
	r.EnvironmentID = "env-1'; DROP DATABASE x; --"
	p, err := allocators.Allocate(r)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	joined := strings.Join(p.Statements, "\n")
	for _, bad := range []string{"'", ";", "--"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("the plan must not contain %q:\n%s", bad, joined)
		}
	}
}

// TestRedisACLIsScopedToItsPrefix.
func TestRedisACLIsScopedToItsPrefix(t *testing.T) {
	p, err := allocators.Allocate(request(allocators.KindRedis))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	joined := strings.Join(p.Statements, "\n")
	if !strings.Contains(joined, "~preview-env-1:*") {
		t.Fatalf("the ACL must scope keys to the environment prefix, got:\n%s", joined)
	}
	if !strings.Contains(joined, "-@all") {
		t.Fatalf("the ACL must deny by default, got:\n%s", joined)
	}
	if strings.Contains(joined, "FLUSHALL") || strings.Contains(joined, "+@all") {
		t.Fatalf("the ACL must not grant administrative commands, got:\n%s", joined)
	}
}

// TestKafkaPlanCarriesQuotas: client quotas are the only noisy-neighbor lever.
func TestKafkaPlanCarriesQuotas(t *testing.T) {
	p, err := allocators.Allocate(request(allocators.KindKafka))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	joined := strings.Join(p.Statements, "\n")
	for _, want := range []string{"preview.env_1.", "producer_byte_rate=1048576", "retention.ms=86400000"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("the plan must %q, got:\n%s", want, joined)
		}
	}
	r := request(allocators.KindKafka)
	r.Bounds.MaxProduceBytesPerSec = 0
	if _, err := allocators.Allocate(r); !errors.Is(err, allocators.ErrBeyondBounds) {
		t.Fatalf("a zero quota must be refused, got %v", err)
	}
}

// TestObjectStoreDeniesOutsideItsPrefix: an explicit deny backstop so IAM drift cannot
// punch through.
func TestObjectStoreDeniesOutsideItsPrefix(t *testing.T) {
	p, err := allocators.Allocate(request(allocators.KindObjectStore))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	joined := strings.Join(p.Statements, "\n")
	if !strings.Contains(joined, "previews/env-1/") {
		t.Fatalf("the plan must scope to the environment prefix, got:\n%s", joined)
	}
	if !strings.Contains(joined, "DENY") {
		t.Fatalf("the plan must carry an explicit deny backstop, got:\n%s", joined)
	}
}

// TestOIDCTrustRequiresTheEnvironmentTag.
func TestOIDCTrustRequiresTheEnvironmentTag(t *testing.T) {
	p, err := allocators.Allocate(request(allocators.KindOIDC))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	joined := strings.Join(p.Statements, "\n")
	if !strings.Contains(joined, "tag:environment:env-1") {
		t.Fatalf("trust must condition on the environment tag, got:\n%s", joined)
	}
}

// TestUnknownKindIsRefused.
func TestUnknownKindIsRefused(t *testing.T) {
	r := request("quantum_queue")
	if _, err := allocators.Allocate(r); !errors.Is(err, allocators.ErrUnknownKind) {
		t.Fatalf("an unknown kind must be refused, got %v", err)
	}
}

// TestScopedCatchesFoundationReach: the backstop for hand-built plans.
func TestScopedCatchesFoundationReach(t *testing.T) {
	p, err := allocators.Allocate(request(allocators.KindPostgres))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if err := allocators.Scoped(p, []string{"vpc-0123abc", "ghostlight-foundation"}); err != nil {
		t.Fatalf("a scoped plan must pass, got %v", err)
	}

	evil := p
	evil.Statements = append(append([]string{}, p.Statements...), "DROP DATABASE ghostlight-foundation vpc-0123abc")
	if err := allocators.Scoped(evil, []string{"vpc-0123abc", "ghostlight-foundation"}); !errors.Is(err, allocators.ErrOutOfScope) {
		t.Fatalf("a plan reaching foundation markers must be refused, got %v", err)
	}

	traversal := p
	traversal.Statements = []string{"READ ../../other-env/secret"}
	if err := allocators.Scoped(traversal, nil); !errors.Is(err, allocators.ErrOutOfScope) {
		t.Fatalf("a traversing plan must be refused, got %v", err)
	}

	global := p
	global.Statements = []string{"FLUSHALL"}
	if err := allocators.Scoped(global, nil); !errors.Is(err, allocators.ErrOutOfScope) {
		t.Fatalf("a plan naming nothing of its environment must be refused, got %v", err)
	}
}

// TestPlansAreDeterministic: two builds of the same request produce the same plan, so
// plans are reviewable and diffable.
func TestPlansAreDeterministic(t *testing.T) {
	for _, kind := range allocators.Kinds() {
		first, err := allocators.Allocate(request(kind))
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		for i := 0; i < 3; i++ {
			again, err := allocators.Allocate(request(kind))
			if err != nil {
				t.Fatalf("%s: %v", kind, err)
			}
			if len(first.Statements) != len(again.Statements) {
				t.Fatalf("%s plans differ in length", kind)
			}
			for j := range first.Statements {
				if first.Statements[j] != again.Statements[j] {
					t.Fatalf("%s plans differ at %d", kind, j)
				}
			}
		}
	}
}

// TestKindsAreStable.
func TestKindsAreStable(t *testing.T) {
	kinds := allocators.Kinds()
	if len(kinds) != 5 {
		t.Fatalf("five kinds must be carried, got %v", kinds)
	}
	for _, k := range []allocators.Kind{
		allocators.KindPostgres, allocators.KindRedis, allocators.KindKafka,
		allocators.KindObjectStore, allocators.KindOIDC,
	} {
		found := false
		for _, got := range kinds {
			if got == k {
				found = true
			}
		}
		if !found {
			t.Fatalf("kind %s is missing", k)
		}
	}
}

// TestDestroyStatementsExistForEveryPlan: an allocation without a teardown path is a
// leak with a creation timestamp.
func TestDestroyStatementsExistForEveryPlan(t *testing.T) {
	for _, kind := range allocators.Kinds() {
		p, err := allocators.Allocate(request(kind))
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if len(p.DestroyStatements) == 0 {
			t.Fatalf("%s has no teardown path", kind)
		}
	}
}
