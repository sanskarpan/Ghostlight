package migrations_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/internal/access"
)

// TestRolesMatchTheSchemaVocabulary is the guard against the two layers describing
// different systems.
//
// internal/access and the memberships.role CHECK constraint were written
// independently and disagreed: the Go code said owner/admin/member while the database
// said owner/billing_admin/platform_admin/developer/reviewer/auditor/support/
// reliability_engineer. Nothing failed until something tried to persist a role, and
// that failure would have arrived at an INSERT during normal operation rather than at
// review.
//
// Reading the constraint out of the live catalog is the point. Asserting against a
// hand-copied list would reproduce the same drift one layer down.
func TestRolesMatchTheSchemaVocabulary(t *testing.T) {
	db := startPostgres(t)

	var definition string
	err := db.QueryRow(`
		SELECT pg_get_constraintdef(c.oid)
		  FROM pg_constraint c
		  JOIN pg_class t ON t.oid = c.conrelid
		  JOIN pg_namespace n ON n.oid = t.relnamespace
		 WHERE n.nspname = 'public'
		   AND t.relname = 'memberships'
		   AND c.conname LIKE '%role%'
		   AND c.contype = 'c'`).Scan(&definition)
	if err != nil {
		t.Fatalf("read the memberships role constraint: %v", err)
	}

	inSchema := parseRoleList(definition)
	sort.Strings(inSchema)
	if len(inSchema) == 0 {
		t.Fatalf("no roles found in constraint: %s", definition)
	}

	inCode := []string{
		string(access.RoleOwner),
		string(access.RolePlatformAdmin),
		string(access.RoleBillingAdmin),
		string(access.RoleDeveloper),
		string(access.RoleReviewer),
		string(access.RoleAuditor),
		string(access.RoleSupport),
		string(access.RoleReliabilityEngineer),
	}
	sort.Strings(inCode)

	if strings.Join(inSchema, ",") != strings.Join(inCode, ",") {
		t.Fatalf("role vocabularies differ:\n schema: %v\n   code: %v", inSchema, inCode)
	}
}

// TestPermissionsMatchTheSchemaVocabulary does the same for repository_grants, whose
// CHECK constraint exists to keep the permission list identical to the one
// internal/access authorizes.
func TestPermissionsMatchTheSchemaVocabulary(t *testing.T) {
	db := startPostgres(t)

	var definition string
	err := db.QueryRow(`
		SELECT pg_get_constraintdef(c.oid)
		  FROM pg_constraint c
		  JOIN pg_class t ON t.oid = c.conrelid
		  JOIN pg_namespace n ON n.oid = t.relnamespace
		 WHERE n.nspname = 'public'
		   AND t.relname = 'repository_grants'
		   AND c.conname LIKE '%permission%'
		   AND c.contype = 'c'`).Scan(&definition)
	if err != nil {
		t.Fatalf("read the repository_grants permission constraint: %v", err)
	}

	inSchema := parseRoleList(definition)
	sort.Strings(inSchema)
	if len(inSchema) == 0 {
		t.Fatalf("no permissions found in constraint: %s", definition)
	}

	var inCode []string
	for _, p := range access.AllPermissions() {
		inCode = append(inCode, string(p))
	}
	sort.Strings(inCode)

	if strings.Join(inSchema, ",") != strings.Join(inCode, ",") {
		t.Fatalf("permission vocabularies differ:\n schema: %v\n   code: %v", inSchema, inCode)
	}
}

// parseRoleList extracts the quoted values from a CHECK constraint definition.
func parseRoleList(definition string) []string {
	var out []string
	rest := definition
	for {
		i := strings.Index(rest, "'")
		if i < 0 {
			return out
		}
		rest = rest[i+1:]
		j := strings.Index(rest, "'")
		if j < 0 {
			return out
		}
		out = append(out, rest[:j])
		rest = rest[j+1:]
	}
}
