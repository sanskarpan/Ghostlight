package migrations_test

import (
	"testing"
)

// TestBillingTablesEnforceTenantIsolationAtDDL pins the production half of
// the billing row security story. The store tests prove the application sets
// app.organization_id per transaction; this test proves the database would
// enforce it even if it did not — for the table owner as well as for other
// roles, which is exactly what FORCE ROW LEVEL SECURITY means.
//
// Why a DDL test rather than a behavioral one: the embedded test database
// connects as a superuser, and BYPASSRLS overrides every policy including
// FORCE, so any read/write test through the test pool passes regardless of
// the policy. The behavioral proof (one tenant's rows invisible to another,
// nothing visible with no tenant) lives in internal/postgres, which connects
// as a dedicated non-superuser role. This test pins the DDL that makes the
// production path — where the app connects as the table-owning,
// non-superuser Render role — enforce the same policy.
func TestBillingTablesForceRowSecurity(t *testing.T) {
	if pgSkip != nil || shared == nil {
		t.Skipf("skipping RLS DDL assertions: %v", pgSkip)
	}
	for _, table := range []string{"billing_subscriptions", "billing_delivery_ids"} {
		var enabled, forced bool
		err := shared.QueryRow(`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = $1`, table).Scan(&enabled, &forced)
		if err != nil {
			t.Fatalf("%s pg_class: %v", table, err)
		}
		if !enabled || !forced {
			t.Errorf("%s: row security enabled=%v forced=%v, want both true", table, enabled, forced)
		}
		var count int
		err = shared.QueryRow(`SELECT count(*) FROM pg_policies WHERE tablename = $1 AND roles = '{public}'`, table).Scan(&count)
		if err != nil {
			t.Fatalf("%s pg_policies: %v", table, err)
		}
		if count == 0 {
			t.Errorf("%s: no public tenant policy found", table)
		}
	}
}
