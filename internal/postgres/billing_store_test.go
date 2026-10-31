package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/billing"
	"github.com/sanskarpan/Ghostlight/internal/entitlements"
	"github.com/sanskarpan/Ghostlight/internal/postgres"
	"github.com/sanskarpan/Ghostlight/internal/subscription"
)

var billAt = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func billStore(t *testing.T) *postgres.BillingStore {
	t.Helper()
	if pgSkip != nil || pgDB == nil {
		t.Skipf("skipping billing store tests: %v", pgSkip)
	}
	s, err := postgres.NewBillingStore(pgDB)
	if err != nil {
		t.Fatalf("NewBillingStore: %v", err)
	}
	return s
}

func billPlan(t *testing.T) entitlements.Plan {
	t.Helper()
	plan, err := entitlements.Lookup(entitlements.PlanTeam)
	if err != nil {
		t.Fatalf("Lookup(team): %v", err)
	}
	return plan
}

// pgPort asks the running database which port it listens on, so the probe
// pool can connect without the test harness exporting internals.
func pgPort(t *testing.T) string {
	t.Helper()
	var port string
	if err := pgDB.QueryRow(`SELECT setting FROM pg_settings WHERE name = 'port'`).Scan(&port); err != nil {
		t.Fatalf("server port: %v", err)
	}
	return port
}

func billSub(t *testing.T, id, customer string) subscription.Subscription {
	t.Helper()
	sub, err := subscription.New(id, customer, billPlan(t), billAt, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sub
}

// lowPrivPool opens a second pool as a role WITHOUT superuser or
// BYPASSRLS. The embedded test database runs everything as a superuser,
// and BYPASSRLS bypasses every row policy including FORCE — so RLS
// assertions through the superuser pool would pass vacuously. The low-priv
// pool is what makes the invisibility tests below mean something: the same
// queries that see everything as the owner must see only one tenant here,
// and nothing at all with no tenant set. Production connects as a
// non-superuser role, where the policies in 0004 enforce for real.
func lowPrivPool(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()
	_, err := pgDB.ExecContext(ctx, `DO $$
		BEGIN
			IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'billing_rls_probe') THEN
				CREATE ROLE billing_rls_probe LOGIN PASSWORD 'billing-rls-probe-pw';
			END IF;
		END $$`)
	if err != nil {
		t.Fatalf("create probe role: %v", err)
	}
	for _, stmt := range []string{
		`GRANT USAGE ON SCHEMA public TO billing_rls_probe`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON billing_subscriptions TO billing_rls_probe`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON billing_delivery_ids TO billing_rls_probe`,
	} {
		if _, err := pgDB.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("grant: %v", err)
		}
	}
	db, err := sql.Open("postgres", fmt.Sprintf(
		"host=localhost port=%s user=billing_rls_probe password=billing-rls-probe-pw dbname=ghostlight sslmode=disable", pgPort(t)))
	if err != nil {
		t.Fatalf("open probe pool: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("probe ping: %v", err)
	}
	return db
}

func TestBillingStoreRequiresADatabase(t *testing.T) {
	if _, err := postgres.NewBillingStore(nil); err == nil {
		t.Error("nil database: expected a refusal, got a store that holds nothing")
	}
}

func TestBillingStoreRoundTripsARecord(t *testing.T) {
	s := billStore(t)
	ctx := context.Background()
	sub := billSub(t, "sub-roundtrip", "cus_acme")
	if _, err := s.Get(ctx, "cus_acme", "sub_roundtrip_typo"); !errors.Is(err, billing.ErrNotFound) {
		t.Fatalf("unknown id: error = %v, want ErrNotFound", err)
	}
	if err := s.Put(ctx, sub); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, "cus_acme", "sub-roundtrip")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != sub.ID || got.CustomerID != sub.CustomerID || got.Plan.ID != sub.Plan.ID {
		t.Errorf("record changed: %+v", got)
	}
	if !got.StartedAt.Equal(sub.StartedAt) {
		t.Errorf("StartedAt = %v, want %v", got.StartedAt, sub.StartedAt)
	}
}

func TestBillingStoreHidesAnotherCustomersRecord(t *testing.T) {
	s := billStore(t)
	ctx := context.Background()
	if err := s.Put(ctx, billSub(t, "sub_private", "cus_acme")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	probeDB := lowPrivPool(t)
	probe, err := postgres.NewBillingStore(probeDB)
	if err != nil {
		t.Fatalf("probe store: %v", err)
	}
	// Positive control: the probe role sees its own tenant's record, so a
	// refusal below cannot be mistaken for a broken connection.
	if _, err := probe.Get(ctx, "cus_acme", "sub_private"); err != nil {
		t.Fatalf("own tenant through probe role: %v", err)
	}
	// Same subscription id, wrong customer: the row policy makes it absent
	// rather than forbidden-with-a-reason, because a reason would confirm
	// that it exists.
	if _, err := probe.Get(ctx, "cus_beta", "sub_private"); !errors.Is(err, billing.ErrNotFound) {
		t.Fatalf("cross-customer read: error = %v, want ErrNotFound", err)
	}
	// A query with no tenant at all sees nothing, which is what makes a
	// forgotten set_config harmless rather than a leak.
	var n int
	if err := probeDB.QueryRow(`SELECT count(*) FROM billing_subscriptions WHERE provider_subscription_id = 'sub_private'`).Scan(&n); err != nil {
		t.Fatalf("raw count: %v", err)
	}
	if n != 0 {
		t.Errorf("tenantless query sees %d rows, want 0", n)
	}
}

func TestBillingStoreRefusesAnEmptyCustomer(t *testing.T) {
	s := billStore(t)
	ctx := context.Background()
	sub := billSub(t, "sub_nocx", "cus_acme")
	sub.CustomerID = ""
	if err := s.Put(ctx, sub); err == nil {
		t.Error("Put without customer: expected a refusal")
	}
	if _, err := s.Get(ctx, "", "sub_nocx"); err == nil {
		t.Error("Get without customer: expected a refusal")
	}
	if _, err := s.Seen(ctx, "", "evt_1"); err == nil {
		t.Error("Seen without customer: expected a refusal")
	}
	if _, err := s.Mark(ctx, "", "evt_1", "sub_nocx"); err == nil {
		t.Error("Mark without customer: expected a refusal")
	}
}

func TestBillingStorePutOverwrites(t *testing.T) {
	s := billStore(t)
	ctx := context.Background()
	sub := billSub(t, "sub_overwrite", "cus_acme")
	if err := s.Put(ctx, sub); err != nil {
		t.Fatalf("Put: %v", err)
	}
	failed := sub
	if _, err := failed.RecordPaymentFailure(billAt.Add(time.Hour), 0); err != nil {
		t.Fatalf("RecordPaymentFailure: %v", err)
	}
	if err := s.Put(ctx, failed); err != nil {
		t.Fatalf("Put again: %v", err)
	}
	got, err := s.Get(ctx, "cus_acme", "sub_overwrite")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PaymentFailedAt.IsZero() {
		t.Error("overwrite did not persist the failure")
	}
}

func TestBillingStoreDedupesConcurrentMarks(t *testing.T) {
	s := billStore(t)
	ctx := context.Background()
	const racers = 16
	var mu sync.Mutex
	trueCount := 0
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recorded, err := s.Mark(ctx, "cus_acme", "evt_race", "sub_race")
			if err != nil {
				t.Errorf("Mark: %v", err)
				return
			}
			mu.Lock()
			if recorded {
				trueCount++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if trueCount != 1 {
		t.Errorf("%d racers reported first, want exactly one", trueCount)
	}
	seen, err := s.Seen(ctx, "cus_acme", "evt_race")
	if err != nil || !seen {
		t.Errorf("Seen after mark: seen=%v err=%v", seen, err)
	}
	seen, err = s.Seen(ctx, "cus_acme", "evt_missing")
	if err != nil || seen {
		t.Errorf("Seen unknown: seen=%v err=%v", seen, err)
	}
}

func TestBillingStoreRefusesACorruptRecord(t *testing.T) {
	s := billStore(t)
	ctx := context.Background()
	plant := func(query string) {
		t.Helper()
		tx, err := pgDB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.organization_id', 'cus_acme', true)`); err != nil {
			t.Fatalf("set tenant: %v", err)
		}
		if _, err := tx.ExecContext(ctx, query); err != nil {
			t.Fatalf("plant: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	plant(`INSERT INTO billing_subscriptions (provider_subscription_id, customer_id, plan_id, record) VALUES ('sub_corrupt','cus_acme','team','{"no":"identity"}')`)
	if _, err := s.Get(ctx, "cus_acme", "sub_corrupt"); err == nil {
		t.Error("corrupt record: expected a refusal, got a subscription that names nothing")
	}
	plant(`DELETE FROM billing_subscriptions WHERE provider_subscription_id = 'sub_corrupt'`)
}
