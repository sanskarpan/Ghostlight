package postgres_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/dodo"
	"github.com/sanskarpan/Ghostlight/internal/postgres"
)

// TestBillingStoreSurvivesReceiverRestart is the durability proof for the
// whole row: a delivery applied by one receiver instance must be a duplicate
// — not a second application — for a second instance sharing nothing but the
// database. That is exactly what a process restart looks like, and an
// in-memory duplicate memory would fail it by re-applying.
//
// The secret below is a fixed test value. The signatures are computed, not
// replayed, so a tampered byte anywhere fails verification.
var restartSecret = "whsec_" + base64.StdEncoding.EncodeToString([]byte("restart0123456789restart0123456789"))

func restartReceiver(t *testing.T, s *postgres.BillingStore) *dodo.Receiver {
	t.Helper()
	plans, err := dodo.ParseProductPlans("prod_team:team")
	if err != nil {
		t.Fatalf("ParseProductPlans: %v", err)
	}
	rc, err := dodo.NewReceiver(restartSecret, "bus_gate", plans, s)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	return rc
}

func restartDeliver(t *testing.T, rc *dodo.Receiver, eventID, typ, business, customer, sub, product string, sent time.Time) (int, map[string]any) {
	t.Helper()
	payload := fmt.Sprintf(`{"business_id":%q,"type":%q,"timestamp":%q,"data":{"subscription_id":%q,"customer_id":%q,"product_id":%q,"status":"active"}}`,
		business, typ, sent.Add(-time.Minute).Format(time.RFC3339), sub, customer, product)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(restartSecret, "whsec_"))
	if err != nil {
		t.Fatalf("bad test secret: %v", err)
	}
	ts := fmt.Sprint(sent.Unix())
	mac := hmac.New(sha256.New, raw)
	fmt.Fprintf(mac, "%s.%s.%s", eventID, ts, payload)
	sig := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	req := httptest.NewRequest(http.MethodPost, "/hooks/dodo", strings.NewReader(payload))
	req.Header.Set("webhook-id", eventID)
	req.Header.Set("webhook-timestamp", ts)
	req.Header.Set("webhook-signature", sig)
	rec := httptest.NewRecorder()
	rc.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	return rec.Code, out
}

func TestBillingStoreSurvivesReceiverRestart(t *testing.T) {
	if pgSkip != nil || pgDB == nil {
		t.Skipf("skipping restart durability test: %v", pgSkip)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store, err := postgres.NewBillingStore(pgDB)
	if err != nil {
		t.Fatalf("NewBillingStore: %v", err)
	}

	first := restartReceiver(t, store)
	code, out := restartDeliver(t, first, "evt_restart", "subscription.active", "bus_gate", "cus_restart", "sub_restart", "prod_team", now)
	if code != http.StatusOK || out["applied"] != true {
		t.Fatalf("first delivery: code=%d body=%v", code, out)
	}

	// A second receiver sharing only the database is a restarted process:
	// no shared memory, no shared maps, just the same tables.
	second := restartReceiver(t, store)
	code, out = restartDeliver(t, second, "evt_restart", "subscription.active", "bus_gate", "cus_restart", "sub_restart", "prod_team", now)
	if code != http.StatusOK || out["duplicate"] != true || out["applied"] != false {
		t.Fatalf("redelivery after restart: code=%d body=%v — want acknowledged-once, applied-once", code, out)
	}

	// And the record itself survived: a new event against the same
	// subscription applies through the fresh receiver.
	code, out = restartDeliver(t, second, "evt_restart_2", "payment.failed", "bus_gate", "cus_restart", "sub_restart", "prod_team", now)
	if code != http.StatusOK || out["applied"] != true {
		t.Fatalf("post-restart failure: code=%d body=%v", code, out)
	}
	if _, err := store.Get(context.Background(), "cus_restart", "sub_restart"); err != nil {
		t.Fatalf("stored record: %v", err)
	}
}
