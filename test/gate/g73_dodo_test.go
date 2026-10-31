package gate_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/billing"
	"github.com/sanskarpan/Ghostlight/internal/dodo"
	"github.com/sanskarpan/Ghostlight/internal/entitlements"
	"github.com/sanskarpan/Ghostlight/internal/providerinbox"
	"github.com/sanskarpan/Ghostlight/internal/subscription"
)

// This file is the G7.3 Dodo receiver gate: the seam where a verified Dodo
// delivery becomes subscription state. The inbox proves a delivery is
// genuine; this suite attacks what happens next. A forged delivery must never
// reach a record, an unknown event must stop at classification, another
// business's intent must not move our record, a redelivery must apply once,
// a routine renewal must change nothing, and a doctored plan cannot enter
// through the webhook path.
//
// What this suite may claim: that the wiring from verified intent to
// subscription record refuses confusion and applies exactly once, over the
// real receiver, the real classifier and the real lifecycle.
//
// What it may not claim: a live end-to-end delivery. The signing secret
// lives in the Dodo dashboard and the dashboard "Send example" button is a
// human step; both remain outstanding. The fake below mirrors the Standard
// Webhooks shapes the receiver was written against.

// g73dNow is the moment the gate's deliveries arrive, anchored to the real
// clock: the receiver enforces freshness bounds, so a fixed fixture date
// would rot into a permanent replay/future failure.
var g73dNow = time.Now().UTC().Truncate(time.Second)

// g73dSecret is the gate's endpoint secret. Test-only, never committed
// anywhere but this test.
var g73dSecret = "whsec_" + base64.StdEncoding.EncodeToString([]byte("gate0123456789abcdefgate0123456789"))

func g73dTeam(t *testing.T) entitlements.Plan {
	t.Helper()
	plan, err := entitlements.Lookup(entitlements.PlanTeam)
	if err != nil {
		t.Fatalf("Lookup(team): %v", err)
	}
	return plan
}

func g73dReceiver(t *testing.T) *dodo.Receiver {
	t.Helper()
	plans, err := dodo.ParseProductPlans("prod_team:team,prod_growth:growth")
	if err != nil {
		t.Fatalf("ParseProductPlans: %v", err)
	}
	rc, err := dodo.NewReceiver(g73dSecret, "bus_gate", plans, dodo.NewMemoryStore())
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	return rc
}

// g73dDeliver signs a Dodo envelope and returns it through the real
// receiver, reporting the HTTP outcome — the honest path every attack below
// deviates from at exactly one step.
func g73dDeliver(t *testing.T, rc *dodo.Receiver, secret, eventID, typ, business, data string, sent time.Time) (int, map[string]any) {
	t.Helper()
	payload := fmt.Sprintf(`{"business_id":%q,"type":%q,"timestamp":%q,"data":%s}`,
		business, typ, sent.Add(-time.Minute).Format(time.RFC3339), data)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
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

func g73dSubData(sub, customer, product string) string {
	return fmt.Sprintf(`{"subscription_id":%q,"customer_id":%q,"product_id":%q,"status":"active"}`, sub, customer, product)
}

func TestG73GateDodoHonestLoopConvertsTheTrial(t *testing.T) {
	rc := g73dReceiver(t)
	code, out := g73dDeliver(t, rc, g73dSecret, "evt_loop", "subscription.active", "bus_gate", g73dSubData("sub_1", "cus_1", "prod_team"), g73dNow)
	if code != http.StatusOK || out["applied"] != true {
		t.Fatalf("start: code=%d body=%v", code, out)
	}
	stored, ok := rc.Stored("cus_1", "sub_1")
	if !ok {
		t.Fatal("no subscription record was stored")
	}
	if stored.CustomerID != "cus_1" || string(stored.Plan.ID) != "team" || !stored.ConvertedAt.IsZero() {
		// OpenSubscription opens paid-direct: ConvertedAt stays zero until a
		// later start records the conversion. The record must name the
		// customer and the catalog plan and nothing else.
		t.Errorf("record = %+v", stored)
	}
	// Failure, then recovery, walks the lifecycle.
	if code, _ := g73dDeliver(t, rc, g73dSecret, "evt_f", "subscription.on_hold", "bus_gate", g73dSubData("sub_1", "cus_1", "prod_team"), g73dNow); code != http.StatusOK {
		t.Fatalf("on_hold: code=%d", code)
	}
	failed, _ := rc.Stored("cus_1", "sub_1")
	if failed.PaymentFailedAt.IsZero() {
		t.Fatal("on_hold left no outstanding failure")
	}
	if code, out := g73dDeliver(t, rc, g73dSecret, "evt_r", "subscription.renewed", "bus_gate", g73dSubData("sub_1", "cus_1", "prod_team"), g73dNow); code != http.StatusOK || out["applied"] != true {
		t.Fatalf("renewed: code=%d body=%v", code, out)
	}
	restored, _ := rc.Stored("cus_1", "sub_1")
	if !restored.PaymentFailedAt.IsZero() {
		t.Error("renewal did not clear the failure")
	}
}

func TestG73GateDodoForgeryNeverReachesARecord(t *testing.T) {
	rc := g73dReceiver(t)
	body := `{"business_id":"bus_gate","type":"subscription.cancelled","timestamp":"2026-11-02T11:59:00Z","data":{"subscription_id":"sub_1","customer_id":"cus_1"}}`
	mac := hmac.New(sha256.New, []byte("wrong-key-0123456789abcdef"))
	fmt.Fprintf(mac, "%s.%s.%s", "evt_forge", "1762085940", body)
	req := httptest.NewRequest(http.MethodPost, "/hooks/dodo", strings.NewReader(body))
	req.Header.Set("webhook-id", "evt_forge")
	req.Header.Set("webhook-timestamp", "1762085940")
	req.Header.Set("webhook-signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	rec := httptest.NewRecorder()
	rc.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("forgery verified: code=%d", rec.Code)
	}
	if _, ok := rc.Stored("cus_1", "sub_1"); ok {
		t.Error("forgery created a record")
	}
}

func TestG73GateDodoUnknownEventStopsAtClassification(t *testing.T) {
	rc := g73dReceiver(t)
	code, _ := g73dDeliver(t, rc, g73dSecret, "evt_new", "dispute.opened", "bus_gate", g73dSubData("sub_1", "cus_1", "prod_team"), g73dNow)
	if code != http.StatusBadRequest {
		t.Fatalf("unknown type: code=%d, want refusal not silence", code)
	}
	if _, ok := rc.Stored("cus_1", "sub_1"); ok {
		t.Error("unknown event created a record")
	}
}

func TestG73GateDodoAnotherBusinessIsRefused(t *testing.T) {
	rc := g73dReceiver(t)
	code, _ := g73dDeliver(t, rc, g73dSecret, "evt_cross", "subscription.active", "bus_other", g73dSubData("sub_1", "cus_1", "prod_team"), g73dNow)
	if code != http.StatusBadRequest {
		t.Fatalf("other business: code=%d", code)
	}
	if _, ok := rc.Stored("cus_1", "sub_1"); ok {
		t.Error("other-business intent created a record")
	}
}

func TestG73GateDodoRedeliveryAppliesOnce(t *testing.T) {
	rc := g73dReceiver(t)
	applications := 0
	for i := 0; i < 3; i++ {
		code, out := g73dDeliver(t, rc, g73dSecret, "evt_once", "subscription.active", "bus_gate", g73dSubData("sub_9", "cus_9", "prod_team"), g73dNow)
		if code != http.StatusOK {
			t.Fatalf("delivery %d: code=%d body=%v", i, code, out)
		}
		if applied, _ := out["applied"].(bool); applied {
			applications++
		}
	}
	if applications != 1 {
		t.Errorf("three deliveries applied %d times, want exactly once", applications)
	}
}

func TestG73GateDodoRenewalStormChangesNothing(t *testing.T) {
	rc := g73dReceiver(t)
	code, _ := g73dDeliver(t, rc, g73dSecret, "evt_s", "subscription.active", "bus_gate", g73dSubData("sub_1", "cus_1", "prod_team"), g73dNow)
	if code != http.StatusOK {
		t.Fatalf("start: code=%d", code)
	}
	before, _ := rc.Stored("cus_1", "sub_1")
	for i := 0; i < 12; i++ {
		code, out := g73dDeliver(t, rc, g73dSecret, fmt.Sprintf("evt_renew_%d", i), "subscription.renewed", "bus_gate", g73dSubData("sub_1", "cus_1", "prod_team"), g73dNow)
		if code != http.StatusOK || out["applied"] != false {
			t.Fatalf("renewal %d: code=%d body=%v", i, code, out)
		}
	}
	after, _ := rc.Stored("cus_1", "sub_1")
	if before.PaymentFailedAt != after.PaymentFailedAt || string(before.Plan.ID) != string(after.Plan.ID) {
		t.Error("twelve routine renewals moved the record")
	}
}

func TestG73GateDodoConflictingStartIsRefused(t *testing.T) {
	rc := g73dReceiver(t)
	code, _ := g73dDeliver(t, rc, g73dSecret, "evt_s", "subscription.active", "bus_gate", g73dSubData("sub_1", "cus_1", "prod_team"), g73dNow)
	if code != http.StatusOK {
		t.Fatalf("start: code=%d", code)
	}
	bad := g73dSubData("sub_1", "cus_1", "prod_growth")
	code, _ = g73dDeliver(t, rc, g73dSecret, "evt_conflict", "subscription.active", "bus_gate", bad, g73dNow)
	if code != http.StatusBadRequest {
		t.Fatalf("conflicting start: code=%d, want refusal", code)
	}
	kept, _ := rc.Stored("cus_1", "sub_1")
	if string(kept.Plan.ID) != "team" {
		t.Errorf("conflict moved the plan to %v", kept.Plan.ID)
	}
}

func TestG73GateDodoIntentAppliesToItsOwnRecord(t *testing.T) {
	// Cross-wiring the classifier output straight into billing.Apply proves
	// the intent shape the receiver produces is the shape billing consumes —
	// the seam the gate exists to cover.
	rc := g73dReceiver(t)
	code, _ := g73dDeliver(t, rc, g73dSecret, "evt_s", "subscription.active", "bus_gate", g73dSubData("sub_1", "cus_1", "prod_team"), g73dNow)
	if code != http.StatusOK {
		t.Fatalf("start: code=%d", code)
	}
	sub, ok := rc.Stored("cus_1", "sub_1")
	if !ok {
		t.Fatal("no record")
	}
	// A sibling subscription's intent must not move this record, even when
	// driven through billing directly.
	alien := providerinbox.BillingIntent{
		Kind: providerinbox.BillingPaymentFailed, EventID: "evt_alien",
		CustomerID: "cus_2", SubscriptionID: "sub_2", At: g73dNow,
	}
	if _, err := billing.Apply(&sub, alien, entitlements.Plan{}); !errors.Is(err, billing.ErrCustomerMismatch) {
		t.Fatalf("cross-customer intent: error = %v", err)
	}
	if !sub.PaymentFailedAt.IsZero() {
		t.Error("alien intent moved the record")
	}
	if sub.Phase(g73dNow) != subscription.PhaseActive {
		t.Errorf("record phase = %v, want active", sub.Phase(g73dNow))
	}
}
