package dodo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/entitlements"
	"github.com/sanskarpan/Ghostlight/internal/providerinbox"
)

var dodoNow = time.Now().UTC().Truncate(time.Second)

// dodoSecret is a fixed test secret (base64 of 32 bytes).
var dodoSecret = "whsec_" + base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// dodoSigned builds a body and its Standard Webhook headers for sent.
func dodoSigned(secret, id, typ, business string, data string, sent time.Time) (body []byte, ts, sig string) {
	payload := fmt.Sprintf(`{"business_id":%q,"type":%q,"timestamp":%q,"data":%s}`,
		business, typ, sent.Add(-time.Minute).Format(time.RFC3339), data)
	body = []byte(payload)
	ts = fmt.Sprint(sent.Unix())
	mac := hmac.New(sha256.New, mustKey(secret))
	fmt.Fprintf(mac, "%s.%s.%s", id, ts, body)
	sig = "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return body, ts, sig
}

func mustKey(secret string) []byte {
	key, ok := decodeSecret(secret)
	if !ok {
		panic("bad test secret")
	}
	return key
}

func subData(sub, customer, product string) string {
	return fmt.Sprintf(`{"subscription_id":%q,"customer_id":%q,"product_id":%q,"status":"active"}`, sub, customer, product)
}

func TestVerifyAcceptsAGenuineDelivery(t *testing.T) {
	body, ts, sig := dodoSigned(dodoSecret, "msg_1", "subscription.active", "bus_1", subData("sub_1", "cus_1", "prod_team"), dodoNow)
	event, err := Verify(dodoSecret, body, "msg_1", ts, sig, dodoNow)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if event.ID != "msg_1" || event.Type != "subscription.active" || event.BusinessID != "bus_1" {
		t.Errorf("parsed %+v", event)
	}
	if event.Sent.IsZero() || event.At().IsZero() {
		t.Error("event carries no usable time")
	}
	if !event.At().Before(dodoNow) {
		t.Errorf("At = %v, want the payload time before now", event.At())
	}
}

// Every verification failure must be the same error, or the endpoint teaches
// a forger which check tripped.
func TestVerifyFailuresAreIndistinguishable(t *testing.T) {
	body, ts, sig := dodoSigned(dodoSecret, "msg_1", "subscription.active", "bus_1", subData("sub_1", "cus_1", "prod_team"), dodoNow)
	staleBody, staleTs, staleSig := dodoSigned(dodoSecret, "msg_1", "subscription.active", "bus_1", subData("sub_1", "cus_1", "prod_team"), dodoNow.Add(-time.Hour))
	futureBody, futureTs, futureSig := dodoSigned(dodoSecret, "msg_1", "subscription.active", "bus_1", subData("sub_1", "cus_1", "prod_team"), dodoNow.Add(2*time.Minute))
	badSig := "v1," + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("0", 32)))
	other := "whsec_" + base64.StdEncoding.EncodeToString([]byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))

	cases := map[string]struct {
		secret, id, timestamp, signature string
		body                             []byte
		now                              time.Time
	}{
		"wrong secret":    {other, "msg_1", ts, sig, body, dodoNow},
		"tampered body":   {dodoSecret, "msg_1", ts, sig, append(body, ' '), dodoNow},
		"tampered sig":    {dodoSecret, "msg_1", ts, badSig, body, dodoNow},
		"legacy scheme":   {dodoSecret, "msg_1", ts, strings.Replace(sig, "v1,", "v0,", 1), body, dodoNow},
		"missing version": {dodoSecret, "msg_1", ts, strings.TrimPrefix(sig, "v1,"), body, dodoNow},
		"stale delivery":  {dodoSecret, "msg_1", staleTs, staleSig, staleBody, dodoNow},
		"future delivery": {dodoSecret, "msg_1", futureTs, futureSig, futureBody, dodoNow},
		"missing id":      {dodoSecret, "", ts, sig, body, dodoNow},
		"bad timestamp":   {dodoSecret, "msg_1", "yesterday", sig, body, dodoNow},
		"empty secret":    {"", "msg_1", ts, sig, body, dodoNow},
		"garbage secret":  {"not-base64!!", "msg_1", ts, sig, body, dodoNow},
		"empty body":      {dodoSecret, "msg_1", ts, sig, nil, dodoNow},
		"zero now":        {dodoSecret, "msg_1", ts, sig, body, time.Time{}},
		"not json":        {dodoSecret, "msg_1", ts, mustSign(t, other, "msg_1", ts, []byte(`{`)), []byte(`{`), dodoNow},
		"missing type":    {dodoSecret, "msg_1", ts, mustSignObj(t, `{"business_id":"bus_1","data":{}}`, "msg_1", ts), []byte(`{"business_id":"bus_1","data":{}}`), dodoNow},
		"future event": {
			dodoSecret, "msg_1", ts, mustSignObj(t,
				fmt.Sprintf(`{"business_id":"bus_1","type":"subscription.active","timestamp":%q,"data":{}}`, dodoNow.Add(time.Hour).Format(time.RFC3339)),
				"msg_1", ts),
			[]byte(fmt.Sprintf(`{"business_id":"bus_1","type":"subscription.active","timestamp":%q,"data":{}}`, dodoNow.Add(time.Hour).Format(time.RFC3339))),
			dodoNow,
		},
	}
	for name, c := range cases {
		_, err := Verify(c.secret, c.body, c.id, c.timestamp, c.signature, c.now)
		if !errors.Is(err, ErrUnverified) {
			t.Errorf("%s: error = %v, want ErrUnverified", name, err)
		}
		if err != nil && err.Error() != ErrUnverified.Error() {
			t.Errorf("%s: error carries detail %q", name, err.Error())
		}
	}
}

func mustSign(t *testing.T, secret, id, ts string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, mustKey(secret))
	fmt.Fprintf(mac, "%s.%s.%s", id, ts, body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func mustSignObj(t *testing.T, payload, id, ts string) string {
	t.Helper()
	return mustSign(t, dodoSecret, id, ts, []byte(payload))
}

func TestClassifyMapsTheConsumedSet(t *testing.T) {
	created := dodoNow.Add(-time.Minute)
	cases := []struct {
		typ  string
		kind providerinbox.BillingKind
	}{
		{"payment.succeeded", providerinbox.BillingPaymentRecovered},
		{"payment.failed", providerinbox.BillingPaymentFailed},
		{"payment.processing", providerinbox.BillingSubscriptionUpdated},
		{"payment.cancelled", providerinbox.BillingSubscriptionUpdated},
		{"subscription.active", providerinbox.BillingSubscriptionStarted},
		{"subscription.renewed", providerinbox.BillingPaymentRecovered},
		{"subscription.unpaused", providerinbox.BillingPaymentRecovered},
		{"subscription.on_hold", providerinbox.BillingPaymentFailed},
		{"subscription.past_due", providerinbox.BillingPaymentFailed},
		{"subscription.updated", providerinbox.BillingSubscriptionUpdated},
		{"subscription.paused", providerinbox.BillingSubscriptionUpdated},
		{"subscription.plan_changed", providerinbox.BillingSubscriptionUpdated},
		{"subscription.update_payment_method", providerinbox.BillingSubscriptionUpdated},
		{"subscription.failed", providerinbox.BillingSubscriptionUpdated},
		{"subscription.cancelled", providerinbox.BillingSubscriptionCancelled},
		{"subscription.expired", providerinbox.BillingSubscriptionCancelled},
	}
	for _, c := range cases {
		body, ts, sig := dodoSigned(dodoSecret, "evt_1", c.typ, "bus_1", subData("sub_1", "cus_1", "prod_team"), dodoNow)
		event, err := Verify(dodoSecret, body, "evt_1", ts, sig, dodoNow)
		if err != nil {
			t.Errorf("%s: verify: %v", c.typ, err)
			continue
		}
		intent, err := Classify(event, "bus_1")
		if err != nil {
			t.Errorf("%s: classify: %v", c.typ, err)
			continue
		}
		if intent.Billing.Kind != c.kind {
			t.Errorf("%s: kind = %v, want %v", c.typ, intent.Billing.Kind, c.kind)
		}
		if intent.Billing.CustomerID != "cus_1" || intent.Billing.SubscriptionID != "sub_1" {
			t.Errorf("%s: refs = %+v", c.typ, intent.Billing)
		}
		if intent.ProductID != "prod_team" {
			t.Errorf("%s: product = %q", c.typ, intent.ProductID)
		}
		if !intent.Billing.At.Equal(created) && !intent.Billing.At.After(created.Add(-time.Second)) {
			t.Errorf("%s: At = %v, want payload time ~%v", c.typ, intent.Billing.At, created)
		}
	}
}

func TestClassifyReadsNestedCustomerShapes(t *testing.T) {
	for name, data := range map[string]string{
		"top-level":     `{"subscription_id":"sub_1","customer_id":"cus_9"}`,
		"nested object": `{"subscription_id":"sub_1","customer":{"customer_id":"cus_9","email":"a@b.c"}}`,
		"nested id":     `{"subscription_id":"sub_1","customer":{"id":"cus_9"}}`,
	} {
		body, ts, sig := dodoSigned(dodoSecret, "evt_c", "subscription.renewed", "bus_1", data, dodoNow)
		event, err := Verify(dodoSecret, body, "evt_c", ts, sig, dodoNow)
		if err != nil {
			t.Fatalf("%s: verify: %v", name, err)
		}
		intent, err := Classify(event, "bus_1")
		if err != nil {
			t.Fatalf("%s: classify: %v", name, err)
		}
		if intent.Billing.CustomerID != "cus_9" {
			t.Errorf("%s: customer = %q", name, intent.Billing.CustomerID)
		}
	}
}

func TestClassifyRefusesTheUnknownAndTheIncomplete(t *testing.T) {
	mk := func(id, typ, business, data string) Event {
		body, ts, sig := dodoSigned(dodoSecret, id, typ, business, data, dodoNow)
		event, err := Verify(dodoSecret, body, id, ts, sig, dodoNow)
		if err != nil {
			t.Fatalf("setup verify (%s): %v", typ, err)
		}
		return event
	}
	cases := map[string]struct {
		event Event
		want  error
	}{
		"unconsumed type":  {mk("e1", "refund.succeeded", "bus_1", subData("sub_1", "cus_1", "p")), ErrUnknownEvent},
		"other business":   {mk("e2", "subscription.active", "bus_2", subData("sub_1", "cus_1", "p")), ErrInvalidEvent},
		"missing sub":      {mk("e3", "payment.failed", "bus_1", `{"customer_id":"cus_1"}`), ErrInvalidEvent},
		"missing customer": {mk("e4", "payment.failed", "bus_1", `{"subscription_id":"sub_1"}`), ErrInvalidEvent},
		"missing id": {func() Event {
			e := mk("e5", "payment.failed", "bus_1", subData("sub_1", "cus_1", "p"))
			e.ID = ""
			return e
		}(), ErrInvalidEvent},
	}
	for name, c := range cases {
		if _, err := Classify(c.event, "bus_1"); !errors.Is(err, c.want) {
			t.Errorf("%s: error = %v, want %v", name, err, c.want)
		}
	}
	// An empty business expectation disables the check.
	event := mk("e6", "subscription.active", "bus_9", subData("sub_1", "cus_1", "p"))
	if _, err := Classify(event, ""); err != nil {
		t.Errorf("empty business expectation: %v", err)
	}
}

func TestParseProductPlans(t *testing.T) {
	team, err := entitlements.Lookup(entitlements.PlanTeam)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	_ = team
	got, err := ParseProductPlans("prod_a:team,prod_b:growth")
	if err != nil {
		t.Fatalf("ParseProductPlans: %v", err)
	}
	if got["prod_a"] != entitlements.PlanTeam || got["prod_b"] != entitlements.PlanGrowth {
		t.Errorf("mapping = %v", got)
	}
	if got, err := ParseProductPlans(""); err != nil || len(got) != 0 {
		t.Errorf("empty spec: %v %v", got, err)
	}
	for name, spec := range map[string]string{
		"no colon":     "prod_a",
		"empty key":    ":team",
		"empty plan":   "prod_a:",
		"unknown plan": "prod_a:platinum",
		"duplicate":    "prod_a:team,prod_a:growth",
		"blank entry":  "prod_a:team,,prod_b:growth",
	} {
		if _, err := ParseProductPlans(spec); !errors.Is(err, ErrUnknownProduct) {
			t.Errorf("%s: error = %v, want ErrUnknownProduct", name, err)
		}
	}
}

func deliver(t *testing.T, rc *Receiver, secret, id, typ, business, data string, sent time.Time) (int, map[string]any) {
	t.Helper()
	if sent.IsZero() {
		sent = time.Now().UTC()
	}
	body, ts, sig := dodoSigned(secret, id, typ, business, data, sent)
	req := httptest.NewRequest(http.MethodPost, "/hooks/dodo", strings.NewReader(string(body)))
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", ts)
	req.Header.Set("webhook-signature", sig)
	rec := httptest.NewRecorder()
	rc.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON: %v\n%s", err, rec.Body.String())
	}
	return rec.Code, out
}

func testReceiver() *Receiver {
	plans, err := ParseProductPlans("prod_team:team,prod_growth:growth")
	if err != nil {
		panic(err)
	}
	rc, err := NewReceiver(dodoSecret, "bus_1", plans, NewMemoryStore())
	if err != nil {
		panic(err)
	}
	return rc
}

func TestNewReceiverRefusesNoStore(t *testing.T) {
	if _, err := NewReceiver(dodoSecret, "bus_1", nil, nil); err == nil {
		t.Error("nil store: expected a refusal, got a receiver that cannot deduplicate")
	}
}

func TestReceiverAppliesAStartExactlyOnce(t *testing.T) {
	rc := testReceiver()
	code, out := deliver(t, rc, dodoSecret, "evt_start", "subscription.active", "bus_1", subData("sub_9", "cus_9", "prod_team"), dodoNow)
	if code != http.StatusOK || out["applied"] != true {
		t.Fatalf("start: code=%d body=%v", code, out)
	}
	stored, ok := rc.Stored("cus_9", "sub_9")
	if !ok {
		t.Fatal("record was not stored")
	}
	if stored.CustomerID != "cus_9" || string(stored.Plan.ID) != "team" {
		t.Errorf("record = %+v", stored)
	}
	// Redelivery acknowledges without applying again.
	code, out = deliver(t, rc, dodoSecret, "evt_start", "subscription.active", "bus_1", subData("sub_9", "cus_9", "prod_team"), dodoNow)
	if code != http.StatusOK || out["duplicate"] != true || out["applied"] != false {
		t.Fatalf("redelivery: code=%d body=%v", code, out)
	}
}

func TestReceiverRefusesBeforeCallingBilling(t *testing.T) {
	rc := testReceiver()
	get := httptest.NewRequest(http.MethodGet, "/hooks/dodo", nil)
	rec := httptest.NewRecorder()
	rc.ServeHTTP(rec, get)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: code=%d, want 405", rec.Code)
	}
	// Forgery: tampered body.
	body, ts, sig := dodoSigned(dodoSecret, "evt_f", "subscription.cancelled", "bus_1", subData("sub_9", "cus_9", "prod_team"), dodoNow)
	req := httptest.NewRequest(http.MethodPost, "/hooks/dodo", strings.NewReader(string(body)+" "))
	req.Header.Set("webhook-id", "evt_f")
	req.Header.Set("webhook-timestamp", ts)
	req.Header.Set("webhook-signature", sig)
	rec = httptest.NewRecorder()
	rc.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("forgery: code=%d, want 401", rec.Code)
	}
	// Stale send.
	_, oldTs, oldSig := dodoSigned(dodoSecret, "evt_o", "subscription.cancelled", "bus_1", subData("sub_9", "cus_9", "prod_team"), dodoNow.Add(-time.Hour))
	oldBody, _, _ := dodoSigned(dodoSecret, "evt_o", "subscription.cancelled", "bus_1", subData("sub_9", "cus_9", "prod_team"), dodoNow.Add(-time.Hour))
	req = httptest.NewRequest(http.MethodPost, "/hooks/dodo", strings.NewReader(string(oldBody)))
	req.Header.Set("webhook-id", "evt_o")
	req.Header.Set("webhook-timestamp", oldTs)
	req.Header.Set("webhook-signature", oldSig)
	rec = httptest.NewRecorder()
	rc.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("stale: code=%d, want 401", rec.Code)
	}
	// Unknown event type verifies but is refused, not ignored.
	code, _ := deliver(t, rc, dodoSecret, "evt_u", "dispute.opened", "bus_1", subData("sub_9", "cus_9", "prod_team"), dodoNow)
	if code != http.StatusBadRequest {
		t.Errorf("unknown type: code=%d, want 400", code)
	}
	// Other business is refused.
	code, _ = deliver(t, rc, dodoSecret, "evt_b", "subscription.active", "bus_2", subData("sub_9", "cus_9", "prod_team"), dodoNow)
	if code != http.StatusBadRequest {
		t.Errorf("other business: code=%d, want 400", code)
	}
	// Failure for an unknown subscription manufactures nothing.
	code, _ = deliver(t, rc, dodoSecret, "evt_n", "payment.failed", "bus_1", subData("sub_x", "cus_x", "prod_team"), dodoNow)
	if code != http.StatusBadRequest {
		t.Errorf("unknown subscription: code=%d, want 400", code)
	}
	if _, ok := rc.Stored("cus_x", "sub_x"); ok {
		t.Error("refused delivery created a record")
	}
	// Unmapped product start is refused.
	code, _ = deliver(t, rc, dodoSecret, "evt_p", "subscription.active", "bus_1", subData("sub_y", "cus_y", "prod_nope"), dodoNow)
	if code != http.StatusBadRequest {
		t.Errorf("unmapped product: code=%d, want 400", code)
	}
}

func TestReceiverHonestFailureAndRecovery(t *testing.T) {
	rc := testReceiver()
	code, _ := deliver(t, rc, dodoSecret, "evt_s", "subscription.active", "bus_1", subData("sub_1", "cus_1", "prod_growth"), dodoNow)
	if code != http.StatusOK {
		t.Fatalf("start: code=%d", code)
	}
	code, out := deliver(t, rc, dodoSecret, "evt_f", "subscription.on_hold", "bus_1", subData("sub_1", "cus_1", "prod_growth"), dodoNow)
	if code != http.StatusOK || out["applied"] != true {
		t.Fatalf("on_hold: code=%d body=%v", code, out)
	}
	stored, _ := rc.Stored("cus_1", "sub_1")
	if stored.PaymentFailedAt.IsZero() {
		t.Error("failure left no outstanding failure")
	}
	// Renewal after a real failure is a recovery: it clears the failure.
	code, out = deliver(t, rc, dodoSecret, "evt_r", "subscription.renewed", "bus_1", subData("sub_1", "cus_1", "prod_growth"), time.Time{})
	if code != http.StatusOK || out["applied"] != true {
		t.Fatalf("renewal after failure: code=%d body=%v", code, out)
	}
	restored, _ := rc.Stored("cus_1", "sub_1")
	if !restored.PaymentFailedAt.IsZero() {
		t.Error("renewal did not clear the outstanding failure")
	}
	// A further renewal with nothing outstanding changes nothing.
	code, out = deliver(t, rc, dodoSecret, "evt_r2", "subscription.renewed", "bus_1", subData("sub_1", "cus_1", "prod_growth"), time.Time{})
	if code != http.StatusOK || out["applied"] != false {
		t.Fatalf("routine renewal: code=%d body=%v", code, out)
	}
	quiet, _ := rc.Stored("cus_1", "sub_1")
	if !reflect.DeepEqual(restored, quiet) {
		t.Error("routine renewal moved the record")
	}
	// Real recovery clears.
	rc2 := testReceiver()
	if code, _ := deliver(t, rc2, dodoSecret, "evt_s", "subscription.active", "bus_1", subData("sub_1", "cus_1", "prod_team"), dodoNow); code != http.StatusOK {
		t.Fatalf("second start: code=%d", code)
	}
	if code, _ := deliver(t, rc2, dodoSecret, "evt_f", "payment.failed", "bus_1", subData("sub_1", "cus_1", "prod_team"), dodoNow); code != http.StatusOK {
		t.Fatalf("failed: code=%d", code)
	}
	if code, out := deliver(t, rc2, dodoSecret, "evt_r", "payment.succeeded", "bus_1", subData("sub_1", "cus_1", "prod_team"), dodoNow); code != http.StatusOK || out["applied"] != true {
		t.Fatalf("recovery: code=%d body=%v", code, out)
	}
	rec, _ := rc2.Stored("cus_1", "sub_1")
	if !rec.PaymentFailedAt.IsZero() {
		t.Error("recovery did not clear the failure")
	}
	// A conflicting start (different plan) errors and keeps the record.
	code, _ = deliver(t, rc2, dodoSecret, "evt_c", "subscription.active", "bus_1", subData("sub_1", "cus_1", "prod_growth"), dodoNow)
	if code != http.StatusBadRequest {
		t.Errorf("conflicting start: code=%d, want 400", code)
	}
	kept, _ := rc2.Stored("cus_1", "sub_1")
	if string(kept.Plan.ID) != "team" {
		t.Errorf("conflict moved the plan to %v", kept.Plan.ID)
	}
}

func TestReceiverRequiresItsSecret(t *testing.T) {
	rc, err := NewReceiver("", "bus_1", nil, NewMemoryStore())
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/hooks/dodo", strings.NewReader(`{}`))
	req.Header.Set("webhook-id", "x")
	req.Header.Set("webhook-timestamp", "1")
	req.Header.Set("webhook-signature", "v1,eA==")
	rec := httptest.NewRecorder()
	rc.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("unconfigured receiver: code=%d, want 500", rec.Code)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["status"] != "receiver-not-configured" {
		t.Errorf("body = %v", out)
	}
}

func TestReceiverErrorCarriesNoSecret(t *testing.T) {
	rc := testReceiver()
	// A forged delivery must fail without naming the secret; the error is a
	// fixed string, but assert the invariant where it matters.
	req := httptest.NewRequest(http.MethodPost, "/hooks/dodo", strings.NewReader(`{"type":"x"}`))
	req.Header.Set("webhook-id", "x")
	req.Header.Set("webhook-timestamp", "1")
	req.Header.Set("webhook-signature", "v1,eA==")
	rec := httptest.NewRecorder()
	rc.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "0123456789abcdef") {
		t.Error("refusal leaks secret material")
	}
}
