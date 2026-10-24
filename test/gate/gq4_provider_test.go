package gate_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/providerinbox"
)

// This file is the GQ.4 provider-inbox gate: the seam where Stripe and WorkOS
// deliveries become subscription and identity facts. It attacks the verifier
// the way a forger would — wrong secret, tampered body, replayed timestamp,
// test event against a live inbox — and the classifier the way a provider
// would, by sending event types the platform does not consume.
//
// What this suite may claim: that an unverifiable or unknown delivery is
// refused with no detail, that a test event cannot move a live subscription,
// and that a redelivery applies once.
//
// What it may not claim: that a live sandbox integration works, that checkout,
// portal, sign-in, MFA, recovery or revocation round-trip against the real
// providers, or that any owner has signed off. Those remain the outstanding
// GQ.4 items, and this suite fails closed without them.

// gq4Now is the moment the gate's deliveries arrive.
var gq4Now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// gq4StripeSecret is the endpoint secret the gate verifies against.
const gq4StripeSecret = "whsec_gate_endpoint_secret"

func gq4Stripe(t *testing.T, secret, payload string, sent time.Time) ([]byte, string) {
	t.Helper()
	body := []byte(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.%s", sent.Unix(), body)
	return body, fmt.Sprintf("t=%d,v1=%s", sent.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

func gq4StripePayload(id, typ string, live bool, created time.Time, object string) string {
	mode := "false"
	if live {
		mode = "true"
	}
	return fmt.Sprintf(`{"id":%q,"type":%q,"livemode":%s,"created":%d,"data":{"object":%s}}`,
		id, typ, mode, created.Unix(), object)
}

func TestGQ4GateForgerGetsNoAnswer(t *testing.T) {
	payload := gq4StripePayload("evt_gate", "invoice.payment_failed", true, gq4Now.Add(-time.Minute),
		`{"customer":"cus_gate","subscription":"sub_gate"}`)
	body, header := gq4Stripe(t, gq4StripeSecret, payload, gq4Now)

	forgeries := map[string]struct {
		secret, mutate string
		body           []byte
		header         string
	}{
		"wrong secret":  {gq4StripeSecret + "x", "", body, header},
		"tampered body": {gq4StripeSecret, "", append(body, ' '), header},
		"replayed hour": {gq4StripeSecret, "", nil, ""},
		"future send":   {gq4StripeSecret, "", nil, ""},
		"stripped sig":  {gq4StripeSecret, "", body, fmt.Sprintf("t=%d", gq4Now.Unix())},
		"legacy scheme": {gq4StripeSecret, "", body, fmt.Sprintf("t=%d,v0=%s", gq4Now.Unix(), strings.Repeat("0", 64))},
		"test for live": {gq4StripeSecret, "testmode", body, header},
	}
	// Build the time-based forgeries with valid signatures over bad moments:
	// a valid signature on a replayed delivery is exactly the attack.
	staleBody, staleHeader := gq4Stripe(t, gq4StripeSecret,
		gq4StripePayload("evt_gate", "invoice.payment_failed", true, gq4Now.Add(-time.Hour), `{"customer":"cus_gate","subscription":"sub_gate"}`),
		gq4Now.Add(-time.Hour))
	forgeries["replayed hour"] = struct {
		secret, mutate string
		body           []byte
		header         string
	}{gq4StripeSecret, "", staleBody, staleHeader}
	futureBody, futureHeader := gq4Stripe(t, gq4StripeSecret, payload, gq4Now.Add(2*time.Minute))
	forgeries["future send"] = struct {
		secret, mutate string
		body           []byte
		header         string
	}{gq4StripeSecret, "", futureBody, futureHeader}

	for name, f := range forgeries {
		fbody, fheader := f.body, f.header
		if f.mutate == "testmode" {
			testPayload := gq4StripePayload("evt_gate", "invoice.payment_failed", false, gq4Now.Add(-time.Minute),
				`{"customer":"cus_gate","subscription":"sub_gate"}`)
			fbody, fheader = gq4Stripe(t, gq4StripeSecret, testPayload, gq4Now)
		}
		_, err := providerinbox.VerifyStripe(f.secret, fbody, fheader, true, gq4Now)
		if !errors.Is(err, providerinbox.ErrUnverified) {
			t.Errorf("%s: error = %v, want ErrUnverified", name, err)
		}
		if err != nil && err.Error() != providerinbox.ErrUnverified.Error() {
			t.Errorf("%s: the forger learned %q", name, err.Error())
		}
	}
}

func TestGQ4GateUnknownEventIsRefusedNotIgnored(t *testing.T) {
	created := gq4Now.Add(-time.Minute)
	for _, typ := range []string{"charge.refunded", "customer.created", "radar.early_fraud_warning_created"} {
		body, header := gq4Stripe(t, gq4StripeSecret,
			gq4StripePayload("evt_new", typ, true, created, `{"id":"ch_1","object":"charge"}`), gq4Now)
		event, err := providerinbox.VerifyStripe(gq4StripeSecret, body, header, true, gq4Now)
		if err != nil {
			t.Fatalf("%s verifies: %v", typ, err)
		}
		if _, err := providerinbox.ClassifyStripe(event); !errors.Is(err, providerinbox.ErrUnknownEvent) {
			t.Errorf("%s: error = %v, want ErrUnknownEvent", typ, err)
		}
	}
}

func TestGQ4GateRedeliveryAppliesOnce(t *testing.T) {
	inbox, err := providerinbox.NewInbox(64)
	if err != nil {
		t.Fatalf("NewInbox: %v", err)
	}
	created := gq4Now.Add(-time.Minute)
	body, header := gq4Stripe(t, gq4StripeSecret,
		gq4StripePayload("evt_once", "invoice.payment_failed", true, created, `{"customer":"cus_1","subscription":"sub_1"}`),
		gq4Now)
	applications := 0
	for i := 0; i < 3; i++ {
		event, err := providerinbox.VerifyStripe(gq4StripeSecret, body, header, true, gq4Now)
		if err != nil {
			t.Fatalf("delivery %d verifies: %v", i, err)
		}
		intent, err := providerinbox.ClassifyStripe(event)
		if err != nil {
			t.Fatalf("delivery %d classifies: %v", i, err)
		}
		seen, err := inbox.Accept(intent.EventID)
		if err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
		if !seen {
			applications++
		}
		if intent.Kind != providerinbox.BillingPaymentFailed {
			t.Fatalf("delivery %d kind = %v", i, intent.Kind)
		}
	}
	if applications != 1 {
		t.Errorf("three deliveries applied %d times, want exactly once", applications)
	}
}

func TestGQ4GateWorkOSForgeryFailsClosed(t *testing.T) {
	secret := "whsec_" + base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	id := "msg_gate"
	payload := fmt.Sprintf(`{"id":%q,"event":"user.deleted","data":{"id":"user_9","email":"revoked@example.com"}}`, id)
	ts := fmt.Sprint(gq4Now.Unix())
	mac := hmac.New(sha256.New, []byte("0123456789abcdef0123456789abcdef"))
	fmt.Fprintf(mac, "%s.%s.%s", id, ts, payload)
	sig := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))

	event, err := providerinbox.VerifyWorkOS(secret, []byte(payload), id, ts, sig, gq4Now)
	if err != nil {
		t.Fatalf("genuine delivery: %v", err)
	}
	intent, err := providerinbox.ClassifyWorkOS(event)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if intent.Kind != providerinbox.IdentityUserDeleted || intent.UserID != "user_9" {
		t.Fatalf("intent = %+v", intent)
	}

	// The same bytes with a tampered email must not verify: the signature
	// covers the payload, not just the envelope.
	tampered := fmt.Sprintf(`{"id":%q,"event":"user.deleted","data":{"id":"user_9","email":"attacker@example.com"}}`, id)
	if _, err := providerinbox.VerifyWorkOS(secret, []byte(tampered), id, ts, sig, gq4Now); !errors.Is(err, providerinbox.ErrUnverified) {
		t.Errorf("tampered payload: error = %v, want ErrUnverified", err)
	}

	// A delivery for a different user replaying this signature must not
	// verify either: the signature binds the delivery ID.
	if _, err := providerinbox.VerifyWorkOS(secret, []byte(payload), "msg_other", ts, sig, gq4Now); !errors.Is(err, providerinbox.ErrUnverified) {
		t.Errorf("rebound delivery: error = %v, want ErrUnverified", err)
	}
}
