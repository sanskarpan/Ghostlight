package providerinbox

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

const stripeSecret = "whsec_test_endpoint_secret"

// stripeSigned builds a body and its Stripe-Signature header for sent.
func stripeSigned(secret, payload string, sent time.Time) (body []byte, header string) {
	body = []byte(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.%s", sent.Unix(), body)
	header = fmt.Sprintf("t=%d,v1=%s", sent.Unix(), hex.EncodeToString(mac.Sum(nil)))
	return body, header
}

func stripePayload(id, typ string, live bool, created time.Time, object string) string {
	mode := "false"
	if live {
		mode = "true"
	}
	return fmt.Sprintf(`{"id":%q,"type":%q,"livemode":%s,"created":%d,"data":{"object":%s}}`,
		id, typ, mode, created.Unix(), object)
}

func TestVerifyStripeAcceptsAGenuineLiveDelivery(t *testing.T) {
	created := testNow.Add(-time.Minute)
	body, header := stripeSigned(stripeSecret,
		stripePayload("evt_1", "invoice.payment_failed", true, created, `{"customer":"cus_1","subscription":"sub_1"}`),
		testNow)
	event, err := VerifyStripe(stripeSecret, body, header, true, testNow)
	if err != nil {
		t.Fatalf("VerifyStripe: %v", err)
	}
	if event.ID != "evt_1" || event.Type != "invoice.payment_failed" || !event.Live {
		t.Errorf("parsed %+v", event)
	}
	if !event.Created.Equal(created) {
		t.Errorf("Created = %v, want %v", event.Created, created)
	}
	if event.Created.Location() != time.UTC {
		t.Errorf("Created is not UTC: %v", event.Created.Location())
	}
}

// Every verification failure must be the same error, or the endpoint teaches a
// forger which check tripped.
func TestVerifyStripeFailuresAreIndistinguishable(t *testing.T) {
	validBody, validHeader := stripeSigned(stripeSecret,
		stripePayload("evt_x", "invoice.payment_failed", true, testNow.Add(-time.Minute), `{"customer":"cus_1","subscription":"sub_1"}`),
		testNow)
	staleBody, staleHeader := stripeSigned(stripeSecret,
		stripePayload("evt_x", "invoice.payment_failed", true, testNow.Add(-time.Hour), `{"customer":"cus_1","subscription":"sub_1"}`),
		testNow.Add(-time.Hour))
	futureBody, futureHeader := stripeSigned(stripeSecret,
		stripePayload("evt_x", "invoice.payment_failed", true, testNow, `{"customer":"cus_1","subscription":"sub_1"}`),
		testNow.Add(2*time.Minute))
	badSigHeader := "t=" + fmt.Sprint(testNow.Unix()) + ",v1=" + strings.Repeat("0", 64)

	cases := map[string]struct {
		secret string
		body   []byte
		header string
		live   bool
		now    time.Time
	}{
		"wrong secret":       {stripeSecret + "x", validBody, validHeader, true, testNow},
		"tampered body":      {stripeSecret, append(validBody, ' '), validHeader, true, testNow},
		"tampered signature": {stripeSecret, validBody, badSigHeader, true, testNow},
		"legacy v0 only":     {stripeSecret, validBody, fmt.Sprintf("t=%d,v0=%s", testNow.Unix(), strings.Repeat("0", 64)), true, testNow},
		"missing signature":  {stripeSecret, validBody, fmt.Sprintf("t=%d", testNow.Unix()), true, testNow},
		"missing timestamp":  {stripeSecret, validBody, "v1=" + strings.Repeat("0", 64), true, testNow},
		"garbage header":     {stripeSecret, validBody, "not-a-signature", true, testNow},
		"stale delivery":     {stripeSecret, staleBody, staleHeader, true, testNow},
		"future delivery":    {stripeSecret, futureBody, futureHeader, true, testNow},
		"test mode to live":  {stripeSecret, validBody, validHeader, false, testNow},
		"empty secret":       {"", validBody, validHeader, true, testNow},
		"empty body":         {stripeSecret, nil, validHeader, true, testNow},
		"zero now":           {stripeSecret, validBody, validHeader, true, time.Time{}},
	}
	// A test-mode envelope presented to a live inbox must fail closed: a
	// sandbox click must never move a real subscription.
	testBody, testHeader := stripeSigned(stripeSecret,
		stripePayload("evt_x", "invoice.payment_failed", false, testNow.Add(-time.Minute), `{"customer":"cus_1","subscription":"sub_1"}`),
		testNow)
	cases["live inbox gets test event"] = struct {
		secret string
		body   []byte
		header string
		live   bool
		now    time.Time
	}{stripeSecret, testBody, testHeader, true, testNow}

	for name, c := range cases {
		_, err := VerifyStripe(c.secret, c.body, c.header, c.live, c.now)
		if !errors.Is(err, ErrUnverified) {
			t.Errorf("%s: error = %v, want ErrUnverified", name, err)
		}
		if err != nil && err.Error() != ErrUnverified.Error() {
			t.Errorf("%s: error carries detail %q", name, err.Error())
		}
	}
}

func TestVerifyStripeAcceptsARolloverSignature(t *testing.T) {
	body, header := stripeSigned(stripeSecret,
		stripePayload("evt_r", "invoice.payment_succeeded", true, testNow.Add(-time.Minute), `{"customer":"cus_1","subscription":"sub_1"}`),
		testNow)
	rolled := header + ",v1=" + strings.Repeat("0", 64)
	if _, err := VerifyStripe(stripeSecret, body, rolled, true, testNow); err != nil {
		t.Errorf("rollover header: %v", err)
	}
}

func TestVerifyStripeRefusesAMalformedEnvelope(t *testing.T) {
	for name, payload := range map[string]string{
		"not json":      `{"id":`,
		"missing id":    stripePayload("", "invoice.payment_failed", true, testNow.Add(-time.Minute), `{"customer":"cus_1","subscription":"sub_1"}`),
		"missing type":  stripePayload("evt_1", "", true, testNow.Add(-time.Minute), `{"customer":"cus_1","subscription":"sub_1"}`),
		"missing data":  `{"id":"evt_1","type":"invoice.payment_failed","livemode":true,"created":1}`,
		"future event":  stripePayload("evt_1", "invoice.payment_failed", true, testNow.Add(time.Hour), `{"customer":"cus_1","subscription":"sub_1"}`),
		"ancient event": stripePayload("evt_1", "invoice.payment_failed", true, testNow.Add(-73*time.Hour), `{"customer":"cus_1","subscription":"sub_1"}`),
	} {
		body, header := stripeSigned(stripeSecret, payload, testNow)
		if _, err := VerifyStripe(stripeSecret, body, header, true, testNow); !errors.Is(err, ErrUnverified) {
			t.Errorf("%s: error = %v, want ErrUnverified", name, err)
		}
	}
}

func TestClassifyStripeMapsTheConsumedSet(t *testing.T) {
	created := testNow.Add(-time.Minute)
	cases := []struct {
		typ           string
		object        string
		kind          BillingKind
		customer, sub string
		trialEnd      bool
	}{
		{"invoice.payment_failed", `{"customer":"cus_1","subscription":"sub_1"}`, BillingPaymentFailed, "cus_1", "sub_1", false},
		{"invoice.payment_succeeded", `{"customer":"cus_1","subscription":"sub_1"}`, BillingPaymentRecovered, "cus_1", "sub_1", false},
		{"customer.subscription.created", `{"id":"sub_1","object":"subscription","customer":"cus_1","trial_end":1730000000}`, BillingSubscriptionStarted, "cus_1", "sub_1", true},
		{"customer.subscription.updated", `{"id":"sub_1","object":"subscription","customer":"cus_1"}`, BillingSubscriptionUpdated, "cus_1", "sub_1", false},
		{"customer.subscription.deleted", `{"id":"sub_1","object":"subscription","customer":"cus_1"}`, BillingSubscriptionCancelled, "cus_1", "sub_1", false},
		{"customer.subscription.trial_will_end", `{"id":"sub_1","object":"subscription","customer":"cus_1"}`, BillingTrialEnding, "cus_1", "sub_1", false},
		{"checkout.session.completed", `{"id":"cs_1","object":"checkout.session","customer":"cus_1","subscription":"sub_1"}`, BillingSubscriptionStarted, "cus_1", "sub_1", false},
	}
	for _, c := range cases {
		event := StripeEvent{ID: "evt_1", Type: c.typ, Live: true, Created: created, Object: json.RawMessage(c.object)}
		intent, err := ClassifyStripe(event)
		if err != nil {
			t.Errorf("%s: %v", c.typ, err)
			continue
		}
		if intent.Kind != c.kind || intent.CustomerID != c.customer || intent.SubscriptionID != c.sub {
			t.Errorf("%s: %+v", c.typ, intent)
		}
		if !intent.At.Equal(created) {
			t.Errorf("%s: At = %v, want event time %v", c.typ, intent.At, created)
		}
		if c.trialEnd && intent.TrialEndsAt.IsZero() {
			t.Errorf("%s: TrialEndsAt not carried", c.typ)
		}
	}
}

func TestClassifyStripeRefusesTheUnknownAndTheIncomplete(t *testing.T) {
	created := testNow.Add(-time.Minute)
	for name, event := range map[string]StripeEvent{
		"unconsumed type":     {ID: "evt_1", Type: "charge.refunded", Created: created, Object: json.RawMessage(`{}`)},
		"empty type":          {ID: "evt_1", Type: "", Created: created, Object: json.RawMessage(`{}`)},
		"invoice without sub": {ID: "evt_1", Type: "invoice.payment_failed", Created: created, Object: json.RawMessage(`{"customer":"cus_1"}`)},
		"invoice without cx":  {ID: "evt_1", Type: "invoice.payment_failed", Created: created, Object: json.RawMessage(`{"subscription":"sub_1"}`)},
		"subscription w/o cx": {ID: "evt_1", Type: "customer.subscription.deleted", Created: created, Object: json.RawMessage(`{"id":"sub_1","object":"subscription"}`)},
		"session without sub": {ID: "evt_1", Type: "checkout.session.completed", Created: created, Object: json.RawMessage(`{"id":"cs_1","object":"checkout.session","customer":"cus_1"}`)},
		"wrong object shape":  {ID: "evt_1", Type: "customer.subscription.deleted", Created: created, Object: json.RawMessage(`[]`)},
		"missing id":          {ID: "", Type: "invoice.payment_failed", Created: created, Object: json.RawMessage(`{"customer":"cus_1","subscription":"sub_1"}`)},
		"missing created":     {ID: "evt_1", Type: "invoice.payment_failed", Object: json.RawMessage(`{"customer":"cus_1","subscription":"sub_1"}`)},
	} {
		_, err := ClassifyStripe(event)
		want := ErrInvalidEvent
		if strings.Contains(name, "unconsumed") {
			want = ErrUnknownEvent
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: error = %v, want %v", name, err, want)
		}
	}
}

var workOSSecretBytes = []byte("0123456789abcdef0123456789abcdef")

func workOSSecret() string {
	return "whsec_" + base64.StdEncoding.EncodeToString(workOSSecretBytes)
}

// workOSSigned builds a body and its Svix headers for sent.
func workOSSigned(secret, id, event string, data string, sent time.Time) (body []byte, ts, sig string) {
	body = []byte(fmt.Sprintf(`{"id":%q,"event":%q,"data":%s}`, id, event, data))
	ts = fmt.Sprint(sent.Unix())
	key, _ := workOSKey(secret)
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s.%s.%s", id, ts, body)
	sig = "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return body, ts, sig
}

func TestVerifyWorkOSAcceptsAGenuineDelivery(t *testing.T) {
	body, ts, sig := workOSSigned(workOSSecret(), "msg_1", "user.created", `{"id":"user_1","email":"ada@example.com"}`, testNow)
	event, err := VerifyWorkOS(workOSSecret(), body, "msg_1", ts, sig, testNow)
	if err != nil {
		t.Fatalf("VerifyWorkOS: %v", err)
	}
	if event.ID != "msg_1" || event.Type != "user.created" {
		t.Errorf("parsed %+v", event)
	}
	if !event.Created.Equal(testNow) {
		t.Errorf("Created = %v, want %v", event.Created, testNow)
	}
}

func TestVerifyWorkOSAcceptsAnUnprefixedSecret(t *testing.T) {
	plain := base64.StdEncoding.EncodeToString(workOSSecretBytes)
	body, ts, sig := workOSSigned(workOSSecret(), "msg_1", "user.created", `{"id":"user_1","email":"ada@example.com"}`, testNow)
	if _, err := VerifyWorkOS(plain, body, "msg_1", ts, sig, testNow); err != nil {
		t.Errorf("unprefixed secret: %v", err)
	}
}

func TestVerifyWorkOSFailuresAreIndistinguishable(t *testing.T) {
	body, ts, sig := workOSSigned(workOSSecret(), "msg_1", "user.created", `{"id":"user_1","email":"ada@example.com"}`, testNow)
	staleBody, staleTs, staleSig := workOSSigned(workOSSecret(), "msg_1", "user.created", `{"id":"user_1","email":"ada@example.com"}`, testNow.Add(-time.Hour))
	futureBody, futureTs, futureSig := workOSSigned(workOSSecret(), "msg_1", "user.created", `{"id":"user_1","email":"ada@example.com"}`, testNow.Add(2*time.Minute))
	badSig := "v1," + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("0", 32)))

	other := "whsec_" + base64.StdEncoding.EncodeToString([]byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))

	cases := map[string]struct {
		secret, id, timestamp, signature string
		body                             []byte
		now                              time.Time
	}{
		"wrong secret":      {other, "msg_1", ts, sig, body, testNow},
		"tampered body":     {workOSSecret(), "msg_1", ts, sig, append(body, ' '), testNow},
		"tampered sig":      {workOSSecret(), "msg_1", ts, badSig, body, testNow},
		"missing version":   {workOSSecret(), "msg_1", ts, strings.TrimPrefix(sig, "v1,"), body, testNow},
		"empty signature":   {workOSSecret(), "msg_1", ts, "", body, testNow},
		"stale delivery":    {workOSSecret(), "msg_1", staleTs, staleSig, staleBody, testNow},
		"future delivery":   {workOSSecret(), "msg_1", futureTs, futureSig, futureBody, testNow},
		"missing id":        {workOSSecret(), "", ts, sig, body, testNow},
		"bad timestamp":     {workOSSecret(), "msg_1", "yesterday", sig, body, testNow},
		"empty secret":      {"", "msg_1", ts, sig, body, testNow},
		"garbage secret":    {"not-base64!!", "msg_1", ts, sig, body, testNow},
		"empty body":        {workOSSecret(), "msg_1", ts, sig, nil, testNow},
		"zero now":          {workOSSecret(), "msg_1", ts, sig, body, time.Time{}},
		"envelope mismatch": {workOSSecret(), "msg_2", ts, sig, body, testNow},
	}
	// A signature made with a different secret over these exact bytes.
	wrongTs := fmt.Sprint(testNow.Unix())
	cases["wrong-secret sig"] = struct {
		secret, id, timestamp, signature string
		body                             []byte
		now                              time.Time
	}{workOSSecret(), "msg_1", wrongTs, "v1," + base64.StdEncoding.EncodeToString(mustHMAC(t, other, "msg_1", wrongTs, body)), body, testNow}
	for name, c := range cases {
		_, err := VerifyWorkOS(c.secret, c.body, c.id, c.timestamp, c.signature, c.now)
		if !errors.Is(err, ErrUnverified) {
			t.Errorf("%s: error = %v, want ErrUnverified", name, err)
		}
		if err != nil && err.Error() != ErrUnverified.Error() {
			t.Errorf("%s: error carries detail %q", name, err.Error())
		}
	}
}

func mustHMAC(t *testing.T, secret, id, ts string, body []byte) []byte {
	t.Helper()
	key, ok := workOSKey(secret)
	if !ok {
		t.Fatalf("bad test secret")
	}
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s.%s.%s", id, ts, body)
	return mac.Sum(nil)
}

func TestClassifyWorkOSMapsTheConsumedSet(t *testing.T) {
	cases := []struct {
		typ                   string
		data                  string
		kind                  IdentityKind
		user, email, org, mem string
	}{
		{"user.created", `{"id":"user_1","email":"ada@example.com"}`, IdentityUserCreated, "user_1", "ada@example.com", "", ""},
		{"user.updated", `{"id":"user_1","email":"ada@example.com"}`, IdentityUserUpdated, "user_1", "ada@example.com", "", ""},
		{"user.deleted", `{"id":"user_1","email":"ada@example.com"}`, IdentityUserDeleted, "user_1", "ada@example.com", "", ""},
		{"organization_membership.created", `{"id":"mem_1","user_id":"user_1","organization_id":"org_1"}`, IdentityMembershipCreated, "user_1", "", "org_1", "mem_1"},
		{"organization_membership.deleted", `{"id":"mem_1","user_id":"user_1","organization_id":"org_1"}`, IdentityMembershipDeleted, "user_1", "", "org_1", "mem_1"},
	}
	for _, c := range cases {
		event := WorkOSEvent{ID: "msg_1", Type: c.typ, Created: testNow, Data: json.RawMessage(c.data)}
		intent, err := ClassifyWorkOS(event)
		if err != nil {
			t.Errorf("%s: %v", c.typ, err)
			continue
		}
		if intent.Kind != c.kind || intent.UserID != c.user || intent.Email != c.email ||
			intent.OrganizationID != c.org || intent.MembershipID != c.mem {
			t.Errorf("%s: %+v", c.typ, intent)
		}
		if !intent.At.Equal(testNow) {
			t.Errorf("%s: At = %v", c.typ, intent.At)
		}
	}
}

func TestClassifyWorkOSRefusesTheUnknownAndTheIncomplete(t *testing.T) {
	for name, event := range map[string]WorkOSEvent{
		"unconsumed type":   {ID: "msg_1", Type: "invitation.created", Created: testNow, Data: json.RawMessage(`{"id":"inv_1"}`)},
		"empty type":        {ID: "msg_1", Type: "", Created: testNow, Data: json.RawMessage(`{}`)},
		"user without id":   {ID: "msg_1", Type: "user.created", Created: testNow, Data: json.RawMessage(`{"email":"ada@example.com"}`)},
		"user without mail": {ID: "msg_1", Type: "user.deleted", Created: testNow, Data: json.RawMessage(`{"id":"user_1"}`)},
		"member w/o org":    {ID: "msg_1", Type: "organization_membership.deleted", Created: testNow, Data: json.RawMessage(`{"id":"mem_1","user_id":"user_1"}`)},
		"missing id":        {ID: "", Type: "user.created", Created: testNow, Data: json.RawMessage(`{"id":"user_1","email":"a@b.c"}`)},
	} {
		_, err := ClassifyWorkOS(event)
		want := ErrInvalidEvent
		if strings.Contains(name, "unconsumed") {
			want = ErrUnknownEvent
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: error = %v, want %v", name, err, want)
		}
	}
}

func TestInboxAppliesOnceAndAcknowledgesTwice(t *testing.T) {
	inbox, err := NewInbox(8)
	if err != nil {
		t.Fatalf("NewInbox: %v", err)
	}
	created := testNow.Add(-time.Minute)
	body, header := stripeSigned(stripeSecret,
		stripePayload("evt_dup", "customer.subscription.deleted", true, created, `{"id":"sub_9","object":"subscription","customer":"cus_9"}`),
		testNow)
	event, err := VerifyStripe(stripeSecret, body, header, true, testNow)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	intent, err := ClassifyStripe(event)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	seen, err := inbox.Accept(intent.EventID)
	if err != nil || seen {
		t.Fatalf("first Accept: seen=%v err=%v", seen, err)
	}
	// Apply exactly once here: the transport would call RecordCancellation.
	seen, err = inbox.Accept(intent.EventID)
	if err != nil || !seen {
		t.Fatalf("second Accept: seen=%v err=%v, want already-seen acknowledgement", seen, err)
	}
	if intent.Kind != BillingSubscriptionCancelled || intent.SubscriptionID != "sub_9" {
		t.Errorf("intent changed between deliveries: %+v", intent)
	}
}

func TestInboxRefusesInsteadOfEvicting(t *testing.T) {
	inbox, err := NewInbox(2)
	if err != nil {
		t.Fatalf("NewInbox: %v", err)
	}
	for _, id := range []string{"a", "b"} {
		if seen, err := inbox.Accept(id); err != nil || seen {
			t.Fatalf("Accept(%q): seen=%v err=%v", id, seen, err)
		}
	}
	if _, err := inbox.Accept("c"); !errors.Is(err, ErrInboxFull) {
		t.Errorf("full inbox: error = %v, want ErrInboxFull", err)
	}
	// Nothing was evicted to make room: the old IDs are still known.
	if !inbox.Seen("a") || !inbox.Seen("b") {
		t.Error("full inbox evicted a recorded ID")
	}
	if inbox.Seen("c") {
		t.Error("refused ID is recorded as seen")
	}
	if inbox.Count() != 2 {
		t.Errorf("Count = %d, want 2", inbox.Count())
	}
}

func TestNewInboxRefusesANonPositiveBound(t *testing.T) {
	for _, max := range []int{0, -1} {
		if _, err := NewInbox(max); !errors.Is(err, ErrInboxFull) {
			t.Errorf("NewInbox(%d): error = %v, want ErrInboxFull", max, err)
		}
	}
}

func TestInboxRefusesAnIDItCannotDeduplicate(t *testing.T) {
	inbox, err := NewInbox(8)
	if err != nil {
		t.Fatalf("NewInbox: %v", err)
	}
	if _, err := inbox.Accept(""); !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("Accept(%q): error = %v, want ErrInvalidEvent", "", err)
	}
}
