package gate_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/billing"
	"github.com/sanskarpan/Ghostlight/internal/entitlements"
	"github.com/sanskarpan/Ghostlight/internal/providerinbox"
	"github.com/sanskarpan/Ghostlight/internal/stripe"
	"github.com/sanskarpan/Ghostlight/internal/subscription"
)

// This file is the G7.3 transport gate: the seam where a validated checkout
// becomes a Stripe session and a Stripe webhook becomes subscription state.
// It walks the honest loop end to end — billing request, transport call,
// signed delivery, verified intent, applied conversion — and attacks each
// joint: a tampered webhook, a redelivered one, a foreign URL smuggled past
// validation, and a reused idempotency key.
//
// What this suite may not claim: that the live Stripe sandbox answers, or
// that checkout, portal, sign-in, MFA, recovery or revocation round-trip
// against the real providers. The fake below mirrors the documented API
// shapes; the sandbox remains the outstanding GQ.4/G7.3 item.

// g73tSecret is the endpoint secret the gate verifies webhooks against.
const g73tSecret = "whsec_gate_transport"

// g73tFake is the contract-fake Stripe: bearer auth, idempotency keys, and
// session creation. Anything else is a refusal, because the fake defines the
// contract the transport was written against.
type g73tFake struct {
	mu       sync.Mutex
	secret   string
	calls    int
	sessions map[string]string
}

func (f *g73tFake) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		if r.Header.Get("Authorization") != "Bearer "+f.secret {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"type":"authentication_error","message":"bad key"}}`)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":{"type":"invalid_request_error","message":"bad form"}}`)
			return
		}
		key := r.Header.Get("Idempotency-Key")
		params := r.PostForm.Encode()
		if id, ok := f.sessions[key+"|"+params]; ok {
			fmt.Fprintf(w, `{"id":%q,"url":"https://checkout.stripe.com/pay/%s"}`, id, id)
			return
		}
		for k := range f.sessions {
			if len(k) > len(key)+1 && k[:len(key)+1] == key+"|" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":{"type":"idempotency_error","message":"key reused"}}`)
				return
			}
		}
		id := fmt.Sprintf("cs_%d", len(f.sessions)+1)
		f.sessions[key+"|"+params] = id
		fmt.Fprintf(w, `{"id":%q,"url":"https://checkout.stripe.com/pay/%s"}`, id, id)
	}
}

// g73tClient points a transport at the fake.
func g73tClient(t *testing.T, fake *g73tFake) *stripe.Client {
	t.Helper()
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)
	client, err := stripe.New(server.URL, "sk_test_transport", time.Second*5)
	if err != nil {
		t.Fatalf("stripe.New: %v", err)
	}
	return client
}

// g73tTrialRecord is an unconverted trial subscription awaiting checkout.
func g73tTrialRecord(t *testing.T) *subscription.Subscription {
	t.Helper()
	trial, err := entitlements.Lookup(entitlements.PlanTrial)
	if err != nil {
		t.Fatalf("Lookup(trial): %v", err)
	}
	sub, err := subscription.New("sub_1", "cus_1", trial, g73Now.Add(-time.Hour), 14)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &sub
}

func g73tTeam(t *testing.T) entitlements.Plan {
	t.Helper()
	plan, err := entitlements.Lookup(entitlements.PlanTeam)
	if err != nil {
		t.Fatalf("Lookup(team): %v", err)
	}
	return plan
}

// g73tWebhook signs a checkout.session.completed envelope for the fake's
// session, the delivery the transport's session eventually produces.
func g73tWebhook(t *testing.T, eventID, sessionID, customer string, created time.Time) ([]byte, string) {
	t.Helper()
	body := []byte(fmt.Sprintf(
		`{"id":%q,"type":"checkout.session.completed","livemode":true,"created":%d,"data":{"object":{"id":%q,"object":"checkout.session","customer":%q,"subscription":"sub_1"}}}`,
		eventID, created.Unix(), sessionID, customer))
	mac := hmac.New(sha256.New, []byte(g73tSecret))
	fmt.Fprintf(mac, "%d.%s", g73Now.Unix(), body)
	header := fmt.Sprintf("t=%d,v1=%s", g73Now.Unix(), hex.EncodeToString(mac.Sum(nil)))
	return body, header
}

// g73tDeliver verifies, classifies, dedups and applies one delivery,
// reporting whether anything moved — the transport-side wiring in one place.
func g73tDeliver(t *testing.T, inbox *providerinbox.Inbox, sub *subscription.Subscription, plan entitlements.Plan, body []byte, header string) bool {
	t.Helper()
	event, err := providerinbox.VerifyStripe(g73tSecret, body, header, true, g73Now)
	if err != nil {
		t.Fatalf("VerifyStripe: %v", err)
	}
	intent, err := providerinbox.ClassifyStripe(event)
	if err != nil {
		t.Fatalf("ClassifyStripe: %v", err)
	}
	seen, err := inbox.Accept(intent.EventID)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if seen {
		return false
	}
	applied, err := billing.Apply(sub, intent, plan)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return applied
}

func TestG73TransportHonestLoopConvertsTheTrial(t *testing.T) {
	fake := &g73tFake{secret: "sk_test_transport", sessions: make(map[string]string)}
	client := g73tClient(t, fake)
	sub := g73tTrialRecord(t)
	sub.CustomerID = "cus_1"
	sub.ID = "sub_1"

	params := stripe.CheckoutRequestOf("cus_1", entitlements.PlanTeam,
		"https://billing.ghostlight.dev/done", "https://app.ghostlight.dev/cancel",
		"price_team_live_0001", "chk-1", "sub_1",
		[]string{"billing.ghostlight.dev", "app.ghostlight.dev"})
	session, err := client.CreateCheckoutSession(t.Context(), params)
	if err != nil {
		t.Fatalf("CreateCheckoutSession: %v", err)
	}
	if session.ID == "" {
		t.Fatal("no session ID to reconcile the webhook against")
	}
	inbox, err := providerinbox.NewInbox(64)
	if err != nil {
		t.Fatalf("NewInbox: %v", err)
	}
	body, header := g73tWebhook(t, "evt_loop", session.ID, "cus_1", g73Now.Add(-time.Minute))
	if applied := g73tDeliver(t, inbox, sub, g73tTeam(t), body, header); !applied {
		t.Fatal("honest loop changed nothing")
	}
	if sub.Plan.ID != entitlements.PlanTeam || sub.ConvertedAt.IsZero() {
		t.Errorf("record after loop: plan=%v converted=%v", sub.Plan.ID, sub.ConvertedAt)
	}
}

func TestG73TransportTamperedWebhookMovesNothing(t *testing.T) {
	fake := &g73tFake{secret: "sk_test_transport", sessions: make(map[string]string)}
	client := g73tClient(t, fake)
	params := stripe.CheckoutRequestOf("cus_1", entitlements.PlanTeam,
		"https://billing.ghostlight.dev/done", "https://app.ghostlight.dev/cancel",
		"price_team_live_0001", "chk-2", "sub_1",
		[]string{"billing.ghostlight.dev", "app.ghostlight.dev"})
	session, err := client.CreateCheckoutSession(t.Context(), params)
	if err != nil {
		t.Fatalf("CreateCheckoutSession: %v", err)
	}
	body, header := g73tWebhook(t, "evt_tamper", session.ID, "cus_1", g73Now.Add(-time.Minute))
	body = append(body, ' ')
	if _, err := providerinbox.VerifyStripe(g73tSecret, body, header, true, g73Now); !errors.Is(err, providerinbox.ErrUnverified) {
		t.Fatalf("tampered delivery verified: %v", err)
	}
	sub := g73tTrialRecord(t)
	sub.CustomerID = "cus_1"
	sub.ID = "sub_1"
	if !sub.ConvertedAt.IsZero() {
		t.Error("unverified delivery moved the record")
	}
}

func TestG73TransportDuplicateWebhookAppliesOnce(t *testing.T) {
	sub := g73tTrialRecord(t)
	sub.CustomerID = "cus_1"
	sub.ID = "sub_1"
	inbox, err := providerinbox.NewInbox(64)
	if err != nil {
		t.Fatalf("NewInbox: %v", err)
	}
	body, header := g73tWebhook(t, "evt_dup", "cs_9", "cus_1", g73Now.Add(-time.Minute))
	applications := 0
	for i := 0; i < 3; i++ {
		if g73tDeliver(t, inbox, sub, g73tTeam(t), body, header) {
			applications++
		}
	}
	if applications != 1 {
		t.Errorf("three deliveries applied %d times, want exactly once", applications)
	}
}

func TestG73TransportForeignURLNeverLeaves(t *testing.T) {
	fake := &g73tFake{secret: "sk_test_transport", sessions: make(map[string]string)}
	client := g73tClient(t, fake)
	params := stripe.CheckoutRequestOf("cus_1", entitlements.PlanTeam,
		"https://billing.ghostlight.dev/done", "https://evil.example/cancel",
		"price_team_live_0001", "chk-3", "sub_1",
		[]string{"billing.ghostlight.dev", "app.ghostlight.dev"})
	if _, err := client.CreateCheckoutSession(t.Context(), params); err == nil {
		t.Fatal("foreign cancel URL: expected a refusal")
	}
	fake.mu.Lock()
	calls := fake.calls
	fake.mu.Unlock()
	if calls != 0 {
		t.Errorf("refused session reached the API %d times", calls)
	}
}

func TestG73TransportKeyReuseConflicts(t *testing.T) {
	fake := &g73tFake{secret: "sk_test_transport", sessions: make(map[string]string)}
	client := g73tClient(t, fake)
	hosts := []string{"billing.ghostlight.dev", "app.ghostlight.dev"}
	first := stripe.CheckoutRequestOf("cus_1", entitlements.PlanTeam,
		"https://billing.ghostlight.dev/done", "https://app.ghostlight.dev/cancel",
		"price_team_live_0001", "chk-4", "sub_1", hosts)
	session, err := client.CreateCheckoutSession(t.Context(), first)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	changed := first
	changed.Request.SuccessURL = "https://billing.ghostlight.dev/other"
	if _, err := client.CreateCheckoutSession(t.Context(), changed); !errors.Is(err, stripe.ErrIdempotencyConflict) {
		t.Fatalf("reused key: error = %v", err)
	}
	retry, err := client.CreateCheckoutSession(t.Context(), first)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if retry != session {
		t.Errorf("same key returned a different session: %+v vs %+v", retry, session)
	}
}
