package gate_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/billing"
	"github.com/sanskarpan/Ghostlight/internal/entitlements"
	"github.com/sanskarpan/Ghostlight/internal/providerinbox"
	"github.com/sanskarpan/Ghostlight/internal/subscription"
)

// This file is the G7.3 billing gate: the seam where verified provider
// deliveries become subscription facts. The inbox proves a delivery is
// genuine; this suite attacks what happens next. A forged delivery must never
// reach a record, an unknown event must stop at classification, another
// customer's intent must not move this record, a redelivery must apply once,
// a routine renewal must change nothing, and a doctored plan must not enter
// through the webhook path.
//
// What this suite may claim: that the wiring from verified intent to
// subscription record refuses confusion and applies exactly once.
//
// What it may not claim: that checkout or portal sessions reach Stripe, or
// that the sandbox integration works. The transport and the GQ.4 sandbox
// remain outstanding.

// g73Now is the moment the gate's deliveries arrive.
var g73Now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// g73Secret is the endpoint secret the gate verifies against.
const g73Secret = "whsec_gate_billing_endpoint"

func g73Team(t *testing.T) entitlements.Plan {
	t.Helper()
	plan, err := entitlements.Lookup(entitlements.PlanTeam)
	if err != nil {
		t.Fatalf("Lookup(team): %v", err)
	}
	return plan
}

func g73Sub(t *testing.T) *subscription.Subscription {
	t.Helper()
	sub, err := subscription.New("sub_1", "cus_1", g73Team(t), g73Now.Add(-time.Hour), 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &sub
}

// g73Deliver signs a Stripe invoice.payment_failed envelope and returns the
// verified, classified intent — the honest path every attack below deviates
// from at exactly one step.
func g73Deliver(t *testing.T, secret, eventID, customer, sub string, created time.Time) providerinbox.BillingIntent {
	t.Helper()
	body := []byte(fmt.Sprintf(
		`{"id":%q,"type":"invoice.payment_failed","livemode":true,"created":%d,"data":{"object":{"customer":%q,"subscription":%q}}}`,
		eventID, created.Unix(), customer, sub))
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.%s", g73Now.Unix(), body)
	header := fmt.Sprintf("t=%d,v1=%s", g73Now.Unix(), hex.EncodeToString(mac.Sum(nil)))
	event, err := providerinbox.VerifyStripe(secret, body, header, true, g73Now)
	if err != nil {
		t.Fatalf("VerifyStripe: %v", err)
	}
	intent, err := providerinbox.ClassifyStripe(event)
	if err != nil {
		t.Fatalf("ClassifyStripe: %v", err)
	}
	return intent
}

func g73Phase(t *testing.T, sub *subscription.Subscription) subscription.Phase {
	t.Helper()
	return sub.Phase(g73Now)
}

func TestG73GateForgedDeliveryNeverReachesARecord(t *testing.T) {
	sub := g73Sub(t)
	// Fresh in every dimension except the key: the attack is the signature.
	body := []byte(fmt.Sprintf(`{"id":"evt_forge","type":"invoice.payment_failed","livemode":true,"created":%d,"data":{"object":{"customer":"cus_1","subscription":"sub_1"}}}`,
		g73Now.Add(-time.Minute).Unix()))
	mac := hmac.New(sha256.New, []byte(g73Secret+"wrong"))
	fmt.Fprintf(mac, "%d.%s", g73Now.Unix(), body)
	header := fmt.Sprintf("t=%d,v1=%s", g73Now.Unix(), hex.EncodeToString(mac.Sum(nil)))
	if _, err := providerinbox.VerifyStripe(g73Secret, body, header, true, g73Now); !errors.Is(err, providerinbox.ErrUnverified) {
		t.Fatalf("forgery verified: %v", err)
	}
	if g73Phase(t, sub) != subscription.PhaseActive {
		t.Errorf("forgery moved the record to %v", g73Phase(t, sub))
	}
}

func TestG73GateUnknownEventStopsAtClassification(t *testing.T) {
	sub := g73Sub(t)
	body := []byte(fmt.Sprintf(`{"id":"evt_new","type":"charge.refunded","livemode":true,"created":%d,"data":{"object":{}}}`,
		g73Now.Add(-time.Minute).Unix()))
	mac := hmac.New(sha256.New, []byte(g73Secret))
	fmt.Fprintf(mac, "%d.%s", g73Now.Unix(), body)
	header := fmt.Sprintf("t=%d,v1=%s", g73Now.Unix(), hex.EncodeToString(mac.Sum(nil)))
	event, err := providerinbox.VerifyStripe(g73Secret, body, header, true, g73Now)
	if err != nil {
		t.Fatalf("genuine delivery: %v", err)
	}
	if _, err := providerinbox.ClassifyStripe(event); !errors.Is(err, providerinbox.ErrUnknownEvent) {
		t.Fatalf("unknown type classified: %v", err)
	}
	if g73Phase(t, sub) != subscription.PhaseActive {
		t.Errorf("unknown event moved the record to %v", g73Phase(t, sub))
	}
}

func TestG73GateAnotherCustomersIntentIsRefused(t *testing.T) {
	sub := g73Sub(t)
	intent := g73Deliver(t, g73Secret, "evt_cross", "cus_2", "sub_1", g73Now.Add(-time.Minute))
	if _, err := billing.Apply(sub, intent, entitlements.Plan{}); !errors.Is(err, billing.ErrCustomerMismatch) {
		t.Fatalf("cross-customer intent applied: intent=%+v err=%v", intent, err)
	}
	if !sub.PaymentFailedAt.IsZero() {
		t.Error("cross-customer intent moved the record")
	}
}

func TestG73GateRedeliveryAppliesOnce(t *testing.T) {
	inbox, err := providerinbox.NewInbox(64)
	if err != nil {
		t.Fatalf("NewInbox: %v", err)
	}
	sub := g73Sub(t)
	intent := g73Deliver(t, g73Secret, "evt_once", "cus_1", "sub_1", g73Now.Add(-time.Minute))
	applications := 0
	for i := 0; i < 3; i++ {
		seen, err := inbox.Accept(intent.EventID)
		if err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
		if seen {
			continue
		}
		applied, err := billing.Apply(sub, intent, entitlements.Plan{})
		if err != nil || !applied {
			t.Fatalf("delivery %d: applied=%v err=%v", i, applied, err)
		}
		applications++
	}
	if applications != 1 {
		t.Errorf("three deliveries applied %d times, want exactly once", applications)
	}
	if g73Phase(t, sub) != subscription.PhaseGrace {
		t.Errorf("phase = %v, want grace", g73Phase(t, sub))
	}
}

func TestG73GateRenewalStormChangesNothing(t *testing.T) {
	sub := g73Sub(t)
	before := *sub
	for i := 0; i < 12; i++ {
		intent := providerinbox.BillingIntent{
			Kind: providerinbox.BillingPaymentRecovered, EventID: fmt.Sprintf("evt_renew_%d", i),
			CustomerID: "cus_1", SubscriptionID: "sub_1", At: g73Now.Add(time.Duration(i) * time.Hour),
		}
		applied, err := billing.Apply(sub, intent, entitlements.Plan{})
		if err != nil || applied {
			t.Fatalf("renewal %d: applied=%v err=%v", i, applied, err)
		}
	}
	if !reflect.DeepEqual(*sub, before) {
		t.Error("twelve routine renewals moved the record")
	}
}

func TestG73GateDoctoredPlanCannotEnterByWebhook(t *testing.T) {
	sub := g73Sub(t)
	doctored := g73Team(t)
	doctored.Seats *= 10
	started := providerinbox.BillingIntent{
		Kind: providerinbox.BillingSubscriptionStarted, EventID: "evt_start",
		CustomerID: "cus_1", SubscriptionID: "sub_1", At: g73Now,
	}
	if _, err := billing.Apply(sub, started, doctored); !errors.Is(err, billing.ErrUnapprovedPlan) {
		t.Fatalf("doctored plan: error = %v", err)
	}
	if !sub.ConvertedAt.IsZero() {
		t.Error("doctored plan converted the record")
	}
}

func TestG73GateTrialNeverChecksOut(t *testing.T) {
	policy := billing.CheckoutPolicy{AllowedHosts: []string{"billing.ghostlight.dev"}}
	trial, err := entitlements.Lookup(entitlements.PlanTrial)
	if err != nil {
		t.Fatalf("Lookup(trial): %v", err)
	}
	_, err = billing.RequestCheckout(policy, billing.CheckoutRequest{
		CustomerID: "cus_9", Plan: trial,
		SuccessURL: "https://billing.ghostlight.dev/done",
		CancelURL:  "https://billing.ghostlight.dev/cancel",
	})
	if !errors.Is(err, billing.ErrTrialCheckout) {
		t.Errorf("trial checkout: error = %v", err)
	}
}

func TestG73GateHonestFailureAndRecovery(t *testing.T) {
	sub := g73Sub(t)
	failed := g73Deliver(t, g73Secret, "evt_f", "cus_1", "sub_1", g73Now.Add(-time.Minute))
	if applied, err := billing.Apply(sub, failed, entitlements.Plan{}); err != nil || !applied {
		t.Fatalf("failure: applied=%v err=%v", applied, err)
	}
	if g73Phase(t, sub) != subscription.PhaseGrace {
		t.Fatalf("phase = %v, want grace", g73Phase(t, sub))
	}
	recovered := providerinbox.BillingIntent{
		Kind: providerinbox.BillingPaymentRecovered, EventID: "evt_r",
		CustomerID: "cus_1", SubscriptionID: "sub_1", At: g73Now,
	}
	if applied, err := billing.Apply(sub, recovered, entitlements.Plan{}); err != nil || !applied {
		t.Fatalf("recovery: applied=%v err=%v", applied, err)
	}
	if g73Phase(t, sub) != subscription.PhaseActive {
		t.Errorf("phase = %v, want active", g73Phase(t, sub))
	}
	// A restored subscription stays restored: no failure on record means no
	// grace window reopens the following week.
	if sub.Phase(g73Now.Add(8*24*time.Hour)) != subscription.PhaseActive {
		t.Errorf("phase next week = %v, want active", sub.Phase(g73Now.Add(8*24*time.Hour)))
	}
}
