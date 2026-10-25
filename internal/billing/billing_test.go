package billing

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/entitlements"
	"github.com/sanskarpan/Ghostlight/internal/providerinbox"
	"github.com/sanskarpan/Ghostlight/internal/subscription"
)

var billNow = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func billPolicy() CheckoutPolicy {
	return CheckoutPolicy{AllowedHosts: []string{"billing.ghostlight.dev", "app.ghostlight.dev"}}
}

func mustPlan(t *testing.T, id entitlements.PlanID) entitlements.Plan {
	t.Helper()
	plan, err := entitlements.Lookup(id)
	if err != nil {
		t.Fatalf("Lookup(%q): %v", id, err)
	}
	return plan
}

func paidSub(t *testing.T) *subscription.Subscription {
	t.Helper()
	sub, err := subscription.New("sub_1", "cus_1", mustPlan(t, entitlements.PlanTeam), billNow.Add(-time.Hour), 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &sub
}

func trialSub(t *testing.T) *subscription.Subscription {
	t.Helper()
	sub, err := subscription.New("sub_9", "cus_9", mustPlan(t, entitlements.PlanTrial), billNow.Add(-time.Hour), 14)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &sub
}

func intent(kind providerinbox.BillingKind, at time.Time) providerinbox.BillingIntent {
	return providerinbox.BillingIntent{
		Kind: kind, EventID: "evt_1", CustomerID: "cus_1", SubscriptionID: "sub_1", At: at,
	}
}

func TestCheckoutPolicyRefusesWhatBindsNothing(t *testing.T) {
	if err := (CheckoutPolicy{}).Validate(); !errors.Is(err, ErrEmptyPolicy) {
		t.Errorf("empty policy: %v", err)
	}
	for name, hosts := range map[string][]string{
		"empty host":     {""},
		"scheme in host": {"https://billing.ghostlight.dev"},
		"path in host":   {"billing.ghostlight.dev/app"},
		"port in host":   {"billing.ghostlight.dev:443"},
		"space in host":  {"billing ghostlight dev"},
		"duplicate":      {"billing.ghostlight.dev", "billing.ghostlight.dev"},
	} {
		if err := (CheckoutPolicy{AllowedHosts: hosts}).Validate(); !errors.Is(err, ErrEmptyPolicy) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	if err := billPolicy().Validate(); err != nil {
		t.Errorf("good policy: %v", err)
	}
}

func TestRequestCheckoutValidatesTotally(t *testing.T) {
	team := mustPlan(t, entitlements.PlanTeam)
	got, err := RequestCheckout(billPolicy(), CheckoutRequest{
		CustomerID: "cus_1", Plan: team,
		SuccessURL: "https://billing.ghostlight.dev/done",
		CancelURL:  "https://app.ghostlight.dev/cancel",
	})
	if err != nil {
		t.Fatalf("RequestCheckout: %v", err)
	}
	if !reflect.DeepEqual(got.Plan, team) {
		t.Errorf("returned plan is not the catalog value: %+v", got.Plan)
	}

	doctored := team
	doctored.Seats *= 10
	cases := map[string]struct {
		req  CheckoutRequest
		want error
	}{
		"empty customer":     {CheckoutRequest{Plan: team, SuccessURL: "https://billing.ghostlight.dev/d", CancelURL: "https://app.ghostlight.dev/c"}, ErrEmptyCustomer},
		"unknown plan":       {CheckoutRequest{CustomerID: "cus_1", Plan: entitlements.Plan{ID: "platinum"}, SuccessURL: "https://billing.ghostlight.dev/d", CancelURL: "https://app.ghostlight.dev/c"}, ErrUnapprovedPlan},
		"doctored plan":      {CheckoutRequest{CustomerID: "cus_1", Plan: doctored, SuccessURL: "https://billing.ghostlight.dev/d", CancelURL: "https://app.ghostlight.dev/c"}, ErrUnapprovedPlan},
		"trial checks out":   {CheckoutRequest{CustomerID: "cus_1", Plan: mustPlan(t, entitlements.PlanTrial), SuccessURL: "https://billing.ghostlight.dev/d", CancelURL: "https://app.ghostlight.dev/c"}, ErrTrialCheckout},
		"http success":       {CheckoutRequest{CustomerID: "cus_1", Plan: team, SuccessURL: "http://billing.ghostlight.dev/d", CancelURL: "https://app.ghostlight.dev/c"}, ErrBadURL},
		"foreign success":    {CheckoutRequest{CustomerID: "cus_1", Plan: team, SuccessURL: "https://evil.example/s", CancelURL: "https://app.ghostlight.dev/c"}, ErrBadURL},
		"relative cancel":    {CheckoutRequest{CustomerID: "cus_1", Plan: team, SuccessURL: "https://billing.ghostlight.dev/d", CancelURL: "/cancel"}, ErrBadURL},
		"userinfo in cancel": {CheckoutRequest{CustomerID: "cus_1", Plan: team, SuccessURL: "https://billing.ghostlight.dev/d", CancelURL: "https://user@app.ghostlight.dev/c"}, ErrBadURL},
		"no policy hosts":    {CheckoutRequest{CustomerID: "cus_1", Plan: team, SuccessURL: "https://billing.ghostlight.dev/d", CancelURL: "https://app.ghostlight.dev/c"}, ErrEmptyPolicy},
	}
	for name, c := range cases {
		policy := billPolicy()
		if name == "no policy hosts" {
			policy = CheckoutPolicy{}
		}
		if _, err := RequestCheckout(policy, c.req); !errors.Is(err, c.want) {
			t.Errorf("%s: error = %v, want %v", name, err, c.want)
		}
	}
}

func TestRequestCheckoutCanonicalizes(t *testing.T) {
	got, err := RequestCheckout(billPolicy(), CheckoutRequest{
		CustomerID: "cus_1", Plan: mustPlan(t, entitlements.PlanTeam),
		SuccessURL: "HTTPS://BILLING.ghostlight.dev/done",
		CancelURL:  "https://app.ghostlight.dev/cancel",
	})
	if err != nil {
		t.Fatalf("RequestCheckout: %v", err)
	}
	if got.SuccessURL != "https://billing.ghostlight.dev/done" {
		t.Errorf("success URL not canonical: %q", got.SuccessURL)
	}
}

func TestRequestPortalValidates(t *testing.T) {
	got, err := RequestPortal(billPolicy(), PortalRequest{CustomerID: "cus_1", ReturnURL: "https://app.ghostlight.dev/account"})
	if err != nil {
		t.Fatalf("RequestPortal: %v", err)
	}
	if got.CustomerID != "cus_1" {
		t.Errorf("customer changed: %+v", got)
	}
	for name, req := range map[string]PortalRequest{
		"empty customer": {ReturnURL: "https://app.ghostlight.dev/account"},
		"foreign host":   {CustomerID: "cus_1", ReturnURL: "https://evil.example/"},
		"relative":       {CustomerID: "cus_1", ReturnURL: "/account"},
	} {
		if _, err := RequestPortal(billPolicy(), req); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestPriceTableResolvesExactlyOnePlan(t *testing.T) {
	team := mustPlan(t, entitlements.PlanTeam)
	growth := mustPlan(t, entitlements.PlanGrowth)
	table, err := NewPriceTable(map[string]entitlements.PlanID{
		"price_team_live_0001": team.ID,
		"price_team_test_0002": team.ID,
		"price_growth_live_9":  growth.ID,
	})
	if err != nil {
		t.Fatalf("NewPriceTable: %v", err)
	}
	got, err := table.Resolve([]string{"price_team_live_0001", "price_team_test_0002"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !reflect.DeepEqual(got, team) {
		t.Errorf("resolved %+v, want team", got)
	}
	for name, ids := range map[string][]string{
		"unknown price": {"price_nope_00000000"},
		"mixed plans":   {"price_team_live_0001", "price_growth_live_9"},
		"empty list":    {},
	} {
		if _, err := table.Resolve(ids); !errors.Is(err, ErrUnknownPrice) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

func TestNewPriceTableRefusesGarbage(t *testing.T) {
	for name, m := range map[string]map[string]entitlements.PlanID{
		"empty":        {},
		"empty price":  {"": entitlements.PlanTeam},
		"not a price":  {"plan_team": entitlements.PlanTeam},
		"short price":  {"price_x": entitlements.PlanTeam},
		"unknown plan": {"price_team_live_0001": "platinum"},
	} {
		if _, err := NewPriceTable(m); !errors.Is(err, ErrUnknownPrice) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

func TestApplyFailureAndRecovery(t *testing.T) {
	sub := paidSub(t)
	applied, err := Apply(sub, intent(providerinbox.BillingPaymentFailed, billNow), entitlements.Plan{})
	if err != nil || !applied {
		t.Fatalf("failure: applied=%v err=%v", applied, err)
	}
	if sub.Phase(billNow) != subscription.PhaseGrace {
		t.Errorf("phase = %v, want grace", sub.Phase(billNow))
	}
	// A routine renewal with nothing outstanding changes nothing.
	renewed := intent(providerinbox.BillingPaymentRecovered, billNow.Add(time.Hour))
	renewed.EventID = "evt_renewal"
	applied, err = Apply(paidSub(t), renewed, entitlements.Plan{})
	if err != nil || applied {
		t.Fatalf("renewal: applied=%v err=%v", applied, err)
	}
	// Recovery after a real failure restores.
	failed := intent(providerinbox.BillingPaymentFailed, billNow)
	recovered := intent(providerinbox.BillingPaymentRecovered, billNow.Add(time.Hour))
	failed.EventID, recovered.EventID = "evt_f", "evt_r"
	sub2 := paidSub(t)
	if _, err := Apply(sub2, failed, entitlements.Plan{}); err != nil {
		t.Fatalf("failure: %v", err)
	}
	applied, err = Apply(sub2, recovered, entitlements.Plan{})
	if err != nil || !applied {
		t.Fatalf("recovery: applied=%v err=%v", applied, err)
	}
	if sub2.Phase(billNow.Add(time.Hour)) != subscription.PhaseActive {
		t.Errorf("phase = %v, want active", sub2.Phase(billNow.Add(time.Hour)))
	}
	// A restoration dated before its failure is a conflict, and the failure stands.
	early := intent(providerinbox.BillingPaymentRecovered, billNow.Add(-time.Hour))
	early.EventID = "evt_early"
	sub3 := paidSub(t)
	if _, err := Apply(sub3, failed, entitlements.Plan{}); err != nil {
		t.Fatalf("failure: %v", err)
	}
	if _, err := Apply(sub3, early, entitlements.Plan{}); err == nil {
		t.Error("backdated restoration: expected an error")
	}
	if sub3.PaymentFailedAt.IsZero() {
		t.Error("failed restoration cleared the failure")
	}
}

func TestApplyStartConvertsOnce(t *testing.T) {
	sub := trialSub(t)
	sub.CustomerID = "cus_1"
	sub.ID = "sub_1"
	team := mustPlan(t, entitlements.PlanTeam)
	started := intent(providerinbox.BillingSubscriptionStarted, billNow)
	applied, err := Apply(sub, started, team)
	if err != nil || !applied {
		t.Fatalf("start: applied=%v err=%v", applied, err)
	}
	if sub.Plan.ID != entitlements.PlanTeam {
		t.Errorf("plan = %v", sub.Plan.ID)
	}
	// Redelivery of the same start is a no-op.
	applied, err = Apply(sub, started, team)
	if err != nil || applied {
		t.Fatalf("redelivered start: applied=%v err=%v", applied, err)
	}
	// A start naming another plan is a conflict, and the record keeps its plan.
	other := started
	other.EventID = "evt_other"
	if _, err := Apply(sub, other, mustPlan(t, entitlements.PlanGrowth)); !errors.Is(err, ErrPlanConflict) {
		t.Errorf("conflicting start: error = %v", err)
	}
	if sub.Plan.ID != entitlements.PlanTeam {
		t.Errorf("conflict moved the plan to %v", sub.Plan.ID)
	}
}

func TestApplyStartRefusesBadPlans(t *testing.T) {
	sub := trialSub(t)
	sub.CustomerID = "cus_1"
	sub.ID = "sub_1"
	team := mustPlan(t, entitlements.PlanTeam)
	doctored := team
	doctored.Seats *= 10
	for name, plan := range map[string]entitlements.Plan{
		"missing plan": {},
		"doctored":     doctored,
		"trial":        mustPlan(t, entitlements.PlanTrial),
		"unknown":      {ID: "platinum"},
	} {
		started := intent(providerinbox.BillingSubscriptionStarted, billNow)
		started.EventID = "evt_" + name
		if _, err := Apply(sub, started, plan); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if !sub.ConvertedAt.IsZero() {
		t.Error("refused starts converted the record")
	}
}

func TestApplyCancellationEndsOnce(t *testing.T) {
	sub := paidSub(t)
	cancelled := intent(providerinbox.BillingSubscriptionCancelled, billNow)
	applied, err := Apply(sub, cancelled, entitlements.Plan{})
	if err != nil || !applied {
		t.Fatalf("cancel: applied=%v err=%v", applied, err)
	}
	if sub.Phase(billNow) != subscription.PhaseCancelled {
		t.Errorf("phase = %v", sub.Phase(billNow))
	}
	applied, err = Apply(sub, cancelled, entitlements.Plan{})
	if err != nil || applied {
		t.Fatalf("redelivered cancel: applied=%v err=%v", applied, err)
	}
}

func TestApplyObservationsChangeNothing(t *testing.T) {
	sub := paidSub(t)
	before := *sub
	for _, kind := range []providerinbox.BillingKind{
		providerinbox.BillingSubscriptionUpdated,
		providerinbox.BillingTrialEnding,
	} {
		applied, err := Apply(sub, intent(kind, billNow), entitlements.Plan{})
		if err != nil || applied {
			t.Fatalf("%s: applied=%v err=%v", kind, applied, err)
		}
	}
	if !reflect.DeepEqual(*sub, before) {
		t.Error("observations moved the record")
	}
}

func TestApplyRefusesAnotherCustomersIntent(t *testing.T) {
	sub := paidSub(t)
	for name, mutate := range map[string]func(*providerinbox.BillingIntent){
		"other customer":     func(i *providerinbox.BillingIntent) { i.CustomerID = "cus_2" },
		"other subscription": func(i *providerinbox.BillingIntent) { i.SubscriptionID = "sub_2" },
	} {
		bad := intent(providerinbox.BillingPaymentFailed, billNow)
		bad.EventID = "evt_" + strings.ReplaceAll(name, " ", "_")
		mutate(&bad)
		if _, err := Apply(sub, bad, entitlements.Plan{}); !errors.Is(err, ErrCustomerMismatch) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	if !sub.PaymentFailedAt.IsZero() {
		t.Error("mismatched intent moved the record")
	}
}

func TestApplyRefusesConfusedCalls(t *testing.T) {
	sub := paidSub(t)
	team := mustPlan(t, entitlements.PlanTeam)
	// A plan where none belongs.
	if _, err := Apply(sub, intent(providerinbox.BillingPaymentFailed, billNow), team); !errors.Is(err, ErrUnexpectedPlan) {
		t.Errorf("plan on failure: %v", err)
	}
	// An intent that names nothing.
	empty := intent(providerinbox.BillingPaymentFailed, billNow)
	empty.EventID = ""
	if _, err := Apply(sub, empty, entitlements.Plan{}); err == nil {
		t.Error("empty event ID: expected an error")
	}
	// A kind the inbox never produces.
	alien := intent("renewable", billNow)
	if _, err := Apply(sub, alien, entitlements.Plan{}); !errors.Is(err, providerinbox.ErrUnknownEvent) {
		t.Errorf("alien kind: %v", err)
	}
	// No record at all.
	if _, err := Apply(nil, intent(providerinbox.BillingPaymentFailed, billNow), entitlements.Plan{}); err == nil {
		t.Error("nil record: expected an error")
	}
}

func TestOpenSubscriptionBindsRecordToProvider(t *testing.T) {
	team := mustPlan(t, entitlements.PlanTeam)
	started := intent(providerinbox.BillingSubscriptionStarted, billNow)
	sub, err := OpenSubscription(started, team)
	if err != nil {
		t.Fatalf("OpenSubscription: %v", err)
	}
	if sub.ID != "sub_1" || sub.CustomerID != "cus_1" || sub.Plan.ID != entitlements.PlanTeam {
		t.Errorf("record = %+v", sub)
	}
	if !sub.StartedAt.Equal(billNow) {
		t.Errorf("started at %v, want event time", sub.StartedAt)
	}
	for name, run := range map[string]func() error{
		"trial plan": func() error {
			_, err := OpenSubscription(started, mustPlan(t, entitlements.PlanTrial))
			return err
		},
		"wrong kind": func() error {
			cancelled := intent(providerinbox.BillingSubscriptionCancelled, billNow)
			_, err := OpenSubscription(cancelled, team)
			return err
		},
		"empty ids": func() error {
			empty := started
			empty.SubscriptionID = ""
			_, err := OpenSubscription(empty, team)
			return err
		},
	} {
		if err := run(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
