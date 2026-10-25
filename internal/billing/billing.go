// Package billing is where money becomes state: it validates the checkout
// and portal requests the platform will send to Stripe, and it applies the
// verified provider intents from `internal/providerinbox` to the lifecycle in
// `internal/subscription`.
//
// The subscription machine advances on recorded facts, and the provider inbox
// proves which deliveries are genuine. Something still has to stand between
// them, because a genuine delivery is not the same as an applicable one: a
// routine renewal is genuine and changes nothing, a redelivered cancellation
// is genuine and must not end anything twice, and a subscription event for
// one customer applied to another's record is genuine, understood — and a
// cross-tenant corruption. This package is that boundary, and it refuses
// rather than guesses everywhere the two sides can disagree.
//
// Five rules shape it.
//
// The first is that **the platform is the authority on price**. A checkout
// session is created only for a plan taken from the approved catalog by
// value, not by ID — passing the ID with doctored seats or ceilings is a
// different plan wearing an approved name, and it is refused. Trial plans
// never check out, because a trial costs nothing and a checkout session for
// it is a charge with no price. Trial length is never a caller parameter;
// the catalog's TrialDays is the only trial length that exists.
//
// The second is that **money URLs are bound**. Success, cancel and return
// URLs must be absolute https URLs on an allowlisted host. A relative URL
// inherits whatever origin renders it, and a foreign host is an open
// redirect wearing a checkout button — both are refused.
//
// The third is that **an intent applies only to its own subscription**. The
// event's customer must match the record's customer before anything else is
// read. A mismatch is refused, never re-targeted, because applying one
// customer's payment failure to another's record ends the wrong trial.
//
// The fourth is that **application is safe under redelivery**. The transport
// deduplicates by event ID, and this package assumes nothing beyond that: a
// recovery with no outstanding failure, a start for the already-converted
// plan, and a cancellation of an ended subscription are no-ops that report
// themselves as such. Genuine conflicts — a different plan on a converted
// record, a restoration dated before its failure — are errors, because
// silently resolving a conflict is how one subscription starts billing
// another's plan.
//
// The fifth is that **a renewal is not a restoration**. Stripe sends a
// successful-invoice event for every cycle, including the uneventful ones. A
// recovery with no failure on record changes nothing and says so, instead of
// erroring and paging someone about money that moved correctly.
//
// What this package does not do is touch the network, hold a secret, or call
// Stripe. The transport builds the sessions from the validated requests and
// dates every application from the event's own creation time, so a redelivery
// applies identically to the first.
package billing

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/sanskarpan/Ghostlight/internal/entitlements"
	"github.com/sanskarpan/Ghostlight/internal/providerinbox"
	"github.com/sanskarpan/Ghostlight/internal/subscription"
)

// Errors returned by this package.
var (
	// ErrUnapprovedPlan means the plan is not the catalog's own value for
	// its ID. The ID may be approved while the seats, ceilings or allowance
	// are not, and that is a different plan.
	ErrUnapprovedPlan = errors.New("billing plan is not the approved catalog value")
	// ErrTrialCheckout means a checkout was requested for a trial plan. A
	// trial costs nothing; checking out for one manufactures a charge.
	ErrTrialCheckout = errors.New("trial plans never check out")
	// ErrBadURL means a success, cancel or return URL is not an absolute
	// https URL on an allowlisted host.
	ErrBadURL = errors.New("billing URL is not bound to an allowed host")
	// ErrEmptyCustomer means no customer was named. Money without a customer
	// is a fact about nothing.
	ErrEmptyCustomer = errors.New("billing request names no customer")
	// ErrUnknownPrice means a Stripe price ID maps to no approved plan. An
	// unmapped price is refused rather than guessed, because guessing is how
	// a customer is billed for a plan they never chose.
	ErrUnknownPrice = errors.New("stripe price maps to no approved plan")
	// ErrCustomerMismatch means the intent's customer is not the record's
	// customer. Application stops before reading anything else.
	ErrCustomerMismatch = errors.New("billing intent is for another customer")
	// ErrPlanConflict means the record already converted to a different
	// plan. Plans change at period boundaries through the platform, never by
	// webhook redelivery.
	ErrPlanConflict = errors.New("subscription already converted to a different plan")
	// ErrUnexpectedPlan means a plan argument was supplied where none is
	// needed, or omitted where one is. Forgetting the plan on a start and
	// passing one on a cancellation are both refused rather than defaulted.
	ErrUnexpectedPlan = errors.New("billing intent carries a plan where none belongs, or none where one does")
	// ErrEmptyPolicy means the checkout policy names no allowed host. A
	// policy that allows everywhere binds nothing.
	ErrEmptyPolicy = errors.New("billing policy allows no host")
)

// CheckoutPolicy bounds where money URLs may point.
type CheckoutPolicy struct {
	// AllowedHosts are the only hosts success, cancel and return URLs may
	// name. At least one is required.
	AllowedHosts []string
}

// Validate refuses a policy that binds nothing, or a host entry that is not
// a bare hostname. Ports, paths, schemes and userinfo in an allowlist entry
// are refused, because an allowlist nobody can read strictly is an allowlist
// nobody can audit.
func (p CheckoutPolicy) Validate() error {
	if len(p.AllowedHosts) == 0 {
		return ErrEmptyPolicy
	}
	seen := make(map[string]bool)
	for _, h := range p.AllowedHosts {
		host := strings.TrimSpace(strings.ToLower(h))
		if host == "" || strings.ContainsAny(host, "/?#@:%") || strings.Contains(host, " ") {
			return fmt.Errorf("%w: %q is not a bare hostname", ErrEmptyPolicy, h)
		}
		if seen[host] {
			return fmt.Errorf("%w: duplicate host %q", ErrEmptyPolicy, h)
		}
		seen[host] = true
	}
	return nil
}

// boundURL parses raw as an absolute https URL on an allowlisted host and
// returns it canonicalized. Anything else is refused with the reason named.
func (p CheckoutPolicy) boundURL(kind, raw string) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(raw)
	u, err := url.Parse(trimmed)
	if err != nil || !u.IsAbs() || !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("%w: %s URL must be absolute https", ErrBadURL, kind)
	}
	if u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("%w: %s URL carries userinfo or a fragment", ErrBadURL, kind)
	}
	host := strings.ToLower(u.Hostname())
	allowed := false
	for _, h := range p.AllowedHosts {
		if host == strings.TrimSpace(strings.ToLower(h)) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Errorf("%w: %s URL host %q is not allowlisted", ErrBadURL, kind, u.Hostname())
	}
	u.Scheme = "https"
	u.Host = strings.ToLower(u.Host)
	return u.String(), nil
}

// CheckoutRequest is a checkout session the transport will create.
type CheckoutRequest struct {
	// CustomerID is the platform customer the session is for. Required.
	CustomerID string
	// Plan must be the catalog's own value for its ID. Required, and never a
	// trial plan.
	Plan entitlements.Plan
	// SuccessURL and CancelURL are where Stripe returns the customer.
	// Both are bound by the policy.
	SuccessURL string
	CancelURL  string
}

// RequestCheckout validates a checkout session before the transport creates
// it. The returned request is canonicalized; the transport creates exactly
// it and nothing else.
func RequestCheckout(policy CheckoutPolicy, req CheckoutRequest) (CheckoutRequest, error) {
	if strings.TrimSpace(req.CustomerID) == "" {
		return CheckoutRequest{}, ErrEmptyCustomer
	}
	catalogPlan, err := entitlements.Lookup(req.Plan.ID)
	if err != nil {
		return CheckoutRequest{}, fmt.Errorf("%w: %s", ErrUnapprovedPlan, req.Plan.ID)
	}
	if !reflect.DeepEqual(req.Plan, catalogPlan) {
		return CheckoutRequest{}, fmt.Errorf("%w: %s differs from the catalog value", ErrUnapprovedPlan, req.Plan.ID)
	}
	if req.Plan.TrialDays > 0 {
		return CheckoutRequest{}, fmt.Errorf("%w: %s", ErrTrialCheckout, req.Plan.ID)
	}
	success, err := policy.boundURL("success", req.SuccessURL)
	if err != nil {
		return CheckoutRequest{}, err
	}
	cancel, err := policy.boundURL("cancel", req.CancelURL)
	if err != nil {
		return CheckoutRequest{}, err
	}
	return CheckoutRequest{
		CustomerID: strings.TrimSpace(req.CustomerID),
		Plan:       catalogPlan,
		SuccessURL: success,
		CancelURL:  cancel,
	}, nil
}

// PortalRequest is a customer-portal session the transport will create. The
// portal shows invoices and payment methods; it never changes the plan, which
// is why it carries no plan at all.
type PortalRequest struct {
	// CustomerID is the platform customer the session is for. Required.
	CustomerID string
	// ReturnURL is where the portal returns the customer. Bound by policy.
	ReturnURL string
}

// RequestPortal validates a portal session before the transport creates it.
func RequestPortal(policy CheckoutPolicy, req PortalRequest) (PortalRequest, error) {
	if strings.TrimSpace(req.CustomerID) == "" {
		return PortalRequest{}, ErrEmptyCustomer
	}
	ret, err := policy.boundURL("return", req.ReturnURL)
	if err != nil {
		return PortalRequest{}, err
	}
	return PortalRequest{CustomerID: strings.TrimSpace(req.CustomerID), ReturnURL: ret}, nil
}

// PriceTable maps Stripe price IDs to approved plans. It is data the
// platform owns: a price nobody mapped is a price nobody may bill.
type PriceTable map[string]entitlements.PlanID

// NewPriceTable validates a price mapping. Every target must be an approved
// catalog plan, every price ID must look like a Stripe price, no price may
// appear twice (a map cannot express that, but an empty key or an empty
// target is refused), and two prices may share a plan — plans have many
// prices across test and live modes — but the reverse is impossible by
// construction.
func NewPriceTable(mapping map[string]entitlements.PlanID) (PriceTable, error) {
	if len(mapping) == 0 {
		return nil, fmt.Errorf("%w: no prices mapped", ErrUnknownPrice)
	}
	out := make(PriceTable, len(mapping))
	for price, planID := range mapping {
		if strings.TrimSpace(price) == "" {
			return nil, fmt.Errorf("%w: empty price ID", ErrUnknownPrice)
		}
		if !strings.HasPrefix(price, "price_") || len(price) < len("price_")+8 {
			return nil, fmt.Errorf("%w: %q is not a Stripe price ID", ErrUnknownPrice, price)
		}
		if _, err := entitlements.Lookup(planID); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrUnknownPrice, planID)
		}
		out[price] = planID
	}
	return out, nil
}

// Resolve maps the prices on a subscription to the single approved plan they
// name. Zero prices name nothing; two prices naming different plans name two
// things, and a subscription billed under two plans is refused rather than
// assigned to either.
func (t PriceTable) Resolve(priceIDs []string) (entitlements.Plan, error) {
	if len(t) == 0 {
		return entitlements.Plan{}, fmt.Errorf("%w: no price table", ErrUnknownPrice)
	}
	seen := make(map[entitlements.PlanID]bool)
	for _, price := range priceIDs {
		planID, ok := t[price]
		if !ok {
			return entitlements.Plan{}, fmt.Errorf("%w: %q", ErrUnknownPrice, price)
		}
		seen[planID] = true
	}
	if len(seen) == 0 {
		return entitlements.Plan{}, fmt.Errorf("%w: subscription names no price", ErrUnknownPrice)
	}
	if len(seen) > 1 {
		return entitlements.Plan{}, fmt.Errorf("%w: prices name %d plans", ErrUnknownPrice, len(seen))
	}
	for planID := range seen {
		plan, err := entitlements.Lookup(planID)
		if err != nil {
			return entitlements.Plan{}, fmt.Errorf("%w: %s", ErrUnknownPrice, planID)
		}
		return plan, nil
	}
	return entitlements.Plan{}, fmt.Errorf("%w: subscription names no price", ErrUnknownPrice)
}

// Apply moves a verified billing intent into a subscription record and
// reports whether it changed anything. The intent's own creation time dates
// the change, so a redelivery applies identically to the first — and the
// idempotent cases below make redelivery safe even where the transport's
// duplicate memory is bypassed.
//
// plan is required for started intents and forbidden for every other kind:
// it must be the catalog's own value, like a checkout plan. Passing a plan
// for a cancellation is refused rather than ignored, because an ignored
// argument is an argument nobody checked.
func Apply(sub *subscription.Subscription, intent providerinbox.BillingIntent, plan entitlements.Plan) (bool, error) {
	if sub == nil {
		return false, fmt.Errorf("%w: no subscription record", subscription.ErrInvalidFact)
	}
	if intent.EventID == "" || intent.CustomerID == "" || intent.SubscriptionID == "" || intent.At.IsZero() {
		return false, fmt.Errorf("%w: intent is missing its identity", subscription.ErrInvalidFact)
	}
	if intent.CustomerID != sub.CustomerID {
		return false, fmt.Errorf("%w: intent for %q does not belong to %q",
			ErrCustomerMismatch, intent.CustomerID, sub.CustomerID)
	}
	if intent.SubscriptionID != sub.ID {
		return false, fmt.Errorf("%w: intent for %q does not belong to %q",
			ErrCustomerMismatch, intent.SubscriptionID, sub.ID)
	}
	at := intent.At.UTC()
	switch intent.Kind {
	case providerinbox.BillingPaymentFailed:
		if plan.ID != "" {
			return false, fmt.Errorf("%w: a payment failure takes no plan", ErrUnexpectedPlan)
		}
		if _, err := sub.RecordPaymentFailure(at, 0); err != nil {
			return false, err
		}
		return true, nil
	case providerinbox.BillingPaymentRecovered:
		if plan.ID != "" {
			return false, fmt.Errorf("%w: a recovery takes no plan", ErrUnexpectedPlan)
		}
		if sub.PaymentFailedAt.IsZero() {
			// A routine renewal: money moved correctly, nothing to restore.
			return false, nil
		}
		if err := sub.RecordPaymentRestored(at); err != nil {
			return false, err
		}
		return true, nil
	case providerinbox.BillingSubscriptionStarted:
		approved, err := catalogEqual(plan)
		if err != nil {
			return false, err
		}
		if !sub.ConvertedAt.IsZero() {
			if reflect.DeepEqual(sub.Plan, approved) {
				return false, nil
			}
			return false, fmt.Errorf("%w: record holds %s, intent carries %s",
				ErrPlanConflict, sub.Plan.ID, approved.ID)
		}
		if err := sub.RecordConversion(at, approved); err != nil {
			return false, err
		}
		return true, nil
	case providerinbox.BillingSubscriptionCancelled:
		if plan.ID != "" {
			return false, fmt.Errorf("%w: a cancellation takes no plan", ErrUnexpectedPlan)
		}
		if !sub.CancelledAt.IsZero() {
			return false, nil
		}
		if err := sub.RecordCancellation(at); err != nil {
			return false, err
		}
		return true, nil
	case providerinbox.BillingSubscriptionUpdated, providerinbox.BillingTrialEnding:
		if plan.ID != "" {
			return false, fmt.Errorf("%w: an observation takes no plan", ErrUnexpectedPlan)
		}
		// Observed, not applied. The platform is the authority on plans and
		// trial ends; the transport records the sighting elsewhere. Changing
		// nothing here is the point: a webhook must not move a plan the
		// customer never chose through the platform.
		return false, nil
	default:
		return false, fmt.Errorf("%w: %q", providerinbox.ErrUnknownEvent, string(intent.Kind))
	}
}

// catalogEqual requires plan to be the catalog's own value for its ID.
func catalogEqual(plan entitlements.Plan) (entitlements.Plan, error) {
	if plan.ID == "" {
		return entitlements.Plan{}, fmt.Errorf("%w: a start requires the plan", ErrUnexpectedPlan)
	}
	catalogPlan, err := entitlements.Lookup(plan.ID)
	if err != nil {
		return entitlements.Plan{}, fmt.Errorf("%w: %s", ErrUnapprovedPlan, plan.ID)
	}
	if !reflect.DeepEqual(plan, catalogPlan) {
		return entitlements.Plan{}, fmt.Errorf("%w: %s differs from the catalog value", ErrUnapprovedPlan, plan.ID)
	}
	if plan.TrialDays > 0 {
		return entitlements.Plan{}, fmt.Errorf("%w: %s", ErrTrialCheckout, plan.ID)
	}
	return catalogPlan, nil
}

// OpenSubscription records a paid-direct signup from a started intent: a
// customer with no record whose checkout completed. The subscription ID is
// the provider's, binding the record to the thing billed. Trial plans are
// refused here as in checkout — a paid-direct signup for a free plan is a
// contradiction — and so is an intent that is not a start.
func OpenSubscription(intent providerinbox.BillingIntent, plan entitlements.Plan) (subscription.Subscription, error) {
	if intent.Kind != providerinbox.BillingSubscriptionStarted {
		return subscription.Subscription{}, fmt.Errorf("%w: cannot open a record from %q",
			providerinbox.ErrUnknownEvent, string(intent.Kind))
	}
	if intent.EventID == "" || intent.CustomerID == "" || intent.SubscriptionID == "" || intent.At.IsZero() {
		return subscription.Subscription{}, fmt.Errorf("%w: intent is missing its identity", subscription.ErrInvalidFact)
	}
	approved, err := catalogEqual(plan)
	if err != nil {
		return subscription.Subscription{}, err
	}
	sub, err := subscription.New(intent.SubscriptionID, intent.CustomerID, approved, intent.At.UTC(), 0)
	if err != nil {
		return subscription.Subscription{}, err
	}
	return sub, nil
}
