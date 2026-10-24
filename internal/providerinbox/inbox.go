// Package providerinbox is where the outside world knocks: it verifies that a
// delivery claiming to come from Stripe or WorkOS actually did, and turns the
// ones that did into intents the platform's own state machines can consume.
//
// The subscription lifecycle in `internal/subscription` and the identity policy
// in `internal/identity` are deliberately closed to the network: they advance
// on recorded facts, never on whoever shouts loudest at an endpoint. Something
// has to stand at the boundary and decide which shouts are facts. That is this
// package, and it holds the same posture as everything behind it: a delivery it
// cannot prove genuine is refused, and a genuine delivery it does not
// understand is refused too, because a 200 OK for an event nobody handled is
// how a cancelled subscription keeps billing.
//
// Five rules shape the verification.
//
// The first is that **a failure is a failure, with no detail**. A bad
// signature, a stale timestamp, a future timestamp, a wrong mode and a mangled
// header all return the same error. Telling a forger which check tripped turns
// the endpoint into a signature oracle, and there is no debugging value in the
// distinction for an honest sender either: every verification failure means
// "do not apply this", and the sender's recourse in every case is to send a
// well-formed delivery.
//
// The second is that **time is bounded on both ends**. A Stripe or Svix
// timestamp older than the tolerance is refused even with a valid signature,
// because a valid signature on an old delivery is exactly what a replay is. A
// timestamp in the future beyond a small skew allowance is refused rather than
// treated as fresh, because a check dated after the moment being assessed is a
// clock problem, not evidence. The event's own creation time is bounded
// separately and more generously — providers retry for days, so the signature
// proves freshness while the creation time only has to prove the event is not
// from the future and not older than the retry horizon.
//
// The third is that **test events cannot move live subscriptions**. A Stripe
// envelope carries its mode, and the inbox is constructed for exactly one of
// them. A test-mode delivery presented to a live inbox is refused, because the
// failure mode it prevents — a sandbox click cancelling a real customer — is
// silent and total.
//
// The fourth is that **an unknown event type is refused, never ignored**.
// Providers add event types without asking. An inbox that acknowledges what it
// does not understand loses data with a success status, which is the one
// outcome nobody investigates. The classified set is deliberately the subset
// the platform consumes; everything else waits, loudly, for a human to teach
// the inbox what it means.
//
// The fifth is that **a delivery is recorded once and applied once**. The
// inbox keeps the IDs it has seen, bounded, and a second delivery of the same
// ID is reported as already seen so the transport can acknowledge it without
// applying it again. A full inbox refuses new IDs rather than evicting old
// ones, because an eviction is a duplicate waiting to be applied twice.
//
// What this package does not do is touch the network, hold a secret beyond the
// call, or apply anything. Verification takes the secret as an argument and
// keeps no copy. Classification takes a verified event and returns an intent.
// Application is the future transport's job, using the subscription and
// identity methods named on each intent kind.
package providerinbox

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Verification bounds. The signature timestamp proves the delivery is fresh;
// the event creation time only has to sit inside the retry horizon.
const (
	// SignatureTolerance is how old a delivery signature may be. Older than
	// this, a valid signature is a replay until proven otherwise.
	SignatureTolerance = 5 * time.Minute
	// FutureSkew is how far ahead of now a timestamp may be before it is a
	// clock problem rather than drift.
	FutureSkew = time.Minute
	// MaxEventAge is how old the event itself may be. Providers retry for
	// days, so this is generous; older than this, the event belongs to an
	// operator investigation, not to automatic application.
	MaxEventAge = 72 * time.Hour
	// MaxSeenIDs bounds the duplicate memory. Full means refuse, not evict.
	MaxSeenIDs = 10000
	// MaxBodyBytes bounds the delivery accepted for verification. Webhook
	// envelopes are small; an unbounded read is a memory allocation the
	// sender controls.
	MaxBodyBytes = 1 << 20
)

// Errors returned by this package. Verification failures are deliberately one
// error: the caller learns nothing about which check tripped.
var (
	// ErrUnverified means the delivery cannot be proven genuine. Bad
	// signature, stale or future timestamp, wrong mode, mangled envelope:
	// all of these are this error, because distinguishing them helps only a
	// forger.
	ErrUnverified = errors.New("provider delivery cannot be verified")
	// ErrUnknownEvent means a genuine delivery carries an event type this
	// inbox does not consume. It is refused, not ignored, so the provider
	// retries and a human teaches the inbox what the type means.
	ErrUnknownEvent = errors.New("provider event type is not consumed")
	// ErrInvalidEvent means a genuine, consumed event type arrives with a
	// payload the type requires and the delivery lacks. The inbox refuses
	// rather than guessing which customer or subscription was meant.
	ErrInvalidEvent = errors.New("provider event payload is missing required fields")
	// ErrDuplicate means the event ID has already been recorded. The delivery
	// is genuine and understood; it must be acknowledged without applying.
	ErrDuplicate = errors.New("provider event already recorded")
	// ErrInboxFull means the duplicate memory is full. New IDs are refused
	// rather than evicting old ones into double-application.
	ErrInboxFull = errors.New("provider inbox duplicate memory is full")
)

// StripeEvent is a verified Stripe delivery.
type StripeEvent struct {
	// ID is Stripe's event ID, the duplicate key.
	ID string
	// Type is the event type, for example invoice.payment_failed.
	Type string
	// Live reports the envelope's mode. It always matches the inbox that
	// verified it; a mismatch is ErrUnverified, not a converted event.
	Live bool
	// Created is when Stripe created the event, the moment intents are dated
	// from. Arrival time is a transport fact, not a billing fact.
	Created time.Time
	// Object is the event's data.object, unparsed. Classification extracts
	// exactly the fields each consumed type requires.
	Object json.RawMessage
}

// stripeEnvelope is the Stripe event shape. Only the fields the inbox needs
// are decoded; the rest is not the inbox's business.
type stripeEnvelope struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Live    bool            `json:"livemode"`
	Created int64           `json:"created"`
	Data    stripeEventData `json:"data"`
}

type stripeEventData struct {
	Object json.RawMessage `json:"object"`
}

// VerifyStripe proves a delivery came from Stripe and parses its envelope.
//
// secret is the endpoint secret, body the raw request body, header the value
// of the Stripe-Signature header, live the mode this inbox serves, and now
// the moment of verification. The secret is used and never kept.
func VerifyStripe(secret string, body []byte, header string, live bool, now time.Time) (StripeEvent, error) {
	if secret == "" {
		return StripeEvent{}, ErrUnverified
	}
	if len(body) == 0 || len(body) > MaxBodyBytes {
		return StripeEvent{}, ErrUnverified
	}
	if now.IsZero() {
		return StripeEvent{}, ErrUnverified
	}
	stamp, sigs, ok := parseStripeHeader(header)
	if !ok {
		return StripeEvent{}, ErrUnverified
	}
	sent := time.Unix(stamp, 0)
	if now.Sub(sent) > SignatureTolerance {
		return StripeEvent{}, ErrUnverified
	}
	if sent.Sub(now) > FutureSkew {
		return StripeEvent{}, ErrUnverified
	}
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.%s", stamp, body)
	expected := mac.Sum(nil)
	matched := false
	for _, sig := range sigs {
		raw, err := hex.DecodeString(sig)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(raw, expected) == 1 {
			matched = true
			break
		}
	}
	if !matched {
		return StripeEvent{}, ErrUnverified
	}
	var env stripeEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return StripeEvent{}, ErrUnverified
	}
	if env.ID == "" || env.Type == "" || env.Created == 0 || len(env.Data.Object) == 0 {
		return StripeEvent{}, ErrUnverified
	}
	if env.Live != live {
		return StripeEvent{}, ErrUnverified
	}
	created := time.Unix(env.Created, 0)
	if created.Sub(now) > FutureSkew {
		return StripeEvent{}, ErrUnverified
	}
	if now.Sub(created) > MaxEventAge {
		return StripeEvent{}, ErrUnverified
	}
	return StripeEvent{ID: env.ID, Type: env.Type, Live: env.Live, Created: created.UTC(), Object: env.Data.Object}, nil
}

// parseStripeHeader splits a Stripe-Signature value into its timestamp and
// candidate v1 signatures. Only v1 is accepted: it is the current scheme,
// and accepting a legacy scheme alongside it doubles the forgery surface for
// no honest sender's benefit.
func parseStripeHeader(header string) (int64, []string, bool) {
	var stamp int64
	var found bool
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return 0, nil, false
		}
		switch kv[0] {
		case "t":
			n, err := parseInt63(kv[1])
			if err != nil {
				return 0, nil, false
			}
			stamp, found = n, true
		case "v1":
			if kv[1] == "" {
				return 0, nil, false
			}
			sigs = append(sigs, kv[1])
		default:
			// Unknown schemes and the legacy v0 are not accepted. A header
			// carrying only schemes the inbox does not speak verifies
			// nothing.
		}
	}
	if !found || len(sigs) == 0 {
		return 0, nil, false
	}
	return stamp, sigs, true
}

func parseInt63(s string) (int64, error) {
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a timestamp: %q", s)
		}
		n = n*10 + int64(c-'0')
		if n > 1<<62 {
			return 0, fmt.Errorf("timestamp out of range: %q", s)
		}
	}
	return n, nil
}

// BillingKind names the subscription fact a verified Stripe event carries.
// Each kind names the subscription method the future transport applies; the
// mapping is stated here so the transport cannot invent one.
type BillingKind string

const (
	// BillingPaymentFailed carries a failed payment: RecordPaymentFailure.
	BillingPaymentFailed BillingKind = "payment_failed"
	// BillingPaymentRecovered carries a payment after failure:
	// RecordPaymentRestored.
	BillingPaymentRecovered BillingKind = "payment_recovered"
	// BillingSubscriptionStarted carries a new or converted subscription:
	// the transport opens the period it describes.
	BillingSubscriptionStarted BillingKind = "subscription_started"
	// BillingSubscriptionUpdated carries a changed subscription for the
	// transport to reconcile against the recorded snapshot.
	BillingSubscriptionUpdated BillingKind = "subscription_updated"
	// BillingSubscriptionCancelled carries a deleted subscription:
	// RecordCancellation.
	BillingSubscriptionCancelled BillingKind = "subscription_cancelled"
	// BillingTrialEnding carries an approaching trial end. It changes no
	// state; it is classified so the delivery is understood rather than
	// unknown.
	BillingTrialEnding BillingKind = "trial_ending"
)

// BillingIntent is a verified, understood Stripe event ready for the
// transport to apply. At is the event's creation time, so a redelivery
// applies identically to the first delivery.
type BillingIntent struct {
	Kind           BillingKind
	EventID        string
	CustomerID     string
	SubscriptionID string
	At             time.Time
	// TrialEndsAt is set for BillingSubscriptionStarted when Stripe names a
	// trial end. Zero otherwise.
	TrialEndsAt time.Time
}

// ClassifyStripe turns a verified Stripe event into the intent the transport
// applies. An event type outside the consumed set is ErrUnknownEvent: refused,
// never ignored.
func ClassifyStripe(event StripeEvent) (BillingIntent, error) {
	if event.ID == "" || event.Type == "" || event.Created.IsZero() {
		return BillingIntent{}, ErrInvalidEvent
	}
	switch event.Type {
	case "invoice.payment_failed":
		customer, subscription, err := invoiceRefs(event.Object)
		if err != nil {
			return BillingIntent{}, err
		}
		return BillingIntent{Kind: BillingPaymentFailed, EventID: event.ID, CustomerID: customer, SubscriptionID: subscription, At: event.Created}, nil
	case "invoice.payment_succeeded":
		customer, subscription, err := invoiceRefs(event.Object)
		if err != nil {
			return BillingIntent{}, err
		}
		return BillingIntent{Kind: BillingPaymentRecovered, EventID: event.ID, CustomerID: customer, SubscriptionID: subscription, At: event.Created}, nil
	case "customer.subscription.created", "checkout.session.completed":
		customer, subscription, trialEnd, err := subscriptionRefs(event.Object)
		if err != nil {
			return BillingIntent{}, err
		}
		return BillingIntent{Kind: BillingSubscriptionStarted, EventID: event.ID, CustomerID: customer, SubscriptionID: subscription, At: event.Created, TrialEndsAt: trialEnd}, nil
	case "customer.subscription.updated":
		customer, subscription, _, err := subscriptionRefs(event.Object)
		if err != nil {
			return BillingIntent{}, err
		}
		return BillingIntent{Kind: BillingSubscriptionUpdated, EventID: event.ID, CustomerID: customer, SubscriptionID: subscription, At: event.Created}, nil
	case "customer.subscription.deleted":
		customer, subscription, _, err := subscriptionRefs(event.Object)
		if err != nil {
			return BillingIntent{}, err
		}
		return BillingIntent{Kind: BillingSubscriptionCancelled, EventID: event.ID, CustomerID: customer, SubscriptionID: subscription, At: event.Created}, nil
	case "customer.subscription.trial_will_end":
		customer, subscription, _, err := subscriptionRefs(event.Object)
		if err != nil {
			return BillingIntent{}, err
		}
		return BillingIntent{Kind: BillingTrialEnding, EventID: event.ID, CustomerID: customer, SubscriptionID: subscription, At: event.Created}, nil
	default:
		return BillingIntent{}, ErrUnknownEvent
	}
}

// invoiceRefs extracts the customer and subscription an invoice belongs to.
// Both are required: a failure that cannot name its subscription is a fact
// about nothing.
func invoiceRefs(raw json.RawMessage) (customer, subscription string, err error) {
	var invoice struct {
		Customer     string  `json:"customer"`
		Subscription *string `json:"subscription"`
	}
	if err := json.Unmarshal(raw, &invoice); err != nil {
		return "", "", ErrInvalidEvent
	}
	if invoice.Customer == "" || invoice.Subscription == nil || *invoice.Subscription == "" {
		return "", "", ErrInvalidEvent
	}
	return invoice.Customer, *invoice.Subscription, nil
}

// subscriptionRefs extracts the customer, subscription ID and optional trial
// end from a subscription object or a checkout session naming one. A session
// without its subscription is refused: the transport cannot open a period it
// cannot name.
func subscriptionRefs(raw json.RawMessage) (customer, subscription string, trialEnd time.Time, err error) {
	var object struct {
		ID           string  `json:"id"`
		Object       string  `json:"object"`
		Customer     *string `json:"customer"`
		Subscription *string `json:"subscription"`
		TrialEnd     *int64  `json:"trial_end"`
	}
	if err := json.Unmarshal(raw, &object); err != nil {
		return "", "", time.Time{}, ErrInvalidEvent
	}
	switch object.Object {
	case "subscription":
		if object.ID == "" || object.Customer == nil || *object.Customer == "" {
			return "", "", time.Time{}, ErrInvalidEvent
		}
		if object.TrialEnd != nil && *object.TrialEnd > 0 {
			trialEnd = time.Unix(*object.TrialEnd, 0).UTC()
		}
		return *object.Customer, object.ID, trialEnd, nil
	case "checkout.session":
		if object.Customer == nil || *object.Customer == "" || object.Subscription == nil || *object.Subscription == "" {
			return "", "", time.Time{}, ErrInvalidEvent
		}
		return *object.Customer, *object.Subscription, time.Time{}, nil
	default:
		return "", "", time.Time{}, ErrInvalidEvent
	}
}

// WorkOSEvent is a verified WorkOS delivery.
type WorkOSEvent struct {
	// ID is the delivery ID from the svix-id header, the duplicate key.
	ID string
	// Type is the WorkOS event name, for example user.created.
	Type string
	// Created is the delivery time from the svix-timestamp header. Svix
	// timestamps the send, so the header time — not arrival — dates the
	// intent, and a redelivery applies identically.
	Created time.Time
	// Data is the event payload, unparsed.
	Data json.RawMessage
}

// workOSEnvelope is the WorkOS event shape.
type workOSEnvelope struct {
	ID    string          `json:"id"`
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

// VerifyWorkOS proves a delivery came from WorkOS via the Svix scheme and
// parses its envelope.
//
// secret is the endpoint secret with or without its whsec_ prefix, body the
// raw request body, id/timestamp/signature the svix-id, svix-timestamp and
// svix-signature header values (the webhook-* aliases are accepted for the
// same values), and now the moment of verification.
func VerifyWorkOS(secret string, body []byte, id, timestamp, signature string, now time.Time) (WorkOSEvent, error) {
	if now.IsZero() {
		return WorkOSEvent{}, ErrUnverified
	}
	if len(body) == 0 || len(body) > MaxBodyBytes {
		return WorkOSEvent{}, ErrUnverified
	}
	key, ok := workOSKey(secret)
	if !ok {
		return WorkOSEvent{}, ErrUnverified
	}
	if id == "" {
		return WorkOSEvent{}, ErrUnverified
	}
	sentUnix, err := parseInt63(timestamp)
	if err != nil {
		return WorkOSEvent{}, ErrUnverified
	}
	sent := time.Unix(sentUnix, 0)
	if now.Sub(sent) > SignatureTolerance {
		return WorkOSEvent{}, ErrUnverified
	}
	if sent.Sub(now) > FutureSkew {
		return WorkOSEvent{}, ErrUnverified
	}
	sigs, ok := parseSvixSignatures(signature)
	if !ok {
		return WorkOSEvent{}, ErrUnverified
	}
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s.%s.%s", id, timestamp, body)
	expected := mac.Sum(nil)
	matched := false
	for _, sig := range sigs {
		raw, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(raw, expected) == 1 {
			matched = true
			break
		}
	}
	if !matched {
		return WorkOSEvent{}, ErrUnverified
	}
	var env workOSEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return WorkOSEvent{}, ErrUnverified
	}
	if env.ID == "" || env.Event == "" || len(env.Data) == 0 {
		return WorkOSEvent{}, ErrUnverified
	}
	if env.ID != id {
		// The signed delivery ID and the envelope ID disagree. One of them
		// is not describing this delivery.
		return WorkOSEvent{}, ErrUnverified
	}
	return WorkOSEvent{ID: id, Type: env.Event, Created: sent.UTC(), Data: env.Data}, nil
}

// workOSKey decodes the endpoint secret, tolerating the whsec_ prefix Svix
// shows it with. The secret is decoded for use and never stored.
func workOSKey(secret string) ([]byte, bool) {
	trimmed := strings.TrimPrefix(secret, "whsec_")
	if trimmed == "" {
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil || len(raw) == 0 {
		return nil, false
	}
	return raw, true
}

// parseSvixSignatures splits a svix-signature value into its v1 candidates.
// Only v1 is accepted, for the same reason only Stripe's v1 is.
func parseSvixSignatures(header string) ([]string, bool) {
	var sigs []string
	for _, part := range strings.Fields(header) {
		kv := strings.SplitN(part, ",", 2)
		if len(kv) != 2 || kv[0] != "v1" || kv[1] == "" {
			return nil, false
		}
		sigs = append(sigs, kv[1])
	}
	if len(sigs) == 0 {
		return nil, false
	}
	return sigs, true
}

// IdentityKind names the identity fact a verified WorkOS event carries.
type IdentityKind string

const (
	// IdentityUserCreated carries a new user: id and email, both required.
	IdentityUserCreated IdentityKind = "user_created"
	// IdentityUserUpdated carries a changed user for the transport to
	// reconcile.
	IdentityUserUpdated IdentityKind = "user_updated"
	// IdentityUserDeleted carries a removed user: the transport revokes
	// every session for the principal without needing the session IDs.
	IdentityUserDeleted IdentityKind = "user_deleted"
	// IdentityMembershipCreated carries a new organization membership.
	IdentityMembershipCreated IdentityKind = "membership_created"
	// IdentityMembershipDeleted carries a removed organization membership:
	// the grant it conferred ends with it.
	IdentityMembershipDeleted IdentityKind = "membership_deleted"
)

// IdentityIntent is a verified, understood WorkOS event ready for the
// transport to apply.
type IdentityIntent struct {
	Kind           IdentityKind
	EventID        string
	UserID         string
	Email          string
	OrganizationID string
	MembershipID   string
	At             time.Time
}

// ClassifyWorkOS turns a verified WorkOS event into the intent the transport
// applies. Types outside the consumed set are ErrUnknownEvent.
func ClassifyWorkOS(event WorkOSEvent) (IdentityIntent, error) {
	if event.ID == "" || event.Type == "" || event.Created.IsZero() {
		return IdentityIntent{}, ErrInvalidEvent
	}
	switch event.Type {
	case "user.created", "user.updated", "user.deleted":
		user, email, err := workOSUser(event.Data)
		if err != nil {
			return IdentityIntent{}, err
		}
		var kind IdentityKind
		switch event.Type {
		case "user.created":
			kind = IdentityUserCreated
		case "user.updated":
			kind = IdentityUserUpdated
		default:
			kind = IdentityUserDeleted
		}
		return IdentityIntent{Kind: kind, EventID: event.ID, UserID: user, Email: email, At: event.Created}, nil
	case "organization_membership.created", "organization_membership.deleted":
		membership, user, org, err := workOSMembership(event.Data)
		if err != nil {
			return IdentityIntent{}, err
		}
		kind := IdentityMembershipCreated
		if event.Type == "organization_membership.deleted" {
			kind = IdentityMembershipDeleted
		}
		return IdentityIntent{Kind: kind, EventID: event.ID, MembershipID: membership, UserID: user, OrganizationID: org, At: event.Created}, nil
	default:
		return IdentityIntent{}, ErrUnknownEvent
	}
}

// workOSUser extracts the user ID and email. A user event without an email
// names an account the platform cannot contact or verify, so it is refused.
func workOSUser(raw json.RawMessage) (user, email string, err error) {
	var data struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", "", ErrInvalidEvent
	}
	if data.ID == "" || data.Email == "" {
		return "", "", ErrInvalidEvent
	}
	return data.ID, data.Email, nil
}

// workOSMembership extracts the membership, user and organization. All three
// are required: a grant that cannot name its holder, its organization or
// itself confers nothing.
func workOSMembership(raw json.RawMessage) (membership, user, org string, err error) {
	var data struct {
		ID             string `json:"id"`
		UserID         string `json:"user_id"`
		OrganizationID string `json:"organization_id"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", "", "", ErrInvalidEvent
	}
	if data.ID == "" || data.UserID == "" || data.OrganizationID == "" {
		return "", "", "", ErrInvalidEvent
	}
	return data.ID, data.UserID, data.OrganizationID, nil
}

// Inbox is the duplicate memory: the bounded set of event IDs already
// recorded. Genuine, understood, already-seen deliveries are acknowledged
// without applying; the zero value is not usable, because an unbounded
// inbox is a memory allocation the sender controls.
type Inbox struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	order []string
	max   int
}

// NewInbox returns an inbox recording at most max event IDs. A non-positive
// max is refused: an inbox that holds nothing acknowledges everything twice.
func NewInbox(max int) (*Inbox, error) {
	if max <= 0 {
		return nil, ErrInboxFull
	}
	return &Inbox{seen: make(map[string]struct{}), max: max}, nil
}

// Accept records id and reports whether it was already seen. An empty ID is
// refused — a delivery that cannot name itself cannot be deduplicated — and a
// full inbox refuses new IDs rather than evicting old ones into
// double-application. seen=true means acknowledge without applying;
// seen=false means the caller applies the intent exactly once.
func (b *Inbox) Accept(id string) (seen bool, err error) {
	if id == "" {
		return false, ErrInvalidEvent
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.seen[id]; ok {
		return true, nil
	}
	if len(b.order) >= b.max {
		return false, ErrInboxFull
	}
	b.seen[id] = struct{}{}
	b.order = append(b.order, id)
	return false, nil
}

// Seen reports whether id was recorded. It is the read half of Accept for
// transports that check before they verify.
func (b *Inbox) Seen(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.seen[id]
	return ok
}

// Count reports how many IDs are recorded.
func (b *Inbox) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.order)
}
