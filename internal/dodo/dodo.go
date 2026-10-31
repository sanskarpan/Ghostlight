// Package dodo is the Dodo Payments side of the provider inbox: it verifies
// that a delivery claiming to come from Dodo actually did, classifies the
// event into the platform's billing vocabulary, and applies it to the
// subscription record exactly once.
//
// `internal/providerinbox` proves Stripe and WorkOS deliveries genuine;
// this package does the same job for the provider chosen in ADR G-038.
// Dodo webhooks follow the Standard Webhooks specification — the same
// `webhook-id` / `webhook-timestamp` / `webhook-signature` shape as Svix —
// so the verification below mirrors the WorkOS verifier deliberately: one
// indistinguishable failure for every forgery shape, bounded timestamps,
// and a signature computed over `{id}.{timestamp}.{body}` with the
// base64-decoded secret (`whsec_` prefix tolerated).
//
// Five rules shape the receiver:
//
// The first is that **a failure is a failure, with no detail**. Wrong
// secret, tampered body, stale or future timestamp, mangled header, missing
// event type: all of these are ErrUnverified. Telling a forger which check
// tripped turns the endpoint into a signature oracle.
//
// The second is that **an unknown event type is refused, never ignored**.
// Dodo adds event types without asking. An inbox that acknowledges what it
// does not understand loses data with a success status, which is the one
// outcome nobody investigates.
//
// The third is that **an intent must name its subscription and its
// customer**. A delivery that cannot name both is a fact about nothing and
// is refused rather than guessed at. The customer is read from
// `data.customer_id`, `data.customer.customer_id` or `data.customer.id`, in
// that order — the first present wins — because the payload shape varies by
// event family and guessing across families is how one customer's payment
// moves another customer's subscription.
//
// The fourth is that **a renewal is not a restoration, and an observation
// is not an application**. `payment.succeeded` and `subscription.renewed`
// against a record with no outstanding failure change nothing and say so;
// routine `subscription.updated` traffic and a `subscription.failed`
// creation (which names no subscription that exists) are observed without
// moving state. Genuine conflicts — a start for an already-converted
// record carrying a different plan — are errors, because silently resolving
// a conflict is how one subscription starts billing another's plan.
//
// The fifth is that **another business's event cannot move our records**.
// When the receiver is constructed with an expected business ID, a delivery
// whose `business_id` differs is refused before anything else is read. The
// signature already binds the delivery to our endpoint, but a check that is
// not written down is a check nobody can review.
//
// What this package does not do is hold a secret beyond the call, touch the
// network, or persist anything: the duplicate memory and the subscription
// records live in the Receiver, which the transport owns and which is
// explicitly in-memory. Test-mode deliveries are safe to replay against it;
// production needs the durable store, which does not exist yet and is not
// claimed here.
package dodo

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/billing"
	"github.com/sanskarpan/Ghostlight/internal/entitlements"
	"github.com/sanskarpan/Ghostlight/internal/providerinbox"
	"github.com/sanskarpan/Ghostlight/internal/subscription"
)

// Verification bounds mirror internal/providerinbox: the signature timestamp
// proves the delivery is fresh; the event's own timestamp only has to sit
// inside the retry horizon. Dodo retries for days; the signature proves
// freshness while the event time only has to prove the event is not from the
// future and not older than the horizon.
const (
	// SignatureTolerance is how old a delivery signature may be. Older than
	// this, a valid signature is a replay until proven otherwise.
	SignatureTolerance = 5 * time.Minute
	// FutureSkew is how far ahead of now a timestamp may be before it is a
	// clock problem rather than drift.
	FutureSkew = time.Minute
	// MaxEventAge is how old the event itself may be. Older than this, the
	// event belongs to an operator investigation, not to automatic
	// application.
	MaxEventAge = 72 * time.Hour
	// MaxBodyBytes bounds the delivery accepted for verification. Webhook
	// envelopes are small; an unbounded read is a memory allocation the
	// sender controls.
	MaxBodyBytes = 1 << 20
	// MaxSeenIDs bounds the duplicate memory. Full means refuse, not evict.
	MaxSeenIDs = 4096
)

// Errors returned by this package.
var (
	// ErrUnverified means the delivery cannot be proven genuine. Every
	// verification failure is this one error, with no detail.
	ErrUnverified = errors.New("dodo delivery cannot be verified")
	// ErrUnknownEvent means a genuine delivery carries an event type this
	// receiver does not consume. It is refused, not ignored.
	ErrUnknownEvent = errors.New("dodo event type is not consumed")
	// ErrInvalidEvent means a genuine, consumed event type arrives without
	// the fields the type requires, or names a business that is not ours.
	// The receiver refuses rather than guessing.
	ErrInvalidEvent = errors.New("dodo event payload is missing required fields")
	// ErrDuplicate means the event ID has already been recorded. The
	// delivery is genuine and understood; it must be acknowledged without
	// applying.
	ErrDuplicate = errors.New("dodo event already recorded")
	// ErrUnknownSubscription means the intent names a subscription the
	// receiver has no record for, and the intent is not a start that would
	// create one. Applying a failure to a record that does not exist would
	// manufacture state.
	ErrUnknownSubscription = errors.New("dodo intent names an unknown subscription")
	// ErrUnknownProduct means a start names a Dodo product ID that maps to
	// no approved plan. An unmapped product is refused rather than guessed,
	// because guessing is how a customer is billed for a plan they never
	// chose.
	ErrUnknownProduct = errors.New("dodo product maps to no approved plan")
)

// Event is a verified Dodo delivery.
type Event struct {
	// ID is the webhook-id header value, the duplicate key.
	ID string
	// Type is the event type, for example subscription.active.
	Type string
	// Sent is the webhook-timestamp header time, the freshness proof.
	Sent time.Time
	// OccurredAt is the payload timestamp, when the event happened. Zero
	// when the payload carries none, in which case Sent dates the intent.
	OccurredAt time.Time
	// BusinessID is the payload business_id.
	BusinessID string
	// Data is the event payload, unparsed.
	Data json.RawMessage
}

// At dates the billing intent. The payload's own timestamp wins when it
// parses, because it says when the money fact happened; the send time is
// the fallback, and both are fixed per event ID so a redelivery applies
// identically.
func (e Event) At() time.Time {
	if !e.OccurredAt.IsZero() {
		return e.OccurredAt
	}
	return e.Sent
}

// envelope is the Dodo event shape. Only the fields the receiver needs are
// decoded; the rest is not the receiver's business.
type envelope struct {
	BusinessID string          `json:"business_id"`
	Type       string          `json:"type"`
	Timestamp  string          `json:"timestamp"`
	Data       json.RawMessage `json:"data"`
}

// VerifyDodo proves a delivery came from Dodo and parses its envelope.
//
// secret is the endpoint signing secret (whsec_ prefix tolerated), body the
// raw request body, id/timestamp/signature the webhook-id, webhook-timestamp
// and webhook-signature header values, and now the moment of verification.
// The secret is used and never kept.
func Verify(secret string, body []byte, id, timestamp, signature string, now time.Time) (Event, error) {
	if now.IsZero() {
		return Event{}, ErrUnverified
	}
	if len(body) == 0 || len(body) > MaxBodyBytes {
		return Event{}, ErrUnverified
	}
	if strings.TrimSpace(id) == "" {
		return Event{}, ErrUnverified
	}
	sentUnix, err := parseInt63(timestamp)
	if err != nil {
		return Event{}, ErrUnverified
	}
	sent := time.Unix(sentUnix, 0)
	if now.Sub(sent) > SignatureTolerance {
		return Event{}, ErrUnverified
	}
	if sent.Sub(now) > FutureSkew {
		return Event{}, ErrUnverified
	}
	key, ok := decodeSecret(secret)
	if !ok {
		return Event{}, ErrUnverified
	}
	sigs, ok := parseSignatures(signature)
	if !ok {
		return Event{}, ErrUnverified
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
		return Event{}, ErrUnverified
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return Event{}, ErrUnverified
	}
	if strings.TrimSpace(env.Type) == "" || len(env.Data) == 0 {
		return Event{}, ErrUnverified
	}
	var occurred time.Time
	if strings.TrimSpace(env.Timestamp) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(env.Timestamp))
		if err != nil {
			return Event{}, ErrUnverified
		}
		if parsed.Sub(now) > FutureSkew {
			return Event{}, ErrUnverified
		}
		if now.Sub(parsed) > MaxEventAge {
			return Event{}, ErrUnverified
		}
		occurred = parsed.UTC()
	}
	return Event{
		ID:         id,
		Type:       env.Type,
		Sent:       sent.UTC(),
		OccurredAt: occurred,
		BusinessID: env.BusinessID,
		Data:       env.Data,
	}, nil
}

// decodeSecret decodes the endpoint secret, tolerating the whsec_ prefix
// Dodo shows it with. The secret is decoded for use and never stored.
func decodeSecret(secret string) ([]byte, bool) {
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

// parseSignatures splits a webhook-signature header into its v1 candidates.
// Only v1 is accepted: accepting a legacy scheme alongside it doubles the
// forgery surface for no honest sender's benefit.
func parseSignatures(header string) ([]string, bool) {
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

func parseInt63(s string) (int64, error) {
	var n int64
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("not a timestamp")
	}
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

// Intent is a verified, understood Dodo event ready to apply. ProductID is
// the Dodo product the subscription was bought under; the transport resolves
// it to an approved plan, and an unmapped product refuses rather than
// defaulting.
type Intent struct {
	Billing   providerinbox.BillingIntent
	ProductID string
}

// kindOf maps a Dodo event type to the platform's billing vocabulary.
// subscription.failed is deliberately an observation, not a failure: a
// failed creation names no subscription that exists, so there is nothing to
// record a failure against, and a 400 on it would retry eight times to no
// effect. payment.processing and payment.cancelled are likewise observed:
// money in flight or withdrawn is not money overdue.
func kindOf(typ string) (providerinbox.BillingKind, error) {
	switch typ {
	case "payment.succeeded":
		return providerinbox.BillingPaymentRecovered, nil
	case "payment.failed":
		return providerinbox.BillingPaymentFailed, nil
	case "payment.processing", "payment.cancelled":
		return providerinbox.BillingSubscriptionUpdated, nil
	case "subscription.active":
		return providerinbox.BillingSubscriptionStarted, nil
	case "subscription.renewed", "subscription.unpaused":
		return providerinbox.BillingPaymentRecovered, nil
	case "subscription.on_hold", "subscription.past_due":
		return providerinbox.BillingPaymentFailed, nil
	case "subscription.updated", "subscription.paused", "subscription.plan_changed",
		"subscription.update_payment_method", "subscription.failed":
		return providerinbox.BillingSubscriptionUpdated, nil
	case "subscription.cancelled", "subscription.expired":
		return providerinbox.BillingSubscriptionCancelled, nil
	default:
		return "", ErrUnknownEvent
	}
}

// Classify turns a verified event into the intent the transport applies.
// businessID, when non-empty, must equal the payload's business_id; an
// event for another business is refused before anything else is read.
func Classify(event Event, businessID string) (Intent, error) {
	if event.ID == "" || event.Type == "" || event.Sent.IsZero() {
		return Intent{}, ErrInvalidEvent
	}
	if businessID != "" && event.BusinessID != businessID {
		return Intent{}, fmt.Errorf("%w: event is for another business", ErrInvalidEvent)
	}
	kind, err := kindOf(event.Type)
	if err != nil {
		return Intent{}, err
	}
	subscriptionID := dodoString(event.Data, "subscription_id")
	if subscriptionID == "" {
		return Intent{}, fmt.Errorf("%w: %s names no subscription", ErrInvalidEvent, event.Type)
	}
	customerID := dodoCustomer(event.Data)
	if customerID == "" {
		return Intent{}, fmt.Errorf("%w: %s names no customer", ErrInvalidEvent, event.Type)
	}
	return Intent{
		Billing: providerinbox.BillingIntent{
			Kind:           kind,
			EventID:        event.ID,
			CustomerID:     customerID,
			SubscriptionID: subscriptionID,
			At:             event.At(),
		},
		ProductID: dodoProduct(event.Data),
	}, nil
}

// dodoString reads the first present non-empty string field at the given
// top-level keys of a data object.
func dodoString(raw json.RawMessage, keys ...string) string {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return ""
	}
	for _, k := range keys {
		var s string
		if err := json.Unmarshal(object[k], &s); err == nil && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// dodoCustomer extracts the customer ID, trying the documented shapes in
// order: a top-level customer_id, then a nested customer object carrying
// customer_id or id. The first present value wins; nothing is defaulted.
func dodoCustomer(raw json.RawMessage) string {
	if id := dodoString(raw, "customer_id"); id != "" {
		return id
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return ""
	}
	var customer map[string]json.RawMessage
	if err := json.Unmarshal(object["customer"], &customer); err != nil {
		return ""
	}
	for _, k := range []string{"customer_id", "id"} {
		var s string
		if err := json.Unmarshal(customer[k], &s); err == nil && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// dodoProduct extracts the Dodo product ID: a top-level product_id, then a
// nested product object's id. Empty is not an error here; the transport
// refuses an unmapped product when it needs a plan, and never needs one for
// intents that change nothing.
func dodoProduct(raw json.RawMessage) string {
	if id := dodoString(raw, "product_id"); id != "" {
		return id
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return ""
	}
	var product map[string]json.RawMessage
	if err := json.Unmarshal(object["product"], &product); err != nil {
		return ""
	}
	var s string
	if err := json.Unmarshal(product["id"], &s); err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// ParseProductPlans validates a product-to-plan mapping of the form
// "prod_abc:team,prod_def:growth". Every target must be an approved catalog
// plan; an empty spec means no products mapped, which is allowed — a start
// naming an unmapped product is then refused per delivery. A malformed spec
// is refused outright, because a mapping nobody can read strictly is a
// mapping nobody can audit.
func ParseProductPlans(spec string) (map[string]entitlements.PlanID, error) {
	out := make(map[string]entitlements.PlanID)
	if strings.TrimSpace(spec) == "" {
		return out, nil
	}
	for _, entry := range strings.Split(spec, ",") {
		kv := strings.SplitN(strings.TrimSpace(entry), ":", 2)
		if len(kv) != 2 || strings.TrimSpace(kv[0]) == "" || strings.TrimSpace(kv[1]) == "" {
			return nil, fmt.Errorf("%w: %q is not product:plan", ErrUnknownProduct, entry)
		}
		product, plan := strings.TrimSpace(kv[0]), entitlements.PlanID(strings.TrimSpace(kv[1]))
		if _, err := entitlements.Lookup(plan); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrUnknownProduct, plan)
		}
		if _, dup := out[product]; dup {
			return nil, fmt.Errorf("%w: duplicate product %q", ErrUnknownProduct, product)
		}
		out[product] = plan
	}
	return out, nil
}

// memoryStore is the in-memory RecordStore: the receiver's original home
// and the no-database fallback. Everything it holds is forgotten on
// restart, which callers must report honestly rather than hide.
type memoryStore struct {
	mu   sync.Mutex
	subs map[string]subscription.Subscription
	seen map[string]string
}

// NewMemoryStore returns an empty in-memory record store.
func NewMemoryStore() billing.RecordStore {
	return &memoryStore{subs: make(map[string]subscription.Subscription), seen: make(map[string]string)}
}

func (m *memoryStore) Get(_ context.Context, customerID, subscriptionID string) (subscription.Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sub := range m.subs {
		if sub.ID == subscriptionID && sub.CustomerID == customerID {
			return sub, nil
		}
	}
	return subscription.Subscription{}, billing.ErrNotFound
}

func (m *memoryStore) Put(_ context.Context, sub subscription.Subscription) error {
	if strings.TrimSpace(sub.ID) == "" || strings.TrimSpace(sub.CustomerID) == "" {
		return fmt.Errorf("%w: subscription record names no id or no customer", subscription.ErrInvalidFact)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subs[sub.ID] = sub
	return nil
}

func (m *memoryStore) Seen(_ context.Context, _ string, eventID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.seen[eventID]
	return ok, nil
}

func (m *memoryStore) Mark(_ context.Context, _, eventID, subscriptionID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.seen[eventID]; ok {
		return false, nil
	}
	m.seen[eventID] = subscriptionID
	return true, nil
}

// Receiver is the Dodo webhook endpoint: it verifies, classifies,
// deduplicates and applies deliveries to the subscription records in its
// store. The store is owned by the transport: an in-memory store forgets
// everything on restart (documented, for development), while a durable
// store remembers records and delivery IDs across restarts — which is what
// makes a redelivery after a crash a duplicate instead of a second
// application.
type Receiver struct {
	secret     string
	businessID string
	plans      map[string]entitlements.PlanID
	store      billing.RecordStore
}

// NewReceiver returns a receiver that verifies with secret, optionally
// scopes to businessID (empty skips the check), resolves start plans
// through plans (nil maps nothing; unmapped products are refused
// per delivery, not at construction), and persists through store. A nil
// store is refused: a receiver that cannot remember cannot deduplicate,
// and one that cannot deduplicate will eventually apply twice.
func NewReceiver(secret, businessID string, plans map[string]entitlements.PlanID, store billing.RecordStore) (*Receiver, error) {
	if store == nil {
		return nil, errors.New("dodo receiver requires a record store: without one every restart is an amnesia event")
	}
	if plans == nil {
		plans = make(map[string]entitlements.PlanID)
	}
	return &Receiver{
		secret:     secret,
		businessID: businessID,
		plans:      plans,
		store:      store,
	}, nil
}

// Stored reports the record held for a Dodo subscription ID. It exists for
// tests and operators; the route never exposes records.
func (rc *Receiver) Stored(customerID, id string) (subscription.Subscription, bool) {
	sub, err := rc.store.Get(context.Background(), customerID, id)
	if err != nil {
		return subscription.Subscription{}, false
	}
	return sub, true
}

// writeJSON writes a response. Bodies are fixed-shape and carry no secrets.
func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ServeHTTP implements the webhook endpoint. Only POST is served: Dodo
// delivers by POST, and anything else is a probe or a mistake, refused
// rather than reinterpreted.
func (rc *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "method-not-allowed"})
		return
	}
	if strings.TrimSpace(rc.secret) == "" {
		// Fail closed without failing the process: the rest of the server
		// must not depend on billing being configured, but no delivery may
		// be acknowledged while it cannot be verified.
		writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "receiver-not-configured"})
		return
	}
	now := time.Now().UTC()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": "unreadable-body"})
		return
	}
	event, err := Verify(rc.secret, body, r.Header.Get("webhook-id"), r.Header.Get("webhook-timestamp"), r.Header.Get("webhook-signature"), now)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unverified"})
		return
	}
	intent, err := Classify(event, rc.businessID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": "refused"})
		return
	}
	ctx := r.Context()
	seen, err := rc.store.Seen(ctx, intent.Billing.CustomerID, intent.Billing.EventID)
	if err != nil {
		// The duplicate memory could not be read. Applying blindly risks a
		// second application, and refusing outright loses nothing: Dodo
		// retries, and a healthy store answers correctly on the retry.
		writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "unavailable"})
		return
	}
	if seen {
		writeJSON(w, http.StatusOK, map[string]any{"received": true, "applied": false, "duplicate": true})
		return
	}
	applied, code := rc.apply(ctx, intent)
	if code != http.StatusOK {
		writeJSON(w, code, map[string]any{"status": "refused"})
		return
	}
	if _, err := rc.store.Mark(ctx, intent.Billing.CustomerID, intent.Billing.EventID, intent.Billing.SubscriptionID); err != nil {
		// Applied but unrecorded: uncertain, not failed. The retry will
		// re-apply, and every application path is idempotent per event —
		// so this 500 converges rather than corrupting.
		writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"received": true, "applied": applied, "duplicate": false})
}

// apply moves one deduplicated intent into the records. A started
// subscription with no record is opened and bound to the provider's ID; any
// other intent for an unknown record is refused rather than manufacturing
// state. Mutations are written back to the store: an Apply that is not
// persisted is an Apply that never happened.
func (rc *Receiver) apply(ctx context.Context, intent Intent) (bool, int) {
	sub, err := rc.store.Get(ctx, intent.Billing.CustomerID, intent.Billing.SubscriptionID)
	if err != nil {
		if !errors.Is(err, billing.ErrNotFound) {
			return false, http.StatusInternalServerError
		}
		if intent.Billing.Kind != providerinbox.BillingSubscriptionStarted {
			return false, http.StatusBadRequest
		}
		planID, ok := rc.plans[intent.ProductID]
		if !ok {
			return false, http.StatusBadRequest
		}
		plan, err := entitlements.Lookup(planID)
		if err != nil {
			return false, http.StatusBadRequest
		}
		opened, err := billing.OpenSubscription(intent.Billing, plan)
		if err != nil {
			return false, http.StatusBadRequest
		}
		if err := rc.store.Put(ctx, opened); err != nil {
			return false, http.StatusInternalServerError
		}
		return true, http.StatusOK
	}
	var plan entitlements.Plan
	if intent.Billing.Kind == providerinbox.BillingSubscriptionStarted {
		planID, ok := rc.plans[intent.ProductID]
		if !ok {
			return false, http.StatusBadRequest
		}
		var err error
		plan, err = entitlements.Lookup(planID)
		if err != nil {
			return false, http.StatusBadRequest
		}
	}
	applied, err := billing.Apply(&sub, intent.Billing, plan)
	if err != nil {
		return false, http.StatusBadRequest
	}
	if applied {
		if err := rc.store.Put(ctx, sub); err != nil {
			return false, http.StatusInternalServerError
		}
	}
	return applied, http.StatusOK
}
