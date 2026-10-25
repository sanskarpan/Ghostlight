// Package stripe is the transport half of billing: it turns validated
// checkout and portal requests into Stripe API calls and Stripe answers into
// typed outcomes.
//
// `internal/billing` decides what may be bought and how verified intents move
// a subscription. This package does the calling: session creation against the
// API, idempotency keys on every mutation, and an error mapping that tells
// the caller whether to retry. The split is deliberate — policy never touches
// the network, and the network never decides policy.
//
// Five rules shape the transport.
//
// The first is that **the secret never travels except to Stripe, and never
// appears in an error**. It is sent as a bearer token over https, it is never
// logged, and every error path is asserted in tests to be free of it. A
// credential that reaches a log is a credential rotation with an audience.
//
// The second is that **cleartext is refused except to loopback**. The default
// base URL is the Stripe API; overriding it exists so tests can point at a
// contract fake, and the only non-https override permitted is localhost. A
// test double that teaches the transport to speak http to the real API is a
// downgrade waiting for a configuration mistake.
//
// The third is that **every mutation carries a caller-chosen idempotency
// key**. Retrying session creation without a key creates a second session,
// and a second session is a second checkout link for the same customer —
// exactly one of which will be paid, leaving the other to confuse dunning.
// An empty key is refused rather than generated, because a generated key
// cannot be regenerated identically on retry, which is the only retry that
// matters.
//
// The fourth is that **a Stripe error is mapped, not forwarded**. The API's
// envelope is translated into one of this package's errors carrying whether
// the caller may retry: rate limits and server faults yes, authentication,
// idempotency and invalid-request faults no. The raw message is preserved for
// the operator, but the decision is made here, once, rather than by every
// caller guessing from a string.
//
// The fifth is that **a session missing its URL is not a session**. A 200
// with no checkout URL sends the customer nowhere, which reads as success
// and behaves as a dead end. It is refused.
//
// What this package does not do is decide anything about plans, trials,
// prices or URLs — that is `internal/billing`, whose validated requests are
// the only input accepted — nor does it verify webhooks, which is
// `internal/providerinbox`. And it does not claim the sandbox works: the
// tests run against a contract fake that mirrors the documented API shapes,
// and the live sandbox integration remains the outstanding GQ.4/G7.3 item.
package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/entitlements"
)

// APIBase is the live Stripe API. Overrides exist for contract fakes.
const APIBase = "https://api.stripe.com"

// Errors returned by this package.
var (
	// ErrNoSecret means no API key was configured. Anonymous calls are not
	// attempted: an unauthenticated call that "works" in a test is a call
	// that will fail everywhere else.
	ErrNoSecret = errors.New("stripe transport has no API secret")
	// ErrBadBase means the base URL is not usable: unparseable, not https
	// outside loopback, or carrying userinfo.
	ErrBadBase = errors.New("stripe transport base URL is not usable")
	// ErrNoIdempotencyKey means a mutation was attempted without a caller
	// key. Keys are caller-chosen so a retry can repeat them exactly.
	ErrNoIdempotencyKey = errors.New("stripe mutation requires a caller idempotency key")
	// ErrUnauthorized means the API rejected the key. Retrying with the same
	// key authenticates the same failure.
	ErrUnauthorized = errors.New("stripe rejected the API key")
	// ErrInvalidRequest means the API refused the parameters. Retrying the
	// same parameters fails the same way.
	ErrInvalidRequest = errors.New("stripe refused the request parameters")
	// ErrIdempotencyConflict means the key was reused with different
	// parameters. The first request won; the second must be rebuilt, not
	// retried.
	ErrIdempotencyConflict = errors.New("stripe idempotency key already used with different parameters")
	// ErrRateLimited means the API asked for less traffic. The caller may
	// retry with backoff.
	ErrRateLimited = errors.New("stripe rate limit hit")
	// ErrProviderFault means Stripe errored on its side. The caller may
	// retry; the same key keeps the retry safe.
	ErrProviderFault = errors.New("stripe API faulted")
	// ErrNoSessionURL means the API answered success without a usable
	// session URL. There is nowhere to send the customer.
	ErrNoSessionURL = errors.New("stripe session has no URL")
	// ErrBadResponse means the transport and the API disagree about the
	// shape of an answer. Application stops rather than guessing.
	ErrBadResponse = errors.New("stripe response is not shaped like a session or an error")
)

// Reportable reports whether the operation may be retried. Retrying a
// refusal loops; retrying a rate limit or a server fault is the recovery.
func Reportable(err error) bool {
	return errors.Is(err, ErrRateLimited) || errors.Is(err, ErrProviderFault)
}

// Client calls the Stripe API.
type Client struct {
	http *http.Client
	base string
	key  string
	// MaxBodyBytes bounds API answers. Envelopes are small; an unbounded
	// read is a memory allocation the other side controls.
	maxBody int64
}

// New returns a client for base with secret. An empty base selects the live
// API. The secret is held for calls and never exposed: there is no accessor,
// no String method, and no error carries it.
func New(base, secret string, timeout time.Duration) (*Client, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, ErrNoSecret
	}
	if strings.TrimSpace(base) == "" {
		base = APIBase
	}
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || !u.IsAbs() {
		return nil, fmt.Errorf("%w: %q is not absolute", ErrBadBase, base)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: userinfo in base URL", ErrBadBase)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		host := strings.ToLower(u.Hostname())
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			return nil, fmt.Errorf("%w: cleartext outside loopback", ErrBadBase)
		}
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		http:    &http.Client{Timeout: timeout},
		base:    strings.TrimSuffix(u.String(), "/"),
		key:     secret,
		maxBody: 1 << 20,
	}, nil
}

// Session is a created checkout or portal session: where to send the
// customer, and the ID the webhook will later name.
type Session struct {
	// ID is the Stripe session ID, the key webhooks arrive under.
	ID string
	// URL is where the customer goes. Always absolute https.
	URL string
}

// CheckoutParams are the transport inputs for a checkout session. The
// request must already be validated by billing.RequestCheckout; the price is
// the Stripe price ID for the plan; the key makes retries safe.
type CheckoutParams struct {
	// Request is the validated checkout. Its plan, customer and URLs are
	// used as given because they were already policed.
	Request ValidatedCheckout
	// PriceID is the Stripe price billed. It must look like a Stripe price.
	PriceID string
	// IdempotencyKey is the caller key for this creation. Required.
	IdempotencyKey string
	// ClientReference binds the session to the platform record. Required,
	// because a session that names nothing cannot be reconciled.
	ClientReference string
	// AllowedHosts re-binds the URLs at send time. The validation layer
	// already policed them; the transport refuses to send money to a host
	// outside this list even if the caller bypassed validation, because a
	// transport that trusts its caller is a confused deputy.
	AllowedHosts []string
}

// ValidatedCheckout is the subset of billing.CheckoutRequest the transport
// reads. It is defined here so the transport depends on values, not on
// another package's constructor — the caller passes the validated request
// field by field, and anything unvalidated fails below.
type ValidatedCheckout struct {
	CustomerID string
	PlanID     entitlements.PlanID
	SuccessURL string
	CancelURL  string
}

// CheckoutRequestOf lifts a validated billing checkout into transport
// params. The lifting is explicit so the call site shows the price and the
// key being bound to the validated request.
func CheckoutRequestOf(customerID string, planID entitlements.PlanID, successURL, cancelURL, priceID, key, reference string, allowedHosts []string) CheckoutParams {
	return CheckoutParams{
		Request:         ValidatedCheckout{CustomerID: customerID, PlanID: planID, SuccessURL: successURL, CancelURL: cancelURL},
		PriceID:         priceID,
		IdempotencyKey:  key,
		ClientReference: reference,
		AllowedHosts:    allowedHosts,
	}
}

// PortalParams are the transport inputs for a portal session.
type PortalParams struct {
	// CustomerID is the platform customer. Required.
	CustomerID string
	// ReturnURL is where the portal returns the customer. Required, and
	// re-bound against AllowedHosts at send time like checkout URLs.
	ReturnURL string
	// IdempotencyKey is the caller key for this creation. Required.
	IdempotencyKey string
	// AllowedHosts re-binds the return URL at send time.
	AllowedHosts []string
}

// CreateCheckoutSession creates a subscription-mode checkout session.
func (c *Client) CreateCheckoutSession(ctx context.Context, p CheckoutParams) (Session, error) {
	if strings.TrimSpace(p.Request.CustomerID) == "" {
		return Session{}, fmt.Errorf("%w: checkout names no customer", ErrInvalidRequest)
	}
	if strings.TrimSpace(string(p.Request.PlanID)) == "" || p.Request.PlanID == entitlements.PlanTrial {
		return Session{}, fmt.Errorf("%w: checkout needs a paid plan", ErrInvalidRequest)
	}
	if !looksLikePrice(p.PriceID) {
		return Session{}, fmt.Errorf("%w: %q", ErrInvalidRequest, p.PriceID)
	}
	for _, u := range []struct {
		kind, raw string
	}{
		{"success", p.Request.SuccessURL},
		{"cancel", p.Request.CancelURL},
	} {
		if !boundHost(u.raw, p.AllowedHosts) {
			return Session{}, fmt.Errorf("%w: %s URL is not bound to an allowed host", ErrInvalidRequest, u.kind)
		}
	}
	if strings.TrimSpace(p.IdempotencyKey) == "" {
		return Session{}, ErrNoIdempotencyKey
	}
	if strings.TrimSpace(p.ClientReference) == "" {
		return Session{}, fmt.Errorf("%w: checkout needs a client reference", ErrInvalidRequest)
	}
	form := url.Values{}
	form.Set("mode", "subscription")
	form.Set("customer", strings.TrimSpace(p.Request.CustomerID))
	form.Set("line_items[0][price]", p.PriceID)
	form.Set("line_items[0][quantity]", "1")
	form.Set("success_url", p.Request.SuccessURL)
	form.Set("cancel_url", p.Request.CancelURL)
	form.Set("client_reference_id", strings.TrimSpace(p.ClientReference))
	return c.post(ctx, "/v1/checkout/sessions", form, p.IdempotencyKey)
}

// CreatePortalSession creates a customer portal session.
func (c *Client) CreatePortalSession(ctx context.Context, p PortalParams) (Session, error) {
	if strings.TrimSpace(p.CustomerID) == "" {
		return Session{}, fmt.Errorf("%w: portal names no customer", ErrInvalidRequest)
	}
	if !boundHost(p.ReturnURL, p.AllowedHosts) {
		return Session{}, fmt.Errorf("%w: return URL is not bound to an allowed host", ErrInvalidRequest)
	}
	if strings.TrimSpace(p.IdempotencyKey) == "" {
		return Session{}, ErrNoIdempotencyKey
	}
	form := url.Values{}
	form.Set("customer", strings.TrimSpace(p.CustomerID))
	form.Set("return_url", strings.TrimSpace(p.ReturnURL))
	return c.post(ctx, "/v1/billing_portal/sessions", form, p.IdempotencyKey)
}

func looksLikePrice(price string) bool {
	return strings.HasPrefix(price, "price_") && len(price) >= len("price_")+8
}

func isHTTPS(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	return u.User == nil && u.Hostname() != ""
}

// boundHost reports whether raw is an absolute https URL on one of the
// allowed bare hostnames. It mirrors the validation layer's rule so the
// transport holds the same boundary: an allowlist checked once, by the
// caller, is a promise, not a control.
func boundHost(raw string, allowed []string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	if u.User != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.ContainsAny(host, "/?#@:") {
		return false
	}
	for _, h := range allowed {
		if host == strings.ToLower(strings.TrimSpace(h)) && strings.TrimSpace(h) != "" {
			return true
		}
	}
	return false
}

// stripeError is the API's error envelope.
type stripeError struct {
	Error struct {
		Type    string `json:"type"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// stripeSession is the successful session shape. Only the two fields the
// transport needs are decoded; the rest is Stripe's business.
type stripeSession struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// post sends one form-encoded mutation with its idempotency key and maps the
// answer. The secret travels in the Authorization header and in no error.
func (c *Client) post(ctx context.Context, path string, form url.Values, key string) (Session, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, strings.NewReader(form.Encode()))
	if err != nil {
		return Session{}, fmt.Errorf("%w: %v", ErrProviderFault, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Idempotency-Key", key)
	resp, err := c.http.Do(req)
	if err != nil {
		return Session{}, fmt.Errorf("%w: %v", ErrProviderFault, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody))
	if err != nil {
		return Session{}, fmt.Errorf("%w: unreadable answer", ErrProviderFault)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Session{}, mapError(resp.StatusCode, body)
	}
	var session stripeSession
	if err := json.Unmarshal(body, &session); err != nil {
		return Session{}, fmt.Errorf("%w: answer is not JSON", ErrBadResponse)
	}
	if strings.TrimSpace(session.ID) == "" {
		return Session{}, fmt.Errorf("%w: answer names no session", ErrBadResponse)
	}
	if !isHTTPS(session.URL) {
		return Session{}, fmt.Errorf("%w: %q", ErrNoSessionURL, redactURL(session.URL))
	}
	return Session{ID: session.ID, URL: session.URL}, nil
}

// mapError translates a non-2xx answer into a typed error with its retry
// guidance. Unknown shapes are provider faults, not caller faults: when the
// transport cannot read the answer, it must not blame the request.
func mapError(status int, body []byte) error {
	var envelope stripeError
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Error.Type == "" {
		if status == http.StatusTooManyRequests {
			return fmt.Errorf("%w: status 429 with an unreadable envelope", ErrRateLimited)
		}
		if status >= 500 {
			return fmt.Errorf("%w: status %d with an unreadable envelope", ErrProviderFault, status)
		}
		return fmt.Errorf("%w: status %d with an unreadable envelope", ErrBadResponse, status)
	}
	detail := strings.TrimSpace(envelope.Error.Message)
	if detail == "" {
		detail = envelope.Error.Type
		if envelope.Error.Code != "" {
			detail += "/" + envelope.Error.Code
		}
	}
	switch envelope.Error.Type {
	case "authentication_error":
		return fmt.Errorf("%w: %s", ErrUnauthorized, detail)
	case "invalid_request_error":
		return fmt.Errorf("%w: %s", ErrInvalidRequest, detail)
	case "idempotency_error":
		return fmt.Errorf("%w: %s", ErrIdempotencyConflict, detail)
	case "rate_limit_error":
		return fmt.Errorf("%w: %s", ErrRateLimited, detail)
	case "card_error":
		// A card error names the customer's card, not this call. It is a
		// refusal of the payment method, which the caller handles as a
		// billing event rather than a transport fault — and never by
		// retrying the identical call.
		return fmt.Errorf("%w: %s", ErrInvalidRequest, detail)
	case "api_error":
		return fmt.Errorf("%w: %s", ErrProviderFault, detail)
	default:
		if status == http.StatusTooManyRequests {
			return fmt.Errorf("%w: %s", ErrRateLimited, detail)
		}
		if status >= 500 {
			return fmt.Errorf("%w: %s", ErrProviderFault, detail)
		}
		return fmt.Errorf("%w: %s", ErrBadResponse, detail)
	}
}

// redactURL keeps a scheme and host for debugging while dropping any path or
// query that might carry a session secret.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "unparseable-url"
	}
	return u.Scheme + "://" + u.Hostname() + "/…"
}
