// Package resend sends transactional email through Resend, the provider
// chosen in ADR G-038.
//
// `internal/identity` mints verification tokens; this package carries them
// to inboxes. The two meet at the idempotency key: the same send retried
// must produce one email, because a verification email delivered twice is a
// token presented twice waiting to happen. Resend deduplicates on the
// Idempotency-Key header (same key with the same body returns the original
// send; same key with a different body is a 409 conflict), and the fake in
// the tests enforces the same contract so retries are proven safe without
// touching the network.
//
// Five rules shape the client, and every one of them is a refusal or a
// fail-closed mapping:
//
// The first is that **nothing is validated remotely that can be validated
// locally**. An empty recipient, an empty subject, no body at all, and more
// than fifty recipients are refused before any HTTP request exists. A
// client that lets the network be its validator turns every typo into a
// billable API call and teaches callers that validation is optional.
//
// The second is that **the secret travels one way**. It leaves in the
// Authorization header and never comes back: no error, log line, or
// response body rendered by this package names it, and the tests assert
// that invariant rather than trusting it.
//
// The third is that **a retry is identical or it is a conflict**. The
// idempotency key is caller-chosen and required on every send, because a
// transport that mints its own keys cannot deduplicate the caller's retry.
// Same key with the same body returns the original send without resending;
// same key with a different body is refused, because silently resolving the
// conflict is how one recipient gets another's token.
//
// The fourth is that **an API error is reported, not reinterpreted**.
// Non-2xx responses map to a typed error carrying the status and Resend's
// error name, with the response body truncated. Rewriting a 403 as a 400
// would send an operator to fix the request when the fix is a verified
// domain.
//
// The fifth is that **the test sender stays in tests**. `onboarding@resend.dev`
// with the `delivered@resend.dev` recipient is the documented simulation
// path; production sends from a verified domain, which this package cannot
// conjure and does not pretend to.
//
// What this package does not do is render templates, manage contacts or
// audiences, or receive webhooks. It sends one transactional email at a
// time and reports its ID.
package resend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// APIEndpoint is Resend's sending endpoint.
const APIEndpoint = "https://api.resend.com/emails"

// Limits mirror the API contract.
const (
	// MaxRecipients bounds one send. The API refuses more than fifty.
	MaxRecipients = 50
	// MaxBodyBytes bounds an API response read. Responses are small JSON
	// documents; an unbounded read is a memory allocation the server controls.
	MaxBodyBytes = 1 << 20
	// HTTPTimeout bounds one send. Notification must never hang a request
	// path indefinitely.
	HTTPTimeout = 30 * time.Second
)

// Errors returned by this package.
var (
	// ErrInvalidEmail means the request is malformed: no sender, no
	// recipient, no subject, no body, or too many recipients. Refused
	// before any network traffic.
	ErrInvalidEmail = errors.New("email request is invalid")
	// ErrConflict means the idempotency key was reused with a different
	// body. The first send stands; this one does not.
	ErrConflict = errors.New("idempotency key reused with a different email")
	// ErrSendFailed means Resend refused or the transport failed. The error
	// names the status and Resend's error name, never the secret.
	ErrSendFailed = errors.New("resend delivery failed")
)

// Email is one transactional email.
type Email struct {
	// From is the sender, for example "Acme <onboarding@resend.dev>" in
	// tests or an address on a verified domain in production.
	From string
	// To names up to MaxRecipients recipients.
	To []string
	// Subject is the subject line.
	Subject string
	// HTML is the HTML body. Exactly one of HTML and Text must be set.
	HTML string
	// Text is the plain-text body. Exactly one of HTML and Text must be set.
	Text string
	// IdempotencyKey deduplicates retries. Required on every send: a
	// transport that mints its own keys cannot deduplicate the caller's
	// retry.
	IdempotencyKey string
}

// validate refuses what the API would refuse, locally.
func (e Email) validate() error {
	if strings.TrimSpace(e.From) == "" {
		return fmt.Errorf("%w: no sender", ErrInvalidEmail)
	}
	if len(e.To) == 0 {
		return fmt.Errorf("%w: no recipient", ErrInvalidEmail)
	}
	if len(e.To) > MaxRecipients {
		return fmt.Errorf("%w: %d recipients exceeds %d", ErrInvalidEmail, len(e.To), MaxRecipients)
	}
	for _, to := range e.To {
		if strings.TrimSpace(to) == "" || !strings.Contains(to, "@") {
			return fmt.Errorf("%w: recipient %q is not an address", ErrInvalidEmail, to)
		}
	}
	if strings.TrimSpace(e.Subject) == "" {
		return fmt.Errorf("%w: no subject", ErrInvalidEmail)
	}
	if e.HTML != "" && e.Text != "" {
		return fmt.Errorf("%w: html and text are mutually exclusive", ErrInvalidEmail)
	}
	if e.HTML == "" && e.Text == "" {
		return fmt.Errorf("%w: no body", ErrInvalidEmail)
	}
	if strings.TrimSpace(e.IdempotencyKey) == "" || len(e.IdempotencyKey) > 256 {
		return fmt.Errorf("%w: idempotency key is required and bounded", ErrInvalidEmail)
	}
	return nil
}

// key returns the canonical dedup identity: the key plus the body it was
// first sent with. Same key with the same body is the same send; same key
// with anything else is a conflict.
func (e Email) key() string {
	return e.IdempotencyKey + "\x00" + strings.Join(e.To, ",") + "\x00" + e.Subject + "\x00" + e.HTML + "\x00" + e.Text
}

// Client sends email through Resend.
type Client struct {
	secret   string
	endpoint string
	http     *http.Client
}

// NewClient builds a client. An empty secret is refused: every send would
// fail at the network with an authentication error, and a client that
// cannot authenticate should not exist. An empty endpoint selects the
// production API; tests point it at a fake.
func NewClient(endpoint, secret string) (*Client, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("%w: an API key is required", ErrSendFailed)
	}
	if strings.TrimSpace(endpoint) == "" {
		endpoint = APIEndpoint
	}
	return &Client{
		secret:   secret,
		endpoint: endpoint,
		http:     &http.Client{Timeout: HTTPTimeout},
	}, nil
}

// Send delivers one email and returns Resend's email ID.
func (c *Client) Send(ctx context.Context, email Email) (string, error) {
	if err := email.validate(); err != nil {
		return "", err
	}
	body := map[string]any{
		"from":    email.From,
		"to":      email.To,
		"subject": email.Subject,
	}
	// Exactly one body part travels: an explicit null is still a claim
	// about the field, and the API treats the two as mutually exclusive.
	if email.HTML != "" {
		body["html"] = email.HTML
	} else {
		body["text"] = email.Text
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("%w: request does not serialize", ErrInvalidEmail)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("%w: request failed: %v", ErrSendFailed, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", email.IdempotencyKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: transport: %v", ErrSendFailed, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return "", fmt.Errorf("%w: unreadable response", ErrSendFailed)
	}
	if resp.StatusCode == http.StatusConflict {
		return "", fmt.Errorf("%w: key %q was already used for a different email", ErrConflict, email.IdempotencyKey)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%w: HTTP %d %s", ErrSendFailed, resp.StatusCode, apiErrorName(raw))
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || strings.TrimSpace(out.ID) == "" {
		return "", fmt.Errorf("%w: response carries no email id", ErrSendFailed)
	}
	return out.ID, nil
}

// apiErrorName extracts Resend's error name for operators. Truncated,
// secret-free: the name of the failure, not its context.
func apiErrorName(body []byte) string {
	var errBody struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &errBody); err != nil {
		return "unparseable response"
	}
	name := strings.TrimSpace(errBody.Name)
	if name == "" {
		name = "api error"
	}
	msg := strings.TrimSpace(errBody.Message)
	if len(msg) > 160 {
		msg = msg[:160] + "..."
	}
	if msg != "" {
		return name + ": " + msg
	}
	return name
}
