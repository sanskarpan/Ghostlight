// Package connector implements the notice and finding connectors: Slack, Teams and
// Jira.
//
// A connector is the one place where Ghostlight's data leaves this system and arrives
// somewhere a customer did not fully control. Three properties follow, and each of them
// has a wrong obvious implementation that this package refuses.
//
// The first is redaction, and the obvious implementation is wrong in a way that is
// invisible until it matters. Redacting "the fields we know are sensitive" means
// sending everything else — and the field nobody thought of, in the notice format
// nobody read, is exactly how a credential reaches a channel. So redaction here is
// **fail-closed**: a field is sent raw only if the policy names it explicitly, and
// anything not named is redacted. That inverts the burden of proof in the safe
// direction.
//
// A name allowlist is not a licence to leak, either. An allowlisted field whose value
// looks like a secret is still redacted, because the allowlist says which fields may
// be *sent*, and not that their contents are safe. Free text — the title and body of a
// notice — is the most likely place to leak, so it is redacted by default too, and a
// policy has to opt into it.
//
// The second is scoped identity. A connector posts as somebody, and that somebody must
// be bound to exactly one scope. One external account serving two scopes is how a
// message about one workspace arrives with the identity of another, and the message
// carries an audience that is not the one it was written for. So an external identity
// binds to one scope and one scope binds to one identity, and neither can be quietly
// re-pointed. Rebinding is refused rather than applied, because a re-pointed identity
// is indistinguishable from a hijacked one at the far end.
//
// The third is signed callbacks. Inbound webhooks are authenticated by a signature
// over the body, checked against a timestamp window and a single-use nonce. A
// timestamp outside the window is refused in both directions — a signature from the
// future is as suspicious as one from the past, and both indicate a clock that
// disagrees with itself. A replayed nonce is refused, and remembering it is the point:
// a signature that verifies forever is a permanent credential, and a webhook that
// repeats a capture is a request to perform an action twice.
//
// Finally, nothing that leaves here carries a connector secret. Delivery checks the
// redacted payload against the connector's own secret before sending, so a secret that
// got into a field by accident is caught at the boundary rather than in somebody's
// channel.
package connector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package's connector rules.
var (
	// ErrNoConnectorID means a connector carries no identifier.
	ErrNoConnectorID = errors.New("connector must carry an identifier")
	// ErrDuplicateConnector means two connectors share an identifier.
	ErrDuplicateConnector = errors.New("connector identifier is already in use")
	// ErrNoKind means a connector names no kind. Slack, Teams and Jira have
	// different callback shapes, and an untyped connector is one whose callbacks
	// cannot be verified correctly.
	ErrNoKind = errors.New("connector must name a kind")
	// ErrUnknownKind means a connector names a kind this package does not support.
	ErrUnknownKind = errors.New("unsupported connector kind")
	// ErrNoTenant means a connector names no tenant.
	ErrNoTenant = errors.New("connector must carry a tenant")
	// ErrNoScope means a scope was empty.
	ErrNoScope = errors.New("scope must not be empty")
	// ErrNoExternalID means an identity carries no external identifier.
	ErrNoExternalID = errors.New("identity must carry an external identifier")
	// ErrIdentityInUse means an external identity is already bound to another
	// connector or scope. One external account serving two scopes is how a message
	// about one workspace arrives with the identity of another.
	ErrIdentityInUse = errors.New("external identity is already bound")
	// ErrScopeAlreadyBound means a connector and scope already have an identity.
	// One scope, one identity: the mapping stays one to one and auditable.
	ErrScopeAlreadyBound = errors.New("scope already has an identity")
	// ErrUnknownConnector means a connector does not exist.
	ErrUnknownConnector = errors.New("no such connector")
	// ErrNoIdentity means a connector and scope have no bound identity.
	ErrNoIdentity = errors.New("no identity is bound to that scope")
	// ErrNoFieldName means a payload field carries no name.
	ErrNoFieldName = errors.New("payload field must carry a name")
	// ErrDuplicateField means a payload carries two fields with the same name.
	ErrDuplicateField = errors.New("payload field name is already used")
	// ErrBadPattern means a redaction pattern does not compile.
	ErrBadPattern = errors.New("redaction pattern does not compile")
	// ErrSecretLeak means a delivery contained the connector's own secret. Caught
	// at the boundary, so a secret that got into a field by accident never reaches
	// a channel.
	ErrSecretLeak = errors.New("delivery contains the connector secret")
	// ErrUnsigned means a callback carried no signature.
	ErrUnsigned = errors.New("callback is unsigned")
	// ErrBadSignature means a callback's signature does not verify.
	ErrBadSignature = errors.New("callback signature does not verify")
	// ErrStaleCallback means a callback's timestamp is outside the accepted window.
	// Both directions are refused: a signature from the future is as suspicious as
	// one from the past.
	ErrStaleCallback = errors.New("callback timestamp is outside the accepted window")
	// ErrReplay means a callback's nonce has been used before. A signature that
	// verifies forever is a permanent credential, and a repeated capture is a
	// request to act twice.
	ErrReplay = errors.New("callback nonce has already been used")
	// ErrNoNonce means a callback carried no nonce.
	ErrNoNonce = errors.New("callback must carry a nonce")
	// ErrNoSecret means a connector has no signing secret.
	ErrNoSecret = errors.New("connector has no signing secret")
)

// Kind names a connector's target.
type Kind string

const (
	// KindSlack posts to Slack.
	KindSlack Kind = "slack"
	// KindTeams posts to Microsoft Teams.
	KindTeams Kind = "teams"
	// KindJira opens or updates a Jira issue.
	KindJira Kind = "jira"
)

// Redacted replaces any value the policy does not permit to be sent.
const Redacted = "[redacted]"

// Connector is an installed target.
type Connector struct {
	// ID identifies the connector.
	ID string
	// Kind names the target.
	Kind Kind
	// Tenant is the owning tenant. A connector belongs to exactly one tenant, so
	// a notice can never be delivered into somebody else's workspace.
	Tenant string
	// Scope is the target scope the connector serves.
	Scope string
	// Secret is the shared secret used to sign and verify callbacks.
	Secret string
}

// Identity is the external account a connector posts as.
type Identity struct {
	// ConnectorID is the connector the identity belongs to.
	ConnectorID string
	// Scope is the scope the identity may speak for.
	Scope string
	// ExternalID is the account identifier at the target.
	ExternalID string
	// Display is the human name shown alongside a message.
	Display string
}

// Field is one named value in a payload.
type Field struct {
	// Name identifies the field.
	Name string
	// Value is the field's content.
	Value string
}

// Payload is a set of named values.
type Payload struct {
	// Fields are the payload's values.
	Fields []Field
}

// Policy says what may be sent.
//
// The default is to send nothing raw, because the default is what applies to a field
// somebody added to a notice format last week and nobody has looked at since.
type Policy struct {
	// AllowFields names the fields that may be sent raw. Everything not named is
	// redacted.
	AllowFields []string
	// DenyFields names the fields that may never be sent raw. A deny beats an
	// allow, so a field can be allowed in general and excluded in one policy.
	DenyFields []string
	// SecretPatterns are regular expressions whose matches are redacted wherever
	// they appear — in a field value, in a title, in a body. A value that looks
	// like a secret is redacted even if its field was allowlisted, because the
	// allowlist says which fields may be sent, not that their contents are safe.
	SecretPatterns []string
	// AllowFreeText permits titles and bodies to be sent raw. Free text is the
	// most likely place to leak, so it is opt-in.
	AllowFreeText bool
}

// Validate compiles the policy's patterns and reports the first that does not compile.
func (p Policy) Validate() error {
	for _, pattern := range p.SecretPatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("%w: %q: %v", ErrBadPattern, pattern, err)
		}
	}
	return nil
}

// Redact applies the policy to a payload.
//
// The order is the policy. Deny is checked first, so an excluded field stays excluded
// even if it is also allowlisted. A field is then a candidate only if it is allowlisted
// — this is the fail-closed step, and it is why an unknown field is redacted rather
// than sent. A candidate is still redacted if its value matches a secret pattern,
// because a name allowlist is not a licence to leak. Everything else is sent as it
// stands.
func (p Policy) Redact(payload Payload) (Payload, error) {
	if err := p.Validate(); err != nil {
		return Payload{}, err
	}
	allow := toSet(p.AllowFields)
	deny := toSet(p.DenyFields)
	patterns, err := p.compile()
	if err != nil {
		return Payload{}, err
	}

	out := Payload{Fields: make([]Field, 0, len(payload.Fields))}
	seen := map[string]bool{}
	for _, f := range payload.Fields {
		if strings.TrimSpace(f.Name) == "" {
			return Payload{}, ErrNoFieldName
		}
		if seen[f.Name] {
			return Payload{}, fmt.Errorf("%w: %q", ErrDuplicateField, f.Name)
		}
		seen[f.Name] = true

		value := f.Value
		switch {
		case deny[f.Name]:
			value = Redacted
		case !allow[f.Name]:
			value = Redacted
		default:
			value = redactPatterns(value, patterns)
		}
		out.Fields = append(out.Fields, Field{Name: f.Name, Value: value})
	}
	return out, nil
}

// RedactText applies the policy's secret patterns to free text. A pattern match is
// redacted even when free text is allowed, because the text is allowed as text, not
// as an exemption from the patterns.
func (p Policy) RedactText(text string) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	patterns, err := p.compile()
	if err != nil {
		return "", err
	}
	return redactPatterns(text, patterns), nil
}

// compile compiles the policy's secret patterns.
func (p Policy) compile() ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, pattern := range p.SecretPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrBadPattern, pattern, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// redactPatterns replaces every pattern match in the text.
func redactPatterns(text string, patterns []*regexp.Regexp) string {
	for _, re := range patterns {
		text = re.ReplaceAllString(text, Redacted)
	}
	return text
}

// toSet builds a set from a list of names.
func toSet(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[strings.TrimSpace(n)] = true
	}
	return out
}

// Registry is the set of connectors and their bound identities.
type Registry struct {
	// Connectors are the installed targets.
	Connectors []Connector
	// Identities are the bound external accounts.
	Identities []Identity
}

// AddConnector installs a connector.
func (r Registry) AddConnector(c Connector) (Registry, error) {
	if strings.TrimSpace(c.ID) == "" {
		return r, ErrNoConnectorID
	}
	switch c.Kind {
	case KindSlack, KindTeams, KindJira:
	case "":
		return r, ErrNoKind
	default:
		return r, fmt.Errorf("%w: %q", ErrUnknownKind, c.Kind)
	}
	if strings.TrimSpace(c.Tenant) == "" {
		return r, ErrNoTenant
	}
	if strings.TrimSpace(c.Scope) == "" {
		return r, ErrNoScope
	}
	for _, existing := range r.Connectors {
		if existing.ID == c.ID {
			return r, fmt.Errorf("%w: %q", ErrDuplicateConnector, c.ID)
		}
	}
	r.Connectors = append(r.Connectors, c)
	return r, nil
}

// BindIdentity binds an external account to a connector and scope.
//
// The binding is one to one in both directions and cannot be quietly re-pointed. An
// external identity already bound elsewhere is refused, and a scope that already has
// an identity is refused, so a re-pointed identity — which is indistinguishable from a
// hijacked one at the far end — cannot be introduced by editing a record.
func (r Registry) BindIdentity(id Identity) (Registry, error) {
	if strings.TrimSpace(id.ConnectorID) == "" {
		return r, ErrNoConnectorID
	}
	if strings.TrimSpace(id.Scope) == "" {
		return r, ErrNoScope
	}
	if strings.TrimSpace(id.ExternalID) == "" {
		return r, ErrNoExternalID
	}
	for _, existing := range r.Identities {
		if existing.ExternalID == id.ExternalID {
			if existing.ConnectorID == id.ConnectorID && existing.Scope == id.Scope {
				return r, nil
			}
			return r, fmt.Errorf("%w: %q", ErrIdentityInUse, id.ExternalID)
		}
		if existing.ConnectorID == id.ConnectorID && existing.Scope == id.Scope {
			return r, fmt.Errorf("%w: %q", ErrScopeAlreadyBound, id.Scope)
		}
	}
	r.Identities = append(r.Identities, id)
	return r, nil
}

// connector looks a connector up by identifier.
func (r Registry) connector(id string) (Connector, bool) {
	for _, c := range r.Connectors {
		if c.ID == id {
			return c, true
		}
	}
	return Connector{}, false
}

// IdentityFor returns the identity bound to a connector and scope.
func (r Registry) IdentityFor(connectorID, scope string) (Identity, error) {
	for _, id := range r.Identities {
		if id.ConnectorID == connectorID && id.Scope == scope {
			return id, nil
		}
	}
	return Identity{}, fmt.Errorf("%w: %q in %q", ErrNoIdentity, connectorID, scope)
}

// Notice is something to deliver to a connector.
type Notice struct {
	// ConnectorID is the target connector.
	ConnectorID string
	// Scope is the scope the notice is for. It must match the connector's scope,
	// because a notice is written for one audience.
	Scope string
	// Title is the notice's headline.
	Title string
	// Body is the notice's text.
	Body string
	// Fields are the notice's named values.
	Fields []Field
}

// Delivery is what actually goes out.
type Delivery struct {
	// ConnectorID is the target connector.
	ConnectorID string
	// Scope is the scope delivered to.
	Scope string
	// Identity is the external account the notice is posted as.
	Identity string
	// Display is the human name shown alongside the notice.
	Display string
	// Title is the delivered headline.
	Title string
	// Body is the delivered text.
	Body string
	// Fields are the delivered values.
	Fields []Field
	// Redacted reports whether anything was withheld.
	Redacted bool
	// Digest binds the delivered content, so what was sent can be checked later.
	Digest string
}

// String renders a delivery for the audit record, with its field values included.
func (d Delivery) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s/%s as %s\n", d.ConnectorID, d.Scope, d.Identity)
	fmt.Fprintf(&b, "title: %s\n", d.Title)
	fmt.Fprintf(&b, "body: %s\n", d.Body)
	for _, f := range d.Fields {
		fmt.Fprintf(&b, "  %s: %s\n", f.Name, f.Value)
	}
	return b.String()
}

// Deliver prepares a notice for a connector.
//
// The notice is redacted before anything else happens, the identity is looked up for
// the notice's own scope, and the result is checked against the connector's secret so
// that a credential which got into a field by accident is caught here rather than in
// somebody's channel.
func (r Registry) Deliver(n Notice, policy Policy) (Delivery, error) {
	c, ok := r.connector(n.ConnectorID)
	if !ok {
		return Delivery{}, fmt.Errorf("%w: %q", ErrUnknownConnector, n.ConnectorID)
	}
	if n.Scope != c.Scope {
		return Delivery{}, fmt.Errorf("%w: notice is for %q, connector serves %q", ErrNoScope, n.Scope, c.Scope)
	}
	identity, err := r.IdentityFor(n.ConnectorID, n.Scope)
	if err != nil {
		return Delivery{}, err
	}

	redacted, err := policy.Redact(Payload{Fields: n.Fields})
	if err != nil {
		return Delivery{}, err
	}

	title := n.Title
	body := n.Body
	if !policy.AllowFreeText {
		title = Redacted
		body = Redacted
	} else {
		title, err = policy.RedactText(title)
		if err != nil {
			return Delivery{}, err
		}
		body, err = policy.RedactText(body)
		if err != nil {
			return Delivery{}, err
		}
	}

	delivery := Delivery{
		ConnectorID: n.ConnectorID,
		Scope:       n.Scope,
		Identity:    identity.ExternalID,
		Display:     identity.Display,
		Title:       title,
		Body:        body,
		Fields:      redacted.Fields,
	}
	delivery.Redacted = title == Redacted || body == Redacted ||
		redactionHappened(n.Fields, redacted.Fields)
	delivery.Digest = DeliveryDigest(delivery)

	if c.Secret != "" && deliveryContains(delivery, c.Secret) {
		return Delivery{}, fmt.Errorf("%w: connector %q", ErrSecretLeak, c.ID)
	}
	return delivery, nil
}

// redactionHappened reports whether any field value was changed by redaction.
func redactionHappened(before, after []Field) bool {
	if len(before) != len(after) {
		return true
	}
	for i := range before {
		if before[i].Value != after[i].Value {
			return true
		}
	}
	return false
}

// deliveryContains reports whether the secret appears anywhere in the delivery.
func deliveryContains(d Delivery, secret string) bool {
	if secret == "" {
		return false
	}
	if strings.Contains(d.Title, secret) || strings.Contains(d.Body, secret) {
		return true
	}
	for _, f := range d.Fields {
		if strings.Contains(f.Value, secret) {
			return true
		}
	}
	return false
}

// DeliveryDigest computes the digest of a delivery's content.
func DeliveryDigest(d Delivery) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s\n", d.ConnectorID, d.Scope, d.Identity, d.Title, d.Body)
	fields := make([]Field, len(d.Fields))
	copy(fields, d.Fields)
	sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
	for _, f := range fields {
		fmt.Fprintf(h, "%s=%s\n", f.Name, f.Value)
	}
	return "delivery-" + hex.EncodeToString(h.Sum(nil))[:32]
}

// Callback is an inbound webhook.
type Callback struct {
	// ConnectorID is the connector the callback came from.
	ConnectorID string
	// Timestamp is when the target signed the callback.
	Timestamp time.Time
	// Nonce is the single-use value that makes a replay detectable.
	Nonce string
	// Body is the callback payload.
	Body []byte
	// Signature is the hex-encoded HMAC over the signed material.
	Signature string
}

// SignedMaterial is the exact string a callback's signature covers.
//
// It binds the connector, the timestamp, the nonce and the body, so none of them can
// be changed without breaking the signature, and the connector and timestamp cannot
// be borrowed from another callback.
func SignedMaterial(cb Callback) string {
	return fmt.Sprintf("%s|%s|%s|%s",
		cb.ConnectorID,
		cb.Timestamp.UTC().Format(time.RFC3339),
		cb.Nonce,
		string(cb.Body),
	)
}

// SignCallback signs a callback with a connector's secret.
func SignCallback(secret string, cb Callback) (Callback, error) {
	if strings.TrimSpace(secret) == "" {
		return cb, ErrNoSecret
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(SignedMaterial(cb)))
	cb.Signature = hex.EncodeToString(mac.Sum(nil))
	return cb, nil
}

// DefaultCallbackWindow is how far a callback's timestamp may drift from now, in either
// direction.
const DefaultCallbackWindow = 5 * time.Minute

// Verifier checks inbound callbacks and remembers the nonces it has seen.
type Verifier struct {
	// Window is how far a callback's timestamp may drift. A zero window means
	// DefaultCallbackWindow.
	Window time.Duration
	// seen records the nonces already used, with the time they were used.
	seen map[string]time.Time
}

// Verify checks a callback's signature, timestamp and nonce.
//
// The order is the policy. The timestamp is checked before the signature, so a stale
// or future callback is refused as such rather than as a bad signature, and the reason
// matters: a clock that disagrees with itself is a different problem from an
// attacker. The nonce is checked last and is remembered, because a signature that
// verifies forever is a permanent credential.
func (v *Verifier) Verify(r Registry, cb Callback, at time.Time) error {
	c, ok := r.connector(cb.ConnectorID)
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownConnector, cb.ConnectorID)
	}
	if c.Secret == "" {
		return fmt.Errorf("%w: connector %q", ErrNoSecret, cb.ConnectorID)
	}
	if strings.TrimSpace(cb.Signature) == "" {
		return ErrUnsigned
	}
	if strings.TrimSpace(cb.Nonce) == "" {
		return ErrNoNonce
	}
	window := v.Window
	if window == 0 {
		window = DefaultCallbackWindow
	}
	delta := at.Sub(cb.Timestamp)
	if delta > window || delta < -window {
		return fmt.Errorf("%w: %s is %s away from %s",
			ErrStaleCallback, cb.Timestamp.UTC().Format(time.RFC3339), delta, at.UTC().Format(time.RFC3339))
	}
	if v.seen == nil {
		v.seen = map[string]time.Time{}
	}
	if _, used := v.seen[cb.Nonce]; used {
		return fmt.Errorf("%w: %q", ErrReplay, cb.Nonce)
	}
	if !hmac.Equal([]byte(cb.Signature), []byte(expectedSignature(c.Secret, cb))) {
		return ErrBadSignature
	}
	v.seen[cb.Nonce] = at
	return nil
}

// expectedSignature computes the signature a callback should carry.
func expectedSignature(secret string, cb Callback) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(SignedMaterial(cb)))
	return hex.EncodeToString(mac.Sum(nil))
}
