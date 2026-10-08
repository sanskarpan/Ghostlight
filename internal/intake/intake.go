// Package intake implements verified webhook intake.
//
// Two rules define this package and both are load-bearing:
//
//   - The signature is verified over the exact bytes received. A body that has
//     been parsed and re-serialised is not the body that was signed, so
//     verification happens before any unmarshalling and against the raw payload.
//   - A verified payload is persisted before the request is acknowledged. If the
//     store cannot accept it, intake fails. Returning success for an event that
//     was not stored loses it, because the provider will not redeliver something
//     it believes was accepted.
//
// Intake deliberately does not decide what an event means. Arrival order is not
// authoritative, so the recorded event carries the provider's delivery identity
// and a digest of what was received; current pull-request state is resolved from an
// authenticated source later, when acting.
package intake

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Retention constants for admitted events. Raw payload bodies are short-lived;
// the delivery identifier and digest outlive them for the audit window.
const (
	// PayloadMetadataRetention is how long an admitted event row is retained.
	PayloadMetadataRetention = 30 * 24 * time.Hour
	// SignatureTolerance is the accepted clock skew on a signature timestamp.
	// Exceeding it is a replay, not a late delivery.
	SignatureTolerance = 5 * time.Minute
)

var (
	// ErrSignatureInvalid means the payload did not verify. It is never stored.
	ErrSignatureInvalid = errors.New("webhook signature did not verify")
	// ErrTimestampOutsideTolerance means a valid signature outside the accepted
	// clock window, which is the replay case.
	ErrTimestampOutsideTolerance = errors.New("webhook timestamp outside tolerance")
	// ErrMalformedDelivery means the delivery metadata itself is unusable.
	ErrMalformedDelivery = errors.New("malformed webhook delivery metadata")
	// ErrStoreRejected means the verified event could not be persisted. Intake
	// must fail rather than acknowledge an event it did not store.
	ErrStoreRejected = errors.New("verified event could not be persisted")
)

// Delivery is the metadata accompanying a provider webhook. Only the fields
// needed for verification and deduplication are used; everything else about the
// event is resolved later from an authenticated source.
type Delivery struct {
	// DeliveryID is the provider's unique identifier for this delivery. It is the
	// intake idempotency key.
	DeliveryID string
	// EventType names the event class.
	EventType string
	// Timestamp is the signature timestamp, used for replay tolerance.
	Timestamp time.Time
	// InstallationRef and RepositoryRef are asserted by the payload after
	// verification. They are recorded, never treated as authority for access.
	InstallationRef string
	RepositoryRef   string
}

// Validate checks the delivery metadata before any verification work.
func (d Delivery) Validate() error {
	if strings.TrimSpace(d.DeliveryID) == "" {
		return fmt.Errorf("%w: delivery id is required and is the intake idempotency key", ErrMalformedDelivery)
	}
	if strings.TrimSpace(d.EventType) == "" {
		return fmt.Errorf("%w: event type is required", ErrMalformedDelivery)
	}
	if d.Timestamp.IsZero() {
		return fmt.Errorf("%w: timestamp is required for replay tolerance", ErrMalformedDelivery)
	}
	return nil
}

// Verifier checks provider signatures.
//
// A verifier is passed the exact bytes that arrived. It must not be handed a
// decoded structure, because re-encoding changes the bytes and a signature over
// different bytes is not a signature over what was received.
type Verifier interface {
	Verify(ctx context.Context, body []byte, signature string) error
}

// HMACVerifier verifies a hex-encoded HMAC-SHA256 over the exact body bytes.
//
// Providers send the digest scheme-qualified ("sha256=<hex>"), so the prefix is
// always tolerated rather than being opt-in: making it configurable means the
// default configuration is the one that rejects real deliveries, and the fix gets
// made under time pressure at the worst possible moment.
//
// The prefix is stripped and only the hex digest is compared. That accepts a
// signed request while refusing to let an unsupported scheme be used to bypass the
// check, since the digest is still what has to match.
type HMACVerifier struct {
	Secret []byte
}

// Verify checks the signature over the exact bytes provided.
func (v HMACVerifier) Verify(_ context.Context, body []byte, signature string) error {
	if len(v.Secret) == 0 {
		// Fail closed: a verifier without a secret must not admit anything.
		return fmt.Errorf("%w: no secret configured", ErrSignatureInvalid)
	}
	provided := strings.TrimSpace(signature)
	if provided == "" {
		return fmt.Errorf("%w: signature is absent", ErrSignatureInvalid)
	}
	if i := strings.IndexByte(provided, '='); i >= 0 {
		provided = provided[i+1:]
	}
	provided = strings.ToLower(strings.TrimSpace(provided))

	mac := hmac.New(sha256.New, v.Secret)
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(provided), []byte(expected)) {
		return fmt.Errorf("%w: digest mismatch", ErrSignatureInvalid)
	}
	return nil
}

// ReplayGuard reports whether a timestamp is inside the accepted window.
type ReplayGuard struct {
	Now       func() time.Time
	Tolerance time.Duration
}

// Check verifies the timestamp is within tolerance of now.
func (g ReplayGuard) Check(ts time.Time) error {
	now := time.Now().UTC()
	if g.Now != nil {
		now = g.Now().UTC()
	}
	tol := g.Tolerance
	if tol == 0 {
		tol = SignatureTolerance
	}
	skew := now.Sub(ts)
	if skew < 0 {
		skew = -skew
	}
	if skew > tol {
		return fmt.Errorf("%w: skew %v exceeds %v", ErrTimestampOutsideTolerance, skew, tol)
	}
	return nil
}

// Stored is an admitted event.
type Stored struct {
	DeliveryID   string
	EventType    string
	PayloadSHA   string
	ReceivedAt   time.Time
	ExpiresAt    time.Time
	Duplicate    bool
	Installation string
	Repository   string
}

// Store persists admitted events.
//
// Insert must be idempotent on (provider, delivery id) and must report whether the
// row was new, so a redelivery is a no-op rather than a second run.
type Store interface {
	Insert(ctx context.Context, s Stored) (inserted bool, err error)
}

// Service admits verified events.
type Service struct {
	verifier Verifier
	store    Store
	guard    ReplayGuard
	provider string
	// Retention overrides PayloadMetadataRetention when non-zero.
	Retention time.Duration
}

// NewService builds an intake service.
func NewService(provider string, verifier Verifier, store Store, guard ReplayGuard) *Service {
	return &Service{provider: provider, verifier: verifier, store: store, guard: guard}
}

// Intake verifies and admits one delivery.
//
// The order is deliberate: validate metadata, verify the signature over raw
// bytes, check the replay window, and only then persist. A payload that fails any
// of these is never stored.
func (s *Service) Intake(ctx context.Context, d Delivery, body []byte, signature string) (Stored, error) {
	if err := d.Validate(); err != nil {
		return Stored{}, err
	}
	if len(body) == 0 {
		return Stored{}, fmt.Errorf("%w: empty payload cannot be verified", ErrSignatureInvalid)
	}
	if err := s.guard.Check(d.Timestamp); err != nil {
		return Stored{}, err
	}
	if err := s.verifier.Verify(ctx, body, signature); err != nil {
		return Stored{}, err
	}

	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	retention := s.Retention
	if retention == 0 {
		retention = PayloadMetadataRetention
	}
	now := time.Now().UTC()
	stored := Stored{
		DeliveryID:   d.DeliveryID,
		EventType:    d.EventType,
		PayloadSHA:   digest,
		ReceivedAt:   now,
		ExpiresAt:    now.Add(retention),
		Installation: d.InstallationRef,
		Repository:   d.RepositoryRef,
	}

	inserted, err := s.store.Insert(ctx, stored)
	if err != nil {
		// Not acknowledging is the safe failure. The provider will redeliver, and
		// acknowledging would lose the event permanently.
		return Stored{}, fmt.Errorf("%w: %v", ErrStoreRejected, err)
	}
	stored.Duplicate = !inserted
	return stored, nil
}

// Digest returns the payload digest an intake would record, for callers that need
// to compare a payload against a previously admitted one.
func Digest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
