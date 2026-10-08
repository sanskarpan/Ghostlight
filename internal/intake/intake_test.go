package intake_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/intake"
)

var secret = []byte("test-webhook-secret")

// fakeStore records inserts and can be made to fail.
type fakeStore struct {
	mu       sync.Mutex
	seen     map[string]intake.Stored
	inserted []intake.Stored
	failWith error
	// concurrent inserts are counted so a duplicate race is detectable.
	duplicateInserts int
}

func newStore() *fakeStore {
	return &fakeStore{seen: map[string]intake.Stored{}}
}

func (f *fakeStore) Insert(_ context.Context, s intake.Stored) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return false, f.failWith
	}
	if _, exists := f.seen[s.DeliveryID]; exists {
		f.duplicateInserts++
		return false, nil
	}
	f.seen[s.DeliveryID] = s
	f.inserted = append(f.inserted, s)
	return true, nil
}

func (f *fakeStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.inserted)
}

// signature returns the hex HMAC over the exact body, matching what the service
// verifies.
func signature(body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func delivery(id string) intake.Delivery {
	return intake.Delivery{
		DeliveryID: id,
		EventType:  "pull_request",
		Timestamp:  time.Now().UTC(),
	}
}

func newService(store intake.Store) *intake.Service {
	return intake.NewService("github",
		intake.HMACVerifier{Secret: secret},
		store,
		intake.ReplayGuard{Now: func() time.Time { return time.Now().UTC() }})
}

func TestValidDeliveryIsAdmitted(t *testing.T) {
	store := newStore()
	svc := newService(store)
	body := []byte(`{"action":"opened","number":142}`)

	got, err := svc.Intake(context.Background(), delivery("d-1"), body, signature(body))
	if err != nil {
		t.Fatalf("intake: %v", err)
	}
	if got.Duplicate {
		t.Fatal("a first delivery is not a duplicate")
	}
	if store.count() != 1 {
		t.Fatalf("expected one stored row, got %d", store.count())
	}
	if got.PayloadSHA != intake.Digest(body) {
		t.Fatal("payload digest must be recorded")
	}
	if !got.ExpiresAt.After(got.ReceivedAt) {
		t.Fatal("retention expiry must follow receipt")
	}
}

// TestDuplicateDeliveryIsANoOp is the intake idempotency property: a
// redelivered event must not be admitted twice.
func TestDuplicateDeliveryIsANoOp(t *testing.T) {
	store := newStore()
	svc := newService(store)
	body := []byte(`{"action":"opened","number":142}`)

	if _, err := svc.Intake(context.Background(), delivery("d-dup"), body, signature(body)); err != nil {
		t.Fatalf("first intake: %v", err)
	}
	got, err := svc.Intake(context.Background(), delivery("d-dup"), body, signature(body))
	if err != nil {
		t.Fatalf("redelivery must not error: %v", err)
	}
	if !got.Duplicate {
		t.Fatal("a redelivered delivery must be reported as a duplicate")
	}
	if store.count() != 1 {
		t.Fatalf("a duplicate must not create a second row, got %d", store.count())
	}
}

func TestSignatureOverDifferentBytesIsRejected(t *testing.T) {
	store := newStore()
	svc := newService(store)
	body := []byte(`{"action":"opened","number":142}`)
	// Sign one body, deliver another. This is what a re-encoding bug looks like.
	other := []byte(`{"action":"opened","number":143}`)

	_, err := svc.Intake(context.Background(), delivery("d-tamper"), other, signature(body))
	if !errors.Is(err, intake.ErrSignatureInvalid) {
		t.Fatalf("a signature over different bytes must be rejected, got %v", err)
	}
	if store.count() != 0 {
		t.Fatal("an unverified payload must never be stored")
	}
}

func TestWhitespaceChangeBreaksVerification(t *testing.T) {
	// A body that is semantically identical but differs by a byte is a different
	// body. This is why verification happens before parsing.
	store := newStore()
	svc := newService(store)
	body := []byte(`{"a":1}`)
	tampered := []byte(`{"a": 1}`)

	if _, err := svc.Intake(context.Background(), delivery("d-ws"), tampered, signature(body)); err == nil {
		t.Fatal("a whitespace change must break verification")
	}
	if store.count() != 0 {
		t.Fatal("nothing may be stored for an unverified payload")
	}
}

func TestMissingSignatureIsRejected(t *testing.T) {
	svc := newService(newStore())
	body := []byte(`{"action":"opened"}`)
	for _, sig := range []string{"", "   "} {
		if _, err := svc.Intake(context.Background(), delivery("d-nosig"), body, sig); !errors.Is(err, intake.ErrSignatureInvalid) {
			t.Fatalf("absent signature %q must be rejected, got %v", sig, err)
		}
	}
}

func TestSchemeQualifiedSignatureVerifies(t *testing.T) {
	// Providers send scheme-qualified digests, so this must work by default.
	// Making it opt-in means the default configuration rejects real deliveries.
	svc := newService(newStore())
	body := []byte(`{"action":"opened"}`)

	if _, err := svc.Intake(context.Background(), delivery("d-pfx"), body, "sha256="+signature(body)); err != nil {
		t.Fatalf("a scheme-qualified signature must verify: %v", err)
	}
}

func TestUppercaseSchemeIsAccepted(t *testing.T) {
	svc := newService(newStore())
	body := []byte(`{"action":"opened"}`)
	if _, err := svc.Intake(context.Background(), delivery("d-up"), body, "SHA256="+strings.ToUpper(signature(body))); err != nil {
		t.Fatalf("a case-different signature must still verify: %v", err)
	}
}

// TestStrippingThePrefixDoesNotWeakenVerification checks the prefix handling is
// not a way to smuggle a different digest through.
func TestStrippingThePrefixDoesNotWeakenVerification(t *testing.T) {
	store := newStore()
	svc := newService(store)
	body := []byte(`{"action":"opened"}`)
	good := signature(body)
	bad := signature([]byte(`{"action":"tampered"}`))

	// A prefix carrying a different digest must fail.
	if _, err := svc.Intake(context.Background(), delivery("d-mix"), body, "sha256="+bad); err == nil {
		t.Fatal("a prefixed signature over different bytes must be rejected")
	}
	// An empty payload behind a prefix must not pass either.
	if _, err := svc.Intake(context.Background(), delivery("d-empty-pfx"), body, "sha256="); err == nil {
		t.Fatal("a prefix with no digest must be rejected")
	}
	// The genuine digest behind a prefix still works.
	if _, err := svc.Intake(context.Background(), delivery("d-good-pfx"), body, "sha256="+good); err != nil {
		t.Fatalf("the genuine digest behind a prefix must verify: %v", err)
	}
	if store.count() != 1 {
		t.Fatalf("only the verified payload may be stored, got %d", store.count())
	}
}

func TestReplayOutsideToleranceIsRejected(t *testing.T) {
	store := newStore()
	svc := newService(store)
	body := []byte(`{"action":"opened"}`)
	d := delivery("d-replay")
	d.Timestamp = time.Now().UTC().Add(-30 * time.Minute)

	if _, err := svc.Intake(context.Background(), d, body, signature(body)); !errors.Is(err, intake.ErrTimestampOutsideTolerance) {
		t.Fatalf("a stale timestamp must be rejected as a replay, got %v", err)
	}
	if store.count() != 0 {
		t.Fatal("a replay must not be stored")
	}
}

func TestTimestampInsideToleranceIsAccepted(t *testing.T) {
	store := newStore()
	svc := newService(store)
	body := []byte(`{"action":"opened"}`)
	d := delivery("d-fresh")
	d.Timestamp = time.Now().UTC().Add(-30 * time.Second)

	if _, err := svc.Intake(context.Background(), d, body, signature(body)); err != nil {
		t.Fatalf("a timestamp inside tolerance must be accepted: %v", err)
	}
}

// TestStoreFailureIsNotAcknowledged is the durability rule: if the verified event
// cannot be stored, intake must fail, because the provider will not redeliver
// something it believes was accepted.
func TestStoreFailureIsNotAcknowledged(t *testing.T) {
	store := newStore()
	store.failWith = errors.New("connection reset")
	svc := newService(store)
	body := []byte(`{"action":"opened"}`)

	_, err := svc.Intake(context.Background(), delivery("d-fail"), body, signature(body))
	if !errors.Is(err, intake.ErrStoreRejected) {
		t.Fatalf("a store failure must surface, got %v", err)
	}
	if store.count() != 0 {
		t.Fatal("nothing may be stored when the store rejects")
	}
}

func TestMalformedDeliveryIsRejectedBeforeVerification(t *testing.T) {
	store := newStore()
	svc := newService(store)
	body := []byte(`{"action":"opened"}`)
	sig := signature(body)

	cases := map[string]intake.Delivery{
		"missing delivery id": {EventType: "pull_request", Timestamp: time.Now().UTC()},
		"missing event type":  {DeliveryID: "d-1", Timestamp: time.Now().UTC()},
		"missing timestamp":   {DeliveryID: "d-1", EventType: "pull_request"},
		"blank delivery id":   {DeliveryID: "   ", EventType: "pull_request", Timestamp: time.Now().UTC()},
	}
	for name, d := range cases {
		if _, err := svc.Intake(context.Background(), d, body, sig); !errors.Is(err, intake.ErrMalformedDelivery) {
			t.Errorf("%s: expected ErrMalformedDelivery, got %v", name, err)
		}
	}
	if store.count() != 0 {
		t.Fatal("malformed metadata must not reach the store")
	}
}

func TestEmptyPayloadIsRejected(t *testing.T) {
	svc := newService(newStore())
	if _, err := svc.Intake(context.Background(), delivery("d-empty"), nil, signature(nil)); !errors.Is(err, intake.ErrSignatureInvalid) {
		t.Fatalf("an empty payload cannot be verified, got %v", err)
	}
}

// TestConcurrentDuplicateIntakeAdmitsOnce exercises the race the unique index is
// there to settle: many identical deliveries arriving together.
func TestConcurrentDuplicateIntakeAdmitsOnce(t *testing.T) {
	store := newStore()
	svc := newService(store)
	body := []byte(`{"action":"synchronize","number":142}`)
	sig := signature(body)

	const n = 12
	var wg sync.WaitGroup
	results := make([]intake.Stored, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = svc.Intake(context.Background(), delivery("d-race"), body, sig)
		}(i)
	}
	close(start)
	wg.Wait()

	admitted := 0
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
		if !results[i].Duplicate {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("exactly one concurrent delivery may be admitted, got %d", admitted)
	}
	if store.count() != 1 {
		t.Fatalf("one row expected, got %d", store.count())
	}
}

func TestDifferentDeliveriesAreBothAdmitted(t *testing.T) {
	store := newStore()
	svc := newService(store)
	body := []byte(`{"action":"opened"}`)
	sig := signature(body)

	for _, id := range []string{"d-1", "d-2", "d-3"} {
		if _, err := svc.Intake(context.Background(), delivery(id), body, sig); err != nil {
			t.Fatalf("intake %s: %v", id, err)
		}
	}
	if store.count() != 3 {
		t.Fatalf("distinct deliveries must all be admitted, got %d", store.count())
	}
}

// TestVerifierMustNotAcceptWrongSecret guards a configuration mistake that would
// otherwise admit unverified payloads.
func TestVerifierMustNotAcceptWrongSecret(t *testing.T) {
	body := []byte(`{"action":"opened"}`)
	svc := intake.NewService("github",
		intake.HMACVerifier{Secret: []byte("a-different-secret")},
		newStore(),
		intake.ReplayGuard{})
	if _, err := svc.Intake(context.Background(), delivery("d-secret"), body, signature(body)); !errors.Is(err, intake.ErrSignatureInvalid) {
		t.Fatalf("a different secret must not verify, got %v", err)
	}
}

func TestVerifierWithNoSecretFailsClosed(t *testing.T) {
	svc := intake.NewService("github",
		intake.HMACVerifier{},
		newStore(),
		intake.ReplayGuard{})
	body := []byte(`{"action":"opened"}`)
	if _, err := svc.Intake(context.Background(), delivery("d-nosecret"), body, signature(body)); err == nil {
		t.Fatal("a verifier with no configured secret must fail closed")
	}
}

func TestDigestIsStableAndSensitive(t *testing.T) {
	a := []byte(`{"number":142}`)
	b := []byte(`{"number":143}`)
	if intake.Digest(a) != intake.Digest(a) {
		t.Fatal("digest must be deterministic")
	}
	if intake.Digest(a) == intake.Digest(b) {
		t.Fatal("digest must differ for different payloads")
	}
	if len(intake.Digest(a)) != 64 {
		t.Fatalf("expected a hex sha256, got length %d", len(intake.Digest(a)))
	}
}

func TestVerificationHappensBeforeAnyParsing(t *testing.T) {
	// A payload that is not valid JSON but carries a valid signature is admitted,
	// because intake does not parse. If intake started parsing first, this event
	// would be rejected here and the provider would never redeliver it.
	store := newStore()
	svc := newService(store)
	body := []byte("not json at all")

	if _, err := svc.Intake(context.Background(), delivery("d-nonjson"), body, signature(body)); err != nil {
		t.Fatalf("a signed non-JSON payload must still be admitted for later handling: %v", err)
	}
	if store.count() != 1 {
		t.Fatal("expected the payload to be stored")
	}
}

func TestRecordInstallationAndRepositoryAsAssertions(t *testing.T) {
	// Client-asserted identity is recorded, never used as authority. The store
	// keeps it; nothing in intake grants access on its basis.
	store := newStore()
	svc := newService(store)
	body := []byte(`{"installation":{"id":123}}`)
	d := delivery("d-inst")
	d.InstallationRef = "inst-123"
	d.RepositoryRef = "repo/acme/app"

	got, err := svc.Intake(context.Background(), d, body, signature(body))
	if err != nil {
		t.Fatalf("intake: %v", err)
	}
	if got.Installation != "inst-123" || got.Repository != "repo/acme/app" {
		t.Fatalf("asserted identity must be recorded verbatim, got %q / %q", got.Installation, got.Repository)
	}
}

func TestErrorMessagesNameTheFailure(t *testing.T) {
	// A refusal must be inspectable. An opaque error here would make a delivery
	// problem undiagnosable.
	store := newStore()
	store.failWith = fmt.Errorf("disk full")
	svc := newService(store)
	body := []byte(`{"action":"opened"}`)

	_, err := svc.Intake(context.Background(), delivery("d-msg"), body, signature(body))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("the underlying cause must be visible, got %q", err)
	}
}
