package attestations

// The signature is the subject: an attestation verifies over its own content
// on every read, expiry and revocation are states the reader sees rather
// than facts the store guesses, and nothing is issued without a binding.

import (
	"strings"
	"testing"
	"time"
)

func TestIssueAndReadBackVerifies(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	a, err := NewAuthority(func() time.Time { return now }, 24*time.Hour)
	if err != nil {
		t.Fatalf("authority: %v", err)
	}
	rec, err := a.Issue("env-1", "repo:acme", 3,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"cleanup_verified")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, state, err := a.Get(rec.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if state != StateValid {
		t.Errorf("state = %q, want valid", state)
	}
	if got.Generation != 3 || got.Result != "cleanup_verified" || got.Scope != "repo:acme" {
		t.Errorf("got = %+v", got)
	}
	if got.SignatureBase64 == "" {
		t.Error("the attestation carries no signature")
	}
}

func TestExpiryIsAStateTheReaderSees(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	a, _ := NewAuthority(func() time.Time { return now }, time.Hour)
	rec, err := a.Issue("env-1", "repo:acme", 1,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"cleanup_verified")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// The clock moves past the validity window.
	later := now.Add(2 * time.Hour)
	a2 := a
	a2.now = func() time.Time { return later }
	_, state, err := a2.Get(rec.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if state != StateExpired {
		t.Errorf("state = %q, want expired", state)
	}
}

func TestRevocationIsAuthoritativeAndAttributed(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	a, _ := NewAuthority(func() time.Time { return now }, 24*time.Hour)
	rec, err := a.Issue("env-1", "repo:acme", 1,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"cleanup_verified")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := a.Revoke(rec.ID, "", "ada"); err == nil {
		t.Fatal("a revocation without a visible reason was accepted")
	}
	if _, err := a.Revoke(rec.ID, "the candidate was superseded", ""); err == nil {
		t.Fatal("a revocation without an attributed actor was accepted")
	}
	revoked, err := a.Revoke(rec.ID, "the candidate was superseded", "ada")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, state, err := a.Get(revoked.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if state != StateRevoked {
		t.Errorf("state = %q, want revoked", state)
	}
	if revoked.RevokeReason != "the candidate was superseded" || revoked.RevokedBy != "ada" {
		t.Errorf("withdrawal record = %+v", revoked)
	}
}

func TestATamperedRecordIsAServerFaultNotAServedFact(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	a, _ := NewAuthority(func() time.Time { return now }, 24*time.Hour)
	rec, err := a.Issue("env-1", "repo:acme", 1,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"cleanup_verified")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Tamper with the record under the authority's own nose.
	a.mu.Lock()
	tampered := a.byID[rec.ID]
	tampered.Result = "pass"
	a.byID[rec.ID] = tampered
	a.mu.Unlock()

	if _, _, err := a.Get(rec.ID); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("a tampered record answered: %v", err)
	}
}

func TestIssueRefusesAnUnboundAttestation(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	a, _ := NewAuthority(func() time.Time { return now }, 24*time.Hour)
	if _, err := a.Issue("env-1", "repo:acme", 1, "not-a-digest", "cleanup_verified"); err == nil {
		t.Fatal("a result bound to a digest that does not parse was signed")
	}
	if _, err := a.Issue("env-1", "repo:acme", 1,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ""); err == nil {
		t.Fatal("an attestation of nothing was signed")
	}
}

func TestZeroValidityIsRefusedAtConstruction(t *testing.T) {
	if _, err := NewAuthority(nil, 0); err == nil {
		t.Fatal("an authority whose attestations never expire was constructed")
	}
}
