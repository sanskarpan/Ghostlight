package evidence_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/evidence"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func keeper(t *testing.T) *evidence.HMACKeeper {
	t.Helper()
	k, err := evidence.NewHMACKeeper([]byte("evidence-test-key"), "test-signer")
	if err != nil {
		t.Fatalf("keeper: %v", err)
	}
	return k
}

func binding() evidence.Binding {
	return evidence.Binding{
		SourceSHA: "abc123", BaseSHA: "def456", ArtifactDigest: "sha256:aaa",
		ConfigDigest: "sha256:bbb", RecipeDigest: "sha256:ccc",
		SchemaDigest: "sha256:ddd", PolicyDigest: "sha256:eee", Generation: 2,
	}
}

func sealed(t *testing.T, outcome string, b evidence.Binding) *evidence.Result {
	t.Helper()
	r, err := evidence.Seal(keeper(t), "smoke", outcome, b, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return r
}

func verifier(t *testing.T) *evidence.Verifier {
	t.Helper()
	v, err := evidence.NewVerifier(keeper(t), func() time.Time { return now })
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return v
}

func expectation() evidence.Expectation {
	return evidence.Expectation{Binding: binding()}
}

// TestVerifierRequiresASigner.
func TestVerifierRequiresASigner(t *testing.T) {
	if _, err := evidence.NewVerifier(nil, nil); err == nil {
		t.Fatal("a verifier without a signer accepts everything")
	}
	if _, err := evidence.NewHMACKeeper(nil, "s"); err == nil {
		t.Fatal("an empty key would qualify anything")
	}
}

// TestBoundPassVerifies is the ordinary path.
func TestBoundPassVerifies(t *testing.T) {
	if err := verifier(t).Verify(context.Background(), sealed(t, "pass", binding()), expectation()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestOnlyAPassQualifies: fail, inconclusive, and canceled results presented as
// qualification are refused outright — not reinterpreted, not upgraded.
func TestOnlyAPassQualifies(t *testing.T) {
	for _, outcome := range []string{"fail", "inconclusive", "canceled"} {
		// Re-seal with the actual outcome so the signature covers it; otherwise the
		// test would pass for the wrong reason (bad signature instead of not-passing).
		r, err := evidence.Seal(keeper(t), "smoke", outcome, binding(), now, now.Add(24*time.Hour))
		if err != nil {
			t.Fatalf("seal %q: %v", outcome, err)
		}
		if err := verifier(t).Verify(context.Background(), r, expectation()); !errors.Is(err, evidence.ErrNotPassing) {
			t.Fatalf("outcome %q must not qualify, got %v", outcome, err)
		}
	}
}

// TestMissingResultIsUnbound.
func TestMissingResultIsUnbound(t *testing.T) {
	if err := verifier(t).Verify(context.Background(), nil, expectation()); !errors.Is(err, evidence.ErrUnbound) {
		t.Fatalf("a missing result must be unbound, got %v", err)
	}
}

// TestIncompleteBindingIsUnbound: seven of eight digests is not bound, because the
// missing digest is exactly the dimension along which the candidate changed.
func TestIncompleteBindingIsUnbound(t *testing.T) {
	b := binding()
	b.PolicyDigest = ""
	r, err := evidence.Seal(keeper(t), "smoke", "pass", b, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := verifier(t).Verify(context.Background(), r, expectation()); !errors.Is(err, evidence.ErrUnbound) {
		t.Fatalf("an incomplete binding must be unbound, got %v", err)
	}
}

// TestForgedSignatureIsRefused.
func TestForgedSignatureIsRefused(t *testing.T) {
	r := sealed(t, "pass", binding())
	r.Signature = "forged"
	if err := verifier(t).Verify(context.Background(), r, expectation()); !errors.Is(err, evidence.ErrBadSignature) {
		t.Fatalf("a forged signature must be refused, got %v", err)
	}
}

// TestSignatureFromAnotherKeyIsRefused.
func TestSignatureFromAnotherKeyIsRefused(t *testing.T) {
	other, err := evidence.NewHMACKeeper([]byte("a-different-key"), "other")
	if err != nil {
		t.Fatalf("keeper: %v", err)
	}
	r, err := evidence.Seal(other, "smoke", "pass", binding(), now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := verifier(t).Verify(context.Background(), r, expectation()); !errors.Is(err, evidence.ErrBadSignature) {
		t.Fatalf("a foreign signature must be refused, got %v", err)
	}
}

// TestStaleGenerationIsRefusedEvenWhenDigestsMatch: the candidate moved on.
func TestStaleGenerationIsRefusedEvenWhenDigestsMatch(t *testing.T) {
	b := binding()
	b.Generation = 1
	r := sealed(t, "pass", b)
	exp := expectation()
	exp.Binding.Generation = 2
	if err := verifier(t).Verify(context.Background(), r, exp); !errors.Is(err, evidence.ErrStaleResult) {
		t.Fatalf("a stale generation must be refused, got %v", err)
	}
}

// TestEachChangedDigestIsNamed: the differing digest is the dimension the candidate
// changed along, and that is what an operator needs to know.
func TestEachChangedDigestIsNamed(t *testing.T) {
	cases := map[string]func(*evidence.Binding){
		"source_sha":      func(b *evidence.Binding) { b.SourceSHA = "changed" },
		"artifact_digest": func(b *evidence.Binding) { b.ArtifactDigest = "sha256:changed" },
		"config_digest":   func(b *evidence.Binding) { b.ConfigDigest = "sha256:changed" },
		"recipe_digest":   func(b *evidence.Binding) { b.RecipeDigest = "sha256:changed" },
		"policy_digest":   func(b *evidence.Binding) { b.PolicyDigest = "sha256:changed" },
	}
	for name, mutate := range cases {
		b := binding()
		mutate(&b)
		r := sealed(t, "pass", b)
		err := verifier(t).Verify(context.Background(), r, expectation())
		if !errors.Is(err, evidence.ErrDigestMismatch) {
			t.Fatalf("a changed %s must mismatch, got %v", name, err)
		}
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("the refusal must name %s, got %q", name, err)
		}
	}
}

// TestExpiredEvidenceDoesNotQualify.
func TestExpiredEvidenceDoesNotQualify(t *testing.T) {
	r, err := evidence.Seal(keeper(t), "smoke", "pass", binding(), now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := verifier(t).Verify(context.Background(), r, expectation()); !errors.Is(err, evidence.ErrExpiredEvidence) {
		t.Fatalf("expired evidence must not qualify, got %v", err)
	}
}

// TestSealRequiresHarnessAndOutcome.
func TestSealRequiresHarnessAndOutcome(t *testing.T) {
	if _, err := evidence.Seal(keeper(t), "", "pass", binding(), now, now.Add(time.Hour)); err == nil {
		t.Fatal("a result must name its harness")
	}
	if _, err := evidence.Seal(keeper(t), "smoke", "", binding(), now, now.Add(time.Hour)); err == nil {
		t.Fatal("a result must name its outcome")
	}
}

// TestPartialExpectationMatchesPresentFields: an expectation that does not pin a digest
// accepts any value for it. Pinning nothing means trusting everything on that dimension.
func TestPartialExpectationMatchesPresentFields(t *testing.T) {
	r := sealed(t, "pass", binding())
	exp := expectation()
	exp.Binding.PolicyDigest = ""
	if err := verifier(t).Verify(context.Background(), r, exp); err != nil {
		t.Fatalf("an unpinned dimension must accept any value, got %v", err)
	}
}

// TestBindingMissingIsStable.
func TestBindingMissingIsStable(t *testing.T) {
	missing := evidence.Binding{}.Missing()
	if len(missing) != 8 {
		t.Fatalf("an empty binding must miss eight dimensions, got %v", missing)
	}
	if binding().Complete() != true {
		t.Fatal("a full binding must be complete")
	}
	if (evidence.Binding{SourceSHA: "x"}).Complete() {
		t.Fatal("a partial binding must not be complete")
	}
}

// TestDescribeOmitsTheSignature.
func TestDescribeOmitsTheSignature(t *testing.T) {
	r := sealed(t, "pass", binding())
	got := evidence.Describe(r)
	if strings.Contains(got, r.Signature) {
		t.Fatal("a description must never carry the signature")
	}
	for _, want := range []string{"smoke", "pass", "2"} {
		if !strings.Contains(got, want) {
			t.Fatalf("a description must stay identifiable, missing %q in %q", want, got)
		}
	}
	if evidence.Describe(nil) != "no result" {
		t.Fatal("a missing result must describe itself as such")
	}
}
