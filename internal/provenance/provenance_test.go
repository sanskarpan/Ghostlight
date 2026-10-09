package provenance_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/provenance"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// builders authorizes named builders per repository.
type builders struct {
	grants map[string]bool
	err    error
}

func (b *builders) Authorized(_ context.Context, builder, repo string) (bool, error) {
	if b.err != nil {
		return false, b.err
	}
	return b.grants[builder+"/"+repo], nil
}

func keeper(t *testing.T) *provenance.HMACKeeper {
	t.Helper()
	k, err := provenance.NewHMACKeeper([]byte("provenance-test-key"), "test-signer")
	if err != nil {
		t.Fatalf("keeper: %v", err)
	}
	return k
}

func verifier(t *testing.T, b *builders) *provenance.Verifier {
	t.Helper()
	if b == nil {
		b = &builders{grants: map[string]bool{"trusted-builder/repo/acme/app": true}}
	}
	v, err := provenance.NewVerifier(keeper(t), b, provenance.Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return v
}

func attestation(t *testing.T) *provenance.Attestation {
	t.Helper()
	a, err := provenance.Attest(keeper(t),
		"sha256:artifact-1", "repo/acme/app", "abc123def456", "trusted-builder", "sha256:inputs-1",
		now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	return a
}

func expectation() provenance.Expectation {
	return provenance.Expectation{
		ArtifactDigest: "sha256:artifact-1", Repository: "repo/acme/app", SourceSHA: "abc123def456",
	}
}

// TestVerifierRequiresItsDependencies.
func TestVerifierRequiresItsDependencies(t *testing.T) {
	b := &builders{}
	if _, err := provenance.NewVerifier(nil, b, provenance.Config{}); err == nil {
		t.Fatal("a verifier without a signer accepts everything")
	}
	if _, err := provenance.NewVerifier(keeper(t), nil, provenance.Config{}); err == nil {
		t.Fatal("a verifier without builder authorization lets anyone attest")
	}
	if _, err := provenance.NewHMACKeeper(nil, "s"); err == nil {
		t.Fatal("an empty key would attest anything")
	}
}

// TestValidProvenanceVerifies is the ordinary path.
func TestValidProvenanceVerifies(t *testing.T) {
	if err := verifier(t, nil).Verify(context.Background(), attestation(t), expectation()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestMissingProvenanceIsNotDeployable: an unattested artifact is an artifact nobody can
// account for, not a deployable artifact with missing paperwork.
func TestMissingProvenanceIsNotDeployable(t *testing.T) {
	if err := verifier(t, nil).Verify(context.Background(), nil, expectation()); !errors.Is(err, provenance.ErrUnattested) {
		t.Fatalf("missing provenance must be refused, got %v", err)
	}
	unsigned := attestation(t)
	unsigned.Signature = ""
	if err := verifier(t, nil).Verify(context.Background(), unsigned, expectation()); !errors.Is(err, provenance.ErrUnattested) {
		t.Fatalf("an unsigned attestation must be refused, got %v", err)
	}
}

// TestAttestationMustNameEverything: each missing identity field is a different way to
// smuggle an unaccounted artifact past the gate.
func TestAttestationMustNameEverything(t *testing.T) {
	base := attestation(t)
	for name, blank := range map[string]func(*provenance.Attestation){
		"no artifact": func(a *provenance.Attestation) { a.ArtifactDigest = "" },
		"no repo":     func(a *provenance.Attestation) { a.Repository = "" },
		"no source":   func(a *provenance.Attestation) { a.SourceSHA = "" },
		"no builder":  func(a *provenance.Attestation) { a.BuilderID = "" },
	} {
		a := *base
		blank(&a)
		if err := verifier(t, nil).Verify(context.Background(), &a, expectation()); !errors.Is(err, provenance.ErrUnattested) {
			t.Fatalf("%s must be refused, got %v", name, err)
		}
	}
}

// TestForgedSignatureIsRefused.
func TestForgedSignatureIsRefused(t *testing.T) {
	a := attestation(t)
	a.ArtifactDigest = "sha256:something-else"
	if err := verifier(t, nil).Verify(context.Background(), a, expectation()); !errors.Is(err, provenance.ErrBadSignature) {
		t.Fatalf("a tampered attestation must fail signature verification, got %v", err)
	}
}

// TestUnauthorizedBuilderIsRefusedDistinctly: a valid signature from the wrong builder
// needs investigation, not a rebuild.
func TestUnauthorizedBuilderIsRefusedDistinctly(t *testing.T) {
	k := keeper(t)
	a, err := provenance.Attest(k,
		"sha256:artifact-1", "repo/acme/app", "abc123def456", "untrusted-builder", "sha256:inputs-1",
		now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	err = verifier(t, nil).Verify(context.Background(), a, expectation())
	if !errors.Is(err, provenance.ErrUnauthorizedBuilder) {
		t.Fatalf("an unauthorized builder must be refused distinctly, got %v", err)
	}
}

// TestDigestMismatchIsRefused: the attestation must describe the artifact being deployed.
func TestDigestMismatchIsRefused(t *testing.T) {
	exp := expectation()
	exp.ArtifactDigest = "sha256:something-else"
	if err := verifier(t, nil).Verify(context.Background(), attestation(t), exp); !errors.Is(err, provenance.ErrDigestMismatch) {
		t.Fatalf("a digest mismatch must be refused, got %v", err)
	}
}

// TestSourceMismatchIsRefused.
func TestSourceMismatchIsRefused(t *testing.T) {
	exp := expectation()
	exp.SourceSHA = "fff000fff000"
	if err := verifier(t, nil).Verify(context.Background(), attestation(t), exp); !errors.Is(err, provenance.ErrSourceMismatch) {
		t.Fatalf("a source mismatch must be refused, got %v", err)
	}
	exp = expectation()
	exp.Repository = "repo/acme/other"
	if err := verifier(t, nil).Verify(context.Background(), attestation(t), exp); !errors.Is(err, provenance.ErrSourceMismatch) {
		t.Fatalf("a repository mismatch must be refused, got %v", err)
	}
}

// TestStaleProvenanceIsRefused: a build from six months ago attests nothing about
// today's toolchain.
func TestStaleProvenanceIsRefused(t *testing.T) {
	k := keeper(t)
	a, err := provenance.Attest(k,
		"sha256:artifact-1", "repo/acme/app", "abc123def456", "trusted-builder", "sha256:inputs-1",
		now.Add(-60*24*time.Hour))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if err := verifier(t, nil).Verify(context.Background(), a, expectation()); !errors.Is(err, provenance.ErrStale) {
		t.Fatalf("a stale attestation must be refused, got %v", err)
	}
}

// TestFutureBuildTimeIsRefused.
func TestFutureBuildTimeIsRefused(t *testing.T) {
	k := keeper(t)
	a, err := provenance.Attest(k,
		"sha256:artifact-1", "repo/acme/app", "abc123def456", "trusted-builder", "sha256:inputs-1",
		now.Add(time.Hour))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if err := verifier(t, nil).Verify(context.Background(), a, expectation()); !errors.Is(err, provenance.ErrStale) {
		t.Fatalf("a future build time must be refused, got %v", err)
	}
}

// TestAttestRequiresIdentity: builders cannot mint anonymous attestations.
func TestAttestRequiresIdentity(t *testing.T) {
	k := keeper(t)
	if _, err := provenance.Attest(k, "", "repo/acme/app", "abc", "b", "i", now); err == nil {
		t.Fatal("an attestation must name its artifact")
	}
	if _, err := provenance.Attest(k, "sha256:x", "", "abc", "b", "i", now); err == nil {
		t.Fatal("an attestation must name its repository")
	}
}

// TestBuilderOutageIsAFault: an authorization store that cannot be read must surface,
// not silently decide.
func TestBuilderOutageIsAFault(t *testing.T) {
	b := &builders{err: errors.New("builder registry unavailable")}
	err := verifier(t, b).Verify(context.Background(), attestation(t), expectation())
	if err == nil {
		t.Fatal("a builder outage must surface")
	}
	if errors.Is(err, provenance.ErrUnauthorizedBuilder) {
		t.Fatal("an outage is a fault, not a denial")
	}
}

// TestEmptyExpectationStillVerifiesSignature: even without an expectation, forgery fails.
func TestEmptyExpectationStillVerifiesSignature(t *testing.T) {
	a := attestation(t)
	a.ArtifactDigest = "tampered"
	if err := verifier(t, nil).Verify(context.Background(), a, provenance.Expectation{}); !errors.Is(err, provenance.ErrBadSignature) {
		t.Fatalf("forgery must fail even with no expectation, got %v", err)
	}
}

// TestDescribeOmitsTheSignature.
func TestDescribeOmitsTheSignature(t *testing.T) {
	a := attestation(t)
	got := provenance.Describe(a)
	if strings.Contains(got, a.Signature) {
		t.Fatal("a description must never carry the signature")
	}
	for _, want := range []string{"repo/acme/app", "trusted-builder"} {
		if !strings.Contains(got, want) {
			t.Fatalf("a description must stay identifiable, missing %q in %q", want, got)
		}
	}
	if provenance.Describe(nil) != "no provenance" {
		t.Fatal("a missing attestation must describe itself as such")
	}
}
