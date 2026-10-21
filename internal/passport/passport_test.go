package passport

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2027, 2, 3, 11, 0, 0, 0, time.UTC)

func manifest() Manifest {
	return Manifest{
		EnvironmentID:       "env-1",
		Generation:          4,
		CandidateDigest:     "sha256:candidate",
		IdentityDigest:      "sha256:identities",
		TopologyDigest:      "sha256:topology",
		FixtureDigest:       "sha256:fixtures",
		FaultScheduleDigest: "sha256:faults",
		Completeness:        CompletenessComplete,
		Confidence:          "high",
		Spend:               "3.42 usd",
		CleanupObservation:  "all resources verified absent",
		Evidence: []EvidenceRef{
			{GateRunID: "run-2", Invariant: "isolation", Result: "pass", Signer: "harness", At: now.Add(-time.Hour)},
			{GateRunID: "run-1", Invariant: "duplicate_effects", Result: "pass", Signer: "harness", At: now.Add(-time.Hour)},
		},
	}
}

func registry(t *testing.T) Registry {
	t.Helper()
	r, err := (Registry{}).AddKey(Key{
		ID: "signer-1", PublicKey: "ed25519:abc", ValidFrom: now.Add(-365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	return r
}

// redactAll is a sanitizer that withholds everything.
type redactAll struct{}

func (redactAll) Sanitize(kind, content string) string { return "[redacted]" }

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

func TestAddKeyRefusesUnusableKeys(t *testing.T) {
	if _, err := (Registry{}).AddKey(Key{PublicKey: "k"}); !errors.Is(err, ErrNoKeyID) {
		t.Errorf("AddKey error = %v, want ErrNoKeyID", err)
	}
	if _, err := (Registry{}).AddKey(Key{ID: "k"}); !errors.Is(err, ErrNoPublicKey) {
		t.Errorf("AddKey error = %v, want ErrNoPublicKey", err)
	}
	r := registry(t)
	if _, err := r.AddKey(Key{ID: "signer-1", PublicKey: "ed25519:abc"}); !errors.Is(err, ErrDuplicateKey) {
		t.Errorf("AddKey error = %v, want ErrDuplicateKey", err)
	}
}

// ---------------------------------------------------------------------------
// Manifest and issue
// ---------------------------------------------------------------------------

// A passport that does not say which code it is about is about nothing.
func TestIssueRefusesAManifestThatCannotSupportAPassport(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Manifest)
		want   error
	}{
		"no environment":    {func(m *Manifest) { m.EnvironmentID = "" }, ErrNoEnvironment},
		"no candidate":      {func(m *Manifest) { m.CandidateDigest = "" }, ErrNoCandidateDigest},
		"no completeness":   {func(m *Manifest) { m.Completeness = "" }, ErrNoCompleteness},
		"no confidence":     {func(m *Manifest) { m.Confidence = "" }, ErrNoConfidence},
		"no cleanup":        {func(m *Manifest) { m.CleanupObservation = "" }, ErrNoCleanupObservation},
		"no evidence":       {func(m *Manifest) { m.Evidence = nil }, ErrNoEvidence},
		"unsigned evidence": {func(m *Manifest) { m.Evidence[0].Signer = "" }, ErrNoSigner},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := manifest()
			tc.mutate(&m)
			if _, _, err := registry(t).Issue("passport-1", m, "repo:acme", "signer-1", now); !errors.Is(err, tc.want) {
				t.Errorf("Issue error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestIssueRefusesAnUnknownOrInvalidKey(t *testing.T) {
	r := registry(t)
	if _, _, err := r.Issue("passport-1", manifest(), "repo:acme", "no-such-key", now); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("Issue error = %v, want ErrUnknownKey", err)
	}
	r, err := r.AddKey(Key{ID: "old", PublicKey: "k", ValidFrom: now.Add(-48 * time.Hour), ValidUntil: now.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if _, _, err := r.Issue("passport-1", manifest(), "repo:acme", "old", now); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Issue error = %v, want ErrBadSignature", err)
	}
}

func TestIssueRefusesADuplicateIdentifier(t *testing.T) {
	r, _, err := registry(t).Issue("passport-1", manifest(), "repo:acme", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, _, err := r.Issue("passport-1", manifest(), "repo:acme", "signer-1", now); !errors.Is(err, ErrDuplicatePassport) {
		t.Errorf("Issue error = %v, want ErrDuplicatePassport", err)
	}
}

func TestIssueRefusesAnEmptyScope(t *testing.T) {
	if _, _, err := registry(t).Issue("passport-1", manifest(), "  ", "signer-1", now); !errors.Is(err, ErrNoScope) {
		t.Errorf("Issue error = %v, want ErrNoScope", err)
	}
}

// Two manifests that differ only in the order their evidence was collected are the
// same manifest.
func TestDigestIsInvariantUnderEvidenceOrdering(t *testing.T) {
	a := manifest()
	b := manifest()
	b.Evidence[0], b.Evidence[1] = b.Evidence[1], b.Evidence[0]
	if Digest(a) != Digest(b) {
		t.Error("the digest must not depend on the order evidence was collected")
	}
	c := manifest()
	c.CandidateDigest = "sha256:other"
	if Digest(a) == Digest(c) {
		t.Error("a changed candidate must change the digest")
	}
}

// A passport is a statement about a manifest, not a view of live state.
func TestThePassportBindsTheManifestItWasGiven(t *testing.T) {
	r, p, err := registry(t).Issue("passport-1", manifest(), "repo:acme", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if p.ManifestDigest != Digest(p.Manifest) {
		t.Error("the passport must bind the manifest digest")
	}
	if err := r.Verify(p); err != nil {
		t.Errorf("Verify: %v", err)
	}
	// The live view has moved on; the passport has not.
	moved := p.Manifest
	moved.Confidence = "low"
	if Digest(moved) == p.ManifestDigest {
		t.Error("the moved view must digest differently")
	}
	if err := r.Verify(p); err != nil {
		t.Errorf("the passport must still verify against its own manifest: %v", err)
	}
}

func TestVerifyRefusesATamperedPassport(t *testing.T) {
	r, p, err := registry(t).Issue("passport-1", manifest(), "repo:acme", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	tampered := p
	tampered.Manifest.Confidence = "certain"
	if err := r.Verify(tampered); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("Verify error = %v, want ErrDigestMismatch", err)
	}
	unsigned := p
	unsigned.Signature = nil
	if err := r.Verify(unsigned); !errors.Is(err, ErrUnsigned) {
		t.Errorf("Verify error = %v, want ErrUnsigned", err)
	}
	forged := p
	sig := *p.Signature
	sig.Value = "sig-forged"
	forged.Signature = &sig
	if err := r.Verify(forged); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Verify error = %v, want ErrBadSignature", err)
	}
	orphan := p
	orphanSig := *p.Signature
	orphanSig.KeyID = "no-such-key"
	orphan.Signature = &orphanSig
	if err := r.Verify(orphan); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("Verify error = %v, want ErrUnknownKey", err)
	}
}

// A key that has since rotated out does not retroactively invalidate what it signed.
func TestASignatureSurvivesRotationOfItsKey(t *testing.T) {
	r, p, err := registry(t).Issue("passport-1", manifest(), "repo:acme", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rotated, err := r.AddKey(Key{ID: "signer-2", PublicKey: "ed25519:def", ValidFrom: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	for i := range rotated.Keys {
		if rotated.Keys[i].ID == "signer-1" {
			rotated.Keys[i].ValidUntil = now.Add(time.Hour)
		}
	}
	if err := rotated.Verify(p); err != nil {
		t.Errorf("the passport must still verify after rotation: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Amendment
// ---------------------------------------------------------------------------

// Amending in place would destroy the only thing that made a passport worth having: a
// thing whose contents change after people begin relying on it is not a record.
func TestAnAmendmentCreatesANewVersionAndLeavesTheOldOneAlone(t *testing.T) {
	r, first, err := registry(t).Issue("passport-1", manifest(), "repo:acme", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	corrected := manifest()
	corrected.Confidence = "medium"
	corrected.CleanupObservation = "one resource quarantined"

	r, amended, err := r.Amend("passport-1", "passport-2", corrected, "signer-1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Amend: %v", err)
	}
	if amended.Version != 2 {
		t.Errorf("version = %d, want 2", amended.Version)
	}
	if amended.PreviousID != "passport-1" {
		t.Errorf("previous = %q, want passport-1", amended.PreviousID)
	}
	if amended.PreviousDigest != first.ManifestDigest {
		t.Error("the amendment must link the predecessor's digest")
	}
	// The predecessor is untouched.
	kept, _ := r.passport("passport-1")
	if kept.ManifestDigest != first.ManifestDigest {
		t.Error("the predecessor's digest must not change")
	}
	if kept.Version != 1 {
		t.Errorf("the predecessor's version = %d, want 1", kept.Version)
	}
	if err := r.Verify(kept); err != nil {
		t.Errorf("the predecessor must still verify: %v", err)
	}
	if err := r.Verify(amended); err != nil {
		t.Errorf("the amendment must verify: %v", err)
	}
}

func TestAmendRefusesUnknownSelfAndDuplicateIdentifiers(t *testing.T) {
	r, _, err := registry(t).Issue("passport-1", manifest(), "repo:acme", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, _, err := r.Amend("no-such", "passport-2", manifest(), "signer-1", now); !errors.Is(err, ErrUnknownPassport) {
		t.Errorf("Amend error = %v, want ErrUnknownPassport", err)
	}
	if _, _, err := r.Amend("passport-1", "passport-1", manifest(), "signer-1", now); !errors.Is(err, ErrSelfAmendment) {
		t.Errorf("Amend error = %v, want ErrSelfAmendment", err)
	}
	r, _, err = r.Amend("passport-1", "passport-2", manifest(), "signer-1", now)
	if err != nil {
		t.Fatalf("Amend: %v", err)
	}
	if _, _, err := r.Amend("passport-1", "passport-2", manifest(), "signer-1", now); !errors.Is(err, ErrDuplicatePassport) {
		t.Errorf("Amend error = %v, want ErrDuplicatePassport", err)
	}
}

// The chain is verifiable in both directions because each version carries its
// predecessor's digest.
func TestChainReturnsTheHistoryOldestFirst(t *testing.T) {
	r, _, err := registry(t).Issue("passport-1", manifest(), "repo:acme", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	r, _, err = r.Amend("passport-1", "passport-2", manifest(), "signer-1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Amend: %v", err)
	}
	chain, err := r.Chain("passport-2")
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	if len(chain) != 2 || chain[0].ID != "passport-1" || chain[1].ID != "passport-2" {
		t.Errorf("chain = %v, want passport-1 then passport-2", chain)
	}
	if _, err := r.Chain("no-such"); !errors.Is(err, ErrUnknownPassport) {
		t.Errorf("Chain error = %v, want ErrUnknownPassport", err)
	}
}

// ---------------------------------------------------------------------------
// Revocation and export
// ---------------------------------------------------------------------------

// Revocation applies to access, not to signatures.
func TestRevocationAppliesToAccessAndNotToTheSignature(t *testing.T) {
	r, _, err := registry(t).Issue("passport-1", manifest(), "repo:acme", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	r, err = r.RevokeAccess("passport-1", "the customer asked us to stop sharing it", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	revoked, _ := r.passport("passport-1")
	if revoked.RevokedAt.IsZero() || revoked.RevocationReason == "" {
		t.Errorf("the revocation must be recorded, got %+v", revoked)
	}
	if r.Readable(revoked, "repo:acme") {
		t.Error("a revoked passport must not be readable")
	}
	if _, err := r.ExportPassport(revoked, "repo:acme", redactAll{}, now); !errors.Is(err, ErrNotAuthorised) {
		t.Errorf("ExportPassport error = %v, want ErrNotAuthorised", err)
	}
	// But the signature still verifies: a copy already downloaded is still a true copy.
	if err := r.Verify(revoked); err != nil {
		t.Errorf("the signature must survive revocation: %v", err)
	}
}

func TestRevokeAccessRequiresAReasonAndRefusesRepeats(t *testing.T) {
	r, _, err := registry(t).Issue("passport-1", manifest(), "repo:acme", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := r.RevokeAccess("passport-1", "  ", now); !errors.Is(err, ErrNoRevocationReason) {
		t.Errorf("RevokeAccess error = %v, want ErrNoRevocationReason", err)
	}
	if _, err := r.RevokeAccess("no-such", "why", now); !errors.Is(err, ErrUnknownPassport) {
		t.Errorf("RevokeAccess error = %v, want ErrUnknownPassport", err)
	}
	r, err = r.RevokeAccess("passport-1", "why", now)
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if _, err := r.RevokeAccess("passport-1", "again", now); !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("second RevokeAccess error = %v, want ErrAlreadyRevoked", err)
	}
}

// Access is scoped, and a passport from another scope is not readable.
func TestAccessIsScoped(t *testing.T) {
	r, p, err := registry(t).Issue("passport-1", manifest(), "repo:acme", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !r.Readable(p, "repo:acme") {
		t.Error("the passport must be readable in its own scope")
	}
	if r.Readable(p, "repo:other") {
		t.Error("the passport must not be readable in another scope")
	}
	if _, err := r.ExportPassport(p, "repo:other", redactAll{}, now); !errors.Is(err, ErrNotAuthorised) {
		t.Errorf("ExportPassport error = %v, want ErrNotAuthorised", err)
	}
}

// An export that cannot be verified is a file, not evidence.
func TestExportCarriesTheSignatureKeyAndInstructions(t *testing.T) {
	r, p, err := registry(t).Issue("passport-1", manifest(), "repo:acme", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	exp, err := r.ExportPassport(p, "repo:acme", redactAll{}, now)
	if err != nil {
		t.Fatalf("ExportPassport: %v", err)
	}
	if exp.Signature == nil {
		t.Error("the export must carry the signature")
	}
	if exp.Signature.Value != p.Signature.Value {
		t.Error("the exported signature must be the passport's")
	}
	if !strings.Contains(exp.KeyIdentity, "signer-1") || !strings.Contains(exp.KeyIdentity, "ed25519:abc") {
		t.Errorf("key identity = %q, want the key and its public material", exp.KeyIdentity)
	}
	if exp.VerificationInstructions == "" {
		t.Error("the export must say how to verify it")
	}
	if exp.ManifestDigest != p.ManifestDigest {
		t.Error("the export must carry the manifest digest")
	}
	if len(exp.Evidence) != len(p.Manifest.Evidence) {
		t.Errorf("evidence = %v, want every referenced gate result", exp.Evidence)
	}
	for _, e := range exp.Evidence {
		if e.Content != "[redacted]" {
			t.Errorf("the evidence must be sanitized, got %q", e.Content)
		}
	}
}

func TestExportRefusesAnAbsentSanitizer(t *testing.T) {
	r, p, err := registry(t).Issue("passport-1", manifest(), "repo:acme", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := r.ExportPassport(p, "repo:acme", nil, now); !errors.Is(err, ErrNotAuthorised) {
		t.Errorf("ExportPassport error = %v, want ErrNotAuthorised", err)
	}
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

// Issue a passport, verify it, amend it, export the amendment, then revoke access and
// confirm the export is refused while the signature still verifies.
func TestHappyPathIssueAmendExportRevoke(t *testing.T) {
	r, first, err := registry(t).Issue("passport-1", manifest(), "repo:acme", "signer-1", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := r.Verify(first); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	corrected := manifest()
	corrected.CleanupObservation = "one resource quarantined, the rest verified absent"
	r, amended, err := r.Amend("passport-1", "passport-2", corrected, "signer-1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Amend: %v", err)
	}
	chain, err := r.Chain("passport-2")
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	if len(chain) != 2 {
		t.Errorf("chain = %v, want two versions", chain)
	}

	exp, err := r.ExportPassport(amended, "repo:acme", redactAll{}, now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("ExportPassport: %v", err)
	}
	if exp.PreviousID != "passport-1" {
		t.Errorf("export predecessor = %q, want passport-1", exp.PreviousID)
	}

	r, err = r.RevokeAccess("passport-2", "the engagement ended", now.Add(3*time.Hour))
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	revoked, _ := r.passport("passport-2")
	if _, err := r.ExportPassport(revoked, "repo:acme", redactAll{}, now.Add(4*time.Hour)); !errors.Is(err, ErrNotAuthorised) {
		t.Errorf("ExportPassport error = %v, want ErrNotAuthorised", err)
	}
	if err := r.Verify(revoked); err != nil {
		t.Errorf("the signature must survive revocation: %v", err)
	}
}
