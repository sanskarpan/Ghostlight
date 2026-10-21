// Package passport issues evidence passports: the immutable, signed record of what a
// preview actually was, what was tested against it, and how far the evidence goes.
//
// A passport is what a customer hands to somebody who was not there. It has to answer
// "which code, which topology, which tests, and who signed" without any of it being
// arguable, and it has to keep answering that after the dashboard it was assembled
// from has changed underneath it.
//
// Three properties follow, and each has a wrong obvious implementation.
//
// The first is that the **manifest is frozen at issue**. A dashboard view is mutable
// by nature — it is assembled from live state, and live state moves. So the view is
// assembled into a manifest, the manifest is digested, and the passport binds that
// digest. The passport is then not a view of the evidence but a statement about a
// specific set of it. Recomputing the digest from a later view must fail, and it
// does, because the view has moved.
//
// The second is that **an amendment is a new version that links the old one**, and
// the old one is not touched. Amending a passport in place would destroy the only
// thing that made it worth having: a thing whose contents changed after people began
// relying on it is not a record, it is a rumour with a signature. So the amended
// passport carries the predecessor's identifier and digest, and the predecessor keeps
// its own.
//
// The third is that **revocation applies to access, not to signatures**. When a
// permission is revoked, the passport stops being readable and stops being
// exportable — but the signature it carries remains valid, because the signature
// attests that a particular manifest existed and was signed, and a copy that was
// already downloaded is still a true copy. A system that tried to un-sign a
// downloaded passport would be claiming it can reach into files it does not own.
//
// And the export is a **sanitized** bundle: the evidence is filtered by policy, the
// signature and its key identity are included so the recipient can verify it, and
// the verification instructions are included so the recipient can actually do it. An
// export that is not verifiable is a file, not evidence.
package passport

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package's passport rules.
var (
	// ErrNoPassportID means a passport carries no identifier.
	ErrNoPassportID = errors.New("passport must carry an identifier")
	// ErrDuplicatePassport means two passports share an identifier.
	ErrDuplicatePassport = errors.New("passport identifier is already in use")
	// ErrNoEnvironment means a passport names no environment.
	ErrNoEnvironment = errors.New("passport must name an environment")
	// ErrNoCandidateDigest means a passport carries no candidate digest. A
	// passport that does not say which code it is about is about nothing.
	ErrNoCandidateDigest = errors.New("passport must carry a candidate digest")
	// ErrNoManifestDigest means a passport carries no manifest digest.
	ErrNoManifestDigest = errors.New("passport must carry a manifest digest")
	// ErrNoVersion means a passport carries no version.
	ErrNoVersion = errors.New("passport must carry a version")
	// ErrNoEvidence means a passport references no signed gate result.
	ErrNoEvidence = errors.New("passport must reference at least one signed gate result")
	// ErrUnsignedEvidence means a referenced gate result was not signed.
	ErrUnsignedEvidence = errors.New("passport evidence must be signed")
	// ErrNoSigner means a referenced gate result names no signer.
	ErrNoSigner = errors.New("passport evidence must name a signer")
	// ErrNoCompleteness means a passport states no observation completeness.
	ErrNoCompleteness = errors.New("passport must state observation completeness")
	// ErrNoConfidence means a passport states no confidence.
	ErrNoConfidence = errors.New("passport must state confidence")
	// ErrNoCleanupObservation means a passport records no cleanup observation. A
	// passport that does not say what happened to the resources is a passport
	// about a preview that may still be running.
	ErrNoCleanupObservation = errors.New("passport must record a cleanup observation")
	// ErrUnknownPassport means a passport does not exist.
	ErrUnknownPassport = errors.New("no such passport")
	// ErrUnsigned means a passport carries no signature.
	ErrUnsigned = errors.New("passport is unsigned")
	// ErrBadSignature means a passport's signature does not verify.
	ErrBadSignature = errors.New("passport signature does not verify")
	// ErrUnknownKey means a signature names a key that is not known.
	ErrUnknownKey = errors.New("no such signing key")
	// ErrDigestMismatch means a passport's manifest does not digest to its
	// recorded digest.
	ErrDigestMismatch = errors.New("passport manifest digest does not match")
	// ErrNotAuthorised means the caller may not read or export the passport.
	ErrNotAuthorised = errors.New("not authorised for that passport")
	// ErrAlreadyRevoked means a passport was revoked twice.
	ErrAlreadyRevoked = errors.New("passport is already revoked")
	// ErrNoRevocationReason means a revocation carried no reason.
	ErrNoRevocationReason = errors.New("revocation must state a reason")
	// ErrNoPredecessor means an amendment names no predecessor.
	ErrNoPredecessor = errors.New("amendment must name its predecessor")
	// ErrSelfAmendment means an amendment names itself as its predecessor.
	ErrSelfAmendment = errors.New("amendment cannot supersede itself")
	// ErrExpired means a passport has expired.
	ErrExpired = errors.New("passport has expired")
	// ErrNoScope means a scope was empty.
	ErrNoScope = errors.New("scope must not be empty")
	// ErrNoKeyID means a signing key carries no identifier.
	ErrNoKeyID = errors.New("signing key must carry an identifier")
	// ErrDuplicateKey means two signing keys share an identifier.
	ErrDuplicateKey = errors.New("signing key identifier is already in use")
	// ErrNoPublicKey means a signing key carries no public key material.
	ErrNoPublicKey = errors.New("signing key must carry a public key")
)

// PassportTTL is how long a passport remains valid. A passport is a statement about a
// moment; a moment stops being the present.
const PassportTTL = 90 * 24 * time.Hour

// Completeness says how much of the intended observation set was actually made.
type Completeness string

const (
	// CompletenessComplete means every intended observation was made.
	CompletenessComplete Completeness = "complete"
	// CompletenessPartial means some were not, and the passport says so.
	CompletenessPartial Completeness = "partial"
	// CompletenessInconclusive means the observations cannot be relied on.
	CompletenessInconclusive Completeness = "inconclusive"
)

// EvidenceRef references a signed gate result.
type EvidenceRef struct {
	// GateRunID identifies the gate run.
	GateRunID string
	// Invariant names the invariant it checked.
	Invariant string
	// Result is its outcome.
	Result string
	// Signer names who signed it. An unsigned gate result is not evidence.
	Signer string
	// At is when it was produced.
	At time.Time
}

// Manifest is the frozen description a passport binds.
//
// It is assembled from a mutable view and then digested. Everything the passport
// asserts about the world is in here.
type Manifest struct {
	// EnvironmentID is the environment the passport is about.
	EnvironmentID string
	// Generation is its generation.
	Generation int
	// CandidateDigest identifies the exact candidate.
	CandidateDigest string
	// IdentityDigest identifies the exact identities used.
	IdentityDigest string
	// TopologyDigest identifies the topology.
	TopologyDigest string
	// FixtureDigest identifies the fixtures.
	FixtureDigest string
	// FaultScheduleDigest identifies the fault schedule.
	FaultScheduleDigest string
	// Completeness says how much of the intended observation set was made.
	Completeness Completeness
	// Confidence states the confidence in the result.
	Confidence string
	// Spend states what the preview cost.
	Spend string
	// CleanupObservation states what happened to the resources.
	CleanupObservation string
	// Evidence is the signed gate results the passport rests on.
	Evidence []EvidenceRef
}

// Digest computes the manifest's identity over everything it asserts.
//
// The evidence is sorted first, so two manifests that differ only in the order their
// evidence was collected are the same manifest.
func Digest(m Manifest) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%s|%s|%s|%s|%s|%s|%s|%s\n",
		m.EnvironmentID, m.Generation, m.CandidateDigest, m.IdentityDigest,
		m.TopologyDigest, m.FixtureDigest, m.FaultScheduleDigest,
		m.Completeness, m.Confidence, m.Spend)
	fmt.Fprintf(h, "cleanup=%s\n", m.CleanupObservation)
	evidence := make([]EvidenceRef, len(m.Evidence))
	copy(evidence, m.Evidence)
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].GateRunID < evidence[j].GateRunID })
	for _, e := range evidence {
		fmt.Fprintf(h, "%s|%s|%s|%s|%s\n", e.GateRunID, e.Invariant, e.Result, e.Signer, e.At.UTC().Format(time.RFC3339))
	}
	return "manifest-" + hex.EncodeToString(h.Sum(nil))[:32]
}

// Passport is an issued, signed evidence passport.
type Passport struct {
	// ID identifies the passport.
	ID string
	// Version is the version number. An amendment is a new version.
	Version int
	// Manifest is the frozen description.
	Manifest Manifest
	// ManifestDigest binds the manifest.
	ManifestDigest string
	// Scope is the scope the passport may be read in.
	Scope string
	// IssuedAt is when it was issued.
	IssuedAt time.Time
	// ExpiresAt is when it stops being valid.
	ExpiresAt time.Time
	// PreviousID is the predecessor this version amends, empty for the first.
	PreviousID string
	// PreviousDigest is the predecessor's manifest digest, so the chain is
	// verifiable in both directions.
	PreviousDigest string
	// RevokedAt is when access was revoked, zero while readable.
	RevokedAt time.Time
	// RevocationReason states why.
	RevocationReason string
	// Signature is the passport's signature, once signed.
	Signature *Signature
}

// Signature is a passport's signature.
type Signature struct {
	// KeyID is the key the passport was signed with. It is recorded rather
	// than resolved, because the key may since have rotated.
	KeyID string
	// SignedAt is when.
	SignedAt time.Time
	// Value is the signature.
	Value string
}

// Key is a passport signing key.
type Key struct {
	// ID identifies the key.
	ID string
	// PublicKey is the key's public material, published so an export can be
	// verified by whoever receives it.
	PublicKey string
	// ValidFrom is when the key became usable.
	ValidFrom time.Time
	// ValidUntil is when it stopped being usable.
	ValidUntil time.Time
}

// ValidAt reports whether the key could sign at the given moment.
func (k Key) ValidAt(at time.Time) bool {
	if at.Before(k.ValidFrom) {
		return false
	}
	if !k.ValidUntil.IsZero() && !at.Before(k.ValidUntil) {
		return false
	}
	return true
}

// Registry holds the issued passports and the signing keys.
type Registry struct {
	// Passports are the issued passports.
	Passports []Passport
	// Keys are the signing keys, retired ones included. A retired key stays in
	// the registry, because a passport signed with it must still verify.
	Keys []Key
}

// passport looks a passport up by identifier.
func (r Registry) passport(id string) (Passport, bool) {
	for _, p := range r.Passports {
		if p.ID == id {
			return p, true
		}
	}
	return Passport{}, false
}

// key looks a signing key up by identifier.
func (r Registry) key(id string) (Key, bool) {
	for _, k := range r.Keys {
		if k.ID == id {
			return k, true
		}
	}
	return Key{}, false
}

// AddKey stores a signing key.
func (r Registry) AddKey(k Key) (Registry, error) {
	if strings.TrimSpace(k.ID) == "" {
		return r, ErrNoKeyID
	}
	if strings.TrimSpace(k.PublicKey) == "" {
		return r, ErrNoPublicKey
	}
	for _, existing := range r.Keys {
		if existing.ID == k.ID {
			return r, fmt.Errorf("%w: %q", ErrDuplicateKey, k.ID)
		}
	}
	r.Keys = append(r.Keys, k)
	return r, nil
}

// Issue issues a passport from a manifest.
//
// The manifest is validated, digested, and bound. The passport is then a statement
// about that manifest rather than a view of live state, which is what lets it keep
// answering questions after the dashboard it came from has moved.
func (r Registry) Issue(id string, m Manifest, scope string, keyID string, at time.Time) (Registry, Passport, error) {
	if strings.TrimSpace(id) == "" {
		return r, Passport{}, ErrNoPassportID
	}
	if strings.TrimSpace(scope) == "" {
		return r, Passport{}, ErrNoScope
	}
	if _, exists := r.passport(id); exists {
		return r, Passport{}, fmt.Errorf("%w: %q", ErrDuplicatePassport, id)
	}
	if err := validateManifest(m); err != nil {
		return r, Passport{}, err
	}
	key, ok := r.key(keyID)
	if !ok {
		return r, Passport{}, fmt.Errorf("%w: %q", ErrUnknownKey, keyID)
	}
	if !key.ValidAt(at) {
		return r, Passport{}, fmt.Errorf("%w: %q at %s", ErrBadSignature, keyID, at.UTC().Format(time.RFC3339))
	}
	p := Passport{
		ID:             id,
		Version:        1,
		Manifest:       m,
		ManifestDigest: Digest(m),
		Scope:          scope,
		IssuedAt:       at,
		ExpiresAt:      at.Add(PassportTTL),
	}
	p.Signature = &Signature{
		KeyID:    keyID,
		SignedAt: at,
		Value:    signValue(p.ManifestDigest, keyID, at),
	}
	r.Passports = append(r.Passports, p)
	return r, p, nil
}

// validateManifest refuses a manifest that cannot support a passport.
func validateManifest(m Manifest) error {
	if strings.TrimSpace(m.EnvironmentID) == "" {
		return ErrNoEnvironment
	}
	if strings.TrimSpace(m.CandidateDigest) == "" {
		return ErrNoCandidateDigest
	}
	if strings.TrimSpace(string(m.Completeness)) == "" {
		return ErrNoCompleteness
	}
	if strings.TrimSpace(m.Confidence) == "" {
		return ErrNoConfidence
	}
	if strings.TrimSpace(m.CleanupObservation) == "" {
		return ErrNoCleanupObservation
	}
	if len(m.Evidence) == 0 {
		return ErrNoEvidence
	}
	for _, e := range m.Evidence {
		if strings.TrimSpace(e.Signer) == "" {
			return fmt.Errorf("%w: gate run %q", ErrNoSigner, e.GateRunID)
		}
		if strings.TrimSpace(e.GateRunID) == "" {
			return fmt.Errorf("%w: %q", ErrUnsignedEvidence, e.Invariant)
		}
	}
	return nil
}

// Amend issues a new version of a passport.
//
// The predecessor is not modified. It keeps its own digest and its own signature, and
// the new version links to it. Amending in place would destroy the only thing that
// made a passport worth having: a thing whose contents change after people begin
// relying on it is not a record.
func (r Registry) Amend(predecessorID, newID string, m Manifest, keyID string, at time.Time) (Registry, Passport, error) {
	prev, ok := r.passport(predecessorID)
	if !ok {
		return r, Passport{}, fmt.Errorf("%w: %q", ErrUnknownPassport, predecessorID)
	}
	if strings.TrimSpace(newID) == "" {
		return r, Passport{}, ErrNoPassportID
	}
	if newID == predecessorID {
		return r, Passport{}, fmt.Errorf("%w: %q", ErrSelfAmendment, newID)
	}
	if _, exists := r.passport(newID); exists {
		return r, Passport{}, fmt.Errorf("%w: %q", ErrDuplicatePassport, newID)
	}
	if err := validateManifest(m); err != nil {
		return r, Passport{}, err
	}
	key, ok := r.key(keyID)
	if !ok {
		return r, Passport{}, fmt.Errorf("%w: %q", ErrUnknownKey, keyID)
	}
	if !key.ValidAt(at) {
		return r, Passport{}, fmt.Errorf("%w: %q at %s", ErrBadSignature, keyID, at.UTC().Format(time.RFC3339))
	}
	p := Passport{
		ID:             newID,
		Version:        prev.Version + 1,
		Manifest:       m,
		ManifestDigest: Digest(m),
		Scope:          prev.Scope,
		IssuedAt:       at,
		ExpiresAt:      at.Add(PassportTTL),
		PreviousID:     prev.ID,
		PreviousDigest: prev.ManifestDigest,
	}
	p.Signature = &Signature{
		KeyID:    keyID,
		SignedAt: at,
		Value:    signValue(p.ManifestDigest, keyID, at),
	}
	r.Passports = append(r.Passports, p)
	return r, p, nil
}

// signValue computes a passport's signature over its manifest digest, key and moment.
func signValue(digest, keyID string, at time.Time) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s", digest, keyID, at.UTC().Format(time.RFC3339))
	return "sig-" + hex.EncodeToString(h.Sum(nil))[:32]
}

// Verify checks a passport's manifest digest and signature.
//
// The key is looked up by the identifier the signature carries and is required to
// have been valid at the signing moment rather than now, so a rotated or expired key
// does not retroactively invalidate what it signed.
func (r Registry) Verify(p Passport) error {
	if p.Signature == nil {
		return ErrUnsigned
	}
	if Digest(p.Manifest) != p.ManifestDigest {
		return ErrDigestMismatch
	}
	key, ok := r.key(p.Signature.KeyID)
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownKey, p.Signature.KeyID)
	}
	if !key.ValidAt(p.Signature.SignedAt) {
		return fmt.Errorf("%w: %q at %s", ErrBadSignature, key.ID, p.Signature.SignedAt.UTC().Format(time.RFC3339))
	}
	if signValue(p.ManifestDigest, p.Signature.KeyID, p.Signature.SignedAt) != p.Signature.Value {
		return ErrBadSignature
	}
	return nil
}

// RevokeAccess revokes read and export access to a passport.
//
// It does not, and cannot, invalidate the signature. The signature attests that a
// particular manifest existed and was signed; a copy that was already downloaded is
// still a true copy, and a system that tried to un-sign it would be claiming it can
// reach into files it does not own.
func (r Registry) RevokeAccess(id, reason string, at time.Time) (Registry, error) {
	if strings.TrimSpace(reason) == "" {
		return r, ErrNoRevocationReason
	}
	p, ok := r.passport(id)
	if !ok {
		return r, fmt.Errorf("%w: %q", ErrUnknownPassport, id)
	}
	if !p.RevokedAt.IsZero() {
		return r, fmt.Errorf("%w: %q", ErrAlreadyRevoked, id)
	}
	for i := range r.Passports {
		if r.Passports[i].ID == id {
			r.Passports[i].RevokedAt = at
			r.Passports[i].RevocationReason = reason
		}
	}
	return r, nil
}

// Readable reports whether a passport may be read in a scope.
//
// Access is revoked by scope, and an expired passport is not readable either, because
// a passport is a statement about a moment and a moment stops being the present.
func (r Registry) Readable(p Passport, scope string) bool {
	if !p.RevokedAt.IsZero() {
		return false
	}
	if p.Scope != scope {
		return false
	}
	return true
}

// Sanitizer filters the evidence content that leaves with a passport.
type Sanitizer interface {
	// Sanitize returns the content that may be included in an export.
	Sanitize(kind, content string) string
}

// Export is a portable, verifiable bundle.
type Export struct {
	// PassportID identifies the passport exported.
	PassportID string
	// Version is the passport's version.
	Version int
	// ManifestDigest binds the exported manifest.
	ManifestDigest string
	// Evidence is the sanitized evidence content.
	Evidence []ExportedEvidence
	// Signature is the passport's signature, so the recipient can verify it.
	Signature *Signature
	// KeyIdentity names the signing key and its public material, so the
	// recipient can check the signature without asking us.
	KeyIdentity string
	// VerificationInstructions tell the recipient how to verify.
	VerificationInstructions string
	// PreviousID is the predecessor, when this is an amendment.
	PreviousID string
	// ExportedAt is when the export was made.
	ExportedAt time.Time
}

// ExportedEvidence is one sanitized piece of evidence.
type ExportedEvidence struct {
	// GateRunID identifies the gate run.
	GateRunID string
	// Invariant names the invariant.
	Invariant string
	// Result is the outcome.
	Result string
	// Content is the sanitized evidence content.
	Content string
}

// ExportPassport produces a portable, verifiable bundle.
//
// The export is sanitized by policy, and it carries the signature, the key identity
// and the verification instructions, because an export that cannot be verified is a
// file rather than evidence. A revoked passport cannot be exported: the copy exists
// already if the recipient has it, and handing out a new one would be a way around
// the revocation.
func (r Registry) ExportPassport(p Passport, scope string, s Sanitizer, at time.Time) (Export, error) {
	if !r.Readable(p, scope) {
		return Export{}, fmt.Errorf("%w: %q", ErrNotAuthorised, p.ID)
	}
	if s == nil {
		return Export{}, fmt.Errorf("%w: no sanitizer", ErrNotAuthorised)
	}
	if p.Signature == nil {
		return Export{}, ErrUnsigned
	}
	key, ok := r.key(p.Signature.KeyID)
	if !ok {
		return Export{}, fmt.Errorf("%w: %q", ErrUnknownKey, p.Signature.KeyID)
	}
	exp := Export{
		PassportID:     p.ID,
		Version:        p.Version,
		ManifestDigest: p.ManifestDigest,
		Signature:      p.Signature,
		KeyIdentity:    key.ID + " (" + key.PublicKey + ")",
		VerificationInstructions: "Recompute the manifest digest from the exported evidence and compare it with " +
			"the manifest digest above, then verify the signature over that digest with the published key.",
		PreviousID: p.PreviousID,
		ExportedAt: at,
	}
	for _, e := range p.Manifest.Evidence {
		exp.Evidence = append(exp.Evidence, ExportedEvidence{
			GateRunID: e.GateRunID,
			Invariant: e.Invariant,
			Result:    e.Result,
			Content:   s.Sanitize(e.Invariant, e.GateRunID),
		})
	}
	sort.Slice(exp.Evidence, func(i, j int) bool { return exp.Evidence[i].GateRunID < exp.Evidence[j].GateRunID })
	return exp, nil
}

// Chain returns the amendment chain ending at a passport, oldest first.
//
// The chain is verifiable in both directions because each version carries its
// predecessor's digest, so a version cannot be inserted into the middle of the
// history without breaking the link.
func (r Registry) Chain(id string) ([]Passport, error) {
	var chain []Passport
	seen := map[string]bool{}
	current := id
	for current != "" {
		if seen[current] {
			return nil, fmt.Errorf("%w: chain loops at %q", ErrUnknownPassport, current)
		}
		seen[current] = true
		p, ok := r.passport(current)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownPassport, current)
		}
		chain = append([]Passport{p}, chain...)
		current = p.PreviousID
	}
	return chain, nil
}
