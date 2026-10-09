// Package provenance verifies that an artifact was built by an authorized builder
// from known source, before anything deploys it.
//
// G0.4: "Establish preview account, protected runner build/provenance, artifact/state/
// evidence KMS boundaries." The cloud account and KMS boundaries need credentials, so
// what is owned here is the property they exist to guarantee: no artifact runs in a
// preview unless its provenance proves who built it, from what, and that the proof
// itself is authentic.
//
// An unattested artifact is not a deployable artifact with missing paperwork. It is an
// artifact nobody can account for, and deploying it means running code of unknown
// origin in an environment with credentials. So verification is a gate, not a label:
// every property checked, in an order that fails safe.
package provenance

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

// Errors returned by this package.
var (
	// ErrUnattested means no provenance was presented at all.
	ErrUnattested = errors.New("artifact has no provenance")
	// ErrBadSignature means the attestation signature does not verify.
	ErrBadSignature = errors.New("provenance signature does not verify")
	// ErrUnauthorizedBuilder means the signer may not attest for this repository.
	ErrUnauthorizedBuilder = errors.New("builder is not authorized for this repository")
	// ErrDigestMismatch means the attestation describes a different artifact than the
	// one being deployed.
	ErrDigestMismatch = errors.New("provenance describes a different artifact")
	// ErrSourceMismatch means the attestation names different source than expected.
	ErrSourceMismatch = errors.New("provenance names different source")
	// ErrStale means the attestation is too old to qualify this deployment.
	ErrStale = errors.New("provenance is too old")
)

// Attestation is a builder's signed claim about an artifact.
type Attestation struct {
	// ArtifactDigest is what was built, content-addressed.
	ArtifactDigest string
	// Repository names the source repository.
	Repository string
	// SourceSHA is the exact commit built.
	SourceSHA string
	// BuilderID names who built it.
	BuilderID string
	// InputsDigest covers the build inputs (config, recipe, base image).
	InputsDigest string
	// BuiltAt is when the build finished.
	BuiltAt time.Time
	// Signature authenticates the claim.
	Signature string
	// SignedBy names the signer.
	SignedBy string
}

// canonical returns the signed content.
func (a Attestation) canonical() string {
	return strings.Join([]string{
		"artifact:" + a.ArtifactDigest,
		"repo:" + a.Repository,
		"source:" + a.SourceSHA,
		"builder:" + a.BuilderID,
		"inputs:" + a.InputsDigest,
		"built:" + a.BuiltAt.UTC().Format(time.RFC3339),
	}, "\n")
}

// Signer signs and verifies attestations.
type Signer interface {
	// Sign authenticates canonical content.
	Sign(canonical string) (signature, signer string, err error)
	// Verify checks a signature over canonical content.
	Verify(canonical, signature string) error
}

// HMACKeeper is a development signer. Production uses KMS.
type HMACKeeper struct {
	key []byte
	id  string
}

// NewHMACKeeper builds a keeper. An empty key is refused: it would attest anything.
func NewHMACKeeper(key []byte, id string) (*HMACKeeper, error) {
	if len(key) == 0 {
		return nil, errors.New("an attestation key is required; an empty key would attest anything")
	}
	if id == "" {
		return nil, errors.New("a signer id is required")
	}
	return &HMACKeeper{key: key, id: id}, nil
}

// Sign authenticates content.
func (k *HMACKeeper) Sign(canonical string) (string, string, error) {
	mac := hmac.New(sha256.New, k.key)
	fmt.Fprintf(mac, "ghostlight-provenance:v1:%s", canonical)
	return hex.EncodeToString(mac.Sum(nil)), k.id, nil
}

// Verify checks a signature.
func (k *HMACKeeper) Verify(canonical, signature string) error {
	want, _, err := k.Sign(canonical)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(want), []byte(signature)) {
		return fmt.Errorf("%w: signature does not match the attested content", ErrBadSignature)
	}
	return nil
}

// Builders authorizes builders per repository.
type Builders interface {
	// Authorized reports whether a builder may attest for a repository.
	Authorized(ctx context.Context, builderID, repository string) (bool, error)
}

// Verifier gates deployment on provenance.
type Verifier struct {
	signer   Signer
	builders Builders
	now      func() time.Time
	// maxAge bounds how old an attestation may be. A build from six months ago
	// attests nothing about today's toolchain: the builder, its inputs, and its
	// compromises may all have changed since.
	maxAge time.Duration
}

// Config bounds a verifier.
type Config struct {
	// MaxAge bounds attestation age. Zero means the default.
	MaxAge time.Duration
	// Now overrides the clock.
	Now func() time.Time
}

// DefaultMaxAge bounds how long a build attests for.
const DefaultMaxAge = 30 * 24 * time.Hour

// NewVerifier builds a verifier.
func NewVerifier(s Signer, b Builders, cfg Config) (*Verifier, error) {
	if s == nil {
		return nil, errors.New("a provenance verifier requires a signer; unverifiable attestations are not attestations")
	}
	if b == nil {
		return nil, errors.New("a provenance verifier requires builder authorization; anyone-can-attest is no-build-protection")
	}
	maxAge := cfg.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Verifier{signer: s, builders: b, now: cfg.Now, maxAge: maxAge}, nil
}

// Expectation is what a deployment requires.
type Expectation struct {
	// ArtifactDigest is the candidate being deployed.
	ArtifactDigest string
	// Repository is the expected source repository.
	Repository string
	// SourceSHA is the expected commit. Empty means any commit qualifies, which is
	// only appropriate for environments that track a branch rather than a pin.
	SourceSHA string
}

// Verify checks an attestation against an expectation.
//
// Every property is checked: presence, signature, builder authorization, artifact
// match, source match, freshness. The order fails safe — signature before
// authorization (an unauthorized signer with a valid signature is a different problem
// from a forged one), identity before freshness (a stale attestation from the right
// builder needs rebuilding; a fresh one from the wrong builder needs investigation).
func (v *Verifier) Verify(ctx context.Context, att *Attestation, exp Expectation) error {
	if att == nil {
		return fmt.Errorf("%w for %s", ErrUnattested, exp.ArtifactDigest)
	}
	if att.ArtifactDigest == "" || att.Repository == "" || att.SourceSHA == "" || att.BuilderID == "" {
		// An attestation that does not say what, from where, from which commit, by
		// whom, attests nothing. Each missing field is a different way to smuggle an
		// unaccounted artifact past the gate.
		return fmt.Errorf("%w: attestation is missing identity fields", ErrUnattested)
	}
	if att.Signature == "" {
		return fmt.Errorf("%w: attestation carries no signature", ErrUnattested)
	}

	if err := v.signer.Verify(att.canonical(), att.Signature); err != nil {
		return err
	}

	authorized, err := v.builders.Authorized(ctx, att.BuilderID, att.Repository)
	if err != nil {
		return fmt.Errorf("authorize builder %s for %s: %w", att.BuilderID, att.Repository, err)
	}
	if !authorized {
		return fmt.Errorf("%w: %s may not attest for %s",
			ErrUnauthorizedBuilder, att.BuilderID, att.Repository)
	}

	if exp.ArtifactDigest != "" && att.ArtifactDigest != exp.ArtifactDigest {
		return fmt.Errorf("%w: attestation covers %s, deployment wants %s",
			ErrDigestMismatch, shortDigest(att.ArtifactDigest), shortDigest(exp.ArtifactDigest))
	}
	if exp.Repository != "" && att.Repository != exp.Repository {
		return fmt.Errorf("%w: attestation names %s, deployment wants %s",
			ErrSourceMismatch, att.Repository, exp.Repository)
	}
	if exp.SourceSHA != "" && att.SourceSHA != exp.SourceSHA {
		return fmt.Errorf("%w: attestation built %s, deployment wants %s",
			ErrSourceMismatch, shortSHA(att.SourceSHA), shortSHA(exp.SourceSHA))
	}

	now := v.now()
	if now.Before(att.BuiltAt) {
		return fmt.Errorf("%w: attestation claims a future build time", ErrStale)
	}
	if now.Sub(att.BuiltAt) > v.maxAge {
		return fmt.Errorf("%w: built %s, older than %s",
			ErrStale, att.BuiltAt.Format(time.RFC3339), v.maxAge)
	}
	return nil
}

// Attest creates a signed attestation. Builders call this; deployers verify.
func Attest(s Signer, artifactDigest, repository, sourceSHA, builderID, inputsDigest string, builtAt time.Time) (*Attestation, error) {
	if artifactDigest == "" || repository == "" || sourceSHA == "" || builderID == "" {
		return nil, fmt.Errorf("%w: an attestation must name artifact, repository, source, and builder", ErrUnattested)
	}
	a := &Attestation{
		ArtifactDigest: artifactDigest, Repository: repository, SourceSHA: sourceSHA,
		BuilderID: builderID, InputsDigest: inputsDigest, BuiltAt: builtAt,
	}
	sig, signer, err := s.Sign(a.canonical())
	if err != nil {
		return nil, fmt.Errorf("sign attestation: %w", err)
	}
	a.Signature, a.SignedBy = sig, signer
	return a, nil
}

func shortDigest(d string) string {
	if len(d) > 16 {
		return d[:16] + "…"
	}
	return d
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// Describe renders an attestation without its signature.
//
// A signature next to the content it authenticates is everything needed to replay the
// attestation somewhere it was never meant to go.
func Describe(a *Attestation) string {
	if a == nil {
		return "no provenance"
	}
	return fmt.Sprintf("artifact=%s repo=%s source=%s builder=%s signed-by=%s",
		shortDigest(a.ArtifactDigest), a.Repository, shortSHA(a.SourceSHA), a.BuilderID, a.SignedBy)
}
