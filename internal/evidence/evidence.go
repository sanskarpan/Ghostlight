// Package evidence verifies that a gate result is bound to the exact candidate it
// claims to qualify.
//
// G3.2: "Bind gate evidence to source/base/artifact/config/recipe/schema/policy/
// generation."
//
// A gate result that is not bound to its candidate is an ornament. It says "pass"
// without saying pass *of what* — and an unbound pass is reusable: yesterday's pass
// for yesterday's code becomes today's qualification for today's code, which is how a
// candidate ships without ever being tested. The G1 gate already proved the platform
// takes generation fencing seriously for lifecycle state; this package applies the same
// discipline to gate results.
//
// Binding is total: source, base, artifact, config, recipe, schema, policy, and
// generation must all match, the evidence must be fresh, and the signature must
// verify. Any gap refuses. A result that is almost bound — seven of eight digests — is
// not bound at all, because the missing digest is exactly the dimension along which
// the candidate changed.
package evidence

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package.
var (
	// ErrUnbound means the evidence does not identify what it qualifies.
	ErrUnbound = errors.New("gate evidence is not bound to a candidate")
	// ErrStaleResult means the evidence qualifies an older generation than current.
	ErrStaleResult = errors.New("gate evidence qualifies a stale generation")
	// ErrDigestMismatch means one of the bound digests differs.
	ErrDigestMismatch = errors.New("gate evidence digest mismatch")
	// ErrBadSignature means the evidence signature does not verify.
	ErrBadSignature = errors.New("gate evidence signature does not verify")
	// ErrExpiredEvidence means the evidence outlived its validity.
	ErrExpiredEvidence = errors.New("gate evidence has expired")
	// ErrNotPassing means the recorded outcome is not a pass.
	ErrNotPassing = errors.New("gate evidence does not record a pass")
)

// Binding is the candidate a result claims to qualify.
type Binding struct {
	SourceSHA      string
	BaseSHA        string
	ArtifactDigest string
	ConfigDigest   string
	RecipeDigest   string
	SchemaDigest   string
	PolicyDigest   string
	Generation     uint64
}

// Complete reports whether every dimension is named.
func (b Binding) Complete() bool {
	return b.SourceSHA != "" && b.BaseSHA != "" && b.ArtifactDigest != "" &&
		b.ConfigDigest != "" && b.RecipeDigest != "" && b.SchemaDigest != "" &&
		b.PolicyDigest != "" && b.Generation > 0
}

// Missing names the absent dimensions, stably ordered.
func (b Binding) Missing() []string {
	var out []string
	if b.SourceSHA == "" {
		out = append(out, "source_sha")
	}
	if b.BaseSHA == "" {
		out = append(out, "base_sha")
	}
	if b.ArtifactDigest == "" {
		out = append(out, "artifact_digest")
	}
	if b.ConfigDigest == "" {
		out = append(out, "config_digest")
	}
	if b.RecipeDigest == "" {
		out = append(out, "recipe_digest")
	}
	if b.SchemaDigest == "" {
		out = append(out, "schema_digest")
	}
	if b.PolicyDigest == "" {
		out = append(out, "policy_digest")
	}
	if b.Generation == 0 {
		out = append(out, "generation")
	}
	sort.Strings(out)
	return out
}

// canonical returns the signed content.
func (b Binding) canonical(harness, outcome string, at time.Time, expiresAt time.Time) string {
	return strings.Join([]string{
		"source:" + b.SourceSHA,
		"base:" + b.BaseSHA,
		"artifact:" + b.ArtifactDigest,
		"config:" + b.ConfigDigest,
		"recipe:" + b.RecipeDigest,
		"schema:" + b.SchemaDigest,
		"policy:" + b.PolicyDigest,
		fmt.Sprintf("generation:%d", b.Generation),
		"harness:" + harness,
		"outcome:" + outcome,
		"at:" + at.UTC().Format(time.RFC3339),
		"expires:" + expiresAt.UTC().Format(time.RFC3339),
	}, "\n")
}

// Result is a gate outcome bound to a candidate.
type Result struct {
	// Harness names what produced it.
	Harness string
	// Outcome is pass, fail, inconclusive, or canceled.
	Outcome string
	// Binding names what it qualifies.
	Binding Binding
	// At is when the harness finished.
	At time.Time
	// ExpiresAt bounds how long the result qualifies for.
	ExpiresAt time.Time
	// Signature authenticates the record.
	Signature string
	// SignedBy names the signer.
	SignedBy string
}

// Signer signs and verifies result records.
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

// NewHMACKeeper builds a keeper. An empty key is refused: it would qualify anything.
func NewHMACKeeper(key []byte, id string) (*HMACKeeper, error) {
	if len(key) == 0 {
		return nil, errors.New("an evidence signing key is required; an empty key would qualify anything")
	}
	if id == "" {
		return nil, errors.New("a signer id is required")
	}
	return &HMACKeeper{key: key, id: id}, nil
}

// Sign authenticates content.
func (k *HMACKeeper) Sign(canonical string) (string, string, error) {
	mac := hmac.New(sha256.New, k.key)
	fmt.Fprintf(mac, "ghostlight-evidence:v1:%s", canonical)
	return hex.EncodeToString(mac.Sum(nil)), k.id, nil
}

// Verify checks a signature.
func (k *HMACKeeper) Verify(canonical, signature string) error {
	want, _, err := k.Sign(canonical)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(want), []byte(signature)) {
		return fmt.Errorf("%w: signature does not match the record", ErrBadSignature)
	}
	return nil
}

// Seal signs a result record. Harnesses call this; verifiers check it.
func Seal(s Signer, harness, outcome string, b Binding, at, expiresAt time.Time) (*Result, error) {
	if harness == "" || outcome == "" {
		return nil, fmt.Errorf("%w: a result must name its harness and outcome", ErrUnbound)
	}
	r := &Result{Harness: harness, Outcome: outcome, Binding: b, At: at, ExpiresAt: expiresAt}
	sig, signer, err := s.Sign(b.canonical(harness, outcome, at, expiresAt))
	if err != nil {
		return nil, fmt.Errorf("sign result: %w", err)
	}
	r.Signature, r.SignedBy = sig, signer
	return r, nil
}

// Expectation is what a deployment requires a result to qualify.
type Expectation struct {
	Binding Binding
}

// Verifier checks results against expectations.
type Verifier struct {
	signer Signer
	now    func() time.Time
}

// NewVerifier builds a verifier.
func NewVerifier(s Signer, now func() time.Time) (*Verifier, error) {
	if s == nil {
		return nil, errors.New("an evidence verifier requires a signer; unverifiable results are not results")
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Verifier{signer: s, now: now}, nil
}

// Verify checks that a result qualifies an expectation.
//
// The checks run in an order that fails safe and diagnoses well. Outcome first: a
// non-pass qualifies nothing regardless of binding. Binding completeness second: a
// result that does not say what it qualifies cannot qualify anything. Signature third:
// only then is the record worth comparing. Generation fourth: a result for an older
// generation is stale even if every digest matches, because the candidate moved on.
// Digests last, each named: the one that differs is the dimension the candidate changed
// along, and that is exactly what an operator needs to know.
func (v *Verifier) Verify(_ context.Context, r *Result, exp Expectation) error {
	if r == nil {
		return fmt.Errorf("%w: no result presented", ErrUnbound)
	}
	if r.Outcome != "pass" {
		// Only a pass qualifies. A fail, inconclusive, or canceled result presented
		// as qualification is refused outright — not reinterpreted, not upgraded.
		return fmt.Errorf("%w: outcome is %q", ErrNotPassing, r.Outcome)
	}
	if missing := r.Binding.Missing(); len(missing) > 0 {
		return fmt.Errorf("%w: missing %v", ErrUnbound, missing)
	}
	if r.Signature == "" {
		return fmt.Errorf("%w: no signature", ErrUnbound)
	}
	if err := v.signer.Verify(
		r.Binding.canonical(r.Harness, r.Outcome, r.At, r.ExpiresAt), r.Signature); err != nil {
		return err
	}

	now := v.now()
	if !now.Before(r.ExpiresAt) {
		return fmt.Errorf("%w at %s", ErrExpiredEvidence, r.ExpiresAt.Format(time.RFC3339))
	}

	// Generation is checked before digests. A newer candidate with identical digests
	// everywhere except generation is still a different candidate — the fence the G1
	// gate proved for lifecycle state applies to gate results with equal force.
	if r.Binding.Generation != exp.Binding.Generation {
		return fmt.Errorf("%w: result qualifies generation %d, current is %d",
			ErrStaleResult, r.Binding.Generation, exp.Binding.Generation)
	}

	// Each digest compared and named. Seven of eight matching is not bound: the one
	// that differs is the dimension the candidate changed along.
	pairs := []struct {
		name string
		got  string
		want string
	}{
		{"source_sha", r.Binding.SourceSHA, exp.Binding.SourceSHA},
		{"base_sha", r.Binding.BaseSHA, exp.Binding.BaseSHA},
		{"artifact_digest", r.Binding.ArtifactDigest, exp.Binding.ArtifactDigest},
		{"config_digest", r.Binding.ConfigDigest, exp.Binding.ConfigDigest},
		{"recipe_digest", r.Binding.RecipeDigest, exp.Binding.RecipeDigest},
		{"schema_digest", r.Binding.SchemaDigest, exp.Binding.SchemaDigest},
		{"policy_digest", r.Binding.PolicyDigest, exp.Binding.PolicyDigest},
	}
	for _, p := range pairs {
		if p.want != "" && p.got != p.want {
			return fmt.Errorf("%w: %s differs", ErrDigestMismatch, p.name)
		}
	}
	return nil
}

// Describe renders a result without its signature.
//
// A signature next to the content it authenticates is everything needed to replay the
// result for a candidate it never examined.
func Describe(r *Result) string {
	if r == nil {
		return "no result"
	}
	return fmt.Sprintf("harness=%s outcome=%s generation=%d expires=%s",
		r.Harness, r.Outcome, r.Binding.Generation, r.ExpiresAt.Format(time.RFC3339))
}
