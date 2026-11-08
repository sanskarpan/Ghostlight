// Package attestations issues and serves signed, candidate-bound results.
//
// An attestation is a signature over one fact about one environment's exact
// generation: the platform's own claim, bound to the candidate it was made
// about, expiring on a stated date, and revocable while it lives. The
// signature is the authority — a fact that arrived without one is somebody's
// assertion, and the platform does not serve assertions as if they were
// results.
//
// The boundary §3 fixes for gates applies here from the other side: what the
// platform may sign is what the platform itself verified — verified cleanup,
// a signed gate report — and never a metric a candidate produced. Issuance
// is therefore an internal act of the authority, not an HTTP route: no
// request can talk this package into signing something the platform did not
// verify.
package attestations

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// State is what a reader learns when they ask about an attestation.
type State string

const (
	// StateValid means the signature verifies, the attestation is unexpired,
	// and it has not been revoked.
	StateValid State = "valid"
	// StateExpired means the attestation's validity window has passed. The
	// record is served as it is: an expired attestation is a fact about the
	// past, and hiding it would be rewriting history.
	StateExpired State = "expired"
	// StateRevoked means the platform withdrew it. The reason is carried.
	StateRevoked State = "revoked"
)

// ErrUnknown means no such attestation.
var ErrUnknown = errors.New("no such attestation")

// ErrTampered means a stored attestation's signature no longer verifies over
// its own content. The store is never the source of truth for validity — the
// signature is — so a tampered record is a server fault, not a served fact.
var ErrTampered = errors.New("attestation signature does not verify over its content")

// Attestation is one signed, candidate-bound fact.
type Attestation struct {
	ID string `json:"id"`
	// EnvironmentID and Scope are the attestation's ownership. The scope is
	// what a reader's grants must cover.
	EnvironmentID string `json:"environment_id"`
	Scope         string `json:"-"`
	// Generation and CandidateDigest bind the fact to one exact candidate. A
	// result without a candidate binding is a vibe, not a result.
	Generation      uint64 `json:"generation"`
	CandidateDigest string `json:"candidate_digest"`
	// Result names the verified fact, in the platform's own vocabulary —
	// "cleanup_verified" is the one fact the cleanup driver genuinely
	// produces today.
	Result string `json:"result"`
	// IssuedAt and ExpiresAt bound the claim. A candidate's attestation
	// expires because the world the candidate ran in changes around it.
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Revocation is the withdrawal record, empty while the attestation lives.
	RevokedAt       time.Time `json:"revoked_at,omitempty"`
	RevokeReason    string    `json:"revoke_reason,omitempty"`
	RevokedBy       string    `json:"revoked_by,omitempty"`
	SignatureBase64 string    `json:"signature"`
}

// issued is the canonical signing payload: everything except the signature,
// marshalled with stable field order (encoding/json keeps struct order).
type issued struct {
	ID              string    `json:"id"`
	EnvironmentID   string    `json:"environment_id"`
	Generation      uint64    `json:"generation"`
	CandidateDigest string    `json:"candidate_digest"`
	Result          string    `json:"result"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// Authority holds the platform's attestation key and store.
type Authority struct {
	mu       sync.Mutex
	priv     ed25519.PrivateKey
	byID     map[string]Attestation
	now      func() time.Time
	seq      int
	validity time.Duration
}

// NewAuthority builds an authority with a fresh key. Production keys come
// from a vault; the fresh-key default keeps a dev deployment from shipping a
// shared constant as its identity.
func NewAuthority(now func() time.Time, validity time.Duration) (*Authority, error) {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if validity <= 0 {
		return nil, fmt.Errorf("an attestation authority requires a positive validity window; an attestation that never expires is a promise about the future nobody can keep")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate attestation key: %w", err)
	}
	return &Authority{priv: priv, byID: map[string]Attestation{}, now: now, validity: validity}, nil
}

// Issue signs one fact and stores it. The candidate digest and result are
// the caller's to establish — this package verifies nothing about the fact
// itself; it makes the fact's record undeniable and expiring.
func (a *Authority) Issue(environmentID, scope string, generation uint64, candidateDigest, result string) (Attestation, error) {
	if environmentID == "" || scope == "" {
		return Attestation{}, fmt.Errorf("an attestation is bound to one environment and one scope")
	}
	if !isDigest(candidateDigest) {
		return Attestation{}, fmt.Errorf("candidate_digest must be a sha256:<64 hex> digest; a result bound to a digest that does not parse is bound to nothing")
	}
	if strings.TrimSpace(result) == "" {
		return Attestation{}, fmt.Errorf("a result is required; an attestation of nothing is not a fact")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.seq++
	payload := issued{
		ID:              fmt.Sprintf("att-%d-%d", now.Unix(), a.seq),
		EnvironmentID:   environmentID,
		Generation:      generation,
		CandidateDigest: candidateDigest,
		Result:          result,
		IssuedAt:        now,
		ExpiresAt:       now.Add(a.validity),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Attestation{}, fmt.Errorf("canonical payload: %w", err)
	}
	rec := Attestation{
		ID: payload.ID, EnvironmentID: environmentID, Scope: scope,
		Generation: payload.Generation, CandidateDigest: payload.CandidateDigest,
		Result: payload.Result, IssuedAt: payload.IssuedAt, ExpiresAt: payload.ExpiresAt,
		SignatureBase64: base64.StdEncoding.EncodeToString(ed25519.Sign(a.priv, body)),
	}
	a.byID[rec.ID] = rec
	return rec, nil
}

// Revoke withdraws an attestation. Revocation is authoritative and
// attributed: a withdrawn result with no withdrawal record is a dispute
// waiting for evidence nobody kept.
func (a *Authority) Revoke(id, reason, by string) (Attestation, error) {
	if strings.TrimSpace(reason) == "" {
		return Attestation{}, fmt.Errorf("a revocation carries a visible reason")
	}
	if strings.TrimSpace(by) == "" {
		return Attestation{}, fmt.Errorf("a revocation carries the actor that withdrew it")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, ok := a.byID[id]
	if !ok {
		return Attestation{}, ErrUnknown
	}
	rec.RevokedAt = a.now()
	rec.RevokeReason = strings.TrimSpace(reason)
	rec.RevokedBy = strings.TrimSpace(by)
	a.byID[id] = rec
	return rec, nil
}

// Get returns the attestation and its state as the reader should see it.
// The signature is verified over the record's own content on every read —
// the store is not the source of truth for validity, the signature is.
func (a *Authority) Get(id string) (Attestation, State, error) {
	a.mu.Lock()
	rec, ok := a.byID[id]
	a.mu.Unlock()
	if !ok {
		return Attestation{}, "", ErrUnknown
	}
	payload := issued{
		ID: rec.ID, EnvironmentID: rec.EnvironmentID, Generation: rec.Generation,
		CandidateDigest: rec.CandidateDigest, Result: rec.Result,
		IssuedAt: rec.IssuedAt, ExpiresAt: rec.ExpiresAt,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Attestation{}, "", ErrTampered
	}
	sig, err := base64.StdEncoding.DecodeString(rec.SignatureBase64)
	if err != nil {
		return Attestation{}, "", ErrTampered
	}
	if !ed25519.Verify(a.priv.Public().(ed25519.PublicKey), body, sig) {
		return Attestation{}, "", ErrTampered
	}
	state := StateValid
	switch {
	case !rec.RevokedAt.IsZero():
		state = StateRevoked
	case !a.now().Before(rec.ExpiresAt):
		state = StateExpired
	}
	return rec, state, nil
}

// isDigest reports whether s is a sha256:<64 hex> digest.
func isDigest(s string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) || len(s) != len(prefix)+64 {
		return false
	}
	for _, c := range s[len(prefix):] {
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return false
	}
	return true
}
