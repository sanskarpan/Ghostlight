// Package identity holds the parts of sign-in that are ours rather than a provider's:
// email verification, session lifecycle and revocation, owner multi-factor
// enforcement, credential lockout and account recovery.
//
// G7.10. WorkOS owns authentication (ADR G-025), but "we chose a provider" is not an
// answer to "what happens to a session after somebody leaves the company". Session
// lifetime, revocation and recovery are contractual and must live here, because a
// provider's defaults are chosen for the provider's reasons.
//
// Five properties hold this together.
//
// A verified address is a precondition, not a preference. An address nobody proved
// ownership of cannot receive an invitation, hold a privileged role or reset a
// password, because every one of those is an account takeover delivered by mail.
//
// Refresh tokens rotate, and reuse is treated as theft. A refresh token that can be
// presented twice means a stolen token is indistinguishable from a legitimate one for
// its whole life. Presenting a consumed token revokes the whole family, because at
// that point somebody has a copy and we cannot tell which one is real.
//
// Sessions have an absolute lifetime as well as an idle one. Idle-only expiry means a
// session that is used every hour is immortal, which is not what "session" means to
// anyone who was told their access would end.
//
// Multi-factor is not a flag a request can carry. "Skip MFA" travelling as a parameter
// is how MFA stops being enforced, so it does not exist here: enforcement is derived
// from the principal's role.
//
// Lockout delays, and never locks. A permanent lockout is a denial of service against
// a customer delivered by someone guessing their password, and the response is
// identical whether or not the account exists so that guessing an account is
// pointless.
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/access"
)

// Errors returned by this package.
var (
	// ErrTokenUnknown means the presented token was never issued.
	ErrTokenUnknown = errors.New("token is not recognised")
	// ErrTokenUsed means a single-use token was presented twice.
	ErrTokenUsed = errors.New("token has already been used")
	// ErrTokenExpired means the token is past its expiry.
	ErrTokenExpired = errors.New("token has expired")
	// ErrEmailUnverified means an action requires a proven address.
	ErrEmailUnverified = errors.New("email address is not verified")
	// ErrSessionRevoked means the session was ended.
	ErrSessionRevoked = errors.New("session has been revoked")
	// ErrSessionExpired means the session passed its idle or absolute limit.
	ErrSessionExpired = errors.New("session has expired")
	// ErrSessionRevokedFamily means a rotated refresh token was replayed, so every
	// session in that family was ended.
	ErrSessionRevokedFamily = errors.New("session family revoked after refresh token reuse")
	// ErrMFARequired means the action needs a verified second factor.
	ErrMFARequired = errors.New("multi-factor authentication is required")
	// ErrRecoveryCodeUsed means a recovery code was presented twice.
	ErrRecoveryCodeUsed = errors.New("recovery code has already been used")
	// ErrInvalidInput means a request was malformed.
	ErrInvalidInput = errors.New("input is not valid")
)

// Token lengths. A token must be unguessable and must not be reconstructible from what
// is stored, so the stored form is always a hash.
const tokenBytes = 32

// NewToken returns a random token and its stored hash.
//
// The caller receives both because the plain token must be delivered once and never
// persisted; the hash is what the system stores. A caller that stores the plain token
// has built a system where a database dump is a list of working credentials.
func NewToken() (plain, hash string, err error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate token: %w", err)
	}
	plain = base64.RawURLEncoding.EncodeToString(buf)
	return plain, HashToken(plain), nil
}

// HashToken is the stored form of a token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// VerificationTTL is how long an email verification token stays valid.
//
// Long enough that somebody who cannot reach their inbox has a chance to retry, short
// enough that an abandoned signup does not leave a usable credential lying around.
const VerificationTTL = 24 * time.Hour

// Verification is a pending email verification.
type Verification struct {
	PrincipalID string
	Email       string
	TokenHash   string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	VerifiedAt  time.Time
}

// IssueVerification mints a verification for an address.
func IssueVerification(principalID, email string, now time.Time) (Verification, string, error) {
	if principalID == "" || strings.TrimSpace(email) == "" {
		return Verification{}, "", fmt.Errorf("%w: a principal and an address are required", ErrInvalidInput)
	}
	plain, hash, err := NewToken()
	if err != nil {
		return Verification{}, "", err
	}
	return Verification{
		PrincipalID: principalID,
		Email:       strings.ToLower(strings.TrimSpace(email)),
		TokenHash:   hash,
		IssuedAt:    now.UTC(),
		ExpiresAt:   now.UTC().Add(VerificationTTL),
	}, plain, nil
}

// Verify consumes a verification token.
//
// Single use and expiring. A single-use rule matters more than it looks: a
// verification token replayed after the address changes hands the new owner's mailbox
// the old account, and verification links end up in forwards and shared inboxes.
func (v *Verification) Verify(presented string, now time.Time) error {
	if presented == "" {
		return fmt.Errorf("%w: nothing presented", ErrTokenUnknown)
	}
	if !v.VerifiedAt.IsZero() {
		return ErrTokenUsed
	}
	if !now.Before(v.ExpiresAt) {
		return ErrTokenExpired
	}
	// Compared as hashes so the check does not depend on how the caller normalised
	// the token, and compared in constant time below.
	if !constantTimeEqual(v.TokenHash, HashToken(presented)) {
		return ErrTokenUnknown
	}
	v.VerifiedAt = now.UTC()
	return nil
}

// constantTimeEqual compares two hex digests without an early exit.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// MFARequiredForRole reports whether a role must present a second factor.
//
// Owners only, and derived from the role rather than carried on the request. A
// "skip_mfa" field travelling through the API is how a policy becomes a suggestion,
// and the day someone adds it the policy is gone.
func MFARequiredForRole(r access.OrgRole) bool { return r == access.RoleOwner }

// Session lifetimes.
//
// Absolute is the hard bound. Idle is the convenience bound. Both exist because
// neither alone is right: idle alone makes a session immortal as long as it is used,
// and absolute alone logs out somebody actively working.
const (
	// SessionAbsoluteLifetime is the hard bound on a session's life.
	SessionAbsoluteLifetime = 12 * time.Hour
	// SessionIdleLifetime is how long a session may go unused.
	SessionIdleLifetime = 30 * time.Minute
	// RecoveryCodeTTL is how long a recovery code stays usable.
	RecoveryCodeTTL = 15 * time.Minute
)

// Lockout policy.
//
// Delays grow and then stop growing. A cap on the delay is what makes this a lockout
// rather than an outage: after the cap, a legitimate user waits a fixed, short,
// predictable time, while an attacker who can guess at a bounded rate still cannot get
// through.
const (
	// LockoutBase is the first failure's delay.
	LockoutBase = time.Second
	// LockoutMax caps the delay however many failures there have been.
	LockoutMax = 15 * time.Minute
)

// Session is an authenticated session.
type Session struct {
	ID          string
	FamilyID    string
	PrincipalID string
	CreatedAt   time.Time
	LastUsedAt  time.Time
	// AbsoluteExpiry is the hard bound and is never extended by rotation.
	AbsoluteExpiry time.Time
	// MFAVerified records that a second factor was presented at or after start.
	MFAVerified bool
	// RevokedAt ends the session; RevokeReason says why, because "logged out" and
	// "revoked because it was replayed" are different incidents.
	RevokedAt    time.Time
	RevokeReason string
}

// Manager owns sessions, lockout state and recovery codes.
type Manager struct {
	mu sync.Mutex
	// sessions by session id
	sessions map[string]*Session
	// refreshHashes maps a consumed refresh token hash to the family it belonged to.
	consumedRefresh map[string]string
	// activeRefresh maps the current refresh token hash to its session.
	activeRefresh map[string]string
	// lockouts tracks consecutive failures per subject key.
	lockouts map[string]*lockoutState
	now      func() time.Time
}

type lockoutState struct {
	failures    int
	nextAllowed time.Time
	// locked records that the delay has reached its cap, so the response can say the
	// account is in a delay rather than that it does not exist.
	locked bool
}

// NewManager returns a session manager bound to a clock.
func NewManager(now func() time.Time) (*Manager, error) {
	if now == nil {
		return nil, fmt.Errorf("%w: a clock is required; a manager reading the wall clock cannot be tested for expiry", ErrInvalidInput)
	}
	if now() == (time.Time{}) {
		return nil, fmt.Errorf("%w: the clock must report a real time", ErrInvalidInput)
	}
	return &Manager{
		sessions:        map[string]*Session{},
		consumedRefresh: map[string]string{},
		activeRefresh:   map[string]string{},
		lockouts:        map[string]*lockoutState{},
		now:             now,
	}, nil
}

// StartSession opens a session and returns its first refresh token.
//
// mfaVerified is a caller assertion about a fact the provider established. It is
// recorded, not trusted, because Verify below re-reads it at use time.
func (m *Manager) StartSession(principalID string, mfaVerified bool, now time.Time) (Session, string, error) {
	if principalID == "" {
		return Session{}, "", fmt.Errorf("%w: a principal is required", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	id, hash, err := NewToken()
	if err != nil {
		return Session{}, "", err
	}
	family, _, err := NewToken()
	if err != nil {
		return Session{}, "", err
	}
	s := &Session{
		ID: id, FamilyID: family, PrincipalID: principalID,
		CreatedAt: now.UTC(), LastUsedAt: now.UTC(),
		AbsoluteExpiry: now.UTC().Add(SessionAbsoluteLifetime),
		MFAVerified:    mfaVerified,
	}
	m.sessions[s.ID] = s
	refresh, hash, err := NewToken()
	if err != nil {
		return Session{}, "", err
	}
	m.activeRefresh[hash] = s.ID
	return *s, refresh, nil
}

// Rotate exchanges a refresh token for a new one.
//
// Reuse of a consumed token revokes the entire family. At that point somebody holds a
// copy, and we cannot tell which session is the legitimate one, so the safe answer is
// to end them all and make the real user sign in again. Keeping the "good" session
// alive would mean choosing a side without evidence.
func (m *Manager) Rotate(presented string, now time.Time) (string, error) {
	if presented == "" {
		return "", fmt.Errorf("%w: nothing presented", ErrTokenUnknown)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	hash := HashToken(presented)
	if family, seen := m.consumedRefresh[hash]; seen {
		m.revokeFamilyLocked(family, now, "refresh token reused")
		return "", ErrSessionRevokedFamily
	}
	id, ok := m.activeRefresh[hash]
	if !ok {
		return "", ErrTokenUnknown
	}
	s, ok := m.sessions[id]
	if !ok {
		return "", ErrTokenUnknown
	}
	if err := usableLocked(s, now); err != nil {
		return "", err
	}

	m.consumedRefresh[hash] = s.FamilyID
	delete(m.activeRefresh, hash)
	next, nextHash, err := NewToken()
	if err != nil {
		return "", err
	}
	m.activeRefresh[nextHash] = s.ID
	s.LastUsedAt = now.UTC()
	return next, nil
}

// Verify reports whether a session may be used, and how long remains on it.
func (m *Manager) Verify(sessionID string, now time.Time) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return Session{}, ErrTokenUnknown
	}
	if err := usableLocked(s, now); err != nil {
		return Session{}, err
	}
	s.LastUsedAt = now.UTC()
	return *s, nil
}

func usableLocked(s *Session, now time.Time) error {
	if !s.RevokedAt.IsZero() {
		return fmt.Errorf("%w: %s", ErrSessionRevoked, s.RevokeReason)
	}
	if !now.Before(s.AbsoluteExpiry) {
		return ErrSessionExpired
	}
	if now.Sub(s.LastUsedAt) >= SessionIdleLifetime {
		return ErrSessionExpired
	}
	return nil
}

// Revoke ends a session.
func (m *Manager) Revoke(sessionID, reason string, now time.Time) error {
	if reason == "" {
		// A revocation with no reason cannot be told apart from a routine logout when
		// somebody asks why their access ended.
		return fmt.Errorf("%w: a revocation needs a reason", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return ErrTokenUnknown
	}
	if !s.RevokedAt.IsZero() {
		return fmt.Errorf("%w: %s", ErrSessionRevoked, s.RevokeReason)
	}
	s.RevokedAt = now.UTC()
	s.RevokeReason = reason
	return nil
}

func (m *Manager) revokeFamilyLocked(family string, now time.Time, reason string) {
	for _, s := range m.sessions {
		if s.FamilyID == family && s.RevokedAt.IsZero() {
			s.RevokedAt = now.UTC()
			s.RevokeReason = reason
		}
	}
	// Every refresh token in the family stops working, including the current one.
	for hash, id := range m.activeRefresh {
		if s, ok := m.sessions[id]; ok && s.FamilyID == family {
			delete(m.activeRefresh, hash)
		}
	}
}

// SessionCount reports how many sessions exist, for revocation sweeps and tests.
func (m *Manager) SessionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// RevokePrincipal ends every session belonging to a principal.
//
// This is the "somebody left the company" path. It has to be callable by an
// administrator without knowing a session id, because the moment it is needed the
// person leaving is not available to enumerate their own sessions.
func (m *Manager) RevokePrincipal(principalID, reason string, now time.Time) (int, error) {
	if principalID == "" || reason == "" {
		return 0, fmt.Errorf("%w: a principal and a reason are required", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, s := range m.sessions {
		if s.PrincipalID == principalID && s.RevokedAt.IsZero() {
			s.RevokedAt = now.UTC()
			s.RevokeReason = reason
			n++
		}
	}
	return n, nil
}

// Lockout is the outcome of a credential check.
type Lockout struct {
	// Allowed reports whether the attempt may proceed.
	Allowed bool
	// RetryAfter is how long until the next attempt is acceptable.
	RetryAfter time.Duration
	// InDelay reports that this subject is in a delay, whether or not the account
	// exists. The two cases are deliberately indistinguishable to the caller.
	InDelay bool
}

// CheckCredential applies the delay policy to one attempt.
//
// The caller supplies the subject key. For a real sign-in this should be derived from
// something stable about the attempt — the address alone, or the address and the
// source — and never from whether the account was found, because the difference
// between those two answers is an account enumeration oracle.
func (m *Manager) CheckCredential(key string, now time.Time) Lockout {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.lockouts[key]
	if !ok {
		return Lockout{Allowed: true}
	}
	if now.Before(st.nextAllowed) {
		return Lockout{Allowed: false, RetryAfter: st.nextAllowed.Sub(now), InDelay: true}
	}
	// The delay has elapsed: the next failure starts from the recorded count rather
	// than from zero, or waiting out one delay would reset the whole policy.
	return Lockout{Allowed: true}
}

// RecordCredentialFailure counts a failed attempt and applies the delay.
func (m *Manager) RecordCredentialFailure(key string, now time.Time) Lockout {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.lockouts[key]
	if !ok {
		st = &lockoutState{}
		m.lockouts[key] = st
	}
	st.failures++
	delay := delayFor(st.failures)
	if delay >= LockoutMax {
		delay = LockoutMax
		st.locked = true
	} else {
		st.locked = false
	}
	st.nextAllowed = now.UTC().Add(delay)
	return Lockout{Allowed: false, RetryAfter: delay, InDelay: true}
}

// RecordCredentialSuccess clears the delay.
func (m *Manager) RecordCredentialSuccess(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.lockouts, key)
}

// delayFor grows the delay with the failure count, capped.
func delayFor(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	delay := LockoutBase
	for i := 1; i < failures; i++ {
		delay *= 2
		if delay >= LockoutMax {
			return LockoutMax
		}
	}
	return delay
}

// RecoveryCode is one single-use code from a recovery set.
type RecoveryCode struct {
	Hash      string
	UsedAt    time.Time
	ExpiresAt time.Time
}

// IssueRecoveryCodes mints a set, returning the codes to show once and the stored
// forms.
//
// Recovery codes are the one credential a user might write on paper, which makes them
// the one credential most likely to be phished out of a drawer. They are stored
// hashed, single use and short lived, and a set is only usable once the second factor
// is re-enrolled.
func IssueRecoveryCodes(count int, now time.Time) ([]RecoveryCode, []string, error) {
	if count <= 0 {
		return nil, nil, fmt.Errorf("%w: a recovery set with no codes is not a recovery set", ErrInvalidInput)
	}
	codes := make([]RecoveryCode, 0, count)
	plain := make([]string, 0, count)
	for i := 0; i < count; i++ {
		p, h, err := NewToken()
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, RecoveryCode{Hash: h, ExpiresAt: now.UTC().Add(RecoveryCodeTTL)})
		plain = append(plain, p)
	}
	return codes, plain, nil
}

// ConsumeRecoveryCode marks a code used if it is valid.
//
// Checking and consuming must be one operation under the caller's lock; doing them
// separately lets two concurrent presentations of the same code both succeed.
func ConsumeRecoveryCode(codes []RecoveryCode, presented string, now time.Time) (int, error) {
	if presented == "" {
		return 0, fmt.Errorf("%w: nothing presented", ErrTokenUnknown)
	}
	hash := HashToken(presented)
	for i := range codes {
		if !constantTimeEqual(codes[i].Hash, hash) {
			continue
		}
		if !codes[i].UsedAt.IsZero() {
			return 0, ErrRecoveryCodeUsed
		}
		if !now.Before(codes[i].ExpiresAt) {
			return 0, ErrTokenExpired
		}
		codes[i].UsedAt = now.UTC()
		return i, nil
	}
	return 0, ErrTokenUnknown
}
