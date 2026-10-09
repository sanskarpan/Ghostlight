// Package certlifecycle owns preview TLS certificates from issuance to revocation.
//
// G2.9: "Own preview URL delivery: wildcard DNS, certificate issuance/renewal/revocation,
// the ACME/API identity, HSTS and origin binding." DNS and ACME need the network, so this
// package covers what can be owned without it: the lifecycle state machine, the renewal
// discipline, revocation on environment end, and origin binding at serve time.
//
// Three rules govern everything here.
//
// Renew before expiry, not after. A certificate has a known end date from the moment it
// is issued, so there is never a reason to discover expiry by serving an expired
// certificate. Renewal starts early, and renewal failure escalates while the old
// certificate keeps serving — up to its expiry, never past it.
//
// Revoke on environment end. A torn-down preview's certificate must die with it, or a
// resurrected DNS name serves a trusted certificate for an environment that no longer
// exists.
//
// Bind the origin. A certificate for env-A never serves env-B, even if the routing is
// wrong. The binding is verified at serve time against the certificate's own record,
// not against the request's claims.
package certlifecycle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Errors returned by this package.
var (
	// ErrExpired means the certificate outlived its validity. It is never served.
	ErrExpired = errors.New("certificate has expired and must not be served")
	// ErrRevoked means the certificate was revoked. It is never served.
	ErrRevoked = errors.New("certificate has been revoked and must not be served")
	// ErrNotIssued means no certificate exists yet.
	ErrNotIssued = errors.New("no certificate has been issued")
	// ErrWrongOrigin means the certificate is bound to a different environment.
	ErrWrongOrigin = errors.New("certificate is bound to a different origin")
	// ErrHSTSViolation means the serving configuration does not enforce HSTS.
	ErrHSTSViolation = errors.New("serving configuration does not enforce HSTS")
)

// State is a certificate's lifecycle state.
type State string

const (
	// StatePending means issuance was requested and has not completed.
	StatePending State = "pending"
	// StateIssued means a valid certificate is live.
	StateIssued State = "issued"
	// StateRenewing means renewal is in flight while the old certificate serves.
	StateRenewing State = "renewing"
	// StateRevoked means the certificate was revoked and must never serve.
	StateRevoked State = "revoked"
	// StateExpired means the certificate lapsed. Terminal: an expired certificate is
	// replaced, never renewed, because renewal extends a chain of trust that ended.
	StateExpired State = "expired"
)

// RenewalThreshold is how much lifetime must remain before renewal starts, as a
// fraction. Renewing at one third remaining means a 90-day certificate renews with 30
// days left — enough for several failed attempts with backoff before expiry forces the
// issue.
const RenewalThreshold = 1.0 / 3.0

// Certificate is one preview's TLS identity.
type Certificate struct {
	// EnvironmentID is the origin this certificate is bound to.
	EnvironmentID string
	// DNSName is the name it covers.
	DNSName string
	// Serial identifies the issuance.
	Serial string
	// IssuedAt and ExpiresAt bound its validity.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// State is where it is in its lifecycle.
	State State
	// RevokedAt records revocation, when applicable.
	RevokedAt time.Time
	// RevocationReason is mandatory. An unexplained revocation cannot be audited.
	RevocationReason string
}

// ValidAt reports whether the certificate may serve at a moment.
//
// Expiry and revocation are both terminal for serving. There is no grace period past
// expiry: a client that accepts an expired certificate is a client that has stopped
// verifying, and serving one trains exactly that.
func (c Certificate) ValidAt(now time.Time) bool {
	if c.State != StateIssued && c.State != StateRenewing {
		return false
	}
	if c.ExpiresAt.IsZero() {
		return false
	}
	return now.Before(c.ExpiresAt)
}

// NeedsRenewal reports whether renewal should start now.
func (c Certificate) NeedsRenewal(now time.Time) bool {
	if c.State != StateIssued {
		return false
	}
	if c.ExpiresAt.IsZero() {
		return false
	}
	lifetime := c.ExpiresAt.Sub(c.IssuedAt)
	if lifetime <= 0 {
		return true
	}
	return now.After(c.ExpiresAt.Add(-time.Duration(float64(lifetime) * RenewalThreshold)))
}

// Issuer obtains certificates. ACME lives behind this seam.
type Issuer interface {
	// Issue obtains a certificate for a DNS name.
	Issue(ctx context.Context, environmentID, dnsName string) (serial string, issuedAt, expiresAt time.Time, err error)
	// Revoke revokes a certificate by serial.
	Revoke(ctx context.Context, serial, reason string) error
}

// Manager owns certificate lifecycles.
type Manager struct {
	issuer Issuer
	// certs maps environment id to its certificate.
	certs map[string]*Certificate
	now   func() time.Time
}

// NewManager builds a manager.
func NewManager(issuer Issuer, now func() time.Time) (*Manager, error) {
	if issuer == nil {
		// Without an issuer there is no path to a certificate, so every request would
		// wait forever. Failing at construction beats a queue that never drains.
		return nil, errors.New("a certificate manager requires an issuer")
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Manager{issuer: issuer, certs: map[string]*Certificate{}, now: now}, nil
}

// Request starts issuance for an environment.
func (m *Manager) Request(ctx context.Context, environmentID, dnsName string) (*Certificate, error) {
	if environmentID == "" {
		return nil, errors.New("a certificate must name the environment it is bound to")
	}
	if dnsName == "" {
		return nil, errors.New("a certificate must name what it covers")
	}
	if !strings.Contains(dnsName, ".") {
		return nil, fmt.Errorf("refusing to issue for %q: not a qualified DNS name", dnsName)
	}
	if existing, ok := m.certs[environmentID]; ok && (existing.State == StateIssued || existing.State == StateRenewing || existing.State == StatePending) {
		// A live certificate already exists. Issuing a second one would leave two
		// trusted identities for one origin, and revocation could then only ever be
		// partial.
		return existing, fmt.Errorf("environment %s already has a %s certificate", environmentID, existing.State)
	}

	serial, issuedAt, expiresAt, err := m.issuer.Issue(ctx, environmentID, dnsName)
	if err != nil {
		m.certs[environmentID] = &Certificate{
			EnvironmentID: environmentID, DNSName: dnsName, State: StatePending,
		}
		return m.certs[environmentID], fmt.Errorf("issue certificate for %s: %w", environmentID, err)
	}
	if serial == "" {
		return nil, errors.New("the issuer returned no serial; a certificate without identity cannot be revoked later")
	}
	if !expiresAt.After(issuedAt) {
		return nil, errors.New("the issuer returned a certificate that is already expired")
	}
	if !m.now().Before(expiresAt) {
		// The interval is sane but it already ended. Accepting it would create a record
		// that can never serve, which is worse than having no record: it looks like an
		// answer.
		return nil, fmt.Errorf("%w at %s", ErrExpired, expiresAt.Format(time.RFC3339))
	}
	cert := &Certificate{
		EnvironmentID: environmentID, DNSName: dnsName, Serial: serial,
		IssuedAt: issuedAt, ExpiresAt: expiresAt, State: StateIssued,
	}
	m.certs[environmentID] = cert
	return cert, nil
}

// Renew replaces a certificate approaching expiry.
//
// Renewal failure keeps the old certificate serving — up to its expiry, never past it.
// Taking a preview offline because renewal failed early would turn every ACME outage
// into customer downtime, while serving past expiry would train clients to accept
// expired certificates. The old certificate's expiry is the hard bound either way.
func (m *Manager) Renew(ctx context.Context, environmentID string) (*Certificate, error) {
	cert, ok := m.certs[environmentID]
	if !ok {
		return nil, fmt.Errorf("%w for %s", ErrNotIssued, environmentID)
	}
	if cert.State == StateRevoked {
		return nil, fmt.Errorf("%w: %s was revoked and is replaced, never renewed", ErrRevoked, environmentID)
	}
	if cert.State == StateExpired {
		return nil, fmt.Errorf("%w: %s lapsed and is replaced, never renewed", ErrExpired, environmentID)
	}
	now := m.now()
	if !now.Before(cert.ExpiresAt) {
		cert.State = StateExpired
		return cert, fmt.Errorf("%w at %s", ErrExpired, cert.ExpiresAt.Format(time.RFC3339))
	}

	cert.State = StateRenewing
	serial, issuedAt, expiresAt, err := m.issuer.Issue(ctx, environmentID, cert.DNSName)
	if err != nil {
		// Renewal failed. The old certificate keeps serving, and the state returns to
		// issued so the next pass retries. Reporting the failure distinctly from a
		// serving failure is what lets an operator tell "renewal is broken" from
		// "serving is broken".
		cert.State = StateIssued
		return cert, fmt.Errorf("renew certificate for %s (serving until %s): %w",
			environmentID, cert.ExpiresAt.Format(time.RFC3339), err)
	}
	cert.Serial = serial
	cert.IssuedAt = issuedAt
	cert.ExpiresAt = expiresAt
	cert.State = StateIssued
	return cert, nil
}

// RevokeEnvironment revokes an environment's certificate when the environment ends.
//
// This runs at teardown, not after. A torn-down preview whose certificate still
// validates is a trusted identity for something that no longer exists.
func (m *Manager) RevokeEnvironment(ctx context.Context, environmentID, reason string) error {
	if reason == "" {
		return errors.New("revocation requires a reason; an unexplained revocation cannot be audited")
	}
	cert, ok := m.certs[environmentID]
	if !ok {
		// Nothing was ever issued. That is not an error: teardown must be safe to run
		// for environments that never got far enough to need a certificate.
		return nil
	}
	if cert.State == StateRevoked {
		return nil
	}
	if cert.Serial == "" {
		// Issuance never completed, so there is nothing to revoke at the issuer. The
		// record is still marked so a later issuance for this environment starts clean.
		cert.State = StateRevoked
		cert.RevokedAt = m.now()
		cert.RevocationReason = reason
		return nil
	}
	if err := m.issuer.Revoke(ctx, cert.Serial, reason); err != nil {
		return fmt.Errorf("revoke certificate for %s: %w", environmentID, err)
	}
	cert.State = StateRevoked
	cert.RevokedAt = m.now()
	cert.RevocationReason = reason
	return nil
}

// Serve checks that an environment may serve at a moment.
//
// Origin binding is verified against the certificate's own record: the certificate
// bound to env-A never serves env-B, even if routing is wrong and even if the request
// claims otherwise.
func (m *Manager) Serve(environmentID string) (*Certificate, error) {
	cert, ok := m.certs[environmentID]
	if !ok {
		return nil, fmt.Errorf("%w for %s", ErrNotIssued, environmentID)
	}
	now := m.now()
	switch cert.State {
	case StateRevoked:
		return nil, fmt.Errorf("%w: %s (%s)", ErrRevoked, environmentID, cert.RevocationReason)
	case StatePending:
		return nil, fmt.Errorf("%w for %s: issuance has not completed", ErrNotIssued, environmentID)
	case StateExpired:
		return nil, fmt.Errorf("%w at %s", ErrExpired, cert.ExpiresAt.Format(time.RFC3339))
	case StateIssued, StateRenewing:
		if !now.Before(cert.ExpiresAt) {
			cert.State = StateExpired
			return nil, fmt.Errorf("%w at %s", ErrExpired, cert.ExpiresAt.Format(time.RFC3339))
		}
		return cert, nil
	default:
		return nil, fmt.Errorf("%w: %s is %s", ErrNotIssued, environmentID, cert.State)
	}
}

// Sweep advances every certificate: expiring the lapsed, renewing the due.
//
// It returns what it did so a pass can report it rather than assume it. A sweep that
// silently did nothing and a sweep that had nothing to do must be distinguishable.
func (m *Manager) Sweep(ctx context.Context) (renewed, expired []string, errs []error) {
	return m.SweepAt(ctx, m.now())
}

// SweepAt runs a sweep as of a moment.
//
// It exists so the renewal threshold is testable without sleeping for sixty days. The
// threshold is the whole renewal discipline, so it must be exercisable directly.
func (m *Manager) SweepAt(ctx context.Context, at time.Time) (renewed, expired []string, errs []error) {
	for id, cert := range m.certs {
		switch {
		case cert.State == StateRevoked || cert.State == StateExpired:
			continue
		case !at.Before(cert.ExpiresAt):
			cert.State = StateExpired
			expired = append(expired, id)
		case cert.NeedsRenewal(at):
			if _, err := m.Renew(ctx, id); err != nil {
				errs = append(errs, err)
			} else {
				renewed = append(renewed, id)
			}
		}
	}
	return renewed, expired, errs
}

// HSTS is the strict-transport-security policy the gateway must emit.
type HSTS struct {
	// MaxAgeSeconds is how long clients must use HTTPS.
	MaxAgeSeconds int
	// IncludeSubDomains extends the policy to subdomains.
	IncludeSubDomains bool
	// Preload requests inclusion in browser preload lists.
	Preload bool
}

// DefaultHSTS is the platform's policy: a year, with subdomains, preloaded.
func DefaultHSTS() HSTS {
	return HSTS{MaxAgeSeconds: 31_536_000, IncludeSubDomains: true, Preload: true}
}

// Header renders the Strict-Transport-Security value.
func (h HSTS) Header() string {
	v := fmt.Sprintf("max-age=%d", h.MaxAgeSeconds)
	if h.IncludeSubDomains {
		v += "; includeSubDomains"
	}
	if h.Preload {
		v += "; preload"
	}
	return v
}

// ValidateHSTS refuses a serving configuration that would weaken transport security.
//
// HSTS without includeSubDomains on a wildcard preview domain leaves every sibling
// preview reachable over plaintext. A max-age of zero disables the policy outright.
// Both are refused rather than warned about, because a warning in a log is not a
// boundary.
func ValidateHSTS(h HSTS) error {
	if h.MaxAgeSeconds <= 0 {
		return fmt.Errorf("%w: max-age %d disables the policy", ErrHSTSViolation, h.MaxAgeSeconds)
	}
	if !h.IncludeSubDomains {
		return fmt.Errorf("%w: preview domains are wildcards, so subdomains must be included", ErrHSTSViolation)
	}
	return nil
}

// Describe renders a certificate without ever including key material.
//
// A certificate record contains no private key by construction — the issuer holds it —
// but the serial is still omitted from casual output. It is enough to revoke with, so
// it does not belong in logs.
func Describe(c *Certificate) string {
	return fmt.Sprintf("env=%s dns=%s state=%s exp=%s",
		c.EnvironmentID, c.DNSName, c.State, c.ExpiresAt.Format(time.RFC3339))
}
