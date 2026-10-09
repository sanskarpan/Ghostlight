package certlifecycle_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/certlifecycle"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// issuer is a controllable certificate authority.
type issuer struct {
	mu        sync.Mutex
	lifetime  time.Duration
	issueErr  error
	revokeErr error
	issued    int
	revoked   []string
	serial    int
}

func newIssuer() *issuer {
	return &issuer{lifetime: 90 * 24 * time.Hour}
}

func (i *issuer) Issue(_ context.Context, _, _ string) (string, time.Time, time.Time, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.issueErr != nil {
		return "", time.Time{}, time.Time{}, i.issueErr
	}
	i.serial++
	i.issued++
	serial := "serial-" + string(rune('a'+i.serial))
	return serial, now, now.Add(i.lifetime), nil
}

func (i *issuer) Revoke(_ context.Context, serial, _ string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.revokeErr != nil {
		return i.revokeErr
	}
	i.revoked = append(i.revoked, serial)
	return nil
}

func newManager(t *testing.T, iss *issuer) *certlifecycle.Manager {
	t.Helper()
	m, err := certlifecycle.NewManager(iss, func() time.Time { return now })
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return m
}

// TestManagerRequiresAnIssuer: without one every request waits forever.
func TestManagerRequiresAnIssuer(t *testing.T) {
	if _, err := certlifecycle.NewManager(nil, nil); err == nil {
		t.Fatal("a manager must not be constructible without an issuer")
	}
}

// TestIssuanceBindsTheOrigin is the ordinary path.
func TestIssuanceBindsTheOrigin(t *testing.T) {
	m := newManager(t, newIssuer())

	cert, err := m.Request(context.Background(), "env-1", "preview-1.example.test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if cert.State != certlifecycle.StateIssued {
		t.Fatalf("a fresh certificate must be issued, got %s", cert.State)
	}
	if cert.EnvironmentID != "env-1" || cert.DNSName != "preview-1.example.test" {
		t.Fatalf("the certificate must carry its binding, got %+v", cert)
	}
	if cert.Serial == "" {
		t.Fatal("a certificate without a serial cannot be revoked later")
	}
}

// TestUnqualifiedNamesAreRefused.
func TestUnqualifiedNamesAreRefused(t *testing.T) {
	m := newManager(t, newIssuer())
	for _, bad := range []string{"", "localhost", "no-dots-here"} {
		if _, err := m.Request(context.Background(), "env-1", bad); err == nil {
			t.Fatalf("name %q must be refused", bad)
		}
	}
	if _, err := m.Request(context.Background(), "", "preview-1.example.test"); err == nil {
		t.Fatal("a certificate must name its environment")
	}
}

// TestSecondIssuanceIsRefusedWhileOneIsLive: two trusted identities for one origin means
// revocation can only ever be partial.
func TestSecondIssuanceIsRefusedWhileOneIsLive(t *testing.T) {
	m := newManager(t, newIssuer())
	ctx := context.Background()

	if _, err := m.Request(ctx, "env-1", "preview-1.example.test"); err != nil {
		t.Fatalf("first: %v", err)
	}
	existing, err := m.Request(ctx, "env-1", "preview-1.example.test")
	if err == nil {
		t.Fatal("a second issuance while one is live must be refused")
	}
	if existing == nil || existing.State != certlifecycle.StateIssued {
		t.Fatal("the refusal must return the live certificate")
	}
}

// TestIssuanceFailureLeavesAPendingRecord: the next pass retries rather than assuming.
func TestIssuanceFailureLeavesAPendingRecord(t *testing.T) {
	iss := newIssuer()
	iss.issueErr = errors.New("ACME unreachable")
	m := newManager(t, iss)

	cert, err := m.Request(context.Background(), "env-1", "preview-1.example.test")
	if err == nil {
		t.Fatal("an issuance failure must surface")
	}
	if cert.State != certlifecycle.StatePending {
		t.Fatalf("a failed issuance must be pending, got %s", cert.State)
	}
	if _, err := m.Serve("env-1"); !errors.Is(err, certlifecycle.ErrNotIssued) {
		t.Fatalf("a pending certificate must not serve, got %v", err)
	}
}

// TestIssuerMustReturnAUsableCertificate: no serial means no future revocation, and an
// already-expired certificate is not a certificate. Both are issuer bugs, and both must
// refuse rather than produce a servable record.
func TestIssuerMustReturnAUsableCertificate(t *testing.T) {
	// Empty serial.
	empty := &brokenIssuer{serial: "", issuedAt: now, expiresAt: now.Add(time.Hour)}
	m, err := certlifecycle.NewManager(empty, func() time.Time { return now })
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	if _, err := m.Request(context.Background(), "env-1", "preview-1.example.test"); err == nil {
		t.Fatal("a certificate without a serial cannot be revoked later and must be refused")
	}

	// Already expired.
	stale := &brokenIssuer{serial: "s-1", issuedAt: now.Add(-2 * time.Hour), expiresAt: now.Add(-time.Hour)}
	m2, err := certlifecycle.NewManager(stale, func() time.Time { return now })
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	if _, err := m2.Request(context.Background(), "env-1", "preview-1.example.test"); err == nil {
		t.Fatal("an already-expired certificate is not a certificate")
	}
}

// brokenIssuer returns fixed, possibly invalid issuance.
type brokenIssuer struct {
	serial    string
	issuedAt  time.Time
	expiresAt time.Time
}

func (b *brokenIssuer) Issue(context.Context, string, string) (string, time.Time, time.Time, error) {
	return b.serial, b.issuedAt, b.expiresAt, nil
}

func (b *brokenIssuer) Revoke(context.Context, string, string) error { return nil }

// TestExpiredCertificatesNeverServe: there is no grace period past expiry.
func TestExpiredCertificatesNeverServe(t *testing.T) {
	iss := newIssuer()
	iss.lifetime = time.Hour
	m := newManager(t, iss)

	if _, err := m.Request(context.Background(), "env-1", "preview-1.example.test"); err != nil {
		t.Fatalf("request: %v", err)
	}
	// Two hours later the hour-long certificate has lapsed.
	renewed, expired, errs := m.SweepAt(context.Background(), now.Add(2*time.Hour))
	if len(errs) != 0 {
		t.Fatalf("sweep: %v", errs)
	}
	if len(renewed) != 0 || len(expired) != 1 {
		t.Fatalf("the lapsed certificate must expire, got %v / %v", renewed, expired)
	}
	if _, err := m.Serve("env-1"); !errors.Is(err, certlifecycle.ErrExpired) {
		t.Fatalf("an expired certificate must never serve, got %v", err)
	}
}

// TestRenewalStartsEarly: a 90-day certificate renews with 30 days left.
func TestRenewalStartsEarly(t *testing.T) {
	iss := newIssuer()
	m := newManager(t, iss)

	cert, err := m.Request(context.Background(), "env-1", "preview-1.example.test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	// With 60 of 90 days left, no renewal.
	if cert.NeedsRenewal(now.Add(30 * 24 * time.Hour)) {
		t.Fatal("a certificate with most of its life left must not renew")
	}
	// With 29 days left, renewal is due.
	if !cert.NeedsRenewal(now.Add(61 * 24 * time.Hour)) {
		t.Fatal("a certificate inside its final third must renew")
	}
}

// TestRenewalReplacesTheSerial: the new certificate is a new identity, not an edit.
func TestRenewalReplacesTheSerial(t *testing.T) {
	iss := newIssuer()
	m := newManager(t, iss)
	ctx := context.Background()

	first, err := m.Request(ctx, "env-1", "preview-1.example.test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	old := first.Serial
	second, err := m.Renew(ctx, "env-1")
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if second.Serial == old {
		t.Fatal("a renewal must be a new issuance with a new serial")
	}
	if second.State != certlifecycle.StateIssued {
		t.Fatalf("a renewed certificate must be issued, got %s", second.State)
	}
}

// TestRenewalFailureKeepsServingUntilExpiry: an ACME outage must not become downtime,
// and must not become post-expiry serving either.
func TestRenewalFailureKeepsServingUntilExpiry(t *testing.T) {
	iss := newIssuer()
	m := newManager(t, iss)
	ctx := context.Background()

	if _, err := m.Request(ctx, "env-1", "preview-1.example.test"); err != nil {
		t.Fatalf("request: %v", err)
	}
	iss.issueErr = errors.New("ACME unreachable")

	cert, err := m.Renew(ctx, "env-1")
	if err == nil {
		t.Fatal("a failed renewal must surface")
	}
	if cert.State != certlifecycle.StateIssued {
		t.Fatalf("the old certificate must keep serving, got %s", cert.State)
	}
	if _, err := m.Serve("env-1"); err != nil {
		t.Fatalf("serving must continue until expiry: %v", err)
	}
	if !strings.Contains(err.Error(), "serving until") {
		t.Fatalf("the error must state the bound, got %q", err)
	}
}

// TestRevokedCertificatesAreReplacedNeverRenewed.
func TestRevokedCertificatesAreReplacedNeverRenewed(t *testing.T) {
	iss := newIssuer()
	m := newManager(t, iss)
	ctx := context.Background()

	if _, err := m.Request(ctx, "env-1", "preview-1.example.test"); err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := m.RevokeEnvironment(ctx, "env-1", "environment torn down"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := m.Renew(ctx, "env-1"); !errors.Is(err, certlifecycle.ErrRevoked) {
		t.Fatalf("a revoked certificate must not renew, got %v", err)
	}
	if _, err := m.Serve("env-1"); !errors.Is(err, certlifecycle.ErrRevoked) {
		t.Fatalf("a revoked certificate must never serve, got %v", err)
	}
	if len(iss.revoked) != 1 {
		t.Fatalf("revocation must reach the issuer, got %v", iss.revoked)
	}
}

// TestRevocationRequiresAReason.
func TestRevocationRequiresAReason(t *testing.T) {
	m := newManager(t, newIssuer())
	if _, err := m.Request(context.Background(), "env-1", "preview-1.example.test"); err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := m.RevokeEnvironment(context.Background(), "env-1", ""); err == nil {
		t.Fatal("an unexplained revocation cannot be audited")
	}
}

// TestRevokingAnEnvironmentThatNeverHadACertIsSafe: teardown runs for environments that
// never got far enough to need one.
func TestRevokingAnEnvironmentThatNeverHadACertIsSafe(t *testing.T) {
	m := newManager(t, newIssuer())
	if err := m.RevokeEnvironment(context.Background(), "env-ghost", "torn down"); err != nil {
		t.Fatalf("revoking nothing must be a no-op, got %v", err)
	}
}

// TestRevocationIsIdempotent: teardown retries must not fail on an already-revoked cert.
func TestRevocationIsIdempotent(t *testing.T) {
	iss := newIssuer()
	m := newManager(t, iss)
	ctx := context.Background()

	if _, err := m.Request(ctx, "env-1", "preview-1.example.test"); err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := m.RevokeEnvironment(ctx, "env-1", "torn down"); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := m.RevokeEnvironment(ctx, "env-1", "torn down"); err != nil {
		t.Fatalf("a repeated revocation must be safe: %v", err)
	}
	if len(iss.revoked) != 1 {
		t.Fatalf("the issuer must see exactly one revocation, got %v", iss.revoked)
	}
}

// TestSweepRenewsTheDue: the sweep reports what it did rather than assuming.
func TestSweepRenewsTheDue(t *testing.T) {
	iss := newIssuer()
	iss.lifetime = 90 * 24 * time.Hour
	m := newManager(t, iss)
	ctx := context.Background()

	if _, err := m.Request(ctx, "env-1", "preview-1.example.test"); err != nil {
		t.Fatalf("request: %v", err)
	}
	// Nothing due yet.
	renewed, expired, errs := m.SweepAt(ctx, now.Add(24*time.Hour))
	if len(renewed) != 0 || len(expired) != 0 || len(errs) != 0 {
		t.Fatalf("a fresh certificate needs nothing, got %v / %v / %v", renewed, expired, errs)
	}
	// Inside the final third, renewal runs.
	renewed, expired, errs = m.SweepAt(ctx, now.Add(61*24*time.Hour))
	if len(renewed) != 1 || len(errs) != 0 {
		t.Fatalf("the due certificate must renew, got %v / %v / %v", renewed, expired, errs)
	}
}

// TestSweepSurfacesRenewalFailuresDistinctly: "renewal is broken" is not "serving is broken".
func TestSweepSurfacesRenewalFailuresDistinctly(t *testing.T) {
	iss := newIssuer()
	m := newManager(t, iss)
	ctx := context.Background()

	if _, err := m.Request(ctx, "env-1", "preview-1.example.test"); err != nil {
		t.Fatalf("request: %v", err)
	}
	iss.issueErr = errors.New("ACME unreachable")
	_, _, errs := m.SweepAt(ctx, now.Add(61*24*time.Hour))
	if len(errs) != 1 {
		t.Fatalf("a failed renewal must surface exactly once, got %v", errs)
	}
	// And the environment still serves on its old certificate.
	if _, err := m.Serve("env-1"); err != nil {
		t.Fatalf("serving must continue: %v", err)
	}
}

// TestHSTSRefusesWeakPolicy: max-age zero disables it; missing subdomains leaves every
// sibling preview on plaintext.
func TestHSTSRefusesWeakPolicy(t *testing.T) {
	if err := certlifecycle.ValidateHSTS(certlifecycle.DefaultHSTS()); err != nil {
		t.Fatalf("the default policy must be valid: %v", err)
	}
	if err := certlifecycle.ValidateHSTS(certlifecycle.HSTS{MaxAgeSeconds: 0, IncludeSubDomains: true}); !errors.Is(err, certlifecycle.ErrHSTSViolation) {
		t.Fatal("max-age zero disables HSTS and must be refused")
	}
	if err := certlifecycle.ValidateHSTS(certlifecycle.HSTS{MaxAgeSeconds: 31536000}); !errors.Is(err, certlifecycle.ErrHSTSViolation) {
		t.Fatal("a wildcard domain without includeSubDomains must be refused")
	}
	got := certlifecycle.DefaultHSTS().Header()
	for _, want := range []string{"max-age=31536000", "includeSubDomains", "preload"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the header must carry %q, got %q", want, got)
		}
	}
}

// TestDescribeOmitsTheSerial: it is enough to revoke with, so it stays out of logs.
func TestDescribeOmitsTheSerial(t *testing.T) {
	m := newManager(t, newIssuer())
	cert, err := m.Request(context.Background(), "env-1", "preview-1.example.test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	got := certlifecycle.Describe(cert)
	if strings.Contains(got, cert.Serial) {
		t.Fatal("a description must never carry the serial")
	}
	for _, want := range []string{"env-1", "preview-1.example.test", "issued"} {
		if !strings.Contains(got, want) {
			t.Fatalf("a description must stay identifiable, missing %q in %q", want, got)
		}
	}
}

// TestCertificatesArePerEnvironment: one preview's lifecycle never touches another's.
func TestCertificatesArePerEnvironment(t *testing.T) {
	iss := newIssuer()
	m := newManager(t, iss)
	ctx := context.Background()

	if _, err := m.Request(ctx, "env-1", "a.example.test"); err != nil {
		t.Fatalf("env-1: %v", err)
	}
	if _, err := m.Request(ctx, "env-2", "b.example.test"); err != nil {
		t.Fatalf("env-2: %v", err)
	}
	if err := m.RevokeEnvironment(ctx, "env-1", "torn down"); err != nil {
		t.Fatalf("revoke env-1: %v", err)
	}
	if _, err := m.Serve("env-2"); err != nil {
		t.Fatalf("revoking env-1 must not affect env-2: %v", err)
	}
	if _, err := m.Serve("env-1"); !errors.Is(err, certlifecycle.ErrRevoked) {
		t.Fatal("env-1 must stay revoked")
	}
}
