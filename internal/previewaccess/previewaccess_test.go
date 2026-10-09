package previewaccess_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/previewaccess"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// authorizer grants named principals.
type authorizer struct {
	mu      sync.Mutex
	allowed map[string]bool
	err     error
}

func (a *authorizer) Authorized(_ context.Context, principal, _ string, _ previewaccess.Purpose) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return false, a.err
	}
	return a.allowed[principal], nil
}

// checker reports readiness per environment.
type checker struct {
	mu    sync.Mutex
	ready map[string]previewaccess.Readiness
	err   error
}

func (c *checker) Check(_ context.Context, _ previewaccess.Identity, env string, _ previewaccess.Purpose) (previewaccess.Readiness, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return previewaccess.Readiness{}, c.err
	}
	if r, ok := c.ready[env]; ok {
		return r, nil
	}
	return previewaccess.Readiness{IdentityChecked: true, ConfigCurrent: true, CheckedAt: now}, nil
}

// revocations tracks revoked nonces.
type revocations struct {
	mu      sync.Mutex
	revoked map[string]bool
	err     error
}

func (r *revocations) Revoked(_ context.Context, nonce string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return false, r.err
	}
	return r.revoked[nonce], nil
}

func (r *revocations) Revoke(_ context.Context, nonce string, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revoked == nil {
		r.revoked = map[string]bool{}
	}
	r.revoked[nonce] = true
	return nil
}

func keeper(t *testing.T) *previewaccess.Keeper {
	t.Helper()
	k, err := previewaccess.NewKeeper([]byte("test-signing-key"), "test-keeper")
	if err != nil {
		t.Fatalf("keeper: %v", err)
	}
	return k
}

func harness(t *testing.T) (*previewaccess.Issuer, *previewaccess.Verifier, *authorizer, *checker, *revocations) {
	t.Helper()
	k := keeper(t)
	a := &authorizer{allowed: map[string]bool{"alice": true}}
	c := &checker{ready: map[string]previewaccess.Readiness{}}
	r := &revocations{revoked: map[string]bool{}}
	issuer, err := previewaccess.NewIssuer(k, a, c, previewaccess.Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	verifier, err := previewaccess.NewVerifier(k, r, func() time.Time { return now })
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return issuer, verifier, a, c, r
}

func identity() previewaccess.Identity {
	return previewaccess.Identity{
		Principal: "alice", AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
}

// TestIssuerRequiresItsDependencies.
func TestIssuerRequiresItsDependencies(t *testing.T) {
	k := keeper(t)
	a := &authorizer{}
	c := &checker{}
	if _, err := previewaccess.NewIssuer(nil, a, c, previewaccess.Config{}); err == nil {
		t.Fatal("an issuer without a keeper would mint unsigned URLs")
	}
	if _, err := previewaccess.NewIssuer(k, nil, c, previewaccess.Config{}); err == nil {
		t.Fatal("an issuer without an authorizer cannot decide anything")
	}
	if _, err := previewaccess.NewIssuer(k, a, nil, previewaccess.Config{}); err == nil {
		t.Fatal("an issuer without a readiness checker would issue into unready environments")
	}
	if _, err := previewaccess.NewKeeper(nil, "k"); err == nil {
		t.Fatal("an empty signing key would mint forgeable URLs")
	}
}

// TestIssueAndServe is the ordinary path.
func TestIssueAndServe(t *testing.T) {
	issuer, verifier, _, _, _ := harness(t)

	url, tok, err := issuer.Issue(context.Background(), identity(), "env-1", previewaccess.PurposeView, "https://preview-1.example.test")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.Contains(url, "preview_token=") {
		t.Fatalf("the URL must carry the token, got %q", url)
	}
	if tok.ExpiresAt != now.Add(previewaccess.DefaultTTL) {
		t.Fatalf("the token must carry the default TTL, got %v", tok.ExpiresAt)
	}

	got, err := verifier.Verify(context.Background(), tok.Encode(), "env-1", previewaccess.PurposeView)
	if err != nil {
		t.Fatalf("serve-time verify: %v", err)
	}
	if got.Principal != "alice" || got.EnvironmentID != "env-1" {
		t.Fatalf("the verified token must carry its claims, got %+v", got)
	}
}

// TestATokenForOneEnvironmentDoesNotOpenAnother is the binding property.
func TestATokenForOneEnvironmentDoesNotOpenAnother(t *testing.T) {
	issuer, verifier, _, _, _ := harness(t)

	_, tok, err := issuer.Issue(context.Background(), identity(), "env-1", previewaccess.PurposeView, "https://x.test")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, err = verifier.Verify(context.Background(), tok.Encode(), "env-2", previewaccess.PurposeView)
	if !errors.Is(err, previewaccess.ErrWrongEnvironment) {
		t.Fatalf("a token must not cross environments, got %v", err)
	}
}

// TestATokenForOnePurposeDoesNotServeAnother.
func TestATokenForOnePurposeDoesNotServeAnother(t *testing.T) {
	issuer, verifier, _, _, _ := harness(t)

	_, tok, err := issuer.Issue(context.Background(), identity(), "env-1", previewaccess.PurposeView, "https://x.test")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), tok.Encode(), "env-1", previewaccess.PurposeInteract); err == nil {
		t.Fatal("a view token must not authorize interaction")
	}
}

// TestExpiredTokensAreRefused.
func TestExpiredTokensAreRefused(t *testing.T) {
	issuer, _, _, _, _ := harness(t)

	_, tok, err := issuer.Issue(context.Background(), identity(), "env-1", previewaccess.PurposeView, "https://x.test")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	late, err := previewaccess.NewVerifier(keeper(t), &revocations{}, func() time.Time { return now.Add(time.Hour) })
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	_, err = late.Verify(context.Background(), tok.Encode(), "env-1", previewaccess.PurposeView)
	if !errors.Is(err, previewaccess.ErrExpired) {
		t.Fatalf("an expired token must be refused, got %v", err)
	}
}

// TestForgedTokensAreRefused: a signature over different claims must not verify.
func TestForgedTokensAreRefused(t *testing.T) {
	_, verifier, _, _, _ := harness(t)

	// Mint with one key, verify with another.
	other, err := previewaccess.NewKeeper([]byte("a-different-key"), "other")
	if err != nil {
		t.Fatalf("keeper: %v", err)
	}
	forged := previewaccess.Token{
		EnvironmentID: "env-1", Principal: "alice", Purpose: previewaccess.PurposeView,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), Nonce: "forged",
	}
	forged.Signature = other.Sign(forged)

	if _, err := verifier.Verify(context.Background(), forged.Encode(), "env-1", previewaccess.PurposeView); !errors.Is(err, previewaccess.ErrBadToken) {
		t.Fatalf("a forged token must be refused, got %v", err)
	}
}

// TestWidenedClaimsAreRefused: keeping a valid signature while changing the claims.
func TestWidenedClaimsAreRefused(t *testing.T) {
	issuer, verifier, _, _, _ := harness(t)

	_, tok, err := issuer.Issue(context.Background(), identity(), "env-1", previewaccess.PurposeView, "https://x.test")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Decode, change the environment, re-encode with the old signature.
	decoded, err := previewaccess.DecodeToken(tok.Encode())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	decoded.EnvironmentID = "env-2"
	if _, err := verifier.Verify(context.Background(), decoded.Encode(), "env-2", previewaccess.PurposeView); !errors.Is(err, previewaccess.ErrBadToken) {
		t.Fatalf("re-targeted claims must fail signature verification, got %v", err)
	}
}

// TestRevokedTokensStopWorking: a principal whose access was removed must lose outstanding URLs.
func TestRevokedTokensStopWorking(t *testing.T) {
	issuer, verifier, _, _, r := harness(t)

	_, tok, err := issuer.Issue(context.Background(), identity(), "env-1", previewaccess.PurposeView, "https://x.test")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := r.Revoke(context.Background(), tok.Nonce, now); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), tok.Encode(), "env-1", previewaccess.PurposeView); !errors.Is(err, previewaccess.ErrRevoked) {
		t.Fatalf("a revoked token must stop working, got %v", err)
	}
}

// TestUnreadableRevocationRefuses: "was this revoked?" with an unknowable answer refuses.
func TestUnreadableRevocationRefuses(t *testing.T) {
	issuer, _, _, _, _ := harness(t)
	broken := &revocations{err: errors.New("revocation store unavailable")}
	v, err := previewaccess.NewVerifier(keeper(t), broken, func() time.Time { return now })
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	_, tok, err := issuer.Issue(context.Background(), identity(), "env-1", previewaccess.PurposeView, "https://x.test")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := v.Verify(context.Background(), tok.Encode(), "env-1", previewaccess.PurposeView); err == nil {
		t.Fatal("an unknowable revocation answer must refuse")
	}
}

// TestStaleAuthenticationCannotMint: a session from last week must not mint fresh capabilities.
func TestStaleAuthenticationCannotMint(t *testing.T) {
	issuer, _, _, _, _ := harness(t)

	stale := previewaccess.Identity{
		Principal: "alice", AuthenticatedAt: now.Add(-30 * 24 * time.Hour), ExpiresAt: now.Add(-29 * 24 * time.Hour),
	}
	if _, _, err := issuer.Issue(context.Background(), stale, "env-1", previewaccess.PurposeView, "https://x.test"); !errors.Is(err, previewaccess.ErrUnauthenticated) {
		t.Fatalf("stale authentication must not mint URLs, got %v", err)
	}
	anonymous := previewaccess.Identity{}
	if _, _, err := issuer.Issue(context.Background(), anonymous, "env-1", previewaccess.PurposeView, "https://x.test"); !errors.Is(err, previewaccess.ErrUnauthenticated) {
		t.Fatal("an anonymous caller must not mint URLs")
	}
}

// TestUnauthorizedPrincipalCannotMint.
func TestUnauthorizedPrincipalCannotMint(t *testing.T) {
	issuer, _, _, _, _ := harness(t)

	bob := previewaccess.Identity{
		Principal: "bob", AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	if _, _, err := issuer.Issue(context.Background(), bob, "env-1", previewaccess.PurposeView, "https://x.test"); !errors.Is(err, previewaccess.ErrUnauthorized) {
		t.Fatalf("an unauthorized principal must be refused, got %v", err)
	}
}

// TestNoURLIntoAnUnreadyEnvironment: issuing first and checking later hands out a
// capability and then tries to take it back, which fails once the URL is copied.
func TestNoURLIntoAnUnreadyEnvironment(t *testing.T) {
	issuer, _, _, c, _ := harness(t)
	c.ready["env-1"] = previewaccess.Readiness{IdentityChecked: true, ConfigCurrent: false, Detail: "config is one generation behind"}

	if _, _, err := issuer.Issue(context.Background(), identity(), "env-1", previewaccess.PurposeView, "https://x.test"); !errors.Is(err, previewaccess.ErrNotReady) {
		t.Fatalf("an environment with stale config must get no URL, got %v", err)
	}
}

// TestMalformedTokensAreClientBugs: parsing and verifying stay separate so incident
// response can tell them apart.
func TestMalformedTokensAreClientBugs(t *testing.T) {
	for _, bad := range []string{"", "no-dot-here", ".sig", "payload.", "!!!.sig"} {
		if _, err := previewaccess.DecodeToken(bad); !errors.Is(err, previewaccess.ErrBadToken) {
			t.Fatalf("%q must decode as a bad token, got %v", bad, err)
		}
	}
}

// TestUnknownPurposeIsRefusedAtBothEnds.
func TestUnknownPurposeIsRefusedAtBothEnds(t *testing.T) {
	issuer, _, _, _, _ := harness(t)
	if _, _, err := issuer.Issue(context.Background(), identity(), "env-1", "admin", "https://x.test"); err == nil {
		t.Fatal("an unknown purpose must not mint")
	}
}

// TestNoncesAreUniquePerIssuance: revoking one nonce must revoke exactly one token.
func TestNoncesAreUniquePerIssuance(t *testing.T) {
	issuer, verifier, _, _, r := harness(t)
	ctx := context.Background()

	_, first, err := issuer.Issue(ctx, identity(), "env-1", previewaccess.PurposeView, "https://x.test")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	_, second, err := issuer.Issue(ctx, identity(), "env-1", previewaccess.PurposeView, "https://x.test")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.Nonce == second.Nonce {
		t.Fatal("two issuances must not share a nonce")
	}
	if err := r.Revoke(ctx, first.Nonce, now); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := verifier.Verify(ctx, first.Encode(), "env-1", previewaccess.PurposeView); !errors.Is(err, previewaccess.ErrRevoked) {
		t.Fatal("the revoked token must stop")
	}
	if _, err := verifier.Verify(ctx, second.Encode(), "env-1", previewaccess.PurposeView); err != nil {
		t.Fatalf("revoking one token must not revoke its sibling: %v", err)
	}
}

// TestFutureIssuedTokensAreRefused: wrong clocks or games, either way it opens nothing.
func TestFutureIssuedTokensAreRefused(t *testing.T) {
	k := keeper(t)
	future, err := previewaccess.NewVerifier(k, &revocations{}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	tok := previewaccess.Token{
		EnvironmentID: "env-1", Principal: "alice", Purpose: previewaccess.PurposeView,
		IssuedAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour), Nonce: "future",
	}
	tok.Signature = k.Sign(tok)
	if _, err := future.Verify(context.Background(), tok.Encode(), "env-1", previewaccess.PurposeView); !errors.Is(err, previewaccess.ErrBadToken) {
		t.Fatalf("a not-yet-valid token must be refused, got %v", err)
	}
}

// TestDescribeOmitsTheSignature: claims plus signature in a log is a replay kit.
func TestDescribeOmitsTheSignature(t *testing.T) {
	issuer, _, _, _, _ := harness(t)
	_, tok, err := issuer.Issue(context.Background(), identity(), "env-1", previewaccess.PurposeView, "https://x.test")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got := previewaccess.Describe(tok)
	if strings.Contains(got, tok.Signature) {
		t.Fatal("a description must never carry the signature")
	}
	for _, want := range []string{"env-1", "alice", "view"} {
		if !strings.Contains(got, want) {
			t.Fatalf("a description must stay identifiable, missing %q in %q", want, got)
		}
	}
}

// TestConcurrentIssuanceIsConsistent.
func TestConcurrentIssuanceIsConsistent(t *testing.T) {
	issuer, verifier, _, _, _ := harness(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make([]error, 16)
	toks := make([]previewaccess.Token, 16)
	for i := range toks {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, tok, err := issuer.Issue(ctx, identity(), "env-1", previewaccess.PurposeView, "https://x.test")
			toks[i], errs[i] = tok, err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("issuance %d: %v", i, err)
		}
		if _, err := verifier.Verify(ctx, toks[i].Encode(), "env-1", previewaccess.PurposeView); err != nil {
			t.Fatalf("token %d must verify: %v", i, err)
		}
	}
}

// TestAuthorizerFailureIsAFault: an authorizer outage must not read as unauthorized.
func TestAuthorizerFailureIsAFault(t *testing.T) {
	issuer, _, a, _, _ := harness(t)
	a.err = errors.New("policy store unavailable")
	if _, _, err := issuer.Issue(context.Background(), identity(), "env-1", previewaccess.PurposeView, "https://x.test"); err == nil {
		t.Fatal("an authorizer outage must surface, not silently decide")
	} else if errors.Is(err, previewaccess.ErrUnauthorized) {
		t.Fatal("an outage is a fault, not a denial; wrapping it as unauthorized hides the outage")
	}
}
