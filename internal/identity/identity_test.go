package identity

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/access"
)

var base = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func mustManager(t *testing.T) (*Manager, func(time.Duration)) {
	t.Helper()
	clock := base
	m, err := NewManager(func() time.Time { return clock })
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	return m, func(d time.Duration) { clock = clock.Add(d) }
}

func mustErr(t *testing.T, err error, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

func TestTokensAreStoredHashedAndAreUnguessable(t *testing.T) {
	plain, hash, err := NewToken()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if plain == "" || hash == "" {
		t.Fatal("an empty token is not a credential")
	}
	if plain == hash {
		t.Fatal("the token was stored in plain text")
	}
	if HashToken(plain) != hash {
		t.Fatal("the hash is not deterministic, so a retry could not reproduce it")
	}
	// Two tokens must not collide, or one person's link opens another's account.
	seen := map[string]bool{}
	for i := 0; i < 256; i++ {
		p, _, err := NewToken()
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		if seen[p] {
			t.Fatal("a token repeated")
		}
		seen[p] = true
	}
}

func TestAValidManagerNeedsAClock(t *testing.T) {
	// A manager reading the wall clock cannot be tested for expiry, and expiry is
	// most of what this package does.
	if _, err := NewManager(nil); err == nil {
		t.Fatal("a manager without a clock was built")
	}
	zero := func() time.Time { return time.Time{} }
	if _, err := NewManager(zero); err == nil {
		t.Fatal("a manager whose clock reads the zero time was built")
	}
}

func TestEmailVerificationIsSingleUseAndExpires(t *testing.T) {
	v, plain, err := IssueVerification("u_1", "Dev@Acme.Example", base)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if v.Email != "dev@acme.example" {
		t.Fatalf("address %q was not normalised", v.Email)
	}
	if err := v.Verify("wrong-token", base); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("a wrong token: %v", err)
	}
	if err := v.Verify(plain, base.Add(VerificationTTL-time.Minute)); err != nil {
		t.Fatalf("a fresh token: %v", err)
	}
	// Single use: a verification replayed after the address changes hands the new
	// owner's mailbox an old account, and these links end up forwarded.
	if err := v.Verify(plain, base.Add(time.Minute)); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("replayed verification: got %v, want ErrTokenUsed", err)
	}
}

func TestAnExpiredVerificationIsRefused(t *testing.T) {
	v, plain, err := IssueVerification("u_1", "dev@acme.example", base)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	mustErr(t, v.Verify(plain, base.Add(VerificationTTL+time.Second)), ErrTokenExpired, "expired verification")
	if !v.VerifiedAt.IsZero() {
		t.Fatal("an expired token was consumed anyway")
	}
}

func TestVerificationRequiresAPrincipalAndAnAddress(t *testing.T) {
	if _, _, err := IssueVerification("", "dev@acme.example", base); err == nil {
		t.Fatal("a verification with no principal was issued")
	}
	if _, _, err := IssueVerification("u_1", "   ", base); err == nil {
		t.Fatal("a verification with no address was issued")
	}
}

// A session used every hour would be immortal under idle-only expiry, which is not
// what "session" means to anybody told their access would end.
func TestASessionHasAnAbsoluteLifetimeRotationCannotExtend(t *testing.T) {
	m, advance := mustManager(t)
	s, refresh, err := m.StartSession("u_1", false, base)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	// Rotate repeatedly just inside the idle window for longer than the absolute one.
	token := refresh
	deadline := base.Add(SessionAbsoluteLifetime + time.Hour)
	at := base
	for at.Before(deadline) {
		at = at.Add(SessionIdleLifetime - time.Minute)
		advance(at.Sub(base))
		next, err := m.Rotate(token, at)
		if err != nil {
			// Once the absolute bound passes, rotation must stop working.
			mustErr(t, err, ErrSessionExpired, "rotation past the absolute lifetime")
			break
		}
		token = next
	}
	_, err = m.Verify(s.ID, at)
	mustErr(t, err, ErrSessionExpired, "verify past the absolute lifetime")
}

func TestASessionExpiresWhenIdle(t *testing.T) {
	m, advance := mustManager(t)
	s, _, err := m.StartSession("u_1", false, base)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	// Just inside the window the session is usable. The check itself refreshes
	// last-used, so the next step has to be measured from here.
	advance(SessionIdleLifetime - time.Minute)
	at := base.Add(SessionIdleLifetime - time.Minute)
	if _, err := m.Verify(s.ID, at); err != nil {
		t.Fatalf("inside the idle window: %v", err)
	}
	advance(SessionIdleLifetime)
	at = at.Add(SessionIdleLifetime)
	_, err = m.Verify(s.ID, at)
	mustErr(t, err, ErrSessionExpired, "idle past the limit")
	_ = s
}

// The property that makes a stolen refresh token detectable. If a token can be
// presented twice, it is indistinguishable from a legitimate one for its whole life.
func TestRefreshTokensRotateAndReuseRevokesTheFamily(t *testing.T) {
	m, _ := mustManager(t)
	s, first, err := m.StartSession("u_1", false, base)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	second, err := m.Rotate(first, base.Add(time.Minute))
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if second == first {
		t.Fatal("rotation returned the same token")
	}
	// The attacker replays the consumed token.
	_, err = m.Rotate(first, base.Add(2*time.Minute))
	mustErr(t, err, ErrSessionRevokedFamily, "replayed refresh token")

	// The legitimate holder is signed out too, because we cannot tell who is real.
	_, err = m.Verify(s.ID, base.Add(3*time.Minute))
	mustErr(t, err, ErrSessionRevoked, "verify after family revocation")
	_, err = m.Rotate(second, base.Add(3*time.Minute))
	mustErr(t, err, ErrTokenUnknown, "rotating with a token from a revoked family")
}

// A second session is a different family, so replaying one session's token must not
// sign the user out everywhere.
func TestReuseRevokesOnlyItsOwnFamily(t *testing.T) {
	m, _ := mustManager(t)
	a, firstA, err := m.StartSession("u_1", false, base)
	if err != nil {
		t.Fatalf("start a: %v", err)
	}
	b, _, err := m.StartSession("u_1", false, base)
	if err != nil {
		t.Fatalf("start b: %v", err)
	}
	if a.FamilyID == b.FamilyID {
		t.Fatal("two sessions share a family, so they cannot be revoked independently")
	}
	nextA, err := m.Rotate(firstA, base.Add(time.Minute))
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := m.Rotate(firstA, base.Add(2*time.Minute)); !errors.Is(err, ErrSessionRevokedFamily) {
		t.Fatalf("reuse: %v", err)
	}
	if _, err := m.Verify(a.ID, base.Add(3*time.Minute)); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("the replayed session should be revoked: %v", err)
	}
	if _, err := m.Verify(b.ID, base.Add(3*time.Minute)); err != nil {
		t.Fatalf("an unrelated session was revoked: %v", err)
	}
	_ = nextA
}

func TestAnUnknownRefreshTokenIsRefused(t *testing.T) {
	m, _ := mustManager(t)
	if _, _, err := m.StartSession("u_1", false, base); err != nil {
		t.Fatalf("start: %v", err)
	}
	_, err := m.Rotate("never-issued", base)
	mustErr(t, err, ErrTokenUnknown, "unknown refresh token")
	_, err = m.Rotate("", base)
	mustErr(t, err, ErrTokenUnknown, "empty refresh token")
}

func TestRevocationNeedsAReasonAndIsIdempotentlyObservable(t *testing.T) {
	m, _ := mustManager(t)
	s, _, err := m.StartSession("u_1", false, base)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	// "Logged out" and "revoked because it was replayed" are different incidents, and
	// a revocation with no reason cannot be told apart when somebody asks.
	mustErr(t, m.Revoke(s.ID, "", base), ErrInvalidInput, "revocation without a reason")

	if err := m.Revoke(s.ID, "user signed out", base.Add(time.Minute)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err = m.Verify(s.ID, base.Add(2*time.Minute))
	mustErr(t, err, ErrSessionRevoked, "verify after revocation")

	if err := m.Revoke(s.ID, "again", base.Add(3*time.Minute)); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("a second revocation: %v", err)
	}
}

// The "somebody left the company" path. It must work without knowing session ids,
// because the moment it is needed the person leaving cannot enumerate their own
// sessions.
func TestEverySessionForAPrincipalCanBeRevokedAtOnce(t *testing.T) {
	m, _ := mustManager(t)
	var ids []string
	for i := 0; i < 3; i++ {
		s, _, err := m.StartSession("u_leaver", false, base)
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		ids = append(ids, s.ID)
	}
	if _, _, err := m.StartSession("u_stays", false, base); err != nil {
		t.Fatalf("start: %v", err)
	}
	n, err := m.RevokePrincipal("u_leaver", "employment ended", base.Add(time.Minute))
	if err != nil {
		t.Fatalf("revoke principal: %v", err)
	}
	if n != 3 {
		t.Fatalf("%d sessions revoked, want 3", n)
	}
	for _, id := range ids {
		if _, err := m.Verify(id, base.Add(2*time.Minute)); !errors.Is(err, ErrSessionRevoked) {
			t.Fatalf("session %s survived revocation of the principal", id)
		}
	}
	_, err = m.RevokePrincipal("", "reason", base)
	mustErr(t, err, ErrInvalidInput, "no principal")
	_, err = m.RevokePrincipal("u_leaver", "", base)
	mustErr(t, err, ErrInvalidInput, "no reason")
}

// "Skip MFA" travelling as a request field is how MFA stops being enforced.
func TestMultiFactorIsDerivedFromTheRoleNotFromTheRequest(t *testing.T) {
	if !MFARequiredForRole(access.RoleOwner) {
		t.Fatal("an owner must present a second factor")
	}
	for _, r := range []access.OrgRole{access.RolePlatformAdmin, access.RoleBillingAdmin,
		access.RoleDeveloper, access.RoleReviewer, access.RoleSupport} {
		if MFARequiredForRole(r) {
			t.Fatalf("%s must not require a second factor; making everyone do it is how MFA gets switched off", r)
		}
	}
}

func TestTheMaaFactIsRecordedOnTheSession(t *testing.T) {
	m, _ := mustManager(t)
	s, _, err := m.StartSession("u_owner", true, base)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if !s.MFAVerified {
		t.Fatal("the verified fact was not recorded")
	}
	plain, _, err := m.StartSession("u_owner", false, base)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if plain.MFAVerified {
		t.Fatal("an unverified factor was recorded as verified")
	}
}

// A permanent lockout is a denial of service against a customer delivered by someone
// guessing their password.
func TestFailuresDelayButNeverLockOut(t *testing.T) {
	m, advance := mustManager(t)
	at := base
	var last time.Duration
	for i := 0; i < 20; i++ {
		got := m.RecordCredentialFailure("u_1", at)
		if !got.InDelay || got.RetryAfter <= 0 {
			t.Fatalf("failure %d produced %+v", i, got)
		}
		if got.RetryAfter > LockoutMax {
			t.Fatalf("failure %d delayed %s, over the %s cap", i, got.RetryAfter, LockoutMax)
		}
		if got.RetryAfter < last {
			t.Fatalf("the delay shrank from %s to %s", last, got.RetryAfter)
		}
		last = got.RetryAfter
		// Wait the delay out each time, so the next attempt is genuinely permitted.
		advance(got.RetryAfter)
		at = at.Add(got.RetryAfter)
	}
	// The delay is capped, so the wait is bounded and predictable: a legitimate user
	// is never locked out of their own account for an unbounded time.
	if last != LockoutMax {
		t.Fatalf("the delay settled at %s, want the %s cap", last, LockoutMax)
	}
	if got := m.CheckCredential("u_1", at); !got.Allowed {
		t.Fatalf("after waiting out the delay: %+v", got)
	}
}

// The difference between "delay" and "no such account" is an enumeration oracle, so the
// answer must not depend on whether the account exists.
func TestAnUnknownSubjectIsDelayedIdenticallyToAKnownOne(t *testing.T) {
	m, _ := mustManager(t)
	m.RecordCredentialFailure("known@example.com", base)
	known := m.CheckCredential("known@example.com", base.Add(time.Second))
	m.RecordCredentialFailure("stranger@example.com", base)
	unknown := m.CheckCredential("stranger@example.com", base.Add(time.Second))

	if known.Allowed != unknown.Allowed || known.InDelay != unknown.InDelay {
		t.Fatal("the delay differs between a known and an unknown subject, which enumerates accounts")
	}
	if known.RetryAfter != unknown.RetryAfter {
		t.Fatalf("delays differ: %s for a known subject, %s for an unknown one",
			known.RetryAfter, unknown.RetryAfter)
	}
}

// Waiting out one delay must not reset the whole policy, or an attacker simply waits.
func TestTheDelayCountSurvivesTheWait(t *testing.T) {
	m, advance := mustManager(t)
	for i := 0; i < 3; i++ {
		got := m.RecordCredentialFailure("u_1", base)
		advance(got.RetryAfter)
	}
	before := m.RecordCredentialFailure("u_1", base).RetryAfter
	after := m.RecordCredentialFailure("u_1", base).RetryAfter
	if after <= before {
		t.Fatalf("the delay restarted after a wait: %s then %s", before, after)
	}
}

func TestASuccessClearsTheDelay(t *testing.T) {
	m, advance := mustManager(t)
	m.RecordCredentialFailure("u_1", base)
	advance(time.Hour)
	m.RecordCredentialSuccess("u_1")
	if got := m.CheckCredential("u_1", base); !got.Allowed {
		t.Fatalf("after a success: %+v", got)
	}
	// The count restarts from zero rather than continuing from where it was.
	first := m.RecordCredentialFailure("u_1", base).RetryAfter
	if first != LockoutBase {
		t.Fatalf("the first failure after success delayed %s, want %s", first, LockoutBase)
	}
}

// Recovery codes are the one credential a user might write on paper, which makes them
// the one most likely to be phished out of a drawer.
func TestRecoveryCodesAreHashedSingleUseAndExpire(t *testing.T) {
	codes, plain, err := IssueRecoveryCodes(3, base)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(codes) != 3 || len(plain) != 3 {
		t.Fatalf("%d stored, %d shown", len(codes), len(plain))
	}
	for i := range codes {
		if codes[i].Hash == plain[i] {
			t.Fatal("a recovery code was stored in plain text")
		}
	}
	if _, err := ConsumeRecoveryCode(codes, "not-a-code", base); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("an unknown code: %v", err)
	}
	idx, err := ConsumeRecoveryCode(codes, plain[1], base.Add(time.Minute))
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if idx != 1 {
		t.Fatalf("consumed index %d, want 1", idx)
	}
	_, err = ConsumeRecoveryCode(codes, plain[1], base.Add(2*time.Minute))
	mustErr(t, err, ErrRecoveryCodeUsed, "a reused recovery code")

	// The others still work: one code is consumed, the set is not burned by it.
	if _, err := ConsumeRecoveryCode(codes, plain[0], base.Add(2*time.Minute)); err != nil {
		t.Fatalf("a sibling code after one use: %v", err)
	}
}

func TestAnExpiredRecoveryCodeIsRefused(t *testing.T) {
	codes, plain, err := IssueRecoveryCodes(1, base)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, err = ConsumeRecoveryCode(codes, plain[0], base.Add(RecoveryCodeTTL+time.Second))
	mustErr(t, err, ErrTokenExpired, "expired recovery code")
	if !codes[0].UsedAt.IsZero() {
		t.Fatal("an expired code was consumed anyway")
	}
}

func TestAZeroLengthRecoverySetIsRefused(t *testing.T) {
	// A recovery set with no codes is not a recovery set.
	if _, _, err := IssueRecoveryCodes(0, base); err == nil {
		t.Fatal("an empty recovery set was issued")
	}
}

func TestConcurrentRotationYieldsOneWinnerAndOneTheftSignal(t *testing.T) {
	m, _ := mustManager(t)
	_, first, err := m.StartSession("u_1", false, base)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	const racers = 24
	var wg sync.WaitGroup
	results := make([]error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = m.Rotate(first, base.Add(time.Minute))
		}(i)
	}
	wg.Wait()

	granted := 0
	theft := 0
	for _, err := range results {
		switch {
		case err == nil:
			granted++
		case errors.Is(err, ErrSessionRevokedFamily):
			theft++
		}
	}
	if granted != 1 {
		t.Fatalf("%d of %d rotations succeeded, want 1", granted, racers)
	}
	// Everyone who lost raced a consumed token, which is exactly the signal that
	// something is wrong, so the family ends.
	if theft != racers-1 {
		t.Fatalf("%d of %d racers saw the theft signal, want %d", theft, racers, racers-1)
	}
}

func TestSessionCountTracksWhatExists(t *testing.T) {
	m, _ := mustManager(t)
	if m.SessionCount() != 0 {
		t.Fatal("a fresh manager holds sessions")
	}
	for i := 0; i < 3; i++ {
		if _, _, err := m.StartSession(fmt.Sprintf("u_%d", i), false, base); err != nil {
			t.Fatalf("start: %v", err)
		}
	}
	if m.SessionCount() != 3 {
		t.Fatalf("manager holds %d sessions, want 3", m.SessionCount())
	}
}

func TestStartingASessionRequiresAPrincipal(t *testing.T) {
	m, _ := mustManager(t)
	if _, _, err := m.StartSession("", false, base); err == nil {
		t.Fatal("a session with no principal was started")
	}
}
