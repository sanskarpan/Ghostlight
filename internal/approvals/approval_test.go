package approvals

import (
	"errors"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// The digest
// ---------------------------------------------------------------------------

// An approval binds a digest, so two arrangements of the same plan must digest the
// same. Otherwise approvals would be a lottery decided by map order.
func TestDigestIsInvariantUnderActionAndParamOrdering(t *testing.T) {
	a := quietPlan(
		act("alpha", "read", map[string]string{"k1": "v1", "k2": "v2"}),
		act("beta", "write", map[string]string{"x": "1"}),
		act("gamma", "observe", nil),
	)
	b := quietPlan(
		act("gamma", "observe", nil),
		act("beta", "write", map[string]string{"x": "1"}),
		act("alpha", "read", map[string]string{"k2": "v2", "k1": "v1"}),
	)
	if Digest(a) != Digest(b) {
		t.Fatalf("reordering the same plan changed its digest: %s vs %s", Digest(a), Digest(b))
	}
}

// The attack this package exists for: approve what you saw, run what arrived. Its
// smallest form is one character in one value.
func TestDigestChangesWhenASingleCharacterChanges(t *testing.T) {
	base := quietPlan(act("orders-db", "read", map[string]string{"where": "status = 'open'"}))
	cases := map[string]Plan{
		"one character in one parameter value": quietPlan(act("orders-db", "read", map[string]string{"where": "status = 'opem'"})),
		"one character in the verb":            quietPlan(act("orders-db", "rea e", map[string]string{"where": "status = 'open'"})),
		"one character in the target":          quietPlan(act("orders-dc", "read", map[string]string{"where": "status = 'open'"})),
		"one character in the plan name":       {Name: "releasf", Actions: []Action{act("orders-db", "read", map[string]string{"where": "status = 'open'"})}},
		"a dropped parameter":                  quietPlan(act("orders-db", "read", nil)),
	}
	for what, changed := range cases {
		if Digest(base) == Digest(changed) {
			t.Fatalf("%s did not change the digest", what)
		}
	}
}

// Length prefixes stop text from moving across a field boundary. Without them,
// {"ab": "c"} and {"a": "bc"} would concatenate identically, and a plan could imitate
// another plan's digest by relocating characters.
func TestDigestCannotBeImitatedByMovingTextAcrossABoundary(t *testing.T) {
	pairs := [][2]Plan{
		{
			quietPlan(act("t", "v", map[string]string{"ab": "c"})),
			quietPlan(act("t", "v", map[string]string{"a": "bc"})),
		},
		{
			quietPlan(act("ab", "c", nil)),
			quietPlan(act("a", "bc", nil)),
		},
		{
			quietPlan(act("t", "v", map[string]string{"a": "b", "c": "d"})),
			quietPlan(act("t", "v", map[string]string{"a": "b"}), act("c", "d", nil)),
		},
		{
			quietPlan(act("t", "v", nil)),
			{Name: "release", Actions: []Action{act("t", "v", nil)}, DeclaresDestructive: true},
		},
	}
	for i, pair := range pairs {
		if Digest(pair[0]) == Digest(pair[1]) {
			t.Fatalf("case %d: two different plans share a digest, so text can move across a boundary", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Approve
// ---------------------------------------------------------------------------

// A yes with no name is not a decision anybody can be held to, and reauthorization has
// nothing to check it against.
func TestApproveRefusesAnAnonymousActor(t *testing.T) {
	p := quietPlan(act("orders-db", "read", nil))
	for _, actor := range []string{"", "   ", "\t"} {
		if _, err := Approve(actor, p, at, time.Hour); !errors.Is(err, ErrAnonymousApproval) {
			t.Fatalf("actor %q: got %v, want %v", actor, err, ErrAnonymousApproval)
		}
	}
}

// Approve is reachable without Preview, so the undeclared-destructive refusal must live
// here too, or it can be walked around.
func TestApproveRefusesAnUndeclaredDestructivePlan(t *testing.T) {
	for _, verb := range DestructiveVerbs {
		p := quietPlan(act("orders-db", verb, nil))
		if _, err := Approve("dana", p, at, time.Hour); !errors.Is(err, ErrUndeclaredDestructive) {
			t.Fatalf("approving a hidden %q: got %v, want %v", verb, err, ErrUndeclaredDestructive)
		}
	}
}

// Asking for too long gets the policy maximum, never the extra time -- the same
// reasoning internal/quota uses for its own TTLs.
func TestApproveClampsATooLongTTLInsteadOfRefusing(t *testing.T) {
	a, err := Approve("dana", quietPlan(act("db", "read", nil)), at, 100*time.Hour)
	if err != nil {
		t.Fatalf("an over-long TTL must clamp, not refuse: %v", err)
	}
	if got := a.ExpiresAt.Sub(a.IssuedAt); got != MaxApprovalTTL {
		t.Fatalf("asking for 100h granted %v, want the %v maximum", got, MaxApprovalTTL)
	}
}

func TestApproveDefaultsAnUnspecifiedTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		a, err := Approve("dana", quietPlan(act("db", "read", nil)), at, ttl)
		if err != nil {
			t.Fatalf("ttl %v: %v", ttl, err)
		}
		if got := a.ExpiresAt.Sub(a.IssuedAt); got != DefaultApprovalTTL {
			t.Fatalf("ttl %v granted %v, want the %v default", ttl, got, DefaultApprovalTTL)
		}
	}
}

func TestApproveHonoursATTLInsideTheBound(t *testing.T) {
	a, err := Approve("dana", quietPlan(act("db", "read", nil)), at, 30*time.Minute)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if got := a.ExpiresAt.Sub(a.IssuedAt); got != 30*time.Minute {
		t.Fatalf("a TTL inside the bound was granted as %v, want 30m", got)
	}
}

// The ID exists so a decision is findable and attributable. It is deterministic so a
// retry is the same decision; the digest is plan-bound while the ID is not, because
// the plan is what the approval covers, whoever made the decision.
func TestAnApprovalNamesItsActorAndIsDeterministic(t *testing.T) {
	p := quietPlan(act("db", "read", nil))
	first, err := Approve("dana", p, at, time.Hour)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if first.Actor != "dana" {
		t.Fatalf("the approval names %q, want dana", first.Actor)
	}
	if first.ID == "" {
		t.Fatal("an approval must have an identifier")
	}
	second, err := Approve("dana", p, at, time.Hour)
	if err != nil {
		t.Fatalf("approve again: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("the same decision produced %s and %s", first.ID, second.ID)
	}
	other, err := Approve("erin", p, at, time.Hour)
	if err != nil {
		t.Fatalf("approve by erin: %v", err)
	}
	if other.ID == first.ID {
		t.Fatal("two actors share an approval identifier")
	}
	if other.Digest != first.Digest {
		t.Fatalf("the digest is plan-bound and must not change with the actor: %s vs %s", other.Digest, first.Digest)
	}
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

func TestVerifyAcceptsTheApprovedPlan(t *testing.T) {
	p := quietPlan(act("db", "read", map[string]string{"k": "v"}))
	a, err := Approve("dana", p, at, time.Hour)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := Verify(a, p, at); err != nil {
		t.Fatalf("verification at the instant of issue must succeed: %v", err)
	}
	if err := Verify(a, p, at.Add(30*time.Minute)); err != nil {
		t.Fatalf("verification inside the window must succeed: %v", err)
	}
}

// The explicit one-character case: approving what you saw and executing what arrived
// later is the attack Verify exists for.
func TestVerifyRefusesAPlanChangedByOneCharacter(t *testing.T) {
	p := quietPlan(act("db", "read", map[string]string{"k": "value"}))
	a, err := Approve("dana", p, at, time.Hour)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	changed := quietPlan(act("db", "read", map[string]string{"k": "valuf"}))
	mustErr(t, Verify(a, changed, at.Add(time.Minute)), ErrDigestMismatch, "one character changed")
}

func TestVerifyRefusesAnExpiredApproval(t *testing.T) {
	p := quietPlan(act("db", "read", nil))
	a, err := Approve("dana", p, at, 30*time.Minute)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	mustErr(t, Verify(a, p, a.ExpiresAt), ErrApprovalExpired, "at the expiry instant")
	mustErr(t, Verify(a, p, a.ExpiresAt.Add(time.Nanosecond)), ErrApprovalExpired, "after expiry")
}

func TestVerifyRefusesBeforeIssue(t *testing.T) {
	p := quietPlan(act("db", "read", nil))
	a, err := Approve("dana", p, at, time.Hour)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	mustErr(t, Verify(a, p, a.IssuedAt.Add(-time.Nanosecond)), ErrNotYetValid, "one nanosecond before issue")
}
