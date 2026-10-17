package approvals

import (
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/roles"
)

// authorityFunc adapts a function to Authority, matching the option style used
// elsewhere in this repository.
type authorityFunc func(actor string, role roles.Role, verb string) (bool, error)

// Allowed implements Authority.
func (f authorityFunc) Allowed(actor string, role roles.Role, verb string) (bool, error) {
	return f(actor, role, verb)
}

func allowAll(string, roles.Role, string) (bool, error) { return true, nil }

var errAuthorityDown = errors.New("authority service unreachable")

func approvedPlan(t *testing.T, p Plan) Approval {
	t.Helper()
	a, err := Approve("dana", p, at, time.Hour)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	return a
}

// A nil authority would otherwise panic somewhere in the middle of a run, after some
// actions may already have happened. It is checked first and refused at the start.
func TestReauthorizeRefusesANilAuthority(t *testing.T) {
	p := quietPlan(act("db", "read", nil))
	a := approvedPlan(t, p)
	err := Reauthorize(a, p, "dana", roles.RoleRunner, nil, at.Add(time.Minute))
	mustErr(t, err, ErrNoAuthority, "reauthorizing with no authority")
}

// An approval that expired between approval and execution must not run: the window was
// the platform's statement about how long the decision stays valid.
func TestReauthorizeRefusesAnApprovalExpiredAtExecution(t *testing.T) {
	p := quietPlan(act("db", "read", nil))
	a, err := Approve("dana", p, at, 30*time.Minute)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	err = Reauthorize(a, p, "dana", roles.RoleRunner, authorityFunc(allowAll), at.Add(45*time.Minute))
	mustErr(t, err, ErrApprovalExpired, "an approval that expired before execution")
}

// Approve what you saw, execute what arrived. One changed character is enough.
func TestReauthorizeRefusesADifferentPlanAtExecution(t *testing.T) {
	p := quietPlan(act("db", "read", map[string]string{"k": "value"}))
	a := approvedPlan(t, p)
	arrived := quietPlan(act("db", "read", map[string]string{"k": "valuf"}))
	err := Reauthorize(a, arrived, "dana", roles.RoleRunner, authorityFunc(allowAll), at.Add(time.Minute))
	mustErr(t, err, ErrDigestMismatch, "the arriving plan differs by one character")
}

// An approval names a person. A different person executing it is executing somebody
// else's decision, and no role membership changes whose call it was.
func TestReauthorizeRefusesADifferentActor(t *testing.T) {
	p := quietPlan(act("db", "read", nil))
	a := approvedPlan(t, p)
	err := Reauthorize(a, p, "mallory", roles.RoleRunner, authorityFunc(allowAll), at.Add(time.Minute))
	mustErr(t, err, ErrActorMismatch, "somebody else spending dana's approval")
}

// An approval is a record that somebody said yes once, not a capability that survives
// them losing the right to say it.
func TestReauthorizeRefusesARevokedVerb(t *testing.T) {
	p := destructivePlan(act("orders-db", "terminate", nil))
	a := approvedPlan(t, p)
	auth := authorityFunc(func(actor string, role roles.Role, verb string) (bool, error) {
		return verb != "terminate", nil
	})
	err := Reauthorize(a, p, "dana", roles.RoleRunner, auth, at.Add(time.Minute))
	mustErr(t, err, ErrAuthorityRevoked, "a verb the actor may no longer perform")
}

// The authority check runs for every action, not just the first, and denying any one
// of them refuses the run with the same sentinel regardless of position.
func TestReauthorizeChecksEveryVerb(t *testing.T) {
	p := quietPlan(
		act("a", "read", nil),
		act("b", "write", nil),
		act("c", "observe", nil),
	)
	a := approvedPlan(t, p)
	for _, deniedVerb := range []string{"read", "write", "observe"} {
		deniedVerb := deniedVerb
		auth := authorityFunc(func(actor string, role roles.Role, verb string) (bool, error) {
			return verb != deniedVerb, nil
		})
		err := Reauthorize(a, p, "dana", roles.RoleRunner, auth, at.Add(time.Minute))
		mustErr(t, err, ErrAuthorityRevoked, "denying "+deniedVerb)
	}
}

// A failed authority check is a fault, not a denial. An outage must never look like a
// policy decision, and a policy decision must never look like an outage.
func TestAFailedAuthorityCheckIsAFaultNotADenial(t *testing.T) {
	p := quietPlan(act("db", "read", nil))
	a := approvedPlan(t, p)

	broken := authorityFunc(func(string, roles.Role, string) (bool, error) {
		return false, errAuthorityDown
	})
	err := Reauthorize(a, p, "dana", roles.RoleRunner, broken, at.Add(time.Minute))
	if !errors.Is(err, errAuthorityDown) {
		t.Fatalf("an authority that could not answer must surface its own error, got %v", err)
	}
	if errors.Is(err, ErrAuthorityRevoked) {
		t.Fatal("an authority outage must not be reported as a policy denial")
	}

	// And the converse, so the test cannot pass by accident: an explicit denial is a
	// policy decision and must not surface as the authority's error.
	denied := authorityFunc(func(string, roles.Role, string) (bool, error) { return false, nil })
	err = Reauthorize(a, p, "dana", roles.RoleRunner, denied, at.Add(time.Minute))
	mustErr(t, err, ErrAuthorityRevoked, "an explicit denial")
	if errors.Is(err, errAuthorityDown) {
		t.Fatal("a policy denial is being reported as a fault")
	}
}

// A gate that only refuses is not proven to allow the right thing. The full path --
// preview, digest, approval, reauthorization -- must succeed end to end on a plan the
// platform intends to permit.
func TestTheHappyPathPreviewsApprovesAndReauthorizes(t *testing.T) {
	p := destructivePlan(
		act("orders-db", "destroy", map[string]string{"id": "preview-7"}),
		act("cache", "flush", nil),
	)

	rendered, err := Preview(p)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if rendered.Digest != Digest(p) {
		t.Fatalf("the preview's digest %s does not equal Digest(p) %s", rendered.Digest, Digest(p))
	}

	a, err := Approve("dana", p, at, 2*time.Hour)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if a.Digest != rendered.Digest {
		t.Fatalf("the approval binds %s but the preview showed %s", a.Digest, rendered.Digest)
	}
	if err := Verify(a, p, at.Add(30*time.Minute)); err != nil {
		t.Fatalf("verify: %v", err)
	}

	err = Reauthorize(a, p, "dana", roles.RoleRunner, authorityFunc(allowAll), at.Add(time.Hour))
	if err != nil {
		t.Fatalf("reauthorize: %v", err)
	}
}
