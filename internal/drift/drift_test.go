package drift_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/drift"
)

// at is the fixed instant every review records. Tests never read the wall clock,
// because a test that depends on now() fails at midnight.
var at = time.Date(2026, 10, 18, 9, 30, 0, 0, time.UTC)

// fleet is the expected state the classifier is compared against: two live
// environments and two known resource types.
func fleet() drift.Expected {
	return drift.Expected{
		TagKey:       drift.DefaultOwnershipTagKey,
		Environments: []string{"env-1", "env-2"},
		KnownTypes:   []string{"aws_db_instance", "aws_s3_bucket"},
	}
}

// tagged builds an object carrying the platform's ownership tag.
func tagged(id, typ, envID string) drift.CloudObject {
	return drift.CloudObject{ID: id, Type: typ, Tags: map[string]string{drift.DefaultOwnershipTagKey: envID}}
}

// classify runs the classifier and enforces the invariants every finding must hold:
// it carries the object it was given, it explains itself, and its confidence is a
// percentage. Every classification test goes through here so a finding that fails
// those invariants fails in one place.
func classify(t *testing.T, obj drift.CloudObject, exp drift.Expected) drift.Finding {
	t.Helper()
	f := drift.Classify(obj, exp)
	if !reflect.DeepEqual(f.Object, obj) {
		t.Fatalf("a finding must carry the object it classified, got %+v for %+v", f.Object, obj)
	}
	if f.Reason == "" {
		t.Fatal("a finding must explain itself")
	}
	if f.Confidence < 0 || f.Confidence > 100 {
		t.Fatalf("confidence must be a percentage in 0..100, got %d", f.Confidence)
	}
	return f
}

// TestClassifyRules exercises each of the six classification rules.
func TestClassifyRules(t *testing.T) {
	exp := fleet()
	cases := []struct {
		name string
		obj  drift.CloudObject
		exp  drift.Expected
		want drift.Class
	}{
		{
			"tagged with an expected environment is owned",
			tagged("db-1", "aws_db_instance", "env-1"),
			exp,
			drift.ClassOwned,
		},
		{
			"tagged with a departed environment is orphaned",
			tagged("db-2", "aws_db_instance", "env-retired"),
			exp,
			drift.ClassOrphaned,
		},
		{
			"an empty ownership tag is unknown, not owned",
			tagged("db-3", "aws_db_instance", ""),
			exp,
			drift.ClassUnknown,
		},
		{
			"untagged with a known type is unmanaged",
			drift.CloudObject{ID: "db-4", Type: "aws_db_instance"},
			exp,
			drift.ClassUnmanaged,
		},
		{
			"untagged with an unknown type is foreign",
			drift.CloudObject{ID: "thing-1", Type: "customer_thing"},
			exp,
			drift.ClassForeign,
		},
		{
			"with no tag key configured nothing can be owned",
			tagged("db-5", "aws_db_instance", "env-1"),
			drift.Expected{},
			drift.ClassUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := classify(t, tc.obj, tc.exp)
			if f.Class != tc.want {
				t.Fatalf("classify(%s): got %s, want %s (reason: %s)", tc.obj.ID, f.Class, tc.want, f.Reason)
			}
			if tc.want == drift.ClassOwned && f.Confidence < 90 {
				t.Fatalf("anticipated ownership must be high confidence, got %d", f.Confidence)
			}
		})
	}
}

// TestNearMissTagKeyIsNeverOwned is the package's load-bearing classification test.
// A tag key that merely resembles the ownership key is not an ownership answer: the
// platform never wrote it, so anything read from it is a guess. Reading a guess as
// ownership is how somebody else's object becomes deletable, so the classifier must
// fail closed.
func TestNearMissTagKeyIsNeverOwned(t *testing.T) {
	nearMisses := []struct {
		ownership string
		nearMiss  string
	}{
		{drift.DefaultOwnershipTagKey, "ghostlight_env"},
		{drift.DefaultOwnershipTagKey, "Ghostlight-Env"},
		{drift.DefaultOwnershipTagKey, "ghostlight.env"},
		{drift.DefaultOwnershipTagKey, "ghostlight env"},
		{"ghostlight.io/environment", "ghostlight_io_environment"},
	}
	for _, tc := range nearMisses {
		t.Run(tc.ownership+" vs "+tc.nearMiss, func(t *testing.T) {
			exp := drift.Expected{
				TagKey:       tc.ownership,
				Environments: []string{"env-1"},
				KnownTypes:   []string{"aws_db_instance"},
			}
			// The type is known on purpose: without the near-miss guard this object
			// would be an unmanaged resource, and the test must prove the guard fires
			// before the type fallback does.
			obj := drift.CloudObject{
				ID: "db-1", Type: "aws_db_instance",
				Tags: map[string]string{tc.nearMiss: "env-1"},
			}
			f := classify(t, obj, exp)
			if f.Class == drift.ClassOwned {
				t.Fatalf("tag key %q must never be read as ownership (reason: %s)", tc.nearMiss, f.Reason)
			}
			if f.Class != drift.ClassUnknown {
				t.Fatalf("a near-miss key must fail closed to unknown, got %s", f.Class)
			}
			if !strings.Contains(f.Reason, tc.nearMiss) {
				t.Fatalf("the reason must name the key it refused, got %q", f.Reason)
			}
		})
	}

	t.Run("the exact key is owned", func(t *testing.T) {
		f := classify(t, tagged("db-exact", "aws_db_instance", "env-1"), fleet())
		if f.Class != drift.ClassOwned {
			t.Fatalf("the exact ownership key must be read as ownership, got %s", f.Class)
		}
	})
}

// TestUnrelatedTagKeysFallBackToType keeps the near-miss guard from swallowing
// unrelated tags: a customer's own "Name" tag is normal, and an object with no
// ownership tag but a known type is still unmanaged.
func TestUnrelatedTagKeysFallBackToType(t *testing.T) {
	exp := fleet()
	for _, key := range []string{"Name", "owner", "ghostlight-envs"} {
		obj := drift.CloudObject{ID: "db-1", Type: "aws_db_instance", Tags: map[string]string{key: "whatever"}}
		f := classify(t, obj, exp)
		if f.Class != drift.ClassUnmanaged {
			t.Fatalf("tag %q is unrelated to ownership; want unmanaged, got %s (%s)", key, f.Class, f.Reason)
		}
	}
}

// TestEmptyOwnershipTagIsUnknown: an empty tag on a resource we did not create is
// worse than no tag, because it looks like an answer. It must never be read as
// ownership, and it must never become an orphan either: we cannot even say the
// environment name is wrong, because there is no name.
func TestEmptyOwnershipTagIsUnknown(t *testing.T) {
	expectedSets := []drift.Expected{
		fleet(),
		{TagKey: drift.DefaultOwnershipTagKey},
	}
	for _, blank := range []string{"", "   "} {
		t.Run(fmt.Sprintf("value=%q", blank), func(t *testing.T) {
			for _, exp := range expectedSets {
				obj := tagged("db-blank", "aws_db_instance", blank)
				f := classify(t, obj, exp)
				if f.Class != drift.ClassUnknown {
					t.Fatalf("an empty ownership tag must be unknown, got %s (%s)", f.Class, f.Reason)
				}
			}
		})
	}
}

// TestOwnershipIsRelativeToTheExpectedSet: the same object flips from owned to
// orphaned when its environment leaves the expected set. That flip is the entire
// point of comparing against expectations instead of pattern-matching tags.
func TestOwnershipIsRelativeToTheExpectedSet(t *testing.T) {
	obj := tagged("db-1", "aws_db_instance", "env-1")

	live := classify(t, obj, fleet())
	if live.Class != drift.ClassOwned {
		t.Fatalf("env-1 is expected; want owned, got %s", live.Class)
	}

	departed := classify(t, obj, drift.Expected{TagKey: drift.DefaultOwnershipTagKey})
	if departed.Class != drift.ClassOrphaned {
		t.Fatalf("the same object with env-1 no longer expected must be orphaned, got %s", departed.Class)
	}
}

// TestExpectedHelpers checks the two lookups classification is built on.
func TestExpectedHelpers(t *testing.T) {
	exp := fleet()
	if !exp.Owns("env-1") || exp.Owns("env-9") {
		t.Fatal("Owns must match exactly the expected environments")
	}
	if !exp.KnowsType("aws_s3_bucket") || exp.KnowsType("customer_thing") {
		t.Fatal("KnowsType must match exactly the known types")
	}
}

// TestSentinelsAreDistinct keeps every refusal from collapsing into one answer: a
// caller must be able to tell "nobody reviewed this" from "this is too large".
func TestSentinelsAreDistinct(t *testing.T) {
	sentinels := []error{
		drift.ErrNoReviewer,
		drift.ErrUnreviewed,
		drift.ErrPlanTooLarge,
		drift.ErrAlreadyExecuted,
		drift.ErrNoGuard,
		drift.ErrNoPlan,
		drift.ErrMissingObjectID,
	}
	for i, a := range sentinels {
		if a == nil {
			t.Fatal("a sentinel must be defined")
		}
		for j, b := range sentinels {
			if i != j && a.Error() == b.Error() {
				t.Fatalf("sentinels %d and %d share a message: %q", i, j, a)
			}
		}
	}
}

// TestActionAndClassValuesAreDistinct keeps the vocabularies from overlapping, so a
// serialized plan can never be ambiguous about what it asks for.
func TestActionAndClassValuesAreDistinct(t *testing.T) {
	classes := []drift.Class{
		drift.ClassOwned, drift.ClassUnmanaged, drift.ClassForeign,
		drift.ClassOrphaned, drift.ClassUnknown,
	}
	seenClasses := map[drift.Class]bool{}
	for _, c := range classes {
		if c == "" || seenClasses[c] {
			t.Fatalf("class %q is empty or duplicated", c)
		}
		seenClasses[c] = true
	}
	actions := []drift.Action{
		drift.ActionReview, drift.ActionTag, drift.ActionQuarantine, drift.ActionRemove,
	}
	seenActions := map[drift.Action]bool{}
	for _, a := range actions {
		if a == "" || seenActions[a] {
			t.Fatalf("action %q is empty or duplicated", a)
		}
		seenActions[a] = true
	}
}

// finding builds a finding for planner tests without going through the classifier,
// so a planner test cannot pass merely because classification changed underneath it.
func finding(id string, class drift.Class) drift.Finding {
	return drift.Finding{Object: drift.CloudObject{ID: id}, Class: class, Reason: "planner test", Confidence: 50}
}

// buildOne builds a single-step plan and fails the test if it cannot.
func buildOne(t *testing.T, id string, class drift.Class, opts drift.Options) drift.Plan {
	t.Helper()
	plan, err := drift.BuildPlan([]drift.Finding{finding(id, class)}, opts)
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	return plan
}

// TestNoRemoveStepsWhenRemovalIsNotAllowed: the strongest action planned without an
// explicit allowance is quarantine. Not one Remove may appear even when every finding
// is orphaned, because removal of an object whose environment is gone is exactly the
// act that needs a person.
func TestNoRemoveStepsWhenRemovalIsNotAllowed(t *testing.T) {
	findings := []drift.Finding{
		finding("a", drift.ClassOrphaned),
		finding("b", drift.ClassOrphaned),
		finding("c", drift.ClassOrphaned),
	}
	plan, err := drift.BuildPlan(findings, drift.Options{AllowRemoval: false})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Steps) != 3 {
		t.Fatalf("every orphan needs a step, got %+v", plan.Steps)
	}
	for _, s := range plan.Steps {
		if s.Action == drift.ActionRemove {
			t.Fatalf("removal was not allowed, yet %s is planned for removal", s.ObjectID)
		}
		if s.Action != drift.ActionQuarantine {
			t.Fatalf("the safe action for an orphan is quarantine, got %s", s.Action)
		}
	}
}

// TestUnmanagedAndForeignAreNeverRemoved: unmanaged objects are the customer's own
// and foreign objects belong to somebody else, so no option value may ever plan their
// removal.
func TestUnmanagedAndForeignAreNeverRemoved(t *testing.T) {
	for _, class := range []drift.Class{drift.ClassUnmanaged, drift.ClassForeign} {
		for _, allow := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s allow=%t", class, allow), func(t *testing.T) {
				plan := buildOne(t, "x", class, drift.Options{AllowRemoval: allow})
				if len(plan.Steps) != 1 {
					t.Fatalf("one finding needs one step, got %+v", plan.Steps)
				}
				if plan.Steps[0].Action == drift.ActionRemove {
					t.Fatalf("%s objects are never removable, no matter the options", class)
				}
				if plan.Steps[0].Action != drift.ActionReview {
					t.Fatalf("want review for %s, got %s", class, plan.Steps[0].Action)
				}
			})
		}
	}
}

// TestRemovalIsOnlyEverPlannedForOrphans builds a plan with every class present and
// confirms that a Review step for an unmanaged object cannot be mistaken for
// authority to remove it.
func TestRemovalIsOnlyEverPlannedForOrphans(t *testing.T) {
	findings := []drift.Finding{
		finding("owned", drift.ClassOwned),
		finding("orphan", drift.ClassOrphaned),
		finding("unmanaged", drift.ClassUnmanaged),
		finding("foreign", drift.ClassForeign),
		finding("unknown", drift.ClassUnknown),
	}
	plan, err := drift.BuildPlan(findings, drift.Options{AllowRemoval: true})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	removals := 0
	for _, s := range plan.Steps {
		if s.Action == drift.ActionRemove {
			removals++
			if s.ObjectID != "orphan" {
				t.Fatalf("only an orphan may be planned for removal, got %s for %s", s.Action, s.ObjectID)
			}
		}
	}
	if removals != 1 {
		t.Fatalf("want exactly the one orphan planned for removal, got %d", removals)
	}
}

// TestPlanNeverTags: BuildPlan has no code path that emits ActionTag. Stamping an
// ownership tag onto a resource whose provenance cannot be proven would manufacture
// the provenance the classifier exists to require, so Tag stays in the vocabulary as
// something this planner refuses to do.
func TestPlanNeverTags(t *testing.T) {
	var findings []drift.Finding
	for i, class := range []drift.Class{
		drift.ClassOwned, drift.ClassUnmanaged, drift.ClassForeign,
		drift.ClassOrphaned, drift.ClassUnknown, drift.Class("future-class"),
	} {
		findings = append(findings, finding(fmt.Sprintf("obj-%d", i), class))
	}
	for _, allow := range []bool{false, true} {
		plan, err := drift.BuildPlan(findings, drift.Options{AllowRemoval: allow})
		if err != nil {
			t.Fatalf("build plan: %v", err)
		}
		for _, s := range plan.Steps {
			if s.Action == drift.ActionTag {
				t.Fatalf("the planner must never manufacture ownership by tagging; got a tag step for %s", s.ObjectID)
			}
		}
	}
}

// TestUnknownClassIsQuarantinedNotRemoved: a class this package did not produce (an
// empty string, a future value) must fail closed to quarantine, never to removal.
func TestUnknownClassIsQuarantinedNotRemoved(t *testing.T) {
	for _, class := range []drift.Class{"", drift.Class("future-class")} {
		plan := buildOne(t, "x", class, drift.Options{AllowRemoval: true})
		if len(plan.Steps) != 1 || plan.Steps[0].Action != drift.ActionQuarantine {
			t.Fatalf("unknown class %q must quarantine, got %+v", class, plan.Steps)
		}
	}
}

// TestPlanSkipsOwnedObjects: an owned, expected object needs no remediation, and a
// step for it would be noise that teaches reviewers to skim.
func TestPlanSkipsOwnedObjects(t *testing.T) {
	plan, err := drift.BuildPlan([]drift.Finding{
		finding("owned-a", drift.ClassOwned),
		finding("owned-b", drift.ClassOwned),
	}, drift.Options{AllowRemoval: true})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Steps) != 0 {
		t.Fatalf("an owned object needs no step, got %+v", plan.Steps)
	}
}

// TestPlanStepsAreSortedByObjectID: ordering is part of the plan, not a presentation
// detail. Duplicate object ids sort by action so even a contradictory scan is
// deterministic.
func TestPlanStepsAreSortedByObjectID(t *testing.T) {
	findings := []drift.Finding{
		finding("c", drift.ClassOrphaned),
		finding("a", drift.ClassOrphaned),
		finding("b", drift.ClassUnknown),
		finding("a", drift.ClassUnknown),
	}
	plan, err := drift.BuildPlan(findings, drift.Options{AllowRemoval: true})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	want := []drift.Step{
		{ObjectID: "a", Action: drift.ActionQuarantine},
		{ObjectID: "a", Action: drift.ActionRemove},
		{ObjectID: "b", Action: drift.ActionQuarantine},
		{ObjectID: "c", Action: drift.ActionRemove},
	}
	if !reflect.DeepEqual(plan.Steps, want) {
		t.Fatalf("plan steps:\n got %+v\nwant %+v", plan.Steps, want)
	}
}

// TestPlanIsDeterministicUnderShuffling: the same findings in any order must produce
// byte-identical plans. If an identical scan can produce two different plans, review
// is theater, because the reviewer never saw the plan that runs.
func TestPlanIsDeterministicUnderShuffling(t *testing.T) {
	findings := []drift.Finding{
		finding("db-a", drift.ClassOrphaned),
		finding("db-b", drift.ClassUnmanaged),
		finding("db-c", drift.ClassForeign),
		finding("db-d", drift.ClassUnknown),
		finding("db-e", drift.ClassOwned),
		finding("db-a", drift.ClassUnknown),
	}
	opts := drift.Options{AllowRemoval: true, MaxSteps: 100}

	base, err := drift.BuildPlan(findings, opts)
	if err != nil {
		t.Fatalf("build base plan: %v", err)
	}
	baseJSON, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal base plan: %v", err)
	}

	rng := rand.New(rand.NewSource(20261018))
	for i := 0; i < 12; i++ {
		shuffled := append([]drift.Finding(nil), findings...)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		got, err := drift.BuildPlan(shuffled, opts)
		if err != nil {
			t.Fatalf("shuffle %d: build plan: %v", i, err)
		}
		if got.ID != base.ID {
			t.Fatalf("shuffle %d changed the plan identity: %s vs %s", i, got.ID, base.ID)
		}
		gotJSON, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("shuffle %d: marshal plan: %v", i, err)
		}
		if !bytes.Equal(gotJSON, baseJSON) {
			t.Fatalf("shuffle %d produced a different plan:\n%s\n%s", i, baseJSON, gotJSON)
		}
	}

	t.Run("different drift has a different identity", func(t *testing.T) {
		other, err := drift.BuildPlan([]drift.Finding{finding("db-z", drift.ClassOrphaned)}, opts)
		if err != nil {
			t.Fatalf("build plan: %v", err)
		}
		if other.ID == base.ID {
			t.Fatal("a different plan must have a different identity")
		}
	})
}

// TestEmptyPlanIsValid: no drift is a legitimate outcome, and even it carries a
// stable identity so an audit can say which empty plan was approved.
func TestEmptyPlanIsValid(t *testing.T) {
	plan, err := drift.BuildPlan(nil, drift.Options{})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Steps) != 0 {
		t.Fatalf("no findings means no steps, got %+v", plan.Steps)
	}
	if plan.ID == "" {
		t.Fatal("even an empty plan carries an identity")
	}
	again, err := drift.BuildPlan([]drift.Finding{}, drift.Options{})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if again.ID != plan.ID {
		t.Fatal("the same empty drift must produce the same plan identity")
	}
}

// TestOversizedPlanIsRefusedNotTruncated: a truncated remediation plan that looks
// complete is a plan that silently leaves half the drift behind, so exceeding the
// bound is a refusal, not a haircut.
func TestOversizedPlanIsRefusedNotTruncated(t *testing.T) {
	findings := []drift.Finding{
		finding("a", drift.ClassOrphaned),
		finding("b", drift.ClassOrphaned),
		finding("c", drift.ClassOrphaned),
		finding("d", drift.ClassOrphaned),
	}
	plan, err := drift.BuildPlan(findings, drift.Options{MaxSteps: 3})
	if !errors.Is(err, drift.ErrPlanTooLarge) {
		t.Fatalf("want ErrPlanTooLarge, got %v", err)
	}
	if plan.ID != "" || len(plan.Steps) != 0 {
		t.Fatalf("an oversized plan must be refused whole, not truncated; got %+v", plan)
	}

	// Exactly at the bound is not over it.
	ok, err := drift.BuildPlan(findings, drift.Options{MaxSteps: 4, AllowRemoval: true})
	if err != nil {
		t.Fatalf("a plan at the bound must be allowed: %v", err)
	}
	if len(ok.Steps) != 4 {
		t.Fatalf("a plan at the bound keeps every step, got %d", len(ok.Steps))
	}
}

// TestDefaultMaxStepsBoundsAPlan: "no bound configured" must mean the default bound,
// never unbounded.
func TestDefaultMaxStepsBoundsAPlan(t *testing.T) {
	if drift.DefaultMaxSteps != 500 {
		t.Fatalf("the documented default is 500, got %d", drift.DefaultMaxSteps)
	}
	makeN := func(n int) []drift.Finding {
		out := make([]drift.Finding, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, finding(fmt.Sprintf("obj-%04d", i), drift.ClassOrphaned))
		}
		return out
	}
	if _, err := drift.BuildPlan(makeN(drift.DefaultMaxSteps), drift.Options{}); err != nil {
		t.Fatalf("a plan at the default bound must be allowed: %v", err)
	}
	if _, err := drift.BuildPlan(makeN(drift.DefaultMaxSteps+1), drift.Options{}); !errors.Is(err, drift.ErrPlanTooLarge) {
		t.Fatalf("a plan over the default bound must be refused, got %v", err)
	}
}

// TestStepNeedsAnObjectIdentity: a step that names no object is a destructive action
// waiting to happen, so the plan is refused rather than emitted with a blank target.
func TestStepNeedsAnObjectIdentity(t *testing.T) {
	f := finding("", drift.ClassOrphaned)
	if _, err := drift.BuildPlan([]drift.Finding{f}, drift.Options{}); !errors.Is(err, drift.ErrMissingObjectID) {
		t.Fatalf("a step without an object identity must be refused, got %v", err)
	}
	// An owned object needs no step at all, so its missing identity is not a problem.
	plan, err := drift.BuildPlan([]drift.Finding{finding("", drift.ClassOwned)}, drift.Options{})
	if err != nil || len(plan.Steps) != 0 {
		t.Fatalf("owned objects produce no steps; got plan=%+v err=%v", plan, err)
	}
}

// TestApproveRequiresANamedReviewer: an anonymous approval is not a review, and a
// refused approval must not mark the plan reviewed.
func TestApproveRequiresANamedReviewer(t *testing.T) {
	plan := buildOne(t, "a", drift.ClassOrphaned, drift.Options{})
	for _, reviewer := range []string{"", "   "} {
		got, err := drift.Approve(plan, reviewer, at)
		if !errors.Is(err, drift.ErrNoReviewer) {
			t.Fatalf("approving with reviewer %q must fail closed, got %v", reviewer, err)
		}
		if got.Reviewed {
			t.Fatal("a refused approval must not mark the plan reviewed")
		}
	}
}

// TestApproveRecordsTheReview: approval records who and when, and changes nothing
// else, so the reviewed plan is the plan that will run.
func TestApproveRecordsTheReview(t *testing.T) {
	plan := buildOne(t, "a", drift.ClassOrphaned, drift.Options{})
	reviewed, err := drift.Approve(plan, "alice@example.com", at)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !reviewed.Reviewed || reviewed.Reviewer != "alice@example.com" || !reviewed.ReviewedAt.Equal(at) {
		t.Fatalf("the review must be recorded in full, got %+v", reviewed)
	}
	if reviewed.ID != plan.ID || !reflect.DeepEqual(reviewed.Steps, plan.Steps) {
		t.Fatalf("approval must not change what was approved, got %+v for %+v", reviewed, plan)
	}
}

// TestNoPlanIsRefused: a plan without an identity cannot be attributed later, so
// approving or executing it is refused before anything is recorded.
func TestNoPlanIsRefused(t *testing.T) {
	guard := &sync.Mutex{}
	if err := drift.Execute(nil, guard); !errors.Is(err, drift.ErrNoPlan) {
		t.Fatalf("executing a nil plan must be refused, got %v", err)
	}
	if err := drift.Execute(&drift.Plan{Reviewed: true}, guard); !errors.Is(err, drift.ErrNoPlan) {
		t.Fatalf("executing an unidentified plan must be refused, got %v", err)
	}
	if _, err := drift.Approve(drift.Plan{}, "alice", at); !errors.Is(err, drift.ErrNoPlan) {
		t.Fatalf("approving an unidentified plan must be refused, got %v", err)
	}
	// Identity is checked before the reviewer: a decision about nothing is refused
	// before it can be recorded.
	if _, err := drift.Approve(drift.Plan{}, "", at); !errors.Is(err, drift.ErrNoPlan) {
		t.Fatalf("want ErrNoPlan before ErrNoReviewer, got %v", err)
	}
}

// TestExecuteRequiresASerializationGuard: a serialization point that can be skipped
// silently is not a serialization point, so a nil guard is refused.
func TestExecuteRequiresASerializationGuard(t *testing.T) {
	plan, err := drift.Approve(buildOne(t, "a", drift.ClassOrphaned, drift.Options{}), "alice", at)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := drift.Execute(&plan, nil); !errors.Is(err, drift.ErrNoGuard) {
		t.Fatalf("execution without a guard must be refused, got %v", err)
	}
	if plan.Executed {
		t.Fatal("a refused execution must not mark the plan executed")
	}
}

// TestExecuteRefusesAnUnreviewedPlan: remediation is where a classification mistake
// becomes a deletion, so an unreviewed plan must not run.
func TestExecuteRefusesAnUnreviewedPlan(t *testing.T) {
	plan := buildOne(t, "a", drift.ClassOrphaned, drift.Options{})
	if err := drift.Execute(&plan, &sync.Mutex{}); !errors.Is(err, drift.ErrUnreviewed) {
		t.Fatalf("want ErrUnreviewed, got %v", err)
	}
	if plan.Executed {
		t.Fatal("a refused execution must not mark the plan executed")
	}
}

// TestExecuteTwiceRefused: re-running the same remediation is how a remove step
// races a tag step.
func TestExecuteTwiceRefused(t *testing.T) {
	plan := buildOne(t, "a", drift.ClassOrphaned, drift.Options{})
	plan, err := drift.Approve(plan, "alice", at)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	guard := &sync.Mutex{}
	if err := drift.Execute(&plan, guard); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !plan.Executed {
		t.Fatal("execution must be recorded on the plan")
	}
	if err := drift.Execute(&plan, guard); !errors.Is(err, drift.ErrAlreadyExecuted) {
		t.Fatalf("a second execution must be refused, got %v", err)
	}
}

// TestExecuteIsSerialized: eight operators sharing one plan and one guard produce
// exactly one execution. The guard is the only thing standing between a shared plan
// and two concurrent remediations.
func TestExecuteIsSerialized(t *testing.T) {
	plan, err := drift.Approve(buildOne(t, "a", drift.ClassOrphaned, drift.Options{}), "alice", at)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	guard := &sync.Mutex{}
	const executors = 8

	errs := make([]error, executors)
	var wg sync.WaitGroup
	for i := 0; i < executors; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = drift.Execute(&plan, guard)
		}(i)
	}
	wg.Wait()

	executed, refused := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			executed++
		case errors.Is(err, drift.ErrAlreadyExecuted):
			refused++
		default:
			t.Fatalf("unexpected execution outcome: %v", err)
		}
	}
	if executed != 1 || refused != executors-1 {
		t.Fatalf("execution must happen exactly once: got %d executed, %d refused", executed, refused)
	}
}

// countingGuard is a real mutex that records how it was used. If Execute ever checks
// review state before acquiring it, the counts show the check ran outside the
// critical section, which is exactly the window two operators race through.
type countingGuard struct {
	mu      sync.Mutex
	locks   int
	unlocks int
}

func (g *countingGuard) Lock() {
	g.mu.Lock()
	g.locks++
}

func (g *countingGuard) Unlock() {
	g.unlocks++
	g.mu.Unlock()
}

// TestExecuteRunsItsChecksInsideTheGuard.
func TestExecuteRunsItsChecksInsideTheGuard(t *testing.T) {
	plan := buildOne(t, "a", drift.ClassOrphaned, drift.Options{})
	guard := &countingGuard{}
	if err := drift.Execute(&plan, guard); !errors.Is(err, drift.ErrUnreviewed) {
		t.Fatalf("want ErrUnreviewed, got %v", err)
	}
	if guard.locks != 1 || guard.unlocks != 1 {
		t.Fatalf("the refusal must happen inside the guard: locks=%d unlocks=%d", guard.locks, guard.unlocks)
	}
}

// TestHappyPath is the whole package end to end: classify a mix of real drift the way
// a scan would, build the plan, have a person approve it, execute it exactly once,
// and confirm the second execution is refused.
func TestHappyPath(t *testing.T) {
	exp := fleet()
	findings := []drift.Finding{
		classify(t, tagged("obj-owned", "aws_db_instance", "env-1"), exp),
		classify(t, tagged("obj-orphan", "aws_db_instance", "env-retired"), exp),
		classify(t, drift.CloudObject{ID: "obj-unmanaged", Type: "aws_s3_bucket"}, exp),
		classify(t, drift.CloudObject{ID: "obj-foreign", Type: "customer_thing"}, exp),
		classify(t, tagged("obj-unknown", "aws_db_instance", ""), exp),
	}
	wantClasses := []drift.Class{
		drift.ClassOwned, drift.ClassOrphaned, drift.ClassUnmanaged,
		drift.ClassForeign, drift.ClassUnknown,
	}
	for i, f := range findings {
		if f.Class != wantClasses[i] {
			t.Fatalf("finding %s: got %s, want %s", f.Object.ID, f.Class, wantClasses[i])
		}
	}

	plan, err := drift.BuildPlan(findings, drift.Options{AllowRemoval: true})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	want := []drift.Step{
		{ObjectID: "obj-foreign", Action: drift.ActionReview},
		{ObjectID: "obj-orphan", Action: drift.ActionRemove},
		{ObjectID: "obj-unknown", Action: drift.ActionQuarantine},
		{ObjectID: "obj-unmanaged", Action: drift.ActionReview},
	}
	if !reflect.DeepEqual(plan.Steps, want) {
		t.Fatalf("plan steps:\n got %+v\nwant %+v", plan.Steps, want)
	}
	if plan.Reviewed || plan.Executed {
		t.Fatalf("a fresh plan is neither reviewed nor executed, got %+v", plan)
	}

	plan, err = drift.Approve(plan, "alice@example.com", at)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !plan.Reviewed || plan.Reviewer != "alice@example.com" {
		t.Fatalf("the review must be recorded before execution, got %+v", plan)
	}

	guard := &sync.Mutex{}
	if err := drift.Execute(&plan, guard); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !plan.Executed {
		t.Fatal("execution must be recorded on the plan")
	}
	if err := drift.Execute(&plan, guard); !errors.Is(err, drift.ErrAlreadyExecuted) {
		t.Fatalf("a reviewed and executed plan must not run twice, got %v", err)
	}
}
