package templates_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/internal/templates"
)

const (
	digestA      = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	digestB      = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	templateName = "preview-postgres"
)

func draft() templates.Version {
	return templates.Version{
		Template:       templateName,
		Version:        3,
		CleanupRuntime: "cleanup-runtime-v1",
		EvidenceID:     "evidence://qual/4711",
	}
}

func qualified(t *testing.T) templates.Version {
	t.Helper()
	v, err := templates.Qualify(draft(), digestA)
	if err != nil {
		t.Fatalf("qualify fixture: %v", err)
	}
	return v
}

func published(t *testing.T) templates.Version {
	t.Helper()
	v, err := templates.Publish(qualified(t))
	if err != nil {
		t.Fatalf("publish fixture: %v", err)
	}
	return v
}

func deprecated(t *testing.T) templates.Version {
	t.Helper()
	v, err := templates.Deprecate(published(t))
	if err != nil {
		t.Fatalf("deprecate fixture: %v", err)
	}
	return v
}

func withdrawn(t *testing.T) templates.Version {
	t.Helper()
	v, err := templates.Withdraw(deprecated(t))
	if err != nil {
		t.Fatalf("withdraw fixture: %v", err)
	}
	return v
}

func registryWith(t *testing.T, vs ...templates.Version) templates.Registry {
	t.Helper()
	reg := templates.Registry{}
	for _, v := range vs {
		var err error
		reg, err = templates.Register(reg, v)
		if err != nil {
			t.Fatalf("register fixture %s v%d: %v", v.Template, v.Version, err)
		}
	}
	return reg
}

// TestStatesRenderForDiagnosis: a refusal must name the state rather than a number.
func TestStatesRenderForDiagnosis(t *testing.T) {
	want := map[templates.State]string{
		templates.StateDraft:      "draft",
		templates.StateQualified:  "qualified",
		templates.StatePublished:  "published",
		templates.StateDeprecated: "deprecated",
		templates.StateWithdrawn:  "withdrawn",
	}
	for state, text := range want {
		if got := state.String(); got != text {
			t.Fatalf("state %d renders as %q, want %q", state, got, text)
		}
	}
	var zero templates.State
	if zero != templates.StateDraft {
		t.Fatalf("the zero state is %s, want draft; an untouched version must not be selectable", zero)
	}
	if templates.State(99).String() == "" {
		t.Fatal("an unknown state must still render, or a refusal cannot name it")
	}
}

// TestLegalTransitionsAreAccepted walks the reviewed lifecycle forward, plus the two
// direct withdrawal edges.
func TestLegalTransitionsAreAccepted(t *testing.T) {
	chain := []templates.State{
		templates.StateDraft,
		templates.StateQualified,
		templates.StatePublished,
		templates.StateDeprecated,
		templates.StateWithdrawn,
	}
	for i := 0; i < len(chain)-1; i++ {
		if err := templates.Transition(chain[i], chain[i+1]); err != nil {
			t.Fatalf("%s -> %s must be legal: %v", chain[i], chain[i+1], err)
		}
	}
	for _, from := range []templates.State{templates.StateQualified, templates.StatePublished} {
		if err := templates.Transition(from, templates.StateWithdrawn); err != nil {
			t.Fatalf("%s -> withdrawn must be legal: %v", from, err)
		}
	}
}

// TestIllegalTransitionsAreRefused is the property test over the whole table: a move
// is accepted exactly when the lifecycle allows it.
func TestIllegalTransitionsAreRefused(t *testing.T) {
	states := []templates.State{
		templates.StateDraft,
		templates.StateQualified,
		templates.StatePublished,
		templates.StateDeprecated,
		templates.StateWithdrawn,
	}
	legal := map[[2]templates.State]bool{
		{templates.StateDraft, templates.StateQualified}:      true,
		{templates.StateQualified, templates.StatePublished}:  true,
		{templates.StatePublished, templates.StateDeprecated}: true,
		{templates.StateDeprecated, templates.StateWithdrawn}: true,
		{templates.StateQualified, templates.StateWithdrawn}:  true,
		{templates.StatePublished, templates.StateWithdrawn}:  true,
	}
	for _, from := range states {
		for _, to := range states {
			err := templates.Transition(from, to)
			if legal[[2]templates.State{from, to}] {
				if err != nil {
					t.Fatalf("%s -> %s must be legal: %v", from, to, err)
				}
				continue
			}
			if !errors.Is(err, templates.ErrIllegalTransition) {
				t.Fatalf("%s -> %s must be refused, got %v", from, to, err)
			}
			msg := err.Error()
			if !strings.Contains(msg, from.String()) || !strings.Contains(msg, to.String()) {
				t.Fatalf("the refusal must name both states, got %q", msg)
			}
		}
	}

	// The moves that would break the lifecycle, named so a regression is loud.
	for name, pair := range map[string][2]templates.State{
		"a published version cannot go back to draft":     {templates.StatePublished, templates.StateDraft},
		"a published version cannot go back to qualified": {templates.StatePublished, templates.StateQualified},
		"a draft cannot skip qualification":               {templates.StateDraft, templates.StatePublished},
		"a deprecated version cannot publish again":       {templates.StateDeprecated, templates.StatePublished},
		"a withdrawn version cannot publish again":        {templates.StateWithdrawn, templates.StatePublished},
	} {
		if err := templates.Transition(pair[0], pair[1]); !errors.Is(err, templates.ErrIllegalTransition) {
			t.Fatalf("%s, got %v", name, err)
		}
	}
}

// TestQualificationNeedsEvidence: a qualified version with no evidence is a claim,
// not a qualification.
func TestQualificationNeedsEvidence(t *testing.T) {
	v := draft()
	v.EvidenceID = ""
	if _, err := templates.Qualify(v, digestA); !errors.Is(err, templates.ErrNoQualificationEvidence) {
		t.Fatalf("a qualification with no evidence must be refused, got %v", err)
	}
}

// TestQualifyRecordsTheDigestAndAdvancesDraft.
func TestQualifyRecordsTheDigestAndAdvancesDraft(t *testing.T) {
	v, err := templates.Qualify(draft(), digestA)
	if err != nil {
		t.Fatalf("qualify: %v", err)
	}
	if v.Digest != digestA {
		t.Fatalf("digest is %q, want %q", v.Digest, digestA)
	}
	if v.State != templates.StateQualified {
		t.Fatalf("state is %s, want qualified", v.State)
	}
	if v.EvidenceID != draft().EvidenceID {
		t.Fatalf("qualification must preserve the evidence, got %q", v.EvidenceID)
	}
	if v.CleanupRuntime != draft().CleanupRuntime {
		t.Fatalf("qualification must not touch the pinned cleanup runtime, got %q", v.CleanupRuntime)
	}
}

// TestTheSameDigestTwiceIsIdempotent: a retry of one qualification is not a change.
func TestTheSameDigestTwiceIsIdempotent(t *testing.T) {
	once := qualified(t)
	twice, err := templates.Qualify(once, digestA)
	if err != nil {
		t.Fatalf("re-qualifying with the same digest must be idempotent: %v", err)
	}
	if twice != once {
		t.Fatalf("an idempotent qualification changed the version: %+v, want %+v", twice, once)
	}
}

// TestADifferentDigestIsRefused: a different artifact wearing the same version
// number is exactly what must not silently replace a qualified artifact.
func TestADifferentDigestIsRefused(t *testing.T) {
	once := qualified(t)
	if _, err := templates.Qualify(once, digestB); !errors.Is(err, templates.ErrDigestChanged) {
		t.Fatalf("a different digest must be refused, got %v", err)
	}
	if once.Digest != digestA {
		t.Fatalf("a refused qualification changed the digest to %q", once.Digest)
	}
}

// TestQualifyDoesNotRewindALaterState: qualification of an already published version
// is a digest comparison, never a step backwards.
func TestQualifyDoesNotRewindALaterState(t *testing.T) {
	p := published(t)
	again, err := templates.Qualify(p, digestA)
	if err != nil {
		t.Fatalf("re-qualifying with the same digest must be idempotent: %v", err)
	}
	if again.State != templates.StatePublished {
		t.Fatalf("state is %s, want published; qualification must not rewind the lifecycle", again.State)
	}
	if _, err := templates.Qualify(p, digestB); !errors.Is(err, templates.ErrDigestChanged) {
		t.Fatalf("a published version's digest must stay immutable, got %v", err)
	}
}

// TestPublishingRequiresQualification: there is no path from draft to published, and
// a deprecation cannot be undone by publishing again.
func TestPublishingRequiresQualification(t *testing.T) {
	if _, err := templates.Publish(draft()); !errors.Is(err, templates.ErrIllegalTransition) {
		t.Fatalf("a draft cannot publish without qualification, got %v", err)
	}
	if _, err := templates.Publish(deprecated(t)); !errors.Is(err, templates.ErrIllegalTransition) {
		t.Fatalf("a deprecated version cannot publish again, got %v", err)
	}
}

// TestAnUnpinnedCleanupRuntimeCannotBePublished is the row's explicit requirement:
// no new environments without a teardown path.
func TestAnUnpinnedCleanupRuntimeCannotBePublished(t *testing.T) {
	v := draft()
	v.CleanupRuntime = ""
	q, err := templates.Qualify(v, digestA)
	if err != nil {
		t.Fatalf("qualify fixture: %v", err)
	}
	if _, err := templates.Publish(q); !errors.Is(err, templates.ErrUnpinnedCleanup) {
		t.Fatalf("publishing without a pinned cleanup runtime must be refused, got %v", err)
	}
	if q.State != templates.StateQualified {
		t.Fatalf("a refused publish changed the state to %s", q.State)
	}
}

// TestDeprecationKeepsThePinnedCleanupRuntime: deprecating a version does not remove
// its cleanup runtime, because the environments built from it still exist.
func TestDeprecationKeepsThePinnedCleanupRuntime(t *testing.T) {
	p := published(t)
	d, err := templates.Deprecate(p)
	if err != nil {
		t.Fatalf("deprecate: %v", err)
	}
	if d.State != templates.StateDeprecated || !d.Deprecated {
		t.Fatalf("deprecated version is state=%s flag=%v", d.State, d.Deprecated)
	}
	if d.CleanupRuntime != p.CleanupRuntime || d.CleanupRuntime == "" {
		t.Fatalf("deprecation must keep the pinned cleanup runtime, got %q", d.CleanupRuntime)
	}
	reg := registryWith(t, d)
	rt, err := templates.CleanupRuntimeFor(reg, d.Template, d.Version)
	if err != nil {
		t.Fatalf("a deprecated version's cleanup runtime must resolve: %v", err)
	}
	if rt != p.CleanupRuntime {
		t.Fatalf("cleanup runtime is %q, want %q", rt, p.CleanupRuntime)
	}
}

// TestDeprecationOnlyFollowsPublication: deprecating an unreleased version makes no
// sense, and deprecating twice is not a move.
func TestDeprecationOnlyFollowsPublication(t *testing.T) {
	for name, v := range map[string]templates.Version{
		"draft":      draft(),
		"qualified":  qualified(t),
		"deprecated": deprecated(t),
		"withdrawn":  withdrawn(t),
	} {
		if _, err := templates.Deprecate(v); !errors.Is(err, templates.ErrIllegalTransition) {
			t.Fatalf("deprecating a %s version must be refused, got %v", name, err)
		}
	}
}

// TestADeprecatedVersionIsNotSelectable: deprecation forbids new use...
func TestADeprecatedVersionIsNotSelectable(t *testing.T) {
	d := deprecated(t)
	if templates.Selectable(d) {
		t.Fatal("a deprecated version must not be selectable")
	}
	reg := registryWith(t, d)
	if _, err := templates.Resolve(reg, d.Template, d.Version); !errors.Is(err, templates.ErrNotSelectable) {
		t.Fatalf("resolving a deprecated version for new work must be refused, got %v", err)
	}
}

// TestAWithdrawnVersionCannotBeSelected: withdrawal is stronger than deprecation.
func TestAWithdrawnVersionCannotBeSelected(t *testing.T) {
	w := withdrawn(t)
	if templates.Selectable(w) {
		t.Fatal("a withdrawn version must not be selectable")
	}
	reg := registryWith(t, w)
	if _, err := templates.Resolve(reg, w.Template, w.Version); !errors.Is(err, templates.ErrNotSelectable) {
		t.Fatalf("resolving a withdrawn version for new work must be refused, got %v", err)
	}
}

// TestAWithdrawnVersionsCleanupRuntimeStillResolves is the key lifecycle property:
// teardown must outlive withdrawal, or every environment built from the version is
// orphaned.
func TestAWithdrawnVersionsCleanupRuntimeStillResolves(t *testing.T) {
	w := withdrawn(t)
	if w.State != templates.StateWithdrawn {
		t.Fatalf("fixture state is %s, want withdrawn", w.State)
	}
	reg := registryWith(t, w)
	rt, err := templates.CleanupRuntimeFor(reg, w.Template, w.Version)
	if err != nil {
		t.Fatalf("teardown must outlive withdrawal: %v", err)
	}
	if rt != draft().CleanupRuntime {
		t.Fatalf("cleanup runtime is %q, want %q", rt, draft().CleanupRuntime)
	}
}

// TestWithdrawalDirectlyFromPublicationKeepsTheCleanupRuntime: a version can be
// abandoned before it is ever deprecated, and teardown still survives.
func TestWithdrawalDirectlyFromPublicationKeepsTheCleanupRuntime(t *testing.T) {
	w, err := templates.Withdraw(published(t))
	if err != nil {
		t.Fatalf("published -> withdrawn must be legal: %v", err)
	}
	reg := registryWith(t, w)
	rt, err := templates.CleanupRuntimeFor(reg, w.Template, w.Version)
	if err != nil {
		t.Fatalf("a withdrawn version's cleanup runtime must still resolve: %v", err)
	}
	if rt != draft().CleanupRuntime {
		t.Fatalf("cleanup runtime is %q, want %q", rt, draft().CleanupRuntime)
	}
}

// TestAWithdrawnVersionCannotBeRevived.
func TestAWithdrawnVersionCannotBeRevived(t *testing.T) {
	w := withdrawn(t)
	if _, err := templates.Publish(w); !errors.Is(err, templates.ErrIllegalTransition) {
		t.Fatalf("a withdrawn version cannot be published again, got %v", err)
	}
	if _, err := templates.Deprecate(w); !errors.Is(err, templates.ErrIllegalTransition) {
		t.Fatalf("a withdrawn version cannot be deprecated again, got %v", err)
	}
	if err := templates.Transition(w.State, templates.StateDraft); !errors.Is(err, templates.ErrIllegalTransition) {
		t.Fatalf("a withdrawn version cannot return to draft, got %v", err)
	}
}

// TestResolveRefusesAnUnknownTemplate.
func TestResolveRefusesAnUnknownTemplate(t *testing.T) {
	reg := registryWith(t, published(t))
	if _, err := templates.Resolve(reg, "no-such-template", 3); !errors.Is(err, templates.ErrUnknownTemplate) {
		t.Fatalf("an unknown template must be refused, got %v", err)
	}
}

// TestResolveRefusesAnUnknownVersion.
func TestResolveRefusesAnUnknownVersion(t *testing.T) {
	reg := registryWith(t, published(t))
	if _, err := templates.Resolve(reg, templateName, 99); !errors.Is(err, templates.ErrUnknownVersion) {
		t.Fatalf("an unknown version must be refused, got %v", err)
	}
}

// TestCleanupRuntimeForRefusesUnknownTemplatesAndVersions: teardown gets the same
// lookup refusals as selection; it only skips the selectability check.
func TestCleanupRuntimeForRefusesUnknownTemplatesAndVersions(t *testing.T) {
	reg := registryWith(t, published(t))
	if _, err := templates.CleanupRuntimeFor(reg, "no-such-template", 3); !errors.Is(err, templates.ErrUnknownTemplate) {
		t.Fatalf("an unknown template must be refused, got %v", err)
	}
	if _, err := templates.CleanupRuntimeFor(reg, templateName, 99); !errors.Is(err, templates.ErrUnknownVersion) {
		t.Fatalf("an unknown version must be refused, got %v", err)
	}
}

// TestCleanupRuntimeForRefusesAnUnpinnedVersion: there is nothing to tear down with.
func TestCleanupRuntimeForRefusesAnUnpinnedVersion(t *testing.T) {
	v := draft()
	v.CleanupRuntime = ""
	reg := registryWith(t, v)
	if _, err := templates.CleanupRuntimeFor(reg, v.Template, v.Version); !errors.Is(err, templates.ErrUnpinnedCleanup) {
		t.Fatalf("an unpinned version has no cleanup runtime to resolve, got %v", err)
	}
}

// TestDuplicateVersionsAreRefused: two versions sharing a number would make "v3"
// ambiguous, and every environment pinned to it uncertain.
func TestDuplicateVersionsAreRefused(t *testing.T) {
	reg := registryWith(t, draft())
	next, err := templates.Register(reg, draft())
	if !errors.Is(err, templates.ErrDuplicateVersion) {
		t.Fatalf("a duplicate version must be refused, got %v", err)
	}
	if len(next.Templates[0].Versions) != 1 {
		t.Fatalf("a refused registration changed the registry: %d versions", len(next.Templates[0].Versions))
	}

	// The same number on a DIFFERENT template is not a duplicate; uniqueness is per
	// template.
	other := draft()
	other.Template = "preview-redis"
	if _, err := templates.Register(reg, other); err != nil {
		t.Fatalf("the same number on another template is not a duplicate: %v", err)
	}
}

// TestRegisterAddsTemplatesAndVersionsWithoutMutating.
func TestRegisterAddsTemplatesAndVersionsWithoutMutating(t *testing.T) {
	reg := registryWith(t, draft())
	if len(reg.Templates) != 1 || len(reg.Templates[0].Versions) != 1 {
		t.Fatalf("registry shape is %d templates, want 1 with 1 version", len(reg.Templates))
	}

	newer := draft()
	newer.Version = 4
	grown, err := templates.Register(reg, newer)
	if err != nil {
		t.Fatalf("register v4: %v", err)
	}
	if len(grown.Templates[0].Versions) != 2 {
		t.Fatalf("v4 was not added: %d versions", len(grown.Templates[0].Versions))
	}
	if len(reg.Templates[0].Versions) != 1 {
		t.Fatal("registering must not mutate the registry it was given")
	}

	other := draft()
	other.Template = "preview-redis"
	both, err := templates.Register(grown, other)
	if err != nil {
		t.Fatalf("register second template: %v", err)
	}
	if len(both.Templates) != 2 || both.Templates[1].Name != "preview-redis" {
		t.Fatalf("the second template was not created: %+v", both.Templates)
	}
}

// TestUpdateReplacesAVersionAndRefusesUnknowns: lifecycle progress has to land in
// the registry, and a typo must not silently become a new version.
func TestUpdateReplacesAVersionAndRefusesUnknowns(t *testing.T) {
	reg := registryWith(t, draft())
	q := qualified(t)
	next, err := templates.Update(reg, q)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if next.Templates[0].Versions[0].State != templates.StateQualified {
		t.Fatalf("state is %s, want qualified", next.Templates[0].Versions[0].State)
	}
	if reg.Templates[0].Versions[0].State != templates.StateDraft {
		t.Fatal("update must not mutate the registry it was given")
	}

	unknownTemplate := q
	unknownTemplate.Template = "no-such-template"
	if _, err := templates.Update(reg, unknownTemplate); !errors.Is(err, templates.ErrUnknownTemplate) {
		t.Fatalf("updating an unknown template must be refused, got %v", err)
	}
	unknownVersion := q
	unknownVersion.Version = 99
	if _, err := templates.Update(reg, unknownVersion); !errors.Is(err, templates.ErrUnknownVersion) {
		t.Fatalf("updating an unknown version must be refused, got %v", err)
	}
}

// TestSelectableOnlyForPublishedVersions is the property table behind the
// deprecation boundary.
func TestSelectableOnlyForPublishedVersions(t *testing.T) {
	cases := map[string]struct {
		v    templates.Version
		want bool
	}{
		"draft":      {templates.Version{State: templates.StateDraft}, false},
		"qualified":  {templates.Version{State: templates.StateQualified}, false},
		"published":  {templates.Version{State: templates.StatePublished}, true},
		"deprecated": {templates.Version{State: templates.StateDeprecated, Deprecated: true}, false},
		"withdrawn":  {templates.Version{State: templates.StateWithdrawn}, false},
		// A stale state must not out-vote the deprecation flag.
		"published but flagged deprecated": {templates.Version{State: templates.StatePublished, Deprecated: true}, false},
	}
	for name, tc := range cases {
		if got := templates.Selectable(tc.v); got != tc.want {
			t.Fatalf("%s: selectable=%v, want %v", name, got, tc.want)
		}
	}
}

// TestResolveRefusesEveryNonPublishedState.
func TestResolveRefusesEveryNonPublishedState(t *testing.T) {
	cases := map[string]templates.Version{
		"draft":      draft(),
		"qualified":  qualified(t),
		"deprecated": deprecated(t),
		"withdrawn":  withdrawn(t),
	}
	for name, v := range cases {
		reg := registryWith(t, v)
		if _, err := templates.Resolve(reg, v.Template, v.Version); !errors.Is(err, templates.ErrNotSelectable) {
			t.Fatalf("a %s version must be refused for new work, got %v", name, err)
		}
	}
}

// TestCleanupRuntimeSurvivesEveryLifecycleStep walks the whole chain in the registry
// and checks after every step that teardown still resolves. Deprecation and
// withdrawal remove selection; they must never remove teardown.
func TestCleanupRuntimeSurvivesEveryLifecycleStep(t *testing.T) {
	reg := registryWith(t, draft())
	v := draft()

	steps := []struct {
		name string
		run  func(v templates.Version) (templates.Version, error)
	}{
		{"qualified", func(v templates.Version) (templates.Version, error) { return templates.Qualify(v, digestA) }},
		{"published", templates.Publish},
		{"deprecated", templates.Deprecate},
		{"withdrawn", templates.Withdraw},
	}
	for _, step := range steps {
		var err error
		v, err = step.run(v)
		if err != nil {
			t.Fatalf("step %s: %v", step.name, err)
		}
		reg, err = templates.Update(reg, v)
		if err != nil {
			t.Fatalf("record %s: %v", step.name, err)
		}
		rt, err := templates.CleanupRuntimeFor(reg, v.Template, v.Version)
		if err != nil {
			t.Fatalf("after %s, the pinned cleanup runtime must still resolve: %v", step.name, err)
		}
		if rt != draft().CleanupRuntime {
			t.Fatalf("after %s, cleanup runtime is %q, want %q", step.name, rt, draft().CleanupRuntime)
		}
	}
}

// TestHappyPathLifecycle is the ordinary life of a template version: drafted,
// qualified with evidence and a digest, published, selected for an environment,
// deprecated, and then refused for new selection while teardown still resolves.
func TestHappyPathLifecycle(t *testing.T) {
	reg := templates.Registry{}
	var err error

	v := draft()
	reg, err = templates.Register(reg, v)
	if err != nil {
		t.Fatalf("register draft: %v", err)
	}
	if v.State != templates.StateDraft {
		t.Fatalf("a fresh version is %s, want draft", v.State)
	}

	v, err = templates.Qualify(v, digestA)
	if err != nil {
		t.Fatalf("qualify: %v", err)
	}
	if v.State != templates.StateQualified || v.Digest != digestA {
		t.Fatalf("qualified version is state=%s digest=%q", v.State, v.Digest)
	}
	reg, err = templates.Update(reg, v)
	if err != nil {
		t.Fatalf("record qualification: %v", err)
	}

	v, err = templates.Publish(v)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if v.State != templates.StatePublished {
		t.Fatalf("published version is %s", v.State)
	}
	reg, err = templates.Update(reg, v)
	if err != nil {
		t.Fatalf("record publication: %v", err)
	}

	selected, err := templates.Resolve(reg, v.Template, v.Version)
	if err != nil {
		t.Fatalf("a published version must be selectable: %v", err)
	}
	if selected.Digest != digestA {
		t.Fatalf("selected digest is %q, want %q", selected.Digest, digestA)
	}

	v, err = templates.Deprecate(v)
	if err != nil {
		t.Fatalf("deprecate: %v", err)
	}
	reg, err = templates.Update(reg, v)
	if err != nil {
		t.Fatalf("record deprecation: %v", err)
	}

	if _, err := templates.Resolve(reg, v.Template, v.Version); !errors.Is(err, templates.ErrNotSelectable) {
		t.Fatalf("a deprecated version must not be selectable, got %v", err)
	}
	rt, err := templates.CleanupRuntimeFor(reg, v.Template, v.Version)
	if err != nil {
		t.Fatalf("a deprecated version's cleanup runtime must still resolve: %v", err)
	}
	if rt != draft().CleanupRuntime {
		t.Fatalf("cleanup runtime is %q, want %q", rt, draft().CleanupRuntime)
	}
}
