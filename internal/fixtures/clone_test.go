package fixtures_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/sanskarpan/Ghostlight/internal/fixtures"
)

func cloneTarget() fixtures.Identity {
	return fixtures.Identity{ID: "env-2", Slug: "pr-2"}
}

// TestCloneHasNoAuthority is the load-bearing rule. The parent is non-empty on
// every authority field so the assertion cannot be vacuously true.
func TestCloneHasNoAuthority(t *testing.T) {
	parent := validSnapshot()
	clone, err := fixtures.Clone(parent, cloneTarget())
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if len(parent.Grants) == 0 || len(parent.Tokens) == 0 || len(parent.Sessions) == 0 || len(parent.DeleteAuthority) == 0 {
		t.Fatal("the parent must carry authority for this test to mean anything")
	}
	for name, values := range map[string][]string{
		"grants":           clone.Grants,
		"tokens":           clone.Tokens,
		"sessions":         clone.Sessions,
		"delete authority": clone.DeleteAuthority,
	} {
		if len(values) != 0 {
			t.Fatalf("clone must carry no %s, got %v", name, values)
		}
	}
}

// TestInheritsNothingAcceptsCorrectClone is the positive control for the checker.
func TestInheritsNothingAcceptsCorrectClone(t *testing.T) {
	parent := validSnapshot()
	clone, err := fixtures.Clone(parent, cloneTarget())
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if err := fixtures.InheritsNothing(parent, clone); err != nil {
		t.Fatalf("a correct clone must inherit nothing: %v", err)
	}
}

// TestInheritsNothingRejectsInheritedAuthority is the required negative control.
// Without it the checker could be vacuously true.
func TestInheritsNothingRejectsInheritedAuthority(t *testing.T) {
	parent := validSnapshot()
	good, err := fixtures.Clone(parent, cloneTarget())
	if err != nil {
		t.Fatalf("clone: %v", err)
	}

	cases := map[string]func(*fixtures.Snapshot){
		"grant":            func(s *fixtures.Snapshot) { s.Grants = append([]string(nil), parent.Grants...) },
		"capability token": func(s *fixtures.Snapshot) { s.Tokens = append([]string(nil), parent.Tokens...) },
		"session":          func(s *fixtures.Snapshot) { s.Sessions = append([]string(nil), parent.Sessions...) },
		"delete authority": func(s *fixtures.Snapshot) {
			s.DeleteAuthority = append([]string(nil), parent.DeleteAuthority...)
		},
	}
	for name, corrupt := range cases {
		broken := good
		corrupt(&broken)
		if err := fixtures.InheritsNothing(parent, broken); err == nil {
			t.Fatalf("a clone that shares a parent %s must be refused", name)
		} else if !errors.Is(err, fixtures.ErrAuthorityInherited) {
			t.Fatalf("the refusal must be ErrAuthorityInherited for %s, got %v", name, err)
		}
	}
}

// TestInheritsNothingRejectsNewAuthorityToo: a clone starts with no authority of
// any kind, whether it came from the parent or was minted afterwards.
func TestInheritsNothingRejectsNewAuthorityToo(t *testing.T) {
	parent := validSnapshot()
	clone, err := fixtures.Clone(parent, cloneTarget())
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	clone.Grants = []string{"db:migrate"}
	if err := fixtures.InheritsNothing(parent, clone); !errors.Is(err, fixtures.ErrAuthorityInherited) {
		t.Fatalf("authority on a clone must be refused even when the parent lacks it, got %v", err)
	}
}

// TestCloneRefusesParentIdentity: reusing either half of the parent identity leaves
// the parent reachable through the clone.
func TestCloneRefusesParentIdentity(t *testing.T) {
	parent := validSnapshot()
	for name, target := range map[string]fixtures.Identity{
		"exact":     parent.Identity,
		"same id":   {ID: parent.Identity.ID, Slug: "pr-other"},
		"same slug": {ID: "env-other", Slug: parent.Identity.Slug},
	} {
		if _, err := fixtures.Clone(parent, target); !errors.Is(err, fixtures.ErrIdentityReused) {
			t.Fatalf("%s identity must be refused, got %v", name, err)
		}
	}
}

// TestCloneRequiresFreshIdentity: an incomplete target cannot become a principal.
func TestCloneRequiresFreshIdentity(t *testing.T) {
	parent := validSnapshot()
	for name, target := range map[string]fixtures.Identity{
		"no id":   {Slug: "pr-2"},
		"no slug": {ID: "env-2"},
		"empty":   {},
	} {
		if _, err := fixtures.Clone(parent, target); !errors.Is(err, fixtures.ErrInvalidIdentity) {
			t.Fatalf("%s target must be refused, got %v", name, err)
		}
	}
	if _, err := fixtures.Clone(fixtures.Snapshot{Generation: 1}, cloneTarget()); !errors.Is(err, fixtures.ErrInvalidIdentity) {
		t.Fatalf("a parent with no identity must be refused, got %v", err)
	}
}

// TestCloneRecordsProvenance: the clone names the parent it came from, but the
// parent identity itself is not usable through the clone.
func TestCloneRecordsProvenance(t *testing.T) {
	parent := validSnapshot()
	target := cloneTarget()
	clone, err := fixtures.Clone(parent, target)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}

	if clone.CloneOf != parent.Identity.ID {
		t.Fatalf("provenance must name the parent id: %q != %q", clone.CloneOf, parent.Identity.ID)
	}
	if clone.ParentDigest != parent.Digest() {
		t.Fatalf("provenance must pin the parent digest: %q != %q", clone.ParentDigest, parent.Digest())
	}
	if clone.Identity != target {
		t.Fatalf("the clone must use the fresh identity: %#v != %#v", clone.Identity, target)
	}
	if clone.Identity == parent.Identity || clone.Identity.ID == parent.Identity.ID || clone.Identity.Slug == parent.Identity.Slug {
		t.Fatal("the parent identity must not be usable through the clone")
	}
	if clone.EnvironmentID != target.ID {
		t.Fatalf("the clone must be scoped to the new environment: %q != %q", clone.EnvironmentID, target.ID)
	}
	if clone.Digest() == parent.Digest() {
		t.Fatal("the clone digest must differ from the parent because provenance is part of it")
	}
}

// TestCloneDoesNotMutateParent: cloning is a copy, not a transfer.
func TestCloneDoesNotMutateParent(t *testing.T) {
	parent := validSnapshot()
	before := parent
	if _, err := fixtures.Clone(parent, cloneTarget()); err != nil {
		t.Fatalf("clone: %v", err)
	}
	if !reflect.DeepEqual(parent, before) {
		t.Fatalf("clone mutated the parent:\n got %#v\nwant %#v", parent, before)
	}
}
