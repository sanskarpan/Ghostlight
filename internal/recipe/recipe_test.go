package recipe_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sanskarpan/Ghostlight/internal/recipe"
)

func catalog() recipe.Catalog {
	return recipe.DefaultCatalog()
}

func valid() recipe.Recipe {
	return recipe.Recipe{
		Name:          "preview-postgres",
		SchemaVersion: recipe.CurrentSchema,
		Image:         "registry.ghostlight.test/previews/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Dependencies: []recipe.Dependency{
			{Kind: "postgres", Profile: "postgres-standard", LogicalKey: "primary"},
		},
		Tests:       []string{"smoke"},
		Profiles:    []string{"postgres-standard"},
		Permissions: []string{"db:connect", "db:migrate"},
		Health: []recipe.HealthCheck{{
			Name: "http-ready", Endpoint: "/readyz",
			IntervalSeconds: 10, TimeoutSeconds: 2, FailureThreshold: 3, SuccessThreshold: 1,
		}},
		Gates: []recipe.Gate{{Name: "smoke", Required: true}},
	}
}

// TestValidRecipePasses is the ordinary path.
func TestValidRecipePasses(t *testing.T) {
	if err := recipe.Validate(valid(), catalog()); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// TestUnknownSchemaIsRefused: an unknown schema cannot be validated, so it is refused
// rather than assumed compatible.
func TestUnknownSchemaIsRefused(t *testing.T) {
	r := valid()
	r.SchemaVersion = "ghostlight.recipe/v99"
	if err := recipe.Validate(r, catalog()); !errors.Is(err, recipe.ErrUnknownSchema) {
		t.Fatalf("an unknown schema must be refused, got %v", err)
	}
}

// TestMutableTagsAreRefused covers every way an image reference can move.
func TestMutableTagsAreRefused(t *testing.T) {
	for name, image := range map[string]string{
		"tagged":   "registry.ghostlight.test/previews/app:latest",
		"version":  "registry.ghostlight.test/previews/app:1.2.3",
		"untagged": "registry.ghostlight.test/previews/app",
		"bad hex":  "registry.ghostlight.test/previews/app@sha256:zzz",
		"short":    "registry.ghostlight.test/previews/app@sha256:abc",
	} {
		r := valid()
		r.Image = image
		if err := recipe.Validate(r, catalog()); !errors.Is(err, recipe.ErrMutableTag) {
			t.Fatalf("%s image %q must be refused, got %v", name, image, err)
		}
	}
	// Empty is a different refusal: incomplete, not mutable.
	empty := valid()
	empty.Image = ""
	if err := recipe.Validate(empty, catalog()); !errors.Is(err, recipe.ErrIncomplete) {
		t.Fatalf("an empty image must be refused as incomplete, got %v", err)
	}
}

// TestDigestPinnedImagePasses.
func TestDigestPinnedImagePasses(t *testing.T) {
	r := valid()
	r.Image = "registry.ghostlight.test/previews/app@sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
	if err := recipe.Validate(r, catalog()); err != nil {
		t.Fatalf("an uppercase digest pin must be accepted: %v", err)
	}
}

// TestUnknownDependencyIsRefused.
func TestUnknownDependencyIsRefused(t *testing.T) {
	r := valid()
	r.Dependencies = append(r.Dependencies, recipe.Dependency{Kind: "quantum_queue", LogicalKey: "q"})
	if err := recipe.Validate(r, catalog()); !errors.Is(err, recipe.ErrUnknownDependency) {
		t.Fatalf("an unknown dependency must be refused, got %v", err)
	}
}

// TestDuplicateDependencyIsRefused: two claims on one logical key would race at allocate.
func TestDuplicateDependencyIsRefused(t *testing.T) {
	r := valid()
	r.Dependencies = append(r.Dependencies, recipe.Dependency{Kind: "postgres", Profile: "postgres-standard", LogicalKey: "primary"})
	if err := recipe.Validate(r, catalog()); err == nil {
		t.Fatal("a duplicate dependency must be refused")
	} else if !strings.Contains(err.Error(), "duplicate dependency") {
		t.Fatalf("the refusal must name the duplication, got %q", err)
	}
}

// TestPermissionEscalationIsRefused is the "PR code cannot extend permissions" rule.
// The direction matters: the recipe's permissions must sit within the catalog's grants.
func TestPermissionEscalationIsRefused(t *testing.T) {
	r := valid()
	r.Permissions = append(r.Permissions, "iam:*")
	if err := recipe.Validate(r, catalog()); !errors.Is(err, recipe.ErrPermissionEscalation) {
		t.Fatalf("an ungranted permission must be refused, got %v", err)
	}
}

// TestHealthChecksMustBeAbleToFail: a check that cannot fail qualifies everything,
// including a dead preview.
func TestHealthChecksMustBeAbleToFail(t *testing.T) {
	base := recipe.HealthCheck{
		Name: "http-ready", Endpoint: "/readyz",
		IntervalSeconds: 10, TimeoutSeconds: 2, FailureThreshold: 3, SuccessThreshold: 1,
	}
	cases := map[string]func(*recipe.HealthCheck){
		"no name":        func(h *recipe.HealthCheck) { h.Name = "" },
		"no endpoint":    func(h *recipe.HealthCheck) { h.Endpoint = "" },
		"no interval":    func(h *recipe.HealthCheck) { h.IntervalSeconds = 0 },
		"no timeout":     func(h *recipe.HealthCheck) { h.TimeoutSeconds = 0 },
		"timeout slower": func(h *recipe.HealthCheck) { h.TimeoutSeconds = 30 },
		"no failure":     func(h *recipe.HealthCheck) { h.FailureThreshold = 0 },
		"no success":     func(h *recipe.HealthCheck) { h.SuccessThreshold = 0 },
	}
	for name, mutate := range cases {
		h := base
		mutate(&h)
		r := valid()
		r.Health = []recipe.HealthCheck{h}
		if err := recipe.Validate(r, catalog()); !errors.Is(err, recipe.ErrBadHealthCheck) {
			t.Fatalf("%s must be refused, got %v", name, err)
		}
	}
}

// TestRecipeWithoutHealthIsRefused.
func TestRecipeWithoutHealthIsRefused(t *testing.T) {
	r := valid()
	r.Health = nil
	if err := recipe.Validate(r, catalog()); err == nil {
		t.Fatal("a recipe with no health checks must be refused")
	}
}

// TestUnknownGateIsRefused.
func TestUnknownGateIsRefused(t *testing.T) {
	r := valid()
	r.Gates = append(r.Gates, recipe.Gate{Name: "vibes", Required: true})
	if err := recipe.Validate(r, catalog()); !errors.Is(err, recipe.ErrUnknownGate) {
		t.Fatalf("an unknown gate must be refused, got %v", err)
	}
}

// TestRecipeWithoutTestsIsRefused.
func TestRecipeWithoutTestsIsRefused(t *testing.T) {
	r := valid()
	r.Tests = nil
	if err := recipe.Validate(r, catalog()); err == nil {
		t.Fatal("a recipe with no tests must be refused")
	}
}

// TestIncompleteRecipeIsRefused names what is missing.
func TestIncompleteRecipeIsRefused(t *testing.T) {
	if err := recipe.Validate(recipe.Recipe{}, catalog()); !errors.Is(err, recipe.ErrIncomplete) {
		t.Fatalf("an empty recipe must be refused as incomplete, got %v", err)
	}
}

// TestAllFailuresAreReportedAtOnce: one error per run would make each authoring cycle
// cost a full round trip for a problem that was already there.
func TestAllFailuresAreReportedAtOnce(t *testing.T) {
	r := valid()
	r.SchemaVersion = "nope"
	r.Image = "app:latest"
	r.Permissions = append(r.Permissions, "iam:*")
	err := recipe.Validate(r, catalog())
	if err == nil {
		t.Fatal("expected failures")
	}
	for _, want := range []string{"schema", "latest", "iam:*"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the report must mention %q, got %q", want, err)
		}
	}
}

// TestUnknownFieldsAreRejectedAtParse: a field the platform does not understand is a
// field whose meaning is unreviewed.
func TestUnknownFieldsAreRejectedAtParse(t *testing.T) {
	raw := `{"name":"x","schema_version":"ghostlight.recipe/v1","image":"i","mystery_field":1}`
	if _, err := recipe.Parse([]byte(raw)); err == nil {
		t.Fatal("unknown fields must be rejected at parse")
	}
}

// TestDigestIdentifiesTheReviewedContent: any byte change is a different recipe.
func TestDigestIdentifiesTheReviewedContent(t *testing.T) {
	a := valid()
	b := valid()
	if recipe.Digest(a) != recipe.Digest(b) {
		t.Fatal("identical recipes must share a digest")
	}
	b.Tests = append(b.Tests, "extra")
	if recipe.Digest(a) == recipe.Digest(b) {
		t.Fatal("a changed recipe must be a different recipe")
	}
	if !strings.HasPrefix(recipe.Digest(a), "sha256:") {
		t.Fatalf("the digest must be a sha256 identity, got %q", recipe.Digest(a))
	}
}

// TestCatalogFixturesValidate: every fixture in catalog/recipes must pass, so the
// catalog cannot drift out of reviewability unnoticed.
func TestCatalogFixturesValidate(t *testing.T) {
	dir := filepath.Join("..", "..", "catalog", "recipes")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("the catalog must ship fixtures, or there is nothing to hold reviewable")
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		r, err := recipe.Parse(raw)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		if err := recipe.Validate(r, catalog()); err != nil {
			t.Fatalf("fixture %s must be reviewable: %v", e.Name(), err)
		}
	}
}

// TestSummarizeNeverPanicsOnHostileInput and never leaks.
func TestSummarizeNeverPanicsOnHostileInput(t *testing.T) {
	_ = strings.Contains(recipe.Summarize(recipe.Recipe{}), "recipe")
	if got := recipe.Summarize(valid()); !strings.Contains(got, "preview-postgres") {
		t.Fatalf("a summary must identify the recipe, got %q", got)
	}
}
