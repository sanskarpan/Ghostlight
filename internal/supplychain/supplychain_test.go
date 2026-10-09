package supplychain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/supplychain"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
var digest = "registry.ghostlight.test/previews/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func artifact() supplychain.Artifact {
	return supplychain.Artifact{
		Image:              digest,
		BaseImage:          "registry.ghostlight.test/base/debian@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		BaseBuiltAt:        now.Add(-7 * 24 * time.Hour),
		ProvenanceVerified: true,
		RecipeValid:        true,
	}
}

// TestCompliantArtifactIsAdmitted is the ordinary path.
func TestCompliantArtifactIsAdmitted(t *testing.T) {
	d := supplychain.Admit(artifact(), supplychain.DefaultPolicy(), now)
	if !d.Admitted || len(d.Broken) != 0 {
		t.Fatalf("a compliant artifact must be admitted, got %+v", d)
	}
}

// TestUnallowlistedRegistryIsRefused, including the Docker Hub shorthand that has no
// registry part at all.
func TestUnallowlistedRegistryIsRefused(t *testing.T) {
	for name, image := range map[string]string{
		"docker hub": "library/nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"other host": "evil.test/previews/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"no host":    "previews/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"empty":      "",
	} {
		a := artifact()
		a.Image = image
		d := supplychain.Admit(a, supplychain.DefaultPolicy(), now)
		if d.Admitted {
			t.Fatalf("%s image must be refused, got %+v", name, d)
		}
	}
}

// TestUnpinnedImageIsRefused even when everything else holds.
func TestUnpinnedImageIsRefused(t *testing.T) {
	a := artifact()
	a.Image = "registry.ghostlight.test/previews/app:latest"
	d := supplychain.Admit(a, supplychain.DefaultPolicy(), now)
	if d.Admitted {
		t.Fatalf("a movable tag must be refused, got %+v", d)
	}
}

// TestUnprovenancedArtifactIsRefused: an image nobody accounts for does not run.
func TestUnprovenancedArtifactIsRefused(t *testing.T) {
	a := artifact()
	a.ProvenanceVerified = false
	a.ProvenanceDetail = "no attestation presented"
	d := supplychain.Admit(a, supplychain.DefaultPolicy(), now)
	if d.Admitted {
		t.Fatalf("an unprovenanced artifact must be refused, got %+v", d)
	}
	if !strings.Contains(strings.Join(d.Broken, ";"), "no attestation") {
		t.Fatalf("the refusal must carry the provenance reason, got %v", d.Broken)
	}
}

// TestInvalidRecipeIsRefused.
func TestInvalidRecipeIsRefused(t *testing.T) {
	a := artifact()
	a.RecipeValid = false
	a.RecipeDetail = "mutable image tag"
	d := supplychain.Admit(a, supplychain.DefaultPolicy(), now)
	if d.Admitted {
		t.Fatalf("an invalid recipe must be refused, got %+v", d)
	}
}

// TestStaleBaseIsRefused: a base past its patch windows accepts known vulnerabilities
// by default.
func TestStaleBaseIsRefused(t *testing.T) {
	a := artifact()
	a.BaseBuiltAt = now.Add(-60 * 24 * time.Hour)
	d := supplychain.Admit(a, supplychain.DefaultPolicy(), now)
	if d.Admitted {
		t.Fatalf("a stale base must be refused, got %+v", d)
	}
}

// TestUndatedBaseIsRefused: an undated base cannot meet a patch SLA.
func TestUndatedBaseIsRefused(t *testing.T) {
	a := artifact()
	a.BaseBuiltAt = time.Time{}
	d := supplychain.Admit(a, supplychain.DefaultPolicy(), now)
	if d.Admitted {
		t.Fatalf("an undated base must be refused, got %+v", d)
	}
}

// TestFutureBaseIsRefused.
func TestFutureBaseIsRefused(t *testing.T) {
	a := artifact()
	a.BaseBuiltAt = now.Add(time.Hour)
	d := supplychain.Admit(a, supplychain.DefaultPolicy(), now)
	if d.Admitted {
		t.Fatalf("a future-dated base must be refused, got %+v", d)
	}
}

// TestEveryBrokenLinkIsReportedAtOnce.
func TestEveryBrokenLinkIsReportedAtOnce(t *testing.T) {
	a := supplychain.Artifact{Image: "evil.test/app:latest"}
	d := supplychain.Admit(a, supplychain.DefaultPolicy(), now)
	if d.Admitted {
		t.Fatal("a fully noncompliant artifact must be refused")
	}
	// Registry, pin, provenance, recipe, base age: five broken links.
	if len(d.Broken) != 5 {
		t.Fatalf("every broken link must be reported, got %v", d.Broken)
	}
	// Stably ordered so two runs report the same refusal.
	joined := strings.Join(d.Broken, "\n")
	for i := 1; i < len(d.Broken); i++ {
		if d.Broken[i-1] > d.Broken[i] {
			t.Fatalf("broken links must be sorted, got %q", joined)
		}
	}
}

// TestPolicyWithoutRequirementsAdmitsMore: the policy is data, so posture changes are
// reviewable diffs rather than code changes.
func TestPolicyWithoutRequirementsAdmitsMore(t *testing.T) {
	p := supplychain.DefaultPolicy()
	p.RequireProvenance = false
	p.RequireRecipe = false
	p.MaxBaseAge = 0
	a := artifact()
	a.ProvenanceVerified = false
	a.RecipeValid = false
	a.BaseBuiltAt = time.Time{}
	d := supplychain.Admit(a, p, now)
	if !d.Admitted {
		t.Fatalf("a relaxed policy must admit, got %+v", d)
	}
}

// TestDefaultPolicyIsStrict.
func TestDefaultPolicyIsStrict(t *testing.T) {
	p := supplychain.DefaultPolicy()
	if !p.RequireProvenance || !p.RequireRecipe {
		t.Fatal("the default policy must require provenance and recipe")
	}
	if len(p.AllowedRegistries) != 1 {
		t.Fatalf("the default allowlist must be exactly the platform registry, got %v", p.AllowedRegistries)
	}
	if p.MaxBaseAge <= 0 {
		t.Fatal("the default policy must bound base age")
	}
}
