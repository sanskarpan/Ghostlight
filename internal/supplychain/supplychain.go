// Package supplychain admits artifacts into previews under a supply-chain policy.
//
// G0.7: "Define platform supply-chain policy, build sandbox isolation and CVE/patch
// SLAs." Sandbox isolation needs a runtime and CVE data needs a feed, so what is owned
// here is the policy itself: the single decision, from verifiable inputs, whether an
// artifact may run.
//
// An artifact is admitted only if every link in its supply chain holds: the source
// registry is allowed, the reference is pinned by digest, provenance attests the build
// and verifies, the recipe validates, and the base image is fresh enough to meet the
// patch SLA. Any broken link refuses. There is no partial admission — a pinned image
// with no provenance is an image nobody accounts for, and fresh base with a mutable
// tag is freshness theater over code that moved.
//
// The policy is data, not code paths: one decision function over explicit inputs, so
// the whole posture fits in a review and every refusal names its broken link.
package supplychain

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package.
var (
	// ErrUnallowedRegistry means the image comes from outside the allowlist.
	ErrUnallowedRegistry = errors.New("image registry is not allowlisted")
	// ErrUnpinned means the reference can move.
	ErrUnpinned = errors.New("image reference is not pinned by digest")
	// ErrNoProvenance means no build provenance was presented.
	ErrNoProvenance = errors.New("no build provenance presented")
	// ErrBadProvenance means provenance failed verification.
	ErrBadProvenance = errors.New("build provenance failed verification")
	// ErrBadRecipe means the recipe failed validation.
	ErrBadRecipe = errors.New("recipe failed validation")
	// ErrStaleBase means the base image exceeds the patch SLA.
	ErrStaleBase = errors.New("base image exceeds the patch SLA")
)

// Artifact is what a preview proposes to run.
type Artifact struct {
	// Image is the workload image reference.
	Image string
	// BaseImage is the base the workload image was built from.
	BaseImage string
	// BaseBuiltAt is when the base image was published.
	BaseBuiltAt time.Time
	// ProvenanceVerified reports that build provenance checked out.
	ProvenanceVerified bool
	// ProvenanceDetail explains a verification failure.
	ProvenanceDetail string
	// RecipeValid reports that the recipe validated.
	RecipeValid bool
	// RecipeDetail explains a validation failure.
	RecipeDetail string
}

// Policy is the admission posture.
type Policy struct {
	// AllowedRegistries are the only sources artifacts may come from.
	AllowedRegistries []string
	// MaxBaseAge bounds how old a base image may be. A base older than this has
	// missed patch windows, and running it accepts known vulnerabilities by default.
	MaxBaseAge time.Duration
	// RequireProvenance refuses artifacts without verified provenance.
	RequireProvenance bool
	// RequireRecipe refuses artifacts without a valid recipe.
	RequireRecipe bool
}

// DefaultPolicy returns the platform posture.
func DefaultPolicy() Policy {
	return Policy{
		AllowedRegistries: []string{"registry.ghostlight.test"},
		MaxBaseAge:        30 * 24 * time.Hour,
		RequireProvenance: true,
		RequireRecipe:     true,
	}
}

// Decision is one admission outcome with every broken link named.
type Decision struct {
	// Admitted reports whether the artifact may run.
	Admitted bool
	// Broken names every failed link, stably ordered.
	Broken []string
}

// Admit evaluates an artifact against the policy.
//
// Every link is checked and every failure reported at once. Reporting one broken link
// per run would make each fix cycle cost a full round trip for a problem that was
// already there — and a builder fixing links one at a time deserves the whole list.
func Admit(a Artifact, p Policy, now time.Time) Decision {
	var broken []string

	if reg := registryOf(a.Image); !containsStr(p.AllowedRegistries, reg) {
		broken = append(broken, fmt.Sprintf("registry %q is not allowlisted", reg))
	}
	if !pinned(a.Image) {
		broken = append(broken, "image reference is not pinned by digest and can move")
	}
	if p.RequireProvenance && !a.ProvenanceVerified {
		reason := "no verified build provenance"
		if a.ProvenanceDetail != "" {
			reason = a.ProvenanceDetail
		}
		broken = append(broken, reason)
	}
	if p.RequireRecipe && !a.RecipeValid {
		reason := "no valid recipe"
		if a.RecipeDetail != "" {
			reason = a.RecipeDetail
		}
		broken = append(broken, reason)
	}
	if p.MaxBaseAge > 0 {
		if a.BaseBuiltAt.IsZero() {
			broken = append(broken, "base image age is unknown; an undated base cannot meet a patch SLA")
		} else if age := now.Sub(a.BaseBuiltAt); age > p.MaxBaseAge {
			broken = append(broken, fmt.Sprintf("base image is %s old, beyond the %s patch SLA", age.Round(24*time.Hour), p.MaxBaseAge))
		} else if age < 0 {
			broken = append(broken, "base image claims a future publish date")
		}
	}

	sort.Strings(broken)
	return Decision{Admitted: len(broken) == 0, Broken: broken}
}

// registryOf extracts the registry host from an image reference.
func registryOf(image string) string {
	// A reference without a host part comes from the default registry, which is
	// never allowlisted: implicit defaults are how unreviewed sources slip in.
	first := image
	if i := strings.Index(first, "/"); i >= 0 {
		first = first[:i]
	} else {
		return ""
	}
	if !strings.Contains(first, ".") && !strings.Contains(first, ":") && first != "localhost" {
		// A single path segment is a Docker Hub shorthand, not a registry.
		return ""
	}
	return first
}

// pinned reports whether the reference is digest-pinned.
func pinned(image string) bool {
	at := strings.LastIndex(image, "@")
	if at < 0 {
		return false
	}
	ref := image[at+1:]
	if !strings.HasPrefix(ref, "sha256:") || len(ref) != len("sha256:")+64 {
		return false
	}
	for _, c := range ref[len("sha256:"):] {
		if !isHex(c) {
			return false
		}
	}
	return true
}

func isHex(c rune) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
