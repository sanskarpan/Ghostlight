// Package recipe validates the shared recipe, health, and gate contracts.
//
// SPEC.md section 8: "Recipe schema and dependency/test/profile declarations match
// reviewed catalog. Mutable image tags are rejected. ... Migration/config/schema
// compatibility gates run before runtime readiness. PR code cannot extend recipe
// permissions or change trusted gate policy."
//
// A recipe is what a pull request proposes to run. The contract is the boundary between
// what a PR may propose and what the platform will accept. Every rule here exists
// because the alternative is a preview running something nobody reviewed: an image that
// moved under its tag, a permission the catalog never granted, a health check that
// cannot fail, a gate that references nothing.
//
// Validation is total: a recipe is accepted only if every declaration conforms. There
// is no "accept with warnings", because a warning in a log is not a boundary and the
// preview runs either way.
package recipe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Errors returned by this package.
var (
	// ErrUnknownSchema means the recipe declares a schema version the platform does
	// not know. An unknown schema cannot be validated, so it is refused rather than
	// assumed compatible.
	ErrUnknownSchema = errors.New("unknown recipe schema version")
	// ErrMutableTag means the image reference can move. A tag that can move means the
	// preview may run code nobody reviewed.
	ErrMutableTag = errors.New("mutable image tag")
	// ErrUnknownDependency means a dependency kind the catalog does not carry.
	ErrUnknownDependency = errors.New("unknown dependency kind")
	// ErrPermissionEscalation means the recipe claims a permission the catalog does
	// not grant. PR code cannot extend recipe permissions.
	ErrPermissionEscalation = errors.New("recipe claims an ungranted permission")
	// ErrBadHealthCheck means a health check declaration cannot fail or cannot run.
	ErrBadHealthCheck = errors.New("invalid health check declaration")
	// ErrUnknownGate means a gate the platform does not run.
	ErrUnknownGate = errors.New("unknown gate")
	// ErrIncomplete means a required declaration is missing.
	ErrIncomplete = errors.New("recipe is missing a required declaration")
)

// CurrentSchema is the recipe schema version this platform validates.
const CurrentSchema = "ghostlight.recipe/v1"

// Dependency is one typed dependency a recipe needs.
type Dependency struct {
	// Kind is the dependency type, such as postgres or redis.
	Kind string `json:"kind"`
	// Profile selects the resource profile.
	Profile string `json:"profile"`
	// LogicalKey is the stable name within the environment.
	LogicalKey string `json:"logical_key"`
}

// HealthCheck is one readiness/liveness declaration.
type HealthCheck struct {
	// Name identifies the check.
	Name string `json:"name"`
	// Endpoint is the path or target probed.
	Endpoint string `json:"endpoint"`
	// IntervalSeconds bounds how often it runs.
	IntervalSeconds int `json:"interval_seconds"`
	// TimeoutSeconds bounds each probe.
	TimeoutSeconds int `json:"timeout_seconds"`
	// FailureThreshold counts consecutive failures before unhealthy.
	FailureThreshold int `json:"failure_threshold"`
	// SuccessThreshold counts consecutive successes before healthy again.
	SuccessThreshold int `json:"success_threshold"`
}

// Gate is one qualification gate the recipe requires.
type Gate struct {
	// Name is the gate, such as smoke or isolation.
	Name string `json:"name"`
	// Required reports whether the preview may serve without passing it.
	Required bool `json:"required"`
}

// Recipe is a reviewable preview definition.
type Recipe struct {
	// Name identifies the recipe in the catalog.
	Name string `json:"name"`
	// SchemaVersion is the contract version.
	SchemaVersion string `json:"schema_version"`
	// Image is the workload image reference. It must be pinned by digest.
	Image string `json:"image"`
	// Dependencies are the typed dependencies.
	Dependencies []Dependency `json:"dependencies"`
	// Tests are the test suites that must pass.
	Tests []string `json:"tests"`
	// Profiles are the resource profiles allowed.
	Profiles []string `json:"profiles"`
	// Permissions are the platform permissions claimed.
	Permissions []string `json:"permissions"`
	// Health are the health check declarations.
	Health []HealthCheck `json:"health"`
	// Gates are the qualification gates required.
	Gates []Gate `json:"gates"`
}

// Catalog is the reviewed set a recipe is validated against.
type Catalog struct {
	// SchemaVersions are the contract versions the platform validates.
	SchemaVersions []string
	// DependencyKinds are the typed dependencies carried.
	DependencyKinds []string
	// Profiles are the resource profiles offered.
	Profiles []string
	// Permissions are the platform permissions grantable.
	Permissions []string
	// Gates are the qualification gates run.
	Gates []string
}

// DefaultCatalog returns the 1.0 reviewed catalog.
func DefaultCatalog() Catalog {
	return Catalog{
		SchemaVersions:  []string{CurrentSchema},
		DependencyKinds: []string{"postgres", "redis", "kafka", "temporal", "object_store", "identity"},
		Profiles:        []string{"postgres-standard", "preview-basic"},
		Permissions:     []string{"db:connect", "db:migrate", "topic:publish", "topic:subscribe", "object:read", "object:write", "http:egress-allowlisted"},
		Gates:           []string{"smoke", "isolation", "replay", "search", "load"},
	}
}

// Parse decodes a recipe document.
func Parse(raw []byte) (Recipe, error) {
	var r Recipe
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Recipe{}, fmt.Errorf("decode recipe: %w", err)
	}
	return r, nil
}

// Validate checks a recipe against the catalog.
//
// Every declaration is checked and every failure is reported at once. Reporting one
// error per run would make each authoring cycle cost a full round trip for a problem
// that was already there.
func Validate(r Recipe, c Catalog) error {
	var errs []error

	if r.Name == "" {
		errs = append(errs, fmt.Errorf("%w: name", ErrIncomplete))
	}
	if !containsStr(c.SchemaVersions, r.SchemaVersion) {
		errs = append(errs, fmt.Errorf("%w: %q", ErrUnknownSchema, r.SchemaVersion))
	}
	if err := validateImage(r.Image); err != nil {
		errs = append(errs, err)
	}

	seenDeps := map[string]bool{}
	for i, d := range r.Dependencies {
		if d.Kind == "" || d.LogicalKey == "" {
			errs = append(errs, fmt.Errorf("%w: dependency %d needs a kind and a logical key", ErrIncomplete, i))
			continue
		}
		if !containsStr(c.DependencyKinds, d.Kind) {
			errs = append(errs, fmt.Errorf("%w: %q", ErrUnknownDependency, d.Kind))
		}
		if d.Profile != "" && !containsStr(c.Profiles, d.Profile) {
			errs = append(errs, fmt.Errorf("unknown profile %q for dependency %s", d.Profile, d.LogicalKey))
		}
		key := d.Kind + "/" + d.LogicalKey
		if seenDeps[key] {
			errs = append(errs, fmt.Errorf("duplicate dependency %s", key))
		}
		seenDeps[key] = true
	}

	if len(r.Tests) == 0 {
		errs = append(errs, fmt.Errorf("%w: at least one test suite", ErrIncomplete))
	}
	for _, t := range r.Tests {
		if t == "" {
			errs = append(errs, fmt.Errorf("%w: test suite name", ErrIncomplete))
		}
	}

	// Permissions are a subset check, and the direction matters. The recipe's
	// permissions must be within the catalog's grants: PR code cannot extend recipe
	// permissions, so anything outside the catalog is an escalation attempt, not a
	// request.
	granted := map[string]bool{}
	for _, p := range c.Permissions {
		granted[p] = true
	}
	for _, p := range r.Permissions {
		if !granted[p] {
			errs = append(errs, fmt.Errorf("%w: %q", ErrPermissionEscalation, p))
		}
	}

	for i, h := range r.Health {
		if err := validateHealth(h); err != nil {
			errs = append(errs, fmt.Errorf("health check %d: %w", i, err))
		}
	}
	if len(r.Health) == 0 {
		errs = append(errs, fmt.Errorf("%w: at least one health check", ErrIncomplete))
	}

	knownGates := map[string]bool{}
	for _, g := range c.Gates {
		knownGates[g] = true
	}
	for _, g := range r.Gates {
		if !knownGates[g.Name] {
			errs = append(errs, fmt.Errorf("%w: %q", ErrUnknownGate, g.Name))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	// errors.Join preserves every sentinel, so a caller can still ask whether the
	// failure was a permission escalation or a mutable tag. Joining messages into one
	// string would erase that distinction and force string matching.
	return errors.Join(errs...)
}

// validateImage refuses anything but a digest-pinned reference.
//
// A tag can move between review and run. A digest cannot. "latest", an untagged name,
// and a tag without a digest all mean the preview may run code nobody reviewed, so all
// three are refused. The digest form is name@sha256:<hex>.
func validateImage(image string) error {
	if image == "" {
		return fmt.Errorf("%w: image", ErrIncomplete)
	}
	at := strings.LastIndex(image, "@")
	if at < 0 {
		if strings.Contains(image, ":") {
			return fmt.Errorf("%w: %q is tagged and tags move; pin by digest", ErrMutableTag, image)
		}
		return fmt.Errorf("%w: %q has no tag at all, which means latest", ErrMutableTag, image)
	}
	ref := image[at+1:]
	if !strings.HasPrefix(ref, "sha256:") || len(ref) != len("sha256:")+64 {
		return fmt.Errorf("%w: %q is not a pinned sha256 digest", ErrMutableTag, image)
	}
	for _, c := range ref[len("sha256:"):] {
		if !isHex(c) {
			return fmt.Errorf("%w: %q is not a pinned sha256 digest", ErrMutableTag, image)
		}
	}
	return nil
}

func isHex(c rune) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// validateHealth refuses declarations that cannot fail or cannot run.
//
// A health check that cannot fail is not a health check: it is a step that always
// passes, which qualifies everything including a dead preview. A check with no endpoint
// cannot run; a zero timeout cannot complete; a zero failure threshold fires on the
// first transient; a zero success threshold flaps back to healthy on one lucky probe.
func validateHealth(h HealthCheck) error {
	switch {
	case h.Name == "":
		return fmt.Errorf("%w: name", ErrBadHealthCheck)
	case h.Endpoint == "":
		return fmt.Errorf("%w: %s has no endpoint", ErrBadHealthCheck, h.Name)
	case h.IntervalSeconds <= 0:
		return fmt.Errorf("%w: %s has no interval", ErrBadHealthCheck, h.Name)
	case h.TimeoutSeconds <= 0:
		return fmt.Errorf("%w: %s cannot complete with no timeout", ErrBadHealthCheck, h.Name)
	case h.TimeoutSeconds >= h.IntervalSeconds:
		return fmt.Errorf("%w: %s times out slower than it probes, so probes overlap forever",
			ErrBadHealthCheck, h.Name)
	case h.FailureThreshold <= 0:
		return fmt.Errorf("%w: %s fires on the first transient", ErrBadHealthCheck, h.Name)
	case h.SuccessThreshold <= 0:
		return fmt.Errorf("%w: %s flaps healthy on one lucky probe", ErrBadHealthCheck, h.Name)
	default:
		return nil
	}
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// Digest returns the content digest of a recipe document.
//
// It is computed over the canonical encoding with SHA-256, so the recipe_digest in a
// candidate identifies exactly what was reviewed. A recipe that changes in any byte is
// a different recipe, and a weak hash would let two different recipes share an
// identity.
func Digest(r Recipe) string {
	raw, _ := json.Marshal(r)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Summarize renders a recipe for review.
func Summarize(r Recipe) string {
	return fmt.Sprintf("recipe %s schema=%s image-pinned=%v deps=%d tests=%d health=%d gates=%d perms=%d",
		r.Name, r.SchemaVersion, validateImage(r.Image) == nil,
		len(r.Dependencies), len(r.Tests), len(r.Health), len(r.Gates), len(r.Permissions))
}
