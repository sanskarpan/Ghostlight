// Package templates keeps the versioned service and template catalog: which versions
// of a template exist, how each one moves through its lifecycle, and what it takes to
// tear down an environment built from a version that is no longer selectable.
//
// G7.5 / G-F05. The catalog is versioned because a template is not a fact that stays
// true; it is an artifact that gets reviewed, used, and retired, and the environments
// built from it outlive all three. The lifecycle exists so the platform can answer two
// different questions with two different answers:
//
//   - May a new environment be created from this version? Only while the version is
//     published. Deprecation refuses a version for new work, which is the whole point
//     of deprecating it.
//   - Can an existing environment be torn down? Always, for every version that was
//     ever published. The cleanup runtime is pinned on the version when it qualifies,
//     never looked up at teardown time, so deprecating or even withdrawing a version
//     cannot orphan the environments already built from it. A version can be retired
//     long before its last environment is.
//
// Two refusals carry the weight of the whole design. A published version cannot
// return to draft, because publishing means it was used and un-publishing would let
// its content change under environments already built from it. A qualified version
// cannot change its digest, because qualification is a statement about one artifact,
// and a statement that can change makes every past qualification meaningless.
package templates

import (
	"errors"
	"fmt"
)

// Errors returned by this package.
var (
	// ErrIllegalTransition means the lifecycle does not allow that move, such as
	// Published back to Draft. It is a refusal rather than a silent edit because the
	// state a version is in is what every other decision was made against.
	ErrIllegalTransition = errors.New("illegal template version transition")
	// ErrDigestChanged means a qualified version was offered a different digest.
	// Qualification is a statement about a specific artifact, and letting the
	// artifact change would make every past qualification meaningless.
	ErrDigestChanged = errors.New("qualified version digest changed")
	// ErrUnpinnedCleanup means a version has no pinned cleanup runtime. Publishing
	// without one is refused because every published version must remain tearable,
	// and a teardown cannot guess which runtime a retired version needs.
	ErrUnpinnedCleanup = errors.New("version has no pinned cleanup runtime")
	// ErrNotSelectable means the version exists but may not start a new environment,
	// because only published versions are selectable.
	ErrNotSelectable = errors.New("version is not selectable for a new deployment")
	// ErrUnknownTemplate means the registry carries no template by that name.
	ErrUnknownTemplate = errors.New("unknown template")
	// ErrUnknownVersion means the template exists but carries no such version.
	ErrUnknownVersion = errors.New("unknown template version")
	// ErrDuplicateVersion means a template already carries that version number. Two
	// versions sharing a number would make "v3" ambiguous, and every environment
	// pinned to it uncertain.
	ErrDuplicateVersion = errors.New("duplicate template version")
	// ErrNoQualificationEvidence means a qualification arrived with no evidence
	// reference. A qualified version with no evidence is a claim, not a qualification.
	ErrNoQualificationEvidence = errors.New("qualification has no evidence reference")
)

// State is the lifecycle state of one template version.
//
// The zero value is StateDraft, so a version that has never been through the
// lifecycle is treated as unqualified rather than accidentally selectable.
type State int

// The lifecycle states. A version is drafted, qualified, published, then deprecated
// and withdrawn; qualified and published versions may also be withdrawn directly,
// because a version can be abandoned before it is ever deprecated.
const (
	// StateDraft is a version nobody has qualified yet.
	StateDraft State = iota
	// StateQualified is a version with recorded evidence and an immutable digest.
	StateQualified
	// StatePublished is a version selectable for new environments.
	StatePublished
	// StateDeprecated is a published version refused for new use but still tearable.
	StateDeprecated
	// StateWithdrawn is a version permanently out of service, still tearable.
	StateWithdrawn
)

// String renders a state for refusals and logs, so a refusal names the state instead
// of a number.
func (s State) String() string {
	switch s {
	case StateDraft:
		return "draft"
	case StateQualified:
		return "qualified"
	case StatePublished:
		return "published"
	case StateDeprecated:
		return "deprecated"
	case StateWithdrawn:
		return "withdrawn"
	default:
		return fmt.Sprintf("state(%d)", int(s))
	}
}

// Version is one version of a service template.
type Version struct {
	// Template is the template name this version belongs to.
	Template string
	// Version is the version number. It is unique within a template.
	Version int
	// Digest is the content address of the artifact this version qualified.
	// Qualify records it, and once recorded it cannot change.
	Digest string
	// CleanupRuntime is the pinned cleanup runtime used to tear down environments
	// created from this version. Pinning it per version is what lets teardown
	// outlive deprecation and withdrawal.
	CleanupRuntime string
	// State is the lifecycle state. It is the authority for what may happen next.
	State State
	// Deprecated reports that the version has been deprecated. It is kept in sync
	// with the deprecated state and never grants anything; a version carrying the
	// flag is refused for new use even if a stale copy of State claims published.
	Deprecated bool
	// EvidenceID references the qualification evidence. Qualify refuses without
	// one, because evidence is what separates a qualification from a claim.
	EvidenceID string
}

// Template is one named template and the versions registered under it.
type Template struct {
	// Name identifies the template.
	Name string
	// Versions are the versions registered under it. Version numbers are unique
	// within one template.
	Versions []Version
}

// Registry is the versioned catalog: every template and every version the platform
// knows about.
type Registry struct {
	// Templates are the known templates.
	Templates []Template
}

// Transition reports whether the lifecycle allows moving from one state to another.
//
// The legal moves are the ones an artifact actually makes: a draft qualifies, a
// qualified version publishes, a published version deprecates, and a version can be
// withdrawn from qualified or published onward. Everything else is refused, including
// self-transitions and unknown states, because "already there" is not a move and
// accepting it would hide a caller that lost track of state.
//
// The move that matters most is the one that is missing: there is no path back to
// draft. A published version has been used, and un-publishing it would let the
// template change under environments already built from it. For the same reason a
// deprecated version cannot become published again; deprecation would be a suggestion
// instead of a decision.
func Transition(from, to State) error {
	switch {
	case from == StateDraft && to == StateQualified,
		from == StateQualified && to == StatePublished,
		from == StatePublished && to == StateDeprecated,
		from == StateDeprecated && to == StateWithdrawn,
		from == StateQualified && to == StateWithdrawn,
		from == StatePublished && to == StateWithdrawn:
		return nil
	}
	return fmt.Errorf("%w: %s -> %s", ErrIllegalTransition, from, to)
}

// Qualify records the digest a version qualified at, and moves a draft version to
// qualified.
//
// Qualification is a statement about one specific artifact, so two things are
// enforced. Evidence is required: without an EvidenceID the "qualification" is a
// claim, and a claim must not unlock publication. And the digest is immutable: the
// same digest twice is the idempotent retry of one qualification, while a different
// digest is a different artifact wearing the same version number, refused rather
// than recorded.
//
// A version already past qualification is not moved backwards. The digest is compared
// and, if it matches, the call is a no-op; if it differs, the refusal stands. That is
// what keeps every past qualification meaningful.
func Qualify(v Version, digest string) (Version, error) {
	if v.EvidenceID == "" {
		return v, fmt.Errorf("%w: %s v%d", ErrNoQualificationEvidence, v.Template, v.Version)
	}
	if v.Digest != "" && v.Digest != digest {
		return v, fmt.Errorf("%w: %s v%d is %q, qualification offered %q",
			ErrDigestChanged, v.Template, v.Version, v.Digest, digest)
	}
	if v.Digest == digest {
		// Same digest, or both empty: an idempotent retry, not a change.
		return v, nil
	}
	v.Digest = digest
	if v.State == StateDraft {
		if err := Transition(v.State, StateQualified); err != nil {
			return v, err
		}
		v.State = StateQualified
	}
	return v, nil
}

// Publish moves a qualified version to published, the first state selectable for a
// new environment.
//
// A version with no pinned cleanup runtime is refused. Publishing is what creates
// environments, and every environment must remain tearable; the cleanup runtime is
// pinned on the version because by the time teardown runs there is no reliable way to
// ask a retired version which runtime it needs.
func Publish(v Version) (Version, error) {
	if err := Transition(v.State, StatePublished); err != nil {
		return v, err
	}
	if v.CleanupRuntime == "" {
		return v, fmt.Errorf("%w: %s v%d", ErrUnpinnedCleanup, v.Template, v.Version)
	}
	v.State = StatePublished
	return v, nil
}

// Deprecate moves a published version to deprecated.
//
// Deprecation forbids new use but not teardown: the version stops being selectable,
// and its pinned cleanup runtime is deliberately left untouched, because the
// environments already built from it still exist and still have to be torn down.
func Deprecate(v Version) (Version, error) {
	if err := Transition(v.State, StateDeprecated); err != nil {
		return v, err
	}
	v.State = StateDeprecated
	v.Deprecated = true
	return v, nil
}

// Withdraw moves a qualified, published, or deprecated version to withdrawn.
//
// Withdrawal is the end of the line: the version will never be selectable again. It
// is still not the end of teardown. The pinned cleanup runtime survives, because
// withdrawing a version must not orphan the environments built from it.
func Withdraw(v Version) (Version, error) {
	if err := Transition(v.State, StateWithdrawn); err != nil {
		return v, err
	}
	v.State = StateWithdrawn
	return v, nil
}

// Selectable reports whether a version may be used for a NEW environment.
//
// Only published versions are selectable. Draft and qualified versions have not been
// released; deprecated and withdrawn ones have been taken out of service. The
// Deprecated flag is checked as well so that a version which was deprecated cannot be
// selected merely because a stale copy of its State still says published.
func Selectable(v Version) bool {
	return v.State == StatePublished && !v.Deprecated
}

// Register adds a version to the registry, creating its template if this is the
// first version.
//
// Version numbers are unique per template. Two versions sharing a number would make
// "v3" ambiguous and every environment pinned to it uncertain, so the second
// registration is refused rather than replacing the first.
//
// The returned Registry shares no mutable state with the input, so neither a refused
// nor a successful registration edits the registry a caller is still holding.
func Register(reg Registry, v Version) (Registry, error) {
	templates := make([]Template, len(reg.Templates))
	copy(templates, reg.Templates)
	for i := range templates {
		if templates[i].Name != v.Template {
			continue
		}
		versions := make([]Version, len(templates[i].Versions), len(templates[i].Versions)+1)
		copy(versions, templates[i].Versions)
		for _, existing := range versions {
			if existing.Version == v.Version {
				return reg, fmt.Errorf("%w: %s v%d", ErrDuplicateVersion, v.Template, v.Version)
			}
		}
		templates[i].Versions = append(versions, v)
		return Registry{Templates: templates}, nil
	}
	return Registry{Templates: append(templates, Template{Name: v.Template, Versions: []Version{v}})}, nil
}

// Update replaces an existing version with a newer copy, so lifecycle progress is
// recorded in the registry rather than only in a caller's variable.
//
// It refuses unknown templates and unknown versions with the same sentinels as
// lookup, because replacing something that does not exist would quietly turn a typo
// into a new version.
func Update(reg Registry, v Version) (Registry, error) {
	templates := make([]Template, len(reg.Templates))
	copy(templates, reg.Templates)
	for i := range templates {
		if templates[i].Name != v.Template {
			continue
		}
		for j, existing := range templates[i].Versions {
			if existing.Version != v.Version {
				continue
			}
			versions := make([]Version, len(templates[i].Versions))
			copy(versions, templates[i].Versions)
			versions[j] = v
			templates[i].Versions = versions
			return Registry{Templates: templates}, nil
		}
		return reg, fmt.Errorf("%w: %s v%d", ErrUnknownVersion, v.Template, v.Version)
	}
	return reg, fmt.Errorf("%w: %s", ErrUnknownTemplate, v.Template)
}

// lookup finds one version without judging its state. The selectability judgement
// belongs to Resolve, and teardown must not make it at all.
func lookup(reg Registry, name string, version int) (Version, error) {
	for _, t := range reg.Templates {
		if t.Name != name {
			continue
		}
		for _, v := range t.Versions {
			if v.Version == version {
				return v, nil
			}
		}
		return Version{}, fmt.Errorf("%w: %s v%d", ErrUnknownVersion, name, version)
	}
	return Version{}, fmt.Errorf("%w: %s", ErrUnknownTemplate, name)
}

// Resolve returns the version a new deployment may use.
//
// It refuses an unknown template, an unknown version, and a version that exists but
// is not selectable. That last refusal is the deprecation boundary: a deprecated
// version is still resolvable for teardown through CleanupRuntimeFor, but it can
// never start anything new.
func Resolve(reg Registry, name string, version int) (Version, error) {
	v, err := lookup(reg, name, version)
	if err != nil {
		return Version{}, err
	}
	if !Selectable(v) {
		return Version{}, fmt.Errorf("%w: %s v%d is %s", ErrNotSelectable, name, version, v.State)
	}
	return v, nil
}

// CleanupRuntimeFor returns the pinned cleanup runtime for a version in ANY state,
// including deprecated and withdrawn.
//
// Teardown must outlive deprecation. Environments built from a version keep existing
// after the version stops being selectable, so this lookup deliberately skips the
// selectability check Resolve makes. Withdrawing a version must not orphan the
// environments created from it.
func CleanupRuntimeFor(reg Registry, name string, version int) (string, error) {
	v, err := lookup(reg, name, version)
	if err != nil {
		return "", err
	}
	if v.CleanupRuntime == "" {
		return "", fmt.Errorf("%w: %s v%d", ErrUnpinnedCleanup, name, version)
	}
	return v.CleanupRuntime, nil
}
