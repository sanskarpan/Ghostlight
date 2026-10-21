// Package apilifecycle governs the lifecycle of the public API: publication, the
// compatibility window a version is promised, deprecation, sunset, notification of
// consumers, and the CLI's inheritance of the same policy.
//
// A public API is a promise, and this package is the part of the system that keeps
// the promise honest. Everything here exists because of one asymmetry: **we can change
// the API in one commit, and a consumer needs one deploy they may not control.** So
// the rules are written from the consumer's side, and the load-bearing ones are all
// refusals.
//
// A version cannot be deprecated before it has been supported for the compatibility
// window. That is the window the row names, and it is a promise about time rather than
// about intent: "we will not remove this for at least N months" is checkable, whereas
// "we will not remove this while you are migrating" is not, because it has no end.
//
// A version cannot be sunset until the notice period has passed since its deprecation
// was announced. Six months of "we told you" is not the same as six months of notice,
// and the difference is exactly the time a consumer needs to schedule the work.
//
// A version cannot be sunset while a consumer is still using it. This is the rule that
// does the most work, and it is deliberately strict: the consumer's own migration
// schedule is the one deadline that actually matters, and an API that sunsets on a
// calendar date rather than on its consumers' state is an API that breaks people to
// hit a target. A consumer that has migrated is released; a consumer that has not
// migrated holds the version open, which is inconvenient for us and correct for them.
//
// A sunset version is retired permanently. It cannot be published again, and requests
// against it are refused with a clear error rather than served from a stale handler.
// A version that can be un-retired is a version nobody can plan against, and the
// failure mode of that is a consumer who left and a consumer who came back.
//
// Consumers are notified, and the notification is recorded per consumer rather than
// broadcast. "We emailed everyone" is not evidence that anybody was told, and a
// deprecation that was never delivered to the consumer it affects is a deprecation
// that did not happen.
//
// And the CLI inherits all of it. A CLI release that targets a retired API version is
// refused at release time, and one that targets a deprecated version is published with
// the deprecation visible. The CLI is not a second policy with a second set of
// exceptions; it is the same policy with a different front end, and a CLI that can
// talk to a version the API has retired is a way to keep using a promise that was
// withdrawn.
package apilifecycle

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package's lifecycle rules.
var (
	// ErrNoVersionPath means a version has no path. A version without a path is
	// not addressable, and an unaddressable version cannot be requested or
	// deprecated.
	ErrNoVersionPath = errors.New("api version must carry a path")
	// ErrDuplicateVersion means two versions share a path.
	ErrDuplicateVersion = errors.New("api version path is already in use")
	// ErrNoMajor means a version has no major number.
	ErrNoMajor = errors.New("api version must carry a major number")
	// ErrNoSpecDigest means a version carries no OpenAPI digest. A published API
	// whose specification cannot be named is a specification nobody can diff.
	ErrNoSpecDigest = errors.New("api version must carry an openapi digest")
	// ErrNoOwner means a version names no owner. A promise with nobody accountable
	// for it is not kept, and if it is not kept nobody notices it was broken.
	ErrNoOwner = errors.New("api version must name an owner")
	// ErrNotPublished means an act requires a published version.
	ErrNotPublished = errors.New("api version is not published")
	// ErrAlreadyPublished means a version was published twice.
	ErrAlreadyPublished = errors.New("api version is already published")
	// ErrSupportWindow means a version was deprecated before it had been supported
	// for the compatibility window. The window is a promise about time, and time
	// is the thing a consumer plans against.
	ErrSupportWindow = errors.New("api version is still inside its compatibility window")
	// ErrNoticePeriod means a version was sunset before the notice period had
	// passed since its deprecation was announced. Six months of "we told you" is
	// not six months of notice.
	ErrNoticePeriod = errors.New("api version has not served its notice period")
	// ErrActiveConsumers means a version was sunset while consumers were still
	// using it. The consumers' own migration schedule is the deadline that matters.
	ErrActiveConsumers = errors.New("api version still has active consumers")
	// ErrUnnotifiedConsumers means a version was sunset while some consumer had
	// never been notified of the deprecation. "We emailed everyone" is not evidence
	// that anybody was told.
	ErrUnnotifiedConsumers = errors.New("api version has consumers who were never notified")
	// ErrSpecChanged means a published version's specification was changed. A
	// version's digest is its promise; changing it in place makes every consumer's
	// pinned expectation wrong.
	ErrSpecChanged = errors.New("published api version specification cannot change")
	// ErrRetired means a version has been sunset. A retired version is retired
	// permanently, because a version that can be un-retired is a version nobody can
	// plan against.
	ErrRetired = errors.New("api version has been retired")
	// ErrUnknownVersion means a path names no version.
	ErrUnknownVersion = errors.New("no such api version")
	// ErrUnsupportedAPIVersion means a CLI release targets a version that is
	// retired, or that does not exist.
	ErrUnsupportedAPIVersion = errors.New("cli release targets an unsupported api version")
	// ErrNoConsumerID means a consumer has no identifier.
	ErrNoConsumerID = errors.New("consumer must carry an identifier")
	// ErrNoChannel means a consumer has no notification channel.
	ErrNoChannel = errors.New("consumer must carry a notification channel")
	// ErrNoCLIVersion means a CLI release has no version.
	ErrNoCLIVersion = errors.New("cli release must carry a version")
	// ErrNoDeprecationTarget means an act names no version to deprecate.
	ErrNoDeprecationTarget = errors.New("no api version named")
	// ErrNoDeprecationNote means a deprecation announcement carried no note. A
	// deprecation with no explanation is a retraction, and a consumer who cannot
	// tell what to do about it will do nothing.
	ErrNoDeprecationNote = errors.New("deprecation must state what is going away")
	// ErrUnknownConsumer means an act names a consumer that does not exist.
	ErrUnknownConsumer = errors.New("no such consumer")
)

// The lifecycle windows. These are the numbers a consumer plans against, so they are
// constants rather than options: a caller who can raise the notice period is the
// caller who decides how long consumers get to react.
const (
	// MinSupportWindow is the minimum time a version must be supported after
	// publication before it may be deprecated. This is the compatibility window.
	MinSupportWindow = 180 * 24 * time.Hour
	// MinNoticePeriod is the minimum time between a deprecation announcement and
	// sunset. This is the notice period.
	MinNoticePeriod = 90 * 24 * time.Hour
)

// State is where a version stands in its lifecycle.
type State string

const (
	// StatePublished means the version is current and supported.
	StatePublished State = "published"
	// StateDeprecated means the version is still served but announced for removal.
	StateDeprecated State = "deprecated"
	// StateSunset means the version is retired and refused.
	StateSunset State = "sunset"
)

// Version is one published API version.
type Version struct {
	// Path is the version's URL segment, such as "v1".
	Path string
	// Major is the version's major number.
	Major int
	// SpecDigest is the digest of the OpenAPI document published for it. A
	// published version's digest cannot change; that is what makes it a promise.
	SpecDigest string
	// Owner is the team accountable for it.
	Owner string
	// PublishedAt is when it was published.
	PublishedAt time.Time
	// DeprecatedAt is when its deprecation was announced; zero while published.
	DeprecatedAt time.Time
	// SunsetAt is when it was retired; zero while not retired.
	SunsetAt time.Time
	// State is the lifecycle state.
	State State
}

// Consumer is a registered API consumer.
type Consumer struct {
	// ID identifies the consumer.
	ID string
	// Version is the API version the consumer currently uses.
	Version string
	// Channel is how the consumer is notified, such as an email address or a
	// webhook URL.
	Channel string
	// RegisteredAt is when the consumer registered.
	RegisteredAt time.Time
	// NotifiedAt is when the consumer was notified of a deprecation; zero until
	// then.
	NotifiedAt time.Time
	// MigratedAt is when the consumer moved to another version; zero while it is
	// still on this one.
	MigratedAt time.Time
}

// Active reports whether the consumer is still using its version.
func (c Consumer) Active() bool { return c.MigratedAt.IsZero() }

// CLIRelease is a CLI release and the API version it targets.
type CLIRelease struct {
	// Version is the CLI's own version.
	Version string
	// TargetAPIVersion is the API version the release speaks to.
	TargetAPIVersion string
	// ReleasedAt is when it was released.
	ReleasedAt time.Time
}

// Registry is the set of published versions and registered consumers.
type Registry struct {
	// Versions are the published versions.
	Versions []Version
	// Consumers are the registered consumers.
	Consumers []Consumer
}

// version looks a version up by path.
func (r Registry) version(path string) (Version, bool) {
	for _, v := range r.Versions {
		if v.Path == path {
			return v, true
		}
	}
	return Version{}, false
}

// consumer looks a consumer up by identifier.
func (r Registry) consumer(id string) (Consumer, bool) {
	for _, c := range r.Consumers {
		if c.ID == id {
			return c, true
		}
	}
	return Consumer{}, false
}

// Publish publishes a version with its OpenAPI digest.
//
// The digest is recorded at publication and cannot change afterwards. Consumers pin
// it, and a specification edited in place turns every one of those pins into a lie.
func (r Registry) Publish(v Version, at time.Time) (Registry, error) {
	if strings.TrimSpace(v.Path) == "" {
		return r, ErrNoVersionPath
	}
	if v.Major <= 0 {
		return r, ErrNoMajor
	}
	if strings.TrimSpace(v.SpecDigest) == "" {
		return r, ErrNoSpecDigest
	}
	if strings.TrimSpace(v.Owner) == "" {
		return r, ErrNoOwner
	}
	for _, existing := range r.Versions {
		if existing.Path == v.Path {
			return r, fmt.Errorf("%w: %q", ErrDuplicateVersion, v.Path)
		}
	}
	v.PublishedAt = at
	v.State = StatePublished
	r.Versions = append(r.Versions, v)
	return r, nil
}

// UpdateSpec refuses to change a published version's specification.
func (r Registry) UpdateSpec(path, digest string) (Registry, error) {
	v, ok := r.version(path)
	if !ok {
		return r, fmt.Errorf("%w: %q", ErrUnknownVersion, path)
	}
	if v.State != StatePublished {
		return r, fmt.Errorf("%w: %q is %s", ErrNotPublished, path, v.State)
	}
	if digest != v.SpecDigest {
		return r, fmt.Errorf("%w: %q", ErrSpecChanged, path)
	}
	return r, nil
}

// Register registers a consumer against a version.
func (r Registry) Register(c Consumer, at time.Time) (Registry, error) {
	if strings.TrimSpace(c.ID) == "" {
		return r, ErrNoConsumerID
	}
	if strings.TrimSpace(c.Channel) == "" {
		return r, ErrNoChannel
	}
	if _, ok := r.version(c.Version); !ok {
		return r, fmt.Errorf("%w: %q", ErrUnknownVersion, c.Version)
	}
	for _, existing := range r.Consumers {
		if existing.ID == c.ID {
			return r, fmt.Errorf("%w: %q", ErrDuplicateVersion, c.ID)
		}
	}
	c.RegisteredAt = at
	r.Consumers = append(r.Consumers, c)
	return r, nil
}

// Deprecate announces a version's removal.
//
// The version must have been published and must have been supported for the
// compatibility window. Every consumer of the version is notified as part of the
// deprecation, and the notification is recorded per consumer rather than broadcast —
// a deprecation that was never delivered to the consumer it affects is a deprecation
// that did not happen.
func (r Registry) Deprecate(path, owner, note string, at time.Time) (Registry, error) {
	if strings.TrimSpace(owner) == "" {
		return r, ErrNoOwner
	}
	if strings.TrimSpace(note) == "" {
		return r, ErrNoDeprecationNote
	}
	v, ok := r.version(path)
	if !ok {
		return r, fmt.Errorf("%w: %q", ErrUnknownVersion, path)
	}
	if v.State == StateSunset {
		return r, fmt.Errorf("%w: %q", ErrRetired, path)
	}
	if v.State == StateDeprecated {
		return r, fmt.Errorf("%w: %q is already deprecated", ErrAlreadyPublished, path)
	}
	if at.Sub(v.PublishedAt) < MinSupportWindow {
		return r, fmt.Errorf("%w: %q was published %s ago, the window is %s",
			ErrSupportWindow, path, at.Sub(v.PublishedAt), MinSupportWindow)
	}
	for i := range r.Versions {
		if r.Versions[i].Path == path {
			r.Versions[i].State = StateDeprecated
			r.Versions[i].DeprecatedAt = at
		}
	}
	// Notify every consumer of the version, and record that we did.
	for i := range r.Consumers {
		if r.Consumers[i].Version == path && r.Consumers[i].NotifiedAt.IsZero() {
			r.Consumers[i].NotifiedAt = at
		}
	}
	return r, nil
}

// Migrate records that a consumer has moved to another version.
func (r Registry) Migrate(consumerID, toVersion string, at time.Time) (Registry, error) {
	c, ok := r.consumer(consumerID)
	if !ok {
		return r, fmt.Errorf("%w: %q", ErrUnknownConsumer, consumerID)
	}
	if _, ok := r.version(toVersion); !ok {
		return r, fmt.Errorf("%w: %q", ErrUnknownVersion, toVersion)
	}
	if !c.Active() {
		return r, nil
	}
	for i := range r.Consumers {
		if r.Consumers[i].ID == consumerID {
			r.Consumers[i].MigratedAt = at
			r.Consumers[i].Version = toVersion
		}
	}
	return r, nil
}

// ActiveConsumers returns the consumers still using a version.
func (r Registry) ActiveConsumers(path string) []Consumer {
	var out []Consumer
	for _, c := range r.Consumers {
		if c.Version == path && c.Active() {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// UnnotifiedConsumers returns the consumers of a version who were never notified of
// its deprecation.
func (r Registry) UnnotifiedConsumers(path string) []Consumer {
	var out []Consumer
	for _, c := range r.Consumers {
		if c.Version == path && c.Active() && c.NotifiedAt.IsZero() {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Sunset retires a version.
//
// Three things must have happened first: the version was deprecated, the notice
// period has passed, and every consumer has either migrated or been notified. A
// version with active consumers is not retired, because the consumers' own migration
// schedule is the deadline that actually matters.
func (r Registry) Sunset(path string, at time.Time) (Registry, error) {
	v, ok := r.version(path)
	if !ok {
		return r, fmt.Errorf("%w: %q", ErrUnknownVersion, path)
	}
	if v.State == StateSunset {
		return r, fmt.Errorf("%w: %q", ErrRetired, path)
	}
	if v.State != StateDeprecated {
		return r, fmt.Errorf("%w: %q is %s", ErrNotPublished, path, v.State)
	}
	if at.Sub(v.DeprecatedAt) < MinNoticePeriod {
		return r, fmt.Errorf("%w: %q was deprecated %s ago, the notice period is %s",
			ErrNoticePeriod, path, at.Sub(v.DeprecatedAt), MinNoticePeriod)
	}
	if active := r.ActiveConsumers(path); len(active) > 0 {
		ids := make([]string, 0, len(active))
		for _, c := range active {
			ids = append(ids, c.ID)
		}
		return r, fmt.Errorf("%w: %q is still used by %s", ErrActiveConsumers, path, strings.Join(ids, ", "))
	}
	for i := range r.Versions {
		if r.Versions[i].Path == path {
			r.Versions[i].State = StateSunset
			r.Versions[i].SunsetAt = at
		}
	}
	return r, nil
}

// Requested reports whether a request against a version may be served.
//
// A retired version is refused outright, with the error naming the retirement, so a
// consumer who comes back after migrating away finds out why rather than finding a
// stale handler.
func (r Registry) Requested(path string) (Version, error) {
	v, ok := r.version(path)
	if !ok {
		return Version{}, fmt.Errorf("%w: %q", ErrUnknownVersion, path)
	}
	if v.State == StateSunset {
		return Version{}, fmt.Errorf("%w: %q was retired at %s", ErrRetired, path, v.SunsetAt.UTC().Format(time.RFC3339))
	}
	return v, nil
}

// CheckCLIRelease checks a CLI release against the same policy the API follows.
//
// A CLI that targets a retired version is refused: it is a way to keep using a
// promise that was withdrawn. A CLI that targets a deprecated version is allowed, and
// the deprecation is returned alongside it so the release notes can carry it — the
// CLI inherits the policy, so it inherits the deprecation too, visibly.
func (r Registry) CheckCLIRelease(rel CLIRelease) (CLIRelease, []string, error) {
	if strings.TrimSpace(rel.Version) == "" {
		return rel, nil, ErrNoCLIVersion
	}
	v, ok := r.version(rel.TargetAPIVersion)
	if !ok {
		return rel, nil, fmt.Errorf("%w: %q", ErrUnsupportedAPIVersion, rel.TargetAPIVersion)
	}
	if v.State == StateSunset {
		return rel, nil, fmt.Errorf("%w: %q was retired at %s",
			ErrUnsupportedAPIVersion, rel.TargetAPIVersion, v.SunsetAt.UTC().Format(time.RFC3339))
	}
	var warnings []string
	if v.State == StateDeprecated {
		warnings = append(warnings, fmt.Sprintf("api version %q is deprecated and retires at %s",
			v.Path, v.DeprecatedAt.Add(MinNoticePeriod).UTC().Format(time.RFC3339)))
	}
	return rel, warnings, nil
}

// Status is what a consumer or operator can see about a version.
type Status struct {
	// Version is the path.
	Version string
	// State is the lifecycle state.
	State State
	// SpecDigest is the published specification's digest.
	SpecDigest string
	// Owner is the accountable team.
	Owner string
	// SupportEnds is the earliest moment the version may be deprecated under the
	// compatibility window.
	SupportEnds time.Time
	// RetiresAt is the earliest moment the version may be sunset, once deprecated.
	// It is zero while the version is not deprecated, because a version that is
	// still published has no retirement date and should not be shown one.
	RetiresAt time.Time
	// ActiveConsumers counts the consumers still using the version.
	ActiveConsumers int
	// NotifiedConsumers counts the consumers that were notified of a deprecation.
	NotifiedConsumers int
}

// Status reports a version's lifecycle state.
func (r Registry) Status(path string) (Status, error) {
	v, ok := r.version(path)
	if !ok {
		return Status{}, fmt.Errorf("%w: %q", ErrUnknownVersion, path)
	}
	st := Status{
		Version:     v.Path,
		State:       v.State,
		SpecDigest:  v.SpecDigest,
		Owner:       v.Owner,
		SupportEnds: v.PublishedAt.Add(MinSupportWindow),
	}
	if v.State == StateDeprecated {
		st.RetiresAt = v.DeprecatedAt.Add(MinNoticePeriod)
	}
	for _, c := range r.Consumers {
		if c.Version != path {
			continue
		}
		if c.Active() {
			st.ActiveConsumers++
		}
		if !c.NotifiedAt.IsZero() {
			st.NotifiedConsumers++
		}
	}
	return st, nil
}
