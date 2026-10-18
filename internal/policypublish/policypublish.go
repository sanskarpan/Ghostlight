// Package policypublish publishes versioned policy test suites, and governs the
// exceptions that let a suite go out with a known failure.
//
// The normal path is unglamorous: every test in the suite passes, so the version is
// published and the fleet gets a stricter policy. The interesting path is the one this
// package exists for — someone needs to ship with a test that does not pass, and that
// is a legitimate thing to do during an incident, a compatibility window or a staged
// rollout. What is not legitimate is doing it quietly, or doing it forever.
//
// So an exception has four properties, all enforced here.
//
// It must expire. `ExpiresAt` is mandatory and must be after `GrantedAt`. A permanent
// exception is not an exception, it is a deleted test, and the person who can grant it
// should not be able to make it permanent without that being visible as a decision.
//
// It must be visible. Every exception ever granted stays attached to the publication
// forever, and `Status` lists all of them — including the expired ones, marked as such.
// A publication cannot be obtained without its exceptions attached, so there is no way
// to read the policy as clean while the exception quietly sits elsewhere.
//
// It must be granted by someone other than the approver of the publication. Nobody may
// grant themselves the waiver for the policy they are releasing. This is the only
// two-party rule in the package and it exists because the single-person version of this
// check is a rubber stamp wearing a checkbox.
//
// And it does not carry forward. An exception binds to exactly one version number.
// Publishing version 2 with version 1's exception in hand is refused, because a waiver
// is a judgement about one specific set of tests at one specific moment; inheriting it
// means the next release silently ships a failure nobody re-examined.
//
// An expired exception does not suppress anything. At publication time an expired
// exception is simply not counted, so the failing test keeps the version unpublished.
package policypublish

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package's publication rules.
var (
	// ErrNoApprover means the publication named no approver. Publishing a policy is
	// a decision with consequences for every fleet behind it.
	ErrNoApprover = errors.New("policy publication must name an approver")
	// ErrEmptySuite means the version has no tests. An empty suite passes trivially
	// and would publish as though it were qualified.
	ErrEmptySuite = errors.New("policy version has no tests")
	// ErrSuiteTooLarge means the version exceeds MaxTests. Bounds are constants for
	// the same reason the destructive set is data: a caller who can raise the bound
	// can raise it past the point where a suite is still reviewable.
	ErrSuiteTooLarge = errors.New("policy suite exceeds the test bound")
	// ErrSuiteTooLong means the declared duration exceeds MaxSuiteDuration. A suite
	// that can never finish is refused rather than published as best-effort.
	ErrSuiteTooLong = errors.New("policy suite exceeds the duration bound")
	// ErrNoTestID means a test carries no identifier. Results key on the identifier,
	// so an unnamed test cannot hold a result.
	ErrNoTestID = errors.New("policy test must carry an identifier")
	// ErrDuplicateTest means two tests share an identifier, which makes every result
	// for that identifier ambiguous.
	ErrDuplicateTest = errors.New("policy suite has duplicate test identifiers")
	// ErrUnknownTest means a result or an exception names a test the version does not
	// contain. Refused rather than ignored: an exception for a test that does not
	// exist is either a typo or a waiver of nothing.
	ErrUnknownTest = errors.New("policy suite has no such test")
	// ErrMissingResult means a version was published without a result for one of its
	// tests. Untested is not passing, however convenient treating it as such would be.
	ErrMissingResult = errors.New("policy test has no result")
	// ErrDuplicateResult means two results share a test identifier.
	ErrDuplicateResult = errors.New("policy test already has a result")
	// ErrTestsFailed means at least one test failed and nothing covered it.
	ErrTestsFailed = errors.New("policy tests failed with no exception in force")
	// ErrNoExceptionID means an exception carries no identifier.
	ErrNoExceptionID = errors.New("policy exception must carry an identifier")
	// ErrNoExceptionReason means an exception states no reason. Six weeks later, an
	// unexplained exception is indistinguishable from a mistake.
	ErrNoExceptionReason = errors.New("policy exception must state a reason")
	// ErrNoExceptionExpiry means an exception has no expiry, which would make it a
	// deleted test rather than an exception.
	ErrNoExceptionExpiry = errors.New("policy exception must expire")
	// ErrBadExceptionWindow means an exception expires before it was granted.
	ErrBadExceptionWindow = errors.New("policy exception expires before it was granted")
	// ErrExceptionExpired means an exception was granted already lapsed.
	ErrExceptionExpired = errors.New("policy exception has already expired")
	// ErrDuplicateException means two exceptions share an identifier.
	ErrDuplicateException = errors.New("policy exception identifier is already in use")
	// ErrExceptionWrongVersion means an exception is offered to a version it was not
	// granted against. Waivers do not inherit.
	ErrExceptionWrongVersion = errors.New("policy exception belongs to another version")
	// ErrSelfException means the approver of a publication is also the grantor of an
	// exception it relies on. Nobody waives the policy they are releasing.
	ErrSelfException = errors.New("policy exception must be granted by another approver")
	// ErrDigestMismatch means a publication's stored version does not digest to its
	// recorded digest, so the tests were altered after the fact.
	ErrDigestMismatch = errors.New("published policy version digest does not match")
	// ErrNotNewer means a superseding publication is not a higher version number.
	ErrNotNewer = errors.New("policy version is not newer than the published one")
	// ErrNoVersionNumber means a version carries no positive version number.
	ErrNoVersionNumber = errors.New("policy version must have a positive version number")
)

// Bounds on a policy suite and on an exception.
const (
	// MaxTests is the largest number of tests a version may contain.
	MaxTests = 500
	// MaxSuiteDuration is the longest a suite's declared duration may be.
	MaxSuiteDuration = 30 * time.Minute
	// MaxExceptionTTL is the longest an exception may remain in force.
	MaxExceptionTTL = 90 * 24 * time.Hour
)

// Test is one check within a policy suite.
type Test struct {
	// ID identifies the test and keys its result.
	ID string
	// Kind names the class of check, for the human reading the record.
	Kind string
	// Target names what the check acts on.
	Target string
}

// Suite is a proposed version of a policy: the tests, and how long they are declared to
// take.
type Suite struct {
	// ID identifies the policy the version belongs to.
	ID string
	// Number is the version number. It is positive and increases; exceptions bind to
	// it and do not follow it forward.
	Number int
	// Tests are the checks in the suite, in any order.
	Tests []Test
	// DeclaredDuration is how long the suite is expected to take.
	DeclaredDuration time.Duration
}

// Result is one test outcome supplied by the runner.
type Result struct {
	TestID string
	Passed bool
	Detail string
}

// Exception is a granted, expiring waiver for a single failing test in a single version.
type Exception struct {
	// ID identifies the exception within the publication.
	ID string
	// TestID is the failing test being waived.
	TestID string
	// Reason states why the failure is acceptable for now.
	Reason string
	// GrantedBy names the person granting the waiver. It may not equal the
	// publication's approver.
	GrantedBy string
	// GrantedAt is when it was granted.
	GrantedAt time.Time
	// ExpiresAt is when it lapses. Mandatory.
	ExpiresAt time.Time
}

// Version is an immutable, digested policy suite.
type Version struct {
	Suite
	// Digest binds the tests and the declared duration, so a publication can prove
	// after the fact that the tests it was granted against are the tests it shipped.
	Digest string
}

// Publication is the record of a version going out, with every exception attached.
type Publication struct {
	Version Version
	// ApprovedBy names the approver of the release.
	ApprovedBy  string
	ApprovedAt  time.Time
	PublishedAt time.Time
	// Exceptions holds every exception ever granted against this version, expired or
	// not. They are never removed: a publication that could be read without them is
	// a publication that can be read as clean.
	Exceptions []Exception
}

// ExceptionView is one exception as reported by Status.
type ExceptionView struct {
	Exception
	// Expired reports whether the exception was still in force at the queried time.
	Expired bool
	// Suppressing reports whether the exception was still covering its test when the
	// version was published, which is what makes it load-bearing.
	Suppressing bool
}

// Status is what an operator sees about a live policy.
type Status struct {
	Version    Version
	Exceptions []ExceptionView
	// Clean reports whether the version has no exceptions attached at all. A policy
	// with only expired exceptions is still not clean, because its history is part of
	// the record.
	Clean bool
}

// validate enforces the structural bounds on a proposed suite. It is called by
// NewVersion and again by Publish, because Publish re-checks rather than trusting that
// the version it was handed came from NewVersion — a Version value may have been
// assembled anywhere, and a suite that was never validated is not one step away from a
// policy.
func validate(s Suite) error {
	if s.Number <= 0 {
		return fmt.Errorf("%w: got %d", ErrNoVersionNumber, s.Number)
	}
	if strings.TrimSpace(s.ID) == "" {
		return fmt.Errorf("%w: suite %q", ErrUnknownTest, s.ID)
	}
	if len(s.Tests) == 0 {
		return ErrEmptySuite
	}
	if len(s.Tests) > MaxTests {
		return fmt.Errorf("%w: %d tests exceeds the maximum of %d", ErrSuiteTooLarge, len(s.Tests), MaxTests)
	}
	if s.DeclaredDuration > MaxSuiteDuration {
		return fmt.Errorf("%w: %s exceeds the maximum of %s", ErrSuiteTooLong, s.DeclaredDuration, MaxSuiteDuration)
	}
	seen := make(map[string]bool, len(s.Tests))
	for _, t := range s.Tests {
		if strings.TrimSpace(t.ID) == "" {
			return ErrNoTestID
		}
		if seen[t.ID] {
			return fmt.Errorf("%w: %q", ErrDuplicateTest, t.ID)
		}
		seen[t.ID] = true
	}
	return nil
}

// NewVersion validates a proposed suite and returns it digested.
func NewVersion(s Suite) (Version, error) {
	if err := validate(s); err != nil {
		return Version{}, err
	}
	v := Version{Suite: s}
	v.Digest = Digest(v)
	return v, nil
}

// Digest computes the identity of a version over its number, its tests and its declared
// duration. Tests are sorted first, so two suites differing only in declaration order
// are the same policy and not a lottery decided by slice order.
func Digest(v Version) string {
	tests := make([]Test, len(v.Tests))
	copy(tests, v.Tests)
	sort.Slice(tests, func(i, j int) bool { return tests[i].ID < tests[j].ID })
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%s\n", v.ID, v.Number, v.DeclaredDuration)
	for _, t := range tests {
		fmt.Fprintf(h, "%s|%s|%s\n", t.ID, t.Kind, t.Target)
	}
	return "policy-" + hex.EncodeToString(h.Sum(nil))[:32]
}

// Evaluate checks a set of results against a version and returns the failing test
// identifiers in deterministic order.
//
// Results must cover every test exactly once. A missing result is not a passing test —
// that conflation is how a policy silently stops covering the thing it was written for.
func Evaluate(v Version, results []Result) ([]string, error) {
	known := make(map[string]bool, len(v.Tests))
	for _, t := range v.Tests {
		known[t.ID] = true
	}
	seen := make(map[string]bool, len(results))
	var failed []string
	for _, r := range results {
		if !known[r.TestID] {
			return nil, fmt.Errorf("%w: %q", ErrUnknownTest, r.TestID)
		}
		if seen[r.TestID] {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateResult, r.TestID)
		}
		seen[r.TestID] = true
		if !r.Passed {
			failed = append(failed, r.TestID)
		}
	}
	for _, t := range v.Tests {
		if !seen[t.ID] {
			return nil, fmt.Errorf("%w: %q", ErrMissingResult, t.ID)
		}
	}
	sort.Strings(failed)
	return failed, nil
}

// GrantException validates an exception against the version it is granted for. The
// version number is stamped onto the exception so that offering it to another version is
// detectable rather than accidental.
func GrantException(v Version, ex Exception) (Exception, error) {
	if strings.TrimSpace(ex.ID) == "" {
		return ex, ErrNoExceptionID
	}
	if strings.TrimSpace(ex.Reason) == "" {
		return ex, ErrNoExceptionReason
	}
	if strings.TrimSpace(ex.GrantedBy) == "" {
		return ex, fmt.Errorf("%w: exception %q names no grantor", ErrNoApprover, ex.ID)
	}
	known := false
	for _, t := range v.Tests {
		if t.ID == ex.TestID {
			known = true
			break
		}
	}
	if !known {
		return ex, fmt.Errorf("%w: %q", ErrUnknownTest, ex.TestID)
	}
	if ex.ExpiresAt.IsZero() {
		return ex, fmt.Errorf("%w: exception %q", ErrNoExceptionExpiry, ex.ID)
	}
	if !ex.ExpiresAt.After(ex.GrantedAt) {
		return ex, fmt.Errorf("%w: exception %q expires at %s but was granted at %s",
			ErrBadExceptionWindow, ex.ID, ex.ExpiresAt.UTC().Format(time.RFC3339), ex.GrantedAt.UTC().Format(time.RFC3339))
	}
	if ex.ExpiresAt.Sub(ex.GrantedAt) > MaxExceptionTTL {
		return ex, fmt.Errorf("%w: exception %q would live for %s, over the maximum of %s",
			ErrNoExceptionExpiry, ex.ID, ex.ExpiresAt.Sub(ex.GrantedAt), MaxExceptionTTL)
	}
	return ex, nil
}

// Publish releases a version.
//
// Every failing test must be covered by an exception that was in force at the moment of
// publication. An expired exception does not count, so a failure that has outlived its
// waiver keeps the version unpublished — the waiver was always a promise to come back,
// and the return is enforced by the release path rather than by somebody's memory.
func Publish(v Version, results []Result, approver string, exceptions []Exception, at time.Time) (Publication, error) {
	if strings.TrimSpace(approver) == "" {
		return Publication{}, ErrNoApprover
	}
	// Publish re-validates the suite rather than trusting the caller: results are
	// granted against a digested version, and an unvalidated one has no digest worth
	// trusting.
	if err := validate(v.Suite); err != nil {
		return Publication{}, err
	}

	failed, err := Evaluate(v, results)
	if err != nil {
		return Publication{}, err
	}

	cover := make(map[string]bool, len(failed))
	lapsed := make(map[string]bool, len(failed))
	seenException := make(map[string]bool, len(exceptions))
	for _, ex := range exceptions {
		if strings.TrimSpace(ex.ID) == "" {
			return Publication{}, ErrNoExceptionID
		}
		if seenException[ex.ID] {
			return Publication{}, fmt.Errorf("%w: %q", ErrDuplicateException, ex.ID)
		}
		seenException[ex.ID] = true
		if strings.TrimSpace(ex.Reason) == "" {
			return Publication{}, ErrNoExceptionReason
		}
		if strings.TrimSpace(ex.GrantedBy) == "" {
			return Publication{}, fmt.Errorf("%w: exception %q names no grantor", ErrNoApprover, ex.ID)
		}
		if ex.GrantedBy == approver {
			return Publication{}, fmt.Errorf("%w: exception %q granted by the approving approver %q", ErrSelfException, ex.ID, approver)
		}
		known := false
		for _, t := range v.Tests {
			if t.ID == ex.TestID {
				known = true
				break
			}
		}
		if !known {
			return Publication{}, fmt.Errorf("%w: %q", ErrUnknownTest, ex.TestID)
		}
		if ex.ExpiresAt.IsZero() {
			return Publication{}, fmt.Errorf("%w: exception %q", ErrNoExceptionExpiry, ex.ID)
		}
		// Only an exception still in force covers a failure. A lapsed one is
		// remembered as the likely explanation for a refusal, because the honest
		// answer to "why will this not publish" is usually "because the waiver
		// lapsed", and not saying that sends people looking in the wrong place.
		if at.After(ex.ExpiresAt) || at.Equal(ex.ExpiresAt) {
			lapsed[ex.TestID] = true
			continue
		}
		cover[ex.TestID] = true
	}

	for _, id := range failed {
		if cover[id] {
			continue
		}
		if lapsed[id] {
			return Publication{}, fmt.Errorf("%w: the exception covering %q lapsed before publication", ErrExceptionExpired, id)
		}
		return Publication{}, fmt.Errorf("%w: %q", ErrTestsFailed, id)
	}

	stored := make([]Exception, len(exceptions))
	copy(stored, exceptions)
	sort.Slice(stored, func(i, j int) bool { return stored[i].ID < stored[j].ID })
	return Publication{
		Version:     v,
		ApprovedBy:  approver,
		ApprovedAt:  at,
		PublishedAt: at,
		Exceptions:  stored,
	}, nil
}

// Supersede publishes a higher-numbered version in place of a publication. The new
// publication starts with no exceptions at all: a waiver belongs to the version it was
// judged against, and carrying it forward would mean the next release shipped a failure
// that nobody re-examined.
func Supersede(prev Publication, newer Version, results []Result, approver string, at time.Time) (Publication, error) {
	if newer.Number <= prev.Version.Number {
		return Publication{}, fmt.Errorf("%w: %d is not newer than %d", ErrNotNewer, newer.Number, prev.Version.Number)
	}
	return Publish(newer, results, approver, nil, at)
}

// ActiveExceptions returns the exceptions still in force at the given time, sorted by
// identifier. Every exception ever granted stays on the publication; this filters, and
// never deletes.
func ActiveExceptions(pub Publication, at time.Time) []Exception {
	var active []Exception
	for _, ex := range pub.Exceptions {
		if at.Before(ex.ExpiresAt) {
			active = append(active, ex)
		}
	}
	return active
}

// StatusOf reports a live policy, including every exception ever granted and whether each
// is still in force. A policy with only expired exceptions is not reported as Clean: its
// history is part of the record, and Clean means nothing has ever been waived here.
func StatusOf(pub Publication, at time.Time) Status {
	views := make([]ExceptionView, 0, len(pub.Exceptions))
	for _, ex := range pub.Exceptions {
		views = append(views, ExceptionView{
			Exception:   ex,
			Expired:     !at.Before(ex.ExpiresAt),
			Suppressing: !pub.PublishedAt.IsZero() && pub.PublishedAt.Before(ex.ExpiresAt),
		})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].ID < views[j].ID })
	return Status{Version: pub.Version, Exceptions: views, Clean: len(views) == 0}
}

// Verify re-derives a publication's version digest and refuses a publication whose
// tests were altered after the fact. Results are granted against a digest, so a mutated
// suite would be shipping under results gathered for a different set of checks.
func Verify(pub Publication) error {
	if pub.Version.Digest == "" {
		return ErrDigestMismatch
	}
	if Digest(pub.Version) != pub.Version.Digest {
		return fmt.Errorf("%w: version %d", ErrDigestMismatch, pub.Version.Number)
	}
	return nil
}
