// Package janitor recovers resources the normal lifecycle lost track of.
//
// SPEC.md gives it two jobs. "Failed teardown escalates and is retried by janitor."
// And after a timeout that may have succeeded: "observe owner-tagged native resources;
// reconcile state."
//
// The janitor's defining property is what it refuses to do. It discovers resources that
// exist in the provider. Some of them have no ledger row, because a crash happened
// between the provider creating something and the ledger recording it. Those are real
// leaks, and the tempting thing is to delete them.
//
// It must not. An unowned resource is the one case where "delete what isn't ours" is
// most likely, because nobody can prove whose it is. It may be another preview's, it may
// be a customer's own, it may be the platform's own foundation. So the janitor
// quarantines and reports, and a human decides.
//
// The second refusal: it never forces success. SPEC.md, "never force success to clear
// the dashboard." A janitor that reported "clean" while a resource still existed would
// be worse than one that reports a problem, because it would be believed.
package janitor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/resource"
)

// ErrQuarantined means a resource was found that the platform cannot prove it owns.
//
// It is deliberately a distinct error from any failure. A janitor that cannot prove
// ownership has found something dangerous, and the difference between "I could not clean
// this" and "I found something that might not be mine" is the difference between a
// ticket and an incident.
var ErrQuarantined = errors.New("resource has no ledger entry and was quarantined, not deleted")

// Discovered is a provider-side resource the janitor found.
type Discovered struct {
	// NativeID is the provider's identifier for it.
	NativeID string
	Kind     string
	// OwnerTags are the tags the provider reports. Ownership is established by tags,
	// which is the only stable handle available after a crash.
	OwnerTags map[string]string
	// CreatedAt is when the provider says it was created.
	CreatedAt time.Time
}

// Owned reports whether the platform's ownership tag is present and well formed.
//
// A tag that is present but empty is not ownership. An empty tag on a resource the
// janitor did not create is worse than no tag, because it looks like an answer.
func (d Discovered) Owned(platformTagKey string) bool {
	v, ok := d.OwnerTags[platformTagKey]
	return ok && v != ""
}

// EnvironmentID returns the environment the ownership tag claims.
func (d Discovered) EnvironmentID(platformTagKey string) (string, bool) {
	v, ok := d.OwnerTags[platformTagKey]
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// Discovery lists what the provider actually holds.
//
// This is the janitor's source of truth. The ledger says what we believe exists; only
// the provider says what does.
type Discovery interface {
	// Discover lists provider resources carrying the platform's ownership tag.
	Discover(ctx context.Context, limit int) ([]Discovered, error)
}

// Ledger is the janitor's record of what it believes exists.
type Ledger interface {
	List(ctx context.Context, environmentID string) ([]resource.Allocation, error)
	ByID(ctx context.Context, id string) (resource.Allocation, error)
}

// Finding is one classification the janitor made.
type Finding struct {
	NativeID string
	Kind     string
	// Verdict is what the janitor concluded.
	Verdict Verdict
	// EnvironmentID is the owner, when one could be established.
	EnvironmentID string
	// Detail is operator-facing context.
	Detail string
}

// Verdict is a janitor conclusion.
type Verdict string

const (
	// VerdictReconciled means the resource is accounted for and needs nothing.
	VerdictReconciled Verdict = "reconciled"
	// VerdictRetried means teardown was incomplete and has been retried.
	VerdictRetried Verdict = "retried_teardown"
	// VerdictAlreadyGone means the ledger says it should be gone and the provider
	// agrees.
	VerdictAlreadyGone Verdict = "already_gone"
	// VerdictQuarantined means the platform cannot prove it owns the resource.
	VerdictQuarantined Verdict = "quarantined"
)

// PhaseResult mirrors the cleanup driver's outcome shape.
//
// It is a distinct type from the driver's own result so this package does not depend on
// it. That keeps the janitor's decision-making testable on its own, which is where the
// safety property lives.
type PhaseResult struct {
	Phase   string
	Pending []string
}

// Retryable is the teardown retry the janitor performs.
type Retryable interface {
	// Retry re-runs an environment's teardown.
	Retry(ctx context.Context, environmentID string, generation uint64, actor string) (PhaseResult, error)
}

// CleanupRetryer adapts a cleanup driver to the janitor's retry seam.
type CleanupRetryer struct {
	// Cleanup retries an environment's teardown. It is supplied by the caller rather
	// than imported, so this package stays independent of the driver.
	Cleanup func(ctx context.Context, environmentID string, generation uint64, actor string) (PhaseResult, error)
}

// Retry implements Retryable.
func (c CleanupRetryer) Retry(ctx context.Context, environmentID string, generation uint64, actor string) (PhaseResult, error) {
	return c.Cleanup(ctx, environmentID, generation, actor)
}

// RetryableFunc adapts a function to Retryable.
type RetryableFunc func(ctx context.Context, environmentID string, generation uint64, actor string) (PhaseResult, error)

// Retry implements Retryable.
func (f RetryableFunc) Retry(ctx context.Context, environmentID string, generation uint64, actor string) (PhaseResult, error) {
	return f(ctx, environmentID, generation, actor)
}

// Quarantine records a resource the janitor will not touch.
type Quarantine interface {
	// Quarantine marks a resource as needing human attention. It must not destroy.
	Quarantine(ctx context.Context, d Discovered, reason string) error
}

// Result is one janitor pass.
type Result struct {
	Scanned     int
	Reconciled  int
	Retried     int
	AlreadyGone int
	// StillPending counts resources whose teardown was retried and did not finish. A
	// pending teardown is a leak in progress, so it is tracked separately from
	// quarantined findings.
	StillPending int
	// Quarantined lists resources the janitor refused to delete.
	Quarantined []Finding
	// Errors lists failures that must not be read as cleanliness.
	Errors []error
}

// Clean reports whether the pass found nothing requiring attention.
//
// It is false whenever anything was quarantined, any teardown is still pending, or any
// error occurred. A janitor that reports clean while a resource still exists would be
// worse than one that reports a problem, because it would be believed.
func (r Result) Clean() bool {
	return len(r.Quarantined) == 0 && len(r.Errors) == 0 && r.StillPending == 0
}

// Janitor recovers lost resources.
type Janitor struct {
	discovery  Discovery
	ledger     Ledger
	retry      Retryable
	quarantine Quarantine
	// tagKey is the ownership tag the platform writes.
	tagKey string
	// quarantineAfter is how many consecutive unowned findings it takes before
	// quarantining. It exists so a single tag-propagation lag does not raise an
	// incident, while a genuinely unowned resource still gets caught.
	quarantineAfter int
	// seen persists sighting history across passes. It is optional, and without it
	// the quarantine threshold cannot be evaluated.
	seen Seen
	// now overrides the clock.
	now func() time.Time
}

// Config bounds a janitor.
type Config struct {
	// TagKey is the ownership tag key the platform stamps on its resources.
	TagKey string
	// QuarantineAfter is how many consecutive findings precede a quarantine.
	QuarantineAfter int
	// Now overrides the clock.
	Now func() time.Time
}

// New builds a janitor.
func New(d Discovery, l Ledger, r Retryable, q Quarantine, cfg Config) (*Janitor, error) {
	if d == nil {
		// Without discovery the janitor only reads its own ledger, so it can only ever
		// confirm what it already believed. It could never find a leak.
		return nil, errors.New("a janitor needs provider discovery; its own ledger cannot tell it what leaked")
	}
	if l == nil {
		return nil, errors.New("a janitor needs the resource ledger to reconcile against")
	}
	if cfg.TagKey == "" {
		return nil, errors.New("a janitor needs an ownership tag key; without one it cannot tell owned from unowned")
	}
	if cfg.QuarantineAfter <= 0 {
		// One pass is enough when there is no propagation lag to tolerate, and the
		// default is deliberately conservative rather than lazy.
		cfg.QuarantineAfter = 1
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Janitor{
		discovery: d, ledger: l, retry: r, quarantine: q,
		tagKey: cfg.TagKey, quarantineAfter: cfg.QuarantineAfter, now: cfg.Now,
	}, nil
}

// Seen is what the janitor remembers between passes.
//
// The quarantine-after threshold needs persistence: a decision about whether something
// has been unowned for several passes is not a decision a single pass can make.
type Seen interface {
	// Count returns how many consecutive passes have seen this resource unowned.
	Count(ctx context.Context, nativeID string) (int, error)
	// Remember records a sighting.
	Remember(ctx context.Context, nativeID string) error
	// Forget clears a resource's history.
	Forget(ctx context.Context, nativeID string) error
}

// Run makes one pass.
//
// The order of the three outcomes is the whole design. Owned and accounted for is
// nothing to do. Owned and pending teardown is retried. Not provably owned is
// quarantined, and never deleted.
func (j *Janitor) Run(ctx context.Context, limit int) (Result, error) {
	var res Result
	var errs []error

	found, err := j.discovery.Discover(ctx, limit)
	if err != nil {
		// A discovery failure is emphatically not a clean pass. It means the janitor
		// could not look, which is indistinguishable from not having looked.
		res.Errors = append(res.Errors, err)
		return res, fmt.Errorf("discover provider resources: %w", err)
	}
	res.Scanned = len(found)

	for _, d := range found {
		verdict, err := j.classify(ctx, d)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.NativeID, err))
			continue
		}

		switch verdict.Verdict {
		case VerdictQuarantined:
			res.Quarantined = append(res.Quarantined, verdict)
		case VerdictRetried:
			res.Retried++
			// A retried-but-still-pending teardown is a leak in progress, so it must
			// keep the pass from reading as clean.
			res.StillPending++
		case VerdictReconciled:
			res.Reconciled++
		case VerdictAlreadyGone:
			res.AlreadyGone++
		}
	}

	res.Errors = errs
	if len(errs) > 0 {
		return res, errors.Join(errs...)
	}
	return res, nil
}

// classify decides what to do with one discovered resource.
func (j *Janitor) classify(ctx context.Context, d Discovered) (Finding, error) {
	f := Finding{NativeID: d.NativeID, Kind: d.Kind}

	if !d.Owned(j.tagKey) {
		return j.handleUnowned(ctx, d, f)
	}

	envID, _ := d.EnvironmentID(j.tagKey)
	f.EnvironmentID = envID

	allocs, err := j.ledger.List(ctx, envID)
	if err != nil {
		return f, fmt.Errorf("list allocations for %s: %w", envID, err)
	}

	// Find whether the ledger knows this specific native resource.
	match, found := findNative(allocs, d.NativeID)
	if !found {
		// Tagged for an environment the ledger has no record of creating this. That is
		// an ownership claim without provenance, and it is treated exactly like an
		// untagged resource: nobody can prove it.
		return j.handleUnowned(ctx, d, f)
	}

	if match.State == resource.StateVerifiedDeleted {
		// The provider has it and we tombstoned it. This is the resurrection case: the
		// native lookup disagrees with a record of verified absence, which means
		// something recreated it. It is not simply cleaned, because the tombstone was
		// correct when written.
		f.Verdict = VerdictQuarantined
		f.Detail = "a resource recorded as verified deleted exists again; the tombstone and the provider disagree"
		if j.quarantine != nil {
			if err := j.quarantine.Quarantine(ctx, d, f.Detail); err != nil {
				return f, fmt.Errorf("quarantine resurrected resource: %w", err)
			}
		}
		return f, nil
	}

	if match.State == resource.StateRevoked {
		// Revoked but still present. Teardown was incomplete, so this is the janitor's
		// actual job.
		if j.retry == nil {
			f.Verdict = VerdictReconciled
			f.Detail = "revoked but still present; no retry is configured"
			return f, nil
		}
		out, err := j.retry.Retry(ctx, envID, match.Generation, "janitor")
		if err != nil {
			return f, fmt.Errorf("retry teardown for %s: %w", envID, err)
		}
		if len(out.Pending) > 0 {
			f.Verdict = VerdictRetried
			f.Detail = "teardown retried and still pending"
		} else {
			f.Verdict = VerdictReconciled
			f.Detail = "teardown completed on retry"
		}
		return f, nil
	}

	// Active and owned. Nothing to do, but the sighting is worth forgetting so the
	// unowned counter does not carry stale history.
	if j.seen != nil {
		if err := j.seen.Forget(ctx, d.NativeID); err != nil {
			return f, fmt.Errorf("forget %s: %w", d.NativeID, err)
		}
	}
	f.Verdict = VerdictReconciled
	f.Detail = "accounted for and still active"
	return f, nil
}

// handleUnowned quarantines a resource nobody can prove belongs to the platform.
//
// This is the janitor's most important branch, and it has exactly one outcome. The
// temptation in every leak investigation is to delete the thing nobody claims, and that
// is precisely how a janitor destroys a customer resource or another preview's database.
func (j *Janitor) handleUnowned(ctx context.Context, d Discovered, f Finding) (Finding, error) {
	f.Verdict = VerdictQuarantined

	if j.seen != nil {
		count, err := j.seen.Count(ctx, d.NativeID)
		if err != nil {
			return f, fmt.Errorf("count sightings of %s: %w", d.NativeID, err)
		}
		if count+1 < j.quarantineAfter {
			// Not yet. Tag propagation can lag, and raising an incident on the first
			// sighting trains people to ignore incidents.
			f.Detail = fmt.Sprintf("unowned; seen %d time(s), waiting for %d before quarantining",
				count+1, j.quarantineAfter)
			if err := j.seen.Remember(ctx, d.NativeID); err != nil {
				return f, fmt.Errorf("remember %s: %w", d.NativeID, err)
			}
			return f, nil
		}
	}

	f.Detail = "no ledger entry and no verifiable ownership tag; a person must decide"
	if j.quarantine == nil {
		return f, fmt.Errorf("%w: %s (%s)", ErrQuarantined, d.NativeID, d.Kind)
	}
	if err := j.quarantine.Quarantine(ctx, d, f.Detail); err != nil {
		return f, fmt.Errorf("quarantine %s: %w", d.NativeID, err)
	}
	return f, nil
}

// SetSeen installs the sighting history seam.
func (j *Janitor) SetSeen(s Seen) { j.seen = s }

// findNative locates an allocation by its native id.
func findNative(allocs []resource.Allocation, nativeID string) (resource.Allocation, bool) {
	for _, a := range allocs {
		for _, v := range a.ProviderRef {
			if v == nativeID {
				return a, true
			}
		}
	}
	return resource.Allocation{}, false
}
