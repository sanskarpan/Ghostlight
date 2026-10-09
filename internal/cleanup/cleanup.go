// Package cleanup removes an environment's resources and proves they are gone.
//
// SPEC.md section 7 fixes the order, and the order is the safety property:
//
//	stop ingress and experiments; terminate admissions; revoke
//	artifact/provider/integration/identity credentials; wait for bounded drain;
//	destroy runtime and allocated dependency data/identities; apply Terraform
//	destroy for owned resources; verify provider inventory and state/resource ledger.
//
// Revocation comes before destruction because credentials outlive the data they grant
// access to unless explicitly removed. Verification comes last because a destroy call
// that returned successfully is not proof — it may have failed after the provider
// applied the change, or the response may have been lost. Only a subsequent observation
// can confirm absence.
//
// The end state is deliberately not "destroyed". It is `cleanup_verifying`, with the
// allocation still recorded, because "pending dependency deletion remains in
// cleanup_verifying" and an unverified destroy must never be reported as a destroyed
// environment.
package cleanup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/resource"
)

// Phase is an environment's cleanup phase.
type Phase string

const (
	// PhaseRunning means the environment is still serving.
	PhaseRunning Phase = "running"
	// PhaseRevoking means credentials are being removed.
	PhaseRevoking Phase = "revoking"
	// PhaseDestroying means data and dependencies are being removed.
	PhaseDestroying Phase = "destroying"
	// PhaseVerifying means destruction was attempted and absence is being confirmed.
	//
	// This is not a transitional state that should be raced past. It is the honest
	// answer, and moving out of it requires provider evidence.
	PhaseVerifying Phase = "cleanup_verifying"
	// PhaseDestroyed means every allocation is verified gone.
	PhaseDestroyed Phase = "destroyed"
	// PhasePreserved means cleanup could not complete and state was kept for a human.
	//
	// SPEC.md: "Cleanup permission revoked → revoke what is possible, preserve
	// state/inventory and page; do not report destroyed."
	PhasePreserved Phase = "cleanup_preserved"
)

// ErrVerifying means cleanup is not finished, and must not be reported as finished.
var ErrVerifying = errors.New("cleanup is still verifying")

// ErrPreserved means cleanup was abandoned with state intact.
var ErrPreserved = errors.New("cleanup could not proceed and state was preserved")

// Depender is one provider dependency to remove.
type Depender interface {
	// Revoke removes credentials and access bindings. It runs before data is
	// destroyed.
	Revoke(ctx context.Context, a resource.Allocation) error
	// Destroy removes the dependency's data and the dependency itself.
	Destroy(ctx context.Context, a resource.Allocation) error
}

// Driver removes one environment's resources and verifies they are gone.
type Driver struct {
	ledger    resource.Ledger
	issuer    *resource.AuthorityIssuer
	dependers map[string]Depender
	now       func() time.Time
	// page is called when cleanup must escalate to a person.
	page func(environmentID string, reason string)
}

// NewDriver builds a cleanup driver.
func NewDriver(l resource.Ledger, issuer *resource.AuthorityIssuer, deps map[string]Depender, now func() time.Time) (*Driver, error) {
	if l == nil {
		return nil, errors.New("a cleanup driver requires the resource ledger")
	}
	if issuer == nil {
		// Without the authority issuer there is no verified path to a delete, and
		// bypassing it would mean deleting on trust.
		return nil, errors.New("a cleanup driver requires the authority issuer; it is the only source of delete authority")
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Driver{ledger: l, issuer: issuer, dependers: deps, now: now}, nil
}

// SetPage installs the escalation seam.
func (d *Driver) SetPage(fn func(environmentID, reason string)) { d.page = fn }

// Result is what one cleanup pass did.
type Result struct {
	EnvironmentID string
	Phase         Phase
	Revoked       int
	Destroyed     int
	// Verified counts allocations confirmed absent by the provider.
	Verified int
	// Pending lists allocations whose absence is not yet proven.
	Pending []string
	// Skipped lists allocations that could not be touched, with reasons.
	Skipped []Skip
}

// Clean reports whether cleanup is complete.
func (r Result) Clean() bool { return r.Phase == PhaseDestroyed }

// SkipReason classifies why an allocation was not removed.
//
// The classification is a type rather than a substring match on an error message,
// because deciding whether to page an operator must not depend on prose staying exactly
// as written.
type SkipReason string

const (
	// SkipShared means the resource is a foundation resource and was correctly left
	// alone. Not a failure, and not pageable.
	SkipShared SkipReason = "shared_foundation_resource"
	// SkipNoAuthority means the ledger refused to authorize the delete.
	SkipNoAuthority SkipReason = "no_delete_authority"
	// SkipNoProvider means no provider is registered for the kind, so nothing can
	// remove it. A real gap.
	SkipNoProvider SkipReason = "no_provider_registered"
	// SkipRevokeFailed means credentials could not be removed.
	SkipRevokeFailed SkipReason = "revoke_failed"
	// SkipDestroyUncertain means the destroy outcome is unknown and must be verified
	// rather than retried.
	SkipDestroyUncertain SkipReason = "destroy_uncertain"
	// SkipVerificationFailed means absence could not be confirmed.
	SkipVerificationFailed SkipReason = "verification_failed"
)

// Skip is an allocation cleanup did not act on, and why.
type Skip struct {
	AllocationID string
	Kind         string
	Reason       SkipReason
	// Detail is operator-facing context. It must not contain credentials.
	Detail string
}

// Pageable reports whether this skip needs a person.
//
// A shared resource that was correctly left alone is not pageable. Paging on it would
// mean every preview using a foundation resource pages an operator, and every page that
// is not actionable trains people to ignore pages.
func (s Skip) Pageable() bool { return s.Reason != SkipShared }

// RevokeOrder is the order credentials are revoked in.
//
// Workload access goes before the things it accesses. Revoking a database credential
// before the workload can no longer reach it would leave the workload holding access to
// a system it should already be locked out of.
var RevokeOrder = []string{"identity", "secret", "endpoint", "database", "topic", "object_store"}

// DestroyOrder is the order resources are destroyed in.
//
// Reversed relative to provisioning, because every dependency must outlive the thing
// that depends on it. SPEC.md: "remove workload access before database/topics/object
// deletion; remove endpoint/identity bindings before namespace disappearance."
var DestroyOrder = []string{"object_store", "topic", "database", "endpoint", "identity", "secret"}

// Cleanup removes an environment's resources.
//
// Revocation and destruction are separate phases that run in order, and verification
// runs per allocation immediately after its destroy. Verifying the whole environment at
// the end instead would mean a single stubborn resource delays every other resource's
// confirmation.
func (d *Driver) Cleanup(ctx context.Context, environmentID string, generation uint64, actor string) (Result, error) {
	res := Result{EnvironmentID: environmentID, Phase: PhaseRevoking}

	allocs, err := d.ledger.List(ctx, environmentID)
	if err != nil {
		return res, fmt.Errorf("list allocations: %w", err)
	}
	if len(allocs) == 0 {
		// Nothing to remove is the one case where "destroyed" is immediately true,
		// and saying so avoids a pointless verification loop.
		res.Phase = PhaseDestroyed
		return res, nil
	}

	// Phase one: revoke every credential.
	for _, a := range ordered(allocs, RevokeOrder) {
		if err := d.revoke(ctx, a, actor); err != nil {
			res.Skipped = append(res.Skipped, Skip{AllocationID: a.ID, Kind: a.Kind, Reason: SkipRevokeFailed, Detail: err.Error()})
			// Revocation failing is not fatal to the pass, but it must be visible and
			// it must stop this allocation's destruction: destroying data whose access
			// is still live is the failure this ordering exists to prevent.
			continue
		}
		res.Revoked++
	}

	res.Phase = PhaseDestroying

	// Phase two: destroy, then verify each one.
	for _, a := range ordered(allocs, DestroyOrder) {
		if a.IsShared {
			// A shared resource belongs to other environments and the ledger already
			// refuses to authorize it. It is recorded rather than silently dropped, so
			// that "destroyed" never means "we did not look".
			res.Skipped = append(res.Skipped, Skip{
				AllocationID: a.ID, Kind: a.Kind,
				Reason: SkipShared,
				Detail: "shared foundation resource; intentionally not deleted",
			})
			continue
		}
		auth, err := d.issuer.Authorize(ctx, a.ID, generation, actor)
		if err != nil {
			res.Skipped = append(res.Skipped, Skip{AllocationID: a.ID, Kind: a.Kind, Reason: SkipNoAuthority, Detail: err.Error()})
			res.Pending = append(res.Pending, a.ID)
			continue
		}

		dep, ok := d.dependers[a.Kind]
		if !ok {
			res.Skipped = append(res.Skipped, Skip{
				AllocationID: a.ID, Kind: a.Kind,
				Reason: SkipNoProvider,
				Detail: fmt.Sprintf("no provider is registered for kind %s, so nothing can destroy it", a.Kind),
			})
			res.Pending = append(res.Pending, a.ID)
			continue
		}

		if err := dep.Destroy(ctx, a); err != nil {
			// The outcome is uncertain: the destroy may or may not have applied. It is
			// not retried here. It is verified on the next pass, because retrying a
			// destroy that already succeeded is how a shared resource gets destroyed
			// twice.
			res.Pending = append(res.Pending, a.ID)
			res.Skipped = append(res.Skipped, Skip{AllocationID: a.ID, Kind: a.Kind, Reason: SkipDestroyUncertain, Detail: "destroy did not complete: " + err.Error()})
			continue
		}
		res.Destroyed++

		// Verified cleanup: ask the provider whether it is actually gone.
		obs, err := d.issuer.VerifyDeleted(ctx, auth)
		if err != nil {
			res.Pending = append(res.Pending, a.ID)
			continue
		}
		if err := d.ledger.MarkDeleted(ctx, a.ID, obs); err != nil {
			res.Pending = append(res.Pending, a.ID)
			res.Skipped = append(res.Skipped, Skip{AllocationID: a.ID, Kind: a.Kind, Reason: SkipVerificationFailed, Detail: err.Error()})
			continue
		}
		res.Verified++
	}

	switch {
	case len(res.Pending) == 0:
		// Everything this environment was responsible for is confirmed gone. A shared
		// foundation resource correctly outliving the environment is not a pending
		// item: it was never this environment's to remove.
		res.Phase = PhaseDestroyed
	case hasPageable(res.Skipped):
		// Something failed that will not resolve on its own. Preserve state and get a
		// person, rather than leaving an operator to notice a stuck environment days
		// later.
		res.Phase = PhaseVerifying
		d.escalate(environmentID, "cleanup could not remove at least one resource")
	default:
		res.Phase = PhaseVerifying
	}
	return res, nil
}

// revoke removes one allocation's credentials.
func (d *Driver) revoke(ctx context.Context, a resource.Allocation, actor string) error {
	if a.State == resource.StateRevoked || a.State == resource.StateVerifiedDeleted {
		// Already handled. Revocation is idempotent so a re-run does not fail.
		return nil
	}
	dep, ok := d.dependers[a.Kind]
	if !ok {
		return fmt.Errorf("no provider is registered for kind %s, so nothing can revoke it", a.Kind)
	}
	if err := dep.Revoke(ctx, a); err != nil {
		return fmt.Errorf("revoke %s: %w", a.ID, err)
	}
	if err := d.ledger.MarkRevoked(ctx, a.ID, actor, "provider revoke returned success"); err != nil {
		return err
	}
	return nil
}

// hasPageable reports whether any skip needs an operator.
func hasPageable(skips []Skip) bool {
	for _, s := range skips {
		if s.Pageable() {
			return true
		}
	}
	return false
}

func (d *Driver) escalate(environmentID, reason string) {
	if d.page != nil {
		d.page(environmentID, reason)
	}
}

// ordered sorts allocations into a dependency-safe sequence.
//
// Kinds not named in the order go first, so an unknown kind is removed before the
// things it might depend on rather than after. Removing a known dependency out of
// order risks breaking something still running; removing an unknown one at the end
// risks the reverse.
func ordered(allocs []resource.Allocation, order []string) []resource.Allocation {
	rank := map[string]int{}
	for i, k := range order {
		rank[k] = i
	}
	out := append([]resource.Allocation(nil), allocs...)
	// Insertion sort keeps this allocation-order-stable, so two runs that see the same
	// allocations produce the same sequence.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			if rankOf(rank, out[j]) < rankOf(rank, out[j-1]) {
				out[j], out[j-1] = out[j-1], out[j]
				continue
			}
			break
		}
	}
	return out
}

// rankOf returns a kind's position, with unlisted kinds sorting before listed ones.
func rankOf(rank map[string]int, a resource.Allocation) int {
	if r, ok := rank[a.Kind]; ok {
		return r
	}
	return -1
}

// NextVerification returns when a pending cleanup should be re-verified.
//
// Backoff is bounded rather than immediate: a resource that has already failed to be
// confirmed absent usually needs provider-side settling time, and hammering it does not
// make it appear sooner.
func NextVerification(attempts int) time.Duration {
	switch {
	case attempts < 1:
		return 0
	case attempts > 5:
		return 15 * time.Minute
	default:
		return time.Duration(attempts) * time.Minute
	}
}
