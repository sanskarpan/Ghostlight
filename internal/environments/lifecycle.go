// Package environments defines the environment lifecycle state machine.
//
// The vocabulary here is deliberately cloud-agnostic (ADR G-031): desired and
// observed lifecycle, candidate identity, TTL and bounded phases. No instance
// family, availability zone, cloud account reference or provider resource type
// appears in this file. Concrete cloud objects are named only by opaque
// references carried in the resource ledger.
package environments

import (
	"errors"
	"fmt"
	"time"
)

// DesiredLifecycle is the platform's intent for an environment. It is set only
// by trusted paths: admission, an authorized update, or the independent
// watchdog marking expiry. A client request is an assertion to validate, never
// authority.
type DesiredLifecycle string

const (
	// DesiredPresent means the environment should exist and, once healthy,
	// serve its current generation.
	DesiredPresent DesiredLifecycle = "present"
	// DesiredAbsent is terminal intent. It overrides every other consideration,
	// including a runtime suspension intent and any admission.
	DesiredAbsent DesiredLifecycle = "absent"
)

// ObservedLifecycle is what the platform has actually achieved, as far as it can
// prove. It never advances on the strength of an external job's exit code.
type ObservedLifecycle string

const (
	ObsRequested        ObservedLifecycle = "requested"
	ObsAdmitted         ObservedLifecycle = "admitted"
	ObsAllocating       ObservedLifecycle = "allocating"
	ObsDeploying        ObservedLifecycle = "deploying"
	ObsValidating       ObservedLifecycle = "validating"
	ObsReady            ObservedLifecycle = "ready"
	ObsDegraded         ObservedLifecycle = "degraded"
	ObsFailed           ObservedLifecycle = "failed"
	ObsDraining         ObservedLifecycle = "draining"
	ObsRevoking         ObservedLifecycle = "revoking"
	ObsDestroying       ObservedLifecycle = "destroying"
	ObsCleanupVerifying ObservedLifecycle = "cleanup_verifying"
	ObsDestroyed        ObservedLifecycle = "destroyed"
	ObsQuarantined      ObservedLifecycle = "quarantined"
)

// RuntimeIntent is orthogonal to lifecycle and exists from 1.5. Suspension is not
// destruction: it preserves ownership, TTL and retained costs, and it invalidates
// the evidence that qualified the generation.
type RuntimeIntent string

const (
	RuntimeRunning   RuntimeIntent = "running"
	RuntimeSuspended RuntimeIntent = "suspended"
	RuntimeResuming  RuntimeIntent = "resuming"
)

// Phase is a bounded provisioning phase. Teardown walks these in reverse after
// stopping ingress and revoking claims.
type Phase string

const (
	PhaseAdmission     Phase = "admission"
	PhaseIdentity      Phase = "identity"
	PhaseDependencies  Phase = "dependencies"
	PhaseRuntimePolicy Phase = "runtime_policy"
	PhaseMigration     Phase = "migration"
	PhaseSeed          Phase = "seed"
	PhaseRollout       Phase = "rollout"
	PhaseHealth        Phase = "health"
	PhaseGates         Phase = "gates"
	PhaseReady         Phase = "ready"
)

var provisioningOrder = []Phase{
	PhaseAdmission,
	PhaseIdentity,
	PhaseDependencies,
	PhaseRuntimePolicy,
	PhaseMigration,
	PhaseSeed,
	PhaseRollout,
	PhaseHealth,
	PhaseGates,
	PhaseReady,
}

// ProvisioningOrder returns the bounded provisioning phases in order. Callers
// must not reorder it: the ordering exists so that namespace, network, egress and
// pod policy are installed before any candidate pod can be scheduled.
func ProvisioningOrder() []Phase {
	out := make([]Phase, len(provisioningOrder))
	copy(out, provisioningOrder)
	return out
}

var (
	// ErrDestroyed is returned for any operation on a destroyed environment.
	// Destroyed is terminal for that immutable identifier; reopening a pull
	// request creates a new environment with a new identifier.
	ErrDestroyed = errors.New("environment is destroyed; this identifier is terminal")

	// ErrGenerationSuperseded is returned when an operation's expected
	// generation no longer matches. A stale completion must never be able to
	// mark a newer generation ready.
	ErrGenerationSuperseded = errors.New("generation superseded")

	// ErrEpochMismatch is returned when a lease owner or epoch no longer
	// matches. Database epochs fence ledger writes, not cloud API calls.
	ErrEpochMismatch = errors.New("lease epoch mismatch")

	// ErrInvalidTransition is returned for a lifecycle transition the state
	// machine does not permit.
	ErrInvalidTransition = errors.New("invalid lifecycle transition")

	// ErrDestroyedIsFinal is returned when something attempts to resurrect a
	// terminal environment.
	ErrDestroyedIsFinal = errors.New("destroyed is terminal for this identifier")
)

// Candidate is the exact identity of a deployable unit. Eight digests, per
// SPEC.md: a candidate that cannot bind a policy digest cannot be gated, which is
// why Policy is not optional here.
type Candidate struct {
	SourceSHA         string `json:"source_sha"`
	BaseSHA           string `json:"base_sha"`
	ArtifactDigest    string `json:"artifact_digest"`
	ConfigDigest      string `json:"configuration_digest"`
	MigrationDigest   string `json:"migration_digest"`
	EventSchemaDigest string `json:"event_schema_digest"`
	RecipeDigest      string `json:"recipe_digest"`
	PolicyDigest      string `json:"policy_digest"`
}

// Validate rejects a candidate that cannot be gated or cleaned up safely. A
// candidate is compared by identity, never by display name.
func (c Candidate) Validate() error {
	fields := []struct {
		name  string
		value string
	}{
		{"source_sha", c.SourceSHA},
		{"artifact_digest", c.ArtifactDigest},
		{"configuration_digest", c.ConfigDigest},
		{"recipe_digest", c.RecipeDigest},
		{"policy_digest", c.PolicyDigest},
	}
	for _, f := range fields {
		if f.value == "" {
			return fmt.Errorf("candidate missing %s: a gated candidate requires an exact identity", f.name)
		}
	}
	return nil
}

// Gateable reports whether this candidate may have a gate result bound to it.
func (c Candidate) Gateable() bool { return c.Validate() == nil }

// Identity is the immutable pair identifying an environment: a random UUID for
// the ledger and a platform-generated DNS-safe slug for routing. The slug never
// derives from a branch name, a label or a callback body.
type Identity struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
}

// Valid reports whether the identity is usable for resource creation and cleanup.
func (i Identity) Valid() bool { return i.ID != "" && i.Slug != "" }

// Environment is the aggregate root of the lifecycle.
type Environment struct {
	Identity    Identity
	Repository  string
	PullRequest int

	Desired  DesiredLifecycle
	Observed ObservedLifecycle
	Runtime  RuntimeIntent

	// Generation increments on every admitted artifact, configuration or recipe
	// change. It is the fence that prevents a stale result from qualifying newer
	// code.
	Generation uint64

	Candidate Candidate

	// ExpiresAt is set by trusted policy, never by the client.
	ExpiresAt time.Time

	// QuarantineReason explains why the environment cannot accept new
	// experiments or promotion, and is empty otherwise.
	QuarantineReason string
}

// IsTerminal reports whether the identifier can no longer change.
func (e Environment) IsTerminal() bool { return e.Observed == ObsDestroyed }

// Expired reports whether trusted policy has passed the environment's TTL.
// Expiry does not wait for a successful gate.
func (e Environment) Expired(now time.Time) bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(e.ExpiresAt)
}

// ShouldTeardown reports whether the independent watchdog should set desired
// absent. This is the only path that sets it automatically, and it is deliberately
// not the controller.
func (e Environment) ShouldTeardown(now time.Time) bool {
	if e.Desired == DesiredAbsent {
		return false
	}
	return e.Expired(now)
}

// CanAdmit reports whether a new generation may be admitted. A new admitted
// generation immediately invalidates the previous generation's gate results.
func (e Environment) CanAdmit(now time.Time) error {
	switch {
	case e.IsTerminal():
		return ErrDestroyedIsFinal
	case e.Desired == DesiredAbsent:
		return fmt.Errorf("environment %s is being torn down; admission is refused", e.Identity.ID)
	case e.Expired(now):
		return fmt.Errorf("environment %s expired at %s; admission is refused", e.Identity.ID, e.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

// nextObserved returns the state that follows the current one on the happy path.
// Desired absent always wins over provisioning progress.
func (e Environment) nextObserved() (ObservedLifecycle, bool) {
	switch e.Desired {
	case DesiredAbsent:
		switch e.Observed {
		case ObsDestroyed:
			// Terminal. Reopening a pull request creates a new environment.
			return "", false
		case ObsDraining:
			return ObsRevoking, true
		case ObsRevoking:
			return ObsDestroying, true
		case ObsDestroying:
			return ObsCleanupVerifying, true
		case ObsCleanupVerifying:
			// Reached only once absence has been verified against the provider.
			// A permission failure is not absence, so this transition is made by
			// the verification step and never inferred from an exit status.
			return ObsDestroyed, true
		default:
			return ObsDraining, true
		}
	}

	switch e.Observed {
	case ObsRequested:
		return ObsAdmitted, true
	case ObsAdmitted:
		return ObsAllocating, true
	case ObsAllocating:
		return ObsDeploying, true
	case ObsDeploying:
		return ObsValidating, true
	case ObsValidating:
		return ObsReady, true
	case ObsDegraded, ObsFailed:
		return e.Observed, false
	default:
		return "", false
	}
}

// Advance moves the environment one bounded step and reports whether it changed.
// The caller is responsible for having committed the action intent before making
// any external call that this transition represents.
func (e *Environment) Advance() bool {
	next, ok := e.nextObserved()
	if !ok {
		return false
	}
	e.Observed = next
	return true
}

// TeardownOrder returns the bounded destruction phases. Workload ingress and
// claims stop first, credentials are revoked before data is removed, and
// endpoint and identity bindings are released before the namespace disappears.
func TeardownOrder() []ObservedLifecycle {
	return []ObservedLifecycle{
		ObsDraining,
		ObsRevoking,
		ObsDestroying,
		ObsCleanupVerifying,
		ObsDestroyed,
	}
}

// AdmissionDecision is the result of evaluating admission for a candidate. It
// carries an explicit reason so a refusal is inspectable rather than opaque.
type AdmissionDecision struct {
	Allowed bool
	Reason  string
}

// Admit decides whether a candidate generation may proceed. Reservation of
// capacity is transactional and performed by the caller, so that a retry cannot
// consume the same reservation twice.
func Admit(e Environment, c Candidate, now time.Time, withinTTL bool) AdmissionDecision {
	if err := c.Validate(); err != nil {
		return AdmissionDecision{false, err.Error()}
	}
	if err := e.CanAdmit(now); err != nil {
		return AdmissionDecision{false, err.Error()}
	}
	if e.Observed == ObsQuarantined {
		return AdmissionDecision{false, "environment is quarantined: " + e.QuarantineReason}
	}
	if !withinTTL {
		return AdmissionDecision{false, "requested TTL exceeds the profile maximum"}
	}
	return AdmissionDecision{true, "admitted"}
}

// nextGeneration is the fence value an action records so that a result written
// after a newer generation was admitted can be rejected.
func nextGeneration(current uint64) uint64 { return current + 1 }
