// Package provider is the only cloud-aware layer in the platform.
//
// Everything above this package — the reconciler, the state model, the ledger,
// the generation fence and the API — speaks in logical resources and
// capabilities. This package is where a logical resource becomes a concrete
// cloud object (ADR G-031).
//
// Two rules constrain everything here:
//
//  1. Absence is proven, never assumed. Observe must distinguish "the resource
//     does not exist" from "I could not look", and only the former may be
//     reported as absent. A permission failure is not absence.
//  2. No typed cloud-native identifier (ARN, instance family, availability zone)
//     may appear in a struct that crosses this boundary. References cross as
//     opaque maps, so the reconciler cannot come to depend on one provider's
//     vocabulary.
package provider

import (
	"context"
	"errors"
	"time"
)

// Capability names a property an environment profile requires from the active
// provider. A profile is refused admission when the provider cannot satisfy a
// required capability. This is what lets a provider without a hardware isolation
// class decline untrusted candidates rather than silently downgrading them.
type Capability string

const (
	// CapIsolationClass means the provider can run candidates inside a
	// qualified hardware-backed isolation class.
	CapIsolationClass Capability = "isolation_class"
	// CapOwnershipTags means resources can carry platform ownership tags, which
	// the janitor and the post-restore reconciliation path both depend on.
	CapOwnershipTags Capability = "ownership_tags"
	// CapDedicatedDependencies means bounded dedicated dependency instances can
	// be provisioned per environment.
	CapDedicatedDependencies Capability = "dedicated_dependencies"
	// CapSharedBrokerWithQuota means a shared broker/workflow service can prove
	// server-side authorization and resource quotas.
	CapSharedBrokerWithQuota Capability = "shared_broker_with_quota"
	// CapEgressEnforcement means egress can be denied by default with explicit
	// allow rules.
	CapEgressEnforcement Capability = "egress_enforcement"
	// CapNodeIdentityWithheld means a workload can be prevented from obtaining a
	// useful node or instance credential.
	CapNodeIdentityWithheld Capability = "node_identity_withheld"
	// CapCostCapsEnforceable means admission and resource caps can be enforced
	// before provisioning.
	CapCostCapsEnforceable Capability = "cost_caps_enforceable"
)

// Requirement is a capability a profile depends on, with the reason it is
// required. The reason exists so a refusal is inspectable rather than opaque.
type Requirement struct {
	Capability Capability
	Reason     string
	// Critical requirements are never waived. A non-critical requirement may be
	// waived only by a reviewed exception that stays visible.
	Critical bool
}

// UnavailableError is returned when the active provider cannot satisfy a
// critical requirement. It must never be downgraded into a weaker profile.
type UnavailableError struct {
	Capability Capability
	Reason     string
}

func (e *UnavailableError) Error() string {
	return "provider cannot satisfy required capability " + string(e.Capability) + ": " + e.Reason
}

// CheckRequirements verifies the provider satisfies every critical requirement.
// This is the admission gate that keeps a weaker provider from being used for
// candidates it cannot safely contain.
func CheckRequirements(caps map[Capability]bool, reqs []Requirement) error {
	for _, r := range reqs {
		ok, known := caps[r.Capability]
		if known && ok {
			continue
		}
		if r.Critical {
			reason := r.Reason
			if !known {
				reason = "capability not reported by this provider; " + reason
			}
			return &UnavailableError{Capability: r.Capability, Reason: reason}
		}
	}
	return nil
}

// DependencyKind is a logical dependency class. It is not a cloud product name,
// though each provider maps it onto one.
type DependencyKind string

const (
	KindPostgres    DependencyKind = "postgres"
	KindRedis       DependencyKind = "redis"
	KindKafka       DependencyKind = "kafka"
	KindWorkflow    DependencyKind = "workflow"
	KindObjectStore DependencyKind = "object_store"
	KindIdentity    DependencyKind = "identity"
)

// SharedResource reports whether a kind is shared across environments rather
// than dedicated. Shared resources never enter environment-owned allocations with
// delete authority.
func (k DependencyKind) SharedResource() bool {
	switch k {
	case KindKafka, KindWorkflow:
		return true
	}
	return false
}

// AllocationRequest asks for a bounded logical dependency. It carries no cloud
// vocabulary, and it never carries credentials.
type AllocationRequest struct {
	EnvironmentID string
	Generation    uint64
	Kind          DependencyKind
	// LogicalKey is stable across retries so a retry resolves to the same
	// allocation rather than creating a second one.
	LogicalKey string
	// Bounds are the maximum resources the allocation may consume. Exceeding them
	// is an allocation failure, not a warning.
	Bounds Bounds
}

// Bounds are resource ceilings for one allocation.
type Bounds struct {
	MaxVCPU       float64
	MaxMemoryMiB  int
	MaxStorageGiB int
	MaxPartitions int
	// MaxActiveUnits caps concurrency for shared services, where the unit is a
	// workflow rather than a vCPU.
	MaxActiveUnits int
}

// Validate rejects a request that exceeds the profile before any external call.
func (r AllocationRequest) Validate(profileMax Bounds) error {
	switch {
	case r.EnvironmentID == "":
		return errors.New("environment id is required")
	case r.LogicalKey == "":
		return errors.New("logical key is required so a retry resolves to the same allocation")
	case r.Kind == "":
		return errors.New("dependency kind is required")
	case r.Bounds.MaxVCPU > profileMax.MaxVCPU:
		return errors.New("requested vCPU exceeds the profile maximum")
	case r.Bounds.MaxMemoryMiB > profileMax.MaxMemoryMiB:
		return errors.New("requested memory exceeds the profile maximum")
	case r.Bounds.MaxStorageGiB > profileMax.MaxStorageGiB:
		return errors.New("requested storage exceeds the profile maximum")
	case r.Bounds.MaxPartitions > profileMax.MaxPartitions:
		return errors.New("requested partitions exceed the profile maximum")
	}
	return nil
}

// Allocation is a provisioned logical dependency. Reference holds an opaque
// provider handle; credentials are referenced, never returned, and never embedded
// in a value that can reach an API response or a log.
type Allocation struct {
	EnvironmentID string
	Kind          DependencyKind
	Reference     map[string]string
	// CredentialRef names where the environment-scoped credential lives. The
	// credential itself is never part of this struct.
	CredentialRef string
	// EndpointRef names an opaque endpoint reference, also credential-gated.
	EndpointRef string
	// SupportsOwnershipTags reports whether this allocation carries platform
	// ownership tags. If false, post-restore reconciliation cannot rely on tags
	// for this type and it must be excluded or given an alternative key.
	SupportsOwnershipTags bool
	Shared                bool
}

// ErrNotAbsent is returned by Observe when absence could not be established. It
// must never be confused with absence.
var ErrNotAbsent = errors.New("absence could not be established; this is not proof of absence")

// Observation is the result of inspecting an external system.
type Observation struct {
	// Present reports whether the resource exists.
	Present bool
	// Reference is the observed provider reference, used to record ownership.
	Reference map[string]string
	// Detail explains the observation for audit.
	Detail string
}

// Observe inspects a logical resource. It must distinguish present from
// unobservable, and must never report a permission or transport failure as
// absence. Getting this wrong causes a duplicate create or an orphaned resource.
type Observer interface {
	Observe(ctx context.Context, ref map[string]string) (Observation, error)
}

// Allocator provisions and destroys bounded logical dependencies.
type Allocator interface {
	// Allocate creates the dependency. If it returns an error after the external
	// call may have taken effect, the caller must treat the outcome as uncertain
	// and resolve it with Observe rather than retrying.
	Allocate(ctx context.Context, req AllocationRequest) (*Allocation, error)
	// Revoke removes credentials and access bindings. It runs before data is
	// destroyed.
	Revoke(ctx context.Context, a Allocation) error
	// Destroy removes the dependency's data and the dependency itself.
	Destroy(ctx context.Context, a Allocation) error
	// Capabilities reports what this provider can satisfy, for admission checks.
	Capabilities() map[Capability]bool
}

// Provider is the full surface the platform depends on.
type Provider interface {
	Allocator
	Observer

	// Describe reports the provider identity and the regions/accounts in scope.
	// It is diagnostic and never returns credentials.
	Describe(ctx context.Context) (Description, error)
}

// Description identifies a provider instance without exposing secrets.
type Description struct {
	Name    string
	Account string
	Region  string
}

// UnsupportedProvider is the null provider. It reports no capabilities, so every
// critical requirement fails admission rather than the platform silently
// pretending a capability exists. It is the correct default before a real
// adapter is configured, and it is what keeps a local slice honest.
type UnsupportedProvider struct {
	Reason string
}

func (p UnsupportedProvider) Capabilities() map[Capability]bool { return map[Capability]bool{} }

func (p UnsupportedProvider) Allocate(context.Context, AllocationRequest) (*Allocation, error) {
	return nil, errors.New("no provider adapter configured: " + p.Reason)
}

func (p UnsupportedProvider) Revoke(context.Context, Allocation) error {
	return errors.New("no provider adapter configured: " + p.Reason)
}

func (p UnsupportedProvider) Destroy(context.Context, Allocation) error {
	return errors.New("no provider adapter configured: " + p.Reason)
}

func (p UnsupportedProvider) Observe(context.Context, map[string]string) (Observation, error) {
	return Observation{}, ErrNotAbsent
}

func (p UnsupportedProvider) Describe(context.Context) (Description, error) {
	return Description{Name: "unsupported", Account: "", Region: ""}, nil
}

// Compile-time check that the null provider satisfies the full interface.
var _ Provider = UnsupportedProvider{}

// Deadline is a helper for external calls that must not hang a reconciliation
// pass. A timeout produces uncertainty, not failure.
const Deadline = 5 * time.Minute
