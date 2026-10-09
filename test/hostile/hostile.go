// Package hostile tests what a malicious or compromised preview can do to its siblings.
//
// G2.6: "Run hostile sibling-preview/fork tests with actual managed-service identities."
// Managed-service identities are not available in this environment, so the identities
// here are faked — and that limit is recorded, not hidden. What is tested instead is the
// property those identities would enforce: every layer refuses cross-preview access, so
// no single layer's failure opens a sibling.
//
// The suite drives the real components — seed binding, resource authority, preview
// tokens, admission, the janitor — with two hostile environments. Each scenario asserts
// refusal at the layer under test. A scenario that passes because the wrong layer
// refused would still be a pass for the wrong reason, so each test names the layer it
// exercises.
package hostile

import (
	"github.com/sanskarpan/Ghostlight/internal/resource"
)

// OwnedAllocation builds an active allocation belonging to an environment.
//
// It is exported so every hostile scenario constructs the victim the same way. A
// scenario that hand-rolled its victim could accidentally make the victim unowned,
// which would test nothing.
func OwnedAllocation(id, envID, kind, key, nativeID string) resource.Allocation {
	return resource.Allocation{
		ID: id, EnvironmentID: envID, Generation: 2, Kind: kind, LogicalKey: key,
		ProviderRef: map[string]string{"native_id": nativeID, "environment_id": envID},
		State:       resource.StateActive,
	}
}
