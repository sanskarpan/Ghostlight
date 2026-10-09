// Package roles defines the least-privilege identities every platform actor runs as.
//
// G0.5: "Create least-privilege identities for controller, build, allocator, runner,
// runtime, experiment, janitor and signer."
//
// Least privilege is a matrix, not a motto. Each role gets exactly the actions its job
// requires, and the interesting entries are the denials: the build role cannot provision,
// the runner cannot sign, the runtime cannot mutate anything, the janitor cannot create.
// A denial that is not written down is a denial that erodes the first time someone is in
// a hurry, so the matrix is data — every cell decided — rather than a set of guidelines.
//
// This package is the reference matrix. Enforcement lives with each component; what
// lives here is the decision itself, in a form a test can hold each component to.
package roles

import (
	"fmt"
	"sort"
	"strings"
)

// Role is a platform actor.
type Role string

const (
	// RoleController reconciles desired state into action intents.
	RoleController Role = "controller"
	// RoleBuild turns source into artifacts. Untrusted by definition: it runs
	// attacker-influenced code, so it is the most constrained role that still does
	// useful work.
	RoleBuild Role = "build"
	// RoleAllocator provisions bounded logical dependencies.
	RoleAllocator Role = "allocator"
	// RoleRunner executes provider mutations for one environment at a time.
	RoleRunner Role = "runner"
	// RoleRuntime is the running preview workload itself.
	RoleRuntime Role = "runtime"
	// RoleExperiment injects faults under authorization.
	RoleExperiment Role = "experiment"
	// RoleJanitor recovers orphaned resources. It may quarantine and retry teardown,
	// never create.
	RoleJanitor Role = "janitor"
	// RoleSigner signs artifacts, roles, and tokens. It verifies nothing else and
	// mutates nothing.
	RoleSigner Role = "signer"
)

// All returns every defined role, in a stable order.
func All() []Role {
	return []Role{
		RoleController, RoleBuild, RoleAllocator, RoleRunner,
		RoleRuntime, RoleExperiment, RoleJanitor, RoleSigner,
	}
}

// Action is something a role may attempt.
type Action string

const (
	// ActionReadLedger reads platform state.
	ActionReadLedger Action = "read_ledger"
	// ActionWriteLedger writes platform state.
	ActionWriteLedger Action = "write_ledger"
	// ActionProvision creates provider resources.
	ActionProvision Action = "provision"
	// ActionMutate changes provider resources.
	ActionMutate Action = "mutate"
	// ActionDestroy removes provider resources.
	ActionDestroy Action = "destroy"
	// ActionSign signs artifacts, roles, or tokens.
	ActionSign Action = "sign"
	// ActionReadSecret reads a credential.
	ActionReadSecret Action = "read_secret"
	// ActionWriteSecret writes a credential.
	ActionWriteSecret Action = "write_secret"
	// ActionRevoke removes credentials and bindings.
	ActionRevoke Action = "revoke"
	// ActionObserve reads provider state without changing it.
	ActionObserve Action = "observe"
	// ActionQuarantine marks resources for human attention.
	ActionQuarantine Action = "quarantine"
	// ActionInjectFault injects a fault into a running preview.
	ActionInjectFault Action = "inject_fault"
	// ActionServeTraffic serves customer traffic.
	ActionServeTraffic Action = "serve_traffic"
	// ActionReadEvidence reads gate evidence and attestations.
	ActionReadEvidence Action = "read_evidence"
	// ActionWriteEvidence writes gate evidence and attestations.
	ActionWriteEvidence Action = "write_evidence"
)

// AllActions returns every defined action, in a stable order.
func AllActions() []Action {
	return []Action{
		ActionReadLedger, ActionWriteLedger, ActionProvision, ActionMutate,
		ActionDestroy, ActionSign, ActionReadSecret, ActionWriteSecret,
		ActionRevoke, ActionObserve, ActionQuarantine, ActionInjectFault,
		ActionServeTraffic, ActionReadEvidence, ActionWriteEvidence,
	}
}

// grants is the complete matrix. An absent cell denies.
var grants = map[Role]map[Action]bool{
	RoleController: {
		ActionReadLedger: true, ActionWriteLedger: true, ActionObserve: true,
		ActionReadEvidence: true, ActionWriteEvidence: true,
		// A controller that could provision would bypass the action ledger and its
		// fencing. It decides; runners do. It writes evidence for the same reason it
		// writes the ledger: attestation integrity depends on a single platform
		// writer, and the runtime writing its own evidence would be self-qualification.
	},
	RoleBuild: {
		ActionReadLedger: true, ActionObserve: true,
		// The build role runs attacker-influenced code. It reads source and writes
		// artifacts through a separate, audited path — never the ledger, never
		// secrets, never the provider. Every absent cell here is load-bearing, and
		// the G0 gate ("untrusted build cannot obtain provisioning, signing, or
		// production credentials") is this row.
	},
	RoleAllocator: {
		ActionReadLedger: true, ActionProvision: true, ActionObserve: true,
		ActionWriteSecret: true,
		// Allocators create bounded dependencies. They do not destroy: destruction
		// goes through revocation and verified cleanup, which is a different role's
		// job with different evidence. They write the credentials they create, and
		// nothing else writes: creators write, consumers (runner, runtime) only read.
		// A role that both writes and uses a credential could rotate it out from
		// under its own running workload without anyone noticing.
	},
	RoleRunner: {
		ActionReadLedger: true, ActionMutate: true, ActionDestroy: true,
		ActionRevoke: true, ActionObserve: true, ActionReadSecret: true,
		// Runners mutate and destroy, which is why at most one mutates an environment
		// at a time and why every mutation is fenced. They cannot sign: a runner
		// that could sign its own evidence could fake a pass.
	},
	RoleRuntime: {
		ActionServeTraffic: true, ActionReadSecret: true,
		// The running preview serves traffic and reads its own scoped credential. It
		// writes nothing — not the ledger, not evidence, not secrets. A workload that
		// could write evidence could qualify itself.
	},
	RoleExperiment: {
		ActionReadLedger: true, ActionInjectFault: true, ActionObserve: true,
		ActionReadEvidence: true,
		// Experiments inject faults and read the results. They cannot provision,
		// mutate, or destroy: a fault that rebuilds infrastructure is not an
		// experiment, it is an outage with a costume on.
	},
	RoleJanitor: {
		ActionReadLedger: true, ActionObserve: true, ActionQuarantine: true,
		ActionRevoke: true, ActionDestroy: true,
		// The janitor retries teardown and quarantines what it cannot prove it owns.
		// It cannot create or provision: a janitor that could create would be able to
		// manufacture the resources it then "discovers".
	},
	RoleSigner: {
		ActionSign: true, ActionReadLedger: true,
		// The signer signs. It reads the ledger to know what it is signing and does
		// nothing else — it cannot provision, mutate, destroy, or touch secrets. A
		// signer with broader rights is a confused deputy waiting for instructions.
	},
}

// Allowed reports whether a role may perform an action.
//
// Unknown roles and unknown actions deny. There is no default-allow anywhere in this
// package: a typo in a role name must fail closed, not open a hole shaped exactly like
// the typo.
func Allowed(role Role, action Action) bool {
	actions, ok := grants[role]
	if !ok {
		return false
	}
	return actions[action]
}

// Denied is Allowed negated, for call sites that read better that way.
func Denied(role Role, action Action) bool { return !Allowed(role, action) }

// Grants returns a role's allowed actions, sorted.
func Grants(role Role) []Action {
	var out []Action
	for action := range grants[role] {
		out = append(out, action)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Denials returns a role's denied actions, sorted.
func Denials(role Role) []Action {
	allowed := map[Action]bool{}
	for action := range grants[role] {
		allowed[action] = true
	}
	var out []Action
	for _, action := range AllActions() {
		if !allowed[action] {
			out = append(out, action)
		}
	}
	return out
}

// Check is one evaluated decision with its reason.
type Check struct {
	Role   Role
	Action Action
	// Allowed is the decision.
	Allowed bool
	// Reason states why, in terms of the job the role does.
	Reason string
}

// Authorize evaluates one decision and explains it.
//
// The explanation matters as much as the boolean. A denial nobody understands becomes
// a ticket asking for broader rights, and broader rights granted to stop the tickets is
// how least privilege dies in practice.
func Authorize(role Role, action Action) Check {
	if _, ok := grants[role]; !ok {
		return Check{Role: role, Action: action, Allowed: false,
			Reason: fmt.Sprintf("unknown role %q; unknown roles deny", role)}
	}
	known := false
	for _, a := range AllActions() {
		if a == action {
			known = true
		}
	}
	if !known {
		return Check{Role: role, Action: action, Allowed: false,
			Reason: fmt.Sprintf("unknown action %q; unknown actions deny", action)}
	}
	if grants[role][action] {
		return Check{Role: role, Action: action, Allowed: true,
			Reason: fmt.Sprintf("%s requires %s to do its job", role, action)}
	}
	return Check{Role: role, Action: action, Allowed: false,
		Reason: reasonFor(role, action)}
}

// reasonFor states the load-bearing denial for the pairs that matter most.
func reasonFor(role Role, action Action) string {
	switch {
	case role == RoleBuild && (action == ActionProvision || action == ActionSign || action == ActionReadSecret || action == ActionWriteSecret):
		return "the build role runs attacker-influenced code (G0 gate)"
	case role == RoleRunner && action == ActionSign:
		return "a runner that could sign its own evidence could fake a pass"
	case role == RoleRuntime && (action == ActionWriteLedger || action == ActionWriteEvidence || action == ActionProvision):
		return "a workload that could write evidence could qualify itself"
	case role == RoleJanitor && (action == ActionProvision):
		return "a janitor that could create could manufacture what it discovers"
	case role == RoleSigner && action != ActionSign && action != ActionReadLedger:
		return "a signer with broader rights is a confused deputy"
	case role == RoleController && (action == ActionProvision || action == ActionMutate || action == ActionDestroy):
		return "the controller decides; runners do, under the fence"
	case role == RoleExperiment && (action == ActionProvision || action == ActionMutate || action == ActionDestroy):
		return "a fault that rebuilds infrastructure is an outage with a costume on"
	case role == RoleAllocator && action == ActionDestroy:
		return "destruction goes through revocation and verified cleanup, not allocation"
	default:
		return fmt.Sprintf("%s does not require %s", role, action)
	}
}

// Matrix renders the full decision table, for review and audit.
//
// Every cell is explicit. A matrix with implicit defaults is a matrix nobody can
// review, and an unreviewed matrix is not least privilege but least effort.
func Matrix() string {
	var b strings.Builder
	actions := AllActions()
	b.WriteString("role")
	for _, a := range actions {
		fmt.Fprintf(&b, " | %s", shortAction(a))
	}
	b.WriteString("\n")
	for _, r := range All() {
		fmt.Fprintf(&b, "%s", r)
		for _, a := range actions {
			if Allowed(r, a) {
				b.WriteString(" |   Y  ")
			} else {
				b.WriteString(" |   .  ")
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func shortAction(a Action) string {
	s := string(a)
	if len(s) > 6 {
		return s[:6]
	}
	return s
}
