// Package installation models the GitHub App installation: the wizard that verifies an
// installation and selects repositories, the revocation that stops it working, the
// reassignment that moves a repository, and the health that says whether the
// integration is working.
//
// This is the entry point to the product, so it is the first place a hostile actor
// touches us. Four properties follow, and each has an obvious wrong implementation.
//
// The first is that a request is an assertion, not authority. The wizard's repository
// selection is constrained to the repositories the installation was actually granted,
// and a request naming a repository outside that grant is **refused** rather than
// silently dropped. Silently dropping is the tempting choice, because a partial
// selection is friendlier — but the user then believes they enabled three repositories
// and got one, and a repository that is not enabled is a repository whose pull requests
// are never reviewed. A refusal is inconvenient and honest.
//
// The second is that revocation is immediate and irreversible. There is no grace period
// and no cache: a revoked installation refuses every subsequent operation, and it
// cannot be un-revoked. Reinstating is a new installation, because an installation
// that was revoked for a reason may be revoked again for the same reason, and a
// "restore" button would make revoking feel temporary, which is exactly the wrong
// lesson to teach.
//
// The third is that reassignment cannot orphan anything. Moving a repository from one
// installation to another is refused while the repository still has live environments,
// because the environments belong to the ownership that is being moved. A reassignment
// that left them behind would leave resources that no installation can clean up — and
// the whole product is about never being the thing that leaks resources.
//
// The fourth is that health is never green when it is unknown. If the integration has
// never been verified, or every check is older than the freshness bound, the status is
// *unknown* and explicitly not healthy. "Unknown" and "healthy" look identical on a
// dashboard that has no third state, and the difference between them is the difference
// between a working integration and one that stopped working an hour ago and nobody
// noticed. A check that fails outright is *degraded* or *unhealthy* depending on
// whether it is critical, so a single failing non-critical check cannot be averaged
// away by a pile of passing ones.
//
// Nothing here holds a token. The installation records when its credential expires and
// never the credential itself, so there is no field for it to leak out of — the
// absence of a place to put the secret is stronger than a rule about where not to put
// it.
package installation

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package's installation rules.
var (
	// ErrNoInstallationID means an installation carries no identifier.
	ErrNoInstallationID = errors.New("installation must carry an identifier")
	// ErrDuplicateInstallation means two installations share an identifier.
	ErrDuplicateInstallation = errors.New("installation identifier is already in use")
	// ErrNoAccount means an installation names no account.
	ErrNoAccount = errors.New("installation must carry an account")
	// ErrNoTenant means an installation names no tenant.
	ErrNoTenant = errors.New("installation must carry a tenant")
	// ErrNotInstalled means an operation requires a verified installation.
	ErrNotInstalled = errors.New("installation is not verified")
	// ErrInvalidState means an operation does not apply to the installation's
	// current state.
	ErrInvalidState = errors.New("installation is not in a state that allows this")
	// ErrRevoked means the installation has been revoked. Revocation is
	// irreversible, and an irreversible thing is refused rather than negotiated.
	ErrRevoked = errors.New("installation is revoked")
	// ErrAlreadyRevoked means a revoked installation was revoked again.
	ErrAlreadyRevoked = errors.New("installation is already revoked")
	// ErrNoRevocationReason means a revocation carried no reason.
	ErrNoRevocationReason = errors.New("revocation must state a reason")
	// ErrNoRevocationActor means a revocation named no actor.
	ErrNoRevocationActor = errors.New("revocation must name an actor")
	// ErrNoVerification means an installation was not verified with evidence.
	ErrNoVerification = errors.New("installation must be verified with evidence")
	// ErrVerificationExpired means the verification evidence had expired.
	ErrVerificationExpired = errors.New("installation verification evidence has expired")
	// ErrUnknownRepository means a repository is not part of the installation.
	ErrUnknownRepository = errors.New("no such repository")
	// ErrRepositoryNotGranted means a selection named a repository the installation
	// was not granted. It is refused rather than dropped, because a partial
	// selection that looks complete is a repository nobody is reviewing.
	ErrRepositoryNotGranted = errors.New("repository was not granted to this installation")
	// ErrNoRepositories means a selection named no repository.
	ErrNoRepositories = errors.New("no repositories were selected")
	// ErrDuplicateRepository means a repository was selected twice.
	ErrDuplicateRepository = errors.New("repository is selected twice")
	// ErrTooManyRepositories means a selection exceeded the bound.
	ErrTooManyRepositories = errors.New("too many repositories selected")
	// ErrHasLiveEnvironments means a repository still has live environments, so
	// reassigning it would orphan them.
	ErrHasLiveEnvironments = errors.New("repository still has live environments")
	// ErrReassignTargetExists means the target installation already holds the
	// repository.
	ErrReassignTargetExists = errors.New("target installation already holds that repository")
	// ErrNoCheckName means a health check carried no name.
	ErrNoCheckName = errors.New("health check must carry a name")
	// ErrDuplicateCheck means two health checks share a name.
	ErrDuplicateCheck = errors.New("health check name is already used")
	// ErrFutureCheck means a health check is dated after the moment being assessed.
	ErrFutureCheck = errors.New("health check is dated in the future")
	// ErrNoConfiguration means the configuration step carried nothing.
	ErrNoConfiguration = errors.New("configuration must be provided")
)

// Bounds on an installation.
const (
	// MaxRepositories is the largest number of repositories one installation may
	// select.
	MaxRepositories = 500
	// MaxHealthAge is how old a health check may be and still count. Beyond it the
	// integration's status is unknown, because a check that has not run is not a
	// passing check.
	MaxHealthAge = 15 * time.Minute
	// VerificationTTL is how long installation verification evidence stays valid.
	VerificationTTL = time.Hour
)

// State is where an installation stands.
type State string

const (
	// StatePending means the app was created but no installation was verified.
	StatePending State = "pending"
	// StateInstalled means an installation was received and verified.
	StateInstalled State = "installed"
	// StateSelected means repositories have been chosen.
	StateSelected State = "selected"
	// StateReady means the integration is configured and healthy.
	StateReady State = "ready"
	// StateRevoked means the installation was revoked and is permanently stopped.
	StateRevoked State = "revoked"
)

// Repository is one repository in an installation.
type Repository struct {
	// ID is the provider's repository identifier.
	ID string
	// FullName is the human name, such as "acme/api".
	FullName string
	// Private reports whether the repository is private.
	Private bool
	// Selected reports whether the repository was chosen for use.
	Selected bool
	// ReassignedTo names the installation the repository was moved to; empty while
	// it is still here.
	ReassignedTo string
	// LiveEnvironments counts the environments still running under this repository.
	// A repository with live environments cannot be reassigned, because the
	// environments belong to the ownership being moved.
	LiveEnvironments int
}

// Installation is a GitHub App installation for one account.
type Installation struct {
	// ID identifies the installation.
	ID string
	// AccountID is the provider's account identifier.
	AccountID string
	// AccountLogin is the human account name.
	AccountLogin string
	// TenantID is the Ghostlight organization that owns this installation.
	TenantID string
	// State is the installation's state.
	State State
	// Repositories are the repositories the installation was granted.
	Repositories []Repository
	// VerifiedAt is when the installation was verified.
	VerifiedAt time.Time
	// TokenExpiresAt is when the installation's credential expires. The credential
	// itself is never held here, so there is no field for it to leak from.
	TokenExpiresAt time.Time
	// RevokedAt is when the installation was revoked.
	RevokedAt time.Time
	// RevokedBy names who revoked it.
	RevokedBy string
	// RevocationReason states why.
	RevocationReason string
}

// Evidence verifies an installation.
type Evidence struct {
	// Digest is the digest of the provider's signed installation payload.
	Digest string
	// IssuedAt is when the provider issued it.
	IssuedAt time.Time
	// Verified reports that the payload's signature was checked against the
	// provider's key.
	Verified bool
}

// Registry is the set of installations.
type Registry struct {
	// Installations are the known installations.
	Installations []Installation
}

// clone returns a registry whose installations are copied, along with their
// repositories.
//
// This is not tidiness. The methods on this type return a new registry and take the
// old one by value, which reads as value semantics: the caller's registry is unchanged
// unless the method succeeds and the result is used. That reading would be false, because
// a Registry holds a slice, and a slice header copied by value still points at the same
// backing array — so mutating "the new" registry mutates the caller's too. A caller
// that discarded a result would see the change anyway, and a caller that kept a
// registry across a refused operation would see a partial mutation.
//
// Cloning first makes the contract true: a refused operation changes nothing, and a
// successful one changes only the registry it returns.
func (r Registry) clone() Registry {
	out := Registry{Installations: make([]Installation, len(r.Installations))}
	for i, inst := range r.Installations {
		out.Installations[i] = inst
		out.Installations[i].Repositories = append([]Repository(nil), inst.Repositories...)
	}
	return out
}

// install looks an installation up by identifier.
func (r Registry) install(id string) (Installation, bool) {
	for _, i := range r.Installations {
		if i.ID == id {
			return i, true
		}
	}
	return Installation{}, false
}

// Add records an installation in the pending state.
func (r Registry) Add(i Installation) (Registry, error) {
	r = r.clone()
	if strings.TrimSpace(i.ID) == "" {
		return r, ErrNoInstallationID
	}
	if strings.TrimSpace(i.AccountID) == "" {
		return r, ErrNoAccount
	}
	if strings.TrimSpace(i.TenantID) == "" {
		return r, ErrNoTenant
	}
	for _, existing := range r.Installations {
		if existing.ID == i.ID {
			return r, fmt.Errorf("%w: %q", ErrDuplicateInstallation, i.ID)
		}
	}
	i.State = StatePending
	r.Installations = append(r.Installations, i)
	return r, nil
}

// VerifyInstallation verifies a pending installation with the provider's evidence.
//
// The evidence must be verified, must carry a digest, and must not have expired. An
// expired verification is refused rather than accepted as "probably still fine",
// because the installation payload is what proves the account granted us access, and
// a stale grant is not a grant.
func (r Registry) VerifyInstallation(id string, ev Evidence, at time.Time) (Registry, error) {
	r = r.clone()
	i, ok := r.install(id)
	if !ok {
		return r, fmt.Errorf("%w: %q", ErrNoInstallationID, id)
	}
	if i.State == StateRevoked {
		return r, fmt.Errorf("%w: %q", ErrRevoked, id)
	}
	if i.State != StatePending {
		return r, fmt.Errorf("%w: %q is %s", ErrInvalidState, id, i.State)
	}
	if !ev.Verified {
		return r, fmt.Errorf("%w: %q", ErrNoVerification, id)
	}
	if strings.TrimSpace(ev.Digest) == "" {
		return r, fmt.Errorf("%w: %q", ErrNoVerification, id)
	}
	if at.Sub(ev.IssuedAt) > VerificationTTL {
		return r, fmt.Errorf("%w: %q was issued %s ago", ErrVerificationExpired, id, at.Sub(ev.IssuedAt))
	}
	for idx := range r.Installations {
		if r.Installations[idx].ID == id {
			r.Installations[idx].State = StateInstalled
			r.Installations[idx].VerifiedAt = at
		}
	}
	return r, nil
}

// SelectRepositories chooses the repositories the installation will use.
//
// The selection must be a subset of what the installation was granted. A repository
// outside that grant is refused outright, naming it, rather than dropped: a partial
// selection that reports success is a repository whose pull requests are never
// reviewed, and the person who enabled it believes otherwise.
func (r Registry) SelectRepositories(id string, selected []string, granted []string, at time.Time) (Registry, error) {
	r = r.clone()
	i, ok := r.install(id)
	if !ok {
		return r, fmt.Errorf("%w: %q", ErrNoInstallationID, id)
	}
	if i.State == StateRevoked {
		return r, fmt.Errorf("%w: %q", ErrRevoked, id)
	}
	if i.State != StateInstalled && i.State != StateSelected {
		return r, fmt.Errorf("%w: %q is %s", ErrInvalidState, id, i.State)
	}
	if len(selected) == 0 {
		return r, ErrNoRepositories
	}
	if len(selected) > MaxRepositories {
		return r, fmt.Errorf("%w: %d selected, the maximum is %d", ErrTooManyRepositories, len(selected), MaxRepositories)
	}
	grantedSet := make(map[string]bool, len(granted))
	for _, g := range granted {
		grantedSet[g] = true
	}
	seen := make(map[string]bool, len(selected))
	for _, repoID := range selected {
		if !grantedSet[repoID] {
			return r, fmt.Errorf("%w: %q", ErrRepositoryNotGranted, repoID)
		}
		if seen[repoID] {
			return r, fmt.Errorf("%w: %q", ErrDuplicateRepository, repoID)
		}
		seen[repoID] = true
	}
	for idx := range r.Installations {
		if r.Installations[idx].ID != id {
			continue
		}
		for j := range r.Installations[idx].Repositories {
			r.Installations[idx].Repositories[j].Selected = seen[r.Installations[idx].Repositories[j].ID]
		}
		r.Installations[idx].State = StateSelected
	}
	return r, nil
}

// Configure supplies the installation's configuration and moves it to ready.
//
// A revoked installation is refused, because a revoked installation that can be
// configured is a revoked installation that is still being used.
func (r Registry) Configure(id string, configuration map[string]string, at time.Time) (Registry, error) {
	r = r.clone()
	i, ok := r.install(id)
	if !ok {
		return r, fmt.Errorf("%w: %q", ErrNoInstallationID, id)
	}
	if i.State == StateRevoked {
		return r, fmt.Errorf("%w: %q", ErrRevoked, id)
	}
	if i.State != StateSelected {
		return r, fmt.Errorf("%w: %q is %s", ErrInvalidState, id, i.State)
	}
	if len(configuration) == 0 {
		return r, ErrNoConfiguration
	}
	for idx := range r.Installations {
		if r.Installations[idx].ID == id {
			r.Installations[idx].State = StateReady
		}
	}
	return r, nil
}

// Revoke stops an installation.
//
// Revocation is immediate, irreversible and requires a named actor and a reason. A
// revoked installation refuses every later operation, and it cannot be un-revoked:
// reinstalling is a new installation, because an installation revoked for a reason may
// be revoked again for the same reason, and a restore button would make revoking feel
// temporary — which is exactly the wrong lesson to teach about a security control.
func (r Registry) Revoke(id, actor, reason string, at time.Time) (Registry, error) {
	r = r.clone()
	i, ok := r.install(id)
	if !ok {
		return r, fmt.Errorf("%w: %q", ErrNoInstallationID, id)
	}
	if i.State == StateRevoked {
		return r, fmt.Errorf("%w: %q", ErrAlreadyRevoked, id)
	}
	if strings.TrimSpace(actor) == "" {
		return r, ErrNoRevocationActor
	}
	if strings.TrimSpace(reason) == "" {
		return r, ErrNoRevocationReason
	}
	for idx := range r.Installations {
		if r.Installations[idx].ID == id {
			r.Installations[idx].State = StateRevoked
			r.Installations[idx].RevokedAt = at
			r.Installations[idx].RevokedBy = actor
			r.Installations[idx].RevocationReason = reason
		}
	}
	return r, nil
}

// Reassign moves a repository from this installation to another.
//
// It is refused while the repository still has live environments, because those
// environments belong to the ownership being moved, and a reassignment that left them
// behind would leave resources that no installation can clean up. The whole product is
// about never being the thing that leaks resources.
func (r Registry) Reassign(id, repoID, targetID string, at time.Time) (Registry, error) {
	r = r.clone()
	i, ok := r.install(id)
	if !ok {
		return r, fmt.Errorf("%w: %q", ErrNoInstallationID, id)
	}
	if i.State == StateRevoked {
		return r, fmt.Errorf("%w: %q", ErrRevoked, id)
	}
	target, ok := r.install(targetID)
	if !ok {
		return r, fmt.Errorf("%w: %q", ErrNoInstallationID, targetID)
	}
	if target.State == StateRevoked {
		return r, fmt.Errorf("%w: %q", ErrRevoked, targetID)
	}
	if id == targetID {
		return r, fmt.Errorf("%w: %q", ErrInvalidState, id)
	}

	var repo *Repository
	for idx := range i.Repositories {
		if i.Repositories[idx].ID == repoID {
			repo = &i.Repositories[idx]
			break
		}
	}
	if repo == nil {
		return r, fmt.Errorf("%w: %q", ErrUnknownRepository, repoID)
	}
	if repo.LiveEnvironments > 0 {
		return r, fmt.Errorf("%w: %q has %d live", ErrHasLiveEnvironments, repoID, repo.LiveEnvironments)
	}
	for _, existing := range target.Repositories {
		if existing.ID == repoID {
			return r, fmt.Errorf("%w: %q", ErrReassignTargetExists, repoID)
		}
	}

	moved := *repo
	moved.Selected = false
	moved.ReassignedTo = targetID
	for instIdx := range r.Installations {
		if r.Installations[instIdx].ID == id {
			for repoIdx := range r.Installations[instIdx].Repositories {
				if r.Installations[instIdx].Repositories[repoIdx].ID == repoID {
					r.Installations[instIdx].Repositories[repoIdx] = moved
				}
			}
		}
	}
	for idx := range r.Installations {
		if r.Installations[idx].ID == targetID {
			r.Installations[idx].Repositories = append(r.Installations[idx].Repositories, moved)
		}
	}
	return r, nil
}

// Check is one observed property of an integration.
type Check struct {
	// Name identifies the check.
	Name string
	// Critical marks a check whose failure makes the integration unusable.
	Critical bool
	// OK reports whether the check passed.
	OK bool
	// Detail explains a failure.
	Detail string
	// At is when the check ran.
	At time.Time
}

// HealthStatus is an integration's health.
type HealthStatus string

const (
	// HealthHealthy means every check passed and every check is fresh.
	HealthHealthy HealthStatus = "healthy"
	// HealthDegraded means a non-critical check failed.
	HealthDegraded HealthStatus = "degraded"
	// HealthUnhealthy means a critical check failed.
	HealthUnhealthy HealthStatus = "unhealthy"
	// HealthUnknown means the integration has not been verified recently enough to
	// say. It is explicitly not healthy.
	HealthUnknown HealthStatus = "unknown"
)

// Health is an integration's assessed health.
type Health struct {
	// InstallationID is the installation assessed.
	InstallationID string
	// Status is the health status.
	Status HealthStatus
	// Verified reports whether the status is based on fresh evidence. A status of
	// healthy always has this set; unknown never does.
	Verified bool
	// FreshChecks counts the checks that were within the freshness bound.
	FreshChecks int
	// StaleChecks counts the checks that were too old to count.
	StaleChecks int
	// FailedChecks names the checks that failed.
	FailedChecks []string
	// Reason explains a non-healthy status.
	Reason string
}

// Assess evaluates an installation's health from its checks.
//
// The order is the policy. Freshness is decided first, because a check that has not
// run is not a passing check: if every check is stale, or there are no checks at all,
// the answer is *unknown* and the installation is not healthy. A failing critical check
// is then unhealthy regardless of how many others passed, and a failing non-critical
// check is degraded — one failing check cannot be averaged away by a pile of passing
// ones.
func Assess(i Installation, checks []Check, at time.Time) (Health, error) {
	h := Health{InstallationID: i.ID}
	if i.State == StateRevoked {
		h.Status = HealthUnhealthy
		h.Reason = "installation is revoked"
		return h, nil
	}
	seen := make(map[string]bool, len(checks))
	for _, c := range checks {
		if strings.TrimSpace(c.Name) == "" {
			return h, ErrNoCheckName
		}
		if seen[c.Name] {
			return h, fmt.Errorf("%w: %q", ErrDuplicateCheck, c.Name)
		}
		seen[c.Name] = true
		if c.At.After(at) {
			return h, fmt.Errorf("%w: %q", ErrFutureCheck, c.Name)
		}
	}

	for _, c := range checks {
		if at.Sub(c.At) > MaxHealthAge {
			h.StaleChecks++
			continue
		}
		h.FreshChecks++
		if !c.OK {
			h.FailedChecks = append(h.FailedChecks, c.Name)
			if c.Critical {
				h.Status = HealthUnhealthy
			} else if h.Status != HealthUnhealthy {
				h.Status = HealthDegraded
			}
		}
	}
	sort.Strings(h.FailedChecks)

	if h.FreshChecks == 0 {
		h.Status = HealthUnknown
		h.Verified = false
		if len(checks) == 0 {
			h.Reason = "no checks have been run"
		} else {
			h.Reason = "every check is older than the freshness bound"
		}
		return h, nil
	}
	h.Verified = true
	if h.Status == "" {
		h.Status = HealthHealthy
	}
	return h, nil
}

// SelectedRepositories returns the repositories an installation has selected, sorted by
// full name.
func (i Installation) SelectedRepositories() []Repository {
	var out []Repository
	for _, repo := range i.Repositories {
		if repo.Selected {
			out = append(out, repo)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].FullName < out[b].FullName })
	return out
}
