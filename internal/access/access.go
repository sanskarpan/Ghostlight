// Package access decides who may do what inside an organization.
//
// G7.2. internal/roles answers a different question — which platform service identity
// holds which system capability — and the two must not be confused. A GitHub App
// installed in an organization is not a controller, and a controller is not an
// organization member. Mixing them is how a service token ends up with the authority
// to read a customer's repository.
//
// The rules here exist because the alternative is a permission system that is
// convenient to write and wrong in ways nobody notices.
//
// Access is scoped to one organization and cannot cross. Every reference is checked
// against the organization that owns it, so a repository belonging to another tenant
// is not "not found", it is refused: a check that reports absence still leaks
// existence to anyone who can time the difference.
//
// Explicit deny beats allow. A repository-level deny overrides an organization-level
// allow, because a deny is the more specific and more deliberate statement. Reversing
// that precedence makes the narrow exception useless, since the broad grant would
// always win it.
//
// Revocation is immediate. There is no session cache in this package and no way to
// add one: a membership that has been revoked must stop authorizing on the next
// check, not when a token expires.
//
// Teardown survives everything. A suspended organization, a revoked member and a
// cancelled subscription all still permit abort and cleanup. The people who most
// need to delete a preview environment are the ones who stopped paying for it.
package access

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// OrgRole is an organization's authority level.
type OrgRole string

const (
	// RoleOwner holds the organization and cannot be reduced to a lesser role by
	// anyone else, including an admin.
	RoleOwner OrgRole = "owner"
	// RoleAdmin manages members, repositories and billing.
	RoleAdmin OrgRole = "admin"
	// RoleMember works in repositories they are granted.
	RoleMember OrgRole = "member"
)

// Permission is a thing a principal may do.
type Permission string

const (
	// PermRepoRead reads repository metadata and diffs.
	PermRepoRead Permission = "repo:read"
	// PermRepoWrite pushes branches and changes settings.
	PermRepoWrite Permission = "repo:write"
	// PermEnvCreate creates preview environments.
	PermEnvCreate Permission = "env:create"
	// PermEnvRead reads preview logs and generated evidence.
	PermEnvRead Permission = "env:read"
	// PermEnvAbort destroys a preview environment. It is never withheld from anyone
	// who can see the environment.
	PermEnvAbort Permission = "env:abort"
	// PermMemberInvite invites new members.
	PermMemberInvite Permission = "member:invite"
	// PermMemberRevoke removes members and revokes access.
	PermMemberRevoke Permission = "member:revoke"
	// PermBillingRead reads invoices and usage.
	PermBillingRead Permission = "billing:read"
	// PermBillingWrite changes payment methods and the subscription.
	PermBillingWrite Permission = "billing:write"
	// PermRepoAdmin changes repository settings and ACLs.
	PermRepoAdmin Permission = "repo:admin"
)

// AllPermissions lists every permission, sorted.
func AllPermissions() []Permission {
	out := []Permission{
		PermRepoRead, PermRepoWrite, PermEnvCreate, PermEnvRead, PermEnvAbort,
		PermMemberInvite, PermMemberRevoke, PermBillingRead, PermBillingWrite, PermRepoAdmin,
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// roleGrants is what each organization role may do on its own.
//
// Note what is absent from RoleMember: billing, membership management and repository
// administration. A member's reach comes from repository grants, not from their role,
// which is why joining an organization does not silently expose every repository in it.
var roleGrants = map[OrgRole]map[Permission]bool{
	RoleOwner: {
		PermRepoRead: true, PermRepoWrite: true, PermEnvCreate: true, PermEnvRead: true, PermEnvAbort: true,
		PermMemberInvite: true, PermMemberRevoke: true, PermBillingRead: true,
		PermBillingWrite: true, PermRepoAdmin: true,
	},
	RoleAdmin: {
		PermRepoRead: true, PermRepoWrite: true, PermEnvCreate: true, PermEnvRead: true, PermEnvAbort: true,
		PermMemberInvite: true, PermMemberRevoke: true, PermBillingRead: true, PermRepoAdmin: true,
	},
	RoleMember: {
		PermRepoRead: true, PermEnvCreate: true, PermEnvRead: true, PermEnvAbort: true,
	},
}

// Effective reports whether a role grants a permission by itself.
func (r OrgRole) Effective(p Permission) bool { return roleGrants[r][p] }

// Valid reports whether the role is one this system understands.
func (r OrgRole) Valid() bool {
	_, ok := roleGrants[r]
	return ok
}

// TeardownPermissions may never be withheld from anyone who can see the resource.
//
// Aborting is in the list because the customer must always be able to stop a preview,
// and reading evidence is in it because a customer who cannot read why their preview
// failed cannot decide whether to destroy it — forcing that choice blind is how support
// tickets reading "I clicked the red button" get written.
//
// Repository write is deliberately absent. It looks like teardown, because a destroy
// action does push a teardown commit, but it is a broad write capability: if it were
// treated as always-available, then granting teardown would also grant the ability to
// push to any repository the organization can see. Abort travels as its own permission
// precisely so that this list cannot widen by accident.
var TeardownPermissions = []Permission{PermEnvAbort, PermEnvRead}

// Org is a tenant.
type Org struct {
	ID string
	// Suspended stops all work. Teardown continues.
	Suspended bool
	// Closed means the organization was verified and emptied; nothing new exists.
	Closed bool
}

// PrincipalKind distinguishes a person from a credential.
type PrincipalKind string

const (
	// PrincipalHuman is a person reached through the identity provider.
	PrincipalHuman PrincipalKind = "human"
	// PrincipalService is a credential such as a GitHub App or CI token.
	PrincipalService PrincipalKind = "service"
)

// Principal is an authenticated actor.
type Principal struct {
	ID    string
	Kind  PrincipalKind
	Email string
}

// Membership ties a principal to an organization.
type Membership struct {
	PrincipalID string
	OrgID       string
	Role        OrgRole
	// RevokedAt ends the membership. It is set rather than deleted so the record of
	// who removed whom survives.
	RevokedAt time.Time
	// Suspended pauses access without ending the membership.
	Suspended bool
}

// Active reports whether the membership currently grants anything.
//
// A membership revoked at a time is active strictly before that time. Comparing the
// other way round — active from the revocation onward — would mean the instant an
// admin pressed the button was the last moment the member still had access, which is
// the opposite of revocation.
func (m Membership) Active(now time.Time) bool {
	return m.RevokedAt.IsZero() || now.Before(m.RevokedAt)
}

// Grant is a repository-level rule.
type Grant struct {
	OrgID       string
	RepoID      string
	PrincipalID string
	Permission  Permission
	// Deny withholds a permission the role would otherwise grant.
	Deny bool
}

// Invitation is a pending membership offer.
type Invitation struct {
	TokenHash  string
	OrgID      string
	Email      string
	Role       OrgRole
	InvitedBy  string
	ExpiresAt  time.Time
	AcceptedAt time.Time
	Revoked    bool
}

// Snapshot is the access state at a point in time.
//
// Authorization is a pure function over a snapshot rather than a chain of queries, so
// a check cannot read the organization row before the membership row and decide
// something different from what it decided a millisecond earlier.
type Snapshot struct {
	Orgs        []Org
	Principals  []Principal
	Memberships []Membership
	Grants      []Grant
	Invitations []Invitation
}

// Errors returned by this package.
var (
	// ErrNotAMember means the principal holds no membership in the organization.
	ErrNotAMember = errors.New("principal is not a member of the organization")
	// ErrRevoked means the membership has ended.
	ErrRevoked = errors.New("membership has been revoked")
	// ErrSuspended means the membership is paused.
	ErrSuspended = errors.New("membership is suspended")
	// ErrOrgSuspended means the organization is suspended.
	ErrOrgSuspended = errors.New("organization is suspended")
	// ErrOrgClosed means the organization has been closed.
	ErrOrgClosed = errors.New("organization is closed")
	// ErrDenied reports an explicit repository deny.
	ErrDenied = errors.New("permission is explicitly denied on this repository")
	// ErrUnknownPermission means a permission this system does not implement was
	// requested, which is a bug rather than a denial.
	ErrUnknownPermission = errors.New("unknown permission")
	// ErrServicePrincipalCannotInvite means a credential tried to delegate.
	ErrServicePrincipalCannotInvite = errors.New("a service principal cannot invite")
	// ErrServicePrincipalCannotOwn means a credential tried to take ownership.
	ErrServicePrincipalCannotOwn = errors.New("a service principal cannot be an owner")
	// ErrLastOwner means removing this member would leave nobody able to administer
	// the organization.
	ErrLastOwner = errors.New("cannot remove the last owner")
	// ErrOwnerIsProtected means a non-owner tried to demote or remove an owner.
	ErrOwnerIsProtected = errors.New("only another owner may change an owner")
	// ErrNotAnAdmin means the actor's role cannot manage members.
	ErrNotAnAdmin = errors.New("role may not manage members")
	// ErrNotAnOwner means the actor's role cannot administer the organization.
	ErrNotAnOwner = errors.New("role may not administer the organization")
	// ErrInvitationExpired means the token is past its expiry.
	ErrInvitationExpired = errors.New("invitation has expired")
	// ErrInvitationUsed means the token has already been accepted or revoked.
	ErrInvitationUsed = errors.New("invitation has already been used")
	// ErrCrossOrganization means a reference points at another tenant's resource.
	ErrCrossOrganization = errors.New("resource belongs to a different organization")
	// ErrInvalidInvitation means the invitation is malformed.
	ErrInvalidInvitation = errors.New("invitation is invalid")
)

// Decision is the outcome of an authorization check.
type Decision struct {
	// Allowed reports whether the action may proceed.
	Allowed bool
	// Reason names the rule that decided it, in words support can read.
	Reason string
	// Role is the membership role the decision was made under.
	Role OrgRole
}

// LookupPrincipal returns a principal by identifier.
func (s Snapshot) LookupPrincipal(id string) (Principal, bool) {
	for _, p := range s.Principals {
		if p.ID == id {
			return p, true
		}
	}
	return Principal{}, false
}

// membership returns the principal's membership in an organization.
func (s Snapshot) membership(principalID, orgID string) (Membership, error) {
	var found Membership
	var ok bool
	for _, m := range s.Memberships {
		if m.PrincipalID == principalID && m.OrgID == orgID {
			found, ok = m, true
		}
	}
	if !ok {
		return Membership{}, ErrNotAMember
	}
	return found, nil
}

// org returns an organization by identifier.
func (s Snapshot) org(orgID string) (Org, error) {
	for _, o := range s.Orgs {
		if o.ID == orgID {
			return o, nil
		}
	}
	return Org{}, fmt.Errorf("%w: %s", ErrNotAMember, orgID)
}

// Authorize decides whether a principal may perform a permission.
//
// repoID may be empty for organization-scoped permissions. When it is supplied, every
// grant consulted must belong to the same organization as the repository: a grant
// naming another tenant's repository is ignored rather than honoured, and a
// membership in that other tenant never applies here.
func (s Snapshot) Authorize(principalID, orgID, repoID string, perm Permission, now time.Time) (Decision, error) {
	if !knownPermission(perm) {
		return Decision{}, fmt.Errorf("%w: %s", ErrUnknownPermission, perm)
	}
	if _, ok := s.LookupPrincipal(principalID); !ok {
		return Decision{}, ErrNotAMember
	}

	// Teardown is granted once the principal is known to belong to the organization,
	// but before its membership status is weighed. A revoked or suspended member can
	// still abort what is running; a principal from another tenant cannot, because
	// their membership lookup below never resolves.
	if repoID != "" && isTeardown(perm) {
		if _, err := s.membership(principalID, orgID); err != nil {
			return Decision{}, err
		}
		return Decision{Allowed: true, Reason: "abort and cleanup are always available"}, nil
	}

	org, err := s.org(orgID)
	if err != nil {
		return Decision{}, err
	}

	m, err := s.membership(principalID, orgID)
	if err != nil {
		return Decision{}, err
	}
	if !m.RevokedAt.IsZero() && !now.Before(m.RevokedAt) {
		return Decision{}, fmt.Errorf("%w: revoked %s", ErrRevoked, m.RevokedAt.Format(time.RFC3339))
	}
	if m.Suspended {
		return Decision{}, ErrSuspended
	}

	if org.Closed {
		return Decision{}, ErrOrgClosed
	}
	if org.Suspended && !isTeardown(perm) {
		return Decision{}, ErrOrgSuspended
	}

	// An explicit deny is the most specific statement available and is checked
	// before the role's grants, so a deny cannot be overridden by a broader allow.
	if repoID != "" {
		for _, g := range s.Grants {
			if g.Deny && g.OrgID == orgID && g.RepoID == repoID && g.PrincipalID == principalID && g.Permission == perm {
				return Decision{Role: m.Role}, fmt.Errorf("%w: %s on %s", ErrDenied, perm, repoID)
			}
		}
	}
	if m.Role.Effective(perm) {
		return Decision{Allowed: true, Role: m.Role, Reason: fmt.Sprintf("%s role grants %s", m.Role, perm)}, nil
	}
	if repoID != "" {
		for _, g := range s.Grants {
			if !g.Deny && g.OrgID == orgID && g.RepoID == repoID && g.PrincipalID == principalID && g.Permission == perm {
				return Decision{Allowed: true, Role: m.Role, Reason: fmt.Sprintf("repository grant on %s", repoID)}, nil
			}
		}
	}
	return Decision{Role: m.Role}, fmt.Errorf("%s does not grant %s", m.Role, perm)
}

func knownPermission(p Permission) bool {
	for _, known := range AllPermissions() {
		if known == p {
			return true
		}
	}
	return false
}

func isTeardown(p Permission) bool {
	for _, t := range TeardownPermissions {
		if t == p {
			return true
		}
	}
	return false
}

// ValidateGrant refuses a grant that crosses organizations or names a permission the
// system does not implement. This is the code-side counterpart of the composite
// foreign keys the schema enforces: a grant row must reference a repository belonging
// to the same organization as the member it names.
func (s Snapshot) ValidateGrant(g Grant) error {
	if !knownPermission(g.Permission) {
		return fmt.Errorf("%w: %s", ErrUnknownPermission, g.Permission)
	}
	o, err := s.org(g.OrgID)
	if err != nil {
		return err
	}
	if o.Closed {
		return fmt.Errorf("%w: %s", ErrOrgClosed, g.OrgID)
	}
	if _, err := s.membership(g.PrincipalID, g.OrgID); err != nil {
		return err
	}
	return nil
}

// Members lists a organization's members in a stable order.
func (s Snapshot) Members(orgID string) []Membership {
	var out []Membership
	for _, m := range s.Memberships {
		if m.OrgID == orgID {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PrincipalID < out[j].PrincipalID })
	return out
}

// Owners counts the memberships that can administer the organization.
func (s Snapshot) Owners(orgID string, now time.Time) int {
	n := 0
	for _, m := range s.Members(orgID) {
		if m.Role == RoleOwner && m.Active(now) {
			n++
		}
	}
	return n
}

// RemoveMember ends a membership.
//
// Three refusals, each for a different reason. Removing the last owner locks
// everybody out of billing and membership with no way back in but support. Changing an
// owner is the owner's own privilege, because an admin demoting an owner is a
// takeover. And service principals are revoked, never demoted, because a credential
// holding RoleOwner could grant itself anything.
func (s Snapshot) RemoveMember(orgID, principalID, actorID string, now time.Time) error {
	target, err := s.membership(principalID, orgID)
	if err != nil {
		return err
	}
	actor, err := s.membership(actorID, orgID)
	if err != nil {
		return err
	}
	if actor.Role != RoleOwner && actor.Role != RoleAdmin {
		return fmt.Errorf("%w: %s", ErrNotAnAdmin, actor.Role)
	}
	if target.Role == RoleOwner {
		if actor.Role != RoleOwner {
			return fmt.Errorf("%w: %s is an owner", ErrOwnerIsProtected, principalID)
		}
		if s.Owners(orgID, now) <= 1 {
			return ErrLastOwner
		}
	}
	return nil
}

// GrantOwnership promotes a human member to owner.
func (s Snapshot) GrantOwnership(orgID, principalID, actorID string, now time.Time) error {
	target, err := s.membership(principalID, orgID)
	if err != nil {
		return err
	}
	p, ok := s.LookupPrincipal(principalID)
	if !ok {
		return ErrNotAMember
	}
	// Only a person can own an organization. A credential that owns one can grant
	// itself anything and there is no human to answer for it.
	if p.Kind == PrincipalService {
		return fmt.Errorf("%w: %s", ErrServicePrincipalCannotOwn, principalID)
	}
	actor, err := s.membership(actorID, orgID)
	if err != nil {
		return err
	}
	if actor.Role != RoleOwner {
		return fmt.Errorf("%w: %s", ErrNotAnOwner, actor.Role)
	}
	if !target.Active(now) {
		return ErrRevoked
	}
	return nil
}

// CreateInvitation returns an invitation and its token. Only the token hash is
// returned; the token itself is shown to the customer once and never stored, so a
// database dump does not hand out membership.
func CreateInvitation(orgID, email string, role OrgRole, invitedBy string, token string, now time.Time, ttl time.Duration) (Invitation, error) {
	if orgID == "" || email == "" || token == "" || invitedBy == "" {
		return Invitation{}, ErrInvalidInvitation
	}
	if !role.Valid() || role == RoleOwner {
		// An invitation that grants ownership lets whoever holds the token become
		// untouchable. Ownership is granted deliberately after joining.
		return Invitation{}, fmt.Errorf("%w: cannot invite as %s", ErrInvalidInvitation, role)
	}
	if ttl <= 0 {
		ttl = 14 * 24 * time.Hour
	}
	return Invitation{
		TokenHash: HashToken(token),
		OrgID:     orgID,
		Email:     email,
		Role:      role,
		InvitedBy: invitedBy,
		ExpiresAt: now.Add(ttl),
	}, nil
}

// HashToken is the stored form of an invitation token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Accept validates a token and returns the membership it creates.
//
// Single use, expiring, and bound to the email that was invited: a token forwarded to
// a colleague must not create an account for the person who forwards it.
func (s Snapshot) Accept(token string, now time.Time) (Membership, Invitation, error) {
	if token == "" {
		return Membership{}, Invitation{}, ErrInvalidInvitation
	}
	hash := HashToken(token)
	var inv Invitation
	var ok bool
	for _, i := range s.Invitations {
		if i.TokenHash == hash {
			inv, ok = i, true
		}
	}
	if !ok {
		return Membership{}, Invitation{}, ErrInvalidInvitation
	}
	if !inv.AcceptedAt.IsZero() || inv.Revoked {
		return Membership{}, Invitation{}, ErrInvitationUsed
	}
	if !now.Before(inv.ExpiresAt) {
		return Membership{}, Invitation{}, ErrInvitationExpired
	}
	// The invited email must already be verified by the identity provider. An
	// invitation to an address nobody has proven is an open door with a delay on it.
	p, found := s.principalByEmail(inv.Email)
	if !found {
		return Membership{}, Invitation{}, fmt.Errorf("%w: %s has no verified account", ErrInvalidInvitation, inv.Email)
	}
	if _, err := s.membership(p.ID, inv.OrgID); err == nil {
		return Membership{}, Invitation{}, fmt.Errorf("%w: already a member", ErrNotAMember)
	}
	return Membership{PrincipalID: p.ID, OrgID: inv.OrgID, Role: inv.Role}, inv, nil
}

func (s Snapshot) principalByEmail(email string) (Principal, bool) {
	for _, p := range s.Principals {
		if p.Kind == PrincipalHuman && strings.EqualFold(p.Email, email) {
			return p, true
		}
	}
	return Principal{}, false
}
