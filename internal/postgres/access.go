package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/access"
)

// AccessStore reads and writes organization access state in the platform database.
//
// The one invariant this package exists to hold: every statement runs inside a
// transaction that has set app.organization_id, so the row level security policies
// from migration 0003 apply to all of them. A store method that opened its own
// connection without that setting would read every organization's rows, and would do
// so without an error — which is why the tenant is a required argument everywhere
// rather than something the caller may forget on one path.
//
// The policy rules themselves live in internal/access and are not reimplemented here.
// Mutations load the snapshot, apply the same rule the HTTP layer would, and persist
// the result, so there is one implementation of "may this person invite somebody"
// rather than two that disagree.
type AccessStore struct {
	db *sql.DB
}

// NewAccessStore returns the access store.
func NewAccessStore(db *sql.DB) (*AccessStore, error) {
	// A nil handle here would panic on first use, in the middle of a request, on a
	// path nobody tested. Refusing at construction puts the failure at wiring time.
	if db == nil {
		return nil, errors.New("a database handle is required")
	}
	return &AccessStore{db: db}, nil
}

// Organization lifecycle values, as constrained by the organizations.status CHECK.
const (
	statusProvisioning = "provisioning"
	statusTrial        = "trial"
	statusActive       = "active"
	statusRestricted   = "restricted"
	statusClosing      = "closing"
	statusClosed       = "closed"
)

// OrganizationFromStatus maps a stored lifecycle value onto the policy view.
//
// The schema already carries a richer lifecycle than a pair of flags, so the flags are
// derived here rather than stored twice. Restricting an organization stops new work
// but keeps teardown available, which is the whole point: a customer who owes money
// still has to be able to delete their environments. Closing means the tenant has been
// verified and emptied, so nothing new exists either way.
func OrganizationFromStatus(id, status string) access.Org {
	org := access.Org{ID: id}
	switch status {
	case statusRestricted, statusClosing:
		org.Suspended = true
	case statusClosed:
		org.Closed = true
	}
	return org
}

// OrganizationStatus names a lifecycle state, for callers that change one.
func OrganizationStatus(o access.Org) string {
	switch {
	case o.Closed:
		return statusClosed
	case o.Suspended:
		return statusRestricted
	default:
		return statusActive
	}
}

// The set of statuses this store can read back. Exported so a caller validating input
// is using the same list the schema constrains rather than a hand-copied one.
var organizationStatuses = []string{
	statusProvisioning, statusTrial, statusActive, statusRestricted, statusClosing, statusClosed,
}

// OrganizationStatuses returns the lifecycle values the schema allows.
func OrganizationStatuses() []string {
	out := make([]string, len(organizationStatuses))
	copy(out, organizationStatuses)
	return out
}

// AcceptsWork reports whether a lifecycle status permits new environments.
func AcceptsWork(status string) bool {
	return status == statusActive || status == statusTrial
}

// A context carrying a transaction is returned so a caller cannot accidentally run a
// second statement outside it: everything for one decision happens in one transaction
// or not at all.
func (s *AccessStore) withTenant(ctx context.Context, orgID string, fn func(context.Context, *sql.Tx) error) error {
	if strings.TrimSpace(orgID) == "" {
		// No tenant means no policy. Rather than defaulting to "no rows" or "all
		// rows", the call is refused.
		return errors.New("an organization is required: a query without a tenant cannot be made safe by policy")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tenant transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.organization_id', $1, true)`, orgID); err != nil {
		return fmt.Errorf("set tenant: %w", err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tenant transaction: %w", err)
	}
	return nil
}

// LoadSnapshot reads one organization's access state.
//
// It reads through the tenant policy rather than filtering in Go. The policy is the
// thing that makes a missing filter harmless; filtering afterwards means every future
// query has to remember, and forgetting is silent.
func (s *AccessStore) LoadSnapshot(ctx context.Context, orgID string) (access.Snapshot, error) {
	var snap access.Snapshot
	err := s.withTenant(ctx, orgID, func(ctx context.Context, tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT id, status FROM organizations WHERE id = $1`, orgID)
		var orgIDOut, status string
		if err := row.Scan(&orgIDOut, &status); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: %s", access.ErrNotAMember, orgID)
			}
			return fmt.Errorf("read organization: %w", err)
		}
		snap.Orgs = append(snap.Orgs, OrganizationFromStatus(orgIDOut, status))

		rows, err := tx.QueryContext(ctx, `
			SELECT p.id, p.email, m.role, m.status, m.updated_at
			  FROM memberships m
			  JOIN principals p ON p.id = m.principal_id
			 WHERE m.organization_id = $1
			 ORDER BY m.principal_id`, orgID)
		if err != nil {
			return fmt.Errorf("read memberships: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var pid, email, role, status string
			var updatedAt time.Time
			if err := rows.Scan(&pid, &email, &role, &status, &updatedAt); err != nil {
				return fmt.Errorf("scan membership: %w", err)
			}
			m := access.Membership{
				PrincipalID: pid, OrgID: orgID, Role: access.OrgRole(role),
				Suspended: status == "inactive",
			}
			// The schema models revocation as a status rather than a timestamp, so the
			// Go view of "revoked" is derived here instead of being stored twice.
			if status == "inactive" {
				m.RevokedAt = updatedAt
			}
			snap.Memberships = append(snap.Memberships, m)
			snap.Principals = append(snap.Principals, access.Principal{
				ID: pid, Kind: access.PrincipalHuman, Email: email,
			})
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("read memberships: %w", err)
		}

		grantRows, err := tx.QueryContext(ctx, `
			SELECT repository_id, principal_id, permission, deny
			  FROM repository_grants
			 WHERE organization_id = $1`, orgID)
		if err != nil {
			return fmt.Errorf("read repository grants: %w", err)
		}
		defer grantRows.Close()
		for grantRows.Next() {
			var repoID, principalID, permission string
			var deny bool
			if err := grantRows.Scan(&repoID, &principalID, &permission, &deny); err != nil {
				return fmt.Errorf("scan repository grant: %w", err)
			}
			snap.Grants = append(snap.Grants, access.Grant{
				OrgID: orgID, RepoID: repoID, PrincipalID: principalID,
				Permission: access.Permission(permission), Deny: deny,
			})
		}
		if err := grantRows.Err(); err != nil {
			return fmt.Errorf("read repository grants: %w", err)
		}

		inviteRows, err := tx.QueryContext(ctx, `
			SELECT token_hash, email, role, COALESCE(invited_by::text, ''),
			       expires_at, accepted_at, revoked_at
			  FROM invitations
			 WHERE organization_id = $1`, orgID)
		if err != nil {
			return fmt.Errorf("read invitations: %w", err)
		}
		defer inviteRows.Close()
		for inviteRows.Next() {
			var inv access.Invitation
			var expires time.Time
			var accepted, revoked sql.NullTime
			if err := inviteRows.Scan(&inv.TokenHash, &inv.Email, &inv.Role, &inv.InvitedBy,
				&expires, &accepted, &revoked); err != nil {
				return fmt.Errorf("scan invitation: %w", err)
			}
			inv.OrgID = orgID
			inv.ExpiresAt = expires
			if accepted.Valid {
				inv.AcceptedAt = accepted.Time
			}
			inv.Revoked = revoked.Valid
			snap.Invitations = append(snap.Invitations, inv)
		}
		if err := inviteRows.Err(); err != nil {
			return fmt.Errorf("read invitations: %w", err)
		}
		return nil
	})
	return snap, err
}

// Invite issues an invitation after applying the same policy the HTTP layer would.
func (s *AccessStore) Invite(ctx context.Context, orgID, email, inviterID, token string, role access.OrgRole, ttl time.Duration) (access.Invitation, error) {
	snap, err := s.LoadSnapshot(ctx, orgID)
	if err != nil {
		return access.Invitation{}, err
	}
	// The rule is applied in one place. This store does not get its own, looser
	// version of "who may invite".
	inv, err := snap.Invite(orgID, email, inviterID, token, role, time.Now().UTC(), ttl)
	if err != nil {
		return access.Invitation{}, err
	}
	err = s.withTenant(ctx, orgID, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO invitations (organization_id, token_hash, email, role, invited_by, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			orgID, inv.TokenHash, inv.Email, inv.Role, inv.InvitedBy, inv.ExpiresAt)
		if err != nil {
			return fmt.Errorf("insert invitation: %w", err)
		}
		return nil
	})
	if err != nil {
		return access.Invitation{}, err
	}
	return inv, nil
}

// AcceptInvitation redeems a token exactly once.
//
// The update is conditional on the invitation still being unused, so two concurrent
// redemptions of the same token produce one membership rather than two. Checking
// first and inserting afterwards would let both succeed.
func (s *AccessStore) AcceptInvitation(ctx context.Context, orgID, tokenHash, email string, principalID string, role access.OrgRole, now time.Time) error {
	return s.withTenant(ctx, orgID, func(ctx context.Context, tx *sql.Tx) error {
		var expires time.Time
		var accepted sql.NullTime
		var revoked sql.NullTime
		err := tx.QueryRowContext(ctx, `
			SELECT expires_at, accepted_at, revoked_at
			  FROM invitations
			 WHERE organization_id = $1 AND token_hash = $2`,
			orgID, tokenHash).Scan(&expires, &accepted, &revoked)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: unknown token", access.ErrInvalidInvitation)
			}
			return fmt.Errorf("read invitation: %w", err)
		}
		if accepted.Valid {
			return access.ErrInvitationUsed
		}
		if revoked.Valid {
			return access.ErrInvitationUsed
		}
		if !now.Before(expires) {
			return access.ErrInvitationExpired
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE invitations SET accepted_at = $1
			 WHERE organization_id = $2 AND token_hash = $3 AND accepted_at IS NULL`,
			now.UTC(), orgID, tokenHash)
		if err != nil {
			return fmt.Errorf("mark invitation accepted: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			// Somebody else redeemed it between the read and the update.
			return access.ErrInvitationUsed
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO memberships (organization_id, principal_id, role)
			VALUES ($1,$2,$3)
			ON CONFLICT (organization_id, principal_id) DO NOTHING`,
			orgID, principalID, role); err != nil {
			return fmt.Errorf("create membership: %w", err)
		}
		return nil
	})
}

// PutRepositoryGrant records an allow or a deny.
//
// Upsert rather than insert: changing a rule is how deny becomes allow, and the change
// has to be expressible without deleting the row first, because a delete-then-insert
// leaves a window where neither exists.
func (s *AccessStore) PutRepositoryGrant(ctx context.Context, orgID, repoID, principalID string, perm access.Permission, deny bool) error {
	snap, err := s.LoadSnapshot(ctx, orgID)
	if err != nil {
		return err
	}
	// ValidateGrant is the same check the migration's composite foreign keys make.
	// Running it first turns a constraint violation into a typed refusal.
	if err := snap.ValidateGrant(access.Grant{
		OrgID: orgID, RepoID: repoID, PrincipalID: principalID, Permission: perm,
	}); err != nil {
		return err
	}
	return s.withTenant(ctx, orgID, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO repository_grants (organization_id, repository_id, principal_id, permission, deny)
			VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (repository_id, principal_id, permission)
			DO UPDATE SET deny = EXCLUDED.deny`,
			orgID, repoID, principalID, perm, deny)
		if err != nil {
			return fmt.Errorf("write repository grant: %w", err)
		}
		return nil
	})
}

// RevokeMember ends a membership after checking the same rules as the policy layer.
//
// The membership row is kept and marked inactive rather than deleted: the record of
// who removed whom is evidence, and deleting the row would delete it with them.
//
// That has a consequence the foreign keys do not cover. The grants carry
// ON DELETE CASCADE, which fires when a membership row is deleted — and revocation
// deliberately does not delete one. So the grants are withdrawn explicitly here. The
// policy layer would refuse a revoked member anyway, which is why this is not an
// immediate hole, but a grant row that outlives the relationship it was granted by is
// a credential waiting for the next bug.
func (s *AccessStore) RevokeMember(ctx context.Context, orgID, principalID, actorID string, now time.Time) error {
	snap, err := s.LoadSnapshot(ctx, orgID)
	if err != nil {
		return err
	}
	if err := snap.RemoveMember(orgID, principalID, actorID, now); err != nil {
		return err
	}
	return s.withTenant(ctx, orgID, func(ctx context.Context, tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE memberships SET status = 'inactive', updated_at = $1
			 WHERE organization_id = $2 AND principal_id = $3 AND status <> 'inactive'`,
			now.UTC(), orgID, principalID)
		if err != nil {
			return fmt.Errorf("revoke membership: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			// A retry of an already-revoked membership is not a failure, but it must
			// not be reported as a success either: the caller cannot tell a revocation
			// that happened from one that did not.
			return fmt.Errorf("%w: %s was already inactive", access.ErrRevoked, principalID)
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM repository_grants WHERE organization_id = $1 AND principal_id = $2`,
			orgID, principalID); err != nil {
			return fmt.Errorf("withdraw repository grants: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM project_grants WHERE organization_id = $1 AND principal_id = $2`,
			orgID, principalID); err != nil {
			return fmt.Errorf("withdraw project grants: %w", err)
		}
		return nil
	})
}
