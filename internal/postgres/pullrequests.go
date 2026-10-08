// Package prrequests persists pull-request state and current-PR resolution.
//
// This is the other half of G1.1: where intake records what a provider asserted,
// this records what is currently true, resolved from an authenticated source.
//
// Two properties matter here. Pull-request state is keyed on repository plus
// number so a late event for an old number cannot overwrite current state, and the
// resolved head is only ever replaced by a newer observation, so a delayed lookup
// result cannot move a pull request backwards.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/prstate"
)

// ErrPullRequestNotFound means no tracked pull request matches.
var ErrPullRequestNotFound = errors.New("pull request not tracked")

// PRStore persists pull-request state.
type PRStore struct {
	db *sql.DB
}

// NewPRStore builds a pull-request store.
func NewPRStore(db *sql.DB) *PRStore { return &PRStore{db: db} }

// Upsert records an observed snapshot for a repository and number.
//
// observed_at is compared against the stored value, so a snapshot that arrives
// late cannot overwrite newer state. This is what makes out-of-order delivery
// harmless without relying on arrival order.
func (s *PRStore) Upsert(ctx context.Context, repoID string, snap prstate.Snapshot) error {
	if repoID == "" {
		return errors.New("repository id is required")
	}
	if snap.Number <= 0 {
		return errors.New("pull request number must be positive")
	}
	if snap.HeadSHA == "" {
		return errors.New("head sha is required; state resolved without an exact head cannot be acted on")
	}
	observedAt := snap.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}

	var orgID string
	if err := s.db.QueryRowContext(ctx,
		`SELECT organization_id::text FROM repositories WHERE id = $1`, repoID).Scan(&orgID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("repository %s is not tracked", repoID)
		}
		return fmt.Errorf("resolve organization: %w", err)
	}

	var closedAt any
	if snap.State == prstate.StateClosed || snap.State == prstate.StateMerged {
		closedAt = observedAt
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pull_requests
			(repository_id, organization_id, number, head_sha, base_sha, state,
			 observed_at, closed_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())
		ON CONFLICT (repository_id, number) DO UPDATE
		SET head_sha = EXCLUDED.head_sha,
		    base_sha = COALESCE(EXCLUDED.base_sha, pull_requests.base_sha),
		    state = EXCLUDED.state,
		    observed_at = EXCLUDED.observed_at,
		    closed_at = COALESCE(EXCLUDED.closed_at, pull_requests.closed_at),
		    updated_at = now()
		WHERE pull_requests.observed_at <= EXCLUDED.observed_at`,
		repoID, orgID, snap.Number, snap.HeadSHA, nullIfEmpty(snap.BaseSHA),
		string(snap.State), observedAt, closedAt)
	if err != nil {
		return fmt.Errorf("upsert pull request: %w", err)
	}
	return nil
}

// CurrentPullRequest satisfies prstate.Lookup.
//
// A tracked pull request is answered from the store. An untracked one is not
// fabricated: the caller is expected to reach the authenticated source and then
// upsert, which keeps "resolved" meaning "confirmed" rather than "assumed".
func (s *PRStore) CurrentPullRequest(ctx context.Context, repositoryRef string, number int) (prstate.Snapshot, error) {
	var snap prstate.Snapshot
	var base sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT r.repository_ref, p.number, p.state, p.head_sha, p.base_sha, p.observed_at
		FROM pull_requests p
		JOIN repositories r ON r.id = p.repository_id
		WHERE r.repository_ref = $1 AND p.number = $2`,
		repositoryRef, number).
		Scan(&snap.RepositoryRef, &snap.Number, &snap.State, &snap.HeadSHA, &base, &snap.ObservedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return prstate.Snapshot{}, fmt.Errorf("%w: %s#%d", ErrPullRequestNotFound, repositoryRef, number)
	}
	if err != nil {
		return prstate.Snapshot{}, fmt.Errorf("current pull request: %w", err)
	}
	if base.Valid {
		snap.BaseSHA = base.String
	}
	return snap, nil
}

// BindEnvironment links a pull request to the environment serving it.
//
// The link is refused for a pull request that is closed: binding an environment to
// a closed pull request is how a destroyed environment gets resurrected through a
// late event.
func (s *PRStore) BindEnvironment(ctx context.Context, repositoryRef string, number int, environmentID string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE pull_requests p
		SET environment_id = $3, updated_at = now()
		FROM repositories r
		WHERE p.repository_id = r.id
		  AND r.repository_ref = $1
		  AND p.number = $2
		  AND p.state = 'open'`, repositoryRef, number, environmentID)
	if err != nil {
		return fmt.Errorf("bind environment: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("cannot bind an environment: %s#%d is unknown or not open", repositoryRef, number)
	}
	return nil
}

// EnvironmentBinding returns the environment currently serving a pull request.
//
// A destroyed environment is reported as Destroyed so the reconciler creates a new
// one rather than reviving a terminal identifier.
func (s *PRStore) EnvironmentBinding(ctx context.Context, repositoryRef string, number int) (*prstate.EnvironmentBinding, error) {
	var b prstate.EnvironmentBinding
	// Read the observed lifecycle as text and compare against the one value that
	// matters here. Comparing against an imported enum type would couple this
	// package to another package's vocabulary for a single value.
	var observed string
	err := s.db.QueryRowContext(ctx, `
		SELECT e.id::text, e.generation, e.observed, e.slug
		FROM pull_requests p
		JOIN repositories r ON r.id = p.repository_id
		JOIN environments e ON e.id = p.environment_id
		WHERE r.repository_ref = $1 AND p.number = $2`,
		repositoryRef, number).
		Scan(&b.EnvironmentID, &b.Generation, &observed, &b.Slug)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("environment binding: %w", err)
	}
	b.Destroyed = observed == "destroyed"
	return &b, nil
}

// ClosePullRequest records a terminal state and returns the environments that now
// need tearing down.
//
// It is a single statement so the state change and the set of affected
// environments cannot disagree.
func (s *PRStore) ClosePullRequest(ctx context.Context, repositoryRef string, number int, state prstate.State) ([]string, error) {
	if state != prstate.StateClosed && state != prstate.StateMerged {
		return nil, fmt.Errorf("close requires a terminal state, got %q", state)
	}
	rows, err := s.db.QueryContext(ctx, `
		UPDATE pull_requests p
		SET state = $3,
		    closed_at = now(),
		    observed_at = now(),
		    updated_at = now()
		FROM repositories r
		WHERE p.repository_id = r.id
		  AND r.repository_ref = $1
		  AND p.number = $2
		RETURNING p.environment_id::text`, repositoryRef, number, string(state))
	if err != nil {
		return nil, fmt.Errorf("close pull request: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id sql.NullString
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan closing environment: %w", err)
		}
		if id.Valid {
			ids = append(ids, id.String)
		}
	}
	return ids, rows.Err()
}
