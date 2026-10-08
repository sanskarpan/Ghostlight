// Package postgres persists the action ledger and the generation fence.
//
// This package is where the invariants in SPEC.md stop being documentation and
// start being enforced by a database. Three properties matter and each is
// enforced in SQL rather than in application code, because application code runs
// in more places and races more often:
//
//   - Claiming an action is a single UPDATE guarded by a WHERE clause that names
//     the expected owner, epoch, state and generation. Two controllers racing for
//     the same action produce one winner, not two.
//   - Committing a result requires the same fence. A stale completion cannot
//     mark a newer generation ready, no matter how it got here.
//   - Claiming increments the epoch, so a lease expiry never silently authorises
//     a takeover. The previous runner must be terminated and observed first.
//
// A database lease fences ledger writes only. It does not fence a cloud API call,
// which is why a runner holding a stale epoch is terminated before a replacement
// starts rather than being replaced on expiry alone.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/actions"
)

var (
	// ErrAlreadyClaimed means another controller won the claim. The caller must
	// not retry blindly; it should move on to other work.
	ErrAlreadyClaimed = errors.New("action was claimed by another owner")
	// ErrFenced means the lease or generation no longer matches.
	ErrFenced = actions.ErrFenced
	// ErrNotFound means no such action.
	ErrNotFound = actions.ErrNotFound
	// ErrAlreadyExists means the idempotency key is already present, which is the
	// normal outcome of a redelivered event and must be a no-op rather than an
	// error the caller retries.
	ErrAlreadyExists = actions.ErrAlreadyExists
)

// Store wraps the platform database.
type Store struct {
	db *sql.DB
	// now reads database time. Using the caller's clock would let two controllers
	// disagree about whether a lease has expired.
	now func(ctx context.Context) (time.Time, error)
}

// New builds a store. A nil clock uses database time via now().
func New(db *sql.DB) *Store {
	return &Store{db: db, now: func(ctx context.Context) (time.Time, error) {
		var t time.Time
		if err := db.QueryRowContext(ctx, "SELECT now()").Scan(&t); err != nil {
			return time.Time{}, fmt.Errorf("read database time: %w", err)
		}
		return t.UTC(), nil
	}}
}

// Now returns database time.
func (s *Store) Now(ctx context.Context) (time.Time, error) { return s.now(ctx) }

// InsertAction commits an action intent. It must be called before any external
// call the action represents.
//
// The insert is idempotent on (environment, generation, type, logical key): a
// duplicate delivery resolves to the existing row and ErrAlreadyExists, which the
// caller treats as success.
func (s *Store) InsertAction(ctx context.Context, a *actions.Action) error {
	scope, err := jsonBytes(a.ResourceScope)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO actions
			(environment_id, generation, action_type, logical_key, input_digest,
			 resource_scope, state, next_attempt_at, expected_generation,
			 lease_owner, lease_epoch, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, now(), now())
		ON CONFLICT (environment_id, generation, action_type, logical_key)
		DO NOTHING`,
		a.EnvironmentID, a.Generation, string(a.Type), a.LogicalKey, a.InputDigest,
		scope, string(a.State), a.NextAttemptAt, a.Generation,
		nullIfEmpty(a.Fencing.Owner), a.Fencing.Epoch)
	if err != nil {
		return fmt.Errorf("insert action: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("insert action rows: %w", err)
	}
	if n == 0 {
		// A duplicate logical key. The caller must load the existing row rather
		// than re-running the work.
		return ErrAlreadyExists
	}
	return nil
}

// Claim takes the lease on one runnable action and increments the epoch.
//
// The guard names every condition that must hold: the action must be runnable,
// not due until the recorded time, and either unowned or owned by the caller.
// The epoch increment is what makes a superseded lease detectable.
func (s *Store) Claim(ctx context.Context, envID string, generation uint64, actionType actions.Type, logicalKey string, owner string) (actions.Lease, int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return actions.Lease{}, 0, fmt.Errorf("begin claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var epoch int64
	var attempt int
	err = tx.QueryRowContext(ctx, `
		UPDATE actions
		SET state = 'running',
		    attempts = attempts + 1,
		    lease_owner = $5,
		    lease_epoch = lease_epoch + 1,
		    updated_at = now()
		WHERE environment_id = $1
		  AND generation = $2
		  AND action_type = $3
		  AND logical_key = $4
		  AND next_attempt_at <= now()
		  AND state = 'planned'
		  AND coalesce(nullif(lease_owner, ''), '') IN ('', $5)
		RETURNING lease_epoch, attempts`,
		envID, generation, string(actionType), logicalKey, owner,
	).Scan(&epoch, &attempt)
	if errors.Is(err, sql.ErrNoRows) {
		// Either it does not exist, is not due, is already running, or another
		// owner holds it. The caller distinguishes by loading it.
		return actions.Lease{}, 0, s.classifyClaimFailure(ctx, tx, envID, generation, actionType, logicalKey)
	}
	if err != nil {
		return actions.Lease{}, 0, fmt.Errorf("claim action: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return actions.Lease{}, 0, fmt.Errorf("commit claim: %w", err)
	}
	return actions.Lease{Owner: owner, Epoch: epoch}, attempt, nil
}

// classifyClaimFailure distinguishes "someone else has it" from "it is not
// runnable yet", because the two need different handling by the caller.
func (s *Store) classifyClaimFailure(ctx context.Context, tx *sql.Tx, envID string, generation uint64, actionType actions.Type, logicalKey string) error {
	var state sql.NullString
	var owner sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT state, lease_owner FROM actions
		WHERE environment_id = $1 AND generation = $2 AND action_type = $3 AND logical_key = $4`,
		envID, generation, string(actionType), logicalKey).Scan(&state, &owner)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("classify claim: %w", err)
	}
	if owner.Valid && owner.String != "" {
		return ErrAlreadyClaimed
	}
	return fmt.Errorf("action is not runnable in state %s", state.String)
}

// CommitResult writes a terminal result under the fence.
//
// Every clause of the WHERE guard must match or nothing is written. This is the
// single most important statement in the package: it is what makes a stale
// completion harmless.
func (s *Store) CommitResult(ctx context.Context, envID string, l actions.Lease, generation uint64, result actions.State, extRef map[string]string) error {
	ref, err := jsonBytes(extRef)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE actions
		SET state = $6,
		    external_ref = COALESCE($7, external_ref),
		    updated_at = now()
		WHERE environment_id = $1
		  AND generation = $2
		  AND lease_owner = $3
		  AND lease_epoch = $4
		  AND expected_generation = $5
		  AND state = 'running'`,
		envID, generation, l.Owner, l.Epoch, generation, string(result), ref)
	if err != nil {
		return fmt.Errorf("commit result: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("commit result rows: %w", err)
	}
	if n == 0 {
		// The fence rejected the write. Do not report success.
		return ErrFenced
	}
	return nil
}

// MarkUncertain records that an external call may or may not have taken effect.
//
// It is a distinct terminal-ish state rather than a failure, and the action is
// left unowned so an observer can resolve it. Resolving requires observation, so
// this never routes back into Claim.
func (s *Store) MarkUncertain(ctx context.Context, envID string, l actions.Lease, generation uint64, cause string, nextAttempt time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE actions
		SET state = 'uncertain',
		    last_error = $6,
		    next_attempt_at = $7,
		    lease_owner = NULL,
		    updated_at = now()
		WHERE environment_id = $1
		  AND generation = $2
		  AND lease_owner = $3
		  AND lease_epoch = $4
		  AND expected_generation = $5
		  AND state = 'running'`,
		envID, generation, l.Owner, l.Epoch, generation, cause, nextAttempt)
	if err != nil {
		return fmt.Errorf("mark uncertain: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrFenced
	}
	return nil
}

// ResolveUncertain applies an observation outcome to an uncertain action.
//
//   - Existed resolves to succeeded and records the observed reference.
//   - Gone resolves to planned, because verified absence is what makes a retry
//     safe. Resolving to failed here would mean the observation that made the
//     retry safe also prevented it.
//   - Unresolved leaves the action uncertain. Staying uncertain is correct.
func (s *Store) ResolveUncertain(ctx context.Context, envID string, generation uint64, obs actions.Observe) error {
	ref, err := jsonBytes(obs.Reference)
	if err != nil {
		return err
	}
	var target actions.State
	switch {
	case obs.Existed:
		target = actions.StateSucceeded
	case obs.Gone:
		target = actions.StatePlanned
	default:
		// Do not guess. A permission failure is not absence.
		return actions.ErrNotUncertain
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE actions
		SET state = $3,
		    external_ref = COALESCE($4, external_ref),
		    last_error = $5,
		    next_attempt_at = now(),
		    updated_at = now()
		WHERE environment_id = $1
		  AND generation = $2
		  AND state = 'uncertain'`,
		envID, generation, string(target), ref, obs.Reason)
	if err != nil {
		return fmt.Errorf("resolve uncertain: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Action is the persisted shape of a ledger row.
type Action struct {
	ID            string
	EnvironmentID string
	Generation    uint64
	Type          actions.Type
	LogicalKey    string
	InputDigest   string
	State         actions.State
	Attempts      int
	NextAttemptAt time.Time
	LeaseOwner    sql.NullString
	LeaseEpoch    int64
	LastError     sql.NullString
	ExternalRef   map[string]string
}

// Load reads one action.
func (s *Store) Load(ctx context.Context, envID string, generation uint64, actionType actions.Type, logicalKey string) (*Action, error) {
	var a Action
	var extRef []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT id::text, environment_id::text, generation, action_type, logical_key,
		       input_digest, state, attempts, next_attempt_at, lease_owner,
		       lease_epoch, last_error, external_ref
		FROM actions
		WHERE environment_id = $1 AND generation = $2 AND action_type = $3 AND logical_key = $4`,
		envID, generation, string(actionType), logicalKey).
		Scan(&a.ID, &a.EnvironmentID, &a.Generation, &a.Type, &a.LogicalKey,
			&a.InputDigest, &a.State, &a.Attempts, &a.NextAttemptAt, &a.LeaseOwner,
			&a.LeaseEpoch, &a.LastError, &extRef)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load action: %w", err)
	}
	if len(extRef) > 0 {
		if err := jsonUnmarshal(extRef, &a.ExternalRef); err != nil {
			return nil, fmt.Errorf("decode external_ref: %w", err)
		}
	}
	return &a, nil
}

// ClaimableActions returns up to limit runnable actions, ordered by due time.
//
// Bounded pages rather than a full scan. At the initial fleet size a full scan
// is an acceptable safety net, but this is the work queue and must not grow with
// the ledger.
func (s *Store) ClaimableActions(ctx context.Context, limit int) ([]Action, error) {
	if limit <= 0 {
		return nil, errors.New("limit must be positive")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id::text, environment_id::text, generation, action_type, logical_key,
		       input_digest, state, attempts, next_attempt_at, lease_owner,
		       lease_epoch, last_error
		FROM actions
		WHERE state = 'planned'
		  AND next_attempt_at <= now()
		  AND coalesce(nullif(lease_owner, ''), '') = ''
		ORDER BY next_attempt_at
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("claimable actions: %w", err)
	}
	defer rows.Close()

	var out []Action
	for rows.Next() {
		var a Action
		if err := rows.Scan(&a.ID, &a.EnvironmentID, &a.Generation, &a.Type, &a.LogicalKey,
			&a.InputDigest, &a.State, &a.Attempts, &a.NextAttemptAt, &a.LeaseOwner,
			&a.LeaseEpoch, &a.LastError); err != nil {
			return nil, fmt.Errorf("scan claimable action: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UncertainActions returns actions awaiting observation.
//
// This is the observe-before-retry work list. It must never be starved: an action
// left uncertain is an action whose external effect is unknown, and an unknown
// effect is exactly what leaks resources.
func (s *Store) UncertainActions(ctx context.Context, limit int) ([]Action, error) {
	if limit <= 0 {
		return nil, errors.New("limit must be positive")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id::text, environment_id::text, generation, action_type, logical_key,
		       input_digest, state, attempts, next_attempt_at, lease_owner,
		       lease_epoch, last_error
		FROM actions
		WHERE state = 'uncertain'
		ORDER BY next_attempt_at
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("uncertain actions: %w", err)
	}
	defer rows.Close()

	var out []Action
	for rows.Next() {
		var a Action
		if err := rows.Scan(&a.ID, &a.EnvironmentID, &a.Generation, &a.Type, &a.LogicalKey,
			&a.InputDigest, &a.State, &a.Attempts, &a.NextAttemptAt, &a.LeaseOwner,
			&a.LeaseEpoch, &a.LastError); err != nil {
			return nil, fmt.Errorf("scan uncertain action: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// nullIfEmpty maps an empty string to SQL NULL.
//
// An unowned action must store a genuinely absent owner rather than an empty
// string. A row that looks owned while carrying no owner makes every ownership
// predicate wrong in a way that is invisible until an action never runs.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// jsonBytes encodes a value for a jsonb column, distinguishing "absent" from
// "empty". A nil map becomes SQL NULL so COALESCE keeps the previous value.
func jsonBytes(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	b, err := jsonMarshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode json: %w", err)
	}
	return b, nil
}
