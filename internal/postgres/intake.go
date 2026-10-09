package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/intake"
)

// intakeStore implements intake.Store against the platform database.
//
// The insert relies on the unique constraint on (provider, delivery_id) rather
// than on a prior SELECT. A read-then-write would race: two concurrent identical
// deliveries could both observe absence and both insert. Letting the database
// arbitrate means exactly one insert succeeds and the other learns it was a
// duplicate from the conflict itself.
// IntakeStore is exported because the controller pass consumes it. The type is
// named for what it is rather than hidden, so its methods can be reached from
// another package without re-declaring an identical interface there.
type IntakeStore struct {
	db       *sql.DB
	provider string
}

// NewIntakeStore builds the intake store for a provider.
func NewIntakeStore(db *sql.DB, provider string) *IntakeStore {
	return &IntakeStore{db: db, provider: provider}
}

// Compile-time check that the store satisfies the interface intake depends on.
var _ intake.Store = (*IntakeStore)(nil)

// Insert persists a verified event, returning false when the delivery was already
// admitted.
//
// A duplicate is not an error: redelivery is normal, and treating it as a failure
// would make the provider retry an event that is already safely stored.
func (s *IntakeStore) Insert(ctx context.Context, e intake.Stored) (bool, error) {
	if s.provider == "" {
		return false, errors.New("provider is required")
	}
	if e.DeliveryID == "" {
		return false, errors.New("delivery id is required")
	}
	if e.PayloadSHA == "" {
		return false, errors.New("payload digest is required; an unverified payload must never be stored")
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO webhook_inbox
			(delivery_id, provider, event_type, installation_ref, repository_ref,
			 payload_digest, signature_verified, replay_rejected, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6, true, false, $7)
		ON CONFLICT (provider, delivery_id) DO NOTHING`,
		e.DeliveryID, s.provider, e.EventType,
		nullIfEmpty(e.Installation), nullIfEmpty(e.Repository),
		e.PayloadSHA, e.ExpiresAt)
	if err != nil {
		return false, fmt.Errorf("insert webhook inbox: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("insert webhook inbox rows: %w", err)
	}
	// Zero rows means the conflict clause matched: this delivery is already stored.
	return n > 0, nil
}

// IntakePending returns admitted events awaiting processing, oldest first.
//
// Processing failures are retried with the same row, so the delivery identifier
// remains the idempotency key across retries rather than a new identity each time.
func (s *IntakeStore) IntakePending(ctx context.Context, limit int) ([]PendingEvent, error) {
	if limit <= 0 {
		return nil, errors.New("limit must be positive")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id::text, delivery_id, event_type, payload_digest,
		       installation_ref, repository_ref, received_at, attempts
		FROM webhook_inbox
		WHERE provider = $1
		  AND processing_status IN ('received','failed')
		  AND next_attempt_at <= now()
		ORDER BY received_at
		LIMIT $2`, s.provider, limit)
	if err != nil {
		return nil, fmt.Errorf("pending intake: %w", err)
	}
	defer rows.Close()

	var out []PendingEvent
	for rows.Next() {
		var e PendingEvent
		if err := rows.Scan(&e.ID, &e.DeliveryID, &e.EventType, &e.PayloadSHA,
			&e.Installation, &e.Repository, &e.ReceivedAt, &e.Attempts); err != nil {
			return nil, fmt.Errorf("scan pending intake: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PendingEvent is an admitted event awaiting processing.
type PendingEvent struct {
	ID           string
	DeliveryID   string
	EventType    string
	PayloadSHA   string
	Installation sql.NullString
	Repository   sql.NullString
	ReceivedAt   time.Time
	Attempts     int
}

// MarkIntakeProcessed records successful handling.
//
// It is refused for a row already recorded as ignored: an ignored event was a
// deliberate decision to do nothing, and later marking it processed would erase
// the reason that decision was recorded.
func (s *IntakeStore) MarkIntakeProcessed(ctx context.Context, deliveryID string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE webhook_inbox
		SET processing_status = 'processed',
		    processed_at = now(),
		    attempts = attempts + 1,
		    processing_error = NULL
		WHERE provider = $1
		  AND delivery_id = $2
		  AND processing_status <> 'ignored'`, s.provider, deliveryID)
	if err != nil {
		return fmt.Errorf("mark intake processed: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkIntakeIgnored records that an event was handled by deciding to do nothing.
//
// A stale or duplicate-meaningful event is a successful outcome, not a failure.
// Recording it as ignored keeps it out of the retry queue while leaving the row
// for audit.
func (s *IntakeStore) MarkIntakeIgnored(ctx context.Context, deliveryID, reason string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE webhook_inbox
		SET processing_status = 'ignored',
		    processed_at = now(),
		    attempts = attempts + 1,
		    processing_error = $3
		WHERE provider = $1 AND delivery_id = $2`, s.provider, deliveryID, reason)
	if err != nil {
		return fmt.Errorf("mark intake ignored: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkIntakeFailed records a failure and schedules a retry.
//
// The row is not deleted on failure, because the delivery identifier is the
// idempotency key: a retry must resolve to the same row, not a new identity.
func (s *IntakeStore) MarkIntakeFailed(ctx context.Context, deliveryID, reason string, nextAttempt time.Time) error {
	// The guard keeps a completed or ignored event from being dragged back into
	// the retry queue by a late-arriving failure report.
	res, err := s.db.ExecContext(ctx, `
		UPDATE webhook_inbox
		SET processing_status = 'failed',
		    attempts = attempts + 1,
		    processing_error = $3,
		    next_attempt_at = $4
		WHERE provider = $1
		  AND delivery_id = $2
		  AND processing_status IN ('received','processing','failed')`,
		s.provider, deliveryID, reason, nextAttempt)
	if err != nil {
		return fmt.Errorf("mark intake failed: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ExpireIntake deletes inbox rows past their retention.
//
// The deletion is bounded and returns how many rows went, so an operator can see
// that retention is actually being applied rather than assumed.
//
// Retention is checked against received_at rather than expires_at, because
// expires_at is computed from receipt by the caller. Checking the caller's
// arithmetic would mean trusting it, and a row recorded with too short a window
// would be deleted immediately instead of persisting for the intended period.
func (s *IntakeStore) ExpireIntake(ctx context.Context, limit int, maxAge time.Duration) (int64, error) {
	if limit <= 0 {
		return 0, errors.New("limit must be positive")
	}
	if maxAge <= 0 {
		return 0, errors.New("max age must be positive")
	}
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM webhook_inbox
		WHERE id IN (
			SELECT id FROM webhook_inbox
			WHERE received_at <= now() - $2::interval
			ORDER BY received_at
			LIMIT $1
		)`, limit, maxAge.String())
	if err != nil {
		return 0, fmt.Errorf("expire intake: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("expire intake rows: %w", err)
	}
	return n, nil
}
