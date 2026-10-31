package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/sanskarpan/Ghostlight/internal/billing"
	"github.com/sanskarpan/Ghostlight/internal/subscription"
)

// BillingStore persists billing subscription records and webhook delivery
// IDs in PostgreSQL. It implements billing.RecordStore.
//
// Tenant rule, matching the access tables: every statement runs inside a
// transaction that sets app.organization_id to the customer, and the tables
// carry FORCE row level security on customer_id. A code path that forgets
// the tenant gets zero rows rather than another tenant's — forgetting is
// silent nowhere.
//
// Delivery IDs are the apply-once memory made durable: Mark inserts the
// event ID and reports whether this call inserted it, atomically, so two
// racing deliveries converge instead of double-applying. A failed apply
// records nothing, so a crash between applying and recording re-applies
// identically rather than losing the event; the intents are dated from the
// event, not the wall clock, which is what makes that safe.
type BillingStore struct {
	db *sql.DB
}

// NewBillingStore returns a store over db. A nil database is refused:
// without one every read would be an absence and every write would be lost,
// and a store that silently holds nothing is worse than no store.
func NewBillingStore(db *sql.DB) (*BillingStore, error) {
	if db == nil {
		return nil, errors.New("billing store requires a database: a nil store would answer every lookup with absence")
	}
	return &BillingStore{db: db}, nil
}

// withCustomer runs fn inside a transaction scoped to the customer. An
// empty customer is refused rather than defaulted to no-rows or all-rows:
// neither default is safe, and the refusal names the actual problem.
func (s *BillingStore) withCustomer(ctx context.Context, customerID string, fn func(context.Context, *sql.Tx) error) error {
	if strings.TrimSpace(customerID) == "" {
		return errors.New("a customer is required: a billing query without a customer cannot be made safe by policy")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin billing transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.organization_id', $1, true)`, customerID); err != nil {
		return fmt.Errorf("set billing customer: %w", err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit billing transaction: %w", err)
	}
	return nil
}

// Get returns the subscription record, or billing.ErrNotFound when no
// record exists for this customer and subscription. A record owned by
// another customer is invisible to this lookup even though the id matches —
// that is the row policy doing its job, not a missing record.
func (s *BillingStore) Get(ctx context.Context, customerID, subscriptionID string) (subscription.Subscription, error) {
	var out subscription.Subscription
	err := s.withCustomer(ctx, customerID, func(ctx context.Context, tx *sql.Tx) error {
		var raw []byte
		err := tx.QueryRowContext(ctx,
			`SELECT record FROM billing_subscriptions WHERE provider_subscription_id = $1`,
			subscriptionID).Scan(&raw)
		if err == sql.ErrNoRows {
			return billing.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read subscription record: %w", err)
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return fmt.Errorf("stored subscription record does not parse: %w", err)
		}
		if strings.TrimSpace(out.ID) == "" || strings.TrimSpace(out.CustomerID) == "" {
			return fmt.Errorf("stored subscription record names nothing: refusing a record that cannot be resolved")
		}
		return nil
	})
	if err != nil {
		return subscription.Subscription{}, err
	}
	return out, nil
}

// Put creates or replaces the subscription record. The document is
// validated to round-trip before anything is written: a record that cannot
// survive its own serialization is refused rather than stored corrupt.
func (s *BillingStore) Put(ctx context.Context, sub subscription.Subscription) error {
	if strings.TrimSpace(sub.ID) == "" || strings.TrimSpace(sub.CustomerID) == "" {
		return fmt.Errorf("%w: subscription record names no id or no customer", subscription.ErrInvalidFact)
	}
	raw, err := json.Marshal(sub)
	if err != nil {
		return fmt.Errorf("subscription record does not serialize: %w", err)
	}
	var check subscription.Subscription
	if err := json.Unmarshal(raw, &check); err != nil {
		return fmt.Errorf("subscription record does not survive a round trip: %w", err)
	}
	return s.withCustomer(ctx, sub.CustomerID, func(ctx context.Context, tx *sql.Tx) error {
		var updated bool
		err := tx.QueryRowContext(ctx, `
			UPDATE billing_subscriptions
			   SET plan_id = $3, record = $4, updated_at = now()
			 WHERE provider_subscription_id = $1 AND customer_id = $2
			RETURNING true`,
			sub.ID, sub.CustomerID, string(sub.Plan.ID), string(raw)).Scan(&updated)
		switch {
		case err == nil:
			return nil
		case err == sql.ErrNoRows:
			// Absent for this customer: fall through to insert.
		default:
			return fmt.Errorf("update subscription record: %w", err)
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO billing_subscriptions (provider_subscription_id, customer_id, plan_id, record)
			VALUES ($1, $2, $3, $4)`,
			sub.ID, sub.CustomerID, string(sub.Plan.ID), string(raw))
		if err != nil {
			// A concurrent writer won the race between the update and the
			// insert. Retrying once converges: the row now exists.
			if isConflict(err) {
				_, uerr := tx.ExecContext(ctx, `
					UPDATE billing_subscriptions
					   SET plan_id = $3, record = $4, updated_at = now()
					 WHERE provider_subscription_id = $1 AND customer_id = $2`,
					sub.ID, sub.CustomerID, string(sub.Plan.ID), string(raw))
				if uerr != nil {
					return fmt.Errorf("update subscription record on retry: %w", uerr)
				}
				return nil
			}
			return fmt.Errorf("insert subscription record: %w", err)
		}
		return nil
	})
}

// Seen reports whether the event ID was recorded.
func (s *BillingStore) Seen(ctx context.Context, customerID, eventID string) (bool, error) {
	var seen bool
	err := s.withCustomer(ctx, customerID, func(ctx context.Context, tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx,
			`SELECT true FROM billing_delivery_ids WHERE event_id = $1`,
			eventID).Scan(&seen)
		if err == sql.ErrNoRows {
			seen = false
			return nil
		}
		return err
	})
	if err != nil {
		return false, fmt.Errorf("check delivery id: %w", err)
	}
	return seen, nil
}

// Mark records the event ID and reports whether this call recorded it. The
// insert is atomic — check-and-insert in one statement — so two racing
// deliveries converge: exactly one reports true. A false return with a nil
// error means another delivery won: acknowledge without applying.
func (s *BillingStore) Mark(ctx context.Context, customerID, eventID, subscriptionID string) (bool, error) {
	if strings.TrimSpace(eventID) == "" {
		return false, fmt.Errorf("%w: a delivery that cannot name itself cannot be deduplicated", subscription.ErrInvalidFact)
	}
	var recorded bool
	err := s.withCustomer(ctx, customerID, func(ctx context.Context, tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO billing_delivery_ids (event_id, customer_id, subscription_id)
			VALUES ($1, $2, $3) ON CONFLICT (event_id) DO NOTHING`,
			eventID, customerID, subscriptionID)
		if err != nil {
			return fmt.Errorf("record delivery id: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("delivery id receipt: %w", err)
		}
		recorded = n == 1
		return nil
	})
	if err != nil {
		return false, err
	}
	return recorded, nil
}

// isConflict reports a unique-violation error: another writer won the race
// for this key. Retrying once converges instead of failing a delivery that
// is already recorded.
func isConflict(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}
