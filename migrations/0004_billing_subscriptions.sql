-- 0004_billing_subscriptions.sql
--
-- Durable home for billing subscription records and webhook delivery IDs,
-- backing the Dodo receiver (internal/dodo) so a restart forgets nothing.
-- The receiver's in-memory map was correct for the test loop and is kept as
-- the no-database fallback; this table is what production reads and writes.
--
-- Tenant rule, matching 0003: customer_id is the billing customer (a
-- provider-side string such as a Dodo customer ID, not the platform's uuid
-- organization key), and every row carries exactly one. The policy compares
-- as text against app.organization_id, which the store sets per transaction
-- exactly like internal/postgres does for the access tables.
-- ---------------------------------------------------------------------------

CREATE TABLE billing_subscriptions (
    -- The provider's subscription identifier (Dodo sub_... / Stripe sub_...).
    -- It is the only stable key across webhook deliveries, retries and
    -- restores, so it is the primary key rather than a generated id.
    provider_subscription_id text PRIMARY KEY,
    -- Platform customer this record belongs to. Every read and write names
    -- it; a row that cannot name its customer cannot be resolved back to
    -- the thing it bills, which is the only reason to record it.
    customer_id              text NOT NULL CHECK (customer_id <> ''),
    -- Approved plan in force, for operator readability. The record of truth
    -- is the JSON document; this column never decides anything.
    plan_id                  text NOT NULL,
    -- The full subscription.Subscription document. Storing the document
    -- rather than a column per field keeps the store open to lifecycle
    -- fields the platform adds later without a migration per field, and the
    -- write path validates the document round-trips before persisting it.
    record                   jsonb NOT NULL,
    updated_at               timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX billing_subscriptions_customer_idx ON billing_subscriptions (customer_id);

ALTER TABLE billing_subscriptions ENABLE ROW LEVEL SECURITY;
-- FORCE so the table owner is also subject to policy, matching 0001/0003. An
-- owner that can bypass its own policy is exactly the connection an attacker
-- with a SQL injection reaches for.
ALTER TABLE billing_subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY billing_subscription_tenant ON billing_subscriptions
    USING (customer_id = nullif(current_setting('app.organization_id', true), ''))
    WITH CHECK (customer_id = nullif(current_setting('app.organization_id', true), ''));

-- ---------------------------------------------------------------------------
-- Webhook delivery IDs
--
-- The apply-once memory, made durable: an event ID recorded here has been
-- applied and must be acknowledged without applying on redelivery. The table
-- holds identifiers and moments only — never payloads — so its growth is
-- bounded by event count, not event size. A failed apply records nothing,
-- so a crash between applying and recording re-applies identically rather
-- than losing the event; the intents are dated from the event, not from the
-- wall clock, which is what makes that re-application safe.
-- ---------------------------------------------------------------------------

CREATE TABLE billing_delivery_ids (
    event_id        text PRIMARY KEY,
    customer_id     text NOT NULL CHECK (customer_id <> ''),
    subscription_id text NOT NULL,
    received_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX billing_delivery_ids_customer_idx ON billing_delivery_ids (customer_id);

ALTER TABLE billing_delivery_ids ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_delivery_ids FORCE ROW LEVEL SECURITY;
CREATE POLICY billing_delivery_tenant ON billing_delivery_ids
    USING (customer_id = nullif(current_setting('app.organization_id', true), ''))
    WITH CHECK (customer_id = nullif(current_setting('app.organization_id', true), ''));
