-- 0002_webhook_inbox.sql
--
-- Verified webhook intake and pull-request tracking.
--
-- Intake rules this file encodes:
--
--   * The provider delivery identifier is unique. A redelivered event is a
--     no-op, not a second run.
--   * A verified payload is persisted before the request is acknowledged. If the
--     database cannot take it, the endpoint must fail rather than return success,
--     because the provider will not redeliver what it believes was accepted.
--   * Arrival order is not authoritative. Pull-request head and base are resolved
--     from an authenticated source when acting, and the observed state carries the
--     time it was observed so a stale event can be recognised as stale.
--   * A reopened or synchronize event for an environment that was already torn
--     down must not resurrect it. The tombstones on environments carry the
--     terminal identity, and closed_at here records when the pull request left
--     the platform's control.
--
-- Retention is bounded and stated: raw payload bodies are not kept long enough to
-- become a liability, while the delivery identifier and digest are kept for the
-- audit window.
--
-- Transaction boundaries are owned by the migration runner, not by this file.
-- Do not add BEGIN or COMMIT here: the runner wraps each migration so a failure
-- rolls back cleanly.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE webhook_inbox (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Provider delivery identifier. This is the idempotency key for intake.
    delivery_id         text NOT NULL,
    provider            text NOT NULL,
    event_type          text NOT NULL,
    -- Installation identity as asserted by the verified payload. Client metadata
    -- is never authority; this records what the provider asserted after
    -- verification.
    installation_ref    text,
    repository_ref      text,
    -- SHA-256 of the exact bytes that were verified. The raw body is not retained
    -- long term; the digest is what an audit needs.
    payload_digest      text NOT NULL,
    -- Signature verification outcome. A payload that did not verify is never
    -- stored here at all, so the table only ever holds admitted events.
    signature_verified  boolean NOT NULL DEFAULT true CHECK (signature_verified),
    -- True when the payload fell outside the allowed clock window.
    replay_rejected     boolean NOT NULL DEFAULT false,

    received_at         timestamptz NOT NULL DEFAULT now(),
    processed_at        timestamptz,
    -- Processing outcome is explicit rather than inferred, so a stuck event is
    -- visible rather than silently absent.
    processing_status   text NOT NULL DEFAULT 'received'
                        CHECK (processing_status IN ('received','processing','processed','ignored','failed')),
    processing_error    text,
    attempts            integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at     timestamptz NOT NULL DEFAULT now(),

    -- Bounded retention: raw payload metadata is short-lived, the digest is not.
    expires_at          timestamptz NOT NULL,

    CONSTRAINT webhook_delivery_unique UNIQUE (provider, delivery_id),
    CONSTRAINT webhook_expiry_after_receipt CHECK (expires_at > received_at)
);

COMMENT ON TABLE webhook_inbox IS
    'Verified intake only. A duplicate delivery is a no-op. The row is written before the request is acknowledged.';
COMMENT ON COLUMN webhook_inbox.payload_digest IS
    'Digest of the exact bytes verified. The raw body is not retained past expires_at.';
COMMENT ON COLUMN webhook_inbox.signature_verified IS
    'Always true: an unverified payload is rejected at the edge and never reaches this table.';

CREATE INDEX webhook_inbox_unprocessed ON webhook_inbox (next_attempt_at)
    WHERE processing_status IN ('received', 'failed');
CREATE INDEX webhook_inbox_expiry ON webhook_inbox (expires_at);

CREATE TABLE pull_requests (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id       uuid NOT NULL REFERENCES repositories(id) ON DELETE RESTRICT,
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    -- Provider-native reference. Unique on repository plus number.
    number              integer NOT NULL CHECK (number > 0),
    -- Current state resolved from an authenticated source when acting, never
    -- assumed from the event that triggered the lookup.
    head_sha            text NOT NULL,
    base_sha            text,
    state               text NOT NULL
                        CHECK (state IN ('open','closed','merged')),
    -- When the state was observed. A late event can be recognised as stale by
    -- comparing its payload head against this.
    observed_at         timestamptz NOT NULL DEFAULT now(),
    -- Set when the pull request leaves the platform's control. Recorded so a
    -- subsequent reopened or synchronize event cannot resurrect a torn-down
    -- environment.
    closed_at           timestamptz,
    -- The environment currently bound to this pull request, if any. The link is
    -- one-to-one in practice but is not constrained as unique, because an old
    -- environment is retained for audit after a new one supersedes it.
    environment_id      uuid REFERENCES environments(id) ON DELETE SET NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pull_request_repo_number UNIQUE (repository_id, number),
    FOREIGN KEY (organization_id, repository_id)
        REFERENCES repositories(organization_id, id),
    -- A closed pull request must carry the time it closed.
    CHECK (state <> 'closed' OR closed_at IS NOT NULL)
);

COMMENT ON TABLE pull_requests IS
    'Current state resolved from an authenticated source. Event arrival order is not authoritative; closed_at prevents a late reopened event resurrecting a destroyed environment.';

ALTER TABLE environments
    ADD COLUMN pull_request_id uuid REFERENCES pull_requests(id) ON DELETE SET NULL;

CREATE INDEX pull_requests_by_repo ON pull_requests (repository_id, number);
-- Environments awaiting a torn-down identity: used to reject resurrection.
CREATE INDEX environments_pull_request ON environments (pull_request_id);

ALTER TABLE environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE pull_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE environments FORCE ROW LEVEL SECURITY;

CREATE POLICY pull_request_tenant ON pull_requests
    USING (organization_id = nullif(current_setting('app.organization_id', true), '')::uuid);

-- The environment policy gains the pull-request link; existing tenant scoping is
-- unchanged, so the added column cannot widen visibility.
DROP POLICY IF EXISTS env_tenant ON environments;
CREATE POLICY env_tenant ON environments
    USING (organization_id = nullif(current_setting('app.organization_id', true), '')::uuid);