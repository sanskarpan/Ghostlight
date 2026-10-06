-- 0001_core_lifecycle.sql
--
-- Core lifecycle schema: organization boundary, repositories, environments,
-- generations, the durable action ledger, the resource ledger, observations,
-- capacity reservations, cleanup runs and the audit log.
--
-- Design constraints this file encodes, not just describes:
--
--   * organization_id is present from the first schema, never retrofitted.
--     Customer-facing tables use composite organization foreign keys so a row
--     cannot be attached to an organization that does not own it.
--   * expires_at is set by trusted policy. The column carries no default and no
--     client-writable path.
--   * generation is the fence. Every action, allocation and cleanup run carries
--     the generation it belongs to, and uniqueness includes it, so a result for
--     an older generation cannot be mistaken for a current one.
--   * action state distinguishes 'uncertain' from 'failed'. A timeout is not
--     proof that creation failed.
--   * The database is unreachable from preview workloads. No role defined here
--     is ever held by a candidate.
--
-- Transaction boundaries are owned by the migration runner, not by this file.
-- Do not add BEGIN or COMMIT here: the runner wraps each migration so a failure
-- rolls back cleanly.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Enumerated vocabulary
-- ---------------------------------------------------------------------------

CREATE TYPE desired_lifecycle AS ENUM ('present', 'absent');
CREATE TYPE observed_lifecycle AS ENUM (
    'requested', 'admitted', 'allocating', 'deploying', 'validating', 'ready',
    'degraded', 'failed', 'draining', 'revoking', 'destroying',
    'cleanup_verifying', 'destroyed', 'quarantined'
);
CREATE TYPE runtime_intent AS ENUM ('running', 'suspended', 'resuming');
CREATE TYPE action_state AS ENUM (
    'planned', 'running', 'succeeded', 'failed', 'uncertain', 'canceled'
);
CREATE TYPE action_type AS ENUM (
    'allocate', 'deploy', 'migrate', 'seed', 'rollout', 'health', 'destroy',
    'revoke', 'verify_absent'
);
CREATE TYPE dependency_kind AS ENUM (
    'postgres', 'redis', 'kafka', 'workflow', 'object_store', 'identity'
);

-- ---------------------------------------------------------------------------
-- Organization boundary
-- ---------------------------------------------------------------------------

CREATE TABLE organizations (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug                text NOT NULL UNIQUE,
    name                text NOT NULL,
    status              text NOT NULL DEFAULT 'provisioning'
                        CHECK (status IN ('provisioning','trial','active','restricted','closing','closed')),
    policy_version      text NOT NULL,
    plan_version        text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$')
);

CREATE TABLE projects (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    slug                text NOT NULL,
    name                text NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, slug),
    -- Unique (organization_id, id) is required so child tables can carry a
    -- composite foreign key that keeps tenant scope consistent.
    UNIQUE (organization_id, id)
);

CREATE TABLE principals (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Provider-neutral identity. Never keyed on email alone: two providers may
    -- issue the same address, and an email change is not an identity change.
    identity_provider   text NOT NULL,
    provider_subject    text NOT NULL,
    email               text,
    email_verified_at   timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (identity_provider, provider_subject)
);

CREATE TABLE memberships (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    principal_id        uuid NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    -- Role lives here, not in the identity provider's vocabulary. The provider's
    -- role claim is advisory.
    role                text NOT NULL
                        CHECK (role IN ('owner','billing_admin','platform_admin','developer','reviewer','reliability_engineer','auditor','support')),
    status              text NOT NULL DEFAULT 'active'
                        CHECK (status IN ('pending','active','inactive')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, principal_id)
);

-- CI identity. Kept in the platform database rather than delegated to an identity
-- provider so revocation, scoping and audit are exact.
CREATE TABLE service_principals (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    name                text NOT NULL,
    key_prefix          text NOT NULL UNIQUE,
    secret_hash         text NOT NULL,
    scopes              jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_by          uuid REFERENCES principals(id),
    last_used_at        timestamptz,
    revoked_at          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name),
    CHECK (revoked_at IS NULL OR revoked_at > created_at)
);

CREATE TABLE project_grants (
    project_id          uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    principal_id        uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    -- Grants narrow capability. They can never widen what a membership allows.
    capabilities        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, principal_id)
);

-- ---------------------------------------------------------------------------
-- Repositories
-- ---------------------------------------------------------------------------

CREATE TABLE repositories (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    project_id          uuid NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    -- Provider-native installation/repository binding, stored as opaque text so
    -- no provider vocabulary leaks into the schema.
    installation_ref    text NOT NULL,
    repository_ref      text NOT NULL,
    catalog_product     text,
    -- Fork admission defaults to denied, which is the 1.0 posture (ADR G-029).
    fork_admission      text NOT NULL DEFAULT 'denied'
                        CHECK (fork_admission IN ('denied','reviewed','allowed')),
    admission_policy    jsonb NOT NULL DEFAULT '{}'::jsonb,
    quotas              jsonb NOT NULL DEFAULT '{}'::jsonb,
    verified_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    -- Unique provider ownership. A native installation/repository binding
    -- cannot be owned by two organizations unless explicitly reviewed.
    UNIQUE (installation_ref, repository_ref),
    -- Required as the target of the composite tenant foreign key used by
    -- environments, so a child row cannot be attached to a repository in another
    -- organization.
    UNIQUE (organization_id, id),
    -- Composite organization foreign key: the project must belong to the same
    -- organization as the repository.
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects(organization_id, id)
);

-- ---------------------------------------------------------------------------
-- Environments
-- ---------------------------------------------------------------------------

CREATE TABLE environments (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- organization_id is redundant with repository_id by design: it exists so
    -- every RLS policy and every index can lead with the tenant key.
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    repository_id       uuid NOT NULL REFERENCES repositories(id) ON DELETE RESTRICT,
    project_id          uuid NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,

    -- Platform-generated DNS-safe slug. Never derived from a branch name, a label
    -- or a callback body.
    slug                text NOT NULL UNIQUE,

    pull_request_number integer,

    desired             desired_lifecycle NOT NULL DEFAULT 'present',
    observed            observed_lifecycle NOT NULL DEFAULT 'requested',
    runtime_intent      runtime_intent,

    -- The fence. Increments on every admitted artifact, configuration or recipe
    -- change.
    generation          bigint NOT NULL DEFAULT 1 CHECK (generation > 0),

    -- Exact candidate identity. policy_digest is NOT NULL because a candidate
    -- that cannot bind a policy cannot be gated.
    source_sha          text NOT NULL,
    base_sha            text,
    artifact_digest     text NOT NULL,
    configuration_digest text NOT NULL,
    migration_digest    text,
    event_schema_digest text,
    recipe_digest       text NOT NULL,
    policy_digest       text NOT NULL,

    resource_profile    text NOT NULL,

    -- Set by trusted policy only. No default, no client-writable path.
    expires_at          timestamptz NOT NULL,

    quarantine_reason   text,

    -- Lease uses database time, never the caller's clock.
    lease_owner         text,
    lease_epoch         bigint NOT NULL DEFAULT 0,
    lease_expires_at    timestamptz,

    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),

    FOREIGN KEY (organization_id, repository_id)
        REFERENCES repositories(organization_id, id),
    -- Quarantine is a consequential state and must carry a reason.
    CHECK (observed <> 'quarantined' OR quarantine_reason IS NOT NULL),
    -- A destroyed environment cannot also be desired present.
    CHECK (observed <> 'destroyed' OR desired = 'absent'),
    -- Unique (organization_id, id) lets children carry a composite tenant FK.
    UNIQUE (organization_id, id)
);

COMMENT ON COLUMN environments.slug IS
    'Platform-generated DNS-safe routing identity. Never a branch name.';
COMMENT ON COLUMN environments.expires_at IS
    'Set by trusted policy. A client TTL is a request to validate, never authority.';
COMMENT ON COLUMN environments.lease_epoch IS
    'Fences ledger writes only. It does not fence a cloud API call.';

CREATE TABLE environment_generations (
    environment_id      uuid NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    generation          bigint NOT NULL CHECK (generation > 0),
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    source_sha          text NOT NULL,
    base_sha            text,
    artifact_digest     text NOT NULL,
    configuration_digest text NOT NULL,
    migration_digest    text,
    event_schema_digest text,
    recipe_digest       text NOT NULL,
    policy_digest       text NOT NULL,
    rollout_status      observed_lifecycle NOT NULL DEFAULT 'requested',
    gates_status        text NOT NULL DEFAULT 'pending',
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (environment_id, generation),
    -- The tenant scope must match the parent environment.
    FOREIGN KEY (organization_id, environment_id)
        REFERENCES environments(organization_id, id)
);

-- ---------------------------------------------------------------------------
-- Durable action ledger
-- ---------------------------------------------------------------------------

CREATE TABLE actions (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id      uuid NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    generation          bigint NOT NULL CHECK (generation > 0),
    action_type         action_type NOT NULL,
    -- Caller-stable across retries. Uniqueness over
    -- (environment, generation, type, logical key) makes a redelivered event a
    -- no-op rather than a second run.
    logical_key         text NOT NULL,
    -- A retry with different arguments is a different action, not a resend.
    input_digest        text NOT NULL,
    resource_scope      jsonb NOT NULL DEFAULT '[]'::jsonb,

    state               action_state NOT NULL DEFAULT 'planned',
    attempts            integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at     timestamptz NOT NULL DEFAULT now(),
    last_error          text,

    -- Fencing triple. A result write must present all three and they must match.
    lease_owner         text,
    lease_epoch         bigint NOT NULL DEFAULT 0,
    expected_generation bigint NOT NULL CHECK (expected_generation > 0),

    -- Opaque provider reference. Deliberately not a typed cloud identifier.
    external_ref        jsonb,

    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),

    -- expected_generation is denormalised from generation and constrained equal,
    -- so a row can never claim to act for a generation other than its own.
    CHECK (expected_generation = generation),

    -- An action may only name a generation that has been recorded.
    FOREIGN KEY (environment_id, generation)
        REFERENCES environment_generations(environment_id, generation),

    CONSTRAINT actions_idempotency_key
        UNIQUE (environment_id, generation, action_type, logical_key)
);

COMMENT ON TABLE actions IS
    'Intent is committed before any external call. A timeout yields uncertain, never failed; an uncertain action must be observed, not re-run.';
COMMENT ON COLUMN actions.expected_generation IS
    'The fence. A stale completion cannot mark a newer generation ready.';

-- ---------------------------------------------------------------------------
-- Runner executions
-- ---------------------------------------------------------------------------

CREATE TABLE runner_executions (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id           uuid NOT NULL REFERENCES actions(id) ON DELETE RESTRICT,
    run_ref             text NOT NULL UNIQUE,
    -- Pinned runner digest. A cleanup run must use the same pinned module and
    -- state identity that allocated the environment.
    runner_digest       text NOT NULL,
    process_ref         text,
    -- Ownership of the native state lock. Required in addition to database
    -- action serialization, because a database lease is not a cloud fence.
    state_lock_owner    text,
    state_lock_acquired_at timestamptz,
    termination_evidence jsonb,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Resource ledger: the only source of delete authority
-- ---------------------------------------------------------------------------

CREATE TABLE resource_allocations (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id      uuid NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    generation          bigint NOT NULL CHECK (generation > 0),
    dependency_kind     dependency_kind NOT NULL,
    logical_key         text NOT NULL,

    -- Opaque provider reference. Never an ARN or any other cloud-native type.
    provider_ref        jsonb NOT NULL,
    -- Where the environment-scoped credential lives. The credential itself is
    -- never stored here, returned by an API, or logged.
    credential_ref      text,
    endpoint_ref        text,

    -- Shared foundation resources never receive delete authority here.
    is_shared           boolean NOT NULL DEFAULT false,
    -- Whether this type carries ownership tags. Post-restore reconciliation
    -- depends on it; a type that does not is excluded or given another key.
    supports_ownership_tags boolean NOT NULL DEFAULT false,

    revoked_at          timestamptz,
    revoked_evidence    jsonb,
    -- Tombstone. Retained after verified deletion so a stale webhook cannot
    -- recreate a removed allocation.
    verified_deleted_at timestamptz,
    retention_until     timestamptz,

    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),

    FOREIGN KEY (environment_id, generation)
        REFERENCES environment_generations(environment_id, generation),
    CONSTRAINT resource_logical_key
        UNIQUE (environment_id, dependency_kind, logical_key),
    -- A shared resource must never be marked deleted through this table.
    CHECK (NOT is_shared OR verified_deleted_at IS NULL)
);

COMMENT ON TABLE resource_allocations IS
    'The only source of delete authority. A shared foundation resource never enters this table with delete authority.';
COMMENT ON COLUMN resource_allocations.provider_ref IS
    'Opaque. Resolved through the provider adapter; never interpreted by the reconciler.';

CREATE TABLE resource_observations (
    id                  bigserial PRIMARY KEY,
    allocation_id       uuid NOT NULL REFERENCES resource_allocations(id) ON DELETE RESTRICT,
    -- Monotonic sequence per allocation. Authoritative provider state.
    observation_seq     bigint NOT NULL CHECK (observation_seq > 0),
    observed_at         timestamptz NOT NULL DEFAULT now(),
    present             boolean NOT NULL,
    provider_state      jsonb NOT NULL,
    -- How the resource was found: ownership scan, state backend, or direct read.
    discovery_source    text NOT NULL,
    detail              text,
    CONSTRAINT resource_observation_seq UNIQUE (allocation_id, observation_seq)
);

COMMENT ON TABLE resource_observations IS
    'Authoritative provider truth and the independent recovery oracle. A failed lookup is recorded as absent only when absence was established; an unobservable lookup is not recorded as absent.';

-- ---------------------------------------------------------------------------
-- Capacity reservations
-- ---------------------------------------------------------------------------

CREATE TABLE capacity_reservations (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    environment_id      uuid REFERENCES environments(id) ON DELETE CASCADE,
    -- scope is 'repository', 'actor', 'fleet' or 'profile'.
    scope               text NOT NULL CHECK (scope IN ('repository','actor','fleet','profile')),
    scope_ref           text NOT NULL,
    resource_profile    text NOT NULL,
    window_start        timestamptz NOT NULL,
    window_end          timestamptz NOT NULL,
    max_concurrency     integer NOT NULL CHECK (max_concurrency > 0),
    max_cpu             numeric(10,2),
    max_storage_gib     integer,
    -- Separate money concept from the subscription ledger.
    max_allowance_minor bigint,
    currency            char(3),
    active              boolean NOT NULL DEFAULT true,
    released_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CHECK (window_end > window_start),
    -- A release is idempotent: an inactive reservation always has a release time.
    CHECK (active OR released_at IS NOT NULL)
);

COMMENT ON TABLE capacity_reservations IS
    'Admission reserves transactionally so a retry cannot consume the last slot twice. Experiment capacity holds a separate reservation from preview slots.';

-- ---------------------------------------------------------------------------
-- Cleanup runs
-- ---------------------------------------------------------------------------

CREATE TABLE cleanup_runs (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id      uuid NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    generation          bigint NOT NULL,
    -- Discovered by ownership scan, not by trusting local state.
    discovered_resources jsonb NOT NULL DEFAULT '[]'::jsonb,
    -- Resources that could not be shown to be absent. The environment stays in
    -- cleanup_verifying while this is non-empty.
    unresolved          jsonb NOT NULL DEFAULT '[]'::jsonb,
    verification_status text NOT NULL DEFAULT 'running'
                        CHECK (verification_status IN ('running','verified','unresolved')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cleanup_run_per_generation UNIQUE (environment_id, generation),
    FOREIGN KEY (organization_id, environment_id)
        REFERENCES environments(organization_id, id)
);

COMMENT ON TABLE cleanup_runs IS
    'Verified cleanup is the trust foundation. Destruction is never forced to clear a dashboard; unresolved resources remain visible.';

-- ---------------------------------------------------------------------------
-- Audit log
-- ---------------------------------------------------------------------------

CREATE TABLE audit_log (
    id                  bigserial PRIMARY KEY,
    organization_id     uuid REFERENCES organizations(id) ON DELETE RESTRICT,
    occurred_at         timestamptz NOT NULL DEFAULT now(),
    actor_ref           text NOT NULL,
    action              text NOT NULL,
    resource_type       text,
    resource_ref        text,
    -- Digests, not payloads. An audit record must not become a secret store.
    input_digest        text,
    output_digest       text,
    correlation_ref     text,
    metadata            jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX audit_log_org_time ON audit_log (organization_id, occurred_at DESC);
CREATE INDEX audit_log_resource ON audit_log (resource_type, resource_ref);

-- ---------------------------------------------------------------------------
-- Reconciliation indexes
-- ---------------------------------------------------------------------------

-- Expired environments the independent watchdog must act on.
CREATE INDEX environments_expired ON environments (expires_at)
    WHERE desired = 'present';

-- Runnable actions, bounded pages rather than full scans.
CREATE INDEX actions_runnable ON actions (next_attempt_at)
    WHERE state IN ('planned', 'running');

-- Uncertain actions awaiting observation. This is the observe-before-retry work
-- list and must never be starved.
CREATE INDEX actions_uncertain ON actions (next_attempt_at)
    WHERE state = 'uncertain';

-- Stale runner leases. A lease expiry is not a takeover trigger; it is a signal
-- to observe and terminate the previous runner first.
CREATE INDEX environments_stale_lease ON environments (lease_expires_at)
    WHERE lease_owner IS NOT NULL AND desired = 'present';

-- Unresolved resources.
CREATE INDEX resource_allocations_unresolved ON resource_allocations (updated_at)
    WHERE verified_deleted_at IS NULL;

-- Cleanup runs with unresolved removals.
CREATE INDEX cleanup_runs_unresolved ON cleanup_runs (updated_at)
    WHERE verification_status <> 'verified';

-- Tenant-scoped listing.
CREATE INDEX environments_org ON environments (organization_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Row level security
-- ---------------------------------------------------------------------------
--
-- Customer-query roles never receive BYPASSRLS. Organization context is set per
-- transaction by a trusted function; a customer session cannot choose global
-- context. Platform safety duties use narrowly reviewed system roles and claim
-- functions instead.

ALTER TABLE organizations           ENABLE ROW LEVEL SECURITY;
ALTER TABLE principals             ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships            ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_principals     ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects               ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_grants         ENABLE ROW LEVEL SECURITY;
ALTER TABLE repositories           ENABLE ROW LEVEL SECURITY;
ALTER TABLE environments           ENABLE ROW LEVEL SECURITY;
ALTER TABLE environment_generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_allocations   ENABLE ROW LEVEL SECURITY;
ALTER TABLE cleanup_runs           ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log              ENABLE ROW LEVEL SECURITY;

-- FORCE so the table owner is also subject to policy. An owner that can bypass
-- its own policy is a hole in the tenant boundary.
ALTER TABLE environments           FORCE ROW LEVEL SECURITY;
ALTER TABLE environment_generations FORCE ROW LEVEL SECURITY;
ALTER TABLE repositories           FORCE ROW LEVEL SECURITY;
ALTER TABLE resource_allocations   FORCE ROW LEVEL SECURITY;
ALTER TABLE cleanup_runs           FORCE ROW LEVEL SECURITY;

CREATE POLICY env_tenant ON environments
    USING (organization_id = nullif(current_setting('app.organization_id', true), '')::uuid);

CREATE POLICY env_gen_tenant ON environment_generations
    USING (organization_id = nullif(current_setting('app.organization_id', true), '')::uuid);

CREATE POLICY repo_tenant ON repositories
    USING (organization_id = nullif(current_setting('app.organization_id', true), '')::uuid);

CREATE POLICY alloc_tenant ON resource_allocations
    USING (organization_id = nullif(current_setting('app.organization_id', true), '')::uuid);

CREATE POLICY cleanup_tenant ON cleanup_runs
    USING (organization_id = nullif(current_setting('app.organization_id', true), '')::uuid);

-- Actions are reached through their environment; they carry no organization_id
-- of their own.
CREATE POLICY action_via_env ON actions
    USING (
        EXISTS (
            SELECT 1 FROM environments e
            WHERE e.id = actions.environment_id
              AND e.organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
        )
    );