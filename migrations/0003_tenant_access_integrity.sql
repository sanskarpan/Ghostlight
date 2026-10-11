-- ---------------------------------------------------------------------------
-- Tenant access integrity
--
-- internal/access refuses a cross-organization grant in Go. This migration makes
-- the database refuse it too, which is the only version that survives: any process
-- holding a database connection can skip an application-level policy check, and a
-- policy check is exactly the thing an attacker with a SQL injection looks for.
--
-- The specific hole this closes: project_grants carried project_id and
-- principal_id with independent single-column foreign keys and no organization
-- column at all. Any principal from any tenant could therefore be granted access
-- to any project in any tenant. The application never did this; the schema allowed
-- it, which means one future query written by someone in a hurry could.
-- ---------------------------------------------------------------------------

-- Backfill from the project's own organization rather than trusting a caller to
-- supply the value: deriving it is the only version that cannot disagree with the
-- project it names.
ALTER TABLE project_grants ADD COLUMN organization_id uuid;

UPDATE project_grants pg
   SET organization_id = p.organization_id
  FROM projects p
 WHERE p.id = pg.project_id;

ALTER TABLE project_grants ALTER COLUMN organization_id SET NOT NULL;

-- The project must belong to the organization the grant claims.
ALTER TABLE project_grants
    ADD CONSTRAINT project_grants_organization_project_fkey
    FOREIGN KEY (organization_id, project_id)
    REFERENCES projects (organization_id, id) ON DELETE CASCADE;

-- The grantee must be a member of that same organization. A grant to a non-member
-- is not a narrow grant, it is an invitation that forgot to be one.
ALTER TABLE project_grants
    ADD CONSTRAINT project_grants_organization_principal_fkey
    FOREIGN KEY (organization_id, principal_id)
    REFERENCES memberships (organization_id, principal_id) ON DELETE CASCADE;

-- Superseded: the composite membership key already implies the principal exists.
-- Keeping both would allow a principal row to be deleted and reinserted with the
-- same id while the grant survived, which no longer means anything.
ALTER TABLE project_grants DROP CONSTRAINT project_grants_principal_id_fkey;

CREATE INDEX project_grants_organization_idx ON project_grants (organization_id);

ALTER TABLE project_grants ENABLE ROW LEVEL SECURITY;
-- FORCE so the table owner is also subject to policy, matching 0001. An owner that
-- can bypass its own policy is exactly the connection an attacker with a SQL
-- injection reaches for.
ALTER TABLE project_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY grant_tenant ON project_grants
    USING (organization_id = nullif(current_setting('app.organization_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- Repository grants
--
-- Repository-level allow and deny, matching internal/access. Deny is stored as a
-- row rather than as an absence, because an explicit deny and a missing grant are
-- different intentions: one says "never", the other says "not yet".
-- ---------------------------------------------------------------------------

CREATE TABLE repository_grants (
    organization_id     uuid NOT NULL,
    repository_id       uuid NOT NULL,
    principal_id        uuid NOT NULL,
    permission          text NOT NULL
                        CHECK (permission IN ('repo:read','repo:write','env:create',
                                              'env:read','env:abort','member:invite',
                                              'member:revoke','billing:read',
                                              'billing:write','repo:admin')),
    deny                boolean NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, principal_id, permission),
-- The repository must belong to the organization the grant claims.
    CONSTRAINT repository_grants_organization_repository_fkey
    FOREIGN KEY (organization_id, repository_id)
        REFERENCES repositories (organization_id, id) ON DELETE CASCADE,
    -- The grantee must be a member of that organization.
    CONSTRAINT repository_grants_organization_principal_fkey
    FOREIGN KEY (organization_id, principal_id)
        REFERENCES memberships (organization_id, principal_id) ON DELETE CASCADE
);

CREATE INDEX repository_grants_organization_idx ON repository_grants (organization_id);

ALTER TABLE repository_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE repository_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY repo_grant_tenant ON repository_grants
    USING (organization_id = nullif(current_setting('app.organization_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- Invitations
--
-- Only the hash is stored. A database dump must not hand out membership, and a
-- membership token that survives a breach is indistinguishable from a membership
-- that was granted deliberately.
-- ---------------------------------------------------------------------------

CREATE TABLE invitations (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_hash          text NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    email               text NOT NULL,
    -- A subset of the membership vocabulary. 'owner' is excluded because a token
    -- that grants ownership makes its holder untouchable to administrators, and the
    -- staff roles are excluded because platform staff are not customers and must
    -- never be reachable through a customer invitation.
    role                text NOT NULL
                        CHECK (role IN ('member','admin','developer','reviewer')),
    invited_by          uuid,
    expires_at          timestamptz NOT NULL,
    accepted_at         timestamptz,
    revoked_at          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
-- The inviter must belong to the organization issuing the invitation.
    --
    -- The SET NULL column list matters. Without it PostgreSQL nulls every column of
    -- the composite key on delete, which would try to null organization_id too — a
    -- NOT NULL column — so deleting anyone who had ever sent an invitation would
    -- fail. Column-list SET NULL requires PostgreSQL 15 or newer, which is below the
    -- 17.11 floor this platform locks to.
    CONSTRAINT invitations_organization_invited_by_fkey
    FOREIGN KEY (organization_id, invited_by)
        REFERENCES memberships (organization_id, principal_id) ON DELETE SET NULL (invited_by)
);

CREATE INDEX invitations_organization_idx ON invitations (organization_id);

ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY invitation_tenant ON invitations
    USING (organization_id = nullif(current_setting('app.organization_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- Service principals
--
-- A credential must be created by somebody who belongs to the organization it will
-- act in. Without this, a service principal could be created inside another
-- tenant's scope by someone with no relationship to that tenant.
-- ---------------------------------------------------------------------------

ALTER TABLE service_principals
    ADD CONSTRAINT service_principals_creator_fkey
    FOREIGN KEY (organization_id, created_by)
    REFERENCES memberships (organization_id, principal_id) ON DELETE SET NULL;