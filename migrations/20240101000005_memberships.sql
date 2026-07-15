-- Migration: 005_memberships.sql
-- Org membership links users to organizations with roles.

CREATE TYPE app.member_role   AS ENUM ('GUARD', 'RESIDENT', 'ADMIN', 'OWNER');
CREATE TYPE app.member_status AS ENUM ('INVITED', 'ACTIVE', 'SUSPENDED', 'LEFT');

CREATE TABLE app.org_memberships (
    id                  UUID               NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id              UUID               NOT NULL REFERENCES app.organizations(id),
    user_id             UUID               NOT NULL REFERENCES app.users(id),
    role                app.member_role    NOT NULL,
    -- Human-readable unit identifier: flat number, department, desk etc.
    unit_identifier     TEXT,
    -- Encrypted E.164 phone for this member within this org.
    phone_enc           BYTEA,
    invited_by          UUID               REFERENCES app.users(id),
    -- SHA-256 hash of the invitation token. Cleared after acceptance.
    invite_token_hash   TEXT,
    invite_expires_at   TIMESTAMPTZ,
    joined_at           TIMESTAMPTZ,
    status              app.member_status  NOT NULL DEFAULT 'INVITED',
    created_at          TIMESTAMPTZ        NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ        NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_memberships_org_user ON app.org_memberships(org_id, user_id);
CREATE INDEX idx_memberships_user ON app.org_memberships(user_id);
CREATE INDEX idx_memberships_invite_token ON app.org_memberships(invite_token_hash)
    WHERE invite_token_hash IS NOT NULL;
