-- Migration: 017_org_join_tokens.sql
-- Table to support group invitation links/QRs for simplified resident onboarding.

CREATE TABLE app.org_join_tokens (
    id                  UUID         NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id              UUID         NOT NULL REFERENCES app.organizations(id) ON DELETE CASCADE,
    -- SHA-256 hash of the secure join token shared with residents.
    token_hash          TEXT         NOT NULL,
    -- Expiry timestamp. NULL means the token never expires (until rotated).
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by          UUID         NOT NULL REFERENCES app.users(id)
);

CREATE UNIQUE INDEX idx_join_tokens_hash ON app.org_join_tokens(token_hash);
CREATE INDEX idx_join_tokens_org ON app.org_join_tokens(org_id);
