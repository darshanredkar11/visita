-- Migration: 006_sessions.sql
-- PASETO v4 refresh tokens (access tokens are stateless).

CREATE TABLE app.sessions (
    id              UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id         UUID        NOT NULL REFERENCES app.users(id),
    org_id          UUID        NOT NULL REFERENCES app.organizations(id),
    -- SHA-256 of the actual refresh token (never stored in clear).
    token_hash      TEXT        NOT NULL,
    -- Previous token hash — retained for 5 minutes to handle network retries.
    -- If a request comes in with this, we re-issue and revoke the family.
    previous_token_hash TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    -- Revoke entire family on token theft detection.
    family_id       UUID        NOT NULL DEFAULT gen_random_uuid(),
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_sessions_token_hash ON app.sessions(token_hash);
CREATE INDEX idx_sessions_user ON app.sessions(user_id);
CREATE INDEX idx_sessions_expires ON app.sessions(expires_at)
    WHERE revoked_at IS NULL;

-- Device authentication challenges (60s TTL; cleaned up on expiry).
CREATE TABLE app.device_challenges (
    nonce       TEXT        NOT NULL PRIMARY KEY,
    device_hint TEXT,           -- Optional device fingerprint
    ip_address  INET,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '60 seconds',
    used_at     TIMESTAMPTZ
);

CREATE INDEX idx_challenges_expires ON app.device_challenges(expires_at);
