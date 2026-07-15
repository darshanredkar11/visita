-- Migration: 004_users.sql

CREATE TYPE app.user_status AS ENUM ('ACTIVE', 'SUSPENDED', 'DELETED');

CREATE TABLE app.users (
    id                      UUID            NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    email                   TEXT            NOT NULL,
    -- HMAC-SHA256(phone_e164, server_hmac_key). Used for dedup without exposing phone.
    phone_hmac              TEXT,
    -- Argon2id PHC string. Never returned in API responses.
    password_hash           TEXT            NOT NULL,
    full_name               TEXT            NOT NULL,
    status                  app.user_status NOT NULL DEFAULT 'ACTIVE',
    email_verified_at       TIMESTAMPTZ,
    last_login_at           TIMESTAMPTZ,
    failed_login_attempts   INTEGER         NOT NULL DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_users_email    ON app.users(LOWER(email));
CREATE INDEX        idx_users_phone    ON app.users(phone_hmac) WHERE phone_hmac IS NOT NULL;
