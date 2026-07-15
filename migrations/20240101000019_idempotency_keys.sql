-- Migration: 019_idempotency_keys.sql
-- Caches POST response status and payloads by Idempotency-Key UUID.

CREATE TABLE app.idempotency_keys (
    key             UUID        PRIMARY KEY,
    response_status INTEGER     NOT NULL,
    response_headers JSONB      NOT NULL DEFAULT '{}',
    response_body   BYTEA       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for scheduled deletion/cleanup jobs after 24h
CREATE INDEX idx_idempotency_created ON app.idempotency_keys(created_at);
