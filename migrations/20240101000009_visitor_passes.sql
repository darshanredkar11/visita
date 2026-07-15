-- Migration: 009_visitor_passes.sql
-- Core visitor pass table.

CREATE TYPE app.pass_status  AS ENUM ('ACTIVE', 'USED', 'EXPIRED', 'REVOKED');
CREATE TYPE app.permission   AS ENUM ('ENTRY', 'EXIT', 'VEHICLE');

CREATE TABLE app.visitor_passes (
    id                  UUID             NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id              UUID             NOT NULL REFERENCES app.organizations(id),
    location_id         UUID             NOT NULL REFERENCES app.locations(id),
    created_by          UUID             NOT NULL REFERENCES app.users(id),

    -- Short human-readable identifier: VP-XXXXXXXX (Base36, 8 chars)
    pass_number         TEXT             NOT NULL,

    -- Visitor identity
    visitor_name        TEXT             NOT NULL,
    -- HMAC-SHA256 of E.164 phone. Used for lookup/dedup without exposing PII.
    visitor_phone_hmac  TEXT             NOT NULL,
    -- ChaCha20-Poly1305 encrypted phone bytes (nonce prepended).
    visitor_phone_enc   BYTEA,

    -- Pass details
    purpose             TEXT             NOT NULL,
    vehicle_number      TEXT,
    permissions         app.permission[] NOT NULL DEFAULT '{ENTRY, EXIT}',
    valid_from          TIMESTAMPTZ      NOT NULL,
    valid_until         TIMESTAMPTZ      NOT NULL,
    max_uses            INTEGER          NOT NULL DEFAULT 1 CHECK (max_uses >= -1),
    use_count           INTEGER          NOT NULL DEFAULT 0,

    -- Cryptographic material
    -- Complete QR string: "vp1.<base64url_cbor_payload>".
    -- Mobile apps render this directly. Never needs to be recomputed.
    qr_payload          TEXT             NOT NULL,
    -- 12-byte ChaCha20 nonce used for phone encryption in QR payload.
    qr_nonce            BYTEA            NOT NULL,
    -- Which org key version signed this pass.
    key_version         INTEGER          NOT NULL,

    -- Status
    status              app.pass_status  NOT NULL DEFAULT 'ACTIVE',
    revoked_at          TIMESTAMPTZ,
    revoked_by          UUID             REFERENCES app.users(id),
    revocation_reason   TEXT,

    -- Sync tracking. Set by a DB trigger when the row is inserted/updated.
    sync_seq            BIGINT,

    created_at          TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ      NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_pass_validity CHECK (valid_until > valid_from)
);

CREATE UNIQUE INDEX idx_passes_org_number ON app.visitor_passes(org_id, pass_number);
CREATE INDEX idx_passes_org_status        ON app.visitor_passes(org_id, status, created_at DESC);
CREATE INDEX idx_passes_org_location      ON app.visitor_passes(org_id, location_id, valid_until)
    WHERE status = 'ACTIVE';
CREATE INDEX idx_passes_phone_hmac        ON app.visitor_passes(org_id, visitor_phone_hmac);
CREATE INDEX idx_passes_sync_seq          ON app.visitor_passes(org_id, sync_seq DESC)
    WHERE sync_seq IS NOT NULL;

-- Expire passes automatically via status column.
-- A pg_cron job (or periodic query) can UPDATE status to 'EXPIRED'
-- WHERE valid_until < NOW() AND status = 'ACTIVE'.
-- This is simpler and cheaper than real-time triggers.
