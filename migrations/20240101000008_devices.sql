-- Migration: 008_devices.sql

CREATE TYPE app.device_type   AS ENUM ('RESIDENT_PHONE', 'GUARD_TABLET', 'GUARD_KIOSK');
CREATE TYPE app.device_status AS ENUM ('ACTIVE', 'REVOKED');

CREATE TABLE app.devices (
    id                  UUID               NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id              UUID               NOT NULL REFERENCES app.organizations(id),
    location_id         UUID               REFERENCES app.locations(id),
    owner_user_id       UUID               REFERENCES app.users(id),
    device_type         app.device_type    NOT NULL,
    name                TEXT               NOT NULL,
    -- Ed25519 public key (32 bytes). Uniquely identifies the device globally.
    public_key          BYTEA              NOT NULL,
    platform            TEXT,              -- "android" | "ios"
    os_version          TEXT,
    app_version         TEXT,
    push_token          TEXT,
    last_seen_at        TIMESTAMPTZ,
    status              app.device_status  NOT NULL DEFAULT 'ACTIVE',
    revoked_at          TIMESTAMPTZ,
    revoked_by          UUID               REFERENCES app.users(id),
    revocation_reason   TEXT,
    created_at          TIMESTAMPTZ        NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ        NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_devices_public_key ON app.devices(public_key);
CREATE INDEX idx_devices_org ON app.devices(org_id, status);
CREATE INDEX idx_devices_location ON app.devices(location_id) WHERE location_id IS NOT NULL;

-- Device sync checkpoints. Tracks last_sync_seq per device per org.
CREATE TABLE sync.device_checkpoints (
    device_id   UUID    NOT NULL REFERENCES app.devices(id),
    org_id      UUID    NOT NULL REFERENCES app.organizations(id),
    last_seq    BIGINT  NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (device_id, org_id)
);
