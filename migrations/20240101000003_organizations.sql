-- Migration: 003_organizations.sql
-- Organization table with type enums and key versioning.

CREATE TYPE app.org_type AS ENUM (
    'HOUSING_SOCIETY', 'OFFICE', 'HOSPITAL', 'WAREHOUSE',
    'SCHOOL', 'COLLEGE', 'FACTORY', 'COWORKING', 'APARTMENT',
    'HOSTEL', 'OTHER'
);

CREATE TYPE app.org_status AS ENUM ('ACTIVE', 'SUSPENDED', 'DELETED');

CREATE TABLE app.organizations (
    id                   UUID         NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    name                 TEXT         NOT NULL,
    org_type             app.org_type NOT NULL,
    slug                 TEXT         NOT NULL,
    status               app.org_status NOT NULL DEFAULT 'ACTIVE',
    retention_days       INTEGER      NOT NULL DEFAULT 90 CHECK (retention_days > 0),
    current_key_version  INTEGER      NOT NULL DEFAULT 1,
    -- Monotonically increasing sequence number. Incremented on every org-scoped event.
    -- Guard devices use this for incremental sync: "give me events after seq N".
    sync_seq             BIGINT       NOT NULL DEFAULT 0,
    timezone             TEXT         NOT NULL DEFAULT 'UTC',
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_orgs_slug ON app.organizations(slug);

-- Per-org Ed25519 signing keys. Historical versions retained for pass verification.
CREATE TABLE app.org_keys (
    id                      UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id                  UUID        NOT NULL REFERENCES app.organizations(id),
    version                 INTEGER     NOT NULL,
    -- Ed25519 public key (32 bytes). Safe to distribute to guard devices.
    signing_public_key      BYTEA       NOT NULL,
    -- Ed25519 private key encrypted with ChaCha20-Poly1305.
    -- Key: HKDF-SHA256(master_key, salt=org_id, info="vp-org-key-v1" || version_le)
    signing_private_key_enc BYTEA       NOT NULL,
    -- 12-byte nonce for ChaCha20-Poly1305.
    key_derivation_nonce    BYTEA       NOT NULL,
    enc_algorithm           TEXT        NOT NULL DEFAULT 'CHACHA20_POLY1305',
    activated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at              TIMESTAMPTZ,
    rotated_by              UUID,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_org_keys_org_version ON app.org_keys(org_id, version);
CREATE INDEX idx_org_keys_org_active ON app.org_keys(org_id) WHERE retired_at IS NULL;
