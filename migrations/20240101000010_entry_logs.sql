-- Migration: 010_entry_logs.sql
-- Immutable append-only gate event log.
-- Partitioned by created_at (monthly) for efficient retention enforcement.

CREATE TYPE app.entry_action AS ENUM ('ENTRY', 'EXIT', 'DENIED');

CREATE TABLE app.entry_logs (
    id                  UUID              NOT NULL DEFAULT gen_random_uuid(),
    org_id              UUID              NOT NULL REFERENCES app.organizations(id),
    location_id         UUID              NOT NULL REFERENCES app.locations(id),
    pass_id             UUID              NOT NULL REFERENCES app.visitor_passes(id),
    device_id           UUID              REFERENCES app.devices(id),
    guard_user_id       UUID              REFERENCES app.users(id),
    action              app.entry_action  NOT NULL,
    denial_reason       TEXT,
    guard_note          TEXT,
    -- Time the event occurred on the device (client-reported, not server time).
    occurred_at         TIMESTAMPTZ       NOT NULL,
    -- Time the server received this event via sync.
    server_received_at  TIMESTAMPTZ       NOT NULL DEFAULT NOW(),
    -- Device-generated idempotency key. Prevents duplicate log entries on retry.
    client_event_id     UUID              NOT NULL,
    created_at          TIMESTAMPTZ       NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- Global unique constraint prevents duplicate sync events across all partitions.
-- Using a partial index on the parent table is more reliable than per-partition constraints.
CREATE UNIQUE INDEX idx_entry_logs_idempotency
    ON app.entry_logs(org_id, client_event_id);

CREATE INDEX idx_entry_logs_pass     ON app.entry_logs(pass_id, created_at DESC);
CREATE INDEX idx_entry_logs_org_loc  ON app.entry_logs(org_id, location_id, created_at DESC);
CREATE INDEX idx_entry_logs_occurred ON app.entry_logs(org_id, occurred_at DESC);

-- Create monthly partitions for the current year + 1 ahead.
-- A maintenance job creates new partitions 30 days before they're needed.
CREATE TABLE app.entry_logs_2024_01 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
CREATE TABLE app.entry_logs_2024_02 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');
CREATE TABLE app.entry_logs_2024_03 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2024-03-01') TO ('2024-04-01');
CREATE TABLE app.entry_logs_2024_04 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2024-04-01') TO ('2024-05-01');
CREATE TABLE app.entry_logs_2024_05 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2024-05-01') TO ('2024-06-01');
CREATE TABLE app.entry_logs_2024_06 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2024-06-01') TO ('2024-07-01');
CREATE TABLE app.entry_logs_2024_07 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2024-07-01') TO ('2024-08-01');
CREATE TABLE app.entry_logs_2024_08 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2024-08-01') TO ('2024-09-01');
CREATE TABLE app.entry_logs_2024_09 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2024-09-01') TO ('2024-10-01');
CREATE TABLE app.entry_logs_2024_10 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2024-10-01') TO ('2024-11-01');
CREATE TABLE app.entry_logs_2024_11 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2024-11-01') TO ('2024-12-01');
CREATE TABLE app.entry_logs_2024_12 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2024-12-01') TO ('2025-01-01');
CREATE TABLE app.entry_logs_2025_01 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE app.entry_logs_2025_02 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE app.entry_logs_2025_03 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');
CREATE TABLE app.entry_logs_2025_04 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2025-04-01') TO ('2025-05-01');
CREATE TABLE app.entry_logs_2025_05 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2025-05-01') TO ('2025-06-01');
CREATE TABLE app.entry_logs_2025_06 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2025-06-01') TO ('2025-07-01');
CREATE TABLE app.entry_logs_2025_07 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2025-07-01') TO ('2025-08-01');
CREATE TABLE app.entry_logs_2025_08 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2025-08-01') TO ('2025-09-01');
CREATE TABLE app.entry_logs_2025_09 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');
CREATE TABLE app.entry_logs_2025_10 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');
CREATE TABLE app.entry_logs_2025_11 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE TABLE app.entry_logs_2025_12 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');
CREATE TABLE app.entry_logs_2026_01 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE app.entry_logs_2026_02 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE app.entry_logs_2026_03 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE app.entry_logs_2026_04 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE app.entry_logs_2026_05 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE app.entry_logs_2026_06 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE app.entry_logs_2026_07 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE app.entry_logs_2026_08 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE app.entry_logs_2026_09 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE app.entry_logs_2026_10 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE app.entry_logs_2026_11 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE app.entry_logs_2026_12 PARTITION OF app.entry_logs
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
