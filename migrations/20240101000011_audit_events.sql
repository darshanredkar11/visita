-- Migration: 011_audit_events.sql
-- Append-only, tamper-evident audit log in a separate schema.
-- Monthly partitioned; retention is configurable per org.

CREATE TABLE audit.audit_events (
    id                  UUID        NOT NULL DEFAULT gen_random_uuid(),
    org_id              UUID        NOT NULL,
    event_type          TEXT        NOT NULL,
    actor_user_id       UUID,
    actor_device_id     UUID,
    target_entity_type  TEXT,
    target_entity_id    UUID,
    metadata            JSONB       NOT NULL DEFAULT '{}',
    ip_address          INET,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (created_at);

CREATE INDEX idx_audit_org_created  ON audit.audit_events(org_id, created_at DESC);
CREATE INDEX idx_audit_actor_user   ON audit.audit_events(actor_user_id, created_at DESC)
    WHERE actor_user_id IS NOT NULL;
CREATE INDEX idx_audit_target       ON audit.audit_events(target_entity_id, created_at DESC)
    WHERE target_entity_id IS NOT NULL;
CREATE INDEX idx_audit_metadata     ON audit.audit_events USING GIN (metadata);

-- Monthly partitions (2024–2026 bootstrap set; job extends these)
CREATE TABLE audit.audit_events_2024_q1 PARTITION OF audit.audit_events
    FOR VALUES FROM ('2024-01-01') TO ('2024-04-01');
CREATE TABLE audit.audit_events_2024_q2 PARTITION OF audit.audit_events
    FOR VALUES FROM ('2024-04-01') TO ('2024-07-01');
CREATE TABLE audit.audit_events_2024_q3 PARTITION OF audit.audit_events
    FOR VALUES FROM ('2024-07-01') TO ('2024-10-01');
CREATE TABLE audit.audit_events_2024_q4 PARTITION OF audit.audit_events
    FOR VALUES FROM ('2024-10-01') TO ('2025-01-01');
CREATE TABLE audit.audit_events_2025_q1 PARTITION OF audit.audit_events
    FOR VALUES FROM ('2025-01-01') TO ('2025-04-01');
CREATE TABLE audit.audit_events_2025_q2 PARTITION OF audit.audit_events
    FOR VALUES FROM ('2025-04-01') TO ('2025-07-01');
CREATE TABLE audit.audit_events_2025_q3 PARTITION OF audit.audit_events
    FOR VALUES FROM ('2025-07-01') TO ('2025-10-01');
CREATE TABLE audit.audit_events_2025_q4 PARTITION OF audit.audit_events
    FOR VALUES FROM ('2025-10-01') TO ('2026-01-01');
CREATE TABLE audit.audit_events_2026_q1 PARTITION OF audit.audit_events
    FOR VALUES FROM ('2026-01-01') TO ('2026-04-01');
CREATE TABLE audit.audit_events_2026_q2 PARTITION OF audit.audit_events
    FOR VALUES FROM ('2026-04-01') TO ('2026-07-01');
CREATE TABLE audit.audit_events_2026_q3 PARTITION OF audit.audit_events
    FOR VALUES FROM ('2026-07-01') TO ('2026-10-01');
CREATE TABLE audit.audit_events_2026_q4 PARTITION OF audit.audit_events
    FOR VALUES FROM ('2026-10-01') TO ('2027-01-01');
