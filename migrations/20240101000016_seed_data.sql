-- Migration: 016_seed_data.sql
-- Minimal bootstrap data for development and integration testing.
-- Do NOT run in production — use the admin CLI instead.

DO $$
BEGIN
    IF current_setting('app.environment', true) != 'test' THEN
        RAISE EXCEPTION 'Migration 016 (seed data) must only run in test environments. Set app.environment=test.';
    END IF;
END $$;

-- Example test organization (used in integration tests only)
INSERT INTO app.organizations (id, name, org_type, slug, status, retention_days, timezone)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Test Organization',
    'OFFICE',
    'test-org',
    'ACTIVE',
    365,
    'UTC'
) ON CONFLICT (slug) DO NOTHING;
