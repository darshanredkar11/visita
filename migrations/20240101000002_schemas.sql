-- Migration: 002_schemas.sql
-- Create logical schemas to separate concerns.

CREATE SCHEMA IF NOT EXISTS app;       -- All application tables
CREATE SCHEMA IF NOT EXISTS audit;     -- Append-only audit events (partitioned)
CREATE SCHEMA IF NOT EXISTS sync;      -- Sync state per device

-- Ensure the search path includes app schema
-- current_database() cannot be used directly as a DATABASE name token in ALTER DATABASE;
-- it must be resolved via dynamic SQL (EXECUTE ... format(...)) instead.
DO $$
BEGIN
    EXECUTE format('ALTER DATABASE %I SET search_path TO app, public', current_database());
END $$;
