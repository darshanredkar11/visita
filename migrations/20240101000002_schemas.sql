-- Migration: 002_schemas.sql
-- Create logical schemas to separate concerns.

CREATE SCHEMA IF NOT EXISTS app;       -- All application tables
CREATE SCHEMA IF NOT EXISTS audit;     -- Append-only audit events (partitioned)
CREATE SCHEMA IF NOT EXISTS sync;      -- Sync state per device

-- Ensure the search path includes app schema
ALTER DATABASE current_database() SET search_path TO app, public;
