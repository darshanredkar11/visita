-- Migration: 007_locations.sql

CREATE TYPE app.location_status AS ENUM ('ACTIVE', 'INACTIVE', 'DELETED');

CREATE TABLE app.locations (
    id            UUID                   NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id        UUID                   NOT NULL REFERENCES app.organizations(id),
    name          TEXT                   NOT NULL,
    description   TEXT,
    timezone      TEXT                   NOT NULL DEFAULT 'UTC',
    address_line  TEXT,
    status        app.location_status    NOT NULL DEFAULT 'ACTIVE',
    created_at    TIMESTAMPTZ            NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ            NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_locations_org ON app.locations(org_id) WHERE status != 'DELETED';
