-- Migration: 001_extensions.sql
-- Enable required PostgreSQL extensions.
-- Must run as superuser or with CREATESUPERUSER privilege.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";    -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";   -- uuid_generate_v4() fallback
CREATE EXTENSION IF NOT EXISTS "pg_trgm";     -- trigram indexes for fuzzy name search
