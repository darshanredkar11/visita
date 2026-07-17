-- Migration: 021_session_refresh_rotation.sql
-- app.sessions already had token_hash/previous_token_hash/family_id columns
-- designed for refresh-token rotation + theft detection, but no way to know
-- WHEN a token was rotated -- which is required to enforce the "previous
-- token is valid for a 5-minute grace window" rule. Add that timestamp.

ALTER TABLE app.sessions
    ADD COLUMN previous_token_rotated_at TIMESTAMPTZ;
