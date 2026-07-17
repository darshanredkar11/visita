-- Migration: 027_denial_reason_enum.sql
-- app.entry_logs.denial_reason was free TEXT, and the three call sites that
-- ever wrote to it were already inconsistent with each other:
--   - VerifyPassUseCase's cross-org check:   "Pass issued by a different organization"
--   - VerifyPassUseCase's time-window check: the literal string "PASS_EXPIRED"
--   - VerifyPassUseCase's check_valid() branch: format!("{}", DomainError),
--     i.e. full human sentences ("Visitor pass has expired", "Visitor pass
--     has been revoked: {reason}", "Visitor pass has reached its maximum use
--     count", "Visitor pass is not yet valid (valid from: ...)")
--   - SyncEventsUseCase's guard-device sync path: arbitrary client-supplied
--     free text (SyncPushEvent.denial_reason), never validated server-side.
-- This migration makes denial_reason a closed, validated enum so every
-- consumer (API responses, entry log listing, analytics) gets one
-- consistent machine-readable code. Free-form guard context (e.g. "visitor
-- had no ID") already has a home in the separate guard_note TEXT column,
-- which is untouched by this migration.

CREATE TYPE app.denial_reason AS ENUM (
    'PASS_EXPIRED',        -- pass valid_until has passed, or PassStatus::Expired
    'PASS_REVOKED',        -- pass was explicitly revoked
    'PASS_EXHAUSTED',      -- pass reached its max_uses
    'PASS_NOT_YET_VALID',  -- now < pass valid_from
    'CROSS_ORG_MISMATCH',  -- QR's signed org_id != the scanning org's id
    'RESIDENT_DENIED',     -- resident denied an ad-hoc visitor approval request
                            -- (app.ad_hoc_approvals), relayed back to the gate
                            -- and recorded by the guard device via /api/v1/sync
    'OTHER'                -- guard's own judgment call; see guard_note for detail
);

-- Best-effort mapping of whatever free text exists today. This dev/staging
-- database has zero denial_reason rows at the time this migration was
-- written, but production-like environments may not -- so every historical
-- value this codebase is ever known to have produced is mapped explicitly,
-- and anything else (never-seen client free text) falls back to 'OTHER'
-- rather than failing the migration or silently dropping data.
DO $$
DECLARE
    unmapped_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO unmapped_count
    FROM app.entry_logs
    WHERE denial_reason IS NOT NULL
      AND denial_reason NOT ILIKE 'PASS_EXPIRED'
      AND denial_reason NOT ILIKE 'Visitor pass has expired'
      AND denial_reason NOT ILIKE 'Visitor pass has been revoked%'
      AND denial_reason NOT ILIKE 'PASS_REVOKED'
      AND denial_reason NOT ILIKE 'Visitor pass has reached its maximum use count'
      AND denial_reason NOT ILIKE 'PASS_EXHAUSTED'
      AND denial_reason NOT ILIKE 'Visitor pass is not yet valid%'
      AND denial_reason NOT ILIKE 'PASS_NOT_YET_VALID'
      AND denial_reason NOT ILIKE 'Pass issued by a different organization'
      AND denial_reason NOT ILIKE 'CROSS_ORG_MISMATCH'
      AND denial_reason NOT ILIKE 'RESIDENT_DENIED';

    IF unmapped_count > 0 THEN
        RAISE NOTICE 'denial_reason_enum migration: % existing row(s) had a free-text denial_reason with no exact match to a known historical value; mapped to OTHER', unmapped_count;
    END IF;
END $$;

ALTER TABLE app.entry_logs
    ALTER COLUMN denial_reason TYPE app.denial_reason
    USING (
        CASE
            WHEN denial_reason IS NULL THEN NULL
            WHEN denial_reason ILIKE 'PASS_EXPIRED'
                OR denial_reason ILIKE 'Visitor pass has expired'
                THEN 'PASS_EXPIRED'::app.denial_reason
            WHEN denial_reason ILIKE 'Visitor pass has been revoked%'
                OR denial_reason ILIKE 'PASS_REVOKED'
                THEN 'PASS_REVOKED'::app.denial_reason
            WHEN denial_reason ILIKE 'Visitor pass has reached its maximum use count'
                OR denial_reason ILIKE 'PASS_EXHAUSTED'
                THEN 'PASS_EXHAUSTED'::app.denial_reason
            WHEN denial_reason ILIKE 'Visitor pass is not yet valid%'
                OR denial_reason ILIKE 'PASS_NOT_YET_VALID'
                THEN 'PASS_NOT_YET_VALID'::app.denial_reason
            WHEN denial_reason ILIKE 'Pass issued by a different organization'
                OR denial_reason ILIKE 'CROSS_ORG_MISMATCH'
                THEN 'CROSS_ORG_MISMATCH'::app.denial_reason
            WHEN denial_reason ILIKE 'RESIDENT_DENIED'
                THEN 'RESIDENT_DENIED'::app.denial_reason
            ELSE 'OTHER'::app.denial_reason
        END
    );

COMMENT ON COLUMN app.entry_logs.denial_reason IS
    'Structured reason a DENIED entry_log was denied. NULL for ENTRY/EXIT. See app.denial_reason enum; guard-entered free text belongs in guard_note instead.';
