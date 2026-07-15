-- Migration: 014_pass_expiry_cron.sql
-- Periodic pass expiry. Run as a pg_cron job or scheduled query.
-- Marks active passes as expired when valid_until has passed.
-- This is a batch operation; frequency: every 15 minutes is adequate.

CREATE OR REPLACE FUNCTION app.expire_passes()
RETURNS INTEGER AS $$
DECLARE
    expired_count INTEGER;
BEGIN
    UPDATE app.visitor_passes
    SET    status     = 'EXPIRED',
           updated_at = NOW()
    WHERE  status     = 'ACTIVE'
      AND  valid_until < NOW();

    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$$ LANGUAGE plpgsql;

-- If pg_cron is available:
-- SELECT cron.schedule('expire-passes', '*/15 * * * *', 'SELECT app.expire_passes()');
-- Otherwise run from the application on a Tokio interval.
COMMENT ON FUNCTION app.expire_passes() IS
    'Marks all overdue passes as EXPIRED. Call every 15 minutes.';
