-- Migration: 015_retention_cleanup.sql
-- Retention-aware data cleanup.
-- Drops old monthly entry_log partitions based on org retention policy.
-- Called from the application on a scheduled job (daily).

CREATE OR REPLACE FUNCTION app.cleanup_entry_logs_partition(
    p_partition_name TEXT
)
RETURNS VOID AS $$
BEGIN
    EXECUTE format('DROP TABLE IF EXISTS %I', p_partition_name);
    RAISE NOTICE 'Dropped old partition: %', p_partition_name;
END;
$$ LANGUAGE plpgsql;

-- Purge anonymous challenge tokens older than 5 minutes.
CREATE OR REPLACE FUNCTION app.cleanup_expired_challenges()
RETURNS INTEGER AS $$
DECLARE n INTEGER;
BEGIN
    DELETE FROM app.device_challenges WHERE expires_at < NOW();
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$ LANGUAGE plpgsql;

-- Purge expired sessions.
CREATE OR REPLACE FUNCTION app.cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE n INTEGER;
BEGIN
    DELETE FROM app.sessions WHERE expires_at < NOW() - INTERVAL '7 days';
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION app.cleanup_entry_logs_partition IS
    'Drops a named partition. Call after verifying age > org retention_days.';
