-- Migration: 012_sync_seq_trigger.sql
-- Trigger: automatically assign sync_seq to visitor_pass rows on insert/update.
-- This ensures guard devices can ask "give me everything after seq N".

CREATE OR REPLACE FUNCTION app.assign_sync_seq()
RETURNS TRIGGER AS $$
BEGIN
    -- Increment the org's sync_seq and assign to the modified row.
    UPDATE app.organizations
    SET    sync_seq   = sync_seq + 1,
           updated_at = NOW()
    WHERE  id         = NEW.org_id
    RETURNING sync_seq INTO NEW.sync_seq;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_pass_sync_seq
    BEFORE INSERT OR UPDATE ON app.visitor_passes
    FOR EACH ROW
    EXECUTE FUNCTION app.assign_sync_seq();

-- Also set updated_at on every UPDATE.
CREATE OR REPLACE FUNCTION app.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_orgs_updated_at
    BEFORE UPDATE ON app.organizations
    FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON app.users
    FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();

CREATE TRIGGER trg_memberships_updated_at
    BEFORE UPDATE ON app.org_memberships
    FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();

CREATE TRIGGER trg_locations_updated_at
    BEFORE UPDATE ON app.locations
    FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();

CREATE TRIGGER trg_devices_updated_at
    BEFORE UPDATE ON app.devices
    FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();
