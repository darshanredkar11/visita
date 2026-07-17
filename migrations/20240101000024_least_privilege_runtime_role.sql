-- Migration: 024_least_privilege_runtime_role.sql
--
-- Migration 023 added Postgres row-level security policies. They were
-- silently INERT: the app's only DB role, `visitorpass`, is the cluster's
-- bootstrap superuser (it's `POSTGRES_USER` in docker-compose, which the
-- official postgres image always makes a superuser). Postgres superusers
-- and BYPASSRLS-attributed roles bypass row security unconditionally --
-- there is no table-level setting, including FORCE ROW LEVEL SECURITY, that
-- can override this. Confirmed empirically: `SELECT count(*) FROM
-- app.organizations` as `visitorpass` returned all rows with zero GUCs set,
-- both before and after FORCE was added.
--
-- Postgres also refuses to let the bootstrap role strip its own SUPERUSER
-- attribute (`ALTER ROLE visitorpass NOSUPERUSER` -> "permission denied ...
-- The bootstrap user must have the SUPERUSER attribute"), and this
-- container has no other superuser to do it from. So `visitorpass` MUST
-- remain superuser -- it still owns every table and is what runs
-- migrations. The fix is a SECOND, genuinely unprivileged role for the
-- application's RUNTIME queries only, distinct from the migration/owner
-- role.
--
-- `visitorpass_app` gets plain DML (SELECT/INSERT/UPDATE/DELETE) on
-- existing tables, `ALTER DEFAULT PRIVILEGES` so tables created by FUTURE
-- migrations (still run as `visitorpass`) are automatically covered without
-- a new grant every time, and sequence USAGE (nextval/currval, needed for
-- any serial/identity columns). It gets no DDL rights at all -- notably it
-- cannot ALTER TABLE ... DISABLE ROW LEVEL SECURITY on its own tables,
-- which a merely-demoted-but-still-owner role could.
--
-- The app's runtime DATABASE_URL must be switched to this role for RLS to
-- have any real effect; see crates/api/src/main.rs (migrations run via a
-- separate, privileged connection string) and docker-compose.yml /
-- .env.example for the corresponding wiring.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'visitorpass_app') THEN
        CREATE ROLE visitorpass_app LOGIN PASSWORD 'CHANGEME_APP_ROLE_PASSWORD' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public, app, sync, audit TO visitorpass_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO visitorpass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app    TO visitorpass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA sync   TO visitorpass_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA audit  TO visitorpass_app;

GRANT USAGE ON ALL SEQUENCES IN SCHEMA public, app, sync, audit TO visitorpass_app;

ALTER DEFAULT PRIVILEGES FOR ROLE visitorpass IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO visitorpass_app;
ALTER DEFAULT PRIVILEGES FOR ROLE visitorpass IN SCHEMA app
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO visitorpass_app;
ALTER DEFAULT PRIVILEGES FOR ROLE visitorpass IN SCHEMA sync
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO visitorpass_app;
ALTER DEFAULT PRIVILEGES FOR ROLE visitorpass IN SCHEMA audit
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO visitorpass_app;
ALTER DEFAULT PRIVILEGES FOR ROLE visitorpass IN SCHEMA public, app, sync, audit
    GRANT USAGE ON SEQUENCES TO visitorpass_app;
