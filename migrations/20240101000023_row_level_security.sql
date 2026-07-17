-- Migration: 023_row_level_security.sql
--
-- Adds genuine Postgres row-level security as a SECOND, defense-in-depth
-- layer underneath the existing application-layer scoping (every repository
-- method already requires `(ctx: &OrgContext, ..)` or an explicit `org_id`
-- param and adds `WHERE org_id = $N` by hand -- RLS means a query that
-- forgets that WHERE clause, or a future call site that copies an existing
-- query and edits it wrong, still cannot cross tenant boundaries).
--
-- Design: two session-local GUCs, set via `SET LOCAL` inside a transaction
-- by the repository layer (see crates/infrastructure/src/db/postgres/rls.rs)
-- so they never leak across pooled connections between requests:
--   * app.current_org_id  -- the caller's org, for ordinary org-scoped
--     requests. `current_setting(.., true)` returns NULL when unset, and
--     `col = NULL` is NULL (falsy) in SQL, so an unset GUC fails closed --
--     denies all rows -- rather than defaulting open.
--   * app.rls_bypass = 'true' -- set for the narrow set of code paths that
--     are legitimately not org-scoped: platform-admin cross-tenant queries,
--     and the handful of pre-authentication lookups that discover org_id
--     FROM the query itself (see exclusions below) rather than already
--     knowing it.
--
-- Table scope -- NOT every table with an org_id column gets a policy here.
-- Included (9, all genuinely tenant-owned operational/PII data, and every
-- access path already has an org_id or is a legitimate bypass case):
--   organizations, app.org_memberships, app.locations, app.devices,
--   app.visitor_passes, app.entry_logs (partitioned parent -- PG16
--   propagates policies to all existing and future partitions
--   automatically), app.org_keys, app.ad_hoc_approvals.
--
-- Deliberately EXCLUDED, each because org-scoping is structurally wrong or
-- impossible for it, not an oversight:
--   * app.users -- global identity table, no org_id column. A user's org
--     memberships live in app.org_memberships (which DOES get RLS); the
--     product spec's Sec 3.1 previously claimed "users" needed an org_id
--     FK, which was never true of this schema -- corrected in the same
--     change as this migration.
--   * app.device_challenges -- pre-pairing nonce table. No user or org
--     exists yet at the point a device requests a challenge.
--   * app.idempotency_keys -- the cache key is itself
--     `SHA256(org_id || path || client_key)` (see
--     crates/api/src/middleware/idempotency.rs), so cross-org collision is
--     already cryptographically prevented by construction; adding a
--     redundant org_id column purely to hang an RLS policy off of isn't
--     worth the schema churn for a transient cache table.
--   * app.share_page_views -- written by anonymous public requests (the
--     `/v/:pass_number` share page has no auth at all), so an INSERT policy
--     would have to be permissive-by-default anyway; low-sensitivity
--     analytics counter, not PII.
--   * app.sessions -- refresh/logout (`/auth/refresh`, `/auth/logout`) are
--     deliberately PUBLIC routes (an expired access token must still be
--     refreshable) that look a session up by `token_hash`, a random secret
--     the caller must already possess -- there is no org context to scope
--     by until AFTER that lookup succeeds. Possession of the hash-matching
--     secret IS the authorization boundary here, the same class of
--     guarantee idempotency_keys relies on.
--   * app.org_join_tokens -- `verify_join_token` exists specifically to
--     DISCOVER an org_id from an opaque invite token; same
--     lookup-before-context problem as sessions.

ALTER TABLE app.organizations     ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.organizations     FORCE ROW LEVEL SECURITY;
ALTER TABLE app.org_memberships   ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.org_memberships   FORCE ROW LEVEL SECURITY;
ALTER TABLE app.locations         ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.locations         FORCE ROW LEVEL SECURITY;
ALTER TABLE app.devices           ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.devices           FORCE ROW LEVEL SECURITY;
ALTER TABLE app.visitor_passes    ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.visitor_passes    FORCE ROW LEVEL SECURITY;
ALTER TABLE app.entry_logs        ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.entry_logs        FORCE ROW LEVEL SECURITY;
ALTER TABLE app.org_keys          ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.org_keys          FORCE ROW LEVEL SECURITY;
ALTER TABLE app.ad_hoc_approvals  ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.ad_hoc_approvals  FORCE ROW LEVEL SECURITY;

-- `organizations` is keyed on `id`, not `org_id` -- everything else below
-- uses `org_id` directly.
CREATE POLICY org_isolation ON app.organizations
    USING (id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true')
    WITH CHECK (id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true');

CREATE POLICY org_isolation ON app.org_memberships
    USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true')
    WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true');

CREATE POLICY org_isolation ON app.locations
    USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true')
    WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true');

CREATE POLICY org_isolation ON app.devices
    USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true')
    WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true');

CREATE POLICY org_isolation ON app.visitor_passes
    USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true')
    WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true');

CREATE POLICY org_isolation ON app.entry_logs
    USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true')
    WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true');

CREATE POLICY org_isolation ON app.org_keys
    USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true')
    WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true');

CREATE POLICY org_isolation ON app.ad_hoc_approvals
    USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true')
    WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true');
