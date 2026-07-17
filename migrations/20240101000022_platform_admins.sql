-- Migration: 022_platform_admins.sql
--
-- Role model change (see Role enum in crates/domain/src/value_objects/role.rs):
--   * Guard, Resident unchanged.
--   * Owner is retired as a distinct tier. Grep across crates/api/src shows
--     every existing RBAC check already treats Owner and Admin identically
--     (`Role::Admin | Role::Owner`) -- there is no code path in this
--     repository that gates on Owner exclusively (e.g. no key-rotation
--     endpoint checks for it specifically). Owner and Admin are therefore
--     collapsed into a single org-scoped tier, renamed OrgAdmin to match the
--     product spec's role vocabulary (PlatformAdmin/OrgAdmin/Resident/Guard).
--   * PlatformAdmin is added as a NEW tier that is deliberately NOT a row in
--     app.org_memberships -- that table's primary key is (org_id, user_id)
--     and every existing query assumes a caller is scoped to exactly one
--     org. A platform admin operates across ALL orgs, so identity lives in
--     its own global table instead.
--
-- Postgres enums cannot drop a value, only add one (ALTER TYPE ... ADD
-- VALUE). We do not need to add PLATFORM_ADMIN to app.member_role at all --
-- platform admins never get an org_memberships row, so that DB enum never
-- needs to represent them. The Rust Role enum's extra PlatformAdmin variant
-- is carried purely as a PASETO token claim string, never persisted via
-- this column. The existing 'OWNER' label is left in place in the enum
-- (Postgres cannot remove it); the migration below moves every existing
-- row off of it and the Rust TryFrom parser still accepts "OWNER" as a
-- read-compat alias for Admin so any token minted in the ~15min window
-- around deploy still verifies.
UPDATE app.org_memberships SET role = 'ADMIN' WHERE role = 'OWNER';

-- Global platform administrators. Intentionally has NO org_id column --
-- that is the entire point of this tier. granted_by is nullable because the
-- very first platform admin has no predecessor to attribute the grant to
-- (seeded directly).
CREATE TABLE app.platform_admins (
    user_id    UUID PRIMARY KEY REFERENCES app.users(id),
    granted_by UUID REFERENCES app.users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
