-- Migration: 026_org_subscription_tier.sql
-- Platform Super-Admin Portal (product_specification.md section 2.1) --
-- "Global Billing & Subscriptions": tracks the SaaS subscription tier and
-- its associated plan limits per organization.
--
-- `subscription_tier` is deliberately a plain TEXT column (not a new
-- Postgres enum type like app.org_type/app.org_status) -- validation lives
-- in the Rust `SubscriptionTier` enum (as_str()/TryFrom, same pattern as
-- OrgType/OrgStatus) plus the CHECK constraint below, which is enough to
-- protect the column without a migration-time enum-alter dance every time
-- a new tier is added.
ALTER TABLE app.organizations
    ADD COLUMN subscription_tier TEXT    NOT NULL DEFAULT 'FREE',
    ADD COLUMN max_locations     INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN max_daily_passes  INTEGER NOT NULL DEFAULT 100;

ALTER TABLE app.organizations
    ADD CONSTRAINT organizations_subscription_tier_check
        CHECK (subscription_tier IN ('FREE', 'PRO', 'ENTERPRISE'));

ALTER TABLE app.organizations
    ADD CONSTRAINT organizations_max_locations_check    CHECK (max_locations > 0);
ALTER TABLE app.organizations
    ADD CONSTRAINT organizations_max_daily_passes_check CHECK (max_daily_passes > 0);

COMMENT ON COLUMN app.organizations.subscription_tier IS
    'SaaS billing tier: FREE, PRO, or ENTERPRISE. Set via platform-admin-only PUT /api/v1/platform/organizations/:org_id/tier.';
COMMENT ON COLUMN app.organizations.max_locations IS
    'Plan limit: max active app.locations rows this org may have. Enforced at the application layer, not by a DB trigger.';
COMMENT ON COLUMN app.organizations.max_daily_passes IS
    'Plan limit: max app.visitor_passes this org may create per rolling 24h. Enforced at the application layer, not by a DB trigger.';
