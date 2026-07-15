-- Migration: 018_ad_hoc_approvals.sql
-- Table to manage real-time ad-hoc visitor approval requests at gates.

CREATE TABLE app.ad_hoc_approvals (
    id                  UUID         NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id              UUID         NOT NULL REFERENCES app.organizations(id) ON DELETE CASCADE,
    location_id         UUID         NOT NULL REFERENCES app.locations(id) ON DELETE CASCADE,
    visitor_name        TEXT         NOT NULL,
    visitor_phone       TEXT         NOT NULL,
    unit_identifier     TEXT         NOT NULL,
    status              TEXT         NOT NULL, -- 'PENDING', 'APPROVED', 'DENIED'
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ad_hoc_approvals_org ON app.ad_hoc_approvals(org_id);
CREATE INDEX idx_ad_hoc_approvals_status ON app.ad_hoc_approvals(org_id, status);
