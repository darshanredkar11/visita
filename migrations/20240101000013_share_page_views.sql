-- Migration: 013_share_page_view_log.sql
-- Log QR share page views for analytics (privacy-preserving: no IP stored).

CREATE TABLE app.share_page_views (
    id          UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    pass_id     UUID        NOT NULL REFERENCES app.visitor_passes(id),
    org_id      UUID        NOT NULL,
    user_agent  TEXT,
    referer     TEXT,
    viewed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_share_views_pass ON app.share_page_views(pass_id, viewed_at DESC);
