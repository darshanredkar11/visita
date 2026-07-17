-- Migration: 020_ad_hoc_approval_phone_encryption.sql
-- app.ad_hoc_approvals.visitor_phone was stored in plaintext. Mirror the
-- encryption pattern already used by app.visitor_passes exactly:
--   - visitor_phone_hmac: HMAC-SHA256(phone_e164) for lookup/dedup without
--     exposing the raw number (same derive_phone_hmac_key() server key).
--   - visitor_phone_enc: ChaCha20-Poly1305 ciphertext with the 12-byte nonce
--     PREPENDED to the ciphertext bytes (self-contained, single BYTEA column
--     -- this is the actual visitor_passes.visitor_phone_enc format; there is
--     no separate nonce column on that table, so none is added here either).
--
-- The plaintext column is dropped in this same migration so plaintext and
-- encrypted versions never coexist. V1 has no production traffic yet, so any
-- pre-existing rows (e.g. from local/dev testing) are cleared rather than
-- backfilled -- a real backfill would require running with MASTER_KEY_HEX
-- available to re-encrypt in an application-side migration script.

DELETE FROM app.ad_hoc_approvals;

ALTER TABLE app.ad_hoc_approvals
    DROP COLUMN visitor_phone,
    ADD COLUMN visitor_phone_hmac TEXT NOT NULL,
    ADD COLUMN visitor_phone_enc  BYTEA;

CREATE INDEX idx_ad_hoc_approvals_phone_hmac ON app.ad_hoc_approvals(org_id, visitor_phone_hmac);
