-- Migration: 025_device_checkpoints_rls.sql
--
-- sync.device_checkpoints was missed in 023's initial table scan (it lives
-- in the `sync` schema, not `app`). Same shape as every other table in 023:
-- has org_id, every access path already has org_id available (no
-- pre-authentication bootstrap lookups against this table), genuinely
-- tenant-owned data.
ALTER TABLE sync.device_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE sync.device_checkpoints FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON sync.device_checkpoints
    USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true')
    WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
           OR current_setting('app.rls_bypass', true) = 'true');
