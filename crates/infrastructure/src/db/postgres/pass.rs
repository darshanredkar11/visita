use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use visitorpass_domain::{
    entities::{PassStatus, Permission, VisitorPass},
    value_objects::{OrgContext, PassNumber},
    DomainError,
};
use visitorpass_application::ports::repositories::{
    CreatePassInput, PassFilter, PassRepository, Page, PageParams, CursorPosition,
};

pub struct PgPassRepository {
    pool: PgPool,
}

impl PgPassRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PassRepository for PgPassRepository {
    async fn create(&self, ctx: &OrgContext, input: CreatePassInput) -> Result<VisitorPass, DomainError> {
        // Use the caller's id, not a freshly generated one: CreatePassUseCase
        // already embedded this exact id in the signed QR payload (CBOR
        // field 2) and used it to derive visitor_phone_enc's encryption key
        // before calling here. Generating a second, independent id at this
        // layer (as this used to do) would mean every QR code's embedded
        // pass_id permanently mismatched its own database row.
        let pass_id = input.pass_id;

        // Convert permissions from string representations
        let permissions_str: Vec<String> = input.permissions;

        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        sqlx::query(
            r#"
            INSERT INTO app.visitor_passes (
                id, org_id, location_id, created_by, pass_number, visitor_name, visitor_phone_hmac, visitor_phone_enc,
                purpose, vehicle_number, permissions, valid_from, valid_until, max_uses, use_count, qr_payload, qr_nonce, key_version,
                status, revoked_at, revoked_by, revocation_reason, created_at, updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8,
                $9, $10, $11::app.permission[], $12, $13, $14, 0, $15, $16, $17,
                'ACTIVE'::app.pass_status, NULL, NULL, NULL, NOW(), NOW()
            )
            "#,
        )
        .bind(pass_id)
        .bind(input.org_id)
        .bind(input.location_id)
        .bind(input.created_by)
        .bind(&input.pass_number)
        .bind(&input.visitor_name)
        .bind(&input.visitor_phone_hmac)
        .bind(&input.visitor_phone_enc)
        .bind(&input.purpose)
        .bind(&input.vehicle_number)
        .bind(&permissions_str)
        .bind(input.valid_from)
        .bind(input.valid_until)
        .bind(input.max_uses)
        .bind(&input.qr_payload)
        .bind(&input.qr_nonce)
        .bind(input.key_version)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create visitor pass in database");
            DomainError::CryptoError
        })?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        self.find_by_id(ctx, pass_id).await
    }

    async fn find_by_id(&self, ctx: &OrgContext, id: Uuid) -> Result<VisitorPass, DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        let row = sqlx::query(
            r#"
            SELECT id, org_id, location_id, created_by, pass_number, visitor_name, visitor_phone_hmac, visitor_phone_enc,
                   purpose, vehicle_number, permissions::text[], valid_from, valid_until, max_uses, use_count, qr_payload, qr_nonce, key_version,
                   status::text, revoked_at, revoked_by, revocation_reason, sync_seq, created_at, updated_at
            FROM app.visitor_passes
            WHERE id = $1 AND org_id = $2
            "#,
        )
        .bind(id)
        .bind(ctx.org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::PassNotFound(id))?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        Ok(map_row_to_pass(row)?)
    }

    async fn find_by_pass_number(&self, ctx: &OrgContext, number: &str) -> Result<VisitorPass, DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        let row = sqlx::query(
            r#"
            SELECT id, org_id, location_id, created_by, pass_number, visitor_name, visitor_phone_hmac, visitor_phone_enc,
                   purpose, vehicle_number, permissions::text[], valid_from, valid_until, max_uses, use_count, qr_payload, qr_nonce, key_version,
                   status::text, revoked_at, revoked_by, revocation_reason, sync_seq, created_at, updated_at
            FROM app.visitor_passes
            WHERE pass_number = $1 AND org_id = $2
            "#,
        )
        .bind(number)
        .bind(ctx.org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::PassNotFound(Uuid::nil()))?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        Ok(map_row_to_pass(row)?)
    }

    async fn find_by_pass_number_public(&self, number: &str) -> Result<VisitorPass, DomainError> {
        // RLS bypass (reason 2, see rls.rs): the public share page
        // (`/v/:pass_number`, no auth) looks a pass up by its number --
        // there is no org context on an anonymous request.
        let mut tx = super::rls::bypass_scoped_tx(&self.pool).await?;
        let row = sqlx::query(
            r#"
            SELECT id, org_id, location_id, created_by, pass_number, visitor_name, visitor_phone_hmac, visitor_phone_enc,
                   purpose, vehicle_number, permissions::text[], valid_from, valid_until, max_uses, use_count, qr_payload, qr_nonce, key_version,
                   status::text, revoked_at, revoked_by, revocation_reason, sync_seq, created_at, updated_at
            FROM app.visitor_passes
            WHERE pass_number = $1
            "#,
        )
        .bind(number)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::PassNotFound(Uuid::nil()))?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        Ok(map_row_to_pass(row)?)
    }

    async fn list(&self, ctx: &OrgContext, filter: PassFilter, page: PageParams) -> Result<Page<VisitorPass>, DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        let mut query = String::from(
            r#"
            SELECT id, org_id, location_id, created_by, pass_number, visitor_name, visitor_phone_hmac, visitor_phone_enc,
                   purpose, vehicle_number, permissions::text[], valid_from, valid_until, max_uses, use_count, qr_payload, qr_nonce, key_version,
                   status::text, revoked_at, revoked_by, revocation_reason, sync_seq, created_at, updated_at
            FROM app.visitor_passes
            WHERE org_id = $1
            "#,
        );

        let mut next_param_idx = 2;
        let mut bind_status = None;
        let mut bind_loc = None;
        let mut bind_user = None;
        let mut bind_from = None;
        let mut bind_to = None;

        if let Some(status) = filter.status {
            query.push_str(&format!(" AND status = ${}::app.pass_status", next_param_idx));
            bind_status = Some(status);
            next_param_idx += 1;
        }

        if let Some(loc_id) = filter.location_id {
            query.push_str(&format!(" AND location_id = ${}", next_param_idx));
            bind_loc = Some(loc_id);
            next_param_idx += 1;
        }

        if let Some(user_id) = filter.created_by {
            query.push_str(&format!(" AND created_by = ${}", next_param_idx));
            bind_user = Some(user_id);
            next_param_idx += 1;
        }

        if let Some(from) = filter.from {
            query.push_str(&format!(" AND created_at >= ${}", next_param_idx));
            bind_from = Some(from);
            next_param_idx += 1;
        }

        if let Some(to) = filter.to {
            query.push_str(&format!(" AND created_at <= ${}", next_param_idx));
            bind_to = Some(to);
            next_param_idx += 1;
        }

        let mut cursor_time = None;
        let mut cursor_id = None;

        if let Some(cursor) = &page.cursor {
            query.push_str(&format!(
                " AND (created_at < ${} OR (created_at = ${} AND id < ${}))",
                next_param_idx, next_param_idx + 1, next_param_idx + 2
            ));
            cursor_time = Some(cursor.created_at);
            cursor_id = Some(cursor.id);
            next_param_idx += 3;
        }

        query.push_str(&format!(" ORDER BY created_at DESC, id DESC LIMIT ${}", next_param_idx));

        let mut q = sqlx::query(&query).bind(ctx.org_id);

        if let Some(s) = bind_status { q = q.bind(s); }
        if let Some(l) = bind_loc { q = q.bind(l); }
        if let Some(u) = bind_user { q = q.bind(u); }
        if let Some(f) = bind_from { q = q.bind(f); }
        if let Some(t) = bind_to { q = q.bind(t); }

        if let (Some(ct), Some(cid)) = (cursor_time, cursor_id) {
            q = q.bind(ct).bind(ct).bind(cid);
        }
        q = q.bind(page.limit + 1);

        let rows = q.fetch_all(&mut *tx).await.map_err(|e| {
            tracing::error!(error = %e, "List passes DB error");
            DomainError::CryptoError
        })?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        let mut items = Vec::new();
        for row in rows {
            items.push(map_row_to_pass(row)?);
        }

        let mut next_cursor = None;
        if items.len() > page.limit as usize {
            items.pop();
            if let Some(last) = items.last() {
                next_cursor = Some(CursorPosition {
                    id: last.id,
                    created_at: last.created_at,
                });
            }
        }

        Ok(Page { items, next_cursor })
    }

    async fn revoke(
        &self,
        ctx: &OrgContext,
        pass_id: Uuid,
        revoked_by: Uuid,
        reason: Option<String>,
    ) -> Result<VisitorPass, DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        // Increment the org sequence and mark revoked.
        sqlx::query(
            r#"
            UPDATE app.visitor_passes
            SET status = 'REVOKED'::app.pass_status, revoked_at = NOW(), revoked_by = $3, revocation_reason = $4, updated_at = NOW()
            WHERE id = $1 AND org_id = $2 AND status = 'ACTIVE'
            "#,
        )
        .bind(pass_id)
        .bind(ctx.org_id)
        .bind(revoked_by)
        .bind(reason)
        .execute(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        self.find_by_id(ctx, pass_id).await
    }

    async fn increment_use_count(&self, ctx: &OrgContext, pass_id: Uuid) -> Result<(), DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        // Select use_count and max_uses
        let row = sqlx::query(
            r#"
            SELECT use_count, max_uses
            FROM app.visitor_passes
            WHERE id = $1 AND org_id = $2
            "#,
        )
        .bind(pass_id)
        .bind(ctx.org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::PassNotFound(pass_id))?;

        let use_count: i32 = row.get("use_count");
        let max_uses: i32 = row.get("max_uses");

        let next_count = use_count + 1;
        let new_status = if max_uses != -1 && next_count >= max_uses {
            "USED"
        } else {
            "ACTIVE"
        };

        sqlx::query(
            r#"
            UPDATE app.visitor_passes
            SET use_count = $3, status = $4::app.pass_status, updated_at = NOW()
            WHERE id = $1 AND org_id = $2 AND status = 'ACTIVE'
            "#,
        )
        .bind(pass_id)
        .bind(ctx.org_id)
        .bind(next_count)
        .bind(new_status)
        .execute(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        Ok(())
    }

    async fn list_for_sync(
        &self,
        org_id: Uuid,
        location_id: Uuid,
        since_sync_seq: i64,
    ) -> Result<Vec<VisitorPass>, DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, org_id).await?;
        let rows = sqlx::query(
            r#"
            SELECT id, org_id, location_id, created_by, pass_number, visitor_name, visitor_phone_hmac, visitor_phone_enc,
                   purpose, vehicle_number, permissions::text[], valid_from, valid_until, max_uses, use_count, qr_payload, qr_nonce, key_version,
                   status::text, revoked_at, revoked_by, revocation_reason, sync_seq, created_at, updated_at
            FROM app.visitor_passes
            WHERE org_id = $1 AND location_id = $2 AND sync_seq > $3 AND status = 'ACTIVE' AND valid_until > NOW()
            ORDER BY sync_seq ASC
            "#,
        )
        .bind(org_id)
        .bind(location_id)
        .bind(since_sync_seq)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        let mut items = Vec::new();
        for row in rows {
            items.push(map_row_to_pass(row)?);
        }
        Ok(items)
    }

    async fn list_revoked_since(
        &self,
        org_id: Uuid,
        since_sync_seq: i64,
    ) -> Result<Vec<(Uuid, DateTime<Utc>)>, DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, org_id).await?;
        let rows = sqlx::query(
            r#"
            SELECT id, revoked_at
            FROM app.visitor_passes
            WHERE org_id = $1 AND sync_seq > $2 AND status = 'REVOKED'
            ORDER BY sync_seq ASC
            "#,
        )
        .bind(org_id)
        .bind(since_sync_seq)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        let mut items = Vec::new();
        for row in rows {
            let id: Uuid = row.get("id");
            let revoked_at: DateTime<Utc> = row.get("revoked_at");
            items.push((id, revoked_at));
        }
        Ok(items)
    }
}

fn map_row_to_pass(row: sqlx::postgres::PgRow) -> Result<VisitorPass, DomainError> {
    let permissions_arr: Vec<String> = row.get("permissions");
    let permissions: Vec<Permission> = permissions_arr
        .into_iter()
        .filter_map(|s| match s.as_str() {
            "ENTRY" => Some(Permission::Entry),
            "EXIT" => Some(Permission::Exit),
            "VEHICLE" => Some(Permission::Vehicle),
            _ => None,
        })
        .collect();

    let status_str: String = row.get("status");
    let status = match status_str.as_str() {
        "REVOKED" => PassStatus::Revoked,
        "USED" => PassStatus::Used,
        "EXPIRED" => PassStatus::Expired,
        _ => PassStatus::Active,
    };

    let pass_num_str: String = row.get("pass_number");
    let pass_number = PassNumber::parse(&pass_num_str)?;

    Ok(VisitorPass {
        id: row.get("id"),
        org_id: row.get("org_id"),
        location_id: row.get("location_id"),
        created_by: row.get("created_by"),
        pass_number,
        visitor_name: row.get("visitor_name"),
        visitor_phone_hmac: row.get("visitor_phone_hmac"),
        visitor_phone_enc: row.get("visitor_phone_enc"),
        purpose: row.get("purpose"),
        vehicle_number: row.get("vehicle_number"),
        permissions,
        valid_from: row.get("valid_from"),
        valid_until: row.get("valid_until"),
        max_uses: row.get("max_uses"),
        use_count: row.get("use_count"),
        qr_payload: row.get("qr_payload"),
        qr_nonce: row.get("qr_nonce"),
        key_version: row.get("key_version"),
        status,
        revoked_at: row.get("revoked_at"),
        revoked_by: row.get("revoked_by"),
        revocation_reason: row.get("revocation_reason"),
        sync_seq: row.get("sync_seq"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}
