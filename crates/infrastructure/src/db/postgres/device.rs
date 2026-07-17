use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use visitorpass_domain::{
    entities::{Device, DeviceStatus, DeviceType},
    value_objects::{OrgContext, PlatformContext},
    DomainError,
};
use visitorpass_application::ports::repositories::{
    CreateDeviceInput, DeviceRepository, Page, PageParams, CursorPosition,
};

pub struct PgDeviceRepository {
    pool: PgPool,
}

impl PgDeviceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DeviceRepository for PgDeviceRepository {
    async fn create(&self, ctx: &OrgContext, input: CreateDeviceInput) -> Result<Device, DomainError> {
        let device_id = Uuid::now_v7();
        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        sqlx::query(
            r#"
            INSERT INTO app.devices (id, org_id, location_id, owner_user_id, device_type, name, public_key, platform, os_version, app_version, push_token, last_seen_at, status, revoked_at, revoked_by, revocation_reason, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5::app.device_type, $6, $7, $8, $9, $10, $11, NULL, 'ACTIVE'::app.device_status, NULL, NULL, NULL, NOW(), NOW())
            "#,
        )
        .bind(device_id)
        .bind(input.org_id)
        .bind(input.location_id)
        .bind(input.owner_user_id)
        .bind(&input.device_type)
        .bind(&input.name)
        .bind(&input.public_key)
        .bind(&input.platform)
        .bind(&input.os_version)
        .bind(&input.app_version)
        .bind(&input.push_token)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if let Some(db_err) = e.as_database_error() {
                if db_err.is_unique_violation() {
                    return DomainError::DeviceKeyAlreadyExists;
                }
            }
            DomainError::CryptoError
        })?;

        // Initialize sync checkpoint to 0 (same transaction, same org).
        sqlx::query(
            r#"
            INSERT INTO sync.device_checkpoints (device_id, org_id, last_seq, updated_at)
            VALUES ($1, $2, 0, NOW())
            "#,
        )
        .bind(device_id)
        .bind(input.org_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        self.find_by_id(ctx, device_id).await
    }

    async fn find_by_id(&self, ctx: &OrgContext, id: Uuid) -> Result<Device, DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        let row = sqlx::query(
            r#"
            SELECT id, org_id, location_id, owner_user_id, device_type::text, name, public_key, platform, os_version, app_version, push_token, last_seen_at, status::text, revoked_at, revoked_by, revocation_reason, created_at, updated_at
            FROM app.devices
            WHERE id = $1 AND org_id = $2
            "#,
        )
        .bind(id)
        .bind(ctx.org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::DeviceNotFound(id))?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        let type_str: String = row.get("device_type");
        let status_str: String = row.get("status");

        Ok(Device {
            id: row.get("id"),
            org_id: row.get("org_id"),
            location_id: row.get("location_id"),
            owner_user_id: row.get("owner_user_id"),
            device_type: match type_str.as_str() {
                "GUARD_TABLET" => DeviceType::GuardTablet,
                "GUARD_KIOSK" => DeviceType::GuardKiosk,
                _ => DeviceType::ResidentPhone,
            },
            name: row.get("name"),
            public_key: row.get("public_key"),
            platform: row.get("platform"),
            os_version: row.get("os_version"),
            app_version: row.get("app_version"),
            push_token: row.get("push_token"),
            last_seen_at: row.get("last_seen_at"),
            status: match status_str.as_str() {
                "REVOKED" => DeviceStatus::Revoked,
                _ => DeviceStatus::Active,
            },
            revoked_at: row.get("revoked_at"),
            revoked_by: row.get("revoked_by"),
            revocation_reason: row.get("revocation_reason"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn find_by_owner(&self, ctx: &OrgContext, owner_user_id: Uuid) -> Result<Vec<Device>, DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        let rows = sqlx::query(
            r#"
            SELECT id, org_id, location_id, owner_user_id, device_type::text, name, public_key, platform, os_version, app_version, push_token, last_seen_at, status::text, revoked_at, revoked_by, revocation_reason, created_at, updated_at
            FROM app.devices
            WHERE org_id = $1 AND owner_user_id = $2 AND status = 'ACTIVE'::app.device_status
            ORDER BY last_seen_at DESC NULLS LAST, created_at DESC
            "#,
        )
        .bind(ctx.org_id)
        .bind(owner_user_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "find_by_owner DB error");
            DomainError::CryptoError
        })?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        let mut devices = Vec::with_capacity(rows.len());
        for row in rows {
            let type_str: String = row.get("device_type");
            let status_str: String = row.get("status");
            devices.push(Device {
                id: row.get("id"),
                org_id: row.get("org_id"),
                location_id: row.get("location_id"),
                owner_user_id: row.get("owner_user_id"),
                device_type: match type_str.as_str() {
                    "GUARD_TABLET" => DeviceType::GuardTablet,
                    "GUARD_KIOSK" => DeviceType::GuardKiosk,
                    _ => DeviceType::ResidentPhone,
                },
                name: row.get("name"),
                public_key: row.get("public_key"),
                platform: row.get("platform"),
                os_version: row.get("os_version"),
                app_version: row.get("app_version"),
                push_token: row.get("push_token"),
                last_seen_at: row.get("last_seen_at"),
                status: match status_str.as_str() {
                    "REVOKED" => DeviceStatus::Revoked,
                    _ => DeviceStatus::Active,
                },
                revoked_at: row.get("revoked_at"),
                revoked_by: row.get("revoked_by"),
                revocation_reason: row.get("revocation_reason"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            });
        }
        Ok(devices)
    }

    async fn find_by_public_key(&self, public_key: &[u8]) -> Result<Device, DomainError> {
        // RLS bypass (reason 2, see rls.rs): device-login challenge
        // verification looks a device up by its public key BEFORE any org
        // context exists -- discovering org_id is the entire point.
        let mut tx = super::rls::bypass_scoped_tx(&self.pool).await?;
        let row = sqlx::query(
            r#"
            SELECT id, org_id, location_id, owner_user_id, device_type::text, name, public_key, platform, os_version, app_version, push_token, last_seen_at, status::text, revoked_at, revoked_by, revocation_reason, created_at, updated_at
            FROM app.devices
            WHERE public_key = $1
            "#,
        )
        .bind(public_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::InvitationNotFound)?; // generic mapping for auth
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        let type_str: String = row.get("device_type");
        let status_str: String = row.get("status");

        Ok(Device {
            id: row.get("id"),
            org_id: row.get("org_id"),
            location_id: row.get("location_id"),
            owner_user_id: row.get("owner_user_id"),
            device_type: match type_str.as_str() {
                "GUARD_TABLET" => DeviceType::GuardTablet,
                "GUARD_KIOSK" => DeviceType::GuardKiosk,
                _ => DeviceType::ResidentPhone,
            },
            name: row.get("name"),
            public_key: row.get("public_key"),
            platform: row.get("platform"),
            os_version: row.get("os_version"),
            app_version: row.get("app_version"),
            push_token: row.get("push_token"),
            last_seen_at: row.get("last_seen_at"),
            status: match status_str.as_str() {
                "REVOKED" => DeviceStatus::Revoked,
                _ => DeviceStatus::Active,
            },
            revoked_at: row.get("revoked_at"),
            revoked_by: row.get("revoked_by"),
            revocation_reason: row.get("revocation_reason"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn list(&self, ctx: &OrgContext, page: PageParams) -> Result<Page<Device>, DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        let mut query = String::from(
            r#"
            SELECT id, org_id, location_id, owner_user_id, device_type::text, name, public_key, platform, os_version, app_version, push_token, last_seen_at, status::text, revoked_at, revoked_by, revocation_reason, created_at, updated_at
            FROM app.devices
            WHERE org_id = $1
            "#,
        );

        let mut next_param_idx = 2;
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

        if let (Some(ct), Some(cid)) = (cursor_time, cursor_id) {
            q = q.bind(ct).bind(ct).bind(cid);
        }
        q = q.bind(page.limit + 1);

        let rows = q.fetch_all(&mut *tx).await.map_err(|_| DomainError::CryptoError)?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        let mut items = Vec::new();
        for row in rows {
            let type_str: String = row.get("device_type");
            let status_str: String = row.get("status");
            items.push(Device {
                id: row.get("id"),
                org_id: row.get("org_id"),
                location_id: row.get("location_id"),
                owner_user_id: row.get("owner_user_id"),
                device_type: match type_str.as_str() {
                    "GUARD_TABLET" => DeviceType::GuardTablet,
                    "GUARD_KIOSK" => DeviceType::GuardKiosk,
                    _ => DeviceType::ResidentPhone,
                },
                name: row.get("name"),
                public_key: row.get("public_key"),
                platform: row.get("platform"),
                os_version: row.get("os_version"),
                app_version: row.get("app_version"),
                push_token: row.get("push_token"),
                last_seen_at: row.get("last_seen_at"),
                status: match status_str.as_str() {
                    "REVOKED" => DeviceStatus::Revoked,
                    _ => DeviceStatus::Active,
                },
                revoked_at: row.get("revoked_at"),
                revoked_by: row.get("revoked_by"),
                revocation_reason: row.get("revocation_reason"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            });
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
        device_id: Uuid,
        reason: Option<String>,
    ) -> Result<Device, DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        sqlx::query(
            r#"
            UPDATE app.devices
            SET status = 'REVOKED'::app.device_status, revoked_at = NOW(), revoked_by = $3, revocation_reason = $4, updated_at = NOW()
            WHERE id = $1 AND org_id = $2 AND status != 'REVOKED'
            "#,
        )
        .bind(device_id)
        .bind(ctx.org_id)
        .bind(ctx.user_id)
        .bind(reason)
        .execute(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        self.find_by_id(ctx, device_id).await
    }

    async fn revoke_platform(
        &self,
        ctx: &PlatformContext,
        device_id: Uuid,
        reason: Option<String>,
    ) -> Result<Device, DomainError> {
        // RLS bypass (reason 1, see rls.rs): platform-admin revocation
        // must work for a device in ANY org -- unlike `revoke` above, the
        // caller does not (and must not need to) already know org_id.
        let mut tx = super::rls::bypass_scoped_tx(&self.pool).await?;
        sqlx::query(
            r#"
            UPDATE app.devices
            SET status = 'REVOKED'::app.device_status, revoked_at = NOW(), revoked_by = $2, revocation_reason = $3, updated_at = NOW()
            WHERE id = $1 AND status != 'REVOKED'
            "#,
        )
        .bind(device_id)
        .bind(ctx.user_id)
        .bind(reason)
        .execute(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        let row = sqlx::query(
            r#"
            SELECT id, org_id, location_id, owner_user_id, device_type::text, name, public_key, platform, os_version, app_version, push_token, last_seen_at, status::text, revoked_at, revoked_by, revocation_reason, created_at, updated_at
            FROM app.devices
            WHERE id = $1
            "#,
        )
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::DeviceNotFound(device_id))?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        let type_str: String = row.get("device_type");
        let status_str: String = row.get("status");

        Ok(Device {
            id: row.get("id"),
            org_id: row.get("org_id"),
            location_id: row.get("location_id"),
            owner_user_id: row.get("owner_user_id"),
            device_type: match type_str.as_str() {
                "GUARD_TABLET" => DeviceType::GuardTablet,
                "GUARD_KIOSK" => DeviceType::GuardKiosk,
                _ => DeviceType::ResidentPhone,
            },
            name: row.get("name"),
            public_key: row.get("public_key"),
            platform: row.get("platform"),
            os_version: row.get("os_version"),
            app_version: row.get("app_version"),
            push_token: row.get("push_token"),
            last_seen_at: row.get("last_seen_at"),
            status: match status_str.as_str() {
                "REVOKED" => DeviceStatus::Revoked,
                _ => DeviceStatus::Active,
            },
            revoked_at: row.get("revoked_at"),
            revoked_by: row.get("revoked_by"),
            revocation_reason: row.get("revocation_reason"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn update_last_seen(&self, device_id: Uuid, org_id: Uuid) -> Result<(), DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, org_id).await?;
        sqlx::query(
            r#"
            UPDATE app.devices
            SET last_seen_at = NOW(), updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(device_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        Ok(())
    }

    async fn get_sync_checkpoint(&self, device_id: Uuid, org_id: Uuid) -> Result<i64, DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, org_id).await?;
        let row = sqlx::query(
            r#"
            SELECT last_seq
            FROM sync.device_checkpoints
            WHERE device_id = $1 AND org_id = $2
            "#,
        )
        .bind(device_id)
        .bind(org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::UnknownKeyVersion(0))?; // checkpoint not initialized should map appropriately
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        Ok(row.get("last_seq"))
    }

    async fn update_sync_checkpoint(
        &self,
        device_id: Uuid,
        org_id: Uuid,
        new_seq: i64,
    ) -> Result<(), DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, org_id).await?;
        sqlx::query(
            r#"
            INSERT INTO sync.device_checkpoints (device_id, org_id, last_seq, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (device_id, org_id) DO UPDATE
            SET last_seq = EXCLUDED.last_seq, updated_at = NOW()
            "#,
        )
        .bind(device_id)
        .bind(org_id)
        .bind(new_seq)
        .execute(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        Ok(())
    }
}
