use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;
use visitorpass_domain::{entities::PlatformAdmin, value_objects::PlatformContext, DomainError};
use visitorpass_application::ports::repositories::PlatformAdminRepository;

pub struct PgPlatformAdminRepository {
    pool: PgPool,
}

impl PgPlatformAdminRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PlatformAdminRepository for PgPlatformAdminRepository {
    async fn is_platform_admin(&self, user_id: Uuid) -> Result<bool, DomainError> {
        let row = sqlx::query("SELECT 1 FROM app.platform_admins WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| DomainError::CryptoError)?;

        Ok(row.is_some())
    }

    async fn grant(&self, user_id: Uuid, granted_by: Option<Uuid>) -> Result<PlatformAdmin, DomainError> {
        let row = sqlx::query(
            r#"
            INSERT INTO app.platform_admins (user_id, granted_by, created_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (user_id) DO UPDATE SET user_id = EXCLUDED.user_id
            RETURNING user_id, granted_by, created_at
            "#,
        )
        .bind(user_id)
        .bind(granted_by)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?;

        Ok(row_to_platform_admin(&row))
    }

    async fn revoke(&self, _ctx: &PlatformContext, user_id: Uuid) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM app.platform_admins WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|_| DomainError::CryptoError)?;

        Ok(())
    }

    async fn list(&self, _ctx: &PlatformContext) -> Result<Vec<PlatformAdmin>, DomainError> {
        let rows = sqlx::query("SELECT user_id, granted_by, created_at FROM app.platform_admins ORDER BY created_at ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(|_| DomainError::CryptoError)?;

        Ok(rows.iter().map(row_to_platform_admin).collect())
    }
}

fn row_to_platform_admin(row: &sqlx::postgres::PgRow) -> PlatformAdmin {
    use sqlx::Row;
    PlatformAdmin {
        user_id:    row.get("user_id"),
        granted_by: row.get("granted_by"),
        created_at: row.get("created_at"),
    }
}
