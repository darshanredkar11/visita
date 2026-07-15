use async_trait::async_trait;
use sqlx::PgPool;
use visitorpass_domain::DomainError;
use visitorpass_application::ports::repositories::{AuditEventInput, AuditRepository};

pub struct PgAuditRepository {
    pool: PgPool,
}

impl PgAuditRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditRepository for PgAuditRepository {
    async fn append(&self, input: AuditEventInput) -> Result<(), DomainError> {
        // Run fire-and-forget; log errors but don't fail user requests
        let _ = sqlx::query(
            r#"
            INSERT INTO audit.audit_events (
                id, org_id, event_type, actor_user_id, actor_device_id, target_entity_type, target_entity_id, metadata, ip_address, created_at
            )
            VALUES (
                gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8::inet, NOW()
            )
            "#,
        )
        .bind(input.org_id)
        .bind(&input.event_type)
        .bind(input.actor_user_id)
        .bind(input.actor_device_id)
        .bind(&input.target_entity_type)
        .bind(input.target_entity_id)
        .bind(&input.metadata)
        .bind(&input.ip_address)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            // Log audit failure but do not crash request
            tracing::error!(error = %e, "Failed to write audit event to database");
            e
        });

        Ok(())
    }
}
