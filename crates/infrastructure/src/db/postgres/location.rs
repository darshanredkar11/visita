use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;
use visitorpass_domain::{
    entities::{Location, LocationStatus},
    value_objects::OrgContext,
    DomainError,
};
use visitorpass_application::ports::repositories::{
    CreateLocationInput, LocationRepository, Page, PageParams, CursorPosition,
};

pub struct PgLocationRepository {
    pool: PgPool,
}

impl PgLocationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl LocationRepository for PgLocationRepository {
    async fn create(&self, ctx: &OrgContext, input: CreateLocationInput) -> Result<Location, DomainError> {
        let location_id = Uuid::now_v7();
        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        sqlx::query(
            r#"
            INSERT INTO app.locations (id, org_id, name, description, timezone, address_line, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE'::app.location_status, NOW(), NOW())
            "#,
        )
        .bind(location_id)
        .bind(input.org_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.timezone)
        .bind(&input.address_line)
        .execute(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        self.find_by_id(ctx, location_id).await
    }

    async fn find_by_id(&self, ctx: &OrgContext, id: Uuid) -> Result<Location, DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        let row = sqlx::query(
            r#"
            SELECT id, org_id, name, description, timezone, address_line, status::text, created_at, updated_at
            FROM app.locations
            WHERE id = $1 AND org_id = $2 AND status != 'DELETED'
            "#,
        )
        .bind(id)
        .bind(ctx.org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::LocationNotFound(id))?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        let status_str: String = row.get("status");

        Ok(Location {
            id: row.get("id"),
            org_id: row.get("org_id"),
            name: row.get("name"),
            description: row.get("description"),
            timezone: row.get("timezone"),
            address_line: row.get("address_line"),
            status: match status_str.as_str() {
                "INACTIVE" => LocationStatus::Inactive,
                _ => LocationStatus::Active,
            },
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn list(&self, ctx: &OrgContext, page: PageParams) -> Result<Page<Location>, DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        let mut query = String::from(
            r#"
            SELECT id, org_id, name, description, timezone, address_line, status::text, created_at, updated_at
            FROM app.locations
            WHERE org_id = $1 AND status != 'DELETED'
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
            let status_str: String = row.get("status");
            items.push(Location {
                id: row.get("id"),
                org_id: row.get("org_id"),
                name: row.get("name"),
                description: row.get("description"),
                timezone: row.get("timezone"),
                address_line: row.get("address_line"),
                status: match status_str.as_str() {
                    "INACTIVE" => LocationStatus::Inactive,
                    _ => LocationStatus::Active,
                },
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

    async fn update(&self, ctx: &OrgContext, location: &Location) -> Result<Location, DomainError> {
        let status_str = match location.status {
            LocationStatus::Inactive => "INACTIVE",
            LocationStatus::Active => "ACTIVE",
            LocationStatus::Deleted => "DELETED",
        };

        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        sqlx::query(
            r#"
            UPDATE app.locations
            SET name = $3, description = $4, timezone = $5, address_line = $6, status = $7::app.location_status, updated_at = NOW()
            WHERE id = $1 AND org_id = $2 AND status != 'DELETED'
            "#,
        )
        .bind(location.id)
        .bind(ctx.org_id)
        .bind(&location.name)
        .bind(&location.description)
        .bind(&location.timezone)
        .bind(&location.address_line)
        .bind(status_str)
        .execute(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        self.find_by_id(ctx, location.id).await
    }

    async fn soft_delete(&self, ctx: &OrgContext, id: Uuid) -> Result<(), DomainError> {
        let mut tx = super::rls::org_scoped_tx(&self.pool, ctx.org_id).await?;
        sqlx::query(
            r#"
            UPDATE app.locations
            SET status = 'DELETED'::app.location_status, updated_at = NOW()
            WHERE id = $1 AND org_id = $2 AND status != 'DELETED'
            "#,
        )
        .bind(id)
        .bind(ctx.org_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| DomainError::CryptoError)?;
        tx.commit().await.map_err(|_| DomainError::CryptoError)?;

        Ok(())
    }
}
