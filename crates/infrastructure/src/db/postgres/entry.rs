use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use visitorpass_domain::{
    entities::{EntryAction, EntryLog},
    value_objects::OrgContext,
    DomainError,
};
use visitorpass_application::ports::repositories::{
    CreateEntryInput, EntryFilter, EntryRepository, Page, PageParams, CursorPosition,
};

pub struct PgEntryRepository {
    pool: PgPool,
}

impl PgEntryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl EntryRepository for PgEntryRepository {
    async fn create(
        &self,
        ctx: &OrgContext,
        input: CreateEntryInput,
    ) -> Result<Option<EntryLog>, DomainError> {
        let entry_id = Uuid::now_v7();

        // Use the global unique index idx_entry_logs_idempotency: (org_id, client_event_id)
        // INSERT ... ON CONFLICT DO NOTHING.
        let result = sqlx::query(
            r#"
            INSERT INTO app.entry_logs (
                id, org_id, location_id, pass_id, device_id, guard_user_id, action, denial_reason, guard_note, occurred_at, server_received_at, client_event_id, created_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7::app.entry_action, $8, $9, $10, NOW(), $11, NOW()
            )
            ON CONFLICT (org_id, client_event_id) DO NOTHING
            "#,
        )
        .bind(entry_id)
        .bind(input.org_id)
        .bind(input.location_id)
        .bind(input.pass_id)
        .bind(input.device_id)
        .bind(input.guard_user_id)
        .bind(&input.action)
        .bind(&input.denial_reason)
        .bind(&input.guard_note)
        .bind(input.occurred_at)
        .bind(input.client_event_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Create entry log DB error");
            DomainError::CryptoError
        })?;

        if result.rows_affected() == 0 {
            // Already synced, idempotent ignore
            return Ok(None);
        }

        let entry = self.find_by_id(ctx, entry_id).await?;
        Ok(Some(entry))
    }

    async fn find_by_id(&self, ctx: &OrgContext, id: Uuid) -> Result<EntryLog, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT id, org_id, location_id, pass_id, device_id, guard_user_id, action::text, denial_reason, guard_note, occurred_at, server_received_at, client_event_id, created_at
            FROM app.entry_logs
            WHERE id = $1 AND org_id = $2
            "#,
        )
        .bind(id)
        .bind(ctx.org_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| DomainError::CryptoError)?
        .ok_or(DomainError::EntryNotFound(id))?;

        let action_str: String = row.get("action");
        let action = match action_str.as_str() {
            "EXIT" => EntryAction::Exit,
            "DENIED" => EntryAction::Denied,
            _ => EntryAction::Entry,
        };

        Ok(EntryLog {
            id: row.get("id"),
            org_id: row.get("org_id"),
            location_id: row.get("location_id"),
            pass_id: row.get("pass_id"),
            device_id: row.get("device_id"),
            guard_user_id: row.get("guard_user_id"),
            action,
            denial_reason: row.get("denial_reason"),
            guard_note: row.get("guard_note"),
            occurred_at: row.get("occurred_at"),
            server_received_at: row.get("server_received_at"),
            client_event_id: row.get("client_event_id"),
            created_at: row.get("created_at"),
        })
    }

    async fn list(
        &self,
        ctx: &OrgContext,
        filter: EntryFilter,
        page: PageParams,
    ) -> Result<Page<EntryLog>, DomainError> {
        let mut query = String::from(
            r#"
            SELECT id, org_id, location_id, pass_id, device_id, guard_user_id, action::text, denial_reason, guard_note, occurred_at, server_received_at, client_event_id, created_at
            FROM app.entry_logs
            WHERE org_id = $1
            "#,
        );

        let mut next_param_idx = 2;
        let mut bind_pass = None;
        let mut bind_loc = None;
        let mut bind_action = None;
        let mut bind_from = None;
        let mut bind_to = None;

        if let Some(pass_id) = filter.pass_id {
            query.push_str(&format!(" AND pass_id = ${}", next_param_idx));
            bind_pass = Some(pass_id);
            next_param_idx += 1;
        }

        if let Some(loc_id) = filter.location_id {
            query.push_str(&format!(" AND location_id = ${}", next_param_idx));
            bind_loc = Some(loc_id);
            next_param_idx += 1;
        }

        if let Some(action) = filter.action {
            query.push_str(&format!(" AND action = ${}::app.entry_action", next_param_idx));
            bind_action = Some(action);
            next_param_idx += 1;
        }

        if let Some(from) = filter.from {
            query.push_str(&format!(" AND occurred_at >= ${}", next_param_idx));
            bind_from = Some(from);
            next_param_idx += 1;
        }

        if let Some(to) = filter.to {
            query.push_str(&format!(" AND occurred_at <= ${}", next_param_idx));
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

        if let Some(p) = bind_pass { q = q.bind(p); }
        if let Some(l) = bind_loc { q = q.bind(l); }
        if let Some(a) = bind_action { q = q.bind(a); }
        if let Some(f) = bind_from { q = q.bind(f); }
        if let Some(t) = bind_to { q = q.bind(t); }

        if let (Some(ct), Some(cid)) = (cursor_time, cursor_id) {
            q = q.bind(ct).bind(ct).bind(cid);
        }
        q = q.bind(page.limit + 1);

        let rows = q.fetch_all(&self.pool).await.map_err(|e| {
            tracing::error!(error = %e, "List entries DB error");
            DomainError::CryptoError
        })?;

        let mut items = Vec::new();
        for row in rows {
            let action_str: String = row.get("action");
            let action = match action_str.as_str() {
                "EXIT" => EntryAction::Exit,
                "DENIED" => EntryAction::Denied,
                _ => EntryAction::Entry,
            };
            items.push(EntryLog {
                id: row.get("id"),
                org_id: row.get("org_id"),
                location_id: row.get("location_id"),
                pass_id: row.get("pass_id"),
                device_id: row.get("device_id"),
                guard_user_id: row.get("guard_user_id"),
                action,
                denial_reason: row.get("denial_reason"),
                guard_note: row.get("guard_note"),
                occurred_at: row.get("occurred_at"),
                server_received_at: row.get("server_received_at"),
                client_event_id: row.get("client_event_id"),
                created_at: row.get("created_at"),
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
}
