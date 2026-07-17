use axum::{extract::State, response::IntoResponse, Extension, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use visitorpass_domain::{entities::{DenialReason, EntryLog}, value_objects::OrgContext};
use visitorpass_application::ports::repositories::{EntryFilter, PageParams};

use crate::{errors::ApiError, state::AppState};

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListEntriesParams {
    pub pass_id:     Option<Uuid>,
    pub location_id: Option<Uuid>,
    pub action:      Option<String>,
    pub limit:       Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct EntryLogResponse {
    pub id:                 Uuid,
    pub org_id:             Uuid,
    pub location_id:        Uuid,
    pub pass_id:            Uuid,
    pub device_id:          Option<Uuid>,
    pub guard_user_id:      Option<Uuid>,
    pub action:             String,
    pub denial_reason:      Option<DenialReason>,
    pub guard_note:         Option<String>,
    pub occurred_at:        chrono::DateTime<chrono::Utc>,
    pub server_received_at: chrono::DateTime<chrono::Utc>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// GET /api/v1/organizations/:org_id/entries
pub async fn list_entries(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    axum::extract::Query(params): axum::extract::Query<ListEntriesParams>,
) -> Result<impl IntoResponse, ApiError> {
    let limit = params.limit.unwrap_or(20);
    let page_params = PageParams::new(limit);

    let filter = EntryFilter {
        pass_id:     params.pass_id,
        location_id: params.location_id,
        action:      params.action,
        from:        None,
        to:          None,
    };

    let page = state.entries.list(&ctx, filter, page_params).await?;

    let items: Vec<EntryLogResponse> = page.items.into_iter().map(|log| EntryLogResponse {
        id:                 log.id,
        org_id:             log.org_id,
        location_id:        log.location_id,
        pass_id:            log.pass_id,
        device_id:          log.device_id,
        guard_user_id:      log.guard_user_id,
        action:             format!("{:?}", log.action).to_uppercase(),
        denial_reason:      log.denial_reason,
        guard_note:         log.guard_note,
        occurred_at:        log.occurred_at,
        server_received_at: log.server_received_at,
    }).collect();

    Ok(Json(serde_json::json!({
        "items":       items,
        "next_cursor": null
    })))
}
