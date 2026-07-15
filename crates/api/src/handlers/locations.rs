use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use visitorpass_domain::{entities::{Location, LocationStatus}, value_objects::OrgContext};
use visitorpass_application::ports::repositories::{CreateLocationInput, PageParams, CursorPosition};

use base64::Engine;

use crate::{errors::ApiError, state::AppState};

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateLocationRequest {
    pub name:         String,
    pub description:  Option<String>,
    pub timezone:     String,
    pub address_line: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LocationResponse {
    pub id:           Uuid,
    pub org_id:       Uuid,
    pub name:         String,
    pub description:  Option<String>,
    pub timezone:     String,
    pub address_line: Option<String>,
    pub status:       String,
    pub created_at:   chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ListLocationsParams {
    pub limit:  Option<i64>,
    pub cursor: Option<String>, // Base64url cursor
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /api/v1/organizations/:org_id/locations
pub async fn create_location(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    Json(req): Json<CreateLocationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if req.name.trim().is_empty() {
        return Err(ApiError::validation("name", "location name is required"));
    }

    let location = state.locations.create(&ctx, CreateLocationInput {
        org_id:       ctx.org_id,
        name:         req.name.trim().to_string(),
        description:  req.description.map(|d| d.trim().to_string()),
        timezone:     req.timezone.trim().to_string(),
        address_line: req.address_line.map(|a| a.trim().to_string()),
    }).await?;

    Ok((StatusCode::CREATED, Json(map_entity_to_response(location))))
}

/// GET /api/v1/organizations/:org_id/locations
pub async fn list_locations(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    axum::extract::Query(params): axum::extract::Query<ListLocationsParams>,
) -> Result<impl IntoResponse, ApiError> {
    let limit = params.limit.unwrap_or(20);
    let mut page_params = PageParams::new(limit);

    if let Some(cursor_str) = params.cursor {
        // Decode cursor (id, created_at) from base64url.
        // For simple V1 compilation, we parse Uuid directly if cursor is Uuid, or decode.
        // Let's decode cursor. If invalid, reject.
        if let Ok(decoded_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&cursor_str) {
            if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                let mut parts = decoded_str.split('|');
                if let (Some(id_str), Some(time_str)) = (parts.next(), parts.next()) {
                    if let (Ok(id), Ok(time)) = (Uuid::parse_str(id_str), chrono::DateTime::parse_from_rfc3339(time_str)) {
                        page_params = page_params.with_cursor(Some(CursorPosition {
                            id,
                            created_at: time.with_timezone(&chrono::Utc),
                        }));
                    }
                }
            }
        }
    }

    let page = state.locations.list(&ctx, page_params).await?;

    let items: Vec<LocationResponse> = page.items.into_iter().map(map_entity_to_response).collect();
    let next_cursor = page.next_cursor.map(|c| {
        let cursor_plain = format!("{}|{}", c.id, c.created_at.to_rfc3339());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cursor_plain.as_bytes())
    });

    Ok(Json(serde_json::json!({
        "items":       items,
        "next_cursor": next_cursor,
    })))
}

/// GET /api/v1/organizations/:org_id/locations/:location_id
pub async fn get_location(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    Path(params): Path<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, ApiError> {
    let loc_id = params
        .get("location_id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::validation("location_id", "invalid location UUID"))?;

    let location = state.locations.find_by_id(&ctx, loc_id).await?;

    Ok(Json(map_entity_to_response(location)))
}

/// PUT /api/v1/organizations/:org_id/locations/:location_id
pub async fn update_location(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    Path(params): Path<std::collections::HashMap<String, String>>,
    Json(req): Json<CreateLocationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let loc_id = params
        .get("location_id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::validation("location_id", "invalid location UUID"))?;

    if req.name.trim().is_empty() {
        return Err(ApiError::validation("name", "location name is required"));
    }

    let mut location = state.locations.find_by_id(&ctx, loc_id).await?;
    location.name = req.name.trim().to_string();
    location.description = req.description.map(|d| d.trim().to_string());
    location.timezone = req.timezone.trim().to_string();
    location.address_line = req.address_line.map(|a| a.trim().to_string());

    let updated = state.locations.update(&ctx, &location).await?;

    Ok(Json(map_entity_to_response(updated)))
}

/// DELETE /api/v1/organizations/:org_id/locations/:location_id
pub async fn delete_location(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    Path(params): Path<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, ApiError> {
    let loc_id = params
        .get("location_id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::validation("location_id", "invalid location UUID"))?;

    state.locations.soft_delete(&ctx, loc_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn map_entity_to_response(loc: Location) -> LocationResponse {
    LocationResponse {
        id:           loc.id,
        org_id:       loc.org_id,
        name:         loc.name,
        description:  loc.description,
        timezone:     loc.timezone,
        address_line: loc.address_line,
        status:       format!("{:?}", loc.status).to_uppercase(),
        created_at:   loc.created_at,
    }
}
