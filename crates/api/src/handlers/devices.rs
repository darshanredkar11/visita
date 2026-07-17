use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use visitorpass_domain::{entities::Device, value_objects::OrgContext};
use visitorpass_application::ports::repositories::PageParams;

use crate::{errors::ApiError, state::AppState};

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    pub location_id:   Option<Uuid>,
    pub owner_user_id: Option<Uuid>,
    pub device_type:   String,
    pub name:          String,
    pub public_key:    String, // hex encoded Ed25519 public key (32 bytes)
    pub platform:      Option<String>,
    pub os_version:    Option<String>,
    pub app_version:   Option<String>,
    /// FCM/APNs push registration token for this device. Column is named
    /// `push_token` (not `fcm_token`, despite that name appearing in some
    /// task/spec text) -- see `app.devices.push_token`.
    pub push_token:    Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeDeviceRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceResponse {
    pub id:                Uuid,
    pub org_id:            Uuid,
    pub location_id:       Option<Uuid>,
    pub owner_user_id:     Option<Uuid>,
    pub device_type:       String,
    pub name:              String,
    pub public_key:        String, // hex encoded
    pub platform:          Option<String>,
    pub os_version:        Option<String>,
    pub app_version:       Option<String>,
    pub status:            String,
    pub last_seen_at:      Option<chrono::DateTime<chrono::Utc>>,
    pub created_at:        chrono::DateTime<chrono::Utc>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /api/v1/organizations/:org_id/devices
pub async fn register_device(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if req.name.trim().is_empty() {
        return Err(ApiError::validation("name", "device name is required"));
    }
    let pub_key_bytes = hex::decode(&req.public_key)
        .map_err(|_| ApiError::validation("public_key", "must be valid hexadecimal"))?;

    let device = state.register_device.execute(
        &ctx,
        visitorpass_application::use_cases::register_device::RegisterDeviceInput {
            location_id:   req.location_id,
            owner_user_id: req.owner_user_id,
            device_type:   req.device_type,
            name:          req.name,
            public_key:    pub_key_bytes,
            platform:      req.platform,
            os_version:    req.os_version,
            app_version:   req.app_version,
            push_token:    req.push_token,
        },
    ).await?;

    Ok((StatusCode::CREATED, Json(map_entity_to_response(device))))
}

/// POST /api/v1/organizations/:org_id/devices/:device_id/revoke
pub async fn revoke_device(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    Path(params): Path<std::collections::HashMap<String, String>>,
    Json(req): Json<RevokeDeviceRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let dev_id = params
        .get("device_id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::validation("device_id", "invalid device UUID"))?;

    let device = state.revoke_device.execute(&ctx, dev_id, req.reason).await?;

    Ok(Json(map_entity_to_response(device)))
}

/// GET /api/v1/organizations/:org_id/devices
pub async fn list_devices(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    axum::extract::Query(params): axum::extract::Query<super::locations::ListLocationsParams>,
) -> Result<impl IntoResponse, ApiError> {
    let limit = params.limit.unwrap_or(20);
    let page_params = PageParams::new(limit);
    // V1 listing implementation (cursors ignored for device listing since device count per org is low)
    let page = state.devices.list(&ctx, page_params).await?;
    let items: Vec<DeviceResponse> = page.items.into_iter().map(map_entity_to_response).collect();

    Ok(Json(serde_json::json!({
        "items": items,
        "next_cursor": null
    })))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn map_entity_to_response(dev: Device) -> DeviceResponse {
    DeviceResponse {
        id:                dev.id,
        org_id:            dev.org_id,
        location_id:       dev.location_id,
        owner_user_id:     dev.owner_user_id,
        device_type:       format!("{:?}", dev.device_type).to_uppercase(),
        name:              dev.name,
        public_key:        hex::encode(dev.public_key),
        platform:          dev.platform,
        os_version:        dev.os_version,
        app_version:       dev.app_version,
        status:            format!("{:?}", dev.status).to_uppercase(),
        last_seen_at:      dev.last_seen_at,
        created_at:        dev.created_at,
    }
}
