use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use visitorpass_domain::value_objects::OrgContext;

use crate::{errors::ApiError, state::AppState};

// ── Request / Response DTOs ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreatePassRequest {
    pub location_id:    Uuid,
    pub visitor_name:   String,
    pub visitor_phone:  String,
    pub purpose:        String,
    pub vehicle_number: Option<String>,
    #[serde(default = "default_permissions")]
    pub permissions:    Vec<String>,
    pub valid_from:     chrono::DateTime<Utc>,
    pub valid_until:    chrono::DateTime<Utc>,
    #[serde(default = "default_max_uses")]
    pub max_uses:       i32,
}

fn default_permissions() -> Vec<String> { vec!["ENTRY".into(), "EXIT".into()] }
fn default_max_uses()     -> i32        { 1 }

#[derive(Debug, Serialize)]
pub struct PassResponse {
    pub id:             Uuid,
    pub org_id:         Uuid,
    pub location_id:    Uuid,
    pub created_by:     Uuid,
    pub pass_number:    String,
    pub visitor_name:   String,
    pub purpose:        String,
    pub vehicle_number: Option<String>,
    pub permissions:    Vec<String>,
    pub valid_from:     chrono::DateTime<Utc>,
    pub valid_until:    chrono::DateTime<Utc>,
    pub max_uses:       i32,
    pub use_count:      i32,
    pub qr_payload:     String,
    pub status:         String,
    pub share_url:      String,
    pub created_at:     chrono::DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ListPassesParams {
    #[serde(default)]
    pub limit: Option<i64>,
    pub cursor: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokePassRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyPassRequest {
    pub qr_payload:  String,
    pub location_id: Uuid,
    #[serde(default = "default_action")]
    pub action:      String,
}

fn default_action() -> String { "ENTRY".into() }

#[derive(Debug, Serialize)]
pub struct VerifyPassResponse {
    pub valid:          bool,
    pub pass_id:        Uuid,
    pub pass_number:    String,
    pub visitor_name:   String,
    pub purpose:        String,
    pub vehicle_number: Option<String>,
    pub permissions:    Vec<String>,
    pub valid_from:     chrono::DateTime<Utc>,
    pub valid_until:    chrono::DateTime<Utc>,
    pub status:         String,
    pub denial_reason:  Option<String>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /api/v1/organizations/:org_id/passes
pub async fn create_pass(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    Json(req): Json<CreatePassRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Basic input validation
    if req.visitor_name.trim().is_empty() {
        return Err(ApiError::validation("visitor_name", "must not be empty"));
    }
    if req.purpose.trim().is_empty() {
        return Err(ApiError::validation("purpose", "must not be empty"));
    }
    if req.visitor_phone.is_empty() || !req.visitor_phone.starts_with('+') {
        return Err(ApiError::validation("visitor_phone", "must be in E.164 format"));
    }

    let output = state.create_pass.execute(
        &ctx,
        visitorpass_application::use_cases::create_pass::CreatePassInput {
            location_id:    req.location_id,
            visitor_name:   req.visitor_name.trim().to_string(),
            visitor_phone:  req.visitor_phone.trim().to_string(),
            purpose:        req.purpose.trim().to_string(),
            vehicle_number: req.vehicle_number.map(|v| v.trim().to_string()),
            permissions:    req.permissions,
            valid_from:     req.valid_from,
            valid_until:    req.valid_until,
            max_uses:       req.max_uses,
        },
    ).await?;

    let pass = &output.pass;
    let response = PassResponse {
        id:             pass.id,
        org_id:         pass.org_id,
        location_id:    pass.location_id,
        created_by:     pass.created_by,
        pass_number:    pass.pass_number.to_string(),
        visitor_name:   pass.visitor_name.clone(),
        purpose:        pass.purpose.clone(),
        vehicle_number: pass.vehicle_number.clone(),
        permissions:    pass.permissions.iter().map(|p| p.as_str().to_string()).collect(),
        valid_from:     pass.valid_from,
        valid_until:    pass.valid_until,
        max_uses:       pass.max_uses,
        use_count:      pass.use_count,
        qr_payload:     pass.qr_payload.clone(),
        status:         format!("{:?}", pass.status),
        share_url:      output.share_url.clone(),
        created_at:     pass.created_at,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/v1/organizations/:org_id/passes
pub async fn list_passes(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    axum::extract::Query(params): axum::extract::Query<ListPassesParams>,
) -> Result<impl IntoResponse, ApiError> {
    use visitorpass_application::ports::repositories::{PassFilter, PageParams, CursorPosition};
    use base64::Engine;

    let limit = params.limit.unwrap_or(20);
    let mut page_params = PageParams::new(limit);

    if let Some(cursor_str) = params.cursor {
        // Decode cursor (id, created_at) from base64url.
        if let Ok(decoded_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&cursor_str) {
            if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                let mut parts = decoded_str.split('|');
                if let (Some(id_str), Some(time_str)) = (parts.next(), parts.next()) {
                    if let (Ok(id), Ok(time)) = (uuid::Uuid::parse_str(id_str), chrono::DateTime::parse_from_rfc3339(time_str)) {
                        page_params = page_params.with_cursor(Some(CursorPosition {
                            id,
                            created_at: time.with_timezone(&chrono::Utc),
                        }));
                    }
                }
            }
        }
    }

    let filter = PassFilter {
        status: params.status,
        location_id: None,
        created_by: None,
        from: None,
        to: None,
    };

    let page = state.passes.list(&ctx, filter, page_params).await?;

    let items: Vec<PassResponse> = page.items.into_iter().map(|pass| {
        PassResponse {
            id: pass.id,
            org_id: pass.org_id,
            location_id: pass.location_id,
            created_by: pass.created_by,
            pass_number: pass.pass_number.to_string(),
            visitor_name: pass.visitor_name.clone(),
            purpose: pass.purpose.clone(),
            vehicle_number: pass.vehicle_number.clone(),
            permissions: pass.permissions.iter().map(|p| format!("{:?}", p)).collect(),
            valid_from: pass.valid_from,
            valid_until: pass.valid_until,
            max_uses: pass.max_uses,
            use_count: pass.use_count,
            qr_payload: pass.qr_payload.clone(),
            status: format!("{:?}", pass.status),
            share_url: format!("{}/v/{}", state.config.base_url, pass.pass_number),
            created_at: pass.created_at,
        }
    }).collect();

    let next_cursor = page.next_cursor.map(|c| {
        let cursor_plain = format!("{}|{}", c.id, c.created_at.to_rfc3339());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cursor_plain.as_bytes())
    });

    Ok(Json(serde_json::json!({
        "items":       items,
        "next_cursor": next_cursor,
    })))
}

/// GET /api/v1/organizations/:org_id/passes/:pass_id
pub async fn get_pass(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    axum::extract::Path(params): axum::extract::Path<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, ApiError> {
    let pass_id = params
        .get("pass_id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::validation("pass_id", "must be a valid UUID"))?;

    let pass = state.passes.find_by_id(&ctx, pass_id).await?;

    Ok(Json(PassResponse {
        id:             pass.id,
        org_id:         pass.org_id,
        location_id:    pass.location_id,
        created_by:     pass.created_by,
        pass_number:    pass.pass_number.to_string(),
        visitor_name:   pass.visitor_name.clone(),
        purpose:        pass.purpose.clone(),
        vehicle_number: pass.vehicle_number.clone(),
        permissions:    pass.permissions.iter().map(|p| p.as_str().to_string()).collect(),
        valid_from:     pass.valid_from,
        valid_until:    pass.valid_until,
        max_uses:       pass.max_uses,
        use_count:      pass.use_count,
        qr_payload:     pass.qr_payload.clone(),
        status:         format!("{:?}", pass.status),
        share_url:      format!("{}/v/{}", state.config.base_url, pass.pass_number.as_str()),
        created_at:     pass.created_at,
    }))
}

/// POST /api/v1/organizations/:org_id/passes/:pass_id/revoke
pub async fn revoke_pass(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    axum::extract::Path(params): axum::extract::Path<std::collections::HashMap<String, String>>,
    Json(req): Json<RevokePassRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let pass_id = params
        .get("pass_id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::validation("pass_id", "must be a valid UUID"))?;

    let pass = state.revoke_pass.execute(&ctx, pass_id, req.reason).await?;

    Ok(Json(serde_json::json!({
        "id":     pass.id,
        "status": format!("{:?}", pass.status),
        "revoked_at": pass.revoked_at,
        "revocation_reason": pass.revocation_reason,
    })))
}

/// POST /api/v1/passes/verify
pub async fn verify_pass(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    Json(req): Json<VerifyPassRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let output = state.verify_pass.execute(
        &ctx,
        visitorpass_application::use_cases::verify_pass::VerifyPassInput {
            qr_payload:  req.qr_payload,
            location_id: req.location_id,
            action:      req.action,
        },
    ).await?;

    Ok(Json(VerifyPassResponse {
        valid:          output.valid,
        pass_id:        output.pass_id,
        pass_number:    output.pass_number,
        visitor_name:   output.visitor_name,
        purpose:        output.purpose,
        vehicle_number: output.vehicle_number,
        permissions:    output.permissions,
        valid_from:     output.valid_from,
        valid_until:    output.valid_until,
        status:         output.status,
        denial_reason:  output.denial_reason,
    }))
}
