use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use visitorpass_application::ports::{ShareChannel, SharePassInput};
use visitorpass_domain::{entities::DenialReason, value_objects::OrgContext};

use crate::{errors::ApiError, state::AppState};

// ── Request / Response DTOs ───────────────────────────────────────────────────

#[derive(Debug, Deserialize, validator::Validate)]
pub struct CreatePassRequest {
    pub location_id:    Uuid,
    #[validate(length(max = 200), custom(function = "crate::validation::validate_non_empty_trimmed"))]
    pub visitor_name:   String,
    #[validate(custom(function = "crate::validation::validate_e164_phone"))]
    pub visitor_phone:  String,
    #[validate(length(max = 500), custom(function = "crate::validation::validate_non_empty_trimmed"))]
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
    pub denial_reason:  Option<DenialReason>,
}

#[derive(Debug, Deserialize)]
pub struct SharePassRequest {
    /// "whatsapp" | "sms"
    pub channel: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /api/v1/organizations/:org_id/passes
pub async fn create_pass(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    Json(req): Json<CreatePassRequest>,
) -> Result<impl IntoResponse, ApiError> {
    use validator::Validate;
    req.validate().map_err(crate::validation::validation_errors_to_api_error)?;

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

/// GET /api/v1/organizations/:org_id/passes/:pass_id/pdf
///
/// Renders a branded, downloadable pass card as `application/pdf`. Not a
/// `ShareChannel` -- a document to fetch/attach, not something dispatched
/// to a recipient.
pub async fn pass_pdf(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    axum::extract::Path(params): axum::extract::Path<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, ApiError> {
    let pass_id = params
        .get("pass_id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::validation("pass_id", "must be a valid UUID"))?;

    let pass = state.passes.find_by_id(&ctx, pass_id).await?;
    let org = state.orgs.find_by_id(&ctx, ctx.org_id).await?;

    let pdf_bytes = visitorpass_infrastructure::share::generate_pass_pdf(
        &org.name,
        &pass.visitor_name,
        pass.pass_number.as_str(),
        &pass.qr_payload,
        pass.valid_from,
        pass.valid_until,
    )?;

    // Pass numbers are base36 [0-9A-Z] (see `PassNumber`), always a safe,
    // unescaped `filename=` value -- the fallback is defensive, not
    // expected to trigger.
    let disposition = format!("attachment; filename=\"visitorpass-{}.pdf\"", pass.pass_number.as_str());
    let disposition_header =
        HeaderValue::from_str(&disposition).unwrap_or_else(|_| HeaderValue::from_static("attachment"));

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("application/pdf")),
            (header::CONTENT_DISPOSITION, disposition_header),
        ],
        pdf_bytes,
    ))
}

/// POST /api/v1/organizations/:org_id/passes/:pass_id/share
///
/// Distributes the pass's public share link to its visitor over the
/// requested channel (`{"channel": "whatsapp" | "sms"}`). The visitor's
/// phone is never stored in plaintext -- it is decrypted here from
/// `visitor_phone_enc` (the same ciphertext/record-id pair `CreatePassUseCase`
/// wrote) for exactly this call, never persisted or logged.
pub async fn share_pass(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    axum::extract::Path(params): axum::extract::Path<std::collections::HashMap<String, String>>,
    Json(req): Json<SharePassRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let pass_id = params
        .get("pass_id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::validation("pass_id", "must be a valid UUID"))?;

    let channel: &std::sync::Arc<dyn ShareChannel> = match req.channel.as_str() {
        "whatsapp" => &state.whatsapp_channel,
        "sms" => &state.sms_channel,
        other => {
            return Err(ApiError::validation(
                "channel",
                &format!("unsupported channel '{other}'; expected 'whatsapp' or 'sms'"),
            ))
        }
    };

    let pass = state.passes.find_by_id(&ctx, pass_id).await?;
    let org = state.orgs.find_by_id(&ctx, ctx.org_id).await?;

    let phone_enc = pass
        .visitor_phone_enc
        .as_ref()
        .ok_or_else(|| ApiError::validation("pass_id", "this pass has no recipient phone on file to share with"))?;
    let recipient_phone = state.crypto.decrypt_phone(pass.id, phone_enc)?;
    let share_url = format!("{}/v/{}", state.config.base_url, pass.pass_number.as_str());

    let result = channel
        .share(SharePassInput {
            recipient_phone,
            visitor_name: pass.visitor_name.clone(),
            share_url,
            org_name: org.name.clone(),
            valid_until: pass.valid_until,
        })
        .await?;

    Ok(Json(result))
}
