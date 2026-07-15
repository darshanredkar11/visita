use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use visitorpass_domain::value_objects::OrgContext;

use crate::{errors::ApiError, state::AppState};

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterOrgRequest {
    pub name:           String,
    pub org_type:       String,
    pub slug:           String,
    pub timezone:       String,
    pub owner_email:    String,
    pub owner_password: String,
    pub owner_name:     String,
}

#[derive(Debug, Serialize)]
pub struct RegisterOrgResponse {
    pub org_id:   Uuid,
    pub org_name: String,
    pub slug:     String,
    pub owner_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct OrgResponse {
    pub id:                  Uuid,
    pub name:                String,
    pub org_type:            String,
    pub slug:                String,
    pub status:              String,
    pub retention_days:      i32,
    pub current_key_version: i32,
    pub timezone:            String,
    pub created_at:          chrono::DateTime<chrono::Utc>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /api/v1/organizations
/// Anonymous endpoint to register a new organization and bootstrap the owner account.
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterOrgRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if req.name.trim().is_empty() {
        return Err(ApiError::validation("name", "organization name is required"));
    }
    if req.slug.trim().is_empty() {
        return Err(ApiError::validation("slug", "slug is required"));
    }
    if req.owner_email.trim().is_empty() {
        return Err(ApiError::validation("owner_email", "owner email is required"));
    }
    if req.owner_password.len() < 8 {
        return Err(ApiError::validation("owner_password", "password must be at least 8 characters"));
    }

    let output = state.register_org.execute(
        visitorpass_application::use_cases::register_organization::RegisterOrgInput {
            name:            req.name,
            org_type:        req.org_type,
            slug:            req.slug,
            timezone:        req.timezone,
            owner_email:     req.owner_email,
            owner_password:  req.owner_password,
            owner_name:      req.owner_name,
        },
    ).await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterOrgResponse {
            org_id:   output.organization.id,
            org_name: output.organization.name,
            slug:     output.organization.slug,
            owner_id: output.owner_id,
        }),
    ))
}

/// GET /api/v1/organizations/:org_id
pub async fn get_org(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
) -> Result<impl IntoResponse, ApiError> {
    let org = state.orgs.find_by_id(&ctx, ctx.org_id).await?;

    Ok(Json(OrgResponse {
        id:                  org.id,
        name:                org.name,
        org_type:            org.org_type.as_str().to_string(),
        slug:                org.slug,
        status:              format!("{:?}", org.status).to_uppercase(),
        retention_days:      org.retention_days,
        current_key_version: org.current_key_version,
        timezone:            org.timezone,
        created_at:          org.created_at,
    }))
}

#[derive(Debug, Deserialize)]
pub struct JoinByTokenRequest {
    pub token:           String,
    pub unit_identifier: String,
}

#[derive(Debug, Serialize)]
pub struct JoinTokenResponse {
    pub token: String,
    pub url:   String,
}

/// POST /api/v1/organizations/:org_id/join-token
/// Generates/rotates a new group onboarding invite token. (Secretary only)
pub async fn generate_join_token(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
) -> Result<impl IntoResponse, ApiError> {
    if ctx.role != visitorpass_domain::value_objects::Role::Owner && ctx.role != visitorpass_domain::value_objects::Role::Admin {
        return Err(ApiError::forbidden("Only building administrators can manage join tokens"));
    }

    let token = state.orgs.generate_join_token(ctx.org_id, ctx.user_id).await?;
    let url = format!("{}/join?token={}", state.config.base_url, token);

    Ok(Json(JoinTokenResponse { token, url }))
}

/// GET /api/v1/organizations/:org_id/join-token
/// Retrieves the current active group onboarding invite token, or generates one if none exists. (Secretary only)
pub async fn get_join_token(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
) -> Result<impl IntoResponse, ApiError> {
    if ctx.role != visitorpass_domain::value_objects::Role::Owner && ctx.role != visitorpass_domain::value_objects::Role::Admin {
        return Err(ApiError::forbidden("Only building administrators can manage join tokens"));
    }

    let active_token = state.orgs.get_active_join_token(ctx.org_id).await?;
    let token = match active_token {
        Some(t) => t,
        None => state.orgs.generate_join_token(ctx.org_id, ctx.user_id).await?,
    };

    let url = format!("{}/join?token={}", state.config.base_url, token);
    Ok(Json(JoinTokenResponse { token, url }))
}

/// POST /api/v1/organizations/join-by-token
/// Onboards a user into an organization using a shared invite token.
pub async fn join_by_token(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    Json(req): Json<JoinByTokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if req.unit_identifier.trim().is_empty() {
        return Err(ApiError::validation("unit_identifier", "unit identifier/flat number is required"));
    }

    let org_id = state.orgs.verify_join_token(&req.token).await?;

    state.orgs.add_membership_direct(
        org_id,
        ctx.user_id,
        visitorpass_domain::value_objects::Role::Resident,
        req.unit_identifier.trim().to_string(),
    ).await?;

    let list = state.users.list_memberships(ctx.user_id).await?;
    let summaries: Vec<crate::handlers::google_auth::MembershipSummary> = list.into_iter().map(|(id, name, role, unit_id)| {
        crate::handlers::google_auth::MembershipSummary {
            org_id: id,
            org_name: name,
            role: role.as_str().to_string(),
            unit_identifier: unit_id,
        }
    }).collect();

    Ok(Json(serde_json::json!({
        "status": "SUCCESS",
        "memberships": summaries
    })))
}
