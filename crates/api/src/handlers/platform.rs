use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use visitorpass_domain::{
    entities::{OrgStatus, OrgType, SubscriptionTier},
    value_objects::PlatformContext,
};

use crate::{errors::ApiError, state::AppState};

#[derive(Debug, Serialize)]
pub struct PlatformOrgSummary {
    pub id:                Uuid,
    pub name:              String,
    pub slug:              String,
    pub org_type:          OrgType,
    pub status:            OrgStatus,
    pub subscription_tier: String,
    pub max_locations:     i32,
    pub max_daily_passes:  i32,
    pub created_at:        chrono::DateTime<chrono::Utc>,
}
#[derive(Debug, Serialize)]
pub struct ListOrganizationsResponse {
    pub organizations: Vec<PlatformOrgSummary>,
}

/// GET /api/v1/platform/organizations
///
/// Cross-tenant: every organization on the platform. Reachable only with a
/// PLATFORM_ADMIN token (see `platform_admin_middleware`) -- an org-scoped
/// token of any role (Guard/Resident/OrgAdmin) gets 403 here, and
/// symmetrically a platform admin token gets 403 on any org-scoped route,
/// because the two token shapes are mutually exclusive (see
/// `build_org_context` / `build_platform_context` in the auth middleware).
pub async fn list_organizations(
    State(state): State<AppState>,
    Extension(ctx): Extension<PlatformContext>,
) -> Result<impl IntoResponse, ApiError> {
    let orgs = state.orgs.list_all(&ctx).await?;

    Ok(Json(ListOrganizationsResponse {
        organizations: orgs
            .into_iter()
            .map(|o| PlatformOrgSummary {
                id:                o.id,
                name:              o.name,
                slug:              o.slug,
                org_type:          o.org_type,
                status:            o.status,
                subscription_tier: o.subscription_tier.as_str().to_string(),
                max_locations:     o.max_locations,
                max_daily_passes:  o.max_daily_passes,
                created_at:        o.created_at,
            })
            .collect(),
    }))
}

// ── POST /api/v1/platform/organizations ─────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ProvisionOrgRequest {
    pub name:        String,
    pub org_type:    String,
    pub slug:        String,
    pub timezone:    String,
    pub admin_email: String,
    pub admin_name:  String,
}

#[derive(Debug, Serialize)]
pub struct ProvisionOrgResponse {
    pub org_id:            Uuid,
    pub org_name:          String,
    pub slug:              String,
    pub admin_user_id:     Uuid,
    pub subscription_tier: String,
}

/// POST /api/v1/platform/organizations
///
/// Onboards a new organization AND provisions its root OrgAdmin account in
/// one step. The new admin does NOT need to have logged in via Google
/// first -- their membership is ACTIVE immediately, so
/// `POST /api/v1/auth/google` logs them straight into this org on their
/// very first request. See `ProvisionOrganizationUseCase` for the full
/// JIT-user-creation contract.
pub async fn provision_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<PlatformContext>,
    Json(req): Json<ProvisionOrgRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let use_case = visitorpass_application::use_cases::ProvisionOrganizationUseCase::new(
        state.orgs.clone(),
        state.users.clone(),
        state.crypto.clone(),
        state.audit.clone(),
    );

    let output = use_case.execute(
        &ctx,
        visitorpass_application::use_cases::provision_organization_platform::ProvisionOrgInput {
            name:        req.name,
            org_type:    req.org_type,
            slug:        req.slug,
            timezone:    req.timezone,
            admin_email: req.admin_email,
            admin_name:  req.admin_name,
        },
    ).await?;

    Ok((
        StatusCode::CREATED,
        Json(ProvisionOrgResponse {
            org_id:            output.organization.id,
            org_name:          output.organization.name,
            slug:              output.organization.slug,
            admin_user_id:     output.admin_user_id,
            subscription_tier: output.organization.subscription_tier.as_str().to_string(),
        }),
    ))
}

// ── PUT /api/v1/platform/organizations/:org_id/tier ─────────────────────────

#[derive(Debug, Deserialize)]
pub struct SetSubscriptionTierRequest {
    pub tier:             String,
    pub max_locations:    i32,
    pub max_daily_passes: i32,
}

#[derive(Debug, Serialize)]
pub struct SubscriptionTierResponse {
    pub org_id:            Uuid,
    pub subscription_tier: String,
    pub max_locations:     i32,
    pub max_daily_passes:  i32,
}

/// PUT /api/v1/platform/organizations/:org_id/tier
///
/// "Global Billing & Subscriptions": sets an org's SaaS tier and its plan
/// limits (max active locations, max visitor passes per rolling 24h).
pub async fn set_org_subscription_tier(
    State(state): State<AppState>,
    Extension(ctx): Extension<PlatformContext>,
    Path(params): Path<HashMap<String, String>>,
    Json(req): Json<SetSubscriptionTierRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let org_id = params
        .get("org_id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::validation("org_id", "invalid organization UUID"))?;
    let tier = SubscriptionTier::try_from(req.tier.to_uppercase().as_str())?;
    if req.max_locations <= 0 {
        return Err(ApiError::validation("max_locations", "must be a positive integer"));
    }
    if req.max_daily_passes <= 0 {
        return Err(ApiError::validation("max_daily_passes", "must be a positive integer"));
    }

    state.orgs.set_subscription_tier(&ctx, org_id, tier, req.max_locations, req.max_daily_passes).await?;

    Ok(Json(SubscriptionTierResponse {
        org_id,
        subscription_tier: tier.as_str().to_string(),
        max_locations:     req.max_locations,
        max_daily_passes:  req.max_daily_passes,
    }))
}

// ── GET /api/v1/platform/metrics ─────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct OrgMetricBreakdownResponse {
    pub org_id:         Uuid,
    pub org_name:       String,
    pub check_in_count: i64,
}

#[derive(Debug, Serialize)]
pub struct PlatformMetricsResponse {
    /// Rolling window, in days, that every field below is computed over.
    pub window_days: i32,
    /// Count of `ENTRY`-action `app.entry_logs` rows across all orgs in the window.
    pub total_check_ins: i64,
    /// Average `server_received_at - occurred_at` gap across `app.entry_logs`
    /// in the window, in seconds -- how long a gate event (of any action:
    /// entry/exit/denied) takes to reach the server after it happens on a
    /// (possibly offline) guard device. `null` when there were no entry
    /// logs in the window to average.
    pub avg_gate_sync_latency_seconds: Option<f64>,
    pub per_org: Vec<OrgMetricBreakdownResponse>,
}

/// GET /api/v1/platform/metrics
///
/// Cross-tenant analytics: platform-wide health metrics for the trailing
/// 30 days -- total check-in volume, average gate sync latency, and a
/// per-org breakdown (every non-deleted org, including ones with zero
/// check-ins in the window). See `OrgRepository::platform_metrics` for the
/// exact query and the "sync latency" definition.
pub async fn platform_metrics(
    State(state): State<AppState>,
    Extension(ctx): Extension<PlatformContext>,
) -> Result<impl IntoResponse, ApiError> {
    let metrics = state.orgs.platform_metrics(&ctx).await?;

    Ok(Json(PlatformMetricsResponse {
        window_days:                30,
        total_check_ins:            metrics.total_check_ins,
        avg_gate_sync_latency_seconds: metrics.avg_sync_latency_seconds,
        per_org: metrics.per_org.into_iter().map(|o| OrgMetricBreakdownResponse {
            org_id:         o.org_id,
            org_name:       o.org_name,
            check_in_count: o.check_in_count,
        }).collect(),
    }))
}

// ── POST /api/v1/platform/devices/:device_id/revoke ─────────────────────────

#[derive(Debug, Deserialize)]
pub struct RevokeDevicePlatformRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PlatformDeviceRevokeResponse {
    pub id:                Uuid,
    pub org_id:            Uuid,
    pub status:            String,
    pub revoked_at:        Option<chrono::DateTime<chrono::Utc>>,
    pub revocation_reason: Option<String>,
}

/// POST /api/v1/platform/devices/:device_id/revoke
///
/// "Global Device Revocation": instantly revokes a device regardless of
/// which org it belongs to -- the caller never needs to know or supply
/// the owning `org_id`. See `DeviceRepository::revoke_platform`.
pub async fn revoke_device_platform(
    State(state): State<AppState>,
    Extension(ctx): Extension<PlatformContext>,
    Path(params): Path<HashMap<String, String>>,
    Json(req): Json<RevokeDevicePlatformRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let device_id = params
        .get("device_id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::validation("device_id", "invalid device UUID"))?;

    let device = state.devices.revoke_platform(&ctx, device_id, req.reason).await?;

    Ok(Json(PlatformDeviceRevokeResponse {
        id:                device.id,
        org_id:            device.org_id,
        status:            format!("{:?}", device.status).to_uppercase(),
        revoked_at:        device.revoked_at,
        revocation_reason: device.revocation_reason,
    }))
}
