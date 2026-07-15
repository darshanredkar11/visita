use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::{Duration, Utc};
use pasetors::{
    claims::Claims,
    keys::{AsymmetricSecretKey, AsymmetricPublicKey},
    version4::V4,
    Local, Public,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use visitorpass_domain::{value_objects::Role, DomainError};

use crate::{errors::ApiError, state::AppState};

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email:    String,
    pub password: String,
    pub slug:     String,  // Org slug to identify which organization they are logging into
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token:  String,
    pub refresh_token: String,
    pub role:          String,
    pub expires_in:    i64, // seconds
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub expires_in: i64,
}

#[derive(Debug, Deserialize)]
pub struct DeviceLoginRequest {
    pub challenge:  String,
    pub public_key: String, // hex encoded
    pub signature:  String, // hex encoded
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /api/v1/auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // 1. Fetch organization by slug
    let org = state.orgs.find_by_slug(&req.slug).await?;
    org.assert_active()?;

    // 2. Fetch user by email
    let user = state.users.find_by_email(&req.email).await?;
    user.check_not_locked(Utc::now())?;

    // 3. Verify password
    let valid = state.crypto.verify_password(&req.password, &user.password_hash).await?;
    if !valid {
        state.users.record_login_failure(user.id).await?;
        return Err(ApiError::unauthorized("INVALID_CREDENTIALS", "Invalid email, password, or organization slug"));
    }

    state.users.record_login_success(user.id).await?;

    // 4. Retrieve membership role for this organization
    let role = state.users.find_membership_role(user.id, org.id).await?;

    // Let's generate access token (PASETO v4.public)
    let access_token = generate_access_token(&state, org.id, user.id, role, None, None)?;

    // Refresh token rotation
    let refresh_token = Uuid::new_v4().to_string();

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
        role: role.as_str().to_string(),
        expires_in: 900,
    }))
}

/// GET /api/v1/auth/device-challenge
pub async fn device_challenge(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let nonce = Uuid::new_v4().to_string();
    
    // Insert challenge with 60s expiration into app.device_challenges
    sqlx::query(
        r#"
        INSERT INTO app.device_challenges (nonce, expires_at, created_at)
        VALUES ($1, NOW() + INTERVAL '60 seconds', NOW())
        "#
    )
    .bind(&nonce)
    .execute(&state.db_pool)
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(ChallengeResponse {
        challenge: nonce,
        expires_in: 60,
    }))
}

/// POST /api/v1/auth/device-login
pub async fn device_login(
    State(state): State<AppState>,
    Json(req): Json<DeviceLoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // 1. Decode hex public key and signature
    let pub_key_bytes = hex::decode(&req.public_key)
        .map_err(|_| ApiError::validation("public_key", "must be valid hex"))?;
    let signature_bytes = hex::decode(&req.signature)
        .map_err(|_| ApiError::validation("signature", "must be valid hex"))?;

    // 1.5 Verify challenge exists and hasn't been used (replay protection)
    let rows_affected = sqlx::query(
        r#"
        UPDATE app.device_challenges
        SET used_at = NOW()
        WHERE nonce = $1 AND used_at IS NULL AND expires_at > NOW()
        "#
    )
    .bind(&req.challenge)
    .execute(&state.db_pool)
    .await
    .map_err(|_| ApiError::internal())?
    .rows_affected();
    
    if rows_affected == 0 {
        return Err(ApiError::unauthorized("INVALID_CHALLENGE", "Challenge not found, expired, or already used"));
    }

    // 2. Lookup device by public key
    let device = state.devices.find_by_public_key(&pub_key_bytes).await?;
    device.assert_active()?;
    // 3. Verify signature over challenge
    state.crypto.verify_device_signature(
        &pub_key_bytes,
        req.challenge.as_bytes(),
        &signature_bytes,
    )?;

    // 4. Generate device access token (PASETO v4.public)
    // Includes device_id and location_id claims
    let access_token = generate_access_token(
        &state,
        device.org_id,
        device.owner_user_id.unwrap_or(Uuid::nil()), // dummy sub for kiosks
        Role::Guard,
        Some(device.id),
        device.location_id,
    )?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: String::new(), // devices do not use refresh tokens; they redo challenge-response
        role: "GUARD".to_string(),
        expires_in: 43200, // 12 hours
    }))
}

// ── Token Generation Helper ──────────────────────────────────────────────────

fn generate_access_token(
    state: &AppState,
    org_id: Uuid,
    user_id: Uuid,
    role: Role,
    device_id: Option<Uuid>,
    location_id: Option<Uuid>,
) -> Result<String, DomainError> {
    let key_bytes = state.key_provider.derive_paseto_key()?;
    let secret_key = AsymmetricSecretKey::<V4>::from(&key_bytes[..32])
        .map_err(|_| DomainError::CryptoError)?;

    let now = Utc::now();
    let duration = if device_id.is_some() {
        Duration::hours(12) // Long-lived guard device sessions
    } else {
        Duration::minutes(15) // Standard 15m user session
    };
    let expiry = now + duration;

    let mut claims = Claims::new().map_err(|_| DomainError::CryptoError)?;
    claims.subject(&user_id.to_string()).map_err(|_| DomainError::CryptoError)?;
    claims.expiration(&expiry.to_rfc3339()).map_err(|_| DomainError::CryptoError)?;
    claims.add_additional("org", org_id.to_string()).map_err(|_| DomainError::CryptoError)?;
    claims.add_additional("role", role.as_str()).map_err(|_| DomainError::CryptoError)?;

    if let Some(dev_id) = device_id {
        claims.add_additional("dev", dev_id.to_string()).map_err(|_| DomainError::CryptoError)?;
    }
    if let Some(loc_id) = location_id {
        claims.add_additional("loc", loc_id.to_string()).map_err(|_| DomainError::CryptoError)?;
    }

    let token = pasetors::public::sign(&secret_key, &claims, None, None)
        .map_err(|_| DomainError::CryptoError)?;

    Ok(token)
}

#[derive(Debug, Deserialize)]
pub struct SelectOrgRequest {
    pub org_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct SelectOrgResponse {
    pub access_token: String,
    pub role:         String,
    pub expires_in:   i64,
}

/// POST /api/v1/auth/select-org
/// Exchanged global token or active org token for a token scoped to a specific organization.
pub async fn select_org(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<visitorpass_domain::value_objects::OrgContext>,
    Json(req): Json<SelectOrgRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let role = state.users.find_membership_role(ctx.user_id, req.org_id).await?;

    let token = generate_access_token(&state, req.org_id, ctx.user_id, role, None, None)?;

    Ok(Json(SelectOrgResponse {
        access_token: token,
        role: role.as_str().to_string(),
        expires_in: 900,
    }))
}
