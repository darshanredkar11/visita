use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use pasetors::{
    claims::Claims as PasetoClaims,
    keys::AsymmetricSecretKey,
    version4::V4,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use visitorpass_domain::{value_objects::Role, DomainError};
use visitorpass_application::ports::repositories::CreateUserInput;

use crate::{errors::ApiError, state::AppState};

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GoogleLoginRequest {
    pub id_token: String,
}

#[derive(Debug, Serialize)]
pub struct MembershipSummary {
    pub org_id:          Uuid,
    pub org_name:        String,
    pub role:            String,
    pub unit_identifier: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GoogleLoginResponse {
    // Present only if user has exactly 1 membership
    pub access_token:   Option<String>,
    pub role:           Option<String>,
    pub expires_in:     Option<i64>,

    // Always returned for frontend routing
    pub user:           UserSummary,
    pub memberships:    Vec<MembershipSummary>,
}

#[derive(Debug, Serialize)]
pub struct UserSummary {
    pub id:        Uuid,
    pub email:     String,
    pub full_name: String,
}

#[derive(Debug, Deserialize)]
struct GoogleClaims {
    iss:   String,
    aud:   String,
    email: String,
    name:  Option<String>,
}

// ── Handler ───────────────────────────────────────────────────────────────────

/// POST /api/v1/auth/google
/// Authenticates the user using a Google Identity Services ID token.
/// Automatically creates a user profile if this is their first login.
pub async fn google_auth(
    State(state): State<AppState>,
    Json(req): Json<GoogleLoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // 1. Verify Google token and extract email/name
    let email_and_name = verify_google_token(&state, &req.id_token).await?;

    let email = email_and_name.0.to_lowercase();
    let full_name = email_and_name.1.unwrap_or_else(|| email.split('@').next().unwrap_or("User").to_string());

    // 2. Lookup or create User
    let user = match state.users.find_by_email(&email).await {
        Ok(u) => u,
        Err(_) => {
            // New user registration
            let dummy_pass = Uuid::new_v4().to_string(); // random password for OAuth accounts
            let password_hash = state.crypto.hash_password(&dummy_pass).await?;
            state.users.create(CreateUserInput {
                email:         email.clone(),
                password_hash,
                phone_hmac:     None,
                full_name:     full_name.clone(),
            }).await?
        }
    };

    user.check_not_locked(chrono::Utc::now())?;
    state.users.record_login_success(user.id).await?;

    // 3. Load all memberships for this user
    let memberships = load_user_memberships(&state, user.id).await?;

    // 4. Determine response: automatic login vs organization selector
    let mut access_token = None;
    let mut active_role = None;
    let mut expires_in = None;

    if memberships.len() == 1 {
        let primary = &memberships[0];
        let role = Role::try_from(primary.role.as_str()).unwrap_or(Role::Resident);
        
        let token = generate_paseto_token(&state, primary.org_id, user.id, role, None, None)?;
        access_token = Some(token);
        active_role = Some(primary.role.clone());
        expires_in = Some(900);
    } else {
        // Fallback global token with nil UUID
        let token = generate_paseto_token(&state, Uuid::nil(), user.id, Role::Resident, None, None)?;
        access_token = Some(token);
        expires_in = Some(900);
    }

    Ok(Json(GoogleLoginResponse {
        access_token,
        role: active_role,
        expires_in,
        user: UserSummary {
            id:        user.id,
            email:     user.email,
            full_name: user.full_name,
        },
        memberships,
    }))
}

// ── Google token verification ────────────────────────────────────────────────

async fn verify_google_token(
    state: &AppState,
    id_token: &str,
) -> Result<(String, Option<String>), ApiError> {
    // ── Local Development / Offline Mock ──────────────────────────────────
    if state.config.env == "development" || state.config.env == "test" {
        // If token starts with mock_, bypass Google servers (enables offline dev)
        if id_token.starts_with("mock_") {
            let email = id_token.strip_prefix("mock_").unwrap_or("dev@visitorpass.app").to_string();
            let name = Some("Developer User".to_string());
            return Ok((email, name));
        }
    }

    // ── Production Verification ───────────────────────────────────────────
    // Fetch google keys and verify JWT signature
    let header = jsonwebtoken::decode_header(id_token)
        .map_err(|_| ApiError::unauthorized("TOKEN_INVALID", "Invalid JWT header format"))?;

    let kid = header.kid.ok_or_else(|| {
        ApiError::unauthorized("TOKEN_INVALID", "Google ID token must contain kid header")
    })?;

    // Fetch JWKS certificates from Google
    let jwks = fetch_google_jwks().await?;
    let key = jwks
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| ApiError::unauthorized("TOKEN_INVALID", "Google signing key not found in JWKS"))?;

    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(&key.n, &key.e)
        .map_err(|_| ApiError::internal())?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);
    // Audience validation: check that token is issued for our app (prevents account takeover)
    validation.set_audience(&[state.config.google_client_id.as_str()]);
    validation.validate_aud = true;

    let claims = jsonwebtoken::decode::<GoogleClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| {
            tracing::error!(error = %e, "Google signature validation failed");
            ApiError::unauthorized("TOKEN_INVALID", "Google signature verification failed")
        })?;

    Ok((claims.claims.email, claims.claims.name))
}

// JWKS fetching structures
#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwksKey>,
}

#[derive(Debug, Deserialize)]
struct JwksKey {
    kid: String,
    n:   String,
    e:   String,
}

async fn fetch_google_jwks() -> Result<JwksResponse, ApiError> {
    // Fetch certificates from Google endpoints. In a high-traffic production system,
    // this JWKS response should be cached in memory with a 6-12 hour TTL.
    // Here we make a simple request using reqwest.
    let resp = reqwest::get("https://www.googleapis.com/oauth2/v3/certs")
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to connect to Google certificate servers");
            ApiError::internal()
        })?;

    let jwks = resp.json::<JwksResponse>().await.map_err(|e| {
        tracing::error!(error = %e, "Failed to parse Google JWKS response");
        ApiError::internal()
    })?;

    Ok(jwks)
}

// ── Memberships loading helper ───────────────────────────────────────────────

async fn load_user_memberships(
    state: &AppState,
    user_id: Uuid,
) -> Result<Vec<MembershipSummary>, ApiError> {
    let list = state.users.list_memberships(user_id).await?;
    let summaries = list.into_iter().map(|(org_id, org_name, role, unit_id)| MembershipSummary {
        org_id,
        org_name,
        role: role.as_str().to_string(),
        unit_identifier: unit_id,
    }).collect();

    Ok(summaries)
}

// ── PASETO Token Builder ─────────────────────────────────────────────────────

fn generate_paseto_token(
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

    let now = chrono::Utc::now();
    let expiry = now + chrono::Duration::minutes(15);

    let mut claims = PasetoClaims::new().map_err(|_| DomainError::CryptoError)?;
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

/// GET /api/v1/users/memberships
/// Returns all active memberships of the authenticated user.
pub async fn list_user_memberships(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<visitorpass_domain::value_objects::OrgContext>,
) -> Result<impl IntoResponse, ApiError> {
    let list = state.users.list_memberships(ctx.user_id).await?;
    let summaries: Vec<MembershipSummary> = list.into_iter().map(|(id, name, role, unit_id)| {
        MembershipSummary {
            org_id: id,
            org_name: name,
            role: role.as_str().to_string(),
            unit_identifier: unit_id,
        }
    }).collect();

    Ok(Json(serde_json::json!({
        "memberships": summaries
    })))
}
