use axum::{extract::State, http::{header, HeaderMap, HeaderValue}, response::IntoResponse, Json};
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
    /// Optional body fallback for clients that can't rely on the
    /// `refresh_token` HttpOnly cookie (see `extract_refresh_cookie`). The
    /// cookie takes priority when both are present.
    #[serde(default)]
    pub refresh_token: Option<String>,
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

    // Issue + persist a new refresh token session (new family: this is a
    // fresh login, not a rotation of an existing session).
    let refresh_token = create_session(&state, org.id, user.id, Uuid::new_v4()).await?;

    Ok((
        refresh_cookie_header(&refresh_token),
        Json(AuthResponse {
            access_token,
            refresh_token,
            role: role.as_str().to_string(),
            expires_in: 900,
        }),
    ))
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
    // AsymmetricSecretKey<V4> requires the full 64-byte seed||pubkey expansion;
    // see EnvKeyProvider::derive_paseto_key for why both halves matter.
    let secret_key = AsymmetricSecretKey::<V4>::from(&key_bytes[..])
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

// ── Refresh Token Session Helpers ────────────────────────────────────────────

/// Refresh sessions live for 30 days from issuance/rotation.
const REFRESH_TOKEN_TTL_DAYS: i32 = 30;
/// Window during which the immediately-previous (just-rotated-away) refresh
/// token is still accepted, to tolerate a client retry after a lost response.
/// Presenting it again OUTSIDE this window is treated as token theft.
const REFRESH_GRACE_WINDOW_MINUTES: i64 = 5;

/// Generates a fresh opaque refresh token (32 random bytes, CSPRNG,
/// URL-safe base64) and its SHA-256 hash for storage. Mirrors the same
/// generate-random / hash-for-storage pattern used for org join tokens.
fn generate_refresh_token() -> (String, String) {
    use base64::Engine;
    use rand::RngCore;
    use sha2::Digest;

    let mut random_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random_bytes);
    let raw_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes);

    let mut hasher = sha2::Sha256::new();
    hasher.update(raw_token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());

    (raw_token, token_hash)
}

fn hash_refresh_token(token: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ── Refresh Cookie Helpers ───────────────────────────────────────────────────
//
// The refresh token travels to the browser as an HttpOnly cookie rather than
// a JSON body field for `/auth/google` and `/auth/select-org` (the two
// handlers a browser actually calls) -- this keeps it unreachable from
// `document.cookie` / XSS, unlike the access token, which stays in the JSON
// body and lives only in the frontend's in-memory state.
//
// `/auth/login` (password-based, not used by the web app) still returns
// `refresh_token` in its body for any existing non-browser caller, but now
// ALSO sets the cookie, so a browser-based caller gets the same protection
// for free.
//
// `/auth/refresh` and `/auth/logout` accept the token from EITHER transport
// (cookie preferred, JSON body as a migration-window fallback), and always
// re-set/clear the cookie on their way out.

/// Name of the cookie carrying the opaque refresh token, and the path it is
/// scoped to -- deliberately narrower than `/`, so the browser only attaches
/// it to the auth endpoints that actually consume it, never to ordinary API
/// calls.
const REFRESH_COOKIE_NAME: &str = "refresh_token";
const REFRESH_COOKIE_PATH: &str = "/api/v1/auth";

/// Builds the `Set-Cookie` header value for a freshly issued/rotated refresh
/// token. `HttpOnly` keeps it out of reach of JS (`document.cookie` / XSS);
/// `Secure` blocks it from ever being sent over plain HTTP; `SameSite=Strict`
/// blocks it from being attached to cross-site requests, including
/// top-level navigations from another origin.
fn build_refresh_cookie(raw_token: &str) -> String {
    format!(
        "{name}={value}; HttpOnly; Secure; SameSite=Strict; Path={path}; Max-Age={max_age}",
        name = REFRESH_COOKIE_NAME,
        value = raw_token,
        path = REFRESH_COOKIE_PATH,
        max_age = REFRESH_TOKEN_TTL_DAYS as i64 * 86_400,
    )
}

/// Wraps `build_refresh_cookie` into a single-header `HeaderMap` ready to be
/// merged into a handler's response tuple, e.g.
/// `Ok((refresh_cookie_header(&t), Json(body)))`.
pub(crate) fn refresh_cookie_header(raw_token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    // `raw_token` is always `generate_refresh_token`'s URL-safe-base64
    // output (`[A-Za-z0-9_-]` only), which is always a valid header value --
    // this can only fail if that alphabet ever changes, so fail loudly
    // rather than silently omitting the cookie and leaving the client
    // holding an access token it can never refresh.
    let value = HeaderValue::try_from(build_refresh_cookie(raw_token))
        .expect("refresh cookie value must be a valid HTTP header value");
    headers.insert(header::SET_COOKIE, value);
    headers
}

/// `Set-Cookie` header that immediately expires the refresh cookie, so a
/// browser drops it right away instead of holding onto a now-revoked token
/// until its 30-day `Max-Age` would otherwise elapse.
fn clear_refresh_cookie_header() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "refresh_token=; HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth; Max-Age=0",
        ),
    );
    headers
}

/// Extracts the refresh token from a request's `Cookie` header, if present.
/// `Cookie` headers pack multiple `name=value` pairs separated by `; `
/// (RFC 6265 §4.2.1) -- unlike `Set-Cookie`, there are no attributes to
/// strip here, just the pairs themselves.
fn extract_refresh_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie_header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == REFRESH_COOKIE_NAME).then(|| value.to_string())
    })
}

/// Persists a brand-new session row (new family) and returns the raw
/// refresh token to hand to the client. Called on every fresh
/// authentication that already knows the target org -- `/auth/login`,
/// `/auth/google` (single-membership auto-login), and `/auth/select-org`
/// (once the caller has picked one). Rotation during `/auth/refresh` updates
/// an existing row in place instead of calling this.
pub(crate) async fn create_session(
    state: &AppState,
    org_id: Uuid,
    user_id: Uuid,
    family_id: Uuid,
) -> Result<String, ApiError> {
    let (raw_token, token_hash) = generate_refresh_token();

    sqlx::query(
        r#"
        INSERT INTO app.sessions (id, user_id, org_id, token_hash, family_id, expires_at, created_at, last_used_at)
        VALUES ($1, $2, $3, $4, $5, NOW() + make_interval(days => $6), NOW(), NOW())
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(org_id)
    .bind(&token_hash)
    .bind(family_id)
    .bind(REFRESH_TOKEN_TTL_DAYS)
    .execute(&state.db_pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to persist refresh session");
        ApiError::internal()
    })?;

    Ok(raw_token)
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
/// Exchanges a global token or active org token for a token scoped to a
/// specific organization, and issues a brand-new refresh session scoped to
/// that org (delivered as an HttpOnly cookie -- see `refresh_cookie_header`).
/// This is the ONLY place a refresh session gets created for a caller who
/// didn't already have exactly one membership at `/auth/google` time (see
/// that handler's doc comment).
pub async fn select_org(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<visitorpass_domain::value_objects::OrgContext>,
    Json(req): Json<SelectOrgRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let role = state.users.find_membership_role(ctx.user_id, req.org_id).await?;

    let token = generate_access_token(&state, req.org_id, ctx.user_id, role, None, None)?;
    let refresh_token = create_session(&state, req.org_id, ctx.user_id, Uuid::new_v4()).await?;

    Ok((
        refresh_cookie_header(&refresh_token),
        Json(SelectOrgResponse {
            access_token: token,
            role: role.as_str().to_string(),
            expires_in: 900,
        }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    /// Optional body fallback -- see `RefreshRequest::refresh_token`.
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub status: &'static str,
}

/// POST /api/v1/auth/refresh
/// Rotates a refresh token: the presented token is invalidated and a new
/// (access_token, refresh_token) pair is issued.
///
/// Theft detection: `previous_token_hash` + `previous_token_rotated_at` let a
/// client retry with the token it JUST rotated away from (e.g. the rotation
/// response was lost in transit) for a 5-minute grace window -- that retry
/// is treated as legitimate and rotates again. Presenting that same
/// pre-rotation token AFTER the grace window has passed means two different
/// parties are using the same refresh token concurrently (the legitimate
/// client already rotated past it) -- i.e. token theft -- so the entire
/// session family is revoked, including the CURRENT token, forcing the
/// legitimate holder to re-authenticate.
pub async fn refresh_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RefreshRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let presented_token = extract_refresh_cookie(&headers)
        .or(req.refresh_token)
        .ok_or_else(|| ApiError::unauthorized("INVALID_REFRESH_TOKEN", "Refresh token is invalid or unknown"))?;
    let presented_hash = hash_refresh_token(&presented_token);
    let (new_raw, new_hash) = generate_refresh_token();

    // 1. Try to rotate as the CURRENT token of some session.
    let rotated: Option<(Uuid, Uuid, Uuid)> = sqlx::query_as(
        r#"
        UPDATE app.sessions
        SET token_hash = $2, previous_token_hash = $1, previous_token_rotated_at = NOW(),
            last_used_at = NOW(), expires_at = NOW() + make_interval(days => $3)
        WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
        RETURNING user_id, org_id, family_id
        "#,
    )
    .bind(&presented_hash)
    .bind(&new_hash)
    .bind(REFRESH_TOKEN_TTL_DAYS)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|_| ApiError::internal())?;

    let (user_id, org_id, _family_id) = if let Some(row) = rotated {
        row
    } else {
        // 2. Not a current token -- check whether it's the PREVIOUS token of
        //    some session (grace window vs theft).
        let candidate: Option<(Uuid, Uuid, Uuid, Uuid, Option<chrono::DateTime<Utc>>, Option<chrono::DateTime<Utc>>)> =
            sqlx::query_as(
                r#"
                SELECT id, user_id, org_id, family_id, revoked_at, previous_token_rotated_at
                FROM app.sessions
                WHERE previous_token_hash = $1
                "#,
            )
            .bind(&presented_hash)
            .fetch_optional(&state.db_pool)
            .await
            .map_err(|_| ApiError::internal())?;

        let Some((session_id, user_id, org_id, family_id, revoked_at, prev_rotated_at)) = candidate else {
            return Err(ApiError::unauthorized("INVALID_REFRESH_TOKEN", "Refresh token is invalid or unknown"));
        };

        let within_grace = prev_rotated_at
            .map(|t| Utc::now() - t < Duration::minutes(REFRESH_GRACE_WINDOW_MINUTES))
            .unwrap_or(false);

        if revoked_at.is_some() || !within_grace {
            // Theft: someone is presenting a refresh token that the
            // legitimate client already rotated away from, outside the
            // retry grace window. Revoke the whole family so the attacker
            // AND the legitimate holder are both forced to re-authenticate.
            sqlx::query("UPDATE app.sessions SET revoked_at = NOW() WHERE family_id = $1 AND revoked_at IS NULL")
                .bind(family_id)
                .execute(&state.db_pool)
                .await
                .map_err(|_| ApiError::internal())?;

            tracing::warn!(family_id = %family_id, "refresh token reuse detected outside grace window; session family revoked");
            return Err(ApiError::unauthorized("REFRESH_TOKEN_REUSE_DETECTED", "This refresh token has already been rotated; the session has been revoked"));
        }

        // Within grace window: legitimate retry (the client's original
        // rotation response was presumably lost in transit). Issue a fresh
        // token_hash so the retry gets something usable, but deliberately
        // leave previous_token_hash/previous_token_rotated_at UNCHANGED --
        // they still describe the ORIGINAL pre-retry rotation this request
        // is retrying. If we advanced them on every grace-window hit, a
        // determined attacker replaying the stale token repeatedly could
        // indefinitely extend their own detection window and never trip
        // theft detection.
        let rotated_again: Option<(Uuid, Uuid, Uuid)> = sqlx::query_as(
            r#"
            UPDATE app.sessions
            SET token_hash = $2, last_used_at = NOW(), expires_at = NOW() + make_interval(days => $3)
            WHERE id = $1 AND revoked_at IS NULL
            RETURNING user_id, org_id, family_id
            "#,
        )
        .bind(session_id)
        .bind(&new_hash)
        .bind(REFRESH_TOKEN_TTL_DAYS)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|_| ApiError::internal())?;

        rotated_again.ok_or_else(|| ApiError::unauthorized("INVALID_REFRESH_TOKEN", "Refresh token is invalid or unknown"))?
    };

    let role = state.users.find_membership_role(user_id, org_id).await?;
    let access_token = generate_access_token(&state, org_id, user_id, role, None, None)?;

    Ok((
        refresh_cookie_header(&new_raw),
        Json(AuthResponse {
            access_token,
            refresh_token: new_raw,
            role: role.as_str().to_string(),
            expires_in: 900,
        }),
    ))
}

/// POST /api/v1/auth/logout
/// Revokes the session identified by the presented refresh token. Idempotent:
/// logging out an already-revoked or unknown token still returns success.
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LogoutRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Idempotent even when no token is presented at all (nothing to
    // revoke) -- logging out twice, or logging out with an already-expired
    // cookie and no body fallback, still returns success.
    if let Some(token) = extract_refresh_cookie(&headers).or(req.refresh_token) {
        let token_hash = hash_refresh_token(&token);
        sqlx::query("UPDATE app.sessions SET revoked_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL")
            .bind(&token_hash)
            .execute(&state.db_pool)
            .await
            .map_err(|_| ApiError::internal())?;
    }

    Ok((clear_refresh_cookie_header(), Json(LogoutResponse { status: "LOGGED_OUT" })))
}
