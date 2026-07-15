use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension,
};
use pasetors::{
    claims::{Claims, ClaimsValidationRules},
    keys::AsymmetricPublicKey,
    version4::V4,
    Public,
};
use std::sync::Arc;
use uuid::Uuid;
use visitorpass_domain::value_objects::{OrgContext, Role};
use visitorpass_application::ports::KeyProvider;

/// The auth middleware extracts and validates the PASETO v4.public access token.
/// On success, it injects an `OrgContext` as an Axum extension accessible
/// by all downstream handlers.
///
/// On failure, it returns a structured JSON error — never a bare 401.
pub async fn auth_middleware(
    key_provider: axum::extract::Extension<Arc<dyn KeyProvider>>,
    org_id_path:  Option<axum::extract::Path<std::collections::HashMap<String, String>>>,
    mut request:  Request,
    next:         Next,
) -> Response {
    let headers = request.headers();

    // ── 1. Extract bearer token ──────────────────────────────────────────
    let token = match extract_bearer_token(headers) {
        Some(t) => t,
        None => return auth_error("UNAUTHORIZED", "Authorization header required", StatusCode::UNAUTHORIZED),
    };

    // ── 2. Verify PASETO v4.public token ─────────────────────────────────
    let claims = match verify_paseto_token(token, &key_provider.0) {
        Ok(c) => c,
        Err(code) => return auth_error(code, "Token is invalid or expired", StatusCode::UNAUTHORIZED),
    };

    // ── 3. Build OrgContext from token claims ─────────────────────────────
    let ctx = match build_org_context(&claims) {
        Ok(c) => c,
        Err(msg) => return auth_error("TOKEN_INVALID", msg, StatusCode::UNAUTHORIZED),
    };

    // ── 4. Validate org_id in URL matches token (critical!) ───────────────
    if let Some(axum::extract::Path(params)) = org_id_path {
        if let Some(url_org_id_str) = params.get("org_id") {
            if let Ok(url_org_id) = Uuid::parse_str(url_org_id_str) {
                if url_org_id != ctx.org_id {
                    return auth_error(
                        "ORG_MISMATCH",
                        "Token organization does not match the requested resource",
                        StatusCode::FORBIDDEN,
                    );
                }
            }
        }
    }

    // ── 5. Inject context into request extensions ─────────────────────────
    request.extensions_mut().insert(ctx);

    next.run(request).await
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

fn verify_paseto_token(
    token: &str,
    key_provider: &Arc<dyn KeyProvider>,
) -> Result<serde_json::Value, &'static str> {
    // Derive the server's Ed25519 verification key
    let key_bytes = key_provider
        .derive_paseto_key()
        .map_err(|_| "TOKEN_INVALID")?;

    // Build AsymmetricPublicKey from the last 32 bytes (public part)
    let public_key = AsymmetricPublicKey::<V4>::from(&key_bytes[32..64])
        .map_err(|_| "TOKEN_INVALID")?;

    let validation_rules = ClaimsValidationRules::new();

    let untrusted = pasetors::token::UntrustedToken::<Public, V4>::try_from(token)
        .map_err(|_| "TOKEN_INVALID")?;

    let trusted = pasetors::public::verify(&public_key, &untrusted, &validation_rules, None, None)
        .map_err(|_| "TOKEN_EXPIRED")?;

    let claims_json: serde_json::Value = serde_json::from_str(trusted.payload())
        .map_err(|_| "TOKEN_INVALID")?;

    Ok(claims_json)
}

fn build_org_context(claims: &serde_json::Value) -> Result<OrgContext, &'static str> {
    let user_id = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("TOKEN_INVALID")?;

    let org_id = claims
        .get("org")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("TOKEN_INVALID")?;

    let role_str = claims
        .get("role")
        .and_then(|v| v.as_str())
        .ok_or("TOKEN_INVALID")?;

    let role = Role::try_from(role_str).map_err(|_| "TOKEN_INVALID")?;

    let device_id = claims
        .get("dev")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

    let location_id = claims
        .get("loc")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

    Ok(OrgContext::new(org_id, user_id, role, device_id, location_id))
}

fn auth_error(code: &str, message: &str, status: StatusCode) -> Response {
    let body = serde_json::json!({
        "error": {
            "code":    code,
            "message": message,
        }
    });
    (status, axum::Json(body)).into_response()
}
