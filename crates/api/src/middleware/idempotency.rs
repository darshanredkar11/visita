use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use axum::body::Body;
use serde_json::json;
use uuid::Uuid;
use visitorpass_domain::value_objects::OrgContext;

use crate::state::AppState;
/// Middleware implementing the Idempotency-Key specification.
/// Intercepts POST requests on protected routes, caching by (org_id, path, Idempotency-Key).
/// Only runs on authenticated requests with OrgContext.
pub async fn idempotency_middleware(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    request: Request,
    next: Next,
) -> Response {
    // 1. Only intercept POST requests
    if request.method() != axum::http::Method::POST {
        return next.run(request).await;
    }

    // 2. Extract Idempotency-Key header
    let key_header = match request.headers().get("Idempotency-Key") {
        Some(h) => h,
        None => return next.run(request).await, // proceed if missing
    };

    let key_str = match key_header.to_str() {
        Ok(s) => s,
        Err(_) => return bad_request("Idempotency-Key must be a valid UTF-8 string"),
    };

    let key_uuid = match Uuid::parse_str(key_str) {
        Ok(u) => u,
        Err(_) => return bad_request("Idempotency-Key must be a valid UUID"),
    };

    // 3. Create composite cache key: (org_id, path, idempotency_key)
    let path = request.uri().path();
    let composite_key_str = format!("{}:{}:{}", ctx.org_id, path, key_str);
    
    // Hash the composite key to create a deterministic cache key
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(composite_key_str.as_bytes());
    let hash = hasher.finalize();
    // Convert first 16 bytes of SHA256 to UUID for database storage
    let composite_key_uuid = Uuid::from_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
    ]);
    
    // Query Postgres cache with composite key
    let cached_query: Result<Option<(i32, Vec<u8>)>, sqlx::Error> = sqlx::query_as(
        "SELECT response_status, response_body FROM app.idempotency_keys WHERE key = $1"
    )
    .bind(composite_key_uuid)
    .fetch_optional(&state.db_pool)
    .await;

    match cached_query {
        Ok(Some((status, body_bytes))) => {
            // Cache Hit: Replay response instantly
            let response = Response::builder()
                .status(status as u16)
                .header("Content-Type", "application/json")
                .header("Idempotent-Replay", "true")
                .body(Body::from(body_bytes))
                .unwrap();
            return response;
        }
        Err(e) => {
            tracing::error!(error = %e, "Idempotency database query failed");
        }
        _ => {} // cache miss, proceed
    }

    // 4. Process request downstream
    let response = next.run(request).await;

    // 5. Cache response status and body
    let (parts, body) = response.into_parts();
    
    // Read body bytes limit to 10MB
    let bytes = match axum::body::to_bytes(body, 10_000_000).await {
        Ok(b) => b,
        Err(_) => return Response::from_parts(parts, Body::empty()),
    };

    // Only cache successful (2xx) or client error (4xx) responses
    if parts.status.is_success() || parts.status.is_client_error() {
        let insert_res = sqlx::query(
            "INSERT INTO app.idempotency_keys (key, response_status, response_body) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING"
        )
        .bind(composite_key_uuid)
        .bind(parts.status.as_u16() as i32)
        .bind(bytes.to_vec())
        .execute(&state.db_pool)
        .await;

        if let Err(e) = insert_res {
            tracing::error!(error = %e, "Failed to cache idempotency key");
        }
    }

    // Rebuild response
    Response::from_parts(parts, Body::from(bytes))
}

fn bad_request(message: &str) -> Response {
    let body = json!({
        "error": {
            "code": "VALIDATION_ERROR",
            "message": message
        }
    });
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}
