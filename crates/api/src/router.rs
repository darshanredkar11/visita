use axum::{
    middleware,
    routing::{delete, get, post, put},
    Extension, Router,
};
use std::sync::Arc;

use crate::{
    handlers::{
        auth::{device_challenge, device_login, login},
        devices::{list_devices, register_device, revoke_device},
        entries::list_entries,
        health::health,
        locations::{create_location, delete_location, get_location, list_locations, update_location},
        organizations::{get_org, register},
        passes::{create_pass, get_pass, revoke_pass, verify_pass, list_passes},
        share_page::share_page,
    },
    middleware::auth_middleware,
    state::AppState,
};

/// Build the main application router with all 37 endpoints registered.
pub fn build_router(state: AppState) -> Router {
    // ── 1. Anonymous / public routes ──────────────────────────────────────
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/v/:pass_number", get(share_page))
        .route("/api/v1/organizations", post(register))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/google", post(crate::handlers::google_auth::google_auth))
        .route("/api/v1/auth/device-challenge", get(device_challenge))
        .route("/api/v1/auth/device-login", post(device_login));

    // ── 2. Protected routes (require PASETO authentication) ────────────────
    // We bind the key_provider to the request extension so the auth middleware can access it.
    let protected_routes = Router::new()
        // Organizations & Join flow
        .route("/api/v1/organizations/:org_id", get(get_org))
        .route("/api/v1/organizations/:org_id/join-token", post(crate::handlers::organizations::generate_join_token).get(crate::handlers::organizations::get_join_token))
        .route("/api/v1/organizations/join-by-token", post(crate::handlers::organizations::join_by_token))
        .route("/api/v1/users/memberships", get(crate::handlers::google_auth::list_user_memberships))
        .route("/api/v1/auth/select-org", post(crate::handlers::auth::select_org))
        
        // Locations
        .route("/api/v1/organizations/:org_id/locations", post(create_location).get(list_locations))
        .route("/api/v1/organizations/:org_id/locations/:location_id", get(get_location).put(update_location).delete(delete_location))

        // Devices
        .route("/api/v1/organizations/:org_id/devices", post(register_device).get(list_devices))
        .route("/api/v1/organizations/:org_id/devices/:device_id/revoke", post(revoke_device))

        // Passes
        .route("/api/v1/organizations/:org_id/passes", post(create_pass).get(list_passes))
        .route("/api/v1/organizations/:org_id/passes/:pass_id", get(get_pass))
        .route("/api/v1/organizations/:org_id/passes/:pass_id/revoke", post(revoke_pass))
        .route("/api/v1/passes/verify", post(verify_pass)) // public QR verify for logged-in devices

        // Entries
        .route("/api/v1/organizations/:org_id/entries", get(list_entries))
        .route("/api/v1/organizations/:org_id/entries/request-approval", post(crate::handlers::sync::request_approval))
        .route("/api/v1/organizations/:org_id/entries/:approval_id/approve", post(crate::handlers::sync::approve_entry))
        .route("/api/v1/sync", post(crate::handlers::sync::sync))
        .route("/api/v1/sync/ws", get(crate::handlers::sync::ws_handler))

        // Wire auth middleware & state
        .layer(middleware::from_fn(auth_middleware_wrapper))
        .layer(Extension(Arc::clone(&state.key_provider)));

    // Combine everything into a single router
    Router::new()
        .merge(public_routes)
        .merge(protected_routes.layer(middleware::from_fn_with_state(state.clone(), crate::middleware::idempotency::idempotency_middleware)))
        .with_state(state)
}

/// Helper wrapper since axum middlewares expect extractors as arguments
async fn auth_middleware_wrapper(
    Extension(key_provider): Extension<Arc<dyn visitorpass_application::ports::KeyProvider>>,
    org_id_path: Option<axum::extract::Path<std::collections::HashMap<String, String>>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    auth_middleware(Extension(key_provider), org_id_path, request, next).await
}
