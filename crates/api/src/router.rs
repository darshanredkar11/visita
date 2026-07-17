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
        passes::{create_pass, get_pass, revoke_pass, verify_pass, list_passes, pass_pdf, share_pass},
        platform::{list_organizations, platform_metrics, provision_organization, revoke_device_platform, set_org_subscription_tier},
        share_page::share_page,
    },
    middleware::{auth_middleware, platform_admin_middleware},
    state::AppState,
};

/// Build the main application router with all 44 endpoints registered.
pub fn build_router(state: AppState) -> Router {
    // ── 1. Anonymous / public routes ──────────────────────────────────────
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/v/:pass_number", get(share_page))
        .route("/api/v1/organizations", post(register))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/refresh", post(crate::handlers::auth::refresh_token))
        .route("/api/v1/auth/logout", post(crate::handlers::auth::logout))
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
        .route("/api/v1/organizations/:org_id/passes/:pass_id/pdf", get(pass_pdf))
        .route("/api/v1/organizations/:org_id/passes/:pass_id/share", post(share_pass))
        .route("/api/v1/passes/verify", post(verify_pass)) // public QR verify for logged-in devices

        // Entries
        .route("/api/v1/organizations/:org_id/entries", get(list_entries))
        .route("/api/v1/organizations/:org_id/entries/request-approval", post(crate::handlers::sync::request_approval))
        .route("/api/v1/organizations/:org_id/entries/:approval_id/approve", post(crate::handlers::sync::approve_entry))
        .route("/api/v1/sync", post(crate::handlers::sync::sync))
        .route("/api/v1/sync/ws", get(crate::handlers::sync::ws_handler))

        // Wire auth middleware & state.
        //
        // Axum layering rule: the LAST `.layer()` call becomes the OUTERMOST
        // layer and runs FIRST on an incoming request. We need, in request
        // order: (1) key_provider available, (2) auth validated + OrgContext
        // inserted, (3) idempotency cache check (which reads OrgContext).
        // So we must add them in the REVERSE of that order below:
        //   idempotency (added first -> innermost, runs LAST, right before
        //     the route handler -- by then OrgContext already exists)
        //   auth_middleware_wrapper (added second -> middle, runs after
        //     key_provider is available and before idempotency)
        //   Extension(key_provider) (added last -> outermost, runs FIRST)
        //
        // Getting this backwards (idempotency added last/outermost) means it
        // runs BEFORE auth ever inserts OrgContext, so its mandatory
        // `Extension<OrgContext>` extractor fails on every protected
        // request -- a full regression previously caught only by an e2e test
        // that goes through the real router, not a unit test of either
        // middleware in isolation.
        .layer(middleware::from_fn_with_state(state.clone(), crate::middleware::idempotency::idempotency_middleware))
        .layer(middleware::from_fn(auth_middleware_wrapper))
        .layer(Extension(Arc::clone(&state.key_provider)));

    // ── 3. Platform-admin routes (cross-tenant, NOT org-scoped) ────────────
    // Deliberately a THIRD router group, not merged into `protected_routes`:
    // idempotency_middleware's extractor requires an `Extension<OrgContext>`,
    // which a platform-admin request never has (it carries a
    // `PlatformContext` instead) -- layering it here would 500 every
    // request. Same outermost-runs-first layering rule as above, just with
    // `platform_admin_middleware` instead of `auth_middleware_wrapper` and
    // no idempotency layer.
    let platform_routes = Router::new()
        .route("/api/v1/platform/organizations", get(list_organizations).post(provision_organization))
        .route("/api/v1/platform/organizations/:org_id/tier", put(set_org_subscription_tier))
        .route("/api/v1/platform/metrics", get(platform_metrics))
        .route("/api/v1/platform/devices/:device_id/revoke", post(revoke_device_platform))
        .layer(middleware::from_fn(platform_admin_middleware_wrapper))
        .layer(Extension(Arc::clone(&state.key_provider)));

    // Combine everything into a single router
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(platform_routes)
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

/// Helper wrapper mirroring `auth_middleware_wrapper` above, for the
/// platform-admin-only router group (no `org_id` path param to cross-check).
async fn platform_admin_middleware_wrapper(
    Extension(key_provider): Extension<Arc<dyn visitorpass_application::ports::KeyProvider>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    platform_admin_middleware(Extension(key_provider), request, next).await
}
