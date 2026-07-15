use std::{net::SocketAddr, sync::Arc};

use axum::Router;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use visitorpass_infrastructure::key_provider::env_key_provider::EnvKeyProvider;
use visitorpass_infrastructure::crypto::service::DefaultCryptoService;

mod config;
mod errors;
mod handlers;
mod middleware;
mod router;
mod state;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() {
    // ── 1. Structured logging ────────────────────────────────────────────
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("visitorpass=info,tower_http=info")
        }))
        .with(fmt::layer().json())
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "VisitorPass starting"
    );

    // ── 2. Load and validate configuration ───────────────────────────────
    let config = config::AppConfig::from_env();
    tracing::info!(
        env  = %config.env,
        host = %config.host,
        port = config.port,
        "Configuration loaded"
    );

    // ── 3. Initialize key provider (panics on missing/bad key) ───────────
    let key_provider: Arc<dyn visitorpass_application::ports::KeyProvider> =
        Arc::new(EnvKeyProvider::from_env());

    // ── 4. Connect to PostgreSQL ─────────────────────────────────────────
    let db_pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .min_connections(config.database_min_connections)
        .connect(&config.database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    tracing::info!("PostgreSQL connected");

    // ── 5. Run pending migrations ────────────────────────────────────────
    sqlx::migrate!("../../migrations")
        .run(&db_pool)
        .await
        .expect("Failed to run database migrations");

    tracing::info!("Migrations applied");

    // ── 6. Build infrastructure implementations ──────────────────────────
    let crypto: Arc<dyn visitorpass_application::ports::CryptoService> =
        Arc::new(DefaultCryptoService::new(Arc::clone(&key_provider)));

    // Repositories
    let orgs: Arc<dyn visitorpass_application::ports::OrgRepository> =
        Arc::new(visitorpass_infrastructure::db::postgres::PgOrgRepository::new(db_pool.clone()));
    let users: Arc<dyn visitorpass_application::ports::UserRepository> =
        Arc::new(visitorpass_infrastructure::db::postgres::PgUserRepository::new(db_pool.clone()));
    let passes: Arc<dyn visitorpass_application::ports::PassRepository> =
        Arc::new(visitorpass_infrastructure::db::postgres::PgPassRepository::new(db_pool.clone()));
    let entries: Arc<dyn visitorpass_application::ports::EntryRepository> =
        Arc::new(visitorpass_infrastructure::db::postgres::PgEntryRepository::new(db_pool.clone()));
    let devices: Arc<dyn visitorpass_application::ports::DeviceRepository> =
        Arc::new(visitorpass_infrastructure::db::postgres::PgDeviceRepository::new(db_pool.clone()));
    let locations: Arc<dyn visitorpass_application::ports::LocationRepository> =
        Arc::new(visitorpass_infrastructure::db::postgres::PgLocationRepository::new(db_pool.clone()));
    let audit: Arc<dyn visitorpass_application::ports::AuditRepository> =
        Arc::new(visitorpass_infrastructure::db::postgres::PgAuditRepository::new(db_pool.clone()));

    // Notifications
    let notifier = Arc::new(
        visitorpass_application::ports::notification_provider::NoopNotificationProvider
    );

    // ── 7. Wire use cases ────────────────────────────────────────────────
    let create_pass = Arc::new(
        visitorpass_application::use_cases::CreatePassUseCase::new(
            Arc::clone(&passes),
            Arc::clone(&orgs),
            Arc::clone(&crypto),
            Arc::clone(&audit),
            config.base_url.clone(),
        )
    );

    let verify_pass = Arc::new(
        visitorpass_application::use_cases::VerifyPassUseCase::new(
            Arc::clone(&passes),
            Arc::clone(&orgs),
            Arc::clone(&crypto),
            Arc::clone(&audit),
        )
    );

    let revoke_pass = Arc::new(
        visitorpass_application::use_cases::RevokePassUseCase::new(
            Arc::clone(&passes),
            Arc::clone(&orgs),
            Arc::clone(&audit),
        )
    );

    let register_org = Arc::new(
        visitorpass_application::use_cases::RegisterOrganizationUseCase::new(
            Arc::clone(&orgs),
            Arc::clone(&users),
            Arc::clone(&crypto),
            Arc::clone(&audit),
        )
    );

    let register_device = Arc::new(
        visitorpass_application::use_cases::RegisterDeviceUseCase::new(
            Arc::clone(&devices),
            Arc::clone(&orgs),
            Arc::clone(&audit),
        )
    );

    let revoke_device = Arc::new(
        visitorpass_application::use_cases::RevokeDeviceUseCase::new(
            Arc::clone(&devices),
            Arc::clone(&audit),
        )
    );

    let sync_events = Arc::new(
        visitorpass_application::use_cases::SyncEventsUseCase::new(
            Arc::clone(&devices),
            Arc::clone(&passes),
            Arc::clone(&entries),
            Arc::clone(&orgs),
            Arc::clone(&audit),
        )
    );

    let (broadcast_tx, _) = tokio::sync::broadcast::channel(1024);

    // ── 8. Build app state ───────────────────────────────────────────────
    let state = state::AppState {
        config:          config.clone(),
        db_pool:         db_pool.clone(),
        key_provider:    Arc::clone(&key_provider),
        crypto:          Arc::clone(&crypto),
        create_pass,
        verify_pass,
        revoke_pass,
        register_org,
        register_device,
        revoke_device,
        sync_events,
        orgs:      Arc::clone(&orgs),
        users:     Arc::clone(&users),
        passes:    Arc::clone(&passes),
        entries:   Arc::clone(&entries),
        devices:   Arc::clone(&devices),
        locations: Arc::clone(&locations),
        audit:     Arc::clone(&audit),
        broadcast_tx,
        rate_limiter: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
    };

    // ── 9. Build router ──────────────────────────────────────────────────
    let app = router::build_router(state);

    // ── 10. Bind and serve ───────────────────────────────────────────────
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .expect("Invalid bind address");

    tracing::info!(%addr, "Listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind listener");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Server error");

    tracing::info!("Server shut down gracefully");
}

/// Listens for SIGTERM (k8s) or Ctrl-C (dev).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM listener failed");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.expect("Ctrl-C handler failed");
    }
    tracing::info!("Shutdown signal received");
}
