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
mod scheduler;
mod state;
mod validation;

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

    // ── 4. Run pending migrations via a SEPARATE, privileged connection ───
    // Migrations need DDL rights (CREATE TABLE, CREATE POLICY, ...) that
    // `database_url`'s runtime role deliberately does not have -- see
    // AppConfig::migration_database_url and migration 024. Kept alive (not
    // closed) after migrations run: the scheduler's partition-maintenance
    // jobs (`CREATE TABLE ... PARTITION OF`) also need DDL rights the
    // runtime pool below deliberately lacks.
    let migration_url = config.migration_database_url.clone().unwrap_or_else(|| config.database_url.clone());
    let privileged_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&migration_url)
        .await
        .expect("Failed to connect to PostgreSQL for migrations");

    sqlx::migrate!("../../migrations")
        .run(&privileged_pool)
        .await
        .expect("Failed to run database migrations");
    tracing::info!("Migrations applied");

    // ── 5. Connect the runtime pool -- least-privilege role (see
    // AppConfig::database_url's doc comment), used for every request ─────
    let db_pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .min_connections(config.database_min_connections)
        .connect(&config.database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    tracing::info!("PostgreSQL connected");

    // ── 5b. Start background maintenance jobs (pass expiry, session/
    // challenge cleanup, partition creation, retention enforcement) ───────
    scheduler::spawn_background_jobs(db_pool.clone(), privileged_pool);

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
    let platform_admins: Arc<dyn visitorpass_application::ports::PlatformAdminRepository> =
        Arc::new(visitorpass_infrastructure::db::postgres::PgPlatformAdminRepository::new(db_pool.clone()));

    // Notifications
    let notifier: Arc<dyn visitorpass_application::ports::NotificationProvider> = Arc::new(
        visitorpass_application::ports::notification_provider::NoopNotificationProvider
    );

    // Share channels (WhatsApp deep link generator, SMS via MSG91)
    let whatsapp_channel: Arc<dyn visitorpass_application::ports::ShareChannel> =
        Arc::new(visitorpass_infrastructure::share::WhatsAppShareChannel::new());
    let sms_channel: Arc<dyn visitorpass_application::ports::ShareChannel> = Arc::new(
        visitorpass_infrastructure::share::SmsShareChannel::msg91(
            config.sms_enabled,
            config.sms_provider_api_key.clone().unwrap_or_default(),
            config.sms_sender_id.clone().unwrap_or_default(),
            config.sms_flow_id.clone().unwrap_or_default(),
        )
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
            Arc::clone(&users),
            Arc::clone(&crypto),
            Arc::clone(&audit),
            Arc::clone(&notifier),
            config.sms_enabled,
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
        platform_admins: Arc::clone(&platform_admins),
        notifier: Arc::clone(&notifier),
        whatsapp_channel,
        sms_channel,
        broadcast_tx,
        rate_limiter: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        jwks_cache: Arc::new(handlers::google_auth::JwksCache::new()),
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
