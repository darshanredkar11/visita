use std::sync::Arc;

use visitorpass_application::{
    ports::{
        AuditRepository, DeviceRepository, EntryRepository, OrgRepository, PassRepository,
        UserRepository, LocationRepository, CryptoService, KeyProvider, NotificationProvider,
    },
    use_cases::{
        CreatePassUseCase, RegisterDeviceUseCase, RegisterOrganizationUseCase,
        RevokeDeviceUseCase, RevokePassUseCase, SyncEventsUseCase, VerifyPassUseCase,
    },
};

use crate::config::AppConfig;

/// Shared application state. Injected into every Axum handler via `State<AppState>`.
///
/// All fields are `Arc<dyn Trait>` for zero-cost cloning and testability.
/// The entire state can be replaced with test doubles in integration tests.
#[derive(Clone)]
pub struct AppState {
    pub config:  AppConfig,
    pub db_pool: sqlx::PgPool,

    // ── Ports ─────────────────────────────────────────────────────────────
    pub key_provider: Arc<dyn KeyProvider>,
    pub crypto:       Arc<dyn CryptoService>,

    // ── Use Cases ─────────────────────────────────────────────────────────
    pub create_pass:          Arc<CreatePassUseCase>,
    pub verify_pass:          Arc<VerifyPassUseCase>,
    pub revoke_pass:          Arc<RevokePassUseCase>,
    pub register_org:         Arc<RegisterOrganizationUseCase>,
    pub register_device:      Arc<RegisterDeviceUseCase>,
    pub revoke_device:        Arc<RevokeDeviceUseCase>,
    pub sync_events:          Arc<SyncEventsUseCase>,

    // ── Repositories (for handlers that need direct queries) ──────────────
    pub orgs:      Arc<dyn OrgRepository>,
    pub users:     Arc<dyn UserRepository>,
    pub passes:    Arc<dyn PassRepository>,
    pub entries:   Arc<dyn EntryRepository>,
    pub devices:   Arc<dyn DeviceRepository>,
    pub locations: Arc<dyn LocationRepository>,
    pub audit:     Arc<dyn AuditRepository>,

    // ── Realtime Sync / PubSub ────────────────────────────────────────────
    // ── Realtime Sync / PubSub ────────────────────────────────────────────
    pub broadcast_tx: tokio::sync::broadcast::Sender<RealtimeEvent>,
    
    // ── Rate Limiting ──────────────────────────────────────────────────────
    // Tracks per-IP request counts for /v/:pass_number endpoint (simple token bucket)
    pub rate_limiter: Arc<std::sync::Mutex<std::collections::HashMap<String, (i32, std::time::Instant)>>>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RealtimeEvent {
    pub org_id:  uuid::Uuid,
    pub payload: serde_json::Value,
}
