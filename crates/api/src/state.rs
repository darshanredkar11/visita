use std::sync::Arc;

use visitorpass_application::{
    ports::{
        AuditRepository, DeviceRepository, EntryRepository, OrgRepository, PassRepository,
        PlatformAdminRepository, UserRepository, LocationRepository, CryptoService, KeyProvider,
        NotificationProvider, ShareChannel,
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
    /// Server-initiated notifications (push/SMS/email). See
    /// `NotificationProvider` doc comment. Previously constructed in
    /// `main.rs` and immediately dropped -- never actually reachable from
    /// any handler or use case; this field closes that wiring gap.
    /// `SyncEventsUseCase` is its only consumer today (entry-arrival push/
    /// SMS notifications); exposed on `AppState` too, matching every other
    /// port here, so a future handler that wants to notify directly (e.g.
    /// an admin broadcast endpoint) doesn't need new plumbing.
    #[allow(dead_code, reason = "no handler calls this directly yet; SyncEventsUseCase holds its own clone")]
    pub notifier:     Arc<dyn NotificationProvider>,
    /// Distributes an already-created pass's `share_url` over a specific
    /// channel on demand -- see `ShareChannel` doc comment for why this is
    /// separate from `notifier`. One field per channel (not a registry/map)
    /// since there are exactly two and that's expected to stay true.
    pub whatsapp_channel: Arc<dyn ShareChannel>,
    pub sms_channel:      Arc<dyn ShareChannel>,

    // ── Use Cases ─────────────────────────────────────────────────────────
    pub create_pass:          Arc<CreatePassUseCase>,
    pub verify_pass:          Arc<VerifyPassUseCase>,
    pub revoke_pass:          Arc<RevokePassUseCase>,
    pub register_org:         Arc<RegisterOrganizationUseCase>,
    pub register_device:      Arc<RegisterDeviceUseCase>,
    pub revoke_device:        Arc<RevokeDeviceUseCase>,
    pub sync_events:          Arc<SyncEventsUseCase>,

    // ── Repositories (for handlers that need direct queries) ──────────────
    pub orgs:            Arc<dyn OrgRepository>,
    pub users:           Arc<dyn UserRepository>,
    pub passes:          Arc<dyn PassRepository>,
    pub entries:         Arc<dyn EntryRepository>,
    pub devices:         Arc<dyn DeviceRepository>,
    pub locations:       Arc<dyn LocationRepository>,
    pub audit:           Arc<dyn AuditRepository>,
    pub platform_admins: Arc<dyn PlatformAdminRepository>,

    // ── Realtime Sync / PubSub ────────────────────────────────────────────
    // ── Realtime Sync / PubSub ────────────────────────────────────────────
    pub broadcast_tx: tokio::sync::broadcast::Sender<RealtimeEvent>,
    
    // ── Rate Limiting ──────────────────────────────────────────────────────
    // Tracks per-IP request counts for /v/:pass_number endpoint (simple token bucket)
    pub rate_limiter: Arc<std::sync::Mutex<std::collections::HashMap<String, (i32, std::time::Instant)>>>,

    // ── Google JWKS Cache ───────────────────────────────────────────────────
    pub jwks_cache: Arc<crate::handlers::google_auth::JwksCache>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RealtimeEvent {
    pub org_id:  uuid::Uuid,
    pub payload: serde_json::Value,
}
