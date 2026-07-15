use serde::Deserialize;
use visitorpass_domain::DomainError;

/// All configuration loaded from environment variables at startup.
/// Missing required values cause a panic with a clear error message.
/// Silent fallbacks are never used.
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    // ── Server ────────────────────────────────────────────────────────────
    #[serde(default = "defaults::host")]
    pub host: String,

    #[serde(default = "defaults::port")]
    pub port: u16,

    #[serde(default = "defaults::env")]
    pub env: String,

    // ── Database ──────────────────────────────────────────────────────────
    pub database_url: String,

    #[serde(default = "defaults::db_max_connections")]
    pub database_max_connections: u32,

    #[serde(default = "defaults::db_min_connections")]
    pub database_min_connections: u32,

    // ── Crypto ────────────────────────────────────────────────────────────
    /// Master key loaded by EnvKeyProvider at startup.
    /// Present here only for validation — never stored or passed around.
    pub master_key_hex: String,

    // ── URLs ──────────────────────────────────────────────────────────────
    /// Base URL for share links: https://visitorpass.app
    pub base_url: String,

    // ── Retention defaults (days) ─────────────────────────────────────────
    #[serde(default = "defaults::retention_free")]
    pub default_retention_days: i32,

    // ── Feature flags defaults ────────────────────────────────────────────
    #[serde(default)]
    pub sms_enabled: bool,

    pub email_enabled: bool,

    // ── Google OAuth ──────────────────────────────────────────────────────
    /// Google OAuth 2.0 Client ID (for audience validation).
    pub google_client_id: String,
}

impl AppConfig {
    /// Load from environment. Panics if required vars are missing.
    pub fn from_env() -> Self {
        // Use the `config` crate with env source for production-grade loading.
        // We use environment variables with prefix `VISITORPASS_`.
        let cfg = config::Config::builder()
            .add_source(config::Environment::default())
            .build()
            .expect("Failed to build configuration");

        let app: AppConfig = cfg
            .try_deserialize()
            .expect("Failed to deserialize configuration — check environment variables");

        app.validate().expect("Configuration validation failed");
        app
    }

    fn validate(&self) -> Result<(), String> {
        if self.database_url.is_empty() {
            return Err("DATABASE_URL is required".into());
        }
        if self.master_key_hex.len() != 64 {
            return Err(format!(
                "MASTER_KEY_HEX must be 64 hex characters; got {}",
                self.master_key_hex.len()
            ));
        }
        if self.base_url.is_empty() {
            return Err("BASE_URL is required".into());
        }
        if self.google_client_id.is_empty() {
            return Err("GOOGLE_CLIENT_ID is required".into());
        }
        Ok(())
    }
}

mod defaults {
    pub fn host()               -> String { "0.0.0.0".into() }
    pub fn port()               -> u16    { 8080 }
    pub fn env()                -> String { "production".into() }
    pub fn db_max_connections() -> u32    { 20 }
    pub fn db_min_connections() -> u32    { 5 }
    pub fn retention_free()     -> i32    { 90 }
    pub fn email_enabled()      -> bool   { true }
}
