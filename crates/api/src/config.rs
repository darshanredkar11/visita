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
    /// Runtime connection string. Migration 024 added a least-privilege
    /// `visitorpass_app` role specifically so RLS (migration 023) has any
    /// real effect -- superusers (which `visitorpass`, the migration/owner
    /// role, is) bypass row-level security unconditionally, with no
    /// override. This MUST point at `visitorpass_app` (or an equivalent
    /// non-superuser, non-BYPASSRLS role) for RLS to actually do anything.
    pub database_url: String,

    #[serde(default = "defaults::db_max_connections")]
    pub database_max_connections: u32,

    #[serde(default = "defaults::db_min_connections")]
    pub database_min_connections: u32,

    /// Connection string used ONLY for the one-time startup migration run
    /// (`sqlx::migrate!`), which needs DDL privileges `database_url`'s
    /// least-privilege runtime role deliberately does not have (CREATE
    /// TABLE, ALTER TABLE, CREATE POLICY, ...). Falls back to
    /// `database_url` when unset so a single-role local/dev setup (where
    /// RLS enforcement doesn't matter) still works with one env var.
    #[serde(default)]
    pub migration_database_url: Option<String>,

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

    /// MSG91 auth key (the `authkey` header on their Flow API). Required
    /// when `sms_enabled` is true; unused when false -- see
    /// `SmsShareChannel::share`'s no-op-when-disabled behavior.
    #[serde(default)]
    pub sms_provider_api_key: Option<String>,

    /// MSG91 DLT-approved sender id (6 chars, e.g. "VISITA"). Required when
    /// `sms_enabled` is true.
    #[serde(default)]
    pub sms_sender_id: Option<String>,

    /// MSG91 Flow API `flow_id`: the pre-approved DLT template that carries
    /// the share message as its one free-text variable. Required when
    /// `sms_enabled` is true.
    #[serde(default)]
    pub sms_flow_id: Option<String>,

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
        if self.sms_enabled {
            if self.sms_provider_api_key.as_deref().unwrap_or("").is_empty() {
                return Err("SMS_PROVIDER_API_KEY is required when SMS_ENABLED=true".into());
            }
            if self.sms_sender_id.as_deref().unwrap_or("").is_empty() {
                return Err("SMS_SENDER_ID is required when SMS_ENABLED=true".into());
            }
            if self.sms_flow_id.as_deref().unwrap_or("").is_empty() {
                return Err("SMS_FLOW_ID is required when SMS_ENABLED=true".into());
            }
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
