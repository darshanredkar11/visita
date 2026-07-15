use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use visitorpass_domain::{
    entities::{Device, EntryLog, Location, OrgKey, Organization, User, VisitorPass},
    value_objects::{OrgContext, Role},
    DomainError,
};

/// Cursor-based pagination parameters.
#[derive(Debug, Clone)]
pub struct PageParams {
    pub limit:  i64,
    pub cursor: Option<CursorPosition>,
}

/// Opaque cursor position (decoded from the base64url cursor string).
#[derive(Debug, Clone)]
pub struct CursorPosition {
    pub id:         Uuid,
    pub created_at: DateTime<Utc>,
}

impl PageParams {
    pub fn new(limit: i64) -> Self {
        Self { limit: limit.min(200).max(1), cursor: None }
    }
    pub fn with_cursor(mut self, cursor: Option<CursorPosition>) -> Self {
        self.cursor = cursor;
        self
    }
}

/// Generic paginated result.
pub struct Page<T> {
    pub items:       Vec<T>,
    pub next_cursor: Option<CursorPosition>,
}

// ─── Organization Repository ──────────────────────────────────────────────────

#[async_trait]
pub trait OrgRepository: Send + Sync + 'static {
    async fn create(&self, org: &Organization, initial_key: &OrgKey, owner_id: Uuid) -> Result<(), DomainError>;
    async fn find_by_id(&self, ctx: &OrgContext, id: Uuid) -> Result<Organization, DomainError>;
    async fn find_by_slug(&self, slug: &str) -> Result<Organization, DomainError>;
    async fn update(&self, ctx: &OrgContext, org: &Organization) -> Result<Organization, DomainError>;
    async fn increment_sync_seq(&self, org_id: Uuid) -> Result<i64, DomainError>;
    async fn find_active_key(&self, org_id: Uuid) -> Result<OrgKey, DomainError>;
    async fn find_key_version(&self, org_id: Uuid, version: i32) -> Result<OrgKey, DomainError>;
    async fn list_keys(&self, ctx: &OrgContext) -> Result<Vec<OrgKey>, DomainError>;
    async fn store_key(&self, key: &OrgKey) -> Result<(), DomainError>;
    async fn retire_key(&self, ctx: &OrgContext, version: i32) -> Result<(), DomainError>;
    async fn generate_join_token(&self, org_id: Uuid, user_id: Uuid) -> Result<String, DomainError>;
    async fn get_active_join_token(&self, org_id: Uuid) -> Result<Option<String>, DomainError>;
    async fn verify_join_token(&self, token: &str) -> Result<Uuid, DomainError>;
    async fn add_membership_direct(&self, org_id: Uuid, user_id: Uuid, role: Role, unit_identifier: String) -> Result<(), DomainError>;
}

// ─── User Repository ──────────────────────────────────────────────────────────

/// Input for creating a new user.
pub struct CreateUserInput {
    pub email:         String,
    pub password_hash: String,
    pub phone_hmac:    Option<String>,
    pub full_name:     String,
}

#[async_trait]
pub trait UserRepository: Send + Sync + 'static {
    async fn create(&self, input: CreateUserInput) -> Result<User, DomainError>;
    async fn find_by_id(&self, id: Uuid) -> Result<User, DomainError>;
    async fn find_by_email(&self, email: &str) -> Result<User, DomainError>;
    async fn record_login_success(&self, user_id: Uuid) -> Result<(), DomainError>;
    async fn record_login_failure(&self, user_id: Uuid) -> Result<(), DomainError>;
    async fn set_lock(&self, user_id: Uuid, until: Option<DateTime<Utc>>) -> Result<(), DomainError>;
    async fn verify_email(&self, user_id: Uuid) -> Result<(), DomainError>;
    async fn find_membership_role(&self, user_id: Uuid, org_id: Uuid) -> Result<Role, DomainError>;
    async fn list_memberships(&self, user_id: Uuid) -> Result<Vec<(Uuid, String, Role, Option<String>)>, DomainError>;
}

// ─── Location Repository ──────────────────────────────────────────────────────

pub struct CreateLocationInput {
    pub org_id:       Uuid,
    pub name:         String,
    pub description:  Option<String>,
    pub timezone:     String,
    pub address_line: Option<String>,
}

#[async_trait]
pub trait LocationRepository: Send + Sync + 'static {
    async fn create(&self, ctx: &OrgContext, input: CreateLocationInput) -> Result<Location, DomainError>;
    async fn find_by_id(&self, ctx: &OrgContext, id: Uuid) -> Result<Location, DomainError>;
    async fn list(&self, ctx: &OrgContext, page: PageParams) -> Result<Page<Location>, DomainError>;
    async fn update(&self, ctx: &OrgContext, location: &Location) -> Result<Location, DomainError>;
    async fn soft_delete(&self, ctx: &OrgContext, id: Uuid) -> Result<(), DomainError>;
}

// ─── Device Repository ────────────────────────────────────────────────────────

pub struct CreateDeviceInput {
    pub org_id:        Uuid,
    pub location_id:   Option<Uuid>,
    pub owner_user_id: Option<Uuid>,
    pub device_type:   String,
    pub name:          String,
    pub public_key:    Vec<u8>,
    pub platform:      Option<String>,
    pub os_version:    Option<String>,
    pub app_version:   Option<String>,
    pub push_token:    Option<String>,
}

#[async_trait]
pub trait DeviceRepository: Send + Sync + 'static {
    async fn create(&self, ctx: &OrgContext, input: CreateDeviceInput) -> Result<Device, DomainError>;
    async fn find_by_id(&self, ctx: &OrgContext, id: Uuid) -> Result<Device, DomainError>;
    async fn find_by_public_key(&self, public_key: &[u8]) -> Result<Device, DomainError>;
    async fn list(&self, ctx: &OrgContext, page: PageParams) -> Result<Page<Device>, DomainError>;
    async fn revoke(
        &self,
        ctx: &OrgContext,
        device_id: Uuid,
        reason: Option<String>,
    ) -> Result<Device, DomainError>;
    async fn update_last_seen(&self, device_id: Uuid) -> Result<(), DomainError>;
    async fn get_sync_checkpoint(&self, device_id: Uuid, org_id: Uuid) -> Result<i64, DomainError>;
    async fn update_sync_checkpoint(
        &self,
        device_id: Uuid,
        org_id: Uuid,
        new_seq: i64,
    ) -> Result<(), DomainError>;
}

// ─── Pass Repository ──────────────────────────────────────────────────────────

pub struct CreatePassInput {
    pub org_id:               Uuid,
    pub location_id:          Uuid,
    pub created_by:           Uuid,
    pub pass_number:          String,
    pub visitor_name:         String,
    pub visitor_phone_hmac:   String,
    pub visitor_phone_enc:    Option<Vec<u8>>,
    pub purpose:              String,
    pub vehicle_number:       Option<String>,
    pub permissions:          Vec<String>,
    pub valid_from:           DateTime<Utc>,
    pub valid_until:          DateTime<Utc>,
    pub max_uses:             i32,
    pub qr_payload:           String,
    pub qr_nonce:             Vec<u8>,
    pub key_version:          i32,
}

#[derive(Debug, Clone, Default)]
pub struct PassFilter {
    pub status:      Option<String>,
    pub location_id: Option<Uuid>,
    pub created_by:  Option<Uuid>,
    pub from:        Option<DateTime<Utc>>,
    pub to:          Option<DateTime<Utc>>,
}

#[async_trait]
pub trait PassRepository: Send + Sync + 'static {
    async fn create(&self, ctx: &OrgContext, input: CreatePassInput) -> Result<VisitorPass, DomainError>;
    async fn find_by_id(&self, ctx: &OrgContext, id: Uuid) -> Result<VisitorPass, DomainError>;
    async fn find_by_pass_number(&self, ctx: &OrgContext, number: &str) -> Result<VisitorPass, DomainError>;
    async fn find_by_pass_number_public(&self, number: &str) -> Result<VisitorPass, DomainError>;
    async fn list(&self, ctx: &OrgContext, filter: PassFilter, page: PageParams)
        -> Result<Page<VisitorPass>, DomainError>;
    async fn revoke(
        &self,
        ctx: &OrgContext,
        pass_id: Uuid,
        revoked_by: Uuid,
        reason: Option<String>,
    ) -> Result<VisitorPass, DomainError>;
    async fn increment_use_count(&self, ctx: &OrgContext, pass_id: Uuid) -> Result<(), DomainError>;
    /// Fetch all active, non-expired passes for a location since `since_seq`.
    /// Used by the sync endpoint to send new passes to guard devices.
    async fn list_for_sync(
        &self,
        org_id: Uuid,
        location_id: Uuid,
        since_sync_seq: i64,
    ) -> Result<Vec<VisitorPass>, DomainError>;
    /// Fetch pass IDs revoked since `since_seq`.
    async fn list_revoked_since(
        &self,
        org_id: Uuid,
        since_sync_seq: i64,
    ) -> Result<Vec<(Uuid, DateTime<Utc>)>, DomainError>;
}

// ─── Entry Repository ─────────────────────────────────────────────────────────

pub struct CreateEntryInput {
    pub org_id:          Uuid,
    pub location_id:     Uuid,
    pub pass_id:         Uuid,
    pub device_id:       Option<Uuid>,
    pub guard_user_id:   Option<Uuid>,
    pub action:          String,
    pub denial_reason:   Option<String>,
    pub guard_note:      Option<String>,
    pub occurred_at:     DateTime<Utc>,
    pub client_event_id: Uuid,
}

#[derive(Debug, Clone, Default)]
pub struct EntryFilter {
    pub pass_id:     Option<Uuid>,
    pub location_id: Option<Uuid>,
    pub action:      Option<String>,
    pub from:        Option<DateTime<Utc>>,
    pub to:          Option<DateTime<Utc>>,
}

#[async_trait]
pub trait EntryRepository: Send + Sync + 'static {
    /// Insert an entry log. Returns `Ok(None)` if the `client_event_id`
    /// already exists (idempotent duplicate); `Ok(Some(log))` on success.
    async fn create(
        &self,
        ctx: &OrgContext,
        input: CreateEntryInput,
    ) -> Result<Option<EntryLog>, DomainError>;
    async fn find_by_id(&self, ctx: &OrgContext, id: Uuid) -> Result<EntryLog, DomainError>;
    async fn list(
        &self,
        ctx: &OrgContext,
        filter: EntryFilter,
        page: PageParams,
    ) -> Result<Page<EntryLog>, DomainError>;
}

// ─── Audit Repository ─────────────────────────────────────────────────────────

pub struct AuditEventInput {
    pub org_id:             Uuid,
    pub event_type:         String,
    pub actor_user_id:      Option<Uuid>,
    pub actor_device_id:    Option<Uuid>,
    pub target_entity_type: Option<String>,
    pub target_entity_id:   Option<Uuid>,
    pub metadata:           serde_json::Value,
    pub ip_address:         Option<String>,
}

#[async_trait]
pub trait AuditRepository: Send + Sync + 'static {
    /// Append an audit event. Fire-and-forget; errors are logged, not surfaced.
    async fn append(&self, input: AuditEventInput) -> Result<(), DomainError>;
}
