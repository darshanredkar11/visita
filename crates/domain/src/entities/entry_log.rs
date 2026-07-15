use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntryAction {
    Entry,
    Exit,
    Denied,
}

/// Immutable record of a gate event. Never updated after creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryLog {
    pub id:               Uuid,
    pub org_id:           Uuid,
    pub location_id:      Uuid,
    pub pass_id:          Uuid,
    pub device_id:        Option<Uuid>,
    pub guard_user_id:    Option<Uuid>,
    pub action:           EntryAction,
    pub denial_reason:    Option<String>,
    pub guard_note:       Option<String>,
    /// When the event occurred on the device (preserved, not server time).
    pub occurred_at:      DateTime<Utc>,
    /// When the server received this event via sync.
    pub server_received_at: DateTime<Utc>,
    /// Device-generated idempotency key. Prevents duplicate sync.
    pub client_event_id:  Uuid,
    pub created_at:       DateTime<Utc>,
}
