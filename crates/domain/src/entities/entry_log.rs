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

/// Structured reason a `DENIED` entry log was denied. Mirrors
/// `app.denial_reason` (migration 027) and `Role`'s `as_str`/`TryFrom`
/// pattern exactly.
///
/// Before migration 027, `denial_reason` was free `TEXT` and the only
/// writer (`VerifyPassUseCase`) was internally inconsistent: sometimes a
/// full human sentence (`DomainError`'s `Display`), sometimes a bare
/// code-like string ("PASS_EXPIRED"). This enum is the single source of
/// truth going forward; free-form guard context belongs in `guard_note`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DenialReason {
    /// Pass `valid_until` has passed, or server-side `PassStatus::Expired`.
    PassExpired,
    /// Pass was explicitly revoked.
    PassRevoked,
    /// Pass reached its `max_uses`.
    PassExhausted,
    /// `now` is before the pass's `valid_from`.
    PassNotYetValid,
    /// QR's signed `org_id` doesn't match the scanning org's id.
    CrossOrgMismatch,
    /// Resident denied an ad-hoc visitor approval request
    /// (`app.ad_hoc_approvals`), relayed back to the gate and recorded by
    /// the guard device via `/api/v1/sync`.
    ResidentDenied,
    /// Guard's own judgment call not covered above; see `guard_note`.
    Other,
}

impl DenialReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            DenialReason::PassExpired      => "PASS_EXPIRED",
            DenialReason::PassRevoked      => "PASS_REVOKED",
            DenialReason::PassExhausted    => "PASS_EXHAUSTED",
            DenialReason::PassNotYetValid  => "PASS_NOT_YET_VALID",
            DenialReason::CrossOrgMismatch => "CROSS_ORG_MISMATCH",
            DenialReason::ResidentDenied   => "RESIDENT_DENIED",
            DenialReason::Other            => "OTHER",
        }
    }
}

impl std::fmt::Display for DenialReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<&str> for DenialReason {
    type Error = crate::DomainError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "PASS_EXPIRED"       => Ok(DenialReason::PassExpired),
            "PASS_REVOKED"       => Ok(DenialReason::PassRevoked),
            "PASS_EXHAUSTED"     => Ok(DenialReason::PassExhausted),
            "PASS_NOT_YET_VALID" => Ok(DenialReason::PassNotYetValid),
            "CROSS_ORG_MISMATCH" => Ok(DenialReason::CrossOrgMismatch),
            "RESIDENT_DENIED"    => Ok(DenialReason::ResidentDenied),
            "OTHER"              => Ok(DenialReason::Other),
            _ => Err(crate::DomainError::ValidationFailed {
                field:   "denial_reason".into(),
                message: format!("unknown denial reason: {s}"),
            }),
        }
    }
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
    pub denial_reason:    Option<DenialReason>,
    pub guard_note:       Option<String>,
    /// When the event occurred on the device (preserved, not server time).
    pub occurred_at:      DateTime<Utc>,
    /// When the server received this event via sync.
    pub server_received_at: DateTime<Utc>,
    /// Device-generated idempotency key. Prevents duplicate sync.
    pub client_event_id:  Uuid,
    pub created_at:       DateTime<Utc>,
}
