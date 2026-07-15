use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeviceType {
    ResidentPhone,
    GuardTablet,
    GuardKiosk,
}

impl DeviceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceType::ResidentPhone => "RESIDENT_PHONE",
            DeviceType::GuardTablet   => "GUARD_TABLET",
            DeviceType::GuardKiosk    => "GUARD_KIOSK",
        }
    }

    pub fn requires_location(&self) -> bool {
        matches!(self, DeviceType::GuardTablet | DeviceType::GuardKiosk)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeviceStatus { Active, Revoked }

/// A registered device with a cryptographic identity.
/// Private key never leaves the device (Android Keystore / iOS Secure Enclave).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id:                Uuid,
    pub org_id:            Uuid,
    /// Assigned gate for GUARD_TABLET / GUARD_KIOSK. None for resident phones.
    pub location_id:       Option<Uuid>,
    /// The human who owns this device. None for shared kiosks.
    pub owner_user_id:     Option<Uuid>,
    pub device_type:       DeviceType,
    pub name:              String,
    /// Ed25519 public key (32 bytes). Globally unique across all orgs.
    pub public_key:        Vec<u8>,
    pub platform:          Option<String>,
    pub os_version:        Option<String>,
    pub app_version:       Option<String>,
    pub push_token:        Option<String>,
    pub last_seen_at:      Option<DateTime<Utc>>,
    pub status:            DeviceStatus,
    pub revoked_at:        Option<DateTime<Utc>>,
    pub revoked_by:        Option<Uuid>,
    pub revocation_reason: Option<String>,
    pub created_at:        DateTime<Utc>,
    pub updated_at:        DateTime<Utc>,
}

impl Device {
    pub fn is_active(&self) -> bool {
        self.status == DeviceStatus::Active
    }

    pub fn assert_active(&self) -> Result<(), crate::DomainError> {
        if self.status == DeviceStatus::Revoked {
            Err(crate::DomainError::DeviceRevoked)
        } else {
            Ok(())
        }
    }
}
