use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::value_objects::PassNumber;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PassStatus {
    Active,
    Used,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Permission {
    Entry,
    Exit,
    Vehicle,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::Entry   => "ENTRY",
            Permission::Exit    => "EXIT",
            Permission::Vehicle => "VEHICLE",
        }
    }
}

/// Core entity. A cryptographically sealed visitor pass.
///
/// Once created, the `qr_payload` field is immutable and self-contained.
/// The guard app only needs the org's public key to verify it offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisitorPass {
    pub id:                  Uuid,
    pub org_id:              Uuid,
    pub location_id:         Uuid,
    pub created_by:          Uuid,

    /// Short human-readable code for voice confirmation: VP-XXXXXXXX
    pub pass_number:         PassNumber,

    // ── Visitor info (server-side representation) ─────────────────────────
    pub visitor_name:        String,
    /// HMAC-SHA256 of E.164 phone. Used for lookup/dedup without exposing PII.
    pub visitor_phone_hmac:  String,
    /// ChaCha20-Poly1305 encrypted phone bytes. Decryptable by server only.
    pub visitor_phone_enc:   Option<Vec<u8>>,

    // ── Pass details ──────────────────────────────────────────────────────
    pub purpose:             String,
    pub vehicle_number:      Option<String>,
    pub permissions:         Vec<Permission>,
    pub valid_from:          DateTime<Utc>,
    pub valid_until:         DateTime<Utc>,
    pub max_uses:            i32,   // -1 = unlimited
    pub use_count:           i32,

    // ── Cryptographic material ────────────────────────────────────────────
    /// Complete QR string: `vp1.<base64url(cbor_payload)>`
    /// Mobile renders this directly. Never needs to be re-computed.
    pub qr_payload:          String,
    /// 12-byte nonce used to encrypt the phone field within the QR payload.
    pub qr_nonce:            Vec<u8>,
    /// Which org key version signed this pass.
    pub key_version:         i32,

    // ── Status ────────────────────────────────────────────────────────────
    pub status:              PassStatus,
    pub revoked_at:          Option<DateTime<Utc>>,
    pub revoked_by:          Option<Uuid>,
    pub revocation_reason:   Option<String>,

    pub sync_seq:            Option<i64>,
    pub created_at:          DateTime<Utc>,
    pub updated_at:          DateTime<Utc>,
}

impl VisitorPass {
    /// Maximum allowed pass duration: 30 days.
    pub const MAX_VALIDITY_SECONDS: i64 = 30 * 24 * 3600;

    /// Check if this pass is currently valid at the given time.
    pub fn check_valid(&self, now: DateTime<Utc>) -> Result<(), crate::DomainError> {
        match self.status {
            PassStatus::Revoked => {
                return Err(crate::DomainError::PassRevoked {
                    reason: self.revocation_reason.clone(),
                });
            }
            PassStatus::Expired => return Err(crate::DomainError::PassExpired),
            PassStatus::Used    => return Err(crate::DomainError::PassExhausted),
            PassStatus::Active  => {}
        }

        if now < self.valid_from {
            return Err(crate::DomainError::PassNotYetValid {
                valid_from: self.valid_from,
            });
        }

        if now > self.valid_until {
            return Err(crate::DomainError::PassExpired);
        }

        if self.max_uses != -1 && self.use_count >= self.max_uses {
            return Err(crate::DomainError::PassExhausted);
        }

        Ok(())
    }
}
