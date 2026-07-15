use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A stored org key version. Both signing and encryption key material.
/// Historical versions are never deleted — needed to verify old passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgKey {
    pub id:                      Uuid,
    pub org_id:                  Uuid,
    pub version:                 i32,
    /// Ed25519 public key (32 bytes). Safe to distribute to guard devices.
    pub signing_public_key:      Vec<u8>,
    /// Ed25519 private key, ChaCha20-Poly1305 encrypted.
    /// Decrypted using: HKDF(master_key, org_id || version, "vp-org-key-v1")
    pub signing_private_key_enc: Vec<u8>,
    /// 12-byte nonce used for the private key encryption.
    pub key_derivation_nonce:    Vec<u8>,
    pub enc_algorithm:           String,
    pub activated_at:            DateTime<Utc>,
    pub retired_at:              Option<DateTime<Utc>>,
    pub rotated_by:              Option<Uuid>,
    pub created_at:              DateTime<Utc>,
}

impl OrgKey {
    pub fn is_active(&self) -> bool {
        self.retired_at.is_none()
    }
}
