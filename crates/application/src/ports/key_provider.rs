use async_trait::async_trait;
use uuid::Uuid;
use visitorpass_domain::DomainError;

/// Abstraction over the master key source.
///
/// V1: `EnvKeyProvider` reads `MASTER_KEY_HEX` from environment.
/// Future: `KmsKeyProvider` wraps AWS KMS / GCP KMS / HashiCorp Vault.
///
/// The interface is stable regardless of the backing implementation.
/// Swapping providers requires no changes to use cases or repositories.
pub trait KeyProvider: Send + Sync + 'static {
    /// Returns the raw 32-byte master key.
    /// The master key is used to derive per-org, per-version encryption keys.
    fn master_key(&self) -> Result<[u8; 32], DomainError>;

    /// Derives a 32-byte org-specific encryption key.
    ///
    /// Derivation: `HKDF-SHA256(master_key, salt=org_id_bytes, info="vp-org-key-v1" || key_version_le_bytes)`
    ///
    /// Used to encrypt and decrypt org signing private keys.
    fn derive_org_enc_key(&self, org_id: Uuid, key_version: i32) -> Result<[u8; 32], DomainError>;

    /// Derives a 32-byte pass-specific symmetric key.
    ///
    /// Derivation: `HKDF-SHA256(master_key, salt=pass_id_bytes, info="vp-pass-phone-v1")`
    ///
    /// Used to encrypt the visitor's phone number in the QR payload.
    fn derive_pass_phone_key(&self, pass_id: Uuid) -> Result<[u8; 32], DomainError>;

    /// Derives the PASETO v4 server signing key.
    ///
    /// Derivation: `HKDF-SHA256(master_key, salt=b"paseto-server-key", info="vp-token-v1")`
    fn derive_paseto_key(&self) -> Result<[u8; 64], DomainError>;

    /// Derives a 32-byte key for HMAC-SHA256 of phone numbers.
    ///
    /// Derivation: `HKDF-SHA256(master_key, salt=b"phone-hmac-key", info="vp-phone-hmac-v1")`
    fn derive_phone_hmac_key(&self) -> Result<[u8; 32], DomainError>;
}
