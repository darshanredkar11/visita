use async_trait::async_trait;
use visitorpass_domain::DomainError;

/// Crypto operations needed by use cases.
/// All methods are pure (no DB access, no network).
#[async_trait]
pub trait CryptoService: Send + Sync + 'static {
    /// Hash a password with Argon2id. Returns the full PHC string.
    async fn hash_password(&self, password: &str) -> Result<String, DomainError>;

    /// Verify a password against an Argon2id PHC hash.
    async fn verify_password(&self, password: &str, hash: &str) -> Result<bool, DomainError>;

    /// Generate a new Ed25519 keypair for an org.
    /// Returns (public_key_bytes, encrypted_private_key_bytes, nonce).
    fn generate_org_keypair(
        &self,
        org_id: uuid::Uuid,
        key_version: i32,
    ) -> Result<OrgKeypairMaterial, DomainError>;

    /// Build and sign the QR CBOR payload for a visitor pass.
    fn build_qr_payload(&self, input: &QrBuildInput) -> Result<QrBuildOutput, DomainError>;

    /// Verify a QR payload offline using only the org's public key.
    fn verify_qr_payload(
        &self,
        qr_string: &str,
        public_key_bytes: &[u8],
    ) -> Result<VerifiedQrPayload, DomainError>;

    /// Sign an arbitrary challenge with the server's Ed25519 key.
    fn sign_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>, DomainError>;

    /// Verify a device challenge signature using the device's public key.
    fn verify_device_signature(
        &self,
        public_key_bytes: &[u8],
        challenge: &[u8],
        signature_bytes: &[u8],
    ) -> Result<(), DomainError>;

    /// Compute HMAC-SHA256 of a phone number using the server's phone HMAC key.
    fn hmac_phone(&self, phone_e164: &str) -> Result<String, DomainError>;

    /// Encrypt a phone number for storage (server decrypts to send notifications).
    fn encrypt_phone(&self, pass_id: uuid::Uuid, phone_e164: &str) -> Result<Vec<u8>, DomainError>;

    /// Parse the QR header to retrieve metadata before verification.
    fn parse_qr_header(&self, qr_string: &str) -> Result<QrHeader, DomainError>;
}

/// Metadata parsed from the QR envelope header.
pub struct QrHeader {
    pub key_version: i32,
    pub pass_id:     uuid::Uuid,
}

/// Output of `generate_org_keypair`.
pub struct OrgKeypairMaterial {
    /// Ed25519 public key (32 bytes).
    pub public_key_bytes: Vec<u8>,
    /// ChaCha20-Poly1305 encrypted Ed25519 private key.
    pub encrypted_private_key: Vec<u8>,
    /// 12-byte nonce used for encryption.
    pub nonce: Vec<u8>,
}

/// All inputs needed to build a QR payload.
pub struct QrBuildInput {
    pub pass_id:          uuid::Uuid,
    pub org_id:           uuid::Uuid,
    pub location_id:      uuid::Uuid,
    pub host_user_id:     uuid::Uuid,
    pub visitor_name:     String,
    pub visitor_phone_hmac_prefix: String, // first 8 chars for display
    pub purpose:          String,
    pub vehicle_number:   Option<String>,
    pub permissions:      Vec<String>,
    pub valid_from:       i64,  // Unix timestamp
    pub valid_until:      i64,  // Unix timestamp
    pub key_version:      i32,
    /// Ed25519 private key bytes (decrypted, in memory briefly).
    /// Zeroed after use.
    pub signing_private_key: Vec<u8>,
    /// Nonce for decrypting the private key (ChaCha20-Poly1305).
    pub key_derivation_nonce: Vec<u8>,
    /// Encrypted phone for storage in DB.
    pub encrypted_phone:  Option<Vec<u8>>,
}

/// Output of `build_qr_payload`.
pub struct QrBuildOutput {
    /// Complete QR string: `vp1.<base64url_cbor>`
    pub qr_string:     String,
    /// 12-byte nonce used for phone encryption (stored in DB).
    pub qr_nonce:      Vec<u8>,
}

/// The decoded, verified contents of a QR scan.
pub struct VerifiedQrPayload {
    pub pass_id:       uuid::Uuid,
    pub org_id:        uuid::Uuid,
    pub location_id:   uuid::Uuid,
    pub visitor_name:  String,
    pub purpose:       String,
    pub vehicle_number: Option<String>,
    pub permissions:   Vec<String>,
    pub valid_from:    i64,
    pub valid_until:   i64,
    pub key_version:   i32,
}
