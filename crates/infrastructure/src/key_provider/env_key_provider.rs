use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;
use visitorpass_domain::DomainError;
use visitorpass_application::ports::KeyProvider;

/// V1 key provider — reads master key from `MASTER_KEY_HEX` environment variable.
///
/// The 64-character hex string (32 bytes) must be generated with a CSPRNG and
/// stored in a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).
/// It must never be committed to source control.
///
/// Future: Replace this with `KmsKeyProvider` that delegates to a cloud KMS
/// without changing any repository or use case code.
pub struct EnvKeyProvider {
    master_key: [u8; 32],
}

impl EnvKeyProvider {
    /// Load from `MASTER_KEY_HEX` env var at startup.
    /// Panics with a clear error if the key is missing or malformed.
    /// This is intentional — a missing key is a fatal misconfiguration.
    pub fn from_env() -> Self {
        let hex_str = std::env::var("MASTER_KEY_HEX")
            .expect("MASTER_KEY_HEX environment variable is required");

        if hex_str.len() != 64 {
            panic!(
                "MASTER_KEY_HEX must be 64 hex characters (32 bytes). Got {} characters.",
                hex_str.len()
            );
        }

        let mut master_key = [0u8; 32];
        hex::decode_to_slice(&hex_str, &mut master_key)
            .expect("MASTER_KEY_HEX must be valid hexadecimal");

        tracing::info!("EnvKeyProvider initialized: master key loaded from environment");
        Self { master_key }
    }

    fn hkdf_derive(&self, salt: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), DomainError> {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.master_key);
        hk.expand(info, output).map_err(|_| DomainError::CryptoError)
    }
}

impl KeyProvider for EnvKeyProvider {
    fn master_key(&self) -> Result<[u8; 32], DomainError> {
        Ok(self.master_key)
    }

    fn derive_org_enc_key(&self, org_id: Uuid, key_version: i32) -> Result<[u8; 32], DomainError> {
        // salt = org_id bytes (16 bytes)
        // info = "vp-org-key-v1" || key_version as little-endian i32
        let salt = org_id.as_bytes();
        let mut info = b"vp-org-key-v1".to_vec();
        info.extend_from_slice(&key_version.to_le_bytes());

        let mut key = [0u8; 32];
        self.hkdf_derive(salt, &info, &mut key)?;
        Ok(key)
    }

    fn derive_pass_phone_key(&self, pass_id: Uuid) -> Result<[u8; 32], DomainError> {
        // salt = pass_id bytes (16 bytes)
        // info = "vp-pass-phone-v1"
        let salt = pass_id.as_bytes();
        let mut key = [0u8; 32];
        self.hkdf_derive(salt, b"vp-pass-phone-v1", &mut key)?;
        Ok(key)
    }

    fn derive_paseto_key(&self) -> Result<[u8; 64], DomainError> {
        // PASETO v4.public (pasetors::keys::AsymmetricSecretKey<V4>) requires the
        // 64-byte "expanded" Ed25519 secret key format: 32-byte seed || 32-byte
        // public key, where the public key MUST be the one mathematically derived
        // from that seed (RFC 8032 scalar multiplication) -- it is NOT valid to fill
        // both halves with independent HKDF output, because signing uses the seed
        // while verification (crates/api/src/middleware/auth.rs) treats bytes
        // [32..64] as the actual Ed25519 public key. Two unrelated random halves
        // would make every issued token fail verification.
        let mut seed = [0u8; 32];
        self.hkdf_derive(b"paseto-server-key", b"vp-token-v1", &mut seed)?;

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();

        let mut expanded = [0u8; 64];
        expanded[..32].copy_from_slice(&seed);
        expanded[32..].copy_from_slice(&public_key);
        Ok(expanded)
    }

    fn derive_phone_hmac_key(&self) -> Result<[u8; 32], DomainError> {
        let mut key = [0u8; 32];
        self.hkdf_derive(b"phone-hmac-key", b"vp-phone-hmac-v1", &mut key)?;
        Ok(key)
    }
}
