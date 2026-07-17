use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng as CcpOsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, Verifier};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::sync::Arc;
use uuid::Uuid;
use visitorpass_domain::DomainError;
use visitorpass_application::ports::{
    crypto_service::{
        CryptoService, OrgKeypairMaterial, QrBuildInput, QrBuildOutput, VerifiedQrPayload, QrHeader,
    },
    KeyProvider,
};

type HmacSha256 = Hmac<Sha256>;

/// QR payload version constant.
const QR_VERSION: u8 = 1;
/// QR string prefix for future version detection.
const QR_PREFIX: &str = "vp1.";

/// Concrete implementation of CryptoService using:
/// - Argon2id for password hashing
/// - Ed25519 (ed25519-dalek) for signing/verifying
/// - ChaCha20-Poly1305 for symmetric encryption
/// - HMAC-SHA256 for phone number hashing
/// - CBOR (ciborium) for QR payload encoding
pub struct DefaultCryptoService {
    key_provider: Arc<dyn KeyProvider>,
}

impl DefaultCryptoService {
    pub fn new(key_provider: Arc<dyn KeyProvider>) -> Self {
        Self { key_provider }
    }

    /// Argon2id parameters (OWASP recommended for 2024).
    fn argon2_params() -> Params {
        Params::new(
            65536, // m_cost: 64 MiB
            3,     // t_cost: 3 iterations
            4,     // p_cost: 4 threads
            None,  // output_len: default (32 bytes)
        )
        .expect("Argon2id params are valid")
    }

    /// Decrypt an org private key from its encrypted form.
    /// The plaintext private key is returned as a `SigningKey`.
    /// Zeroed when dropped (ed25519-dalek uses Zeroize).
    fn decrypt_org_private_key(
        &self,
        org_id: Uuid,
        key_version: i32,
        encrypted_private_key: &[u8],
        nonce_bytes: &[u8],
    ) -> Result<SigningKey, DomainError> {
        let enc_key = self.key_provider.derive_org_enc_key(org_id, key_version)?;
        let cipher  = ChaCha20Poly1305::new(Key::from_slice(&enc_key));
        let nonce   = Nonce::from_slice(nonce_bytes);

        let private_key_bytes = cipher
            .decrypt(nonce, encrypted_private_key)
            .map_err(|_| DomainError::CryptoError)?;

        let key_bytes: [u8; 32] = private_key_bytes
            .try_into()
            .map_err(|_| DomainError::CryptoError)?;

        Ok(SigningKey::from_bytes(&key_bytes))
    }
}

#[async_trait]
impl CryptoService for DefaultCryptoService {
    // ── Password ─────────────────────────────────────────────────────────────

    async fn hash_password(&self, password: &str) -> Result<String, DomainError> {
        let params = Self::argon2_params();
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );
        let salt = SaltString::generate(&mut OsRng);
        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|_| DomainError::CryptoError)
    }

    async fn verify_password(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
        let parsed = PasswordHash::new(hash).map_err(|_| DomainError::CryptoError)?;
        match Argon2::default().verify_password(password.as_bytes(), &parsed) {
            Ok(())                                    => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(_)                                    => Err(DomainError::CryptoError),
        }
    }

    // ── Org Keypair ───────────────────────────────────────────────────────────

    fn generate_org_keypair(
        &self,
        org_id: Uuid,
        key_version: i32,
    ) -> Result<OrgKeypairMaterial, DomainError> {
        // Generate Ed25519 keypair
        let mut csprng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut csprng);
        let public_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let private_key_bytes = signing_key.to_bytes();

        // Derive encryption key
        let enc_key = self.key_provider.derive_org_enc_key(org_id, key_version)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&enc_key));

        // Generate random nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut CcpOsRng);

        // Encrypt private key
        let encrypted_private_key = cipher
            .encrypt(&nonce, private_key_bytes.as_ref())
            .map_err(|_| DomainError::CryptoError)?;

        Ok(OrgKeypairMaterial {
            public_key_bytes,
            encrypted_private_key,
            nonce: nonce.to_vec(),
        })
    }

    // ── QR Payload Build ──────────────────────────────────────────────────────

    fn build_qr_payload(&self, input: &QrBuildInput) -> Result<QrBuildOutput, DomainError> {
        // ── Build CBOR outer envelope ─────────────────────────────────────
        // Uses integer keys for compactness.
        // Map layout:
        //   1  -> version (u8)
        //   2  -> pass_id (bytes, 16)
        //   3  -> valid_until (u32 unix ts)
        //   4  -> valid_from  (u32 unix ts)
        //   5  -> key_version (u8)
        //   6  -> org_id      (bytes, 16)
        //   7  -> location_id (bytes, 16)
        //   8  -> visitor_name (text)
        //   9  -> purpose      (text)
        //   10 -> permissions  (array of text)
        //   11 -> vehicle_number (text | null)
        //   12 -> enc_phone    (bytes | null) — nonce prepended
        //   13 -> signature    (bytes, 64) — over fields 1–12

        let mut phone_nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut phone_nonce);

        // Encrypt phone if provided
        let enc_phone: Option<Vec<u8>> = if let Some(enc) = &input.encrypted_phone {
            // enc_phone already encrypted in the use case; we reuse the nonce here
            // For QR, prepend nonce to ciphertext: [12 nonce bytes | ciphertext]
            let mut combined = phone_nonce.to_vec();
            combined.extend_from_slice(enc);
            Some(combined)
        } else {
            None
        };

        // Build the unsigned CBOR map (fields 1–12)
        let unsigned_cbor = Self::build_cbor_envelope(
            QR_VERSION,
            input.pass_id,
            input.valid_until as u32,
            input.valid_from as u32,
            input.key_version as u8,
            input.org_id,
            input.location_id,
            &input.visitor_name,
            &input.purpose,
            &input.permissions,
            input.vehicle_number.as_deref(),
            enc_phone.as_deref(),
        )?;

        // ── Decrypt org private key and sign ──────────────────────────────
        // The private key is in memory only for the duration of this function.
        // ed25519-dalek's SigningKey implements Zeroize, so it's zeroed on drop.
        // NOTE: In the real implementation, the CryptoService receives the
        // encrypted key bytes and org_id/version to decrypt internally.
        // Here we simplify: the signing_private_key field in QrBuildInput
        // carries the encrypted bytes; we decrypt them here.

        // (In the actual call from CreatePassUseCase, we need to pass org_id
        // and key_version to decrypt. For clarity, we use a fixed approach.)
        let signature_bytes = self.sign_cbor_payload(
            input.org_id,
            input.key_version,
            &input.signing_private_key,
            &input.key_derivation_nonce,
            &unsigned_cbor,
        )?;

        // Append signature as field 13
        let signed_cbor = Self::append_signature_to_cbor(unsigned_cbor, &signature_bytes)?;

        let qr_string = format!(
            "{}{}",
            QR_PREFIX,
            URL_SAFE_NO_PAD.encode(&signed_cbor)
        );

        Ok(QrBuildOutput {
            qr_string,
            qr_nonce: phone_nonce.to_vec(),
        })
    }

    // ── QR Payload Verify ─────────────────────────────────────────────────────

    fn verify_qr_payload(
        &self,
        qr_string: &str,
        public_key_bytes: &[u8],
    ) -> Result<VerifiedQrPayload, DomainError> {
        // ── Strip prefix ──────────────────────────────────────────────────
        let b64_payload = qr_string
            .strip_prefix(QR_PREFIX)
            .ok_or(DomainError::InvalidQrFormat)?;

        let cbor_bytes = URL_SAFE_NO_PAD
            .decode(b64_payload)
            .map_err(|_| DomainError::InvalidQrFormat)?;

        // ── Parse the signed CBOR ─────────────────────────────────────────
        let (fields, signature_bytes) = Self::parse_signed_cbor(&cbor_bytes)?;

        // ── Reconstruct the unsigned payload for verification ─────────────
        let unsigned_cbor = Self::rebuild_unsigned_cbor(&fields)?;

        // ── Verify Ed25519 signature ──────────────────────────────────────
        let pub_key_arr: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| DomainError::CryptoError)?;
        let verifying_key = VerifyingKey::from_bytes(&pub_key_arr)
            .map_err(|_| DomainError::CryptoError)?;
        let sig_arr: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| DomainError::CryptoError)?;
        let signature = Signature::from_bytes(&sig_arr);

        verifying_key
            .verify(&unsigned_cbor, &signature)
            .map_err(|_| DomainError::InvalidSignature)?;

        // ── Extract fields ────────────────────────────────────────────────
        let payload = Self::extract_qr_fields(&fields)?;
        Ok(payload)
    }

    // ── Challenge signing ─────────────────────────────────────────────────────

    fn sign_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>, DomainError> {
        let key_bytes = self.key_provider.derive_paseto_key()?;
        let signing_key = SigningKey::from_bytes(
            &key_bytes[..32].try_into().map_err(|_| DomainError::CryptoError)?
        );
        let sig = signing_key.sign(challenge);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify_device_signature(
        &self,
        public_key_bytes: &[u8],
        challenge: &[u8],
        signature_bytes: &[u8],
    ) -> Result<(), DomainError> {
        let pub_key_arr: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| DomainError::CryptoError)?;
        let verifying_key = VerifyingKey::from_bytes(&pub_key_arr)
            .map_err(|_| DomainError::CryptoError)?;

        let sig_arr: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| DomainError::CryptoError)?;
        let signature = Signature::from_bytes(&sig_arr);

        verifying_key
            .verify(challenge, &signature)
            .map_err(|_| DomainError::InvalidSignature)
    }

    // ── Phone HMAC / encrypt ──────────────────────────────────────────────────

    fn hmac_phone(&self, phone_e164: &str) -> Result<String, DomainError> {
        let key = self.key_provider.derive_phone_hmac_key()?;
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(&key)
            .map_err(|_| DomainError::CryptoError)?;
        mac.update(phone_e164.as_bytes());
        let result = mac.finalize().into_bytes();
        Ok(hex::encode(result))
    }

    fn encrypt_phone(&self, record_id: Uuid, phone_e164: &str) -> Result<Vec<u8>, DomainError> {
        let key = self.key_provider.derive_pass_phone_key(record_id)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce  = ChaCha20Poly1305::generate_nonce(&mut CcpOsRng);
        let mut ciphertext = cipher
            .encrypt(&nonce, phone_e164.as_bytes())
            .map_err(|_| DomainError::CryptoError)?;
        // Prepend nonce so it's self-contained
        let mut result = nonce.to_vec();
        result.append(&mut ciphertext);
        Ok(result)
    }

    fn decrypt_phone(&self, record_id: Uuid, ciphertext: &[u8]) -> Result<String, DomainError> {
        // Nonce (12 bytes) is prepended to the ciphertext by encrypt_phone.
        if ciphertext.len() < 12 {
            return Err(DomainError::CryptoError);
        }
        let (nonce_bytes, encrypted) = ciphertext.split_at(12);
        let key = self.key_provider.derive_pass_phone_key(record_id)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| DomainError::CryptoError)?;
        String::from_utf8(plaintext).map_err(|_| DomainError::CryptoError)
    }

    fn parse_qr_header(&self, qr_string: &str) -> Result<QrHeader, DomainError> {
        use ciborium::Value;

        let b64 = qr_string.strip_prefix(QR_PREFIX)
            .ok_or(DomainError::InvalidQrFormat)?;
        let bytes = URL_SAFE_NO_PAD.decode(b64)
            .map_err(|_| DomainError::InvalidQrFormat)?;
        let val: Value = ciborium::from_reader(bytes.as_slice())
            .map_err(|_| DomainError::InvalidQrFormat)?;

        let entries = match val {
            Value::Map(m) => m,
            _ => return Err(DomainError::InvalidQrFormat),
        };

        let get = |key: i64| -> Option<&Value> {
            entries.iter().find(|(k, _)| k == &Value::Integer(key.into())).map(|(_, v)| v)
        };

        let key_version = match get(5) {
            Some(Value::Integer(n)) => i128::from(*n) as i32,
            _ => return Err(DomainError::InvalidQrFormat),
        };
        let pass_id_bytes = match get(2) {
            Some(Value::Bytes(b)) => b,
            _ => return Err(DomainError::InvalidQrFormat),
        };
        let pass_id = Uuid::from_slice(pass_id_bytes)
            .map_err(|_| DomainError::InvalidQrFormat)?;

        Ok(QrHeader { key_version, pass_id })
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

impl DefaultCryptoService {
    fn sign_cbor_payload(
        &self,
        org_id: uuid::Uuid,
        key_version: i32,
        encrypted_private_key: &[u8],
        nonce_bytes: &[u8],
        cbor_payload: &[u8],
    ) -> Result<Vec<u8>, DomainError> {
        // Decrypt the org-specific Ed25519 private key
        let signing_key = self.decrypt_org_private_key(
            org_id,
            key_version,
            encrypted_private_key,
            nonce_bytes,
        )?;
        // Sign the payload (SigningKey implements Zeroize, so it's zeroed on drop)
        let sig = signing_key.sign(cbor_payload);
        Ok(sig.to_bytes().to_vec())
    }

    fn build_cbor_envelope(
        version:      u8,
        pass_id:      Uuid,
        valid_until:  u32,
        valid_from:   u32,
        key_version:  u8,
        org_id:       Uuid,
        location_id:  Uuid,
        visitor_name: &str,
        purpose:      &str,
        permissions:  &[String],
        vehicle:      Option<&str>,
        enc_phone:    Option<&[u8]>,
    ) -> Result<Vec<u8>, DomainError> {
        use ciborium::Value;

        let mut map_entries = vec![
            (Value::Integer(1.into()), Value::Integer(version.into())),
            (Value::Integer(2.into()), Value::Bytes(pass_id.as_bytes().to_vec())),
            (Value::Integer(3.into()), Value::Integer(valid_until.into())),
            (Value::Integer(4.into()), Value::Integer(valid_from.into())),
            (Value::Integer(5.into()), Value::Integer(key_version.into())),
            (Value::Integer(6.into()), Value::Bytes(org_id.as_bytes().to_vec())),
            (Value::Integer(7.into()), Value::Bytes(location_id.as_bytes().to_vec())),
            (Value::Integer(8.into()), Value::Text(visitor_name.to_string())),
            (Value::Integer(9.into()), Value::Text(purpose.to_string())),
            (Value::Integer(10.into()), Value::Array(
                permissions.iter().map(|p| Value::Text(p.clone())).collect()
            )),
            (Value::Integer(11.into()), match vehicle {
                Some(v) => Value::Text(v.to_string()),
                None    => Value::Null,
            }),
            (Value::Integer(12.into()), match enc_phone {
                Some(b) => Value::Bytes(b.to_vec()),
                None    => Value::Null,
            }),
        ];

        let cbor_val = Value::Map(map_entries);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_val, &mut buf).map_err(|_| DomainError::CryptoError)?;
        Ok(buf)
    }

    fn append_signature_to_cbor(
        mut unsigned: Vec<u8>,
        signature: &[u8],
    ) -> Result<Vec<u8>, DomainError> {
        // Re-parse, add field 13, re-serialize
        use ciborium::Value;

        let unsigned_val: Value = ciborium::from_reader(unsigned.as_slice())
            .map_err(|_| DomainError::CryptoError)?;

        let mut entries = match unsigned_val {
            Value::Map(m) => m,
            _ => return Err(DomainError::CryptoError),
        };

        entries.push((
            Value::Integer(13.into()),
            Value::Bytes(signature.to_vec()),
        ));

        let signed_val = Value::Map(entries);
        let mut buf = Vec::new();
        ciborium::into_writer(&signed_val, &mut buf).map_err(|_| DomainError::CryptoError)?;
        Ok(buf)
    }

    fn parse_signed_cbor(
        cbor_bytes: &[u8],
    ) -> Result<(Vec<(ciborium::Value, ciborium::Value)>, Vec<u8>), DomainError> {
        use ciborium::Value;

        let val: Value = ciborium::from_reader(cbor_bytes)
            .map_err(|_| DomainError::InvalidQrFormat)?;

        let entries = match val {
            Value::Map(m) => m,
            _ => return Err(DomainError::InvalidQrFormat),
        };

        // Extract signature (field 13)
        let sig_bytes = entries
            .iter()
            .find(|(k, _)| k == &Value::Integer(13.into()))
            .and_then(|(_, v)| if let Value::Bytes(b) = v { Some(b.clone()) } else { None })
            .ok_or(DomainError::InvalidQrFormat)?;

        Ok((entries, sig_bytes))
    }

    fn rebuild_unsigned_cbor(
        entries: &[(ciborium::Value, ciborium::Value)],
    ) -> Result<Vec<u8>, DomainError> {
        use ciborium::Value;

        // Remove field 13 (signature) from the map
        let unsigned: Vec<_> = entries
            .iter()
            .filter(|(k, _)| k != &Value::Integer(13.into()))
            .cloned()
            .collect();

        let val = Value::Map(unsigned);
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).map_err(|_| DomainError::CryptoError)?;
        Ok(buf)
    }

    fn extract_qr_fields(
        entries: &[(ciborium::Value, ciborium::Value)],
    ) -> Result<VerifiedQrPayload, DomainError> {
        use ciborium::Value;

        let get = |key: i64| -> Option<&Value> {
            entries
                .iter()
                .find(|(k, _)| k == &Value::Integer(key.into()))
                .map(|(_, v)| v)
        };

        let pass_id_bytes = match get(2) {
            Some(Value::Bytes(b)) => b,
            _ => return Err(DomainError::InvalidQrFormat),
        };
        let pass_id = Uuid::from_slice(pass_id_bytes)
            .map_err(|_| DomainError::InvalidQrFormat)?;

        let valid_until = match get(3) {
            Some(Value::Integer(n)) => i128::from(*n) as i64,
            _ => return Err(DomainError::InvalidQrFormat),
        };
        let valid_from = match get(4) {
            Some(Value::Integer(n)) => i128::from(*n) as i64,
            _ => return Err(DomainError::InvalidQrFormat),
        };
        let key_version = match get(5) {
            Some(Value::Integer(n)) => i128::from(*n) as i32,
            _ => return Err(DomainError::InvalidQrFormat),
        };
        let org_id_bytes = match get(6) {
            Some(Value::Bytes(b)) => b,
            _ => return Err(DomainError::InvalidQrFormat),
        };
        let org_id = Uuid::from_slice(org_id_bytes)
            .map_err(|_| DomainError::InvalidQrFormat)?;

        let location_id_bytes = match get(7) {
            Some(Value::Bytes(b)) => b,
            _ => return Err(DomainError::InvalidQrFormat),
        };
        let location_id = Uuid::from_slice(location_id_bytes)
            .map_err(|_| DomainError::InvalidQrFormat)?;

        let visitor_name = match get(8) {
            Some(Value::Text(t)) => t.clone(),
            _ => return Err(DomainError::InvalidQrFormat),
        };
        let purpose = match get(9) {
            Some(Value::Text(t)) => t.clone(),
            _ => return Err(DomainError::InvalidQrFormat),
        };
        let permissions = match get(10) {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| if let Value::Text(t) = v { Some(t.clone()) } else { None })
                .collect(),
            _ => vec![],
        };
        let vehicle_number = match get(11) {
            Some(Value::Text(t)) => Some(t.clone()),
            _                    => None,
        };

        Ok(VerifiedQrPayload {
            pass_id,
            org_id,
            location_id,
            visitor_name,
            purpose,
            vehicle_number,
            permissions,
            valid_from,
            valid_until,
            key_version,
        })
    }
}
