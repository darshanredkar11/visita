use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;
use visitorpass_domain::{
    entities::{EntryAction, VisitorPass},
    value_objects::OrgContext,
    DomainError,
};

use crate::ports::{
    crypto_service::{CryptoService, VerifiedQrPayload},
    repositories::{AuditEventInput, AuditRepository, OrgRepository, PassRepository},
};

pub struct VerifyPassInput {
    pub qr_payload:  String,
    pub location_id: Uuid,
    pub action:      String,  // "ENTRY" or "EXIT"
}

pub struct VerifyPassOutput {
    pub valid:          bool,
    pub pass_id:        Uuid,
    pub pass_number:    String,
    pub visitor_name:   String,
    pub purpose:        String,
    pub vehicle_number: Option<String>,
    pub permissions:    Vec<String>,
    pub valid_from:     chrono::DateTime<Utc>,
    pub valid_until:    chrono::DateTime<Utc>,
    pub status:         String,
    pub denial_reason:  Option<String>,
}

/// Server-side QR verification.
/// Primary path: offline verification on the guard device (no server call).
/// This use case is the *secondary* path for connected guard kiosks that want
/// real-time revocation checking in addition to offline signature verification.
pub struct VerifyPassUseCase {
    passes: Arc<dyn PassRepository>,
    orgs:   Arc<dyn OrgRepository>,
    crypto: Arc<dyn CryptoService>,
    audit:  Arc<dyn AuditRepository>,
}

impl VerifyPassUseCase {
    pub fn new(
        passes: Arc<dyn PassRepository>,
        orgs:   Arc<dyn OrgRepository>,
        crypto: Arc<dyn CryptoService>,
        audit:  Arc<dyn AuditRepository>,
    ) -> Self {
        Self { passes, orgs, crypto, audit }
    }

    pub async fn execute(
        &self,
        ctx: &OrgContext,
        input: VerifyPassInput,
    ) -> Result<VerifyPassOutput, DomainError> {
        let now = Utc::now();

        // ── 1. Parse and check QR structure ───────────────────────────────
        // We don't yet know the key_version, so we do a structural parse first.
        // The crypto service parses the CBOR envelope and returns the key_version.
        // Then we fetch the correct public key and verify the signature.
        let unverified = self.crypto.parse_qr_header(&input.qr_payload)
            .map_err(|_| DomainError::InvalidQrFormat)?;

        // ── 2. Fetch the correct org public key by version ─────────────────
        let org_key = self.orgs
            .find_key_version(ctx.org_id, unverified.key_version)
            .await
            .map_err(|_| DomainError::UnknownKeyVersion(unverified.key_version))?;

        // ── 3. Verify Ed25519 signature (cryptographic proof of authenticity) ──
        let verified: VerifiedQrPayload = self.crypto.verify_qr_payload(
            &input.qr_payload,
            &org_key.signing_public_key,
        )?;

        // ── 4. Check org matches what's claimed in QR ──────────────────────
        if verified.org_id != ctx.org_id {
            return Ok(VerifyPassOutput {
                valid:          false,
                pass_id:        verified.pass_id,
                pass_number:    String::new(),
                visitor_name:   verified.visitor_name,
                purpose:        verified.purpose,
                vehicle_number: verified.vehicle_number,
                permissions:    verified.permissions,
                valid_from:     chrono::DateTime::from_timestamp(verified.valid_from, 0)
                    .unwrap_or_default(),
                valid_until:    chrono::DateTime::from_timestamp(verified.valid_until, 0)
                    .unwrap_or_default(),
                status:         "DENIED".into(),
                denial_reason:  Some("Pass issued by a different organization".into()),
            });
        }

        // ── 5. Check time validity ─────────────────────────────────────────
        let valid_from  = chrono::DateTime::from_timestamp(verified.valid_from, 0)
            .unwrap_or_default();
        let valid_until = chrono::DateTime::from_timestamp(verified.valid_until, 0)
            .unwrap_or_default();

        if now < valid_from || now > valid_until {
            return Ok(self.denial_output(verified, "PASS_EXPIRED", valid_from, valid_until));
        }

        // ── 6. Check server-side pass status (revocation, use count) ───────
        let pass = match self.passes.find_by_id(ctx, verified.pass_id).await {
            Ok(p)  => p,
            Err(DomainError::PassNotFound(_)) => {
                // Pass not yet synced to server. Trust the cryptographic proof.
                // This is the legitimate offline-created pass scenario.
                tracing::warn!(
                    pass_id = %verified.pass_id,
                    org_id = %ctx.org_id,
                    "Pass not found server-side; accepting on crypto proof alone"
                );
                return Ok(self.build_unsynced_output(verified, valid_from, valid_until));
            }
            Err(e) => return Err(e),
        };

        // ── 7. Check server-side pass validity ─────────────────────────────
        if let Err(e) = pass.check_valid(now) {
            let reason = format!("{}", e);
            let _ = self.audit.append(AuditEventInput {
                org_id:             ctx.org_id,
                event_type:         "ENTRY_DENIED".into(),
                actor_user_id:      ctx.device_id.and(None).or(Some(ctx.user_id)),
                actor_device_id:    ctx.device_id,
                target_entity_type: Some("visitor_pass".into()),
                target_entity_id:   Some(pass.id),
                metadata:           serde_json::json!({ "denial_reason": reason }),
                ip_address:         None,
            }).await;
            return Ok(VerifyPassOutput {
                valid:          false,
                pass_id:        pass.id,
                pass_number:    pass.pass_number.to_string(),
                visitor_name:   pass.visitor_name.clone(),
                purpose:        pass.purpose.clone(),
                vehicle_number: pass.vehicle_number.clone(),
                permissions:    pass.permissions.iter().map(|p| p.as_str().to_string()).collect(),
                valid_from,
                valid_until,
                status:         "DENIED".into(),
                denial_reason:  Some(reason),
            });
        }

        // ── 8. All checks passed ───────────────────────────────────────────
        Ok(VerifyPassOutput {
            valid:          true,
            pass_id:        pass.id,
            pass_number:    pass.pass_number.to_string(),
            visitor_name:   pass.visitor_name.clone(),
            purpose:        pass.purpose.clone(),
            vehicle_number: pass.vehicle_number.clone(),
            permissions:    pass.permissions.iter().map(|p| p.as_str().to_string()).collect(),
            valid_from,
            valid_until,
            status:         "ACTIVE".into(),
            denial_reason:  None,
        })
    }

    fn denial_output(
        &self,
        verified: VerifiedQrPayload,
        reason: &str,
        valid_from: chrono::DateTime<Utc>,
        valid_until: chrono::DateTime<Utc>,
    ) -> VerifyPassOutput {
        VerifyPassOutput {
            valid:          false,
            pass_id:        verified.pass_id,
            pass_number:    String::new(),
            visitor_name:   verified.visitor_name,
            purpose:        verified.purpose,
            vehicle_number: verified.vehicle_number,
            permissions:    verified.permissions,
            valid_from,
            valid_until,
            status:         "DENIED".into(),
            denial_reason:  Some(reason.into()),
        }
    }

    fn build_unsynced_output(
        &self,
        verified: VerifiedQrPayload,
        valid_from: chrono::DateTime<Utc>,
        valid_until: chrono::DateTime<Utc>,
    ) -> VerifyPassOutput {
        VerifyPassOutput {
            valid:          true,
            pass_id:        verified.pass_id,
            pass_number:    String::new(),
            visitor_name:   verified.visitor_name,
            purpose:        verified.purpose,
            vehicle_number: verified.vehicle_number,
            permissions:    verified.permissions,
            valid_from,
            valid_until,
            status:         "ACTIVE".into(),
            denial_reason:  None,
        }
    }
}
