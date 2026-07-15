use std::sync::Arc;

use chrono::{Duration, Utc};
use uuid::Uuid;
use visitorpass_domain::{
    entities::VisitorPass,
    value_objects::{OrgContext, PassNumber},
    DomainError,
};

use crate::ports::{
    crypto_service::{CryptoService, QrBuildInput},
    repositories::{AuditEventInput, AuditRepository, OrgRepository, PassRepository},
};

/// Input for pass creation.
pub struct CreatePassInput {
    pub location_id:    Uuid,
    pub visitor_name:   String,
    pub visitor_phone:  String,  // E.164; hashed + encrypted; not stored plaintext
    pub purpose:        String,
    pub vehicle_number: Option<String>,
    pub permissions:    Vec<String>,
    pub valid_from:     chrono::DateTime<Utc>,
    pub valid_until:    chrono::DateTime<Utc>,
    pub max_uses:       i32,
}

pub struct CreatePassOutput {
    pub pass:      VisitorPass,
    pub share_url: String,
}

pub struct CreatePassUseCase {
    passes:    Arc<dyn PassRepository>,
    orgs:      Arc<dyn OrgRepository>,
    crypto:    Arc<dyn CryptoService>,
    audit:     Arc<dyn AuditRepository>,
    base_url:  String,
}

impl CreatePassUseCase {
    pub fn new(
        passes:   Arc<dyn PassRepository>,
        orgs:     Arc<dyn OrgRepository>,
        crypto:   Arc<dyn CryptoService>,
        audit:    Arc<dyn AuditRepository>,
        base_url: String,
    ) -> Self {
        Self { passes, orgs, crypto, audit, base_url }
    }

    pub async fn execute(
        &self,
        ctx: &OrgContext,
        input: CreatePassInput,
    ) -> Result<CreatePassOutput, DomainError> {
        ctx.require_role(visitorpass_domain::value_objects::Role::Resident)?;

        // ── 1. Validate timing ─────────────────────────────────────────────
        let now = Utc::now();
        if input.valid_until <= input.valid_from {
            return Err(DomainError::InvalidValidityWindow);
        }
        let max_secs = VisitorPass::MAX_VALIDITY_SECONDS;
        if (input.valid_until - input.valid_from).num_seconds() > max_secs {
            return Err(DomainError::ValidityWindowTooLong);
        }
        if input.valid_from < now - Duration::minutes(5) {
            // Allow 5-minute clock skew, but reject obviously stale valid_from.
        }

        // ── 2. Fetch org and verify it is active ───────────────────────────
        let org = self.orgs.find_by_id(ctx, ctx.org_id).await?;
        org.assert_active()?;

        // ── 3. Fetch the active org signing key ────────────────────────────
        let org_key = self.orgs.find_active_key(ctx.org_id).await?;

        // ── 4. Hash and encrypt visitor phone ─────────────────────────────
        let phone_hmac = self.crypto.hmac_phone(&input.visitor_phone)?;
        let phone_enc  = Some(self.crypto.encrypt_phone(Uuid::now_v7(), &input.visitor_phone)?);

        // ── 5. Generate pass number (retry on collision) ───────────────────
        let pass_number = self
            .generate_unique_pass_number(ctx)
            .await?;

        let pass_id = Uuid::now_v7();

        // ── 6. Build the QR payload ────────────────────────────────────────
        // The private key is decrypted in the crypto service, used to sign,
        // then zeroed. It never crosses the network.
        let qr_output = self.crypto.build_qr_payload(&QrBuildInput {
            pass_id,
            org_id:        ctx.org_id,
            location_id:   input.location_id,
            host_user_id:  ctx.user_id,
            visitor_name:  input.visitor_name.clone(),
            visitor_phone_hmac_prefix: phone_hmac.chars().take(8).collect(),
            purpose:       input.purpose.clone(),
            vehicle_number: input.vehicle_number.clone(),
            permissions:   input.permissions.clone(),
            valid_from:    input.valid_from.timestamp(),
            valid_until:   input.valid_until.timestamp(),
            key_version:   org_key.version,
            signing_private_key: org_key.signing_private_key_enc.clone(),
            key_derivation_nonce: org_key.key_derivation_nonce.clone(),
            encrypted_phone: phone_enc.clone(),
        })?;

        // ── 7. Persist pass ────────────────────────────────────────────────
        let db_input = crate::ports::repositories::CreatePassInput {
            org_id:             ctx.org_id,
            location_id:        input.location_id,
            created_by:         ctx.user_id,
            pass_number:        pass_number.to_string(),
            visitor_name:       input.visitor_name.clone(),
            visitor_phone_hmac: phone_hmac,
            visitor_phone_enc:  phone_enc,
            purpose:            input.purpose.clone(),
            vehicle_number:     input.vehicle_number.clone(),
            permissions:        input.permissions.clone(),
            valid_from:         input.valid_from,
            valid_until:        input.valid_until,
            max_uses:           input.max_uses,
            qr_payload:         qr_output.qr_string.clone(),
            qr_nonce:           qr_output.qr_nonce.clone(),
            key_version:        org_key.version,
        };
        let pass = self.passes.create(ctx, db_input).await?;

        // ── 8. Increment sync sequence ─────────────────────────────────────
        self.orgs.increment_sync_seq(ctx.org_id).await?;

        // ── 9. Emit audit event (fire-and-forget) ─────────────────────────
        let _ = self.audit.append(AuditEventInput {
            org_id:             ctx.org_id,
            event_type:         "PASS_CREATED".into(),
            actor_user_id:      Some(ctx.user_id),
            actor_device_id:    ctx.device_id,
            target_entity_type: Some("visitor_pass".into()),
            target_entity_id:   Some(pass.id),
            metadata:           serde_json::json!({
                "pass_number":   pass.pass_number.as_str(),
                "location_id":   input.location_id,
                "purpose":       input.purpose,
                "valid_until":   input.valid_until,
            }),
            ip_address: None,
        }).await;

        let share_url = format!("{}/v/{}", self.base_url, pass.pass_number.as_str());

        Ok(CreatePassOutput { pass, share_url })
    }

    /// Generate a pass number that doesn't conflict with existing ones for this org.
    async fn generate_unique_pass_number(
        &self,
        ctx: &OrgContext,
    ) -> Result<PassNumber, DomainError> {
        for attempt in 0..5 {
            let number = PassNumber::generate();
            match self.passes.find_by_pass_number(ctx, number.as_str()).await {
                Ok(_)  => {
                    // Collision — try again
                    tracing::warn!(
                        org_id = %ctx.org_id,
                        pass_number = %number,
                        attempt,
                        "pass number collision, regenerating"
                    );
                    continue;
                }
                Err(DomainError::PassNotFound(_)) => return Ok(number),
                Err(e) => return Err(e),
            }
        }
        Err(DomainError::CryptoError) // Pathological; should never happen
    }
}
