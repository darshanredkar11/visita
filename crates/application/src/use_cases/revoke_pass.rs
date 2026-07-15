use std::sync::Arc;

use uuid::Uuid;
use visitorpass_domain::{
    entities::VisitorPass,
    value_objects::OrgContext,
    DomainError,
};

use crate::ports::repositories::{AuditEventInput, AuditRepository, OrgRepository, PassRepository};

pub struct RevokePassUseCase {
    passes: Arc<dyn PassRepository>,
    orgs:   Arc<dyn OrgRepository>,
    audit:  Arc<dyn AuditRepository>,
}

impl RevokePassUseCase {
    pub fn new(
        passes: Arc<dyn PassRepository>,
        orgs:   Arc<dyn OrgRepository>,
        audit:  Arc<dyn AuditRepository>,
    ) -> Self {
        Self { passes, orgs, audit }
    }

    pub async fn execute(
        &self,
        ctx: &OrgContext,
        pass_id: Uuid,
        reason: Option<String>,
    ) -> Result<VisitorPass, DomainError> {
        // Enforce role authorization: Residents can revoke passes they created or admin/owner can revoke any
        // For simplicity in V1, we verify Resident minimum role first.
        ctx.require_role(visitorpass_domain::value_objects::Role::Resident)?;

        let pass = self.passes.find_by_id(ctx, pass_id).await?;

        // If caller is resident, make sure they own the pass
        if ctx.role == visitorpass_domain::value_objects::Role::Resident && pass.created_by != ctx.user_id {
            return Err(DomainError::InsufficientRole {
                required: "Pass Owner / Admin".into(),
                actual:   "Other Resident".into(),
            });
        }

        // Perform repository revocation
        let revoked_pass = self.passes.revoke(ctx, pass_id, ctx.user_id, reason.clone()).await?;

        // Increment the org's sync sequence to broadcast the revocation event to all guard devices
        self.orgs.increment_sync_seq(ctx.org_id).await?;

        // Record audit log
        let _ = self.audit.append(AuditEventInput {
            org_id:             ctx.org_id,
            event_type:         "PASS_REVOKED".into(),
            actor_user_id:      Some(ctx.user_id),
            actor_device_id:    ctx.device_id,
            target_entity_type: Some("visitor_pass".into()),
            target_entity_id:   Some(pass_id),
            metadata:           serde_json::json!({
                "pass_number": revoked_pass.pass_number.as_str(),
                "reason":      reason,
            }),
            ip_address: None,
        }).await;

        Ok(revoked_pass)
    }
}
