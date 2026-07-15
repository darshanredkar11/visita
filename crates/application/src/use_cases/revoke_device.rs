use std::sync::Arc;

use uuid::Uuid;
use visitorpass_domain::{
    entities::Device,
    value_objects::OrgContext,
    DomainError,
};

use crate::ports::repositories::{AuditEventInput, AuditRepository, DeviceRepository};

pub struct RevokeDeviceUseCase {
    devices: Arc<dyn DeviceRepository>,
    audit:   Arc<dyn AuditRepository>,
}

impl RevokeDeviceUseCase {
    pub fn new(
        devices: Arc<dyn DeviceRepository>,
        audit:   Arc<dyn AuditRepository>,
    ) -> Self {
        Self { devices, audit }
    }

    pub async fn execute(
        &self,
        ctx: &OrgContext,
        device_id: Uuid,
        reason: Option<String>,
    ) -> Result<Device, DomainError> {
        // Enforce role authorization: Admins or Owners can revoke devices
        ctx.require_role(visitorpass_domain::value_objects::Role::Admin)?;

        // Revoke the device
        let device = self.devices.revoke(ctx, device_id, reason.clone()).await?;

        // Audit log
        let _ = self.audit.append(AuditEventInput {
            org_id:             ctx.org_id,
            event_type:         "DEVICE_REVOKED".into(),
            actor_user_id:      Some(ctx.user_id),
            actor_device_id:    ctx.device_id,
            target_entity_type: Some("device".into()),
            target_entity_id:   Some(device_id),
            metadata:           serde_json::json!({
                "device_name": device.name,
                "reason":      reason,
            }),
            ip_address: None,
        }).await;

        Ok(device)
    }
}
