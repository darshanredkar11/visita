use std::sync::Arc;

use uuid::Uuid;
use visitorpass_domain::{
    entities::{Device, DeviceType},
    value_objects::OrgContext,
    DomainError,
};

use crate::ports::repositories::{
    AuditEventInput, AuditRepository, CreateDeviceInput, DeviceRepository, OrgRepository,
};

pub struct RegisterDeviceInput {
    pub location_id:   Option<Uuid>,
    pub owner_user_id: Option<Uuid>,
    pub device_type:   String,
    pub name:          String,
    pub public_key:    Vec<u8>,
    pub platform:      Option<String>,
    pub os_version:    Option<String>,
    pub app_version:   Option<String>,
    pub push_token:    Option<String>,
}

pub struct RegisterDeviceUseCase {
    devices: Arc<dyn DeviceRepository>,
    orgs:    Arc<dyn OrgRepository>,
    audit:   Arc<dyn AuditRepository>,
}

impl RegisterDeviceUseCase {
    pub fn new(
        devices: Arc<dyn DeviceRepository>,
        orgs:    Arc<dyn OrgRepository>,
        audit:   Arc<dyn AuditRepository>,
    ) -> Self {
        Self { devices, orgs, audit }
    }

    pub async fn execute(
        &self,
        ctx: &OrgContext,
        input: RegisterDeviceInput,
    ) -> Result<Device, DomainError> {
        // Enforce role authorization: OrgAdmins can register devices
        ctx.require_role(visitorpass_domain::value_objects::Role::OrgAdmin)?;

        // Validate public key length (Ed25519 requires 32 bytes)
        if input.public_key.len() != 32 {
            return Err(DomainError::ValidationFailed {
                field:   "public_key".into(),
                message: "public key must be exactly 32 bytes (Ed25519)".into(),
            });
        }

        // Validate DeviceType
        let dev_type = match input.device_type.as_str() {
            "GUARD_TABLET"   => DeviceType::GuardTablet,
            "GUARD_KIOSK"    => DeviceType::GuardKiosk,
            "RESIDENT_PHONE" => DeviceType::ResidentPhone,
            _ => {
                return Err(DomainError::ValidationFailed {
                    field:   "device_type".into(),
                    message: format!("unknown device type: {}", input.device_type),
                })
            }
        };

        // If it's a guard device, a location_id is recommended
        if dev_type.requires_location() && input.location_id.is_none() {
            return Err(DomainError::ValidationFailed {
                field:   "location_id".into(),
                message: "location_id is required for guard devices".into(),
            });
        }

        // Save device record
        let db_input = CreateDeviceInput {
            org_id:        ctx.org_id,
            location_id:   input.location_id,
            owner_user_id: input.owner_user_id,
            device_type:   input.device_type.clone(),
            name:          input.name.trim().to_string(),
            public_key:    input.public_key.clone(),
            platform:      input.platform,
            os_version:    input.os_version,
            app_version:   input.app_version,
            push_token:    input.push_token,
        };

        let device = self.devices.create(ctx, db_input).await?;

        // Increment org sync seq so other nodes are aware of the new device
        self.orgs.increment_sync_seq(ctx.org_id).await?;

        // Audit log
        let _ = self.audit.append(AuditEventInput {
            org_id:             ctx.org_id,
            event_type:         "DEVICE_REGISTERED".into(),
            actor_user_id:      Some(ctx.user_id),
            actor_device_id:    ctx.device_id,
            target_entity_type: Some("device".into()),
            target_entity_id:   Some(device.id),
            metadata:           serde_json::json!({
                "device_name": device.name,
                "device_type": input.device_type,
                "location_id": input.location_id,
            }),
            ip_address: None,
        }).await;

        Ok(device)
    }
}
