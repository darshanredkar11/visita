use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::value_objects::Role;

/// Mandatory context passed to every repository and use case.
///
/// Invariant: this struct cannot be constructed without a valid, authenticated
/// principal. It is created only in the auth middleware after PASETO token
/// verification, and then passed through the call stack by value.
///
/// No repository method accepts a bare `pass_id: Uuid` — it always takes
/// `(ctx: &OrgContext, pass_id: Uuid)`. This ensures all queries are
/// automatically scoped to the authenticated org.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgContext {
    pub org_id:    Uuid,
    pub user_id:   Uuid,
    pub role:      Role,
    /// Populated for device tokens (guard tablets). None for human sessions.
    pub device_id: Option<Uuid>,
    /// For guard devices: the location they are assigned to.
    pub location_id: Option<Uuid>,
}

impl OrgContext {
    pub fn new(
        org_id:    Uuid,
        user_id:   Uuid,
        role:      Role,
        device_id: Option<Uuid>,
        location_id: Option<Uuid>,
    ) -> Self {
        Self { org_id, user_id, role, device_id, location_id }
    }

    /// Returns true if the caller has at least `required` role privilege.
    pub fn has_role(&self, required: Role) -> bool {
        self.role >= required
    }

    /// Convenience: require minimum role, returning an error if insufficient.
    pub fn require_role(&self, required: Role) -> Result<(), crate::DomainError> {
        if self.has_role(required) {
            Ok(())
        } else {
            Err(crate::DomainError::InsufficientRole {
                required: format!("{:?}", required),
                actual:   format!("{:?}", self.role),
            })
        }
    }
}
