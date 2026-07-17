use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A global, cross-tenant platform administrator. Deliberately has no
/// `org_id` -- see `app.platform_admins` (migration 022) and
/// `PlatformContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformAdmin {
    pub user_id:    Uuid,
    pub granted_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}
