use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Mandatory context for platform-admin-only use cases and routes.
///
/// Deliberately NOT `OrgContext`: it carries no `org_id` and no `role`
/// field. Its very existence proves the caller is a platform admin --
/// there is no other way to construct one (see
/// `platform_admin_middleware` in the API crate, which is the only
/// production code that builds this struct, only after confirming the
/// PASETO token's `role` claim is `PLATFORM_ADMIN`).
///
/// Every platform-only repository method takes `(ctx: &PlatformContext,
/// ..)` even when it doesn't need `user_id`, mirroring the `OrgContext`
/// convention: the type of the parameter is what proves authorization
/// happened, not a runtime role check sprinkled at each call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformContext {
    pub user_id: Uuid,
}

impl PlatformContext {
    pub fn new(user_id: Uuid) -> Self {
        Self { user_id }
    }
}
