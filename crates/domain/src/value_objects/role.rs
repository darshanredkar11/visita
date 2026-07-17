use serde::{Deserialize, Serialize};

/// Roles, ordered by privilege level (lowest to highest) within the tier
/// each is meaningful in.
///
/// `PlatformAdmin` is NOT org-scoped -- it is never stored in a row of
/// `app.org_memberships` and never appears on an `OrgContext` (see
/// `PlatformContext` instead, which platform-only routes use in its place).
/// It is ordered highest here purely so the `Role` enum has one total order
/// for display/claim purposes; no code path ever compares a `PlatformAdmin`
/// role against an org-scoped role via `OrgContext::has_role`, because a
/// `PlatformAdmin` PASETO token never carries an `org` claim and therefore
/// can never construct an `OrgContext` in the first place (see
/// `build_org_context` in the API's auth middleware).
///
/// The `PartialOrd` / `Ord` derives allow `role >= Role::OrgAdmin`
/// comparisons, which are the basis of `OrgContext::has_role`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Role {
    /// Can scan QR codes and record entry/exit at their assigned location.
    Guard         = 1,
    /// Can create passes and approve/reject for their unit.
    Resident      = 2,
    /// Can manage members, locations, devices, and org settings (including
    /// key rotation) for their own org. Formerly two tiers (Admin/Owner);
    /// collapsed to one because no RBAC check in this codebase ever
    /// distinguished them (see migration 022_platform_admins.sql).
    OrgAdmin      = 3,
    /// Cross-tenant SaaS operator. Not tied to any single org_id; see
    /// `app.platform_admins` and `PlatformContext`.
    PlatformAdmin = 4,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Guard         => "GUARD",
            Role::Resident      => "RESIDENT",
            Role::OrgAdmin      => "ORG_ADMIN",
            Role::PlatformAdmin => "PLATFORM_ADMIN",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<&str> for Role {
    type Error = crate::DomainError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "GUARD"          => Ok(Role::Guard),
            "RESIDENT"       => Ok(Role::Resident),
            "ORG_ADMIN"      => Ok(Role::OrgAdmin),
            // Read-compat: rows/tokens minted before migration 022 still
            // say ADMIN or OWNER. Both map to the collapsed OrgAdmin tier.
            "ADMIN"          => Ok(Role::OrgAdmin),
            "OWNER"          => Ok(Role::OrgAdmin),
            "PLATFORM_ADMIN" => Ok(Role::PlatformAdmin),
            _ => Err(crate::DomainError::ValidationFailed {
                field:   "role".into(),
                message: format!("unknown role: {s}"),
            }),
        }
    }
}
