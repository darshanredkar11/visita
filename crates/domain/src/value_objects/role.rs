use serde::{Deserialize, Serialize};

/// Roles within an organization, ordered by privilege level (lowest to highest).
///
/// The `PartialOrd` / `Ord` derives allow `role >= Role::Admin` comparisons,
/// which are the basis of `OrgContext::has_role`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Role {
    /// Can scan QR codes and record entry/exit at their assigned location.
    Guard    = 1,
    /// Can create passes and approve/reject for their unit.
    Resident = 2,
    /// Can manage members, locations, and devices.
    Admin    = 3,
    /// Full control including key rotation and org settings.
    Owner    = 4,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Guard    => "GUARD",
            Role::Resident => "RESIDENT",
            Role::Admin    => "ADMIN",
            Role::Owner    => "OWNER",
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
            "GUARD"    => Ok(Role::Guard),
            "RESIDENT" => Ok(Role::Resident),
            "ADMIN"    => Ok(Role::Admin),
            "OWNER"    => Ok(Role::Owner),
            _ => Err(crate::DomainError::ValidationFailed {
                field:   "role".into(),
                message: format!("unknown role: {s}"),
            }),
        }
    }
}
