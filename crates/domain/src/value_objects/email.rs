use serde::{Deserialize, Serialize};

/// A validated email address (newtype). Validation is intentionally minimal —
/// we only check structural plausibility, not deliverability.
/// We normalize to lowercase on construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Email(String);

impl Email {
    pub fn parse(s: &str) -> Result<Self, crate::DomainError> {
        let s = s.trim().to_lowercase();
        let err = || crate::DomainError::ValidationFailed {
            field:   "email".into(),
            message: "must be a valid email address".into(),
        };
        // Must have exactly one @ with non-empty local and domain parts.
        let mut parts = s.splitn(2, '@');
        let local  = parts.next().ok_or_else(err)?;
        let domain = parts.next().ok_or_else(err)?;
        if local.is_empty() || domain.is_empty() {
            return Err(err());
        }
        if !domain.contains('.') {
            return Err(err());
        }
        if s.len() > 254 {
            return Err(err());
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
