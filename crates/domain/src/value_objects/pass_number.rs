use serde::{Deserialize, Serialize};

/// A validated visitor pass number in the format `VP-XXXXXXXX`
/// where X is an uppercase base-36 character (0-9, A-Z).
///
/// 8 characters gives 36^8 ≈ 2.8 trillion combinations per org,
/// making collisions negligible even at high volumes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PassNumber(String);

const BASE36_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const PASS_LENGTH: usize = 8;

impl PassNumber {
    /// Generate a new random pass number.
    ///
    /// The caller must check for uniqueness within the org before committing.
    /// In the unlikely event of a collision, call again.
    pub fn generate() -> Self {
        use rand::Rng;
        
        // Generate 8 random base36 characters using OsRng (CSPRNG)
        let mut rng = rand::rngs::OsRng;
        let mut chars = [0u8; PASS_LENGTH];
        for c in chars.iter_mut() {
            *c = BASE36_CHARS[rng.gen_range(0..36)];
        }
        let suffix = String::from_utf8(chars.to_vec()).expect("base36 chars are valid utf8");
        Self(format!("VP-{suffix}"))
    }

    /// Parse an existing pass number string. Validates format.
    pub fn parse(s: &str) -> Result<Self, crate::DomainError> {
        if s.len() != PASS_LENGTH + 3 {
            return Err(crate::DomainError::ValidationFailed {
                field:   "pass_number".into(),
                message: format!("expected {PASS_LENGTH} chars after VP-, got {}", s.len().saturating_sub(3)),
            });
        }
        let Some(suffix) = s.strip_prefix("VP-") else {
            return Err(crate::DomainError::ValidationFailed {
                field:   "pass_number".into(),
                message: "must start with VP-".into(),
            });
        };
        if !suffix.bytes().all(|b| BASE36_CHARS.contains(&b)) {
            return Err(crate::DomainError::ValidationFailed {
                field:   "pass_number".into(),
                message: "must contain only uppercase alphanumeric characters".into(),
            });
        }
        Ok(Self(s.to_uppercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PassNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for PassNumber {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
