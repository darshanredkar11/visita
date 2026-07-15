use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserStatus { Active, Suspended, Deleted }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id:                    Uuid,
    pub email:                 String,
    pub phone_hmac:            Option<String>,
    /// Argon2id PHC string. Never returned in API responses.
    pub password_hash:         String,
    pub full_name:             String,
    pub status:                UserStatus,
    pub email_verified_at:     Option<DateTime<Utc>>,
    pub last_login_at:         Option<DateTime<Utc>>,
    pub failed_login_attempts: i32,
    pub locked_until:          Option<DateTime<Utc>>,
    pub created_at:            DateTime<Utc>,
    pub updated_at:            DateTime<Utc>,
}

impl User {
    /// Max failed attempts before account lock.
    pub const MAX_FAILED_ATTEMPTS: i32 = 10;
    /// Lock duration after max attempts.
    pub const LOCK_DURATION_MINUTES: i64 = 30;

    pub fn is_locked(&self, now: DateTime<Utc>) -> bool {
        self.locked_until.map_or(false, |lu| lu > now)
    }

    pub fn check_not_locked(&self, now: DateTime<Utc>) -> Result<(), crate::DomainError> {
        if let Some(locked_until) = self.locked_until {
            if locked_until > now {
                return Err(crate::DomainError::AccountLocked(locked_until));
            }
        }
        Ok(())
    }
}
