use thiserror::Error;
use uuid::Uuid;

/// All domain-level errors. These are business rule violations, not
/// infrastructure failures. Infrastructure layers map their own errors
/// into these types when crossing the boundary.
#[derive(Debug, Error, Clone)]
pub enum DomainError {
    // ── Not Found ──────────────────────────────────────────────────────────
    #[error("Organization not found: {0}")]
    OrganizationNotFound(Uuid),

    #[error("Location not found: {0}")]
    LocationNotFound(Uuid),

    #[error("User not found: {0}")]
    UserNotFound(Uuid),

    #[error("Device not found: {0}")]
    DeviceNotFound(Uuid),

    #[error("Visitor pass not found: {0}")]
    PassNotFound(Uuid),

    #[error("Entry log not found: {0}")]
    EntryNotFound(Uuid),

    #[error("Invitation not found or expired")]
    InvitationNotFound,

    // ── Conflict ───────────────────────────────────────────────────────────
    #[error("Email already registered")]
    EmailAlreadyExists,

    #[error("Organization slug already taken: {0}")]
    SlugAlreadyExists(String),

    #[error("User is already a member of this organization")]
    MemberAlreadyExists,

    #[error("Device public key already registered")]
    DeviceKeyAlreadyExists,

    // ── Pass State ─────────────────────────────────────────────────────────
    #[error("Visitor pass has expired")]
    PassExpired,

    #[error("Visitor pass has been revoked: {}", .reason.as_deref().unwrap_or("no reason provided"))]
    PassRevoked { reason: Option<String> },

    #[error("Visitor pass has reached its maximum use count")]
    PassExhausted,

    #[error("Visitor pass is not yet valid (valid from: {valid_from})")]
    PassNotYetValid { valid_from: chrono::DateTime<chrono::Utc> },

    // ── Security ───────────────────────────────────────────────────────────
    #[error("QR signature verification failed")]
    InvalidSignature,

    #[error("QR payload cannot be parsed")]
    InvalidQrFormat,

    #[error("Unknown org key version: {0}")]
    UnknownKeyVersion(i32),

    #[error("Device has been revoked")]
    DeviceRevoked,

    #[error("Account locked until {0}")]
    AccountLocked(chrono::DateTime<chrono::Utc>),

    #[error("Invalid credentials")]
    InvalidCredentials,

    // ── Authorization ──────────────────────────────────────────────────────
    #[error("Insufficient role for this operation (required: {required}, actual: {actual})")]
    InsufficientRole { required: String, actual: String },

    #[error("Organization is suspended")]
    OrganizationSuspended,

    #[error("Location does not belong to this organization")]
    LocationOrgMismatch,

    // ── Validation ─────────────────────────────────────────────────────────
    #[error("Validation failed: {field}: {message}")]
    ValidationFailed { field: String, message: String },

    #[error("Pass validity window is invalid: valid_until must be after valid_from")]
    InvalidValidityWindow,

    #[error("Pass validity window exceeds maximum allowed duration")]
    ValidityWindowTooLong,

    // ── Crypto ─────────────────────────────────────────────────────────────
    #[error("Cryptographic operation failed")]
    CryptoError,

    #[error("Data export not yet ready")]
    ExportNotReady,

    // ── Infrastructure (share channels: SMS provider calls, PDF/QR generation) ──
    #[error("External operation failed: {0}")]
    ExternalServiceError(String),
}

impl DomainError {
    /// Returns true if this error should be surfaced as 404 to the client.
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            DomainError::OrganizationNotFound(_)
                | DomainError::LocationNotFound(_)
                | DomainError::UserNotFound(_)
                | DomainError::DeviceNotFound(_)
                | DomainError::PassNotFound(_)
                | DomainError::EntryNotFound(_)
                | DomainError::InvitationNotFound
        )
    }

    /// Returns true if this error should be surfaced as 409 to the client.
    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            DomainError::EmailAlreadyExists
                | DomainError::SlugAlreadyExists(_)
                | DomainError::MemberAlreadyExists
                | DomainError::DeviceKeyAlreadyExists
        )
    }

    /// Returns the API error code string for this error.
    pub fn error_code(&self) -> &'static str {
        match self {
            DomainError::OrganizationNotFound(_) => "ORG_NOT_FOUND",
            DomainError::LocationNotFound(_)     => "LOCATION_NOT_FOUND",
            DomainError::UserNotFound(_)         => "USER_NOT_FOUND",
            DomainError::DeviceNotFound(_)       => "DEVICE_NOT_FOUND",
            DomainError::PassNotFound(_)         => "PASS_NOT_FOUND",
            DomainError::EntryNotFound(_)        => "ENTRY_NOT_FOUND",
            DomainError::InvitationNotFound      => "INVITATION_NOT_FOUND",
            DomainError::EmailAlreadyExists      => "EMAIL_ALREADY_EXISTS",
            DomainError::SlugAlreadyExists(_)    => "SLUG_ALREADY_EXISTS",
            DomainError::MemberAlreadyExists     => "MEMBER_ALREADY_EXISTS",
            DomainError::DeviceKeyAlreadyExists  => "DEVICE_KEY_ALREADY_EXISTS",
            DomainError::PassExpired             => "PASS_EXPIRED",
            DomainError::PassRevoked { .. }      => "PASS_REVOKED",
            DomainError::PassExhausted           => "PASS_EXHAUSTED",
            DomainError::PassNotYetValid { .. }  => "PASS_NOT_YET_VALID",
            DomainError::InvalidSignature        => "QR_SIGNATURE_INVALID",
            DomainError::InvalidQrFormat         => "INVALID_QR_FORMAT",
            DomainError::UnknownKeyVersion(_)    => "QR_KEY_VERSION_UNKNOWN",
            DomainError::DeviceRevoked           => "DEVICE_REVOKED",
            DomainError::AccountLocked(_)        => "ACCOUNT_LOCKED",
            DomainError::InvalidCredentials      => "INVALID_CREDENTIALS",
            DomainError::InsufficientRole { .. } => "FORBIDDEN",
            DomainError::OrganizationSuspended   => "ORG_SUSPENDED",
            DomainError::LocationOrgMismatch     => "LOCATION_ORG_MISMATCH",
            DomainError::ValidationFailed { .. } => "VALIDATION_FAILED",
            DomainError::InvalidValidityWindow   => "INVALID_VALIDITY_WINDOW",
            DomainError::ValidityWindowTooLong   => "VALIDITY_WINDOW_TOO_LONG",
            DomainError::CryptoError             => "INTERNAL_ERROR",
            DomainError::ExportNotReady          => "EXPORT_NOT_READY",
            DomainError::ExternalServiceError(_) => "EXTERNAL_SERVICE_ERROR",
        }
    }
}
