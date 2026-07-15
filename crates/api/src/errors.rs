use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use visitorpass_domain::DomainError;

/// Unified API error type. All handlers return `Result<T, ApiError>`.
/// `ApiError` implements `IntoResponse` and always returns a JSON error envelope.
#[derive(Debug)]
pub struct ApiError {
    pub status:  StatusCode,
    pub code:    &'static str,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    pub fn validation(field: &str, message: &str) -> Self {
        Self {
            status:  StatusCode::BAD_REQUEST,
            code:    "VALIDATION_FAILED",
            message: format!("Validation failed: {field}: {message}"),
            details: Some(json!({
                "fields": [{ "field": field, "message": message }]
            })),
        }
    }

    pub fn unauthorized(code: &'static str, msg: &str) -> Self {
        Self {
            status:  StatusCode::UNAUTHORIZED,
            code,
            message: msg.to_string(),
            details: None,
        }
    }

    pub fn forbidden(msg: &str) -> Self {
        Self {
            status:  StatusCode::FORBIDDEN,
            code:    "FORBIDDEN",
            message: msg.to_string(),
            details: None,
        }
    }

    pub fn internal() -> Self {
        Self {
            status:  StatusCode::INTERNAL_SERVER_ERROR,
            code:    "INTERNAL_ERROR",
            message: "An unexpected error occurred. Please try again.".to_string(),
            details: None,
        }
    }
    
    pub fn rate_limited() -> Self {
        Self {
            status:  StatusCode::TOO_MANY_REQUESTS,
            code:    "RATE_LIMITED",
            message: "Too many requests from this IP address".into(),
            details: None,
        }
    }
}

impl From<DomainError> for ApiError {
    fn from(e: DomainError) -> Self {
        let code    = e.error_code();
        let message = e.to_string();

        let status = if e.is_not_found() {
            StatusCode::NOT_FOUND
        } else if e.is_conflict() {
            StatusCode::CONFLICT
        } else {
            match &e {
                DomainError::PassExpired
                | DomainError::PassRevoked { .. }
                | DomainError::PassExhausted => StatusCode::GONE,

                DomainError::InvalidSignature
                | DomainError::InvalidQrFormat
                | DomainError::UnknownKeyVersion(_) => StatusCode::UNPROCESSABLE_ENTITY,

                DomainError::DeviceRevoked
                | DomainError::AccountLocked(_)
                | DomainError::InvalidCredentials => StatusCode::UNAUTHORIZED,

                DomainError::InsufficientRole { .. }
                | DomainError::OrganizationSuspended
                | DomainError::LocationOrgMismatch => StatusCode::FORBIDDEN,

                DomainError::ValidationFailed { .. }
                | DomainError::InvalidValidityWindow
                | DomainError::ValidityWindowTooLong => StatusCode::BAD_REQUEST,

                DomainError::CryptoError => {
                    // Never expose crypto failure details
                    tracing::error!("Crypto error in request handler");
                    return ApiError::internal();
                }

                _ => StatusCode::INTERNAL_SERVER_ERROR,
            }
        };

        Self { status, code, message, details: None }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // The request_id is injected by the request-id middleware.
        // Here we produce a placeholder; the middleware replaces it.
        let body = json!({
            "error": {
                "code":    self.code,
                "message": self.message,
                "details": self.details.unwrap_or(json!({})),
            }
        });
        (self.status, Json(body)).into_response()
    }
}
