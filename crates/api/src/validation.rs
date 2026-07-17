//! Shared `validator`-crate wiring: a loose E.164 phone check (kept custom
//! rather than a `regex(...)` validator attribute, so this doesn't need to
//! pull in the `regex` crate as a direct dependency just for one pattern),
//! and a converter from `validator::ValidationErrors` into the existing
//! `ApiError` envelope.

use serde_json::json;
use validator::{ValidationError, ValidationErrors};

use crate::errors::ApiError;

/// Loose E.164 check: a leading `+` followed by 8-15 digits (E.164's actual
/// bound is 15 digits total including the country code; 8 is a reasonable
/// floor to reject obviously-truncated input without hand-coding every
/// country's real minimum length).
pub fn validate_e164_phone(phone: &str) -> Result<(), ValidationError> {
    let digits = match phone.strip_prefix('+') {
        Some(rest) => rest,
        None => return Err(ValidationError::new("phone_must_start_with_plus")),
    };

    if digits.len() < 8 || digits.len() > 15 {
        return Err(ValidationError::new("phone_length_out_of_range"));
    }
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(ValidationError::new("phone_must_be_digits_after_plus"));
    }

    Ok(())
}

/// Rejects strings that are empty OR contain only whitespace -- matches the
/// strictness of the hand-written `.trim().is_empty()` checks this replaces.
/// `validator`'s built-in `length(min = 1)` alone would NOT catch an
/// all-whitespace string, since its length is non-zero.
pub fn validate_non_empty_trimmed(s: &str) -> Result<(), ValidationError> {
    if s.trim().is_empty() {
        Err(ValidationError::new("must_not_be_empty"))
    } else {
        Ok(())
    }
}

/// Converts every field error `validator` collected into the same
/// `{"fields": [{"field", "message"}]}` shape `ApiError::validation`
/// already produces for a single field, so handlers get one consistent
/// 400 envelope regardless of whether the check was hand-written or derived.
pub fn validation_errors_to_api_error(errors: ValidationErrors) -> ApiError {
    let fields: Vec<serde_json::Value> = errors
        .field_errors()
        .into_iter()
        .flat_map(|(field, field_errors)| {
            field_errors.iter().map(move |e| {
                let message = e
                    .message
                    .as_ref()
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| e.code.to_string());
                json!({ "field": field, "message": message })
            })
        })
        .collect();

    let summary = fields
        .iter()
        .filter_map(|f| f["message"].as_str())
        .collect::<Vec<_>>()
        .join("; ");

    ApiError {
        status: axum::http::StatusCode::BAD_REQUEST,
        code: "VALIDATION_FAILED",
        message: format!("Validation failed: {summary}"),
        details: Some(json!({ "fields": fields })),
    }
}
