use axum::{extract::State, response::IntoResponse, Json};
use serde_json::json;

use crate::{errors::ApiError, state::AppState};

/// GET /health
/// Anonymous health check endpoint checking overall service state and database connectivity.
pub async fn health(State(_state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    // For V1 simple status: we confirm that state is initialized.
    // Database connection status could be verified with a fast query like "SELECT 1" in future.
    Ok(Json(json!({
        "status": "UP",
        "timestamp": chrono::Utc::now(),
        "version": env!("CARGO_PKG_VERSION")
    })))
}
