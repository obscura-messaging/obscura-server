use crate::api::AppState;
use crate::api::middleware::AuthUser;
use crate::api::schemas::push_tokens::RegisterPushTokenRequest;
use crate::error::{AppError, Result};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

/// Registers or updates a push token for the authenticated device.
///
/// # Errors
/// Returns `AppError::BadRequest` if the token format is invalid.
/// Returns `AppError::Database` if the database operation fails.
pub(crate) async fn register_token(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<RegisterPushTokenRequest>,
) -> Result<impl IntoResponse> {
    payload.validate().map_err(AppError::BadRequest)?;

    state.push_token_service.register_token(auth.device_id, payload.token).await?;
    Ok(StatusCode::OK)
}
