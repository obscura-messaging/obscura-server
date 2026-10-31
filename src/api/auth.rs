use crate::api::AppState;
use crate::api::middleware::AuthUser;
use crate::api::schemas::auth::{AuthResponse, LoginRequest, RefreshRequest};
use crate::error::Result;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

/// Authenticates an existing device of a user and returns a session.
///
/// # Errors
/// Returns `AppError::Unauthorized` if the credentials are invalid.
/// Returns `AppError::Conflict` if the device does not belong to the user.
pub(crate) async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse> {
    let session = state.auth_service.login(&payload.username, payload.password, payload.device_id).await?;
    Ok(Json(AuthResponse::from(session)))
}

/// Rotates a session using a refresh token.
///
/// # Errors
/// Returns `AppError::Unauthorized` if the refresh token is invalid or expired.
pub(crate) async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<impl IntoResponse> {
    let session = state.auth_service.refresh_session(payload.refresh_token).await?;
    Ok(Json(AuthResponse::from(session)))
}

/// Invalidates the authenticated device's refresh token.
///
/// # Errors
/// Returns `AppError::Unauthorized` if the user is not authorized.
pub(crate) async fn logout(auth_user: AuthUser, State(state): State<AppState>) -> Result<impl IntoResponse> {
    state.auth_service.logout(auth_user.device_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
