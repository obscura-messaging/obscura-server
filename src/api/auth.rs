use crate::api::AppState;
use crate::api::middleware::AuthUser;
use crate::api::schemas::auth::{
    AuthResponse, LoginRequest, LogoutRequest, RefreshRequest, RegistrationRequest, ResetAccountRequest,
};
use crate::domain::auth_session::AuthSession;
use crate::error::{AppError, Result};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

/// Authenticates a user and returns a session.
///
/// # Errors
/// Returns `AppError::AuthError` if the credentials are invalid.
/// Returns `AppError::BadRequest` if the device ID is invalid.
pub(crate) async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse> {
    let device_id = payload
        .device_id
        .map(|s| uuid::Uuid::parse_str(&s).map_err(|_| AppError::BadRequest("Invalid device_id".to_string())))
        .transpose()?;

    let session = state.auth_service.login(&payload.username, payload.password, device_id).await?;
    let auth_response = map_session(session);
    Ok(Json(auth_response))
}

/// Registers a new user. Returns a user-only JWT (no `device_id`).
///
/// # Errors
/// Returns `AppError::BadRequest` if validation fails.
/// Returns `AppError::Conflict` if the username is already taken.
pub(crate) async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegistrationRequest>,
) -> Result<impl IntoResponse> {
    let username = payload.validate().map_err(AppError::BadRequest)?;

    let session = state.auth_service.register(&username, payload.password).await?;

    let auth_response = map_session(session);
    Ok((StatusCode::CREATED, Json(auth_response)))
}

/// Deletes all of the account's devices and clears its identity.
///
/// # Errors
/// Returns `AppError::AuthError` if the credentials are invalid.
pub(crate) async fn reset_account(
    State(state): State<AppState>,
    Json(payload): Json<ResetAccountRequest>,
) -> Result<impl IntoResponse> {
    state.device_service.reset_account(&payload.username, &payload.password).await?;
    Ok(StatusCode::OK)
}

/// Rotates a session using a refresh token.
///
/// # Errors
/// Returns `AppError::AuthError` if the refresh token is invalid or expired.
pub(crate) async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<impl IntoResponse> {
    let session = state.auth_service.refresh_session(payload.refresh_token).await?;
    let auth_response = map_session(session);
    Ok(Json(auth_response))
}

/// Invalidates a refresh token.
///
/// # Errors
/// Returns `AppError::AuthError` if the user is not authorized.
pub(crate) async fn logout(
    auth_user: AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<impl IntoResponse> {
    state.auth_service.logout(auth_user.user_id, payload.refresh_token).await?;
    Ok(StatusCode::OK)
}

pub(crate) fn map_session(session: AuthSession) -> AuthResponse {
    AuthResponse {
        token: session.token,
        refresh_token: session.refresh_token,
        expires_at: session.expires_at,
        device_id: session.device_id.map(|d| d.to_string()),
    }
}
