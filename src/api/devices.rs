use crate::api::AppState;
use crate::api::middleware::AuthUser;
use crate::api::schemas::auth::{AuthResponse, RegistrationRequest, ResetAccountRequest};
use crate::api::schemas::devices::{CreateDeviceRequest, DeviceListResponse, DeviceResponse};
use crate::api::schemas::link_sessions::{CreateLinkSessionRequest, LinkSessionResponse};
use crate::error::{AppError, Result};
use crate::services::device_service::NewLinkedDevice;
use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

/// Registers a new user and provisions its primary device.
///
/// # Errors
/// Returns `AppError::BadRequest` if validation fails or keys are malformed.
/// Returns `AppError::Conflict` if the username is already taken.
pub(crate) async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegistrationRequest>,
) -> Result<impl IntoResponse> {
    let username = payload.validate().map_err(AppError::BadRequest)?;
    let keys = payload.device.try_into().map_err(AppError::BadRequest)?;

    let session = state.device_service.register_account(&username, payload.password, keys).await?;

    Ok((StatusCode::CREATED, Json(AuthResponse::from(session))))
}

/// Deletes all of the account's devices, replaces its identity, and provisions a new primary device.
///
/// # Errors
/// Returns `AppError::BadRequest` if keys are malformed or do not verify.
/// Returns `AppError::Unauthorized` if the credentials are invalid.
pub(crate) async fn reset_account(
    State(state): State<AppState>,
    Json(payload): Json<ResetAccountRequest>,
) -> Result<impl IntoResponse> {
    let keys = payload.device.try_into().map_err(AppError::BadRequest)?;
    let session = state.device_service.reset_account(&payload.username, &payload.password, keys).await?;
    Ok(Json(AuthResponse::from(session)))
}

/// Verifies credentials and creates a link session bound to the account.
///
/// # Errors
/// Returns `AppError::Unauthorized` if the credentials are invalid.
pub(crate) async fn create_link_session(
    State(state): State<AppState>,
    Json(payload): Json<CreateLinkSessionRequest>,
) -> Result<impl IntoResponse> {
    let session = state.device_service.create_link_session(&payload.username, &payload.password).await?;
    Ok((
        StatusCode::CREATED,
        Json(LinkSessionResponse {
            id: session.id,
            user_id: session.user_id.to_string(),
            expires_at: session.expires_at.unix_timestamp(),
        }),
    ))
}

/// Approves a link session by storing the opaque provisioning message for the new device.
///
/// # Errors
/// Returns `AppError::Forbidden` if the caller is not the primary device.
/// Returns `AppError::NotFound` if the session is unknown, expired, or another user's.
/// Returns `AppError::Conflict` if the session is already approved.
/// Returns `AppError::PayloadTooLarge` if the body exceeds the size cap.
pub(crate) async fn approve_link_session(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse> {
    state.device_service.approve_link_session(auth.user_id, auth.is_primary, &id, &body).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Returns the provisioning message of an approved link session, or 204 if it is not approved yet.
///
/// # Errors
/// Returns `AppError::NotFound` if the session is unknown, expired, or consumed.
pub(crate) async fn get_link_session(State(state): State<AppState>, Path(id): Path<String>) -> Result<Response> {
    let body = state.device_service.get_link_session_body(&id).await?;
    Ok(body.map_or_else(
        || StatusCode::NO_CONTENT.into_response(),
        |body| ([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response(),
    ))
}

/// Provisions a linked device authorized by an approved link session and returns a session.
///
/// # Errors
/// Returns `AppError::BadRequest` if validation fails or keys are malformed.
/// Returns `AppError::Forbidden` if the link session is invalid, the device limit is reached, or the
/// identity key does not match the account identity.
pub(crate) async fn create_device(
    State(state): State<AppState>,
    Json(payload): Json<CreateDeviceRequest>,
) -> Result<impl IntoResponse> {
    let device = NewLinkedDevice {
        link_session_id: payload.link_session_id,
        keys: payload.device.try_into().map_err(AppError::BadRequest)?,
    };
    let session = state.device_service.create_linked_device(device).await?;

    Ok((StatusCode::CREATED, Json(AuthResponse::from(session))))
}

/// Lists all devices for the authenticated user.
///
/// # Errors
/// Returns `AppError::Database` if the query fails.
pub(crate) async fn list_devices(auth_user: AuthUser, State(state): State<AppState>) -> Result<impl IntoResponse> {
    let devices = state.device_service.list_devices(auth_user.user_id).await?;

    let response = DeviceListResponse { devices: devices.into_iter().map(DeviceResponse::from).collect() };

    Ok(Json(response))
}

/// Deletes a device owned by the authenticated user.
///
/// # Errors
/// Returns `AppError::NotFound` if the device doesn't exist or isn't owned by the user.
/// Returns `AppError::Forbidden` if the caller may not delete the device.
pub(crate) async fn delete_device(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    state.device_service.delete_device(auth.user_id, auth.device_id, auth.is_primary, device_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
