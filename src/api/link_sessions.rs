use crate::api::AppState;
use crate::api::middleware::{DeviceAuth, UserAuth};
use crate::api::schemas::link_sessions::LinkSessionResponse;
use crate::error::Result;
use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

/// Creates a link session bound to the caller's account.
///
/// # Errors
/// Returns `AppError::Forbidden` if the token is device-scoped.
pub(crate) async fn create_link_session(auth: UserAuth, State(state): State<AppState>) -> Result<impl IntoResponse> {
    let session = state.link_session_service.create(auth.user_id).await?;
    Ok((
        StatusCode::CREATED,
        Json(LinkSessionResponse { id: session.id, expires_at: session.expires_at.unix_timestamp() }),
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
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse> {
    state.link_session_service.approve(auth.user_id, auth.device_id, &id, &body).await?;
    Ok(StatusCode::OK)
}

/// Returns the provisioning message of an approved link session, or 204 if it is not approved yet.
///
/// # Errors
/// Returns `AppError::Forbidden` if the token is device-scoped.
/// Returns `AppError::NotFound` if the session is unknown, expired, or another user's.
pub(crate) async fn get_link_session(
    auth: UserAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response> {
    let body = state.link_session_service.get_body(auth.user_id, &id).await?;
    Ok(body.map_or_else(
        || StatusCode::NO_CONTENT.into_response(),
        |body| ([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response(),
    ))
}
