use crate::api::AppState;
use crate::api::middleware::AuthUser;
use crate::api::schemas::link_sessions::{LinkSessionResponse, LinkSessionWaitParams};
use crate::error::{AppError, Result};
use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use std::time::Duration;

/// Creates a link session bound to the caller's account.
///
/// # Errors
/// Returns `AppError::Forbidden` if the token is device-scoped.
pub(crate) async fn create_link_session(
    auth_user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse> {
    auth_user.require_user_scope()?;
    let session = state.link_session_service.create(auth_user.user_id).await?;
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
    auth_user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse> {
    let device_id = auth_user.device_id.ok_or_else(|| AppError::Forbidden("Device-scoped token required".into()))?;
    state.link_session_service.approve(auth_user.user_id, device_id, &id, &body).await?;
    Ok(StatusCode::OK)
}

/// Returns the provisioning message of an approved link session, or 204 if it is not approved within the wait.
///
/// # Errors
/// Returns `AppError::Forbidden` if the token is device-scoped.
/// Returns `AppError::NotFound` if the session is unknown, expired, or another user's.
pub(crate) async fn get_link_session(
    auth_user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<LinkSessionWaitParams>,
) -> Result<Response> {
    auth_user.require_user_scope()?;
    let body =
        state.link_session_service.wait_for_approval(auth_user.user_id, &id, Duration::from_secs(params.wait)).await?;
    Ok(body.map_or_else(
        || StatusCode::NO_CONTENT.into_response(),
        |body| ([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response(),
    ))
}
