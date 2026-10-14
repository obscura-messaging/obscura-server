use crate::api::AppState;
use crate::api::middleware::AuthUser;
use crate::api::schemas::provisioning::{ProvisioningRelayResponse, ProvisioningWaitParams};
use crate::error::Result;
use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use std::time::Duration;

/// Creates a provisioning relay address bound to the caller's account.
///
/// # Errors
/// Returns `AppError::InternalMsg` if the relay store fails.
pub(crate) async fn create_relay(auth_user: AuthUser, State(state): State<AppState>) -> Result<impl IntoResponse> {
    let relay = state.provisioning_service.create_relay(auth_user.user_id).await?;
    Ok((
        StatusCode::CREATED,
        Json(ProvisioningRelayResponse { address: relay.value, expires_at: relay.expires_at.unix_timestamp() }),
    ))
}

/// Stores the opaque provisioning message for a relay address.
///
/// # Errors
/// Returns `AppError::Forbidden` if the caller is not the primary device.
/// Returns `AppError::NotFound` if the address is unknown, expired, or another user's.
/// Returns `AppError::Conflict` if the address already received a message.
/// Returns `AppError::PayloadTooLarge` if the body exceeds the size cap.
pub(crate) async fn put_relay(
    auth_user: AuthUser,
    State(state): State<AppState>,
    Path(address): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse> {
    state.provisioning_service.put_relay(auth_user.user_id, auth_user.device_id, &address, &body).await?;
    Ok(StatusCode::OK)
}

/// Returns and deletes the provisioning message of a relay address, or 204 if none arrived within the wait.
///
/// # Errors
/// Returns `AppError::NotFound` if the address is unknown, expired, or another user's.
pub(crate) async fn take_relay(
    auth_user: AuthUser,
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(params): Query<ProvisioningWaitParams>,
) -> Result<Response> {
    let body =
        state.provisioning_service.take_relay(auth_user.user_id, &address, Duration::from_secs(params.wait)).await?;
    Ok(body.map_or_else(
        || StatusCode::NO_CONTENT.into_response(),
        |body| ([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response(),
    ))
}
