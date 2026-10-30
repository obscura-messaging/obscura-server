use crate::api::AppState;
use crate::api::middleware::AuthUser;
use crate::api::schemas::devices::{CreateDeviceRequest, DeviceListResponse, DeviceResponse};
use crate::error::{AppError, Result};
use crate::services::device_service::NewLinkedDevice;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use uuid::Uuid;

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

    let auth_response = crate::api::auth::map_session(session);
    Ok((StatusCode::CREATED, Json(auth_response)))
}

/// Lists all devices for the authenticated user.
///
/// # Errors
/// Returns `AppError::Database` if the query fails.
pub(crate) async fn list_devices(auth_user: AuthUser, State(state): State<AppState>) -> Result<impl IntoResponse> {
    let devices = state.device_service.list_devices(auth_user.user_id).await?;

    let response = DeviceListResponse { devices: devices.into_iter().map(device_to_response).collect() };

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
    state.device_service.delete_device(auth.user_id, auth.device_id, device_id).await?;
    Ok(StatusCode::OK)
}

fn device_to_response(d: crate::domain::device::Device) -> DeviceResponse {
    DeviceResponse {
        device_id: d.id.to_string(),
        name: d.name,
        is_primary: d.is_primary,
        created_at: d
            .created_at
            .map(|ts| ts.format(&time::format_description::well_known::Rfc3339).unwrap_or_default())
            .unwrap_or_default(),
    }
}
