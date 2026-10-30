use crate::api::AppState;
use crate::api::middleware::AuthUser;
use crate::api::schemas::keys::{PreKeyBundleResponse, PreKeyUploadRequest};
use crate::error::{AppError, Result};
use crate::services::key_service::KeyUploadParams;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::convert::TryInto;
use uuid::Uuid;

/// Fetches all pre-key bundles for a user (one per device).
///
/// # Errors
/// Returns `AppError::NotFound` if the user has no registered devices or keys.
pub(crate) async fn get_pre_key_bundles(
    _auth: AuthUser,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    let bundles = state.key_service.get_pre_key_bundles(user_id, None).await?;

    if bundles.is_empty() {
        return Err(AppError::NotFound);
    }

    let response: Vec<PreKeyBundleResponse> = bundles.into_iter().map(PreKeyBundleResponse::from).collect();
    Ok(Json(response))
}

/// Fetches the pre-key bundle of one device of a user, consuming a one-time pre-key on that device only.
///
/// # Errors
/// Returns `AppError::NotFound` if the user has no such device.
pub(crate) async fn get_device_pre_key_bundle(
    _auth: AuthUser,
    State(state): State<AppState>,
    Path((user_id, device_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse> {
    let bundle =
        state.key_service.get_pre_key_bundles(user_id, Some(device_id)).await?.pop().ok_or(AppError::NotFound)?;

    Ok(Json(PreKeyBundleResponse::from(bundle)))
}

/// Uploads new pre-keys for the authenticated device.
///
/// # Errors
/// Returns `AppError::BadRequest` if the keys are malformed or validation fails.
pub(crate) async fn upload_keys(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<PreKeyUploadRequest>,
) -> Result<impl IntoResponse> {
    payload.validate().map_err(AppError::BadRequest)?;

    let params = KeyUploadParams {
        device_id: auth.device_id,
        signed_pre_key: payload.signed_pre_key.try_into().map_err(AppError::BadRequest)?,
        one_time_pre_keys: payload
            .one_time_pre_keys
            .into_iter()
            .map(TryInto::try_into)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(AppError::BadRequest)?,
    };

    state.key_service.upload_keys(params).await?;

    Ok(StatusCode::OK)
}
