use crate::api::AppState;
use crate::api::middleware::AuthUser;
use crate::api::schemas::attachments::AttachmentResponse;
use crate::error::{AppError, Result};
use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use uuid::Uuid;

/// Uploads an attachment to storage.
///
/// # Errors
/// Returns `AppError::LengthRequired` if the Content-Length header is missing.
/// Returns `AppError::Internal` if there is an error during upload.
pub(crate) async fn upload_attachment(
    _auth: AuthUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<impl IntoResponse> {
    let content_len = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok().and_then(|s| s.parse::<usize>().ok()))
        .ok_or(AppError::LengthRequired)?;

    // Bridge Axum Body -> StorageStream (using neutral std::io::Error)
    let stream = body.into_data_stream().map(|res| res.map_err(|e| std::io::Error::other(e.to_string()))).boxed();

    let (id, expires_at) = state.attachment_service.upload(Some(content_len), stream).await?;

    Ok((StatusCode::CREATED, Json(AttachmentResponse { id, expires_at })))
}

/// Downloads an attachment from storage.
///
/// # Errors
/// Returns `AppError::NotFound` if the attachment is not found.
/// Returns `AppError::Internal` if there is an error during download or header serialization.
///
/// # Panics
/// Panics if the default Content-Type cannot be parsed.
pub(crate) async fn download_attachment(
    _auth: AuthUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    // 1. Immutable Caching Shortcut: If ID matches ETag, it's definitely the same file.
    if let Some(if_none_match) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        let if_none_match_id = if_none_match.trim_matches('"');
        if if_none_match_id == id.to_string() {
            return Ok(StatusCode::NOT_MODIFIED.into_response());
        }
    }

    let (content_length, stream) = state.attachment_service.download(id).await?;

    // Bridge StorageStream -> Axum Body
    let body = Body::from_stream(stream);
    let mut response = Response::new(body);

    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&content_length.to_string()).map_err(|_| AppError::Internal)?,
    );
    // Use the ID as the ETag for caching
    response
        .headers_mut()
        .insert(header::ETAG, HeaderValue::from_str(&format!("\"{id}\"")).map_err(|_| AppError::Internal)?);

    Ok(response)
}
