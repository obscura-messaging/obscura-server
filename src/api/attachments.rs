use crate::api::AppState;
use crate::api::schemas::attachments::AttachmentResponse;
use crate::domain::auth::Caller;
use crate::error::{AppError, Result};
use crate::services::attachment_service::Download;
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
    _auth: Caller,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<impl IntoResponse> {
    let content_len = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok().and_then(|s| s.parse::<u64>().ok()))
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
    _auth: Caller,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    let client_has_copy = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|if_none_match| etag_matches(id, if_none_match));
    let (content_length, stream) = match state.attachment_service.download(id, client_has_copy).await? {
        Download::AlreadyHeld => return Ok(StatusCode::NOT_MODIFIED.into_response()),
        Download::Content { length, stream } => (length, stream),
    };

    let body = Body::from_stream(stream);
    let mut response = Response::new(body);

    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&content_length.to_string()).map_err(|_| AppError::Internal)?,
    );
    response.headers_mut().insert(header::ETAG, HeaderValue::from_str(&etag(id)).map_err(|_| AppError::Internal)?);

    Ok(response)
}

/// The `ETag` of an attachment: its ID, quoted. Attachments never change, so the ID identifies the content.
#[must_use]
fn etag(id: Uuid) -> String {
    format!("\"{id}\"")
}

/// Whether an `If-None-Match` request header matches the attachment `id`.
///
/// Follows RFC 9110's weak comparison: `*`, or any tag in a comma-separated list, with or without a `W/`
/// prefix.
#[must_use]
fn etag_matches(id: Uuid, if_none_match: &str) -> bool {
    let quoted = etag(id);
    if_none_match.split(',').map(str::trim).any(|tag| {
        let tag = tag.strip_prefix("W/").unwrap_or(tag);
        tag == "*" || tag == quoted
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etag_header_value_is_the_quoted_id() {
        let id = Uuid::new_v4();
        assert_eq!(etag(id), format!("\"{id}\""));
    }

    #[test]
    fn test_etag_matches() {
        let id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let matches = |header: &str| etag_matches(id, header);
        assert!(matches(&format!("\"{id}\"")));
        assert!(matches(&format!("W/\"{id}\"")), "weak comparison ignores W/");
        assert!(matches(&format!("\"{other}\", \"{id}\"")), "any tag in a list");
        assert!(matches("*"));
        assert!(!matches(&id.to_string()), "an unquoted ID is not an entity tag");
        assert!(!matches(&format!("\"{other}\"")));
        assert!(!matches(""));
        assert!(!matches(&format!("\"{id}")), "a malformed tag does not match");
    }
}
