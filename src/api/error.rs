//! How an [`AppError`] becomes an HTTP response.

use crate::api::schemas::common::ErrorResponse;
use crate::error::AppError;
use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, retry_after_secs) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string(), None),
            Self::NotFound => (StatusCode::NOT_FOUND, "Not found".to_string(), None),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg, None),
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg, None),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, msg, None),
            Self::Timeout => (StatusCode::REQUEST_TIMEOUT, "Request timeout".to_string(), None),
            Self::LengthRequired => (StatusCode::LENGTH_REQUIRED, "Length required".to_string(), None),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "Payload too large".to_string(), None),
            Self::TooManyRequests { retry_after_secs } => {
                (StatusCode::TOO_MANY_REQUESTS, "Too many requests".to_string(), Some(retry_after_secs))
            }
            Self::Database(_) | Self::Internal => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string(), None)
            }
        };

        let mut response = (status, Json(ErrorResponse { error: message })).into_response();
        if let Some(secs) = retry_after_secs {
            response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn status_of(err: AppError) -> StatusCode {
        err.into_response().status()
    }

    #[test]
    fn test_error_status_codes() {
        assert_eq!(status_of(AppError::Unauthorized), StatusCode::UNAUTHORIZED);
        assert_eq!(status_of(AppError::NotFound), StatusCode::NOT_FOUND);
        assert_eq!(status_of(AppError::BadRequest("bad".into())), StatusCode::BAD_REQUEST);
        assert_eq!(status_of(AppError::Conflict("dup".into())), StatusCode::CONFLICT);
        assert_eq!(status_of(AppError::Forbidden("no".into())), StatusCode::FORBIDDEN);
        assert_eq!(status_of(AppError::Timeout), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(status_of(AppError::LengthRequired), StatusCode::LENGTH_REQUIRED);
        assert_eq!(status_of(AppError::PayloadTooLarge), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(status_of(AppError::Internal), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_too_many_requests_says_when_to_retry() {
        let response = AppError::TooManyRequests { retry_after_secs: 42 }.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "42");
    }

    #[tokio::test]
    async fn test_error_response_body_format() {
        let response = AppError::NotFound.into_response();
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");
        assert_eq!(json["error"], "Not found");
    }
}
