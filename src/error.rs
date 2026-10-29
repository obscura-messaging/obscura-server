use crate::api::schemas::common::ErrorResponse;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Authentication failed")]
    AuthError,
    #[error("Not found")]
    NotFound,
    #[error("Invalid request: {0}")]
    BadRequest(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Precondition failed")]
    PreconditionFailed,
    #[error("Request timeout")]
    Timeout,
    #[error("Length required")]
    LengthRequired,
    #[error("Payload too large")]
    PayloadTooLarge,
    #[error("Internal server error")]
    Internal,
}

pub type Result<T> = std::result::Result<T, AppError>;

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::AuthError => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            Self::NotFound => (StatusCode::NOT_FOUND, "Not found".to_string()),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            Self::PreconditionFailed => (StatusCode::PRECONDITION_FAILED, "Precondition failed".to_string()),
            Self::Timeout => (StatusCode::REQUEST_TIMEOUT, "Request timeout".to_string()),
            Self::LengthRequired => (StatusCode::LENGTH_REQUIRED, "Length required".to_string()),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "Payload too large".to_string()),
            Self::Database(_) | Self::Internal => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        let body = Json(ErrorResponse { error: message });

        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;

    fn status_of(err: AppError) -> StatusCode {
        err.into_response().status()
    }

    #[test]
    fn test_error_status_codes() {
        assert_eq!(status_of(AppError::AuthError), StatusCode::UNAUTHORIZED);
        assert_eq!(status_of(AppError::NotFound), StatusCode::NOT_FOUND);
        assert_eq!(status_of(AppError::BadRequest("bad".into())), StatusCode::BAD_REQUEST);
        assert_eq!(status_of(AppError::Conflict("dup".into())), StatusCode::CONFLICT);
        assert_eq!(status_of(AppError::Forbidden("no".into())), StatusCode::FORBIDDEN);
        assert_eq!(status_of(AppError::PreconditionFailed), StatusCode::PRECONDITION_FAILED);
        assert_eq!(status_of(AppError::Timeout), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(status_of(AppError::LengthRequired), StatusCode::LENGTH_REQUIRED);
        assert_eq!(status_of(AppError::PayloadTooLarge), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(status_of(AppError::Internal), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_error_response_body_format() {
        let response = AppError::NotFound.into_response();
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");
        assert_eq!(json["error"], "Not found");
    }
}
