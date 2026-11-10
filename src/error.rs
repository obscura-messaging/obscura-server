//! The error every layer returns. How it becomes an HTTP response is the API's concern, in
//! `api::error`, so this module stays free of HTTP.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Authentication failed")]
    Unauthorized,
    #[error("Not found")]
    NotFound,
    #[error("Invalid request: {0}")]
    BadRequest(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Request timeout")]
    Timeout,
    #[error("Length required")]
    LengthRequired,
    #[error("Payload too large")]
    PayloadTooLarge,
    #[error("Too many requests; retry after {retry_after_secs}s")]
    TooManyRequests { retry_after_secs: u64 },
    #[error("Internal server error")]
    Internal,
}

pub type Result<T> = std::result::Result<T, AppError>;
