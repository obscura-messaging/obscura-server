use crate::api::AppState;
use crate::domain::auth::{Caller, Jwt};
use crate::error::AppError;
use axum::http::HeaderValue;
use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use tower_http::request_id::{MakeRequestId, RequestId};
use uuid::Uuid;

impl FromRequestParts<AppState> for Caller {
    type Rejection = AppError;

    #[tracing::instrument(err, skip(parts, state))]
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let auth_header = parts.headers.get(header::AUTHORIZATION).ok_or(AppError::Unauthorized)?;

        let auth_str = auth_header.to_str().map_err(|_| AppError::Unauthorized)?;

        if !auth_str.starts_with("Bearer ") {
            return Err(AppError::Unauthorized);
        }

        let token = &auth_str[7..];
        let jwt = Jwt::new(token.to_string());

        let caller = state.auth_service.authenticate(&jwt).await?;

        tracing::Span::current().record("user.id", tracing::field::display(caller.user_id()));
        tracing::Span::current().record("device.id", tracing::field::display(caller.device_id()));

        Ok(caller)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MakeRequestUuidOrHeader;

impl MakeRequestId for MakeRequestUuidOrHeader {
    fn make_request_id<B>(&mut self, request: &axum::http::Request<B>) -> Option<RequestId> {
        let header_value = request.headers().get("x-request-id").cloned().unwrap_or_else(|| {
            let uuid = Uuid::new_v4().to_string();
            HeaderValue::from_str(&uuid).expect("Invalid UUID generated for request ID")
        });

        Some(RequestId::new(header_value))
    }
}
