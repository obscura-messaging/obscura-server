use crate::api::AppState;
use crate::domain::auth::Jwt;
use crate::error::AppError;
use axum::http::HeaderValue;
use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use tower_http::request_id::{MakeRequestId, RequestId};
use uuid::Uuid;

#[derive(Debug)]
pub struct AuthUser {
    pub(crate) user_id: Uuid,
    pub(crate) device_id: Option<Uuid>,
}

/// Authenticated caller with a user-scoped token (no `device_id` claim).
#[derive(Debug)]
pub struct UserAuth {
    pub(crate) user_id: Uuid,
}

/// Authenticated caller with a device-scoped token.
#[derive(Debug)]
pub struct DeviceAuth {
    pub(crate) user_id: Uuid,
    pub(crate) device_id: Uuid,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    #[tracing::instrument(err, skip(parts, state))]
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let auth_header = parts.headers.get(header::AUTHORIZATION).ok_or(AppError::AuthError)?;

        let auth_str = auth_header.to_str().map_err(|_| AppError::AuthError)?;

        if !auth_str.starts_with("Bearer ") {
            return Err(AppError::AuthError);
        }

        let token = &auth_str[7..];
        let jwt = Jwt::new(token.to_string());

        let (user_id, device_id) = state.auth_service.authenticate(&jwt).await?;

        tracing::Span::current().record("user.id", tracing::field::display(user_id));
        if let Some(did) = device_id {
            tracing::Span::current().record("device.id", tracing::field::display(did));
        }

        Ok(Self { user_id, device_id })
    }
}

impl FromRequestParts<AppState> for UserAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let auth = AuthUser::from_request_parts(parts, state).await?;
        if auth.device_id.is_some() {
            return Err(AppError::Forbidden("User-scoped token required".into()));
        }
        Ok(Self { user_id: auth.user_id })
    }
}

impl FromRequestParts<AppState> for DeviceAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let auth = AuthUser::from_request_parts(parts, state).await?;
        let device_id = auth.device_id.ok_or_else(|| AppError::Forbidden("Device-scoped token required".into()))?;
        Ok(Self { user_id: auth.user_id, device_id })
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
