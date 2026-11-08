use crate::api::AppState;
use crate::api::middleware::AuthUser;
use crate::api::schemas::messaging::parse_send_request;
use crate::error::{AppError, Result};
use crate::proto::obscura::v1 as proto;
use axum::{body::Bytes, extract::State, http::HeaderMap, response::IntoResponse};
use prost::Message;
use uuid::Uuid;

/// Sends a batch of encrypted messages.
///
/// # Errors
/// Returns `AppError::BadRequest` if the request protobuf is malformed or missing the idempotency key.
/// Returns `AppError::PayloadTooLarge` if the batch size exceeds the limit.
pub(crate) async fn send_messages(
    auth: AuthUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse> {
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("Missing idempotency-key header".to_string()))
        .and_then(|s| Uuid::parse_str(s).map_err(|e| AppError::BadRequest(format!("Invalid idempotency-key: {e}"))))?;

    let request = proto::SendMessageRequest::decode(body)
        .map_err(|e| AppError::BadRequest(format!("Invalid SendMessageRequest protobuf: {e}")))?;

    let batch_limit = state.config.messaging.send_batch_limit.get();
    let recipients = parse_send_request(auth.device_id, batch_limit, request)?;

    let outcome = state.message_service.send(auth.user_id, auth.device_id, idempotency_key, recipients).await?;

    Ok(proto::SendMessageResponse::from(outcome).encode_to_vec())
}
