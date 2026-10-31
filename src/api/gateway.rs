use crate::api::AppState;
use crate::api::schemas::gateway::{TicketResponse, WsParams};
use axum::{
    extract::{Query, State, ws::WebSocketUpgrade},
    http::Extensions,
    response::IntoResponse,
};
use tower_http::request_id::RequestId;

/// Generates a connection ticket for the WebSocket gateway.
///
/// # Errors
/// Returns `AppError::Internal` if the ticket cannot be cached.
pub(crate) async fn generate_ticket(
    auth: crate::api::middleware::AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, crate::error::AppError> {
    let ticket = state.gateway_service.issue_ticket(auth.device_id).await?;
    Ok((axum::http::StatusCode::CREATED, axum::Json(TicketResponse { ticket })))
}

pub(crate) async fn websocket_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsParams>,
    extensions: Extensions,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let request_id = extensions
        .get::<RequestId>()
        .map_or_else(|| "unknown".to_string(), |id| id.header_value().to_str().unwrap_or_default().to_string());

    match state.gateway_service.redeem_ticket(&params.ticket).await {
        Ok(device_id) => ws.on_upgrade(move |socket| {
            let service = state.gateway_service.clone();
            let shutdown = state.shutdown_rx.clone();
            async move {
                service.handle_socket(socket, device_id, request_id, shutdown).await;
            }
        }),
        Err(e) => {
            tracing::warn!(error = %e, "WebSocket handshake failed: invalid ticket");
            axum::http::StatusCode::UNAUTHORIZED.into_response()
        }
    }
}
