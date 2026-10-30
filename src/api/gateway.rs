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
    let ticket = uuid::Uuid::new_v4().to_string();
    state.ws_ticket_cache.set(&ticket, auth.device_id.to_string().as_bytes()).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to cache websocket ticket");
        crate::error::AppError::Internal
    })?;

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

    match redeem_ticket(&state, &params.ticket).await {
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

/// Takes a ticket so it can be used only once, and returns its device if that device still exists.
async fn redeem_ticket(state: &AppState, ticket: &str) -> Result<uuid::Uuid, String> {
    let bytes = match state.ws_ticket_cache.take(ticket).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Err("Ticket not found or expired".to_string()),
        Err(e) => {
            tracing::error!(error = %e, "Failed to read ticket from cache");
            return Err("Internal server error".to_string());
        }
    };
    let id_str = String::from_utf8(bytes).map_err(|_| "Invalid UTF-8 in cache".to_string())?;
    let device_id = uuid::Uuid::parse_str(&id_str).map_err(|_| "Invalid device ID format in cache".to_string())?;
    match state.device_service.device_exists(device_id).await {
        Ok(true) => Ok(device_id),
        Ok(false) => Err("Ticket device no longer exists".to_string()),
        Err(e) => {
            tracing::error!(error = %e, "Failed to check the ticket's device");
            Err("Internal server error".to_string())
        }
    }
}
