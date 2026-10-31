#![allow(unreachable_pub)]
pub(crate) mod ack_batcher;
pub(crate) mod message_pump;
pub(crate) mod prekey_pump;
pub(crate) mod session;

use crate::adapters::redis::RedisCache;
use crate::config::WsConfig;
use crate::error::{AppError, Result};
use crate::proto::obscura::v1 as proto;
use crate::services::device_service::DeviceService;
use crate::services::gateway::session::Session;
use crate::services::key_service::KeyService;
use crate::services::message_service::MessageService;
use crate::services::notification_service::NotificationService;
use axum::extract::ws::{Message as WsMessage, WebSocket};
use opentelemetry::{
    global,
    metrics::{Counter, Histogram, UpDownCounter},
};
use prost::Message as ProstMessage;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub(crate) struct Metrics {
    pub(crate) ack_batch_size: Histogram<u64>,
    pub(crate) outbound_dropped_total: Counter<u64>,
    pub(crate) active_connections: UpDownCounter<i64>,
    pub(crate) ack_queue_dropped_total: Counter<u64>,
    pub(crate) acks_received_total: Counter<u64>,
}

impl Metrics {
    #[must_use]
    pub(crate) fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            ack_batch_size: meter
                .u64_histogram("obscura_websocket_ack_batch_size")
                .with_description("Size of ACK batches processed")
                .build(),
            outbound_dropped_total: meter
                .u64_counter("obscura_websocket_outbound_dropped_total")
                .with_description("Total messages dropped due to full outbound buffer")
                .build(),
            active_connections: meter
                .i64_up_down_counter("obscura_websocket_connections")
                .with_description("Number of active WebSocket connections")
                .build(),
            ack_queue_dropped_total: meter
                .u64_counter("obscura_websocket_ack_dropped_total")
                .with_description("Total ACKs dropped due to full buffer")
                .build(),
            acks_received_total: meter
                .u64_counter("obscura_websocket_acks_received_total")
                .with_description("Total ACKs received from clients")
                .build(),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GatewayService {
    message_service: MessageService,
    key_service: KeyService,
    device_service: DeviceService,
    notifier: NotificationService,
    ticket_cache: RedisCache,
    config: WsConfig,
    metrics: Metrics,
}

impl GatewayService {
    #[must_use]
    pub(crate) fn new(
        message_service: MessageService,
        key_service: KeyService,
        device_service: DeviceService,
        notifier: NotificationService,
        ticket_cache: RedisCache,
        config: WsConfig,
    ) -> Self {
        Self { message_service, key_service, device_service, notifier, ticket_cache, config, metrics: Metrics::new() }
    }

    /// Generates and caches a single-use connection ticket for `device_id`.
    ///
    /// # Errors
    /// Returns `AppError::Internal` if the ticket cannot be cached.
    pub(crate) async fn issue_ticket(&self, device_id: Uuid) -> Result<String> {
        let ticket = Uuid::new_v4().to_string();
        self.ticket_cache.set(&ticket, device_id.to_string().as_bytes()).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to cache websocket ticket");
            AppError::Internal
        })?;
        Ok(ticket)
    }

    /// Consumes a single-use ticket and returns its device if that device still exists.
    pub(crate) async fn redeem_ticket(&self, ticket: &str) -> std::result::Result<Uuid, String> {
        let bytes = match self.ticket_cache.take(ticket).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Err("Ticket not found or expired".to_string()),
            Err(e) => {
                tracing::error!(error = %e, "Failed to read ticket from cache");
                return Err("Internal server error".to_string());
            }
        };
        let id_str = String::from_utf8(bytes).map_err(|_| "Invalid UTF-8 in cache".to_string())?;
        let device_id = Uuid::parse_str(&id_str).map_err(|_| "Invalid device ID format in cache".to_string())?;
        match self.device_service.device_exists(device_id).await {
            Ok(true) => Ok(device_id),
            Ok(false) => Err("Ticket device no longer exists".to_string()),
            Err(e) => {
                tracing::error!(error = %e, "Failed to check the ticket's device");
                Err("Internal server error".to_string())
            }
        }
    }

    pub async fn handle_socket(
        &self,
        mut socket: WebSocket,
        device_id: Uuid,
        request_id: String,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        // Clients need to know if they are low on pre-keys immediately upon connection
        // to prevent exhausting their bundle during an active session.
        match self.key_service.check_pre_key_status(device_id).await {
            Ok(Some(status)) => {
                let frame = proto::WebSocketFrame {
                    payload: Some(proto::web_socket_frame::Payload::PreKeyStatus(proto::PreKeyStatus {
                        one_time_pre_key_count: status.one_time_pre_key_count,
                        min_threshold: status.min_threshold,
                    })),
                };
                let mut buf = Vec::new();
                if frame.encode(&mut buf).is_ok() {
                    let _ = socket.send(WsMessage::Binary(buf.into())).await;
                }
            }

            Err(e) => {
                tracing::warn!(error = %e, "Failed to check pre-key status");
            }
            _ => {}
        }

        // 3. Hand over to Session
        let session = Session {
            device_id,
            request_id,
            socket,
            message_service: self.message_service.clone(),
            key_service: self.key_service.clone(),
            notifier: self.notifier.clone(),
            metrics: self.metrics.clone(),
            config: self.config.clone(),
            shutdown_rx,
        };

        session.run().await;
    }
}
