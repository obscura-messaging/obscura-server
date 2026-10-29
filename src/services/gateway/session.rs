use crate::config::WsConfig;
use crate::domain::notification::UserEvent;
use crate::proto::obscura::v1 as proto;
use crate::services::gateway::{Metrics, ack_batcher::AckBatcher, message_pump::MessagePump, prekey_pump::PreKeyPump};
use crate::services::key_service::KeyService;
use crate::services::message_service::MessageService;
use crate::services::notification_service::NotificationService;
use axum::extract::ws::{Message as WsMessage, WebSocket};
use futures::{SinkExt, StreamExt};
use prost::Message;
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

pub struct Session {
    pub device_id: Uuid,
    pub request_id: String,
    pub socket: WebSocket,
    pub message_service: MessageService,
    pub key_service: KeyService,
    pub notifier: NotificationService,
    pub metrics: Metrics,
    pub config: WsConfig,
    pub shutdown_rx: tokio::sync::watch::Receiver<bool>,
}

impl Session {
    #[tracing::instrument(
        name = "websocket_session",
        skip(self),
        fields(
            device.id = %self.device_id,
            request.id = %self.request_id,
            otel.kind = "server",
            ws.session_id = %Uuid::new_v4()
        )
    )]
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn run(self) {
        // Destructuring allows independent mutable access to fields while the socket
        // is split into sink and stream halves.
        let Self {
            device_id, socket, message_service, key_service, notifier, metrics, config, mut shutdown_rx, ..
        } = self;

        metrics.active_connections.add(1, &[]);
        tracing::info!("WebSocket connected");

        // Immediately cancel any pending push notifications since the device is now connected.
        notifier.cancel_pending_notifications(device_id).await;

        let mut notification_rx = notifier.subscribe(device_id).await;
        let (mut ws_sink, mut ws_stream) = socket.split();

        // Components are initialized here inside the 'websocket_session' span
        // to ensure they are recorded as child spans in traces.
        let (outbound_tx, mut outbound_rx) = mpsc::channel(config.outbound_buffer_size);

        let ack_batcher = AckBatcher::new(
            device_id,
            message_service.clone(),
            metrics.clone(),
            config.ack_buffer_size,
            config.ack_batch_size,
            config.ack_flush_interval_ms,
        );

        let message_pump = MessagePump::new(
            device_id,
            message_service.clone(),
            outbound_tx.clone(),
            metrics.clone(),
            crate::services::gateway::message_pump::PumpTuning {
                batch_limit: config.message_fetch_batch_size,
                max_batch_bytes: config.max_batch_bytes,
                retry_budget: std::time::Duration::from_millis(config.fetch_retry_budget_ms),
            },
        );

        let prekey_pump =
            PreKeyPump::new(device_id, key_service.clone(), outbound_tx.clone(), config.prekey_debounce_interval_ms);

        message_pump.notify();

        let mut last_seen = tokio::time::Instant::now();
        let mut ping_interval = tokio::time::interval(std::time::Duration::from_secs(config.ping_interval_secs.max(1)));
        // First tick happens immediately, we skip it to start probing after the first interval.
        ping_interval.tick().await;
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            // Priority is given to shutdown and high-frequency events to ensure
            // the server remains responsive to control signals.
            if *shutdown_rx.borrow() {
                tracing::info!("Shutdown signal received, closing WebSocket");
                let _ = ws_sink
                    .send(WsMessage::Close(Some(axum::extract::ws::CloseFrame {
                        code: axum::extract::ws::close_code::AWAY,
                        reason: "Server shutting down".into(),
                    })))
                    .await;
                break;
            }

            tokio::select! {
                biased;

                _ = shutdown_rx.changed() => {}

                _ = ping_interval.tick() => {
                    let now = tokio::time::Instant::now();
                    let timeout = std::time::Duration::from_secs(config.ping_interval_secs + config.ping_timeout_secs);

                    if now.duration_since(last_seen) > timeout {
                        tracing::warn!(
                            last_seen_secs = %now.duration_since(last_seen).as_secs(),
                            "WebSocket connection timed out (no pong/activity), closing"
                        );
                        break;
                    }

                    if ws_sink.send(WsMessage::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }

                msg = ws_stream.next() => {
                    let continue_loop = match msg {
                        Some(Ok(msg)) => {
                            last_seen = tokio::time::Instant::now();
                            match msg {
                                WsMessage::Binary(bin) => {
                                    if let Ok(frame) = proto::WebSocketFrame::decode(bin.as_ref()) {
                                        if let Some(proto::web_socket_frame::Payload::Ack(ack)) = frame.payload {
                                            let mut uuids = Vec::new();

                                            if !ack.message_ids.is_empty() {
                                                metrics.acks_received_total.add(1, &[]);
                                            }
                                            for id_bytes in ack.message_ids {
                                                if let Ok(id) = Uuid::from_slice(&id_bytes) {
                                                    uuids.push(id);
                                                } else {
                                                    tracing::warn!(
                                                        len = id_bytes.len(),
                                                        hex = %hex::encode(&id_bytes),
                                                        "Received ACK with invalid UUID bytes in list (expected 16)"
                                                    );
                                                }
                                            }

                                            if !uuids.is_empty() {
                                                // Immediately cancel push notifications to avoid "phantom buzzes"
                                                // Run as fire-and-forget task to avoid blocking the WebSocket loop
                                                let notifier_clone = notifier.clone();
                                                tokio::spawn(async move {
                                                    notifier_clone.cancel_pending_notifications(device_id).await;
                                                });
                                                ack_batcher.push(uuids);
                                            }
                                        } else {
                                            tracing::warn!("Received unexpected Protobuf payload type");
                                        }
                                    } else {
                                        tracing::warn!("Failed to decode WebSocket frame");
                                    }
                                    true
                                }
                                WsMessage::Text(t) => {
                                    tracing::warn!("Received unexpected text message: {}", t);
                                    true
                                }
                                WsMessage::Ping(_) => {
                                    tracing::debug!("Received heartbeat ping from client");
                                    // axum automatically responds with Pong to protocol-level Pings
                                    true
                                }
                                WsMessage::Pong(_) => {
                                    tracing::debug!("Received heartbeat pong from client");
                                    true
                                }
                                WsMessage::Close(_) => false,
                            }
                        }
                        Some(Err(_)) | None => false,
                    };

                    if !continue_loop { break; }
                }

                msg = outbound_rx.recv() => {
                    match msg {
                        Some(msg) => {
                            if ws_sink.send(msg).await.is_err() { break; }
                        }
                        None => break,
                    }
                }

                result = notification_rx.recv() => {
                    let continue_loop = match result {
                        Ok(UserEvent::MessageReceived) => {
                            message_pump.notify();
                            true
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            // If the channel lagged (burst of events), we safely trigger both pumps
                            // because we don't know which event we missed. The pumps will debounce.
                            message_pump.notify();
                            prekey_pump.notify();
                            true
                        }
                        Ok(UserEvent::PreKeyLow) => {
                            prekey_pump.notify();
                            true
                        }
                        Ok(UserEvent::Disconnect) | Err(broadcast::error::RecvError::Closed) => false,
                    };

                     if !continue_loop { break; }
                }
            }
        }

        let _ = ws_sink.close().await;

        metrics.active_connections.add(-1, &[]);
        tracing::info!("WebSocket disconnected");
    }
}
