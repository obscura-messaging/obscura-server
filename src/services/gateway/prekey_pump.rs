use crate::proto::obscura::v1 as proto;
use crate::services::key_service::KeyService;
use axum::extract::ws::Message as WsMessage;
use prost::Message as ProstMessage;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::Instrument;
use uuid::Uuid;

/// `PreKeyPump` coalesces multiple `PreKeyLow` notifications into a single background
/// database poll and delayed WebSocket frame to avoid overwhelming the client UI
/// with repetitive status updates when a large number of keys are consumed concurrently.
pub struct PreKeyPump {
    notify_tx: mpsc::Sender<()>,
}

impl PreKeyPump {
    pub fn new(
        device_id: Uuid,
        key_service: KeyService,
        outbound_tx: mpsc::Sender<WsMessage>,
        debounce_interval_ms: u64,
    ) -> Self {
        // Channel size 1 effectively drops notifications while a fetch is in progress or sleeping.
        let (notify_tx, notify_rx) = mpsc::channel(1);

        tokio::spawn(
            async move {
                Self::run_background(device_id, notify_rx, key_service, outbound_tx, debounce_interval_ms).await;
            }
            .instrument(tracing::info_span!("prekey_pump", "device.id" = %device_id)),
        );

        Self { notify_tx }
    }

    pub fn notify(&self) {
        let _ = self.notify_tx.try_send(());
    }

    async fn run_background(
        device_id: Uuid,
        mut rx: mpsc::Receiver<()>,
        key_service: KeyService,
        outbound_tx: mpsc::Sender<WsMessage>,
        debounce_interval_ms: u64,
    ) {
        while rx.recv().await.is_some() {
            // 1. Wait to allow concurrent key consumptions to settle
            tokio::time::sleep(Duration::from_millis(debounce_interval_ms)).await;

            // 2. Drain any redundant notifications that piled up during sleep
            while rx.try_recv().is_ok() {}

            // 3. Query the database once and send the frame
            match key_service.check_pre_key_status(device_id).await {
                Ok(Some(status)) => {
                    // If outbound_tx is closed (user disconnected), we just break and exit
                    let frame = proto::WebSocketFrame::from(status).encode_to_vec();
                    if outbound_tx.send(WsMessage::Binary(frame.into())).await.is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    // User is no longer low (refilled keys during the 500ms window)
                    tracing::debug!("PreKeyLow event coalesced, but user is no longer low on keys");
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to check pre-key status for coalesced frame");
                }
            }
        }
    }
}
