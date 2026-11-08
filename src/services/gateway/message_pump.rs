use crate::error::Result;
use crate::proto::obscura::v1 as proto;
use crate::services::gateway::Metrics;
use crate::services::message_service::MessageService;
use axum::extract::ws::Message as WsMessage;
use opentelemetry::KeyValue;
use prost::Message as ProstMessage;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::Instrument;
use uuid::Uuid;

/// Multiplied by the attempt number, so retries back off linearly.
const FETCH_RETRY_BASE: Duration = Duration::from_millis(250);

/// Tuning for one pump, grouped so it threads through as a single parameter.
#[derive(Clone, Copy, Debug)]
pub struct PumpTuning {
    pub batch_limit: NonZeroU32,
    pub max_batch_bytes: usize,
    /// How long one delivery notification keeps retrying a failed read before it is abandoned.
    pub retry_budget: Duration,
}

/// `MessagePump` coalesces multiple delivery notifications into a single background
/// database poll to avoid overwhelming the database with redundant queries.
pub struct MessagePump {
    notify_tx: mpsc::Sender<()>,
}

impl MessagePump {
    pub fn new(
        device_id: Uuid,
        message_service: MessageService,
        outbound_tx: mpsc::Sender<WsMessage>,
        metrics: Metrics,
        tuning: PumpTuning,
    ) -> Self {
        // Channel size 1 effectively coalesces notifications while a fetch is in progress.
        let (notify_tx, notify_rx) = mpsc::channel(1);

        tokio::spawn(
            async move {
                Self::run_background(device_id, notify_rx, message_service, outbound_tx, metrics, tuning).await;
            }
            .instrument(tracing::info_span!("message_pump", "device.id" = %device_id)),
        );

        Self { notify_tx }
    }

    pub fn notify(&self) {
        let _ = self.notify_tx.try_send(());
    }

    async fn run_background(
        device_id: Uuid,
        mut rx: mpsc::Receiver<()>,
        message_service: MessageService,
        outbound_tx: mpsc::Sender<WsMessage>,
        metrics: Metrics,
        tuning: PumpTuning,
    ) {
        let mut cursor: Option<(time::OffsetDateTime, Uuid)> = None;

        while rx.recv().await.is_some() {
            Self::drain(device_id, &message_service, &outbound_tx, &metrics, tuning, &mut cursor).await;
        }
    }

    /// Fetches until the backlog is drained, retrying a read that fails.
    ///
    /// The retry is the point. This pump is edge-triggered, so the notification that woke it is
    /// already consumed by the time a fetch fails — without a retry the envelope waits for an
    /// unrelated future event, which for an idle conversation means until the client reconnects.
    ///
    /// Bounded by wall time rather than an attempt count, because attempts multiply by the pool's
    /// acquire timeout — five attempts is five seconds or twenty depending on a setting in another
    /// module. Giving up is survivable: the row is still in Postgres, the scheduled push fallback
    /// still fires, and the next notification or reconnect delivers it.
    async fn drain(
        device_id: Uuid,
        service: &MessageService,
        outbound_tx: &mpsc::Sender<WsMessage>,
        metrics: &Metrics,
        tuning: PumpTuning,
        cursor: &mut Option<(time::OffsetDateTime, Uuid)>,
    ) {
        let mut failures = 0;
        let started = Instant::now();

        loop {
            match Self::flush_batch(device_id, service, outbound_tx, metrics, tuning, cursor).await {
                // A full batch means there is more waiting.
                Ok(true) => failures = 0,
                Ok(false) => return,
                Err(e) => {
                    failures += 1;
                    let remaining = tuning.retry_budget.saturating_sub(started.elapsed());
                    if remaining.is_zero() {
                        tracing::warn!(
                            device.id = %device_id,
                            error = %e,
                            "Giving up on this delivery notification; messages wait for the next trigger"
                        );
                        return;
                    }
                    // Clamped so the budget bounds the wall clock rather than only the decision to
                    // start another attempt. An in-flight acquire can still overrun it by its own
                    // timeout; the sleep should not add to that.
                    tokio::time::sleep((FETCH_RETRY_BASE * failures).min(remaining)).await;
                }
            }
        }
    }

    #[tracing::instrument(
        skip(service, outbound_tx, metrics, cursor),
        fields(device.id = %device_id, batch.count = tracing::field::Empty)
    )]
    async fn flush_batch(
        device_id: Uuid,
        service: &MessageService,
        outbound_tx: &mpsc::Sender<WsMessage>,
        metrics: &Metrics,
        tuning: PumpTuning,
        cursor: &mut Option<(time::OffsetDateTime, Uuid)>,
    ) -> Result<bool> {
        let messages = service.fetch_pending_batch(device_id, *cursor, i64::from(tuning.batch_limit.get())).await?;

        if messages.is_empty() {
            return Ok(false);
        }

        let batch_size = messages.len();
        tracing::Span::current().record("batch.count", batch_size);

        if let Some(last_msg) = messages.last() {
            *cursor = Some((last_msg.created_at, last_msg.id));
        }

        let envelopes: Vec<proto::Envelope> = messages
            .into_iter()
            .map(|msg| proto::Envelope {
                id: msg.id.as_bytes().to_vec(),
                sender_user_id: msg.sender_user_id.as_bytes().to_vec(),
                sender_device_id: msg.sender_device_id.as_bytes().to_vec(),
                timestamp: u64::try_from(msg.created_at.unix_timestamp_nanos() / 1_000_000).unwrap_or(0),
                message: msg.content,
            })
            .collect();

        // Split envelopes into sub-batches that stay under the WebSocket frame
        // size limit, sending each as a separate EnvelopeBatch frame.
        let mut current_batch: Vec<proto::Envelope> = Vec::new();
        let mut current_size: usize = 0;

        for envelope in envelopes {
            let envelope_size = envelope.encoded_len();

            if !current_batch.is_empty() && current_size + envelope_size > tuning.max_batch_bytes {
                Self::send_batch(std::mem::take(&mut current_batch), outbound_tx, metrics).await;
                current_size = 0;
            }

            current_size += envelope_size;
            current_batch.push(envelope);
        }

        if !current_batch.is_empty() {
            Self::send_batch(current_batch, outbound_tx, metrics).await;
        }

        // A batch too long to count in a u32 is certainly full.
        Ok(u32::try_from(batch_size).map_or(true, |n| n >= tuning.batch_limit.get()))
    }

    /// Sends one frame, counting anything it could not deliver.
    ///
    /// A drop here is not recoverable at this layer and does not need to be: the only way the
    /// channel closes is the session ending, and the rows are unacked, so the next connection's
    /// pump refetches them from `cursor = None`.
    async fn send_batch(envelopes: Vec<proto::Envelope>, outbound_tx: &mpsc::Sender<WsMessage>, metrics: &Metrics) {
        let batch = proto::EnvelopeBatch { envelopes };
        let frame = proto::WebSocketFrame { payload: Some(proto::web_socket_frame::Payload::EnvelopeBatch(batch)) };
        let mut buf = Vec::new();

        if let Err(err) = frame.encode(&mut buf) {
            metrics.outbound_dropped_total.add(1, &[KeyValue::new("reason", "encode_failed")]);
            tracing::warn!(error = ?err, "failed to encode outbound websocket frame");
            return;
        }

        if outbound_tx.send(WsMessage::Binary(buf.into())).await.is_err() {
            metrics.outbound_dropped_total.add(1, &[KeyValue::new("reason", "channel_closed")]);
        }
    }
}
