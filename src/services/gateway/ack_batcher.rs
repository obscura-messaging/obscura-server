use crate::services::gateway::Metrics;
use crate::services::message_service::MessageService;
use std::num::NonZeroUsize;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::Instrument;
use uuid::Uuid;

/// `AckBatcher` decouples fast WebSocket ACKs from slow database deletes and
/// reduces database overhead by batching multiple deletions into a single query.
pub struct AckBatcher {
    tx: mpsc::Sender<Uuid>,
    metrics: Metrics,
}

impl AckBatcher {
    pub fn new(
        device_id: Uuid,
        message_service: MessageService,
        metrics: Metrics,
        buffer_size: NonZeroUsize,
        batch_size: NonZeroUsize,
        flush_interval_ms: u64,
    ) -> Self {
        let (tx, rx) = mpsc::channel(buffer_size.get());

        let batcher_metrics = metrics.clone();
        tokio::spawn(
            async move {
                Self::run_background(device_id, rx, message_service, batcher_metrics, batch_size, flush_interval_ms)
                    .await;
            }
            .instrument(tracing::info_span!("ack_batcher", "device.id" = %device_id)),
        );

        Self { tx, metrics }
    }

    pub fn push(&self, msg_ids: Vec<Uuid>) {
        for msg_id in msg_ids {
            if self.tx.try_send(msg_id).is_err() {
                tracing::warn!(message_id = %msg_id, "Dropped ACK due to full buffer");
                self.metrics.ack_queue_dropped_total.add(1, &[]);
            }
        }
    }

    async fn run_background(
        device_id: Uuid,
        mut rx: mpsc::Receiver<Uuid>,
        message_service: MessageService,
        metrics: Metrics,
        batch_size: NonZeroUsize,
        flush_interval_ms: u64,
    ) {
        loop {
            let mut batch = Vec::new();

            // Unconditionally wait for the first item. This prevents busy-waiting
            // and waking up the CPU on idle connections.
            match rx.recv().await {
                Some(id) => batch.push(id),
                None => return, // Channel closed cleanly, nothing to flush
            }

            // Once we have at least one item, start the flush timer.
            let timeout = tokio::time::sleep(Duration::from_millis(flush_interval_ms));
            tokio::pin!(timeout);

            loop {
                if batch.len() >= batch_size.get() {
                    break;
                }

                tokio::select! {
                    res = rx.recv() => {
                        if let Some(id) = res {
                            batch.push(id);
                        } else {
                            // Channel closed, flush whatever we have right now and exit
                            Self::flush_batch(device_id, &message_service, &metrics, batch).await;
                            return;
                        }
                    }
                    () = &mut timeout => break,
                }
            }

            Self::flush_batch(device_id, &message_service, &metrics, batch).await;
        }
    }

    async fn flush_batch(device_id: Uuid, message_service: &MessageService, metrics: &Metrics, batch: Vec<Uuid>) {
        if !batch.is_empty() {
            tracing::debug!(batch_size = batch.len(), "Flushing ACK batch");
            metrics.ack_batch_size.record(batch.len() as u64, &[]);
            if let Err(e) = message_service.delete_batch(device_id, &batch).await {
                tracing::error!(error = %e, "Failed to delete message batch");
            }
        }
    }
}
