use crate::adapters::push::{PushError, PushProvider};
use crate::config::NotificationConfig;
use crate::services::notification_service::NotificationService;
use crate::services::push_token_service::PushTokenService;
use opentelemetry::{KeyValue, global, metrics::Counter};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};
use tracing::Instrument;
use uuid::Uuid;

#[derive(Clone, Debug)]
struct Metrics {
    sent: Counter<u64>,
    errors: Counter<u64>,
    invalidated_tokens: Counter<u64>,
}

impl Metrics {
    fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            sent: meter
                .u64_counter("obscura_push_notifications_sent_total")
                .with_description("Total number of push notifications successfully sent")
                .build(),
            errors: meter
                .u64_counter("obscura_push_notification_errors_total")
                .with_description("Total number of push notification delivery errors")
                .build(),
            invalidated_tokens: meter
                .u64_counter("obscura_push_invalid_tokens_total")
                .with_description("Total number of push tokens removed due to being unregistered")
                .build(),
        }
    }
}

#[derive(Debug)]
pub struct PushNotificationWorker {
    notification_service: NotificationService,
    push_token_service: PushTokenService,
    provider: Arc<dyn PushProvider>,
    interval_secs: u64,
    visibility_timeout_secs: u64,
    invalid_token_cleanup_interval_secs: u64,
    invalid_token_cleanup_batch_size: usize,
    invalid_token_cleanup_channel_capacity: usize,
    semaphore: Arc<Semaphore>,
    metrics: Metrics,
}

impl PushNotificationWorker {
    pub fn new(
        notification_service: NotificationService,
        push_token_service: PushTokenService,
        provider: Arc<dyn PushProvider>,
        config: &NotificationConfig,
    ) -> Self {
        Self {
            notification_service,
            push_token_service,
            provider,
            interval_secs: config.worker_interval_secs,
            visibility_timeout_secs: config.visibility_timeout_secs,
            invalid_token_cleanup_interval_secs: config.invalid_token_cleanup_interval_secs,
            invalid_token_cleanup_batch_size: config.invalid_token_cleanup_batch_size,
            invalid_token_cleanup_channel_capacity: config.invalid_token_cleanup_channel_capacity,
            semaphore: Arc::new(Semaphore::new(config.worker_concurrency)),
            metrics: Metrics::new(),
        }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(self.invalid_token_cleanup_interval_secs));
        let (invalid_token_tx, mut invalid_token_rx) =
            mpsc::channel::<String>(self.invalid_token_cleanup_channel_capacity);

        let mut cleanup_batch = Vec::new();

        tracing::info!("Push notification worker started");

        while !*shutdown.borrow() {
            tokio::select! {
                _ = shutdown.changed() => break,

                _ = interval.tick() => {
                    if let Err(e) = self.process_due_jobs(invalid_token_tx.clone())
                        .instrument(tracing::debug_span!("process_push_jobs"))
                        .await
                    {
                        tracing::error!(error = %e, "Failed to process due notification jobs");
                    }
                }

                _ = cleanup_interval.tick() => {
                    async {
                        Self::flush_invalid_tokens(&self.push_token_service, &mut cleanup_batch).await;
                    }
                    .instrument(tracing::debug_span!("flush_invalid_tokens"))
                    .await;
                }

                res = invalid_token_rx.recv() => {
                    if let Some(token) = res {
                        cleanup_batch.push(token);
                        if cleanup_batch.len() >= self.invalid_token_cleanup_batch_size {
                            Self::flush_invalid_tokens(&self.push_token_service, &mut cleanup_batch).await;
                        }
                    }
                }
            }
        }

        tracing::info!("Push notification worker shutting down...");

        // Final cleanup
        Self::flush_invalid_tokens(&self.push_token_service, &mut cleanup_batch).await;
    }

    #[tracing::instrument(level = "debug", skip(push_token_service, batch))]
    async fn flush_invalid_tokens(push_token_service: &PushTokenService, batch: &mut Vec<String>) {
        if batch.is_empty() {
            return;
        }

        let count = batch.len();
        if let Err(e) = push_token_service.delete_tokens_batch(batch).await {
            tracing::error!(error = %e, "Failed to delete invalid token batch");
        } else {
            tracing::info!(count, "Successfully deleted invalid tokens in batch");
            batch.clear();
        }
    }

    /// Processes a batch of due push notification jobs.
    ///
    /// # Errors
    /// Returns an error if the scheduler or database operation fails.
    #[tracing::instrument(level = "debug", skip(self, invalid_token_tx), name = "process_due_jobs", err)]
    pub async fn process_due_jobs(&self, invalid_token_tx: mpsc::Sender<String>) -> anyhow::Result<()> {
        let available = self.semaphore.available_permits();
        if available == 0 {
            return Ok(());
        }

        // We poll up to 'available' jobs, which is naturally capped by worker_concurrency
        let limit = available.cast_signed();
        // If the worker crashes, the job will become visible again after this period.
        let device_ids = self.notification_service.lease_due_push_jobs(limit, self.visibility_timeout_secs).await?;

        if device_ids.is_empty() {
            tracing::debug!("No due push notification jobs found");
            return Ok(());
        }

        tracing::info!(count = device_ids.len(), "Processing leased push notifications");

        // 1. Batch lookup tokens for all devices
        let device_token_pairs = self.push_token_service.find_tokens_for_devices(&device_ids).await?;

        let devices_with_tokens: std::collections::HashSet<Uuid> =
            device_token_pairs.iter().map(|(id, _)| *id).collect();

        // 2. Identify and remove jobs for devices who have no token
        for device_id in &device_ids {
            if !devices_with_tokens.contains(device_id) {
                tracing::info!(%device_id, "Device has no registered push token, removing job");
                let _ = self.notification_service.complete_push_job(*device_id).await;
            }
        }

        // 3. Dispatch concurrently, bounded by the semaphore
        for (device_id, token) in device_token_pairs {
            let provider = Arc::clone(&self.provider);
            let notification_service = self.notification_service.clone();
            let metrics = self.metrics.clone();
            let tx = invalid_token_tx.clone();

            // Acquire a permit before spawning.
            let permit = Arc::clone(&self.semaphore)
                .acquire_owned()
                .await
                .map_err(|e| anyhow::anyhow!("Semaphore closed: {e}"))?;

            tokio::spawn(
                async move {
                    let _permit = permit;

                    match provider.send_push(&token).await {
                        Ok(()) => {
                            tracing::debug!("Push notification sent successfully");
                            metrics.sent.add(1, &[]);
                            // Success: Remove job from Redis
                            let _ = notification_service.complete_push_job(device_id).await;
                        }
                        Err(PushError::Unregistered) => {
                            tracing::info!("Token unregistered, reporting to invalid token cleanup");
                            metrics.invalidated_tokens.add(1, &[]);

                            // Definitively failed: Remove job from Redis anyway
                            let _ = notification_service.complete_push_job(device_id).await;

                            // Send to cleanup for batch DB deletion
                            let _ = tx.send(token).await;
                        }
                        Err(PushError::QuotaExceeded) => {
                            tracing::warn!("Push quota exceeded, allowing visibility timeout to trigger retry");
                            metrics.errors.add(1, &[KeyValue::new("reason", "quota_exceeded")]);
                            // We do NOT delete the job; it will be retried when the lease expires.
                        }
                        Err(PushError::Other(e)) => {
                            tracing::error!(error = %e, "Failed to send push notification, will retry");
                            metrics.errors.add(1, &[KeyValue::new("reason", "other")]);
                            // We do NOT delete the job; it will be retried when the lease expires.
                        }
                    }
                }
                .instrument(tracing::debug_span!("dispatch_push", %device_id)),
            );
        }

        Ok(())
    }
}
