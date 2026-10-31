use crate::adapters::redis::NotificationRepository;
use crate::config::NotificationConfig;
use crate::domain::notification::DeviceEvent;
use dashmap::DashMap;
use opentelemetry::{
    KeyValue, global,
    metrics::{Counter, Histogram, UpDownCounter},
};
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Clone, Debug)]
struct Metrics {
    sends_total: Counter<u64>,
    received_total: Counter<u64>,
    unrouted_total: Counter<u64>,
    active_channels: UpDownCounter<i64>,
    cleanup_duration_seconds: Histogram<f64>,
    cleanup_reclaimed_total: Counter<u64>,
}

impl Metrics {
    fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            sends_total: meter
                .u64_counter("obscura_notifications_sent_total")
                .with_description("Total notification send attempts")
                .build(),
            received_total: meter
                .u64_counter("obscura_notifications_received_total")
                .with_description("Total notifications received from PubSub")
                .build(),
            unrouted_total: meter
                .u64_counter("obscura_notifications_unrouted_total")
                .with_description("Notifications received from PubSub with no local subscribers")
                .build(),
            active_channels: meter
                .i64_up_down_counter("obscura_notification_channels")
                .with_description("Number of active local notification channels")
                .build(),
            cleanup_duration_seconds: meter
                .f64_histogram("obscura_notification_cleanup_duration_seconds")
                .with_description("Time taken to perform a single cleanup iteration")
                .build(),
            cleanup_reclaimed_total: meter
                .u64_counter("obscura_notification_channels_reclaimed_total")
                .with_description("Total number of stale channels reclaimed by cleanup")
                .build(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct NotificationService {
    repo: Arc<NotificationRepository>,
    channels: Arc<DashMap<Uuid, broadcast::Sender<DeviceEvent>>>,
    device_channel_capacity: usize,
    push_delay_secs: u64,
    metrics: Metrics,
}

impl NotificationService {
    /// Creates a new notification service handle.
    #[must_use]
    pub fn new(repo: Arc<NotificationRepository>, config: &NotificationConfig) -> Self {
        Self {
            repo,
            channels: Arc::new(DashMap::new()),
            device_channel_capacity: config.device_channel_capacity,
            push_delay_secs: config.push_delay_secs,
            metrics: Metrics::new(),
        }
    }

    /// Dispatches an external real-time notification to local subscribers.
    pub fn dispatch_event(&self, notification: &crate::domain::notification::RealtimeNotification) {
        let device_id = notification.device_id;
        let event = notification.event;
        let event_label = format!("{event:?}");

        self.metrics.received_total.add(1, &[KeyValue::new("event", event_label.clone())]);

        if let Some(tx) = self.channels.get(&device_id) {
            tracing::trace!(%device_id, ?event, "Dispatched notification to local channel");
            let _ = tx.send(event);
        } else {
            tracing::debug!(%device_id, ?event, "No local subscriber for notification");
            self.metrics.unrouted_total.add(1, &[KeyValue::new("event", event_label)]);
        }
    }

    /// Performs a cleanup cycle to reclaim stale notification channels.
    pub fn perform_cleanup(&self) {
        let start = std::time::Instant::now();
        tracing::debug!("Starting notification channel cleanup cycle");
        let mut reclaimed_this_cycle = 0;

        self.channels.retain(|_, sender| {
            let active = sender.receiver_count() > 0;
            if !active {
                self.metrics.active_channels.add(-1, &[]);
                reclaimed_this_cycle += 1;
            }
            active
        });

        let duration = start.elapsed().as_secs_f64();
        self.metrics.cleanup_duration_seconds.record(duration, &[]);

        if reclaimed_this_cycle > 0 {
            self.metrics.cleanup_reclaimed_total.add(reclaimed_this_cycle, &[]);
            tracing::info!(reclaimed = reclaimed_this_cycle, "Notification channel cleanup reclaimed stale channels");
        }
        tracing::debug!(duration_secs = %duration, "Notification channel cleanup cycle completed");
    }

    #[tracing::instrument(skip(self), fields(device.id = %device_id))]
    pub async fn subscribe(&self, device_id: Uuid) -> broadcast::Receiver<DeviceEvent> {
        let tx = self
            .channels
            .entry(device_id)
            .or_insert_with(|| {
                self.metrics.active_channels.add(1, &[]);
                let (tx, _rx) = broadcast::channel(self.device_channel_capacity);
                tx
            })
            .value()
            .clone();

        tx.subscribe()
    }

    #[tracing::instrument(skip(self, recipients), fields(count = recipients.len(), event = ?event))]
    pub async fn notify(&self, recipients: &[Uuid], event: DeviceEvent) {
        if recipients.is_empty() {
            return;
        }

        // Fast Path: WebSocket/PubSub
        if let Err(e) = self.repo.publish_realtime(recipients, event).await {
            tracing::error!(error = %e, "Failed to batch publish to PubSub");
            self.metrics.sends_total.add(recipients.len() as u64, &[KeyValue::new("status", "error")]);
        } else {
            self.metrics.sends_total.add(recipients.len() as u64, &[KeyValue::new("status", "sent")]);
        }

        // Slow Path: Scheduled Push Fallback
        if (event == DeviceEvent::MessageReceived || event == DeviceEvent::PreKeyLow)
            && let Err(e) = self.repo.push_jobs(recipients, self.push_delay_secs).await
        {
            tracing::error!(error = %e, "Failed to batch schedule push notifications");
        }
    }

    #[tracing::instrument(skip(self), fields(device.id = %device_id))]
    pub async fn cancel_pending_notifications(&self, device_id: Uuid) {
        if let Err(e) = self.repo.cancel_job(device_id).await {
            tracing::error!(error = %e, "Failed to cancel pending push notification");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::watch;

    #[tokio::test]
    async fn test_run_cleanup_reclaims_stale_channels() {
        crate::telemetry::init_test_telemetry();

        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let config = NotificationConfig::default();

        let pubsub =
            crate::adapters::redis::RedisClient::new(&crate::config::PubSubConfig::default(), 1024, shutdown_rx)
                .await
                .expect("Redis client creation");

        let repo = Arc::new(NotificationRepository::new(pubsub, &config));
        let service = NotificationService::new(repo, &config);

        // 1. Setup channels
        let device_id_active = Uuid::new_v4();
        let device_id_stale = Uuid::new_v4();

        let (tx_active, _rx_active) = broadcast::channel(10);
        let (tx_stale, rx_stale) = broadcast::channel(10);

        service.channels.insert(device_id_active, tx_active);
        service.channels.insert(device_id_stale, tx_stale);

        // 2. Make one stale by dropping its last receiver
        drop(rx_stale);

        // Check initial state
        assert_eq!(service.channels.len(), 2);

        // 3. Perform cleanup
        service.perform_cleanup();

        // 4. Verify results
        assert_eq!(service.channels.len(), 1, "Cleanup should have reclaimed exactly 1 channel");
        assert!(service.channels.contains_key(&device_id_active), "Active channel should remain");
        assert!(!service.channels.contains_key(&device_id_stale), "Stale channel should be gone");
    }
}
