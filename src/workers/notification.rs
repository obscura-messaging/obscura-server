use crate::services::notification_service::NotificationService;
use opentelemetry::{global, metrics::Counter};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::sync::watch;
use tracing::Instrument;

#[derive(Clone, Debug)]
struct Metrics {
    processed_total: Counter<u64>,
}

impl Metrics {
    fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            processed_total: meter
                .u64_counter("obscura_notification_worker_processed_total")
                .with_description("Total number of notifications processed by the worker loop")
                .build(),
        }
    }
}

#[derive(Debug)]
pub struct NotificationWorker {
    service: NotificationService,
    cleanup_interval_secs: u64,
    metrics: Option<Metrics>,
}

impl NotificationWorker {
    #[must_use]
    pub const fn new(service: NotificationService, cleanup_interval_secs: u64) -> Self {
        Self { service, cleanup_interval_secs, metrics: None }
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        self.metrics = Some(Metrics::new());
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(self.cleanup_interval_secs));

        let mut notification_rx = match self.service.subscribe_realtime().await {
            Ok(rx) => rx,
            Err(e) => {
                tracing::error!(error = %e, "Failed to subscribe to real-time notifications, worker exiting");
                return;
            }
        };

        tracing::info!("Notification worker started");

        loop {
            tokio::select! {
                _ = shutdown.changed() => break,

                _ = cleanup_interval.tick() => {
                    async {
                        self.service.perform_cleanup();
                    }
                    .instrument(tracing::debug_span!("run_notification_cleanup"))
                    .await;
                }

                result = notification_rx.recv() => {
                    match result {
                        Ok(notification) => {
                            let device_id = notification.device_id;
                            let event = format!("{:?}", notification.event);

                            async {
                                self.service.dispatch_event(&notification);
                                if let Some(ref m) = self.metrics {
                                    m.processed_total.add(1, &[]);
                                }
                            }
                            .instrument(tracing::debug_span!("dispatch_notification", %device_id, %event))
                            .await;
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(missed = n, "Internal notification dispatcher lagged");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::error!("Notification stream closed, worker exiting");
                            break;
                        }
                    }
                }
            }
        }

        tracing::info!("Notification worker shutting down...");
    }
}
