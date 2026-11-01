use crate::error::AppError;
use crate::services::message_service::MessageService;
use std::time::Duration;
use tracing::Instrument;

#[derive(Debug)]
pub struct MessageCleanupWorker {
    service: MessageService,
    cleanup_interval_secs: u64,
}

impl MessageCleanupWorker {
    #[must_use]
    pub const fn new(service: MessageService, cleanup_interval_secs: u64) -> Self {
        Self { service, cleanup_interval_secs }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(self.cleanup_interval_secs));

        while !*shutdown.borrow() {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.perform_cleanup()
                        .instrument(tracing::info_span!("run_message_cleanup"))
                        .await
                    {
                        tracing::error!(error = ?e, "Message cleanup iteration failed");
                    }
                }
                _ = shutdown.changed() => {}
            }
        }
        tracing::info!("Message cleanup loop shutting down...");
    }

    /// Periodically cleans up expired messages and enforces inbox limits via [`MessageService`].
    ///
    /// # Errors
    /// Returns an error if the database connection or query fails.
    pub async fn perform_cleanup(&self) -> Result<(), AppError> {
        self.service.cleanup_expired_and_overflow().await
    }
}
