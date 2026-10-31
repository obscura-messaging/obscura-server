use crate::error::Result;
use crate::services::attachment_service::AttachmentService;
use std::time::Duration;
use tracing::Instrument;

#[derive(Clone, Debug)]
pub struct AttachmentCleanupWorker {
    service: AttachmentService,
    cleanup_interval_secs: u64,
}

impl AttachmentCleanupWorker {
    #[must_use]
    pub const fn new(service: AttachmentService, cleanup_interval_secs: u64) -> Self {
        Self { service, cleanup_interval_secs }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(self.cleanup_interval_secs));

        while !*shutdown.borrow() {
            tokio::select! {
                _ = interval.tick() => {
                    async {
                        tracing::debug!("Running attachment cleanup cycle...");

                        if let Err(e) = self.cleanup_batch().await {
                            tracing::error!(error = %e, "Attachment cleanup cycle failed");
                        }
                    }
                    .instrument(tracing::info_span!("run_attachment_cleanup"))
                    .await;
                }
                _ = shutdown.changed() => {}
            }
        }
        tracing::info!("Attachment cleanup loop shutting down...");
    }

    /// Runs a single batch of attachment cleanup via [`AttachmentService`].
    ///
    /// # Errors
    /// Returns an error if the database or storage operations fail.
    pub async fn cleanup_batch(&self) -> Result<u64> {
        self.service.cleanup_expired().await
    }
}
