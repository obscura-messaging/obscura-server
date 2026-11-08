use crate::error::AppError;
use crate::services::auth_service::AuthService;
use crate::services::device_service::DeviceService;
use std::num::NonZeroU64;
use std::time::Duration;
use tracing::Instrument;

#[derive(Debug)]
pub struct RefreshTokenCleanupWorker {
    auth_service: AuthService,
    device_service: DeviceService,
    cleanup_interval_secs: NonZeroU64,
}

impl RefreshTokenCleanupWorker {
    #[must_use]
    pub const fn new(
        auth_service: AuthService,
        device_service: DeviceService,
        cleanup_interval_secs: NonZeroU64,
    ) -> Self {
        Self { auth_service, device_service, cleanup_interval_secs }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(self.cleanup_interval_secs.get()));

        while !*shutdown.borrow() {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.perform_cleanup()
                        .instrument(tracing::info_span!("run_refresh_token_cleanup"))
                        .await
                    {
                        tracing::error!(error = ?e, "Refresh token cleanup iteration failed");
                    }
                }
                _ = shutdown.changed() => {}
            }
        }
        tracing::info!("Refresh token cleanup loop shutting down...");
    }

    /// Periodically cleans up expired refresh tokens and link sessions.
    ///
    /// # Errors
    /// Returns an error if the database connection or query fails.
    #[tracing::instrument(skip(self), err, fields(expired_deleted = tracing::field::Empty, link_sessions_deleted = tracing::field::Empty))]
    pub async fn perform_cleanup(&self) -> Result<(), AppError> {
        tracing::debug!("Running refresh token and link session cleanup...");

        match self.auth_service.cleanup_expired_refresh_tokens().await {
            Ok(count) => {
                if count > 0 {
                    tracing::info!(count = %count, "Deleted expired refresh tokens");
                    tracing::Span::current().record("expired_deleted", count);
                }
            }
            Err(e) => tracing::error!(error = ?e, "Cleanup error (refresh tokens)"),
        }

        match self.device_service.cleanup_expired_link_sessions().await {
            Ok(count) => {
                if count > 0 {
                    tracing::info!(count = %count, "Deleted expired link sessions");
                    tracing::Span::current().record("link_sessions_deleted", count);
                }
            }
            Err(e) => tracing::error!(error = ?e, "Cleanup error (link sessions)"),
        }

        Ok(())
    }
}
