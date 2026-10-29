use crate::adapters::database::DbPool;
use crate::adapters::database::link_session_repo::LinkSessionRepository;
use crate::adapters::database::refresh_token_repo::RefreshTokenRepository;
use crate::error::AppError;
use std::time::Duration;
use tracing::Instrument;

#[derive(Debug)]
pub struct RefreshTokenCleanupWorker {
    pool: DbPool,
    repo: RefreshTokenRepository,
    link_session_repo: LinkSessionRepository,
    cleanup_interval_secs: u64,
}

impl RefreshTokenCleanupWorker {
    #[must_use]
    pub const fn new(
        pool: DbPool,
        repo: RefreshTokenRepository,
        link_session_repo: LinkSessionRepository,
        cleanup_interval_secs: u64,
    ) -> Self {
        Self { pool, repo, link_session_repo, cleanup_interval_secs }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        if self.cleanup_interval_secs == 0 {
            tracing::info!("Refresh token cleanup is disabled (interval = 0)");
            return;
        }

        let mut interval = tokio::time::interval(Duration::from_secs(self.cleanup_interval_secs));

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

        let res = if let Ok(mut conn) = self.pool.acquire().await {
            self.repo.delete_expired(&mut conn).await
        } else {
            Err(AppError::Internal)
        };

        match res {
            Ok(count) => {
                if count > 0 {
                    tracing::info!(count = %count, "Deleted expired refresh tokens");
                    tracing::Span::current().record("expired_deleted", count);
                }
            }
            Err(e) => tracing::error!(error = ?e, "Cleanup error (refresh tokens)"),
        }

        let link_res = if let Ok(mut conn) = self.pool.acquire().await {
            self.link_session_repo.delete_expired(&mut conn).await
        } else {
            Err(AppError::Internal)
        };

        match link_res {
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
