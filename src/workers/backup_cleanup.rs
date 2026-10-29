use crate::adapters::database::DbPool;
use crate::adapters::database::backup_repo::BackupRepository;
use crate::adapters::storage::ObjectStorage;
use crate::config::BackupConfig;
use crate::error::{AppError, Result};
use opentelemetry::{global, metrics::Counter};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};
use tracing::Instrument;

#[derive(Clone, Debug)]
struct Metrics {
    cleanup_runs: Counter<u64>,
    cleaned_items: Counter<u64>,
    errors: Counter<u64>,
}

impl Metrics {
    fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            cleanup_runs: meter.u64_counter("obscura_backup_cleanup_runs").build(),
            cleaned_items: meter.u64_counter("obscura_backup_cleanup_cleaned").build(),
            errors: meter.u64_counter("obscura_backup_cleanup_errors").build(),
        }
    }
}

#[derive(Clone)]
pub struct BackupCleanupWorker {
    pool: DbPool,
    repo: BackupRepository,
    storage: Arc<dyn ObjectStorage>,
    backup_config: BackupConfig,
    metrics: Metrics,
}

impl std::fmt::Debug for BackupCleanupWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupCleanupWorker")
            .field("backup_config", &self.backup_config)
            .field("metrics", &self.metrics)
            .finish_non_exhaustive()
    }
}

impl BackupCleanupWorker {
    #[must_use]
    pub fn new(
        pool: DbPool,
        repo: BackupRepository,
        storage: Arc<dyn ObjectStorage>,
        backup_config: BackupConfig,
    ) -> Self {
        Self { pool, repo, storage, backup_config, metrics: Metrics::new() }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(StdDuration::from_secs(self.backup_config.cleanup_interval_secs));

        while !*shutdown.borrow() {
            tokio::select! {
                _ = interval.tick() => {
                    async {
                        tracing::debug!("Running backup cleanup...");
                        match self.cleanup_stale().await {
                            Ok(count) => {
                                if count > 0 {
                                    self.metrics.cleaned_items.add(count, &[]);
                                }
                                self.metrics.cleanup_runs.add(1, &[]);
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "Backup cleanup failed");
                                self.metrics.errors.add(1, &[]);
                            }
                        }
                    }
                    .instrument(tracing::info_span!("run_backup_cleanup"))
                    .await;
                }
                _ = shutdown.changed() => {}
            }
        }
        tracing::info!("Backup cleanup shutting down...");
    }

    /// Cleans up stale "UPLOADING" backup records.
    ///
    /// # Errors
    /// Returns an error if the database or storage operations fail.
    #[tracing::instrument(
        err,
        skip(self),
        fields(total_cleaned = tracing::field::Empty)
    )]
    pub async fn cleanup_stale(&self) -> Result<u64> {
        let mut total_cleaned = 0;
        let threshold = OffsetDateTime::now_utc() - Duration::minutes(self.backup_config.stale_threshold_mins);

        loop {
            let mut conn = self.pool.acquire().await.map_err(AppError::Database)?;
            let stale_backups = self.repo.fetch_stale_uploads(&mut conn, threshold, 50).await?;

            if stale_backups.is_empty() {
                break;
            }

            for backup in stale_backups {
                let device_id = backup.device_id;
                let pending_version = backup.pending_version.unwrap_or(0);

                match self.repo.reset_stale(&mut conn, device_id, threshold).await {
                    Ok(true) => {
                        if pending_version > 0 {
                            let key = format!("{}{}/v{}", self.backup_config.prefix, device_id, pending_version);
                            if let Err(e) = self.storage.delete(&key).await {
                                tracing::warn!(error = ?e, key = %key, "Failed to delete stale backup from storage");
                            }
                        }
                        total_cleaned += 1;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        tracing::error!(error = ?e, "device.id" = %device_id, "Failed to reset stale backup in DB");
                    }
                }
            }
        }

        if total_cleaned > 0 {
            tracing::Span::current().record("total_cleaned", total_cleaned);
        }

        Ok(total_cleaned)
    }
}
