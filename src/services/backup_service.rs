use crate::adapters::database::DbPool;
use crate::adapters::database::backup_repo::BackupRepository;
use crate::adapters::storage::{ObjectStorage, StorageError, StorageStream};
use crate::config::BackupConfig;
use crate::domain::backup::BackupState;
use crate::error::{AppError, Result};
use opentelemetry::{
    global,
    metrics::{Counter, Histogram},
};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub(crate) struct Metrics {
    pub(crate) uploaded_bytes: Counter<u64>,
    pub(crate) upload_size_bytes: Histogram<u64>,
}

impl Metrics {
    fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            uploaded_bytes: meter
                .u64_counter("obscura_backup_upload_bytes_total")
                .with_description("Total bytes of backups uploaded")
                .build(),
            upload_size_bytes: meter
                .u64_histogram("obscura_backup_upload_size_bytes")
                .with_description("Distribution of backup upload sizes")
                .build(),
        }
    }
}

#[derive(Clone)]
pub struct BackupService {
    pool: DbPool,
    repo: BackupRepository,
    storage: Arc<dyn ObjectStorage>,
    backup_config: BackupConfig,
    metrics: Metrics,
}

impl std::fmt::Debug for BackupService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupService")
            .field("backup_config", &self.backup_config)
            .field("metrics", &self.metrics)
            .finish_non_exhaustive()
    }
}

impl BackupService {
    #[must_use]
    pub fn new(
        pool: DbPool,
        repo: BackupRepository,
        storage: Arc<dyn ObjectStorage>,
        backup_config: BackupConfig,
    ) -> Self {
        Self { pool, repo, storage, backup_config, metrics: Metrics::new() }
    }

    /// Handles the full backup upload workflow.
    ///
    /// # Errors
    /// Returns `AppError::BadRequest` if the backup is too small.
    /// Returns `AppError::PayloadTooLarge` if the backup is too large.
    /// Returns `AppError::PreconditionFailed` if the version does not match.
    /// Returns `AppError::Conflict` if another upload is in progress.
    #[tracing::instrument(
        err(level = "warn"),
        skip(self, stream),
        fields(device.id = %device_id, version = %if_match_version)
    )]
    pub async fn handle_upload(
        &self,
        device_id: Uuid,
        if_match_version: i32,
        content_len: Option<usize>,
        stream: StorageStream,
    ) -> Result<i32> {
        if let Some(len) = content_len {
            if len < self.backup_config.min_size_bytes {
                return Err(AppError::BadRequest("Backup too small".into()));
            }
            if len > self.backup_config.max_size_bytes {
                return Err(AppError::PayloadTooLarge);
            }
        }

        let mut conn = self.pool.acquire().await.map_err(AppError::Database)?;

        let _ = self.repo.create_if_not_exists(&mut conn, device_id).await?;

        let backup = if let Some(b) = self.repo.reserve_active_slot(&mut conn, device_id, if_match_version).await? {
            b
        } else {
            let current = self.repo.find_by_device_id(&mut conn, device_id).await?.ok_or(AppError::Internal)?;

            if current.current_version != if_match_version {
                return Err(AppError::PreconditionFailed);
            }

            if current.state == BackupState::Uploading {
                let pending_at = current.pending_at.unwrap_or_else(OffsetDateTime::now_utc);
                let threshold = OffsetDateTime::now_utc() - Duration::minutes(self.backup_config.stale_threshold_mins);

                if pending_at > threshold {
                    return Err(AppError::Conflict("Upload already in progress".into()));
                }

                // Takeover
                self.repo.reserve_slot_force(&mut conn, device_id).await?
            } else {
                return Err(AppError::Conflict("Concurrent modification".into()));
            }
        };

        drop(conn);

        let pending_version = backup.pending_version.ok_or(AppError::Internal)?;
        let key = format!("{}{}/v{}", self.backup_config.prefix, device_id, pending_version);

        let put_future = self.storage.put(
            &key,
            stream,
            content_len,
            self.backup_config.min_size_bytes,
            self.backup_config.max_size_bytes,
        );

        let actual_len = put_future.await.map_err(|e| match e {
            StorageError::ExceedsLimit => AppError::PayloadTooLarge,
            StorageError::BelowMinSize => AppError::BadRequest("Backup too small".into()),
            _ => AppError::Internal,
        })?;

        let mut conn = self.pool.acquire().await.map_err(AppError::Database)?;
        self.repo.commit_version(&mut conn, device_id, pending_version).await?;

        // Record metrics
        self.metrics.uploaded_bytes.add(actual_len, &[]);
        self.metrics.upload_size_bytes.record(actual_len, &[]);

        // Cleanup old version
        let old_version = backup.current_version;
        if old_version > 0 {
            let old_key = format!("{}{}/v{}", self.backup_config.prefix, device_id, old_version);
            let storage = Arc::clone(&self.storage);
            tokio::spawn(async move {
                let _ = storage.delete(&old_key).await;
            });
        }

        Ok(pending_version)
    }

    /// Downloads the current backup for the device.
    ///
    /// # Errors
    /// Returns `AppError::NotFound` if no backup exists or the current version is 0.
    #[tracing::instrument(err(level = "warn"), skip(self), fields(device.id = %device_id))]
    pub async fn download(&self, device_id: Uuid) -> Result<(i32, u64, StorageStream)> {
        let mut conn = self.pool.acquire().await.map_err(AppError::Database)?;
        let backup = self.repo.find_by_device_id(&mut conn, device_id).await?;

        if let Some(backup) = backup {
            if backup.current_version == 0 {
                return Err(AppError::NotFound);
            }

            let key = format!("{}{}/v{}", self.backup_config.prefix, device_id, backup.current_version);
            let (len, stream) = self.storage.get(&key).await.map_err(|e| match e {
                StorageError::NotFound => AppError::NotFound,
                _ => AppError::Internal,
            })?;
            tracing::debug!(version = %backup.current_version, size = %len, "Backup download started");
            Ok((backup.current_version, len, stream))
        } else {
            Err(AppError::NotFound)
        }
    }

    /// Checks for the existence of a backup.
    ///
    /// # Errors
    /// Returns `AppError::NotFound` if no backup exists or the current version is 0.
    #[tracing::instrument(err(level = "warn"), skip(self), fields(device.id = %device_id))]
    pub async fn head(&self, device_id: Uuid) -> Result<(i32, u64)> {
        let mut conn = self.pool.acquire().await.map_err(AppError::Database)?;
        let backup = self.repo.find_by_device_id(&mut conn, device_id).await?;

        if let Some(backup) = backup {
            if backup.current_version == 0 {
                return Err(AppError::NotFound);
            }

            let key = format!("{}{}/v{}", self.backup_config.prefix, device_id, backup.current_version);
            let len = self.storage.head(&key).await.map_err(|e| match e {
                StorageError::NotFound => AppError::NotFound,
                _ => AppError::Internal,
            })?;
            tracing::debug!(version = %backup.current_version, size = %len, "Backup metadata retrieved");
            Ok((backup.current_version, len))
        } else {
            Err(AppError::NotFound)
        }
    }

    /// Returns the current version of the device's backup if it exists.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the query fails.
    pub async fn get_current_version(&self, device_id: Uuid) -> Result<Option<i32>> {
        let mut conn = self.pool.acquire().await.map_err(AppError::Database)?;
        let backup = self.repo.find_by_device_id(&mut conn, device_id).await?;
        Ok(backup.map(|b| b.current_version))
    }

    /// Fetches the backup record of a device inside an existing transaction before the device is deleted.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the query fails.
    pub(crate) async fn find_for_device(
        &self,
        conn: &mut sqlx::PgConnection,
        device_id: Uuid,
    ) -> Result<Option<crate::domain::backup::Backup>> {
        self.repo.find_by_device_id(conn, device_id).await
    }

    /// Fetches all backup records for a user's devices inside an existing transaction before the devices are deleted.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the query fails.
    pub(crate) async fn find_for_user(
        &self,
        conn: &mut sqlx::PgConnection,
        user_id: Uuid,
    ) -> Result<Vec<crate::domain::backup::Backup>> {
        self.repo.find_by_user_id(conn, user_id).await
    }

    /// Deletes the stored S3 backup objects (active and pending) for deleted devices.
    pub(crate) async fn delete_device_objects(&self, backups: &[crate::domain::backup::Backup]) {
        for backup in backups {
            for version in [Some(backup.current_version), backup.pending_version].into_iter().flatten() {
                if version > 0 {
                    let key = format!("{}{}/v{}", self.backup_config.prefix, backup.device_id, version);
                    if let Err(e) = self.storage.delete(&key).await {
                        tracing::warn!(error = ?e, key = %key, "Failed to delete backup object of deleted device");
                    }
                }
            }
        }
    }
}
