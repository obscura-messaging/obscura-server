use crate::adapters::database::DbPool;
use crate::adapters::database::attachment_repo::AttachmentRepository;
use crate::adapters::storage::{ObjectStorage, StorageError, StorageStream};
use crate::config::AttachmentConfig;
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
    pub(crate) deleted: Counter<u64>,
    pub(crate) cleanup_errors: Counter<u64>,
}

impl Metrics {
    fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            uploaded_bytes: meter
                .u64_counter("obscura_attachment_upload_bytes_total")
                .with_description("Total bytes of attachments uploaded")
                .build(),
            upload_size_bytes: meter
                .u64_histogram("obscura_attachment_upload_size_bytes")
                .with_description("Distribution of attachment upload sizes")
                .build(),
            deleted: meter
                .u64_counter("obscura_attachments_deleted_total")
                .with_description("Total number of expired attachments deleted from storage")
                .build(),
            cleanup_errors: meter
                .u64_counter("obscura_attachment_cleanup_errors_total")
                .with_description("Total number of errors encountered during attachment cleanup")
                .build(),
        }
    }
}

#[derive(Clone)]
pub struct AttachmentService {
    pool: DbPool,
    repo: AttachmentRepository,
    storage: Arc<dyn ObjectStorage>,
    attachment_config: AttachmentConfig,
    ttl_days: i64,
    metrics: Metrics,
}

impl std::fmt::Debug for AttachmentService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentService")
            .field("attachment_config", &self.attachment_config)
            .field("ttl_days", &self.ttl_days)
            .field("metrics", &self.metrics)
            .finish_non_exhaustive()
    }
}

impl AttachmentService {
    #[must_use]
    pub fn new(
        pool: DbPool,
        repo: AttachmentRepository,
        storage: Arc<dyn ObjectStorage>,
        attachment_config: AttachmentConfig,
        ttl_days: i64,
    ) -> Self {
        Self { pool, repo, storage, attachment_config, ttl_days, metrics: Metrics::new() }
    }

    /// Uploads an attachment to storage.
    ///
    /// # Errors
    /// Returns `AppError::BadRequest` if the attachment is too small.
    /// Returns `AppError::PayloadTooLarge` if the attachment is too large.
    /// Returns `AppError::Internal` if there is an error during upload or database operation.
    #[tracing::instrument(
        err(level = "warn"),
        skip(self, stream),
        fields(attachment_id = tracing::field::Empty, attachment_size = tracing::field::Empty)
    )]
    pub(crate) async fn upload(&self, content_len: Option<usize>, stream: StorageStream) -> Result<(Uuid, i64)> {
        if let Some(len) = content_len {
            tracing::Span::current().record("attachment_size", len);
            if len < self.attachment_config.min_size_bytes {
                return Err(AppError::BadRequest("Attachment too small".into()));
            }
            if len > self.attachment_config.max_size_bytes {
                return Err(AppError::PayloadTooLarge);
            }
        }

        let id = Uuid::new_v4();
        let key = format!("{}{}", self.attachment_config.prefix, id);
        tracing::Span::current().record("attachment_id", tracing::field::display(id));

        let put_future = self.storage.put(
            &key,
            stream,
            content_len,
            self.attachment_config.min_size_bytes,
            self.attachment_config.max_size_bytes,
        );

        let actual_len = put_future.await.map_err(|e| match e {
            StorageError::ExceedsLimit => AppError::PayloadTooLarge,
            StorageError::BelowMinSize => AppError::BadRequest("Attachment too small".into()),
            _ => AppError::Internal,
        })?;

        let expires_at = OffsetDateTime::now_utc() + Duration::days(self.ttl_days);
        let mut conn = self.pool.acquire().await?;
        self.repo.create(&mut conn, id, expires_at).await?;

        tracing::debug!(attachment_id = %id, expires_at = %expires_at, "Attachment uploaded");

        self.metrics.uploaded_bytes.add(actual_len, &[]);
        self.metrics.upload_size_bytes.record(actual_len, &[]);

        Ok((id, expires_at.unix_timestamp()))
    }

    /// Downloads an attachment from storage.
    #[tracing::instrument(
        err(level = "warn"),
        skip(self),
        fields(attachment_id = %id, attachment_size = tracing::field::Empty)
    )]
    pub(crate) async fn download(&self, id: Uuid) -> Result<(u64, StorageStream)> {
        let mut conn = self.pool.acquire().await?;
        if !self.repo.exists_unexpired(&mut conn, id).await? {
            return Err(AppError::NotFound);
        }
        drop(conn);

        // Stream from Storage
        let key = format!("{}{}", self.attachment_config.prefix, id);
        let (content_length, stream) = self.storage.get(&key).await.map_err(|e| match e {
            StorageError::NotFound => AppError::NotFound,
            _ => AppError::Internal,
        })?;

        tracing::Span::current().record("attachment_size", content_length);

        tracing::debug!("Attachment download successful");
        Ok((content_length, stream))
    }

    /// Deletes expired attachments in batches, removing each object from storage before deleting its
    /// database row so failed storage deletes are retried rather than orphaned.
    ///
    /// # Errors
    /// Returns an error if a database operation fails.
    #[tracing::instrument(err, skip(self), fields(total_deleted = tracing::field::Empty))]
    pub async fn cleanup_expired(&self) -> Result<u64> {
        use tracing::Instrument;

        let mut total_deleted = 0;
        let batch_limit = i64::try_from(self.attachment_config.cleanup_batch_size).unwrap_or(i64::MAX);

        loop {
            let ids = {
                let mut conn = self.pool.acquire().await.inspect_err(|_| {
                    self.metrics.cleanup_errors.add(1, &[]);
                })?;
                self.repo.fetch_expired(&mut conn, batch_limit).await.inspect_err(|_| {
                    self.metrics.cleanup_errors.add(1, &[]);
                })?
            };

            if ids.is_empty() {
                break;
            }

            tracing::info!(count = %ids.len(), "Found expired attachments to delete");

            let count = ids.len();
            for id in ids {
                let key = format!("{}{}", self.attachment_config.prefix, id);
                let res: Result<bool> = async {
                    if let Err(e) = self.storage.delete(&key).await {
                        tracing::warn!(error = ?e, key = %key, "Storage delete error");
                        return Ok(false);
                    }

                    let mut conn = self.pool.acquire().await?;
                    self.repo.delete(&mut conn, id).await?;
                    Ok(true)
                }
                .instrument(tracing::debug_span!("delete_attachment", attachment_id = %id))
                .await;

                match res {
                    Ok(true) => total_deleted += 1,
                    Ok(false) => {}
                    Err(e) => {
                        self.metrics.cleanup_errors.add(1, &[]);
                        return Err(e);
                    }
                }
            }
            tracing::info!(deleted_count = %count, "Attachment cleanup batch completed successfully");
        }

        if total_deleted > 0 {
            self.metrics.deleted.add(total_deleted, &[]);
            tracing::Span::current().record("total_deleted", total_deleted);
        }

        Ok(total_deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::storage::StorageResult;
    use async_trait::async_trait;
    use bytes::Bytes;
    use futures::StreamExt;

    /// Fails every upload with one error. `S3Storage` returns these when a streamed body breaks a size limit,
    /// which the API cannot trigger because it requires a matching `Content-Length` and checks it first.
    struct FailingStorage(fn() -> StorageError);

    #[async_trait]
    impl ObjectStorage for FailingStorage {
        async fn put(
            &self,
            _key: &str,
            _stream: StorageStream,
            _content_len: Option<usize>,
            _min_size: usize,
            _max_size: usize,
        ) -> StorageResult<u64> {
            Err((self.0)())
        }

        async fn get(&self, _key: &str) -> StorageResult<(u64, StorageStream)> {
            Err(StorageError::NotFound)
        }

        async fn delete(&self, _key: &str) -> StorageResult<()> {
            Ok(())
        }
    }

    async fn upload_error(error: fn() -> StorageError) -> AppError {
        // Never connects: the storage error is returned before the database is used.
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").expect("Valid test pool");
        let service = AttachmentService::new(
            pool,
            AttachmentRepository::new(),
            Arc::new(FailingStorage(error)),
            AttachmentConfig::default(),
            30,
        );
        let stream: StorageStream = futures::stream::iter([Ok(Bytes::from_static(b"data"))]).boxed();
        service.upload(None, stream).await.expect_err("a storage error should fail the upload")
    }

    #[tokio::test]
    async fn test_upload_maps_storage_errors() {
        assert!(matches!(upload_error(|| StorageError::ExceedsLimit).await, AppError::PayloadTooLarge));
        assert!(matches!(upload_error(|| StorageError::BelowMinSize).await, AppError::BadRequest(_)));
        assert!(matches!(upload_error(|| StorageError::Internal("boom".into())).await, AppError::Internal));
    }
}
