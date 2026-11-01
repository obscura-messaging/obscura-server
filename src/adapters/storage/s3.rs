use crate::adapters::storage::{ObjectStorage, StorageError, StorageResult, StorageStream};
use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use futures::StreamExt;
use http_body_util::StreamBody;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::mpsc;
use tracing::Instrument;

#[derive(Clone, Debug)]
pub struct S3Storage {
    client: Client,
    bucket: String,
}

impl S3Storage {
    #[must_use]
    pub const fn new(client: Client, bucket: String) -> Self {
        Self { client, bucket }
    }
}

#[async_trait]
impl ObjectStorage for S3Storage {
    #[tracing::instrument(
        level = "debug",
        err,
        skip(self, stream),
        fields(key = %key, bucket = %self.bucket)
    )]
    async fn put(
        &self,
        key: &str,
        mut stream: StorageStream,
        content_len: Option<usize>,
        min_size: usize,
        max_size: usize,
    ) -> StorageResult<u64> {
        let (tx, rx) = mpsc::channel(2);
        let limit_exceeded = Arc::new(AtomicBool::new(false));
        let total_uploaded = Arc::new(AtomicU64::new(0));

        let limit_signal = Arc::clone(&limit_exceeded);
        let total_signal = Arc::clone(&total_uploaded);

        let bridge_handle = tokio::spawn(
            async move {
                let mut current_total = 0;
                while let Some(item) = stream.next().await {
                    match item {
                        Ok(bytes) => {
                            current_total += u64::try_from(bytes.len()).unwrap_or(0);
                            if current_total > u64::try_from(max_size).unwrap_or(u64::MAX) {
                                tracing::warn!(current_total = %current_total, max_size = %max_size, "Size limit exceeded in bridge task");
                                limit_signal.store(true, Ordering::SeqCst);
                                break;
                            }
                            total_signal.store(current_total, Ordering::SeqCst);
                            if tx.send(Ok(http_body::Frame::data(bytes))).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            let err: Box<dyn std::error::Error + Send + Sync> = Box::new(e);
                            let _ = tx.send(Err(err)).await;
                            break;
                        }
                    }
                }
            }
            .instrument(tracing::info_span!("s3_upload_bridge")),
        );

        let stream_body = StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx));
        let byte_stream = ByteStream::from_body_1_x(stream_body);

        let res = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .set_content_length(content_len.map(|l| i64::try_from(l).unwrap_or(i64::MAX)))
            .body(byte_stream)
            .send()
            .await;

        // PRIORITIZE: Check if we manually triggered a size limit abortion
        if limit_exceeded.load(Ordering::SeqCst) {
            return Err(StorageError::ExceedsLimit);
        }

        match res {
            Ok(_) => {
                let final_total = total_uploaded.load(Ordering::SeqCst);
                if final_total < u64::try_from(min_size).unwrap_or(0) {
                    // Cleanup failed upload
                    let _ = self.delete(key).await;
                    return Err(StorageError::BelowMinSize);
                }
                Ok(final_total)
            }
            Err(e) => {
                // If S3 failed but our flag wasn't set yet, wait a tiny bit for the bridge task to finish its check
                if !bridge_handle.is_finished() {
                    let _ = bridge_handle.await;
                    if limit_exceeded.load(Ordering::SeqCst) {
                        return Err(StorageError::ExceedsLimit);
                    }
                }

                tracing::error!(error = ?e, key = %key, "S3 Upload failed");
                Err(StorageError::Internal(e.to_string()))
            }
        }
    }

    #[tracing::instrument(
        level = "debug",
        err,
        skip(self),
        fields(key = %key, bucket = %self.bucket)
    )]
    async fn get(&self, key: &str) -> StorageResult<(u64, StorageStream)> {
        let output = self.client.get_object().bucket(&self.bucket).key(key).send().await.map_err(|e| {
            if let aws_sdk_s3::error::SdkError::ServiceError(ref err) = e
                && err.err().is_no_such_key()
            {
                return StorageError::NotFound;
            }
            StorageError::Internal(e.to_string())
        })?;

        let content_length = output.content_length.unwrap_or(0);

        let sdk_stream = output.body;
        let stream = futures::stream::unfold(sdk_stream, |mut s| async move {
            match s.next().await {
                Some(Ok(bytes)) => Some((Ok(bytes), s)),
                Some(Err(e)) => {
                    tracing::error!(error = ?e, "S3 Stream error");
                    Some((Err(std::io::Error::other(e.to_string())), s))
                }
                None => None,
            }
        })
        .boxed();

        Ok((u64::try_from(content_length).unwrap_or(0), stream))
    }

    #[tracing::instrument(
        level = "debug",
        err,
        skip(self),
        fields(key = %key, bucket = %self.bucket)
    )]
    async fn delete(&self, key: &str) -> StorageResult<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::Internal(e.to_string()))?;
        Ok(())
    }
}
