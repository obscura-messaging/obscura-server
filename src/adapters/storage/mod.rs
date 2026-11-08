use crate::domain::attachment::{SizeLimits, SizeViolation};
use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use thiserror::Error;

pub mod s3;

pub use s3::S3Storage;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error(transparent)]
    Size(#[from] SizeViolation),
    #[error("Object not found")]
    NotFound,
    #[error("Internal storage error: {0}")]
    Internal(String),
}

pub type StorageResult<T> = Result<T, StorageError>;
/// A neutral byte stream that uses `std::io::Error` to avoid coupling to the application's error types.
pub type StorageStream = BoxStream<'static, Result<Bytes, std::io::Error>>;

#[async_trait]
pub trait ObjectStorage: Send + Sync + 'static {
    async fn put(
        &self,
        key: &str,
        stream: StorageStream,
        content_len: Option<u64>,
        limits: SizeLimits,
    ) -> StorageResult<u64>;
    async fn get(&self, key: &str) -> StorageResult<(u64, StorageStream)>;
    async fn delete(&self, key: &str) -> StorageResult<()>;
}
