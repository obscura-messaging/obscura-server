use crate::adapters::database::DbPool;
use crate::adapters::redis::RedisClient;
use crate::config::HealthConfig;
use aws_sdk_s3::Client;
use opentelemetry::{KeyValue, global, metrics::Gauge};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

#[derive(Clone, Debug)]
pub struct Metrics {
    pub status: Gauge<i64>,
}

impl Metrics {
    #[must_use]
    pub(crate) fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            status: meter
                .i64_gauge("obscura_health_status")
                .with_description("Status of health checks (1 for ok, 0 for error)")
                .build(),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct HealthService {
    pool: DbPool,
    s3_client: Client,
    pubsub: Arc<RedisClient>,
    storage_bucket: String,
    config: HealthConfig,
    metrics: Metrics,
}

impl HealthService {
    #[must_use]
    pub fn new(
        pool: DbPool,
        s3_client: Client,
        pubsub: Arc<RedisClient>,
        storage_bucket: String,
        config: HealthConfig,
    ) -> Self {
        Self { pool, s3_client, pubsub, storage_bucket, config, metrics: Metrics::new() }
    }

    /// Checks database connectivity.
    ///
    /// # Errors
    /// Returns a string describing the failure if the database is unreachable.
    pub async fn check_db(&self) -> Result<(), String> {
        let db_timeout = Duration::from_millis(self.config.db_timeout_ms.get());

        match timeout(db_timeout, sqlx::query("SELECT 1").execute(&self.pool)).await {
            Ok(Ok(_)) => {
                self.metrics.status.record(1, &[KeyValue::new("component", "database")]);
                Ok(())
            }
            Ok(Err(e)) => {
                self.metrics.status.record(0, &[KeyValue::new("component", "database")]);
                Err(format!("Database connection failed: {e:?}"))
            }
            Err(_) => {
                self.metrics.status.record(0, &[KeyValue::new("component", "database")]);
                Err("Database connection timed out".to_string())
            }
        }
    }

    /// Checks S3 connectivity.
    ///
    /// # Errors
    /// Returns a string describing the failure if S3 is unreachable.
    pub async fn check_storage(&self) -> Result<(), String> {
        let storage_timeout = Duration::from_millis(self.config.storage_timeout_ms.get());

        match timeout(storage_timeout, self.s3_client.head_bucket().bucket(&self.storage_bucket).send()).await {
            Ok(Ok(_)) => {
                self.metrics.status.record(1, &[KeyValue::new("component", "storage")]);
                Ok(())
            }
            Ok(Err(e)) => {
                self.metrics.status.record(0, &[KeyValue::new("component", "storage")]);
                Err(format!("Storage connection failed for bucket {}: {:?}", self.storage_bucket, e))
            }
            Err(_) => {
                self.metrics.status.record(0, &[KeyValue::new("component", "storage")]);
                Err("Storage connection timed out".to_string())
            }
        }
    }

    /// Checks `PubSub` connectivity.
    ///
    /// # Errors
    /// Returns a string describing the failure if `PubSub` is unreachable.
    pub async fn check_pubsub(&self) -> Result<(), String> {
        let pubsub_timeout = Duration::from_millis(self.config.pubsub_timeout_ms.get());

        match timeout(pubsub_timeout, self.pubsub.ping()).await {
            Ok(Ok(())) => {
                self.metrics.status.record(1, &[KeyValue::new("component", "pubsub")]);
                Ok(())
            }
            Ok(Err(e)) => {
                self.metrics.status.record(0, &[KeyValue::new("component", "pubsub")]);
                Err(format!("PubSub connection failed: {e:?}"))
            }
            Err(_) => {
                self.metrics.status.record(0, &[KeyValue::new("component", "pubsub")]);
                Err("PubSub connection timed out".to_string())
            }
        }
    }
}
