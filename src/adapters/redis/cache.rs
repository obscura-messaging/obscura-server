use crate::adapters::redis::RedisClient;
use redis::AsyncCommands;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct RedisCache {
    redis: Arc<RedisClient>,
    prefix: String,
    ttl_secs: u64,
}

impl RedisCache {
    #[must_use]
    pub const fn new(redis: Arc<RedisClient>, prefix: String, ttl_secs: u64) -> Self {
        Self { redis, prefix, ttl_secs }
    }

    /// Retrieves a cached response for a key.
    ///
    /// # Errors
    /// Returns an error if the Redis operation fails.
    pub async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let mut conn = self.redis.publisher();
        let full_key = format!("{}{key}", self.prefix);
        let response: Option<Vec<u8>> = conn.get(full_key).await?;
        Ok(response)
    }

    /// Saves a response for a key with the cache's configured TTL.
    ///
    /// # Errors
    /// Returns an error if the Redis operation fails.
    pub async fn set(&self, key: &str, value: &[u8]) -> anyhow::Result<()> {
        let mut conn = self.redis.publisher();
        let full_key = format!("{}{key}", self.prefix);
        let _: () = conn.set_ex(full_key, value, self.ttl_secs).await?;
        Ok(())
    }

    /// Removes a key and returns its value in one atomic operation, so that only one caller gets it.
    ///
    /// # Errors
    /// Returns an error if the Redis operation fails.
    pub async fn take(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let mut conn = self.redis.publisher();
        let full_key = format!("{}{key}", self.prefix);
        let value: Option<Vec<u8>> = conn.get_del(full_key).await?;
        Ok(value)
    }
}
