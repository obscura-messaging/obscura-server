use crate::adapters::redis::RedisClient;
use std::sync::Arc;

/// A fixed-window rate limit kept in Valkey, so every server replica counts against the same limit.
///
/// The window starts at a key's first hit and lasts `window_secs`; up to `limit` hits fit in it.
#[derive(Debug, Clone)]
pub struct RateLimitCounter {
    redis: Arc<RedisClient>,
    prefix: String,
    limit: u32,
    window_secs: u64,
}

impl RateLimitCounter {
    #[must_use]
    pub const fn new(redis: Arc<RedisClient>, prefix: String, limit: u32, window_secs: u64) -> Self {
        Self { redis, prefix, limit, window_secs }
    }

    /// Counts one hit for `key`. Returns `None` if it fits within the limit, or the seconds until the window
    /// ends if it does not.
    ///
    /// # Errors
    /// Returns an error if the Valkey operation fails.
    pub async fn hit(&self, key: &str) -> anyhow::Result<Option<u64>> {
        let mut conn = self.redis.publisher();
        let full_key = format!("{}{key}", self.prefix);
        // One atomic round trip: count the hit, start the window on the first one, and read how long it has left.
        // Milliseconds, rounded up, so `Retry-After` never says to come back before the window ends.
        let (count, ttl_ms): (u64, i64) = redis::pipe()
            .atomic()
            .incr(&full_key, 1)
            .cmd("EXPIRE")
            .arg(&full_key)
            .arg(self.window_secs)
            .arg("NX")
            .ignore()
            .pttl(&full_key)
            .query_async(&mut conn)
            .await?;
        if count <= u64::from(self.limit) {
            return Ok(None);
        }
        Ok(Some(u64::try_from(ttl_ms).map_or(self.window_secs, |ms| ms.div_ceil(1000)).max(1)))
    }
}
