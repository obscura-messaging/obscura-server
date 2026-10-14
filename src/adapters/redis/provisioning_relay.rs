use crate::adapters::redis::RedisClient;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

// The owner check and the single-store rule must hold together, so they run as one script.
const PUT_SCRIPT: &str = r"
if redis.call('HGET', KEYS[1], 'user') ~= ARGV[1] then return 0 end
if redis.call('HSETNX', KEYS[1], 'stored', '1') == 0 then return 2 end
redis.call('RPUSH', KEYS[2], ARGV[2])
redis.call('PEXPIRE', KEYS[2], redis.call('PTTL', KEYS[1]))
return 1
";

#[derive(Debug, PartialEq, Eq)]
pub enum RelayPut {
    Stored,
    NotFound,
    AlreadyStored,
}

/// Provisioning relay addresses and their single body, held in Valkey so that expiry purges them.
#[derive(Debug, Clone)]
pub struct ProvisioningRelay {
    redis: Arc<RedisClient>,
}

impl ProvisioningRelay {
    #[must_use]
    pub const fn new(redis: Arc<RedisClient>) -> Self {
        Self { redis }
    }

    fn address_key(address: &str) -> String {
        format!("provisioning:{{{address}}}")
    }

    fn body_key(address: &str) -> String {
        format!("provisioning:{{{address}}}:body")
    }

    /// Creates an address owned by `user_id` that expires after `ttl`.
    ///
    /// # Errors
    /// Returns an error if the Redis operation fails.
    pub async fn create(&self, address: &str, user_id: Uuid, ttl: Duration) -> anyhow::Result<()> {
        let key = Self::address_key(address);
        let ttl_ms = i64::try_from(ttl.as_millis())?;
        let mut conn = self.redis.publisher();
        redis::pipe()
            .atomic()
            .hset(&key, "user", user_id.to_string())
            .ignore()
            .pexpire(&key, ttl_ms)
            .ignore()
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    /// Stores the body of an address owned by `user_id`, at most once per address.
    ///
    /// # Errors
    /// Returns an error if the Redis operation fails.
    pub async fn put(&self, address: &str, user_id: Uuid, body: &[u8]) -> anyhow::Result<RelayPut> {
        let mut conn = self.redis.publisher();
        let outcome: i64 = redis::Script::new(PUT_SCRIPT)
            .key(Self::address_key(address))
            .key(Self::body_key(address))
            .arg(user_id.to_string())
            .arg(body)
            .invoke_async(&mut conn)
            .await?;

        Ok(match outcome {
            1 => RelayPut::Stored,
            2 => RelayPut::AlreadyStored,
            _ => RelayPut::NotFound,
        })
    }

    /// Returns the owner of an unexpired address.
    ///
    /// # Errors
    /// Returns an error if the Redis operation fails.
    pub async fn owner(&self, address: &str) -> anyhow::Result<Option<Uuid>> {
        let mut conn = self.redis.publisher();
        let user: Option<String> =
            redis::cmd("HGET").arg(Self::address_key(address)).arg("user").query_async(&mut conn).await?;
        Ok(user.map(|u| Uuid::parse_str(&u)).transpose()?)
    }

    /// Removes and returns the body of an address, waiting up to `wait` for it to be stored.
    ///
    /// # Errors
    /// Returns an error if the Redis operation fails.
    pub async fn take(&self, address: &str, wait: Duration) -> anyhow::Result<Option<Vec<u8>>> {
        let key = Self::body_key(address);
        if wait.is_zero() {
            let mut conn = self.redis.publisher();
            return Ok(redis::cmd("LPOP").arg(key).query_async(&mut conn).await?);
        }

        let mut conn = self.redis.dedicated_connection().await?;
        let popped: Option<(String, Vec<u8>)> =
            redis::cmd("BLPOP").arg(key).arg(wait.as_secs_f64()).query_async(&mut conn).await?;
        Ok(popped.map(|(_, body)| body))
    }
}
