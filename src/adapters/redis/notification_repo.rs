use crate::adapters::redis::RedisClient;
use crate::config::NotificationConfig;
use crate::domain::notification::{DeviceEvent, RealtimeNotification};
use redis::AsyncCommands;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct NotificationRepository {
    redis: Arc<RedisClient>,
    channel_prefix: String,
    push_queue_key: String,
    global_channel_capacity: NonZeroUsize,
}

impl NotificationRepository {
    #[must_use]
    pub fn new(redis: Arc<RedisClient>, config: &NotificationConfig) -> Self {
        Self {
            redis,
            channel_prefix: config.channel_prefix.clone(),
            push_queue_key: config.push_queue_key.clone(),
            global_channel_capacity: config.global_channel_capacity,
        }
    }

    /// Publishes a realtime event to multiple devices using a pipeline.
    ///
    /// # Errors
    /// Returns an error if the Redis operation fails.
    #[tracing::instrument(level = "debug", skip(self, device_ids), err)]
    pub async fn publish_realtime(&self, device_ids: &[Uuid], event: DeviceEvent) -> anyhow::Result<()> {
        if device_ids.is_empty() {
            return Ok(());
        }
        let payload = [event as u8];
        let mut pipe = redis::pipe();

        for device_id in device_ids {
            let channel_name = format!("{}{device_id}", self.channel_prefix);
            pipe.publish(&channel_name, &payload);
        }

        let mut conn = self.redis.publisher();
        let _: () = pipe.query_async(&mut conn).await?;
        Ok(())
    }

    /// Subscribes to realtime events for all devices.
    ///
    /// # Errors
    /// Returns an error if the subscription fails.
    #[tracing::instrument(level = "debug", skip(self), err)]
    pub async fn subscribe_realtime(&self) -> anyhow::Result<broadcast::Receiver<RealtimeNotification>> {
        let pattern = format!("{}*", self.channel_prefix);
        let mut redis_rx = self.redis.subscribe(&pattern)?;

        let (tx, rx) = broadcast::channel(self.global_channel_capacity.get());
        let prefix = self.channel_prefix.clone();
        // Spawn a mapper task to translate technical PubSubMessages into domain RealtimeNotifications
        tokio::spawn(async move {
            loop {
                match redis_rx.recv().await {
                    Ok(msg) => {
                        if let Some(device_id_str) = msg.channel.strip_prefix(&prefix)
                            && let Ok(device_id) = Uuid::parse_str(device_id_str)
                            && let Some(payload_byte) = msg.payload.first()
                            && let Ok(event) = DeviceEvent::try_from(*payload_byte)
                        {
                            let _ = tx.send(RealtimeNotification { device_id, event });
                        }
                    }
                    // Lagged means we skipped `n` messages, not that the receiver is dead — the
                    // scheduled push fallback and the reconnect backlog drain cover the gap.
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(missed = n, "Realtime notification mapper lagged; continuing");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        tracing::info!("Realtime notification source closed; mapper exiting");
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Schedules push notification jobs for multiple devices using a pipeline.
    ///
    /// # Errors
    /// Returns an error if the Redis operation fails.
    #[allow(clippy::cast_precision_loss)]
    #[tracing::instrument(level = "debug", skip(self, device_ids), err)]
    pub async fn push_jobs(&self, device_ids: &[Uuid], delay_secs: u64) -> anyhow::Result<()> {
        if device_ids.is_empty() {
            return Ok(());
        }

        let run_at = time::OffsetDateTime::now_utc().unix_timestamp() + i64::try_from(delay_secs).unwrap_or(0);
        let mut pipe = redis::pipe();

        for device_id in device_ids {
            pipe.cmd("ZADD").arg(&self.push_queue_key).arg("NX").arg(run_at as f64).arg(device_id.to_string());
        }

        let mut conn = self.redis.publisher();
        let _: () = pipe.query_async(&mut conn).await?;
        Ok(())
    }

    /// Cancels a pending push notification job for a device.
    ///
    /// # Errors
    /// Returns an error if the Redis operation fails.
    #[tracing::instrument(level = "debug", skip(self), err)]
    pub async fn cancel_job(&self, device_id: Uuid) -> anyhow::Result<()> {
        let mut conn = self.redis.publisher();
        let _: i64 = conn.zrem(&self.push_queue_key, device_id.to_string()).await?;
        Ok(())
    }

    /// Leases a batch of due push notification jobs atomically.
    ///
    /// # Errors
    /// Returns an error if the Redis operation fails.
    #[allow(clippy::cast_precision_loss)]
    #[tracing::instrument(level = "debug", skip(self), err)]
    pub async fn lease_due_jobs(&self, limit: isize, timeout_secs: u64) -> anyhow::Result<Vec<Uuid>> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
        let lease_until = now + timeout_secs as f64;
        let mut conn = self.redis.publisher();

        // Lua Script:
        // 1. Get candidates using ZRANGEBYSCORE
        // 2. Loop through candidates and ZADD them with the new score
        // 3. Return the candidates
        let script = redis::Script::new(
            r#"
            local jobs = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, ARGV[2])
            if #jobs > 0 then
                for _, job in ipairs(jobs) do
                    redis.call('ZADD', KEYS[1], ARGV[3], job)
                end
            end
            return jobs
            "#,
        );

        let candidates: Vec<String> =
            script.key(&self.push_queue_key).arg(now).arg(limit).arg(lease_until).invoke_async(&mut conn).await?;

        let leased = candidates.into_iter().filter_map(|s| Uuid::parse_str(&s).ok()).collect();

        Ok(leased)
    }

    /// Deletes a push notification job from the queue (finalizing it).
    ///
    /// # Errors
    /// Returns an error if the Redis operation fails.
    #[tracing::instrument(level = "debug", skip(self), err)]
    pub async fn delete_job(&self, device_id: Uuid) -> anyhow::Result<()> {
        let mut conn = self.redis.publisher();
        let _: i64 = conn.zrem(&self.push_queue_key, device_id.to_string()).await?;
        Ok(())
    }
}
