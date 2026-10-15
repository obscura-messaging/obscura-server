use crate::config::PubSubConfig;
use dashmap::DashMap;
use futures::StreamExt;
use opentelemetry::metrics::Gauge;
use opentelemetry::{KeyValue, global};
use rand::RngExt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, watch};
use tracing::Instrument;

pub mod cache;
pub mod notification_repo;

pub use cache::RedisCache;
pub use notification_repo::NotificationRepository;

#[derive(Debug, Clone)]
pub struct PubSubMessage {
    pub channel: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Metrics {
    subscription_up: Gauge<i64>,
}

impl Metrics {
    fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            subscription_up: meter
                .i64_gauge("obscura_pubsub_subscription_up")
                .with_description("1 while this process holds a live PubSub subscription for a pattern, 0 otherwise")
                .build(),
        }
    }
}

/// Exponential backoff with jitter for the pubsub reconnect loop.
///
/// Unbounded by design: the listener is a process-lifetime daemon, and one that gives up cannot deliver
/// notifications. Jitter decorrelates replicas, which all watch the same pattern on the same Valkey.
#[derive(Debug)]
struct Backoff {
    min: Duration,
    max: Duration,
    current: Duration,
}

impl Backoff {
    fn new(min_secs: u64, max_secs: u64) -> Self {
        let min = Duration::from_secs(min_secs.max(1));
        let max = Duration::from_secs(max_secs).max(min);
        Self { min, max, current: min }
    }

    /// Next delay, then double the ceiling for the attempt after this one.
    fn next_delay(&mut self) -> Duration {
        // Jitter spans [min, current] rather than [0, current] so `--pubsub-min-backoff-secs` is
        // actually a minimum.
        let spread = u64::try_from(self.current.saturating_sub(self.min).as_millis()).unwrap_or(u64::MAX);
        let delay = self.min + Duration::from_millis(rand::rng().random_range(0..=spread));
        self.current = self.current.saturating_mul(2).min(self.max);
        delay
    }

    const fn reset(&mut self) {
        self.current = self.min;
    }
}

#[derive(Debug)]
pub struct RedisClient {
    publisher: redis::aio::ConnectionManager,
    // Maps patterns (e.g. "user:*") to broadcast senders
    subscriptions: Arc<DashMap<String, broadcast::Sender<PubSubMessage>>>,
    client: redis::Client,
    shutdown: watch::Receiver<bool>,
    channel_capacity: usize,
    config: PubSubConfig,
}

impl RedisClient {
    /// Creates a new Redis-based `PubSub` client.
    ///
    /// # Errors
    /// Returns an error if the connection fails.
    pub async fn new(
        config: &PubSubConfig,
        channel_capacity: usize,
        shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<Arc<Self>> {
        let client = redis::Client::open(config.url.as_str())?;
        let publisher = client.get_connection_manager().await?;
        let subscriptions = Arc::new(DashMap::new());

        let redis_client =
            Arc::new(Self { publisher, subscriptions, client, shutdown, channel_capacity, config: config.clone() });

        Ok(redis_client)
    }

    /// Returns a publisher connection that can be used for standard Redis commands.
    #[must_use]
    pub fn publisher(&self) -> redis::aio::ConnectionManager {
        self.publisher.clone()
    }

    /// Subscribes to a Redis pattern.
    /// If a background listener for this pattern isn't already running, it will be started.
    ///
    /// # Errors
    /// Returns an error if the subscription fails.
    pub fn subscribe(&self, pattern: &str) -> anyhow::Result<broadcast::Receiver<PubSubMessage>> {
        if let Some(tx) = self.subscriptions.get(pattern) {
            return Ok(tx.subscribe());
        }

        // Create new broadcast channel for this pattern
        let (tx, rx) = broadcast::channel(self.channel_capacity);
        self.subscriptions.insert(pattern.to_string(), tx.clone());

        // Spawn a background listener for this specific pattern
        let pattern_str = pattern.to_string();
        let client = self.client.clone();
        let shutdown = self.shutdown.clone();
        let subscriptions = Arc::clone(&self.subscriptions);
        let config = self.config.clone();

        // Returns before the listener has necessarily subscribed. The receiver is valid either
        // way — it yields nothing until the subscription is live, then starts delivering — and
        // waiting would only block the caller for the length of an outage.
        tokio::spawn(
            async move {
                Self::run_pattern_listener(client, pattern_str, tx, shutdown, subscriptions, config).await;
            }
            .instrument(tracing::debug_span!("pubsub_listener", pattern = %pattern)),
        );

        Ok(rx)
    }

    async fn run_pattern_listener(
        client: redis::Client,
        pattern: String,
        tx: broadcast::Sender<PubSubMessage>,
        mut shutdown: watch::Receiver<bool>,
        subscriptions: Arc<DashMap<String, broadcast::Sender<PubSubMessage>>>,
        config: PubSubConfig,
    ) {
        // Connect failure and stream loss are the same event — no subscription — so one loop, one
        // backoff.
        let metrics = Metrics::new();
        let attrs = [KeyValue::new("pattern", pattern.clone())];

        let mut backoff = Backoff::new(config.min_backoff_secs, config.max_backoff_secs);
        // Reset only after a subscription proves stable, not merely established: a flapping Valkey
        // would otherwise pull the delay back to the minimum on every cycle.
        let stable_after = Duration::from_secs(config.stable_after_secs);
        let mut first_attempt = true;
        metrics.subscription_up.record(0, &attrs);

        'reconnect: loop {
            if *shutdown.borrow() {
                break;
            }

            // Every path back to the top of this loop is a lost subscription, whether the connect
            // failed or an established stream ended, so the delay belongs here rather than in the
            // connect-failure arm. A Valkey that accepts and immediately drops (a pubsub
            // output-buffer kill, a failover resetting the connection) would otherwise spin.
            if !first_attempt {
                let delay = backoff.next_delay();
                tracing::debug!(pattern = %pattern, retry_in_ms = %delay.as_millis(), "Reconnecting to pubsub");
                tokio::select! {
                    _ = shutdown.changed() => break 'reconnect,
                    () = tokio::time::sleep(delay) => {}
                }
            }
            first_attempt = false;

            let pubsub = match Self::connect_and_subscribe(&client, &pattern).await {
                Ok(ps) => ps,
                Err(e) => {
                    tracing::warn!(pattern = %pattern, error = %e, "Failed to subscribe to pubsub, retrying");
                    continue 'reconnect;
                }
            };

            tracing::info!(pattern = %pattern, "Successfully subscribed to pubsub");
            metrics.subscription_up.record(1, &attrs);
            let connected_at = Instant::now();
            let mut message_stream = pubsub.into_on_message();

            loop {
                tokio::select! {
                    _ = shutdown.changed() => {
                        metrics.subscription_up.record(0, &attrs);
                        break 'reconnect;
                    }
                    msg = message_stream.next() => {
                        if let Some(msg) = msg {
                            let channel = msg.get_channel_name().to_string();
                            let span = tracing::info_span!("pubsub_receive", %channel);

                            let pubsub_msg = span.in_scope(|| PubSubMessage {
                                channel,
                                payload: msg.get_payload().unwrap_or_default(),
                            });
                            // Send fails only when nobody is subscribed right now; the listener
                            // outlives its receivers.
                            let _ = tx.send(pubsub_msg);
                        } else {
                            tracing::warn!(pattern = %pattern, "Pubsub connection lost, reconnecting");
                            break;
                        }
                    }
                }
            }

            metrics.subscription_up.record(0, &attrs);
            if connected_at.elapsed() >= stable_after {
                backoff.reset();
            }
        }

        metrics.subscription_up.record(0, &attrs);
        subscriptions.remove(&pattern);
    }

    async fn connect_and_subscribe(client: &redis::Client, pattern: &str) -> redis::RedisResult<redis::aio::PubSub> {
        let mut pubsub = client.get_async_pubsub().await?;
        pubsub.psubscribe(pattern).await?;
        Ok(pubsub)
    }

    /// Pings the Redis server to check connectivity.
    ///
    /// # Errors
    /// Returns an error if the ping fails.
    pub async fn ping(&self) -> anyhow::Result<()> {
        let mut conn = self.publisher();
        redis::cmd("PING").query_async::<String>(&mut conn).await?;
        Ok(())
    }
}
