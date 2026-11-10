use crate::domain::attachment::SizeLimits;
use clap::{Args, Parser};
use ipnetwork::IpNetwork;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use thiserror::Error;
use uuid::Uuid;

/// A configuration whose values parse individually but contradict each other.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Attachment minimum size {min} exceeds maximum size {max}")]
    AttachmentSizeLimits { min: u64, max: u64 },
    #[error(
        "FCM is half configured: {missing} is not set. Set both OBSCURA_FCM_PROJECT_ID and OBSCURA_FCM_CREDENTIALS_FILE, or neither"
    )]
    PartialFcm { missing: &'static str },
}

// Integer types follow what a value is used for: `u32` for limits passed to SQL (each fits the `i64` that
// Postgres takes), `usize` for sizes of in-memory buffers and channels, and `u64` for seconds. A limit is
// `NonZero` when 0 would crash the server or silently disable a feature.

// Build non-zero defaults. Only called with literals.
const fn non_zero_u32(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).expect("config defaults are non-zero")
}

const fn non_zero_u64(n: u64) -> NonZeroU64 {
    NonZeroU64::new(n).expect("config defaults are non-zero")
}

const fn non_zero_usize(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).expect("config defaults are non-zero")
}

/// Parses a ratio from 0.0 to 1.0. The trace sampler silently clamps anything outside that range, so a
/// percentage such as `10` would sample every trace instead of a tenth of them.
fn parse_ratio(value: &str) -> Result<f64, String> {
    let ratio: f64 = value.parse().map_err(|e| format!("{e}"))?;
    if (0.0..=1.0).contains(&ratio) { Ok(ratio) } else { Err(format!("{ratio} is not between 0.0 and 1.0")) }
}

#[derive(Clone, Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct Config {
    /// Global time-to-live for messages and attachments in days
    #[arg(long, env = "OBSCURA_TTL_DAYS", default_value_t = Config::default().ttl_days)]
    pub ttl_days: NonZeroU32,

    #[command(flatten)]
    pub database: DatabaseConfig,

    #[command(flatten)]
    pub server: ServerConfig,

    #[command(flatten)]
    pub auth: AuthConfig,

    #[command(flatten)]
    pub rate_limit: RateLimitConfig,

    #[command(flatten)]
    pub health: HealthConfig,

    #[command(flatten)]
    pub messaging: MessagingConfig,

    #[command(flatten)]
    pub notifications: NotificationConfig,

    #[command(flatten)]
    pub pubsub: PubSubConfig,

    #[command(flatten)]
    pub websocket: WsConfig,

    #[command(flatten)]
    pub attachment: AttachmentConfig,

    #[command(flatten)]
    pub storage: StorageConfig,

    #[command(flatten)]
    pub telemetry: TelemetryConfig,

    #[command(flatten)]
    pub fcm: FcmConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ttl_days: non_zero_u32(30),
            database: DatabaseConfig::default(),
            server: ServerConfig::default(),
            auth: AuthConfig::default(),
            rate_limit: RateLimitConfig::default(),
            health: HealthConfig::default(),
            messaging: MessagingConfig::default(),
            notifications: NotificationConfig::default(),
            pubsub: PubSubConfig::default(),
            websocket: WsConfig::default(),
            attachment: AttachmentConfig::default(),
            storage: StorageConfig::default(),
            telemetry: TelemetryConfig::default(),
            fcm: FcmConfig::default(),
        }
    }
}

impl Config {
    /// Parses the configuration from arguments and the environment, then checks the rules that span
    /// several values. A process should not start with a configuration that fails either step.
    ///
    /// # Errors
    /// Returns a [`ConfigError`] if values contradict each other. Values that fail to parse individually
    /// exit through clap, like `--help`.
    pub fn load() -> Result<Self, ConfigError> {
        let config = Self::parse();
        config.validate()?;
        Ok(config)
    }

    /// Checks the rules that span several values.
    ///
    /// # Errors
    /// Returns the first [`ConfigError`] found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.attachment.size_limits()?;
        self.fcm.credentials()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Args)]
pub struct DatabaseConfig {
    /// Database connection URL
    #[arg(
        long = "db-url",
        id = "DATABASE_URL",
        env = "OBSCURA_DATABASE_URL",
        default_value_t = DatabaseConfig::default().url
    )]
    pub url: String,

    /// Maximum number of connections in the pool
    #[arg(
        long = "db-max-connections",
        id = "DATABASE_MAX_CONNECTIONS",
        env = "OBSCURA_DATABASE_MAX_CONNECTIONS",
        default_value_t = DatabaseConfig::default().max_connections
    )]
    pub max_connections: NonZeroU32,

    /// Minimum number of connections to keep idle in the pool
    #[arg(long = "db-min-connections", env = "OBSCURA_DATABASE_MIN_CONNECTIONS", default_value_t = DatabaseConfig::default().min_connections)]
    pub min_connections: u32,

    /// Seconds to wait before timing out on acquiring a connection
    #[arg(long = "db-acquire-timeout-secs", env = "OBSCURA_DATABASE_ACQUIRE_TIMEOUT_SECS", default_value_t = DatabaseConfig::default().acquire_timeout_secs)]
    pub acquire_timeout_secs: NonZeroU64,

    /// Seconds before an idle connection is closed
    #[arg(long = "db-idle-timeout-secs", env = "OBSCURA_DATABASE_IDLE_TIMEOUT_SECS", default_value_t = DatabaseConfig::default().idle_timeout_secs)]
    pub idle_timeout_secs: u64,

    /// Seconds before a connection is retired and replaced
    #[arg(long = "db-max-lifetime-secs", env = "OBSCURA_DATABASE_MAX_LIFETIME_SECS", default_value_t = DatabaseConfig::default().max_lifetime_secs)]
    pub max_lifetime_secs: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgres://user:password@localhost/signal_server".to_string(),
            max_connections: non_zero_u32(20),
            min_connections: 5,
            acquire_timeout_secs: non_zero_u64(3),
            idle_timeout_secs: 600,
            max_lifetime_secs: 1800,
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct PubSubConfig {
    /// `PubSub` connection URL (e.g. <redis://localhost:6379>)
    #[arg(
        long = "pubsub-url",
        id = "PUBSUB_URL",
        env = "OBSCURA_PUBSUB_URL",
        default_value_t = PubSubConfig::default().url
    )]
    pub url: String,

    /// Minimum backoff time for `PubSub` reconnection in seconds
    #[arg(
        long = "pubsub-min-backoff-secs",
        id = "PUBSUB_MIN_BACKOFF_SECS",
        env = "OBSCURA_PUBSUB_MIN_BACKOFF_SECS",
        default_value_t = PubSubConfig::default().min_backoff_secs
    )]
    pub min_backoff_secs: u64,

    /// Maximum backoff time for `PubSub` reconnection in seconds
    #[arg(
        long = "pubsub-max-backoff-secs",
        id = "PUBSUB_MAX_BACKOFF_SECS",
        env = "OBSCURA_PUBSUB_MAX_BACKOFF_SECS",
        default_value_t = PubSubConfig::default().max_backoff_secs
    )]
    pub max_backoff_secs: u64,

    /// How long a `PubSub` subscription must hold before its reconnect backoff resets, in seconds
    #[arg(
        long = "pubsub-stable-after-secs",
        id = "PUBSUB_STABLE_AFTER_SECS",
        env = "OBSCURA_PUBSUB_STABLE_AFTER_SECS",
        default_value_t = PubSubConfig::default().stable_after_secs
    )]
    pub stable_after_secs: u64,
}

impl Default for PubSubConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            min_backoff_secs: 1,
            max_backoff_secs: 30,
            stable_after_secs: 30,
        }
    }
}

#[derive(Clone, Debug, Default, clap::ValueEnum)]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Clone, Debug, Args)]
pub struct TelemetryConfig {
    /// OTLP Endpoint for traces and metrics (e.g. <http://localhost:4318>)
    /// If not set, OTLP export is disabled (logs only).
    #[arg(long = "telemetry-otlp-endpoint", env = "OBSCURA_TELEMETRY_OTLP_ENDPOINT")]
    pub otlp_endpoint: Option<String>,

    /// Log format (text or json)
    #[arg(
        long = "telemetry-log-format",
        env = "OBSCURA_TELEMETRY_LOG_FORMAT",
        default_value_t = TelemetryConfig::default().log_format
    )]
    pub log_format: LogFormat,

    /// Trace sampling ratio (0.0 to 1.0)
    #[arg(
        long = "telemetry-trace-sampling-ratio",
        env = "OBSCURA_TELEMETRY_TRACE_SAMPLING_RATIO",
        default_value_t = TelemetryConfig::default().trace_sampling_ratio,
        value_parser = parse_ratio
    )]
    pub trace_sampling_ratio: f64,

    /// Metric export interval in seconds
    #[arg(
        long = "telemetry-metrics-export-interval-secs",
        env = "OBSCURA_TELEMETRY_METRICS_EXPORT_INTERVAL_SECS",
        default_value_t = TelemetryConfig::default().metrics_export_interval_secs
    )]
    pub metrics_export_interval_secs: NonZeroU64,

    /// OTLP export timeout in seconds
    #[arg(
        long = "telemetry-export-timeout-secs",
        env = "OBSCURA_TELEMETRY_EXPORT_TIMEOUT_SECS",
        default_value_t = TelemetryConfig::default().export_timeout_secs
    )]
    pub export_timeout_secs: NonZeroU64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            log_format: LogFormat::Text,
            trace_sampling_ratio: 1.0,
            metrics_export_interval_secs: non_zero_u64(60),
            export_timeout_secs: non_zero_u64(10),
        }
    }
}

impl std::fmt::Display for LogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Json => write!(f, "json"),
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct ServerConfig {
    /// Host to listen on
    #[arg(long = "server-host", env = "OBSCURA_SERVER_HOST", default_value_t = ServerConfig::default().host)]
    pub host: String,

    /// Port to listen on
    #[arg(long = "server-port", env = "OBSCURA_SERVER_PORT", default_value_t = ServerConfig::default().port)]
    pub port: u16,

    /// Management port for health checks and metrics
    #[arg(
        long = "server-mgmt-port",
        env = "OBSCURA_SERVER_MGMT_PORT",
        default_value_t = ServerConfig::default().mgmt_port
    )]
    pub mgmt_port: u16,

    /// How long to wait for background tasks to finish during shutdown in seconds
    #[arg(long = "server-shutdown-timeout-secs", env = "OBSCURA_SERVER_SHUTDOWN_TIMEOUT_SECS", default_value_t = ServerConfig::default().shutdown_timeout_secs)]
    pub shutdown_timeout_secs: u64,

    /// Timeout for standard requests in seconds
    #[arg(long = "server-request-timeout-secs", env = "OBSCURA_SERVER_REQUEST_TIMEOUT_SECS", default_value_t = ServerConfig::default().request_timeout_secs)]
    pub request_timeout_secs: NonZeroU64,

    /// Global catch-all safety timeout in seconds
    #[arg(long = "server-global-timeout-secs", env = "OBSCURA_SERVER_GLOBAL_TIMEOUT_SECS", default_value_t = ServerConfig::default().global_timeout_secs)]
    pub global_timeout_secs: NonZeroU64,

    /// Comma-separated list of CIDRs to trust for X-Forwarded-For IP extraction
    #[arg(
        long,
        env = "OBSCURA_SERVER_TRUSTED_PROXIES",
        default_value = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1/32",
        value_delimiter = ','
    )]
    pub trusted_proxies: Vec<IpNetwork>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 3000,
            mgmt_port: 9090,
            shutdown_timeout_secs: 5,
            request_timeout_secs: non_zero_u64(30),
            global_timeout_secs: non_zero_u64(600),
            trusted_proxies: vec![
                "10.0.0.0/8".parse().expect("Invalid default CIDR for private network"),
                "172.16.0.0/12".parse().expect("Invalid default CIDR for private network"),
                "192.168.0.0/16".parse().expect("Invalid default CIDR for private network"),
                "127.0.0.1/32".parse().expect("Invalid default CIDR for localhost"),
            ],
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct AuthConfig {
    /// Secret key for JWT signing
    #[arg(long = "auth-jwt-secret", env = "OBSCURA_AUTH_JWT_SECRET", default_value_t = AuthConfig::default().jwt_secret)]
    pub jwt_secret: String,

    /// Access token time-to-live in seconds
    #[arg(long = "auth-token-ttl-secs", env = "OBSCURA_AUTH_TOKEN_TTL_SECS", default_value_t = AuthConfig::default().access_token_ttl_secs)]
    pub access_token_ttl_secs: NonZeroU64,

    /// Refresh token time-to-live in days
    #[arg(long = "auth-refresh-token-ttl-days", env = "OBSCURA_AUTH_REFRESH_TOKEN_TTL_DAYS", default_value_t = AuthConfig::default().refresh_token_ttl_days)]
    pub refresh_token_ttl_days: NonZeroU32,

    /// How often to run the refresh token cleanup task in seconds
    #[arg(
        long = "auth-refresh-token-cleanup-interval-secs",
        env = "OBSCURA_AUTH_REFRESH_TOKEN_CLEANUP_INTERVAL_SECS",
        default_value_t = AuthConfig::default().refresh_token_cleanup_interval_secs
    )]
    pub refresh_token_cleanup_interval_secs: NonZeroU64,

    /// Maximum number of devices a single user can have registered
    #[arg(
        long = "auth-max-devices-per-user",
        env = "OBSCURA_AUTH_MAX_DEVICES_PER_USER",
        default_value_t = AuthConfig::default().max_devices_per_user
    )]
    pub max_devices_per_user: NonZeroU32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "change_me_in_production".to_string(),
            access_token_ttl_secs: non_zero_u64(900),
            refresh_token_ttl_days: non_zero_u32(30),
            refresh_token_cleanup_interval_secs: non_zero_u64(86400), // 24 hours
            max_devices_per_user: non_zero_u32(10),
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct RateLimitConfig {
    /// Requests per second allowed for standard endpoints
    #[arg(long = "rate-limit-per-second", env = "OBSCURA_RATE_LIMIT_PER_SECOND", default_value_t = RateLimitConfig::default().per_second)]
    pub per_second: NonZeroU32,

    /// Burst allowance for standard endpoints
    #[arg(long = "rate-limit-burst", env = "OBSCURA_RATE_LIMIT_BURST", default_value_t = RateLimitConfig::default().burst)]
    pub burst: NonZeroU32,

    /// Stricter rate limit for expensive auth-related endpoints (/v1/users*, /v1/session*, POST /v1/link-sessions)
    #[arg(long = "auth-rate-limit-per-second", env = "OBSCURA_RATE_LIMIT_AUTH_PER_SECOND", default_value_t = RateLimitConfig::default().auth_per_second)]
    pub auth_per_second: NonZeroU32,

    /// Burst allowance for expensive auth-related endpoints
    #[arg(long = "auth-rate-limit-burst", env = "OBSCURA_RATE_LIMIT_AUTH_BURST", default_value_t = RateLimitConfig::default().auth_burst)]
    pub auth_burst: NonZeroU32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_second: non_zero_u32(10),
            burst: non_zero_u32(20),
            auth_per_second: non_zero_u32(1),
            auth_burst: non_zero_u32(3),
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct MessagingConfig {
    /// Maximum number of messages in a device's inbox
    #[arg(long = "messaging-inbox-max-size", env = "OBSCURA_MESSAGING_INBOX_MAX_SIZE", default_value_t = MessagingConfig::default().max_inbox_size)]
    pub max_inbox_size: NonZeroU32,

    /// How often to run the message cleanup task
    #[arg(
        long = "messaging-cleanup-interval-secs",
        id = "MESSAGING_CLEANUP_INTERVAL_SECS",
        env = "OBSCURA_MESSAGING_CLEANUP_INTERVAL_SECS",
        default_value_t = MessagingConfig::default().cleanup_interval_secs
    )]
    pub cleanup_interval_secs: NonZeroU64,

    /// Maximum number of messages to accept in a single send request
    #[arg(
        long = "messaging-send-batch-limit",
        env = "OBSCURA_MESSAGING_SEND_BATCH_LIMIT",
        default_value_t = MessagingConfig::default().send_batch_limit
    )]
    pub send_batch_limit: NonZeroUsize,

    /// Time-to-live for idempotency keys in seconds
    #[arg(
        long = "messaging-idempotency-ttl-secs",
        env = "OBSCURA_MESSAGING_IDEMPOTENCY_TTL_SECS",
        default_value_t = MessagingConfig::default().idempotency_ttl_secs
    )]
    pub idempotency_ttl_secs: NonZeroU64,

    /// Most one-time prekeys of each kind (EC and Kyber) per upload, and so per device
    #[arg(
        long = "messaging-pre-keys-max",
        env = "OBSCURA_PRE_KEYS_MAX",
        default_value_t = MessagingConfig::default().max_pre_keys
    )]
    pub max_pre_keys: NonZeroU32,
}

impl Default for MessagingConfig {
    fn default() -> Self {
        Self {
            max_inbox_size: non_zero_u32(1000),
            cleanup_interval_secs: non_zero_u64(300),
            send_batch_limit: non_zero_usize(100),
            idempotency_ttl_secs: non_zero_u64(86400),
            max_pre_keys: non_zero_u32(100),
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct NotificationConfig {
    /// How often to run the notification cleanup
    #[arg(long = "notifications-cleanup-interval-secs", env = "OBSCURA_NOTIFICATIONS_CLEANUP_INTERVAL_SECS", default_value_t = NotificationConfig::default().cleanup_interval_secs)]
    pub cleanup_interval_secs: NonZeroU64,

    /// Capacity of the global notification dispatcher channel
    #[arg(long = "notifications-global-channel-capacity", env = "OBSCURA_NOTIFICATIONS_GLOBAL_CHANNEL_CAPACITY", default_value_t = NotificationConfig::default().global_channel_capacity)]
    pub global_channel_capacity: NonZeroUsize,

    /// Capacity of the per-device notification channel
    #[arg(long = "notifications-device-channel-capacity", env = "OBSCURA_NOTIFICATIONS_DEVICE_CHANNEL_CAPACITY", default_value_t = NotificationConfig::default().device_channel_capacity)]
    pub device_channel_capacity: NonZeroUsize,

    /// Delay in seconds before a push notification is sent as a fallback
    #[arg(long = "notifications-push-delay-secs", env = "OBSCURA_NOTIFICATIONS_PUSH_DELAY_SECS", default_value_t = NotificationConfig::default().push_delay_secs)]
    pub push_delay_secs: u64,

    /// Interval in seconds for the notification worker to poll for due jobs
    #[arg(long = "notifications-worker-interval-secs", env = "OBSCURA_NOTIFICATIONS_WORKER_INTERVAL_SECS", default_value_t = NotificationConfig::default().worker_interval_secs)]
    pub worker_interval_secs: NonZeroU64,

    /// Maximum number of concurrent push notification requests (also used as Redis poll limit)
    #[arg(long = "notifications-worker-concurrency", env = "OBSCURA_NOTIFICATIONS_WORKER_CONCURRENCY", default_value_t = NotificationConfig::default().worker_concurrency)]
    pub worker_concurrency: NonZeroUsize,

    /// Redis key for the push notification job queue
    #[arg(long = "notifications-push-queue-key", env = "OBSCURA_NOTIFICATIONS_PUSH_QUEUE_KEY", default_value_t = NotificationConfig::default().push_queue_key)]
    pub push_queue_key: String,

    /// Redis `PubSub` channel prefix for device notifications
    #[arg(long = "notifications-channel-prefix", env = "OBSCURA_NOTIFICATIONS_CHANNEL_PREFIX", default_value_t = NotificationConfig::default().channel_prefix)]
    pub channel_prefix: String,

    /// How long a push job is leased by a worker in seconds
    #[arg(long = "notifications-visibility-timeout-secs", env = "OBSCURA_NOTIFICATIONS_VISIBILITY_TIMEOUT_SECS", default_value_t = NotificationConfig::default().visibility_timeout_secs)]
    pub visibility_timeout_secs: NonZeroU64,

    /// How often the invalid token cleanup flushes to the database in seconds
    #[arg(long = "notifications-invalid-token-cleanup-interval-secs", env = "OBSCURA_NOTIFICATIONS_INVALID_TOKEN_CLEANUP_INTERVAL_SECS", default_value_t = NotificationConfig::default().invalid_token_cleanup_interval_secs)]
    pub invalid_token_cleanup_interval_secs: NonZeroU64,

    /// Maximum number of invalid tokens to delete in a single batch
    #[arg(long = "notifications-invalid-token-cleanup-batch-size", env = "OBSCURA_NOTIFICATIONS_INVALID_TOKEN_CLEANUP_BATCH_SIZE", default_value_t = NotificationConfig::default().invalid_token_cleanup_batch_size)]
    pub invalid_token_cleanup_batch_size: NonZeroUsize,

    /// Capacity of the invalid token cleanup channel
    #[arg(long = "notifications-invalid-token-cleanup-channel-capacity", env = "OBSCURA_NOTIFICATIONS_INVALID_TOKEN_CLEANUP_CHANNEL_CAPACITY", default_value_t = NotificationConfig::default().invalid_token_cleanup_channel_capacity)]
    pub invalid_token_cleanup_channel_capacity: NonZeroUsize,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            cleanup_interval_secs: non_zero_u64(60),
            global_channel_capacity: non_zero_usize(1024),
            device_channel_capacity: non_zero_usize(64),
            push_delay_secs: 2,
            worker_interval_secs: non_zero_u64(1),
            worker_concurrency: non_zero_usize(100),
            push_queue_key: "jobs:push_notifications".to_string(),
            channel_prefix: "device:".to_string(),
            visibility_timeout_secs: non_zero_u64(30),
            invalid_token_cleanup_interval_secs: non_zero_u64(5),
            invalid_token_cleanup_batch_size: non_zero_usize(50),
            invalid_token_cleanup_channel_capacity: non_zero_usize(256),
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct WsConfig {
    /// Size of the outbound message buffer
    #[arg(long = "ws-outbound-buffer-size", env = "OBSCURA_WS_OUTBOUND_BUFFER_SIZE", default_value_t = WsConfig::default().outbound_buffer_size)]
    pub outbound_buffer_size: NonZeroUsize,

    /// Size of the acknowledgment buffer
    #[arg(long = "ws-ack-buffer-size", env = "OBSCURA_WS_ACK_BUFFER_SIZE", default_value_t = WsConfig::default().ack_buffer_size)]
    pub ack_buffer_size: NonZeroUsize,

    /// Number of acknowledgments to batch before flushing
    #[arg(long = "ws-ack-batch-size", env = "OBSCURA_WS_ACK_BATCH_SIZE", default_value_t = WsConfig::default().ack_batch_size)]
    pub ack_batch_size: NonZeroUsize,

    /// How often to flush pending acknowledgments
    #[arg(long = "ws-ack-flush-interval-ms", env = "OBSCURA_WS_ACK_FLUSH_INTERVAL_MS", default_value_t = WsConfig::default().ack_flush_interval_ms)]
    pub ack_flush_interval_ms: u64,

    /// How often to send a WebSocket ping frame in seconds.
    /// A value of 0 results in a 1-second interval.
    #[arg(
            long = "ws-ping-interval-secs",
            env = "OBSCURA_WS_PING_INTERVAL_SECS",
            default_value_t = WsConfig::default().ping_interval_secs
        )]
    pub ping_interval_secs: NonZeroU64,

    /// How long to wait for a pong response before closing the connection in seconds
    #[arg(long = "ws-ping-timeout-secs", env = "OBSCURA_WS_PING_TIMEOUT_SECS", default_value_t = WsConfig::default().ping_timeout_secs)]
    pub ping_timeout_secs: u64,

    /// Maximum number of messages to fetch in a single database query and deliver in a single WebSocket batch frame
    #[arg(
        long = "ws-message-fetch-batch-size",
        env = "OBSCURA_WS_MESSAGE_FETCH_BATCH_SIZE",
        default_value_t = WsConfig::default().message_fetch_batch_size
    )]
    pub message_fetch_batch_size: NonZeroU32,

    /// Maximum size in bytes for a single WebSocket batch frame.
    /// Envelopes are split into sub-batches that stay under this limit to avoid
    /// exceeding client-side frame size limits (e.g. tungstenite's 16 MiB default).
    #[arg(
        long = "ws-max-batch-bytes",
        env = "OBSCURA_WS_MAX_BATCH_BYTES",
        default_value_t = WsConfig::default().max_batch_bytes
    )]
    pub max_batch_bytes: usize,

    /// How long a delivery notification keeps retrying a failed database read, in milliseconds
    #[arg(
        long = "ws-fetch-retry-budget-ms",
        env = "OBSCURA_WS_FETCH_RETRY_BUDGET_MS",
        default_value_t = WsConfig::default().fetch_retry_budget_ms
    )]
    pub fetch_retry_budget_ms: u64,

    /// Time-to-live for WebSocket authentication tickets in seconds
    #[arg(
        long = "ws-ticket-ttl-secs",
        env = "OBSCURA_WS_TICKET_TTL_SECS",
        default_value_t = WsConfig::default().ticket_ttl_secs
    )]
    pub ticket_ttl_secs: NonZeroU64,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            outbound_buffer_size: non_zero_usize(32),
            ack_buffer_size: non_zero_usize(1000),
            ack_batch_size: non_zero_usize(100),
            ack_flush_interval_ms: 500,
            ping_interval_secs: non_zero_u64(30),
            ping_timeout_secs: 10,
            message_fetch_batch_size: non_zero_u32(50),
            max_batch_bytes: 8 * 1024 * 1024, // 8 MiB
            fetch_retry_budget_ms: 10_000,
            ticket_ttl_secs: non_zero_u64(30),
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct AttachmentConfig {
    /// Max attachment size in bytes (Default: 50MB)
    #[arg(
        long = "attachment-max-size-bytes",
        id = "ATTACHMENT_MAX_SIZE_BYTES",
        env = "OBSCURA_ATTACHMENT_MAX_SIZE_BYTES",
        default_value_t = AttachmentConfig::default().max_size_bytes
    )]
    pub max_size_bytes: u64,

    /// Min attachment size in bytes (Default: 1 byte)
    #[arg(
        long = "attachment-min-size-bytes",
        id = "ATTACHMENT_MIN_SIZE_BYTES",
        env = "OBSCURA_ATTACHMENT_MIN_SIZE_BYTES",
        default_value_t = AttachmentConfig::default().min_size_bytes
    )]
    pub min_size_bytes: u64,

    /// S3 prefix for logical namespacing of attachments.
    #[arg(
        long = "attachment-prefix",
        id = "ATTACHMENT_PREFIX",
        env = "OBSCURA_ATTACHMENT_PREFIX",
        default_value_t = AttachmentConfig::default().prefix
    )]
    pub prefix: String,

    /// How often to run the attachment cleanup task in seconds
    #[arg(
        long = "attachment-cleanup-interval-secs",
        id = "ATTACHMENT_CLEANUP_INTERVAL_SECS",
        env = "OBSCURA_ATTACHMENT_CLEANUP_INTERVAL_SECS",
        default_value_t = AttachmentConfig::default().cleanup_interval_secs
    )]
    pub cleanup_interval_secs: NonZeroU64,

    /// Maximum number of attachments to delete in a single batch
    #[arg(
        long = "attachment-cleanup-batch-size",
        id = "ATTACHMENT_CLEANUP_BATCH_SIZE",
        env = "OBSCURA_ATTACHMENT_CLEANUP_BATCH_SIZE",
        default_value_t = AttachmentConfig::default().cleanup_batch_size
    )]
    pub cleanup_batch_size: NonZeroU32,

    /// S3 streaming timeout in seconds
    #[arg(
        long = "attachment-timeout-secs",
        id = "ATTACHMENT_TIMEOUT_SECS",
        env = "OBSCURA_ATTACHMENT_TIMEOUT_SECS",
        default_value_t = AttachmentConfig::default().request_timeout_secs
    )]
    pub request_timeout_secs: NonZeroU64,
}

impl Default for AttachmentConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 52_428_800,
            min_size_bytes: 1,
            prefix: "attachments/".to_string(),
            cleanup_interval_secs: non_zero_u64(3600),
            cleanup_batch_size: non_zero_u32(100),
            request_timeout_secs: non_zero_u64(120),
        }
    }
}

impl AttachmentConfig {
    /// # Errors
    /// Returns [`ConfigError::AttachmentSizeLimits`] if the minimum size exceeds the maximum.
    pub const fn size_limits(&self) -> Result<SizeLimits, ConfigError> {
        let (min, max) = (self.min_size_bytes, self.max_size_bytes);
        match SizeLimits::new(min, max) {
            Some(limits) => Ok(limits),
            None => Err(ConfigError::AttachmentSizeLimits { min, max }),
        }
    }

    /// The storage key of an attachment.
    #[must_use]
    pub fn object_key(&self, id: Uuid) -> String {
        format!("{}{id}", self.prefix)
    }
}

#[derive(Clone, Debug, Args)]
pub struct StorageConfig {
    /// Storage bucket name
    #[arg(
        long = "storage-bucket",
        id = "STORAGE_BUCKET",
        env = "OBSCURA_STORAGE_BUCKET",
        default_value_t = StorageConfig::default().bucket
    )]
    pub bucket: String,

    /// Storage region
    #[arg(
        long = "storage-region",
        id = "STORAGE_REGION",
        env = "OBSCURA_STORAGE_REGION",
        default_value_t = StorageConfig::default().region
    )]
    pub region: String,

    /// Custom storage endpoint (useful for `MinIO` or other S3-compatible services)
    #[arg(long = "storage-endpoint", id = "STORAGE_ENDPOINT", env = "OBSCURA_STORAGE_ENDPOINT")]
    pub endpoint: Option<String>,

    /// Storage access key
    #[arg(long = "storage-access-key", id = "STORAGE_ACCESS_KEY", env = "OBSCURA_STORAGE_ACCESS_KEY")]
    pub access_key: Option<String>,

    /// Storage secret key
    #[arg(long = "storage-secret-key", id = "STORAGE_SECRET_KEY", env = "OBSCURA_STORAGE_SECRET_KEY")]
    pub secret_key: Option<String>,

    /// Force path style (required for many `MinIO` setups: <http://host/bucket/key>)
    #[arg(
        long = "storage-force-path-style",
        id = "STORAGE_FORCE_PATH_STYLE",
        env = "OBSCURA_STORAGE_FORCE_PATH_STYLE",
        default_value_t = StorageConfig::default().force_path_style
    )]
    pub force_path_style: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            bucket: "obscura-storage".to_string(),
            region: "us-east-1".to_string(),
            endpoint: None,
            access_key: None,
            secret_key: None,
            force_path_style: false,
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct HealthConfig {
    /// Timeout for database health check in milliseconds
    #[arg(
        long = "health-db-timeout-ms",
        id = "HEALTH_DB_TIMEOUT_MS",
        env = "OBSCURA_HEALTH_DB_TIMEOUT_MS",
        default_value_t = HealthConfig::default().db_timeout_ms
    )]
    pub db_timeout_ms: NonZeroU64,

    /// Timeout for storage health check in milliseconds
    #[arg(
        long = "health-storage-timeout-ms",
        id = "HEALTH_STORAGE_TIMEOUT_MS",
        env = "OBSCURA_HEALTH_STORAGE_TIMEOUT_MS",
        default_value_t = HealthConfig::default().storage_timeout_ms
    )]
    pub storage_timeout_ms: NonZeroU64,

    /// Timeout for pubsub health check in milliseconds
    #[arg(
        long = "health-pubsub-timeout-ms",
        id = "HEALTH_PUBSUB_TIMEOUT_MS",
        env = "OBSCURA_HEALTH_PUBSUB_TIMEOUT_MS",
        default_value_t = HealthConfig::default().pubsub_timeout_ms
    )]
    pub pubsub_timeout_ms: NonZeroU64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            db_timeout_ms: non_zero_u64(2000),
            storage_timeout_ms: non_zero_u64(2000),
            pubsub_timeout_ms: non_zero_u64(2000),
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct FcmConfig {
    /// Google Cloud Project ID for FCM
    #[arg(long = "fcm-project-id", env = "OBSCURA_FCM_PROJECT_ID")]
    pub project_id: Option<String>,

    /// Path to the Google service account JSON credentials file
    #[arg(long = "fcm-credentials-file", env = "OBSCURA_FCM_CREDENTIALS_FILE")]
    pub credentials_file: Option<String>,

    /// Time-to-live for FCM push notifications in seconds
    #[arg(long = "fcm-ttl-secs", env = "OBSCURA_FCM_TTL_SECS", default_value_t = FcmConfig::default().ttl_secs)]
    pub ttl_secs: u64,
}

impl Default for FcmConfig {
    fn default() -> Self {
        Self { project_id: None, credentials_file: None, ttl_secs: 604_800 }
    }
}

/// The project and service account FCM needs to send pushes, both present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FcmCredentials<'a> {
    pub project_id: &'a str,
    pub credentials_file: &'a str,
}

impl FcmConfig {
    /// The FCM credentials, or `None` if FCM is not configured. An empty value counts as unset, so an
    /// environment variable set to an empty string leaves FCM off.
    ///
    /// # Errors
    /// Returns [`ConfigError::PartialFcm`] if only one of the two values is set.
    pub fn credentials(&self) -> Result<Option<FcmCredentials<'_>>, ConfigError> {
        fn set(value: Option<&str>) -> Option<&str> {
            value.filter(|s| !s.is_empty())
        }
        match (set(self.project_id.as_deref()), set(self.credentials_file.as_deref())) {
            (Some(project_id), Some(credentials_file)) => Ok(Some(FcmCredentials { project_id, credentials_file })),
            (None, None) => Ok(None),
            (Some(_), None) => Err(ConfigError::PartialFcm { missing: "OBSCURA_FCM_CREDENTIALS_FILE" }),
            (None, Some(_)) => Err(ConfigError::PartialFcm { missing: "OBSCURA_FCM_PROJECT_ID" }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Config::command().debug_assert();
    }

    #[test]
    fn test_defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn test_limits_reject_zero_and_negative_values() {
        for value in ["0", "-5"] {
            let result = Config::try_parse_from(["obscura-server", "--messaging-send-batch-limit", value]);
            assert!(result.is_err(), "a send batch limit of {value} should not parse");
        }
        let config = Config::try_parse_from(["obscura-server", "--messaging-send-batch-limit", "7"]).unwrap();
        assert_eq!(config.messaging.send_batch_limit.get(), 7);
    }

    #[test]
    fn test_sampling_ratio_must_be_between_zero_and_one() {
        let parse = |value: &str| {
            Config::try_parse_from(["obscura-server", "--telemetry-trace-sampling-ratio", value])
                .map(|config| config.telemetry.trace_sampling_ratio)
        };
        assert_eq!(parse("0").unwrap(), 0.0);
        assert_eq!(parse("0.25").unwrap(), 0.25);
        assert_eq!(parse("1").unwrap(), 1.0);
        for value in ["10", "1.01", "-0.1", "NaN", "abc"] {
            assert!(parse(value).is_err(), "a sampling ratio of {value} should not parse");
        }
    }

    #[test]
    fn test_inverted_attachment_sizes_are_rejected() {
        let mut config = Config::default();
        config.attachment.min_size_bytes = 11;
        config.attachment.max_size_bytes = 10;
        assert!(matches!(config.validate(), Err(ConfigError::AttachmentSizeLimits { min: 11, max: 10 })));
    }

    #[test]
    fn test_object_key_prefixes_the_id() {
        let config = AttachmentConfig { prefix: "att/".to_string(), ..Default::default() };
        let id = Uuid::new_v4();
        assert_eq!(config.object_key(id), format!("att/{id}"));
    }

    #[test]
    fn test_fcm_credentials_require_both_values_or_neither() {
        let fcm = |project: Option<&str>, credentials: Option<&str>| FcmConfig {
            project_id: project.map(String::from),
            credentials_file: credentials.map(String::from),
            ..Default::default()
        };

        assert_eq!(fcm(None, None).credentials().unwrap(), None);
        assert_eq!(fcm(Some(""), Some("")).credentials().unwrap(), None, "empty values count as unset");
        assert_eq!(
            fcm(Some("proj"), Some("/creds.json")).credentials().unwrap(),
            Some(FcmCredentials { project_id: "proj", credentials_file: "/creds.json" })
        );
        assert!(matches!(
            fcm(Some("proj"), None).credentials(),
            Err(ConfigError::PartialFcm { missing: "OBSCURA_FCM_CREDENTIALS_FILE" })
        ));
        assert!(matches!(
            fcm(Some(""), Some("/creds.json")).credentials(),
            Err(ConfigError::PartialFcm { missing: "OBSCURA_FCM_PROJECT_ID" })
        ));
    }

    #[test]
    #[allow(clippy::panic)]
    fn test_docs_up_to_date() {
        const AT_LEAST_ONE: &str = "At least 1.";
        let docs = std::fs::read_to_string("docs/CONFIGURATION.md").expect("Could not read CONFIGURATION.md");
        let cmd = Config::command();

        for arg in cmd.get_arguments() {
            if arg.is_hide_set() {
                continue;
            }

            let env = arg.get_env();
            if env.is_none() {
                continue;
            }

            let env_name = env.expect("Missing environment variable name").to_string_lossy();
            let env_pattern = format!("`{env_name}`");
            let env_count = docs.matches(&env_pattern).count();
            assert_eq!(
                env_count, 1,
                "Environment variable {env_pattern} must appear exactly once in documentation, found {env_count}"
            );

            if let Some(long) = arg.get_long() {
                let flag_pattern = format!("`--{long}`");
                let flag_count = docs.matches(&flag_pattern).count();
                assert_eq!(
                    flag_count, 1,
                    "Flag {flag_pattern} must appear exactly once in documentation, found {flag_count}"
                );

                // Verify default value
                let defaults = arg.get_default_values();
                let expected_default = if defaults.is_empty() {
                    // Special case for boolean flags which default to false in our docs
                    if arg.get_id() == "STORAGE_FORCE_PATH_STYLE" { "false".to_string() } else { "None".to_string() }
                } else {
                    defaults.iter().map(|v| v.to_string_lossy()).collect::<Vec<_>>().join(",")
                };

                // Extract the default value from the markdown table row
                // Pattern: | --flag | ENV_VAR | Default | Description |
                let row_pattern =
                    format!(r"\| `--{}` \| `{}` \| ([^|]+) \| (.*) \|", regex::escape(long), regex::escape(&env_name));
                let re = regex::Regex::new(&row_pattern).expect("Invalid regex pattern");

                if let Some(caps) = re.captures(&docs) {
                    let actual_default = caps.get(1).expect("Missing capture group").as_str().trim().replace('`', "");
                    assert_eq!(
                        actual_default, expected_default,
                        "Default value mismatch for flag --{long}. Expected '{expected_default}', found '{actual_default}' in docs"
                    );

                    // An integer option whose type rejects 0 must say so, and only those may.
                    let description = caps.get(2).expect("Missing capture group").as_str();
                    let integer = expected_default.parse::<i64>().is_ok();
                    let rejects_zero =
                        integer && Config::try_parse_from(["obscura-server", &format!("--{long}"), "0"]).is_err();
                    assert_eq!(
                        description.contains(AT_LEAST_ONE),
                        rejects_zero,
                        "--{long} {} 0, so its description must {}contain \"{AT_LEAST_ONE}\"",
                        if rejects_zero { "rejects" } else { "accepts" },
                        if rejects_zero { "" } else { "not " },
                    );
                } else {
                    panic!(
                        "Could not find documentation row for flag --{long} and env {env_name}. \
                         Ensure it matches the format: | `--{long}` | `{env_name}` | Default | Description |"
                    );
                }
            }
        }
    }
}
