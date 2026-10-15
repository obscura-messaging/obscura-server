pub mod adapters;
pub mod api;
pub mod config;
pub mod domain;
pub mod error;
pub mod proto;
pub mod services;
pub mod telemetry;
pub mod workers;

use crate::adapters::database::attachment_repo::AttachmentRepository;
use crate::adapters::database::backup_repo::BackupRepository;
use crate::adapters::database::device_repo::DeviceRepository;
use crate::adapters::database::key_repo::KeyRepository;
use crate::adapters::database::link_session_repo::LinkSessionRepository;
use crate::adapters::database::message_repo::MessageRepository;
use crate::adapters::database::push_token_repo::PushTokenRepository;
use crate::adapters::database::refresh_token_repo::RefreshTokenRepository;
use crate::adapters::database::user_repo::UserRepository;
use crate::adapters::push::PushProvider;
use crate::adapters::redis::RedisCache;
use crate::adapters::storage::S3Storage;
use crate::config::{Config, StorageConfig};
use crate::services::attachment_service::AttachmentService;
use crate::services::auth_service::AuthService;
use crate::services::backup_service::BackupService;
use crate::services::crypto_service::CryptoService;
use crate::services::device_service::DeviceService;
use crate::services::gateway::GatewayService;
use crate::services::health_service::HealthService;
use crate::services::key_service::KeyService;
use crate::services::link_session_service::LinkSessionService;
use crate::services::message_service::MessageService;
use crate::services::notification_service::NotificationService;
use crate::services::push_token_service::PushTokenService;
use crate::services::rate_limit_service::RateLimitService;
use crate::workers::{
    AttachmentCleanupWorker, BackupCleanupWorker, MessageCleanupWorker, NotificationWorker, PushNotificationWorker,
    RefreshTokenCleanupWorker,
};
use std::sync::Arc;
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub struct Resources {
    pub pool: adapters::database::DbPool,
    pub pubsub: Arc<adapters::redis::RedisClient>,
    pub s3_client: aws_sdk_s3::Client,
}

#[derive(Clone)]
pub struct Adapters {
    pub device: DeviceRepository,
    pub key: KeyRepository,
    pub link_session: LinkSessionRepository,
    pub message: MessageRepository,
    pub user: UserRepository,
    pub refresh: RefreshTokenRepository,
    pub attachment: AttachmentRepository,
    pub backup: BackupRepository,
    pub push_token: PushTokenRepository,
    pub notification: Arc<adapters::redis::NotificationRepository>,
    pub storage: Arc<dyn adapters::storage::ObjectStorage>,
    pub push: Arc<dyn PushProvider>,
}

impl std::fmt::Debug for Adapters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Adapters")
            .field("device", &self.device)
            .field("key", &self.key)
            .field("link_session", &self.link_session)
            .field("message", &self.message)
            .field("user", &self.user)
            .field("refresh", &self.refresh)
            .field("attachment", &self.attachment)
            .field("backup", &self.backup)
            .field("push_token", &self.push_token)
            .field("notification", &self.notification)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct Services {
    pub key_service: KeyService,
    pub attachment_service: AttachmentService,
    pub backup_service: BackupService,
    pub device_service: DeviceService,
    pub auth_service: AuthService,
    pub(crate) message_service: MessageService,
    pub(crate) gateway_service: GatewayService,
    pub notification_service: NotificationService,
    pub link_session_service: LinkSessionService,
    pub push_token_service: PushTokenService,
    pub rate_limit_service: RateLimitService,
    pub submission_cache: RedisCache,
    pub ws_ticket_cache: RedisCache,
}

#[derive(Debug)]
pub struct App {
    pub resources: Resources,
    pub services: Services,
    pub health_service: HealthService,
    pub workers: Workers,
}

#[derive(Debug)]
pub struct Workers {
    pub message_worker: MessageCleanupWorker,
    pub attachment_worker: AttachmentCleanupWorker,
    pub backup_worker: BackupCleanupWorker,
    pub push_worker: PushNotificationWorker,
    pub notification_worker: NotificationWorker,
    pub refresh_token_worker: RefreshTokenCleanupWorker,
}

impl Workers {
    /// Spawns every background worker into a [`JoinSet`] so the caller can supervise them: a worker
    /// returning before shutdown is a fault, and `main` needs to see it. Each task yields its name.
    #[must_use]
    pub fn spawn_all(self, shutdown_rx: watch::Receiver<bool>) -> tokio::task::JoinSet<&'static str> {
        let mut tasks = tokio::task::JoinSet::new();

        let message_worker = self.message_worker;
        let message_rx = shutdown_rx.clone();
        tasks.spawn(async move {
            message_worker.run(message_rx).await;
            "message_cleanup"
        });

        let attachment_worker = self.attachment_worker;
        let attachment_rx = shutdown_rx.clone();
        tasks.spawn(async move {
            attachment_worker.run(attachment_rx).await;
            "attachment_cleanup"
        });

        let backup_worker = self.backup_worker;
        let backup_rx = shutdown_rx.clone();
        tasks.spawn(async move {
            backup_worker.run(backup_rx).await;
            "backup_cleanup"
        });

        let push_worker = self.push_worker;
        let push_rx = shutdown_rx.clone();
        tasks.spawn(async move {
            push_worker.run(push_rx).await;
            "push_notification"
        });

        let notification_worker = self.notification_worker;
        let notification_rx = shutdown_rx.clone();
        tasks.spawn(async move {
            notification_worker.run(notification_rx).await;
            "notification"
        });

        let refresh_token_worker = self.refresh_token_worker;
        tasks.spawn(async move {
            refresh_token_worker.run(shutdown_rx).await;
            "refresh_token_cleanup"
        });

        tasks
    }
}

/// Builder for constructing and wiring the application object graph.
#[derive(Debug)]
pub struct AppBuilder {
    config: Config,
    pool: Option<adapters::database::DbPool>,
    pubsub: Option<Arc<adapters::redis::RedisClient>>,
    s3_client: Option<aws_sdk_s3::Client>,
    push_provider: Option<Arc<dyn PushProvider>>,
    shutdown_rx: Option<watch::Receiver<bool>>,
}

impl AppBuilder {
    /// Creates a new builder with the provided configuration.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self { config, pool: None, pubsub: None, s3_client: None, push_provider: None, shutdown_rx: None }
    }

    /// Sets the database connection pool.
    #[must_use]
    pub fn with_database(mut self, pool: adapters::database::DbPool) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Sets the `PubSub` (Redis) client.
    #[must_use]
    pub fn with_pubsub(mut self, pubsub: Arc<adapters::redis::RedisClient>) -> Self {
        self.pubsub = Some(pubsub);
        self
    }

    /// Sets the S3 storage client.
    #[must_use]
    pub fn with_s3(mut self, client: aws_sdk_s3::Client) -> Self {
        self.s3_client = Some(client);
        self
    }

    /// Sets the push notification provider.
    #[must_use]
    pub fn with_push_provider(mut self, provider: Arc<dyn PushProvider>) -> Self {
        self.push_provider = Some(provider);
        self
    }

    /// Sets the shutdown receiver for coordinating graceful exit.
    #[must_use]
    pub fn with_shutdown_rx(mut self, rx: watch::Receiver<bool>) -> Self {
        self.shutdown_rx = Some(rx);
        self
    }

    /// Builds the application components by wiring all services and repositories.
    ///
    /// # Errors
    /// Returns an error if mandatory dependencies (pool, pubsub, etc.) are missing,
    /// or if any service fails to initialize.
    #[tracing::instrument(skip(self))]
    #[allow(clippy::too_many_lines)]
    pub async fn initialize(self) -> anyhow::Result<App> {
        let pool = self.pool.ok_or_else(|| anyhow::anyhow!("Database pool is required"))?;
        let pubsub = self.pubsub.ok_or_else(|| anyhow::anyhow!("PubSub client is required"))?;
        let s3_client = self.s3_client.ok_or_else(|| anyhow::anyhow!("S3 client is required"))?;
        let push_provider = self.push_provider.ok_or_else(|| anyhow::anyhow!("Push provider is required"))?;
        let _shutdown_rx = self.shutdown_rx.clone().ok_or_else(|| anyhow::anyhow!("Shutdown receiver is required"))?;

        let config = &self.config;

        let resources = Resources { pool: pool.clone(), pubsub: Arc::clone(&pubsub), s3_client: s3_client.clone() };

        // Initialize Adapters (Trait implementations and Repositories)
        let adapters = Adapters {
            device: DeviceRepository::new(),
            key: KeyRepository::new(),
            link_session: LinkSessionRepository::new(),
            message: MessageRepository::new(),
            user: UserRepository::new(),
            refresh: RefreshTokenRepository::new(),
            attachment: AttachmentRepository::new(),
            backup: BackupRepository::new(),
            push_token: PushTokenRepository::new(),
            notification: Arc::new(adapters::redis::NotificationRepository::new(
                Arc::clone(&pubsub),
                &config.notifications,
            )),
            storage: Arc::new(S3Storage::new(s3_client.clone(), config.storage.bucket.clone())),
            push: push_provider,
        };

        // Initialize Core Services
        let crypto_service = CryptoService::new();
        let notifier = NotificationService::new(Arc::clone(&adapters.notification), &config.notifications);
        let key_service = KeyService::new(
            pool.clone(),
            adapters.key.clone(),
            crypto_service,
            notifier.clone(),
            config.messaging.clone(),
        );
        let auth_service = AuthService::new(
            config.auth.clone(),
            pool.clone(),
            adapters.user.clone(),
            adapters.refresh.clone(),
            adapters.device.clone(),
        );
        let submission_cache = RedisCache::new(
            Arc::clone(&pubsub),
            "idempotency:submission:".to_string(),
            config.messaging.idempotency_ttl_secs,
        );
        let ws_ticket_cache =
            RedisCache::new(Arc::clone(&pubsub), "ws:ticket:".to_string(), config.websocket.ticket_ttl_secs);
        let message_service = MessageService::new(
            pool.clone(),
            adapters.message.clone(),
            notifier.clone(),
            config.messaging.clone(),
            config.ttl_days,
        );
        let device_service = DeviceService::new(
            pool.clone(),
            adapters.device.clone(),
            adapters.user.clone(),
            adapters.link_session.clone(),
            key_service.clone(),
            auth_service.clone(),
            notifier.clone(),
            config.auth.max_devices_per_user,
        );
        let link_session_service =
            LinkSessionService::new(pool.clone(), adapters.device.clone(), adapters.link_session.clone());
        let gateway_service = GatewayService::new(
            message_service.clone(),
            key_service.clone(),
            notifier.clone(),
            config.websocket.clone(),
        );
        let push_token_service = PushTokenService::new(pool.clone(), adapters.push_token.clone());
        let attachment_service = AttachmentService::new(
            pool.clone(),
            adapters.attachment.clone(),
            Arc::clone(&adapters.storage),
            config.attachment.clone(),
            config.ttl_days,
        );
        let backup_service = BackupService::new(
            pool.clone(),
            adapters.backup.clone(),
            Arc::clone(&adapters.storage),
            config.backup.clone(),
        );
        let rate_limit_service = RateLimitService::new(config.server.trusted_proxies.clone());
        let health_service = HealthService::new(
            pool.clone(),
            s3_client,
            Arc::clone(&pubsub),
            config.storage.bucket.clone(),
            config.health.clone(),
        );

        let services = Services {
            key_service,
            attachment_service,
            backup_service,
            device_service,
            auth_service,
            message_service,
            gateway_service,
            notification_service: notifier.clone(),
            link_session_service,
            push_token_service,
            rate_limit_service,
            submission_cache,
            ws_ticket_cache,
        };

        let workers = Self::init_workers(config, &pool, &adapters, notifier);

        Ok(App { resources, services, health_service, workers })
    }

    fn init_workers(
        config: &Config,
        pool: &adapters::database::DbPool,
        adapters: &Adapters,
        notifier: NotificationService,
    ) -> Workers {
        Workers {
            message_worker: MessageCleanupWorker::new(pool.clone(), adapters.message.clone(), config.messaging.clone()),
            attachment_worker: AttachmentCleanupWorker::new(
                pool.clone(),
                adapters.attachment.clone(),
                Arc::clone(&adapters.storage),
                config.attachment.clone(),
            ),
            backup_worker: BackupCleanupWorker::new(
                pool.clone(),
                adapters.backup.clone(),
                Arc::clone(&adapters.storage),
                config.backup.clone(),
            ),
            push_worker: PushNotificationWorker::new(
                pool.clone(),
                Arc::clone(&adapters.notification),
                Arc::clone(&adapters.push),
                adapters.push_token.clone(),
                &config.notifications,
            ),
            notification_worker: NotificationWorker::new(
                notifier,
                Arc::clone(&adapters.notification),
                config.notifications.cleanup_interval_secs,
            ),
            refresh_token_worker: RefreshTokenCleanupWorker::new(
                pool.clone(),
                adapters.refresh.clone(),
                config.auth.refresh_token_cleanup_interval_secs,
            ),
        }
    }
}

/// Runs database migrations.
///
/// # Errors
/// Returns an error if migrations fail.
#[tracing::instrument(skip(pool))]
pub async fn run_migrations(pool: &adapters::database::DbPool) -> anyhow::Result<()> {
    sqlx::migrate!().run(pool).await.map_err(Into::into)
}

/// Initializes an S3 client from configuration.
#[tracing::instrument(skip(config))]
pub async fn initialize_s3_client(config: &StorageConfig) -> aws_sdk_s3::Client {
    let region_provider = aws_config::Region::new(config.region.clone());
    let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest()).region(region_provider);

    if let Some(ref endpoint) = config.endpoint {
        config_loader = config_loader.endpoint_url(endpoint);
    }

    if let (Some(ak), Some(sk)) = (&config.access_key, &config.secret_key) {
        let creds = aws_credential_types::Credentials::new(ak.clone(), sk.clone(), None, None, "static");
        config_loader = config_loader.credentials_provider(creds);
    }

    let sdk_config = config_loader.load().await;
    let s3_config_builder = aws_sdk_s3::config::Builder::from(&sdk_config).force_path_style(config.force_path_style);
    aws_sdk_s3::Client::from_conf(s3_config_builder.build())
}

/// Sets up a panic hook that logs the panic message and location.
pub fn setup_panic_hook() {
    std::panic::set_hook(Box::new(|panic_info| {
        let payload = panic_info.payload();
        let msg = payload
            .downcast_ref::<&str>()
            .map_or_else(|| payload.downcast_ref::<String>().map_or_else(|| "Box<Any>", String::as_str), |s| *s);

        let location = panic_info.location().map_or_else(
            || "unknown".to_string(),
            |location| format!("{}:{}:{}", location.file(), location.line(), location.column()),
        );

        tracing::error!(
            panic.message = %msg,
            panic.location = %location,
            "Application panicked"
        );
    }));
}

/// Returns a future that completes when a termination signal is received.
///
/// # Panics
/// Panics if the signal handlers cannot be installed.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("Shutdown signal received, starting graceful shutdown...");
}

/// Spawns a task that listens for OS signals and broadcasts a shutdown signal.
pub fn spawn_signal_handler(shutdown_tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });
}
