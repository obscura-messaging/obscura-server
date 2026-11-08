use anyhow::Context;
use obscura_server::api::MgmtState;
use obscura_server::config::Config;
use obscura_server::{AppBuilder, adapters, telemetry};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::Instrument;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::load()?;
    let telemetry_guard = telemetry::init_telemetry(&config.telemetry)?;

    obscura_server::setup_panic_hook();

    let boot_span = tracing::info_span!("boot_server");
    let (api_listener, mgmt_listener, app_router, mgmt_app, shutdown_tx, shutdown_rx, workers) = async {
        // Phase 1: Infrastructure Setup (Resources)
        let pool = adapters::database::init_pool(&config.database).await?;
        obscura_server::run_migrations(&pool).await?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        obscura_server::spawn_signal_handler(shutdown_tx.clone());

        let pubsub = adapters::redis::RedisClient::new(
            &config.pubsub,
            config.notifications.global_channel_capacity,
            shutdown_rx.clone(),
        )
        .await?;

        let s3_client = obscura_server::initialize_s3_client(&config.storage).await;

        // Phase 2: Component Wiring (Pure logic, no side effects)
        let push_provider: Arc<dyn adapters::push::PushProvider> = if let Some(fcm) = config.fcm.settings()? {
            tracing::info!("FCM credentials configured, using real FCM push provider");
            Arc::new(
                adapters::push::fcm::FcmPushProvider::new(fcm, config.fcm.ttl_secs)
                    .context("Failed to initialize FCM push provider. Verify that OBSCURA_FCM_CREDENTIALS_FILE points to a valid service account JSON file")?,
            )
        } else {
            tracing::warn!("FCM credentials not configured, push notifications will be logged but not sent");
            Arc::new(adapters::push::LoggingPushProvider)
        };
        let app = AppBuilder::new(config.clone())
            .with_database(pool)
            .with_pubsub(pubsub)
            .with_s3(s3_client)
            .with_push_provider(push_provider)
            .with_shutdown_rx(shutdown_rx.clone())
            .initialize()
            .await?;

        // Phase 3: Runtime Setup (Listeners and Routers)
        let app_router = obscura_server::api::app_router(&config, app.services, shutdown_rx.clone());
        let mgmt_app = obscura_server::api::mgmt_router(MgmtState { health_service: app.health_service });

        let api_addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
        let mgmt_addr: SocketAddr = format!("{}:{}", config.server.host, config.server.mgmt_port).parse()?;

        tracing::info!(address = %api_addr, "listening");
        tracing::info!(address = %mgmt_addr, "management server listening");

        let api_listener = tokio::net::TcpListener::bind(api_addr).await?;
        let mgmt_listener = tokio::net::TcpListener::bind(mgmt_addr).await?;

        Ok::<
            (
                tokio::net::TcpListener,
                tokio::net::TcpListener,
                axum::Router,
                axum::Router,
                watch::Sender<bool>,
                watch::Receiver<bool>,
                obscura_server::Workers,
            ),
            anyhow::Error,
        >((api_listener, mgmt_listener, app_router, mgmt_app, shutdown_tx, shutdown_rx, app.workers))
    }
    .instrument(boot_span)
    .await?;

    // Phase 4: Start Runtime (Explicit Spawning and Listening)
    let mut worker_tasks = workers.spawn_all(shutdown_rx.clone());

    let mut api_rx = shutdown_rx.clone();
    let api_server = axum::serve(api_listener, app_router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async move {
            let _ = api_rx.wait_for(|&s| s).await;
        });

    let mut mgmt_rx = shutdown_rx.clone();
    let mgmt_server = axum::serve(mgmt_listener, mgmt_app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async move {
            let _ = mgmt_rx.wait_for(|&s| s).await;
        });

    let mut server_task = tokio::spawn(async move {
        if let Err(e) = tokio::try_join!(api_server, mgmt_server) {
            tracing::error!(error = %e, "Server error");
        }
    });

    // A worker finishing while we are not shutting down is fatal, each runs for the life of the process.
    let mut servers_finished = false;
    let mut worker_fault = None;
    tokio::select! {
        res = &mut server_task => {
            servers_finished = true;
            if let Err(e) = res {
                tracing::error!(error = %e, "Server task panicked");
            }
        }
        Some(res) = worker_tasks.join_next() => match res {
            Ok(name) if *shutdown_rx.borrow() => tracing::info!(worker = %name, "Worker finished during shutdown"),
            Ok(name) => {
                tracing::error!(worker = %name, "Worker exited unexpectedly; shutting down");
                worker_fault = Some(format!("background worker {name} exited unexpectedly"));
            }
            Err(e) => {
                tracing::error!(error = %e, "Worker panicked; shutting down");
                worker_fault = Some(format!("background worker panicked: {e}"));
            }
        },
    }

    // Phase 5: Graceful Shutdown Orchestration
    let _ = shutdown_tx.send(true);

    let shutdown_timeout = std::time::Duration::from_secs(config.server.shutdown_timeout_secs);
    let running_server = (!servers_finished).then_some(server_task);
    drain(running_server, &mut worker_tasks, shutdown_timeout).await;

    telemetry_guard.shutdown();

    // Exit non-zero so the fault is visible to anything reading the exit code, not just the logs.
    worker_fault.map_or(Ok(()), |reason| Err(anyhow::anyhow!(reason)))
}

/// Waits for the HTTP servers, then the background workers, within one shared `timeout`.
///
/// Servers drain first so in-flight requests finish against workers that are still alive. The
/// deadline is shared rather than applied twice, so the whole shutdown stays inside the window a
/// `terminationGracePeriodSeconds` is tuned against.
async fn drain(
    server_task: Option<tokio::task::JoinHandle<()>>,
    workers: &mut tokio::task::JoinSet<&'static str>,
    timeout: std::time::Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;

    if let Some(task) = server_task
        && tokio::time::timeout_at(deadline, task).await.is_err()
    {
        tracing::warn!("Timeout waiting for HTTP servers to finish.");
    }

    tokio::select! {
        () = async {
            while workers.join_next().await.is_some() {}
        } => {
            tracing::info!("Background tasks finished.");
        }
        () = tokio::time::sleep_until(deadline) => {
            tracing::warn!("Timeout waiting for background tasks to finish.");
        }
    }
}
