#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::todo,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    missing_debug_implementations,
    clippy::cast_precision_loss,
    clippy::clone_on_ref_ptr,
    clippy::match_same_arms,
    clippy::items_after_statements,
    unreachable_pub,
    clippy::print_stdout,
    clippy::similar_names
)]
mod common;

use async_trait::async_trait;
use common::{SharedMockPushProvider, TestApp, notification_counts};
use obscura_server::adapters::push::{PushError, PushProvider};
use obscura_server::adapters::redis::NotificationRepository;
use obscura_server::workers::PushNotificationWorker;
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};
use tracing::Instrument;

#[tokio::test]
async fn test_scheduled_push_delivery() {
    let mut config = common::get_test_config();
    config.notifications.push_delay_secs = 1;
    config.notifications.worker_interval_secs = std::num::NonZeroU64::new(1).unwrap();

    let app = TestApp::spawn_with_workers(config).await;

    let user_id = common::insert_device_with_push_token(&app.pool, "u").await;

    // 1. Notify MessageReceived
    app.notifier.notify(&[user_id], obscura_server::domain::notification::DeviceEvent::MessageReceived).await;

    // 2. Wait for push
    let start = std::time::Instant::now();
    let mut delivered = false;
    while start.elapsed() < Duration::from_secs(10) {
        if notification_counts().get(&user_id).map_or(0, |c| *c) > 0 {
            delivered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(delivered, "Push notification was not delivered for unique user {user_id}");
    assert_eq!(*notification_counts().get(&user_id).unwrap(), 1);
}

#[tokio::test]
async fn test_push_cancellation_on_ack() {
    common::setup_tracing();
    let mut config = common::get_test_config();
    config.notifications.push_delay_secs = 15;

    let app = TestApp::spawn_with_workers(config).await;
    let username = common::generate_username("u_ack");
    let user = app.register_user(&username).await;
    let sender = app.register_user(&common::generate_username("u_ack_sender")).await;

    // 1. Connect via WebSocket first so connect itself doesn't cancel the push we are about to schedule
    let mut ws = app.connect_ws(&user.token).await;
    ws.ensure_subscribed().await;

    // 2. Schedule a push while connected
    app.send_message(&sender.token, user.device_id, b"msg").await;
    let env = ws.receive_envelope().await.expect("Envelope missing");

    // Sending schedules the fallback push before it responds, so the job must exist before the ACK.
    // Without this, the test would also pass if no push had been scheduled at all.
    assert!(app.push_job_scheduled(user.device_id).await, "sending should schedule a fallback push");

    // 3. Send an ACK
    ws.send_ack(env.id).await;

    // 4. Wait and verify it's removed from Redis
    let removed =
        app.wait_until(|| async { !app.push_job_scheduled(user.device_id).await }, Duration::from_secs(5)).await;
    assert!(removed, "Push job was not removed from Redis on ACK");
}

#[tokio::test]
async fn test_push_cancellation_on_websocket_connect() {
    common::setup_tracing();
    let mut config = common::get_test_config();
    config.notifications.push_delay_secs = 10;

    let app = TestApp::spawn_with_workers(config).await;
    let username = common::generate_username("u_ws");
    let user = app.register_user(&username).await;
    let sender = app.register_user(&common::generate_username("u_ws_sender")).await;

    // 1. Schedule push
    app.send_message(&sender.token, user.device_id, b"msg").await;

    // 2. Connect WS
    let _ws = app.connect_ws(&user.token).await;

    // 3. Verify removed
    let success = app
        .wait_until(
            || {
                let config = app.config.clone();
                let pubsub_url = config.pubsub.url.clone();
                let queue_key = config.notifications.push_queue_key;
                let device_id = user.device_id;
                async move {
                    let client = redis::Client::open(pubsub_url).unwrap();
                    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
                    let score: Option<f64> = redis::cmd("ZSCORE")
                        .arg(&queue_key)
                        .arg(device_id.to_string())
                        .query_async(&mut conn)
                        .await
                        .unwrap();
                    score.is_none()
                }
            },
            Duration::from_secs(5),
        )
        .await;

    assert!(success, "Push job was not removed from Redis on WS connect");
}

#[tokio::test]
async fn test_delivery_exactly_once_under_competition() {
    let mut config = common::get_test_config();
    config.notifications.push_delay_secs = 0;
    config.notifications.worker_interval_secs = std::num::NonZeroU64::new(1).unwrap();

    let app = TestApp::spawn_with_config(config).await;

    let user_id = common::insert_device_with_push_token(&app.pool, "u_comp").await;

    // Access internal components via Resources/Config
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let notification_repo =
        Arc::new(NotificationRepository::new(app.resources.pubsub.clone(), &app.config.notifications));

    // Spawn 10 competing workers
    let notification_service = obscura_server::services::notification_service::NotificationService::new(
        notification_repo.clone(),
        &app.config.notifications,
    );
    let push_token_service = obscura_server::services::push_token_service::PushTokenService::new(
        app.pool.clone(),
        obscura_server::adapters::database::push_token_repo::PushTokenRepository::new(),
    );
    for i in 0..10 {
        let worker = PushNotificationWorker::new(
            notification_service.clone(),
            push_token_service.clone(),
            Arc::new(SharedMockPushProvider),
            &app.config.notifications,
        );
        let rx = shutdown_rx.clone();
        tokio::spawn(
            async move {
                worker.run(rx).await;
            }
            .instrument(tracing::info_span!("competing_worker", id = i)),
        );
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let _: anyhow::Result<()> = notification_repo.push_jobs(&[user_id], 0).await;

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if notification_counts().get(&user_id).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let count = notification_counts().get(&user_id).map_or(0, |c| *c);
    assert_eq!(count, 1, "Notification delivered {count} times, expected exactly 1");

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_push_coalescing() {
    let mut config = common::get_test_config();
    config.notifications.push_delay_secs = 2;
    config.notifications.worker_interval_secs = std::num::NonZeroU64::new(1).unwrap();

    let app = TestApp::spawn_with_workers(config).await;

    let user_id = common::insert_device_with_push_token(&app.pool, "u_coal").await;

    for _ in 0..5 {
        app.notifier.notify(&[user_id], obscura_server::domain::notification::DeviceEvent::MessageReceived).await;
    }

    let sent =
        app.wait_until(|| async { notification_counts().get(&user_id).is_some() }, Duration::from_secs(10)).await;
    assert!(sent, "the coalesced push was never sent");

    // The worker removes a job only after sending its push, so once the job is gone, no further push can
    // come from it. A job kept after sending would be sent again when its lease expired.
    let removed = app.wait_until(|| async { !app.push_job_scheduled(user_id).await }, Duration::from_secs(10)).await;
    assert!(removed, "the push job should be removed once its push is sent");

    let count = notification_counts().get(&user_id).map_or(0, |c| *c);
    assert_eq!(count, 1, "Expected 1 coalesced notification, got {count}");
}

/// Leasing is what stops competing workers from sending the same push twice: of many concurrent leases
/// for one due job, exactly one may get it.
#[tokio::test]
async fn test_concurrent_leases_are_exclusive() {
    let app = TestApp::spawn().await;
    let repo = Arc::new(NotificationRepository::new(app.resources.pubsub.clone(), &app.config.notifications));
    let device_id = uuid::Uuid::new_v4();
    repo.push_jobs(&[device_id], 0).await.unwrap();

    let leases = futures::future::join_all((0..10).map(|_| {
        let repo = Arc::clone(&repo);
        async move { repo.lease_due_jobs(10, 30).await.unwrap() }
    }))
    .await;

    let winners = leases.iter().filter(|leased| !leased.is_empty()).count();
    assert_eq!(winners, 1, "exactly one concurrent lease should get the job: {leases:?}");
}

/// Holds every push until the test opens the gate, and records how many are in flight at once.
#[derive(Debug)]
struct GatedPushProvider {
    gate: Semaphore,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
    sent: AtomicUsize,
}

impl GatedPushProvider {
    fn new() -> Self {
        Self {
            gate: Semaphore::new(0),
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            sent: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl PushProvider for GatedPushProvider {
    async fn send_push(&self, _token: &str) -> Result<(), PushError> {
        let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(current, Ordering::SeqCst);
        self.gate.acquire().await.expect("gate closed").forget();
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.sent.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// Runs one pass of the worker. A pass that waits for a permit instead of returning is a failure.
async fn process_due_jobs(worker: &PushNotificationWorker, invalid_token_tx: &mpsc::Sender<String>) {
    tokio::time::timeout(Duration::from_secs(5), worker.process_due_jobs(invalid_token_tx.clone()))
        .await
        .expect("process_due_jobs blocked waiting for a permit")
        .expect("process_due_jobs failed");
}

/// Counts queued jobs scored in the future. Every job here is scheduled with no delay, so these are leased.
async fn count_leased_jobs(app: &TestApp) -> i64 {
    let client = redis::Client::open(app.config.pubsub.url.clone()).unwrap();
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    redis::cmd("ZCOUNT")
        .arg(&app.config.notifications.push_queue_key)
        .arg(format!("({now}"))
        .arg("+inf")
        .query_async(&mut conn)
        .await
        .unwrap()
}

#[tokio::test]
async fn test_notification_worker_concurrency_limit() {
    common::setup_tracing();

    let mut config = common::get_test_config();
    let concurrency = 2;
    let jobs = 10;
    config.notifications.worker_concurrency = std::num::NonZeroUsize::new(concurrency).unwrap();

    let app = TestApp::spawn_with_config(config).await;

    let notification_repo =
        Arc::new(NotificationRepository::new(app.resources.pubsub.clone(), &app.config.notifications));
    let notification_service = obscura_server::services::notification_service::NotificationService::new(
        notification_repo.clone(),
        &app.config.notifications,
    );
    let push_token_service = obscura_server::services::push_token_service::PushTokenService::new(
        app.pool.clone(),
        obscura_server::adapters::database::push_token_repo::PushTokenRepository::new(),
    );
    let provider = Arc::new(GatedPushProvider::new());
    let worker = PushNotificationWorker::new(
        notification_service,
        push_token_service,
        provider.clone(),
        &app.config.notifications,
    );
    let (invalid_token_tx, _invalid_token_rx) = mpsc::channel(16);

    for i in 0..jobs {
        let user_id = common::insert_device_with_push_token(&app.pool, &format!("conc_{i}")).await;
        let _: anyhow::Result<()> = notification_repo.push_jobs(&[user_id], 0).await;
    }

    // Driven directly rather than through `run`, so no timer decides when jobs are picked up.
    // The worker leases jobs before dispatching them, so the lease count after a pass is exact.
    process_due_jobs(&worker, &invalid_token_tx).await;
    assert_eq!(count_leased_jobs(&app).await, 2, "a pass should lease only as many jobs as there are permits");
    let both_started = app
        .wait_until(|| async { provider.in_flight.load(Ordering::SeqCst) == concurrency }, Duration::from_secs(5))
        .await;
    assert!(both_started, "both permitted pushes should start");

    // Both permits are held by pushes stuck at the gate, so another pass must lease nothing.
    process_due_jobs(&worker, &invalid_token_tx).await;
    assert_eq!(count_leased_jobs(&app).await, 2, "a pass with no free permits should lease nothing");

    provider.gate.add_permits(jobs);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while provider.sent.load(Ordering::SeqCst) < jobs {
        assert!(
            std::time::Instant::now() < deadline,
            "only {} of {jobs} pushes were sent",
            provider.sent.load(Ordering::SeqCst)
        );
        process_due_jobs(&worker, &invalid_token_tx).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(provider.peak.load(Ordering::SeqCst), concurrency, "pushes should run exactly {concurrency} at a time");
}

#[tokio::test]
async fn test_register_push_token() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("token_user");
    let user = app.register_user(&username).await;

    let token = "test_fcm_token_123";
    let payload = json!({
        "token": token
    });

    let resp = app
        .client
        .put(format!("{}/v1/push-token", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);

    let stored_token: String = sqlx::query_scalar("SELECT token FROM push_tokens WHERE device_id = $1")
        .bind(user.device_id)
        .fetch_one(&app.pool)
        .await
        .unwrap();

    assert_eq!(stored_token, token);

    let new_token = "updated_fcm_token_456";
    let resp = app
        .client
        .put(format!("{}/v1/push-token", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&json!({ "token": new_token }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);

    let stored_token: String = sqlx::query_scalar("SELECT token FROM push_tokens WHERE device_id = $1")
        .bind(user.device_id)
        .fetch_one(&app.pool)
        .await
        .unwrap();

    assert_eq!(stored_token, new_token);
}

#[tokio::test]
async fn test_register_push_token_unauthorized() {
    let app = TestApp::spawn().await;

    let resp = app
        .client
        .put(format!("{}/v1/push-token", app.server_url))
        .json(&json!({ "token": "some_token" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_notification_lag_recovery() {
    common::setup_tracing();
    let mut config = common::get_test_config();
    config.websocket.outbound_buffer_size = std::num::NonZeroUsize::new(10).unwrap();

    let app = TestApp::spawn_with_workers(config).await;

    let user_a = app.register_user(&common::generate_username("alice")).await;
    let user_b = app.register_user(&common::generate_username("bob")).await;

    let mut ws = app.connect_ws(&user_b.token).await;

    let message_count = 100;
    for i in 0..message_count {
        let content = format!("Message {i}").into_bytes();
        app.send_message(&user_a.token, user_b.device_id, &content).await;
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut received = 0;
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(10);

    while received < message_count && start.elapsed() < timeout {
        if ws.receive_envelope_timeout(Duration::from_millis(100)).await.is_some() {
            received += 1;
        }
    }

    assert_eq!(received, message_count, "Should receive all {message_count} messages despite notification lag");
}
