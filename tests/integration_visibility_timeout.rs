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
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Default)]
struct TransientFailureProvider;

#[async_trait]
impl PushProvider for TransientFailureProvider {
    async fn send_push(&self, _token: &str) -> Result<(), PushError> {
        // Simulate a transient network error
        Err(PushError::Other(anyhow::anyhow!("Temporary failure")))
    }
}

#[tokio::test]
async fn test_push_visibility_timeout_retry() {
    common::setup_tracing();
    let mut config = common::get_test_config();
    // Set a very short visibility timeout to test retry logic quickly
    config.notifications.visibility_timeout_secs = 2;

    let app = TestApp::spawn_with_config(config.clone()).await;
    let user_id = Uuid::new_v4();
    let token = format!("token:{user_id}");

    // 1. Setup User and Token
    {
        let mut conn = app.pool.acquire().await.unwrap();
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1, $2, 'hash')")
            .bind(user_id)
            .bind(format!("retry_{}", &user_id.to_string()[..8]))
            .execute(&mut *conn)
            .await
            .unwrap();

        sqlx::query("INSERT INTO devices (id, user_id, registration_id) VALUES ($1, $1, 1)")
            .bind(user_id)
            .execute(&mut *conn)
            .await
            .unwrap();

        let repo = obscura_server::adapters::database::push_token_repo::PushTokenRepository::new();
        repo.upsert_token(&mut conn, user_id, &token).await.unwrap();
    }

    // 2. Schedule a job
    let pubsub =
        obscura_server::adapters::redis::RedisClient::new(&config.pubsub, 1024, tokio::sync::watch::channel(false).1)
            .await
            .unwrap();
    let notification_repo = Arc::new(NotificationRepository::new(pubsub.clone(), &config.notifications));
    notification_repo.push_jobs(&[user_id], 0).await.unwrap();

    // 3. Run worker with FAILING provider
    let failing_worker = PushNotificationWorker::new(
        app.pool.clone(),
        notification_repo.clone(),
        Arc::new(TransientFailureProvider),
        obscura_server::adapters::database::push_token_repo::PushTokenRepository::new(),
        &config.notifications,
    );

    let (tx, _rx) = tokio::sync::mpsc::channel(10);
    failing_worker.process_due_jobs(tx.clone()).await.unwrap();

    // 4. Verify job is STILL in Redis but with a future score (the lease)
    let score: f64 = {
        let mut conn = pubsub.publisher();
        redis::cmd("ZSCORE")
            .arg(&config.notifications.push_queue_key)
            .arg(user_id.to_string())
            .query_async(&mut conn)
            .await
            .unwrap()
    };

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
    assert!(score > now, "Job should have a future score (lease), got {score} vs now {now}");

    // 5. Wait for the visibility timeout to expire naturally
    tokio::time::sleep(Duration::from_secs(3)).await;

    // 6. Run worker with SUCCESSFUL provider
    let success_worker = PushNotificationWorker::new(
        app.pool.clone(),
        notification_repo.clone(),
        Arc::new(SharedMockPushProvider),
        obscura_server::adapters::database::push_token_repo::PushTokenRepository::new(),
        &config.notifications,
    );

    success_worker.process_due_jobs(tx).await.unwrap();

    // 7. Verify delivered and removed
    let mut delivered = false;
    for _ in 0..50 {
        if notification_counts().get(&user_id).map_or(0, |c| *c) > 0 {
            delivered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(delivered, "Push was not delivered on retry after lease expired");

    let final_score: Option<f64> = {
        let mut conn = pubsub.publisher();
        redis::cmd("ZSCORE")
            .arg(&config.notifications.push_queue_key)
            .arg(user_id.to_string())
            .query_async(&mut conn)
            .await
            .unwrap()
    };
    assert!(final_score.is_none(), "Job should have been deleted after successful delivery");
}
