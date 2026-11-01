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
use obscura_server::adapters::database::message_repo::MessageRepository;
use obscura_server::adapters::redis::{NotificationRepository, RedisCache, RedisClient};
use obscura_server::config::{MessagingConfig, NotificationConfig, PubSubConfig};
use obscura_server::services::message_service::MessageService;
use obscura_server::services::notification_service::NotificationService;
use obscura_server::workers::MessageCleanupWorker;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

mod common;

#[tokio::test]
async fn test_message_cleanup_worker_full_orchestration() {
    let pool = common::get_test_pool().await;
    let repo = MessageRepository::new();
    let config = MessagingConfig {
        max_inbox_size: 2, // Small limit for overflow test
        ..MessagingConfig::default()
    };

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let pubsub = RedisClient::new(&PubSubConfig::default(), 1024, shutdown_rx).await.unwrap();
    let notif_config = NotificationConfig::default();
    let notifier = NotificationService::new(
        Arc::new(NotificationRepository::new(Arc::clone(&pubsub), &notif_config)),
        &notif_config,
    );
    let submission_cache = RedisCache::new(pubsub, "test:idemp:".to_string(), 60);
    let service = MessageService::new(pool.clone(), repo, notifier, submission_cache, config.max_inbox_size, 30);
    let worker = MessageCleanupWorker::new(service, config.cleanup_interval_secs);

    // --- Part 1: Overflow Pruning ---
    let user_a = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, username, password_hash, identity_key) VALUES ($1, $2, 'hash', '\\x05')")
        .bind(user_a)
        .bind(format!("worker_a_{}", &user_a.to_string()[..8]))
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("INSERT INTO devices (id, user_id, registration_id) VALUES ($1, $1, 1)")
        .bind(user_a)
        .execute(&pool)
        .await
        .unwrap();

    // Seed 3 messages (exceeds limit of 2)
    for i in 0..3 {
        let msg_id = Uuid::new_v4();
        sqlx::query("INSERT INTO messages (id, idempotency_key, sender_user_id, sender_device_id, device_id, content, created_at, expires_at) VALUES ($1, $6, $2, $2, $2, $3, $4, $5)")
            .bind(msg_id)
            .bind(user_a)
            .bind(format!("msg {i}").into_bytes())
            .bind(OffsetDateTime::now_utc() + Duration::seconds(i))
            .bind(OffsetDateTime::now_utc() + Duration::days(1))
            .bind(Uuid::new_v4())
            .execute(&pool)
            .await
            .unwrap();
    }

    // --- Part 2: Expiry Deletion ---
    let user_b = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, username, password_hash, identity_key) VALUES ($1, $2, 'hash', '\\x05')")
        .bind(user_b)
        .bind(format!("worker_b_{}", &user_b.to_string()[..8]))
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("INSERT INTO devices (id, user_id, registration_id) VALUES ($1, $1, 1)")
        .bind(user_b)
        .execute(&pool)
        .await
        .unwrap();

    // Insert one expired message
    let expired_msg_id = Uuid::new_v4();
    let expired_time = OffsetDateTime::now_utc() - Duration::days(1);
    sqlx::query("INSERT INTO messages (id, idempotency_key, sender_user_id, sender_device_id, device_id, content, expires_at) VALUES ($1, $5, $2, $2, $2, $3, $4)")
        .bind(expired_msg_id)
        .bind(user_b)
        .bind(b"expired content".to_vec())
        .bind(expired_time)
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .unwrap();

    // Insert one active message
    let active_msg_id = Uuid::new_v4();
    let active_time = OffsetDateTime::now_utc() + Duration::days(1);
    sqlx::query("INSERT INTO messages (id, idempotency_key, sender_user_id, sender_device_id, device_id, content, expires_at) VALUES ($1, $5, $2, $2, $2, $3, $4)")
        .bind(active_msg_id)
        .bind(user_b)
        .bind(b"active content".to_vec())
        .bind(active_time)
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .unwrap();

    // --- Execution ---
    worker.perform_cleanup().await.expect("Worker cleanup failed");

    // --- Assertions Part 1 (Overflow) ---
    let count_a: i64 = sqlx::query_scalar("SELECT count(*) FROM messages WHERE device_id = $1")
        .bind(user_a)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count_a, 2, "User A inbox should have been pruned to 2 messages");

    // --- Assertions Part 2 (Expiry) ---
    let count_b: i64 = sqlx::query_scalar("SELECT count(*) FROM messages WHERE device_id = $1")
        .bind(user_b)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count_b, 1, "User B should only have the active message remaining");

    let expired_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM messages WHERE id = $1)")
        .bind(expired_msg_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!expired_exists, "Expired message should be deleted");

    let active_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM messages WHERE id = $1)")
        .bind(active_msg_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(active_exists, "Active message should still exist");
}
