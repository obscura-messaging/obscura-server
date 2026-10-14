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

use sqlx::migrate::Migrator;
use sqlx::{Connection, PgConnection, PgPool};
use std::borrow::Cow;
use uuid::Uuid;

const ACCOUNT_IDENTITY_MIGRATION: i64 = 4;

/// A fresh database migrated up to, but not including, the account identity migration.
async fn database_before_account_identity() -> (PgPool, String, String) {
    common::setup_tracing();
    let base_url = std::env::var("OBSCURA_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://user:password@localhost/signal_server".to_string());
    let name = format!("migration_test_{}", Uuid::new_v4().simple());
    let mut admin = PgConnection::connect(&base_url).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}")).execute(&mut admin).await.unwrap();

    let url = format!("{}/{name}", base_url.rsplit_once('/').unwrap().0);
    let pool = PgPool::connect(&url).await.unwrap();

    let all = sqlx::migrate!();
    let before = Migrator {
        migrations: Cow::Owned(
            all.migrations.iter().filter(|m| m.version < ACCOUNT_IDENTITY_MIGRATION).cloned().collect(),
        ),
        ..Migrator::DEFAULT
    };
    before.run(&pool).await.unwrap();

    (pool, base_url, name)
}

async fn insert_user(pool: &PgPool, username: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO users (username, password_hash) VALUES ($1, 'x') RETURNING id")
        .bind(username)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Inserts a device created `minutes` after a fixed epoch, with an identity key row unless `identity` is None.
async fn insert_device(pool: &PgPool, user_id: Uuid, minutes: i32, identity: Option<u8>, registration_id: i32) -> Uuid {
    let device_id: Uuid = sqlx::query_scalar(
        "INSERT INTO devices (user_id, created_at) VALUES ($1, '2026-01-01'::timestamptz + make_interval(mins => $2)) RETURNING id",
    )
    .bind(user_id)
    .bind(minutes)
    .fetch_one(pool)
    .await
    .unwrap();
    if let Some(identity) = identity {
        sqlx::query("INSERT INTO identity_keys (device_id, identity_key, registration_id) VALUES ($1, $2, $3)")
            .bind(device_id)
            .bind(identity_key(identity))
            .bind(registration_id)
            .execute(pool)
            .await
            .unwrap();
    }
    device_id
}

fn identity_key(seed: u8) -> Vec<u8> {
    let mut key = vec![seed; 33];
    key[0] = 0x05;
    key
}

async fn insert_message(pool: &PgPool, sender_id: Uuid, sender_device_id: Uuid, device_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        r"INSERT INTO messages (sender_id, sender_device_id, device_id, submission_id, content, expires_at)
          VALUES ($1, $2, $3, $4, 'm', NOW() + INTERVAL '1 day') RETURNING id",
    )
    .bind(sender_id)
    .bind(sender_device_id)
    .bind(device_id)
    .bind(Uuid::new_v4())
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn device_ids(pool: &PgPool, user_id: Uuid) -> Vec<(Uuid, bool, i32)> {
    sqlx::query_as("SELECT id, is_primary, registration_id FROM devices WHERE user_id = $1 ORDER BY created_at")
        .bind(user_id)
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn account_identity(pool: &PgPool, user_id: Uuid) -> Option<Vec<u8>> {
    sqlx::query_scalar("SELECT identity_key FROM users WHERE id = $1").bind(user_id).fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn test_account_identity_migration_on_existing_data() {
    let (pool, base_url, name) = database_before_account_identity().await;

    // Independent installations: the oldest wins, a later one with its identity survives, another is deleted.
    let mixed = insert_user(&pool, "mixed").await;
    let mixed_second = insert_device(&pool, mixed, 20, Some(1), 12).await;
    let mixed_oldest = insert_device(&pool, mixed, 10, Some(1), 11).await;
    let mixed_foreign = insert_device(&pool, mixed, 30, Some(2), 13).await;

    // All devices already agree: every device is kept.
    let agreeing = insert_user(&pool, "agreeing").await;
    let agreeing_first = insert_device(&pool, agreeing, 10, Some(3), 21).await;
    let agreeing_second = insert_device(&pool, agreeing, 20, Some(3), 22).await;

    let single = insert_user(&pool, "single").await;
    let single_device = insert_device(&pool, single, 10, Some(4), 31).await;

    let keyless = insert_user(&pool, "keyless").await;
    insert_device(&pool, keyless, 10, None, 0).await;

    let deviceless = insert_user(&pool, "deviceless").await;

    let survives = insert_message(&pool, mixed, mixed_foreign, single_device).await;
    insert_message(&pool, single, single_device, mixed_foreign).await;

    sqlx::migrate!().run(&pool).await.unwrap();

    assert_eq!(device_ids(&pool, mixed).await, vec![(mixed_oldest, true, 11), (mixed_second, false, 12)]);
    assert_eq!(account_identity(&pool, mixed).await, Some(identity_key(1)));

    assert_eq!(device_ids(&pool, agreeing).await, vec![(agreeing_first, true, 21), (agreeing_second, false, 22)]);
    assert_eq!(account_identity(&pool, agreeing).await, Some(identity_key(3)));

    assert_eq!(device_ids(&pool, single).await, vec![(single_device, true, 31)]);
    assert_eq!(account_identity(&pool, single).await, Some(identity_key(4)));

    assert!(device_ids(&pool, keyless).await.is_empty(), "A device without keys cannot be used");
    assert_eq!(account_identity(&pool, keyless).await, None);
    assert_eq!(account_identity(&pool, deviceless).await, None);

    let messages: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT id, sender_device_id FROM messages").fetch_all(&pool).await.unwrap();
    assert_eq!(messages, vec![(survives, mixed_foreign)], "Only the message queued for a deleted device is gone");

    let identity_keys_table: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('identity_keys')::text").fetch_one(&pool).await.unwrap();
    assert_eq!(identity_keys_table, None);

    let second_primary = sqlx::query("UPDATE devices SET is_primary = TRUE WHERE id = $1")
        .bind(mixed_second)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(second_primary.as_database_error().unwrap().code().as_deref(), Some("23505"));

    pool.close().await;
    let mut admin = PgConnection::connect(&base_url).await.unwrap();
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)")).execute(&mut admin).await.unwrap();
}
