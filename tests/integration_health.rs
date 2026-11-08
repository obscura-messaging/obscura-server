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
use axum::http::StatusCode;
use obscura_server::config::HealthConfig;
use obscura_server::services::health_service::HealthService;
use std::sync::Arc;
mod common;

#[tokio::test]
async fn test_livez() {
    let app = common::TestApp::spawn().await;

    let resp = app.client.get(format!("{}/livez", app.mgmt_url)).send().await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_readyz_happy_path() {
    let app = common::TestApp::spawn().await;

    // Ensure the bucket exists so storage check passes
    common::ensure_storage_bucket(&app.s3_client, &app.config.storage.bucket).await;

    let resp = app.client.get(format!("{}/readyz", app.mgmt_url)).send().await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["database"], "ok");
    assert_eq!(body["storage"], "ok");
}

#[tokio::test]
async fn test_readyz_storage_error() {
    let mut config = common::get_test_config();
    // Use a bucket name that definitely won't exist and we won't create
    config.storage.bucket = format!("non-existent-bucket-{}", uuid::Uuid::new_v4());

    let app = common::TestApp::spawn_with_config(config).await;

    let resp = app.client.get(format!("{}/readyz", app.mgmt_url)).send().await.unwrap();

    // Storage check should fail because the bucket doesn't exist
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "error");
    assert_eq!(body["database"], "ok");
    assert_eq!(body["storage"], "error");
}

#[tokio::test]
async fn test_readyz_database_error() {
    let app = common::TestApp::spawn().await;
    common::ensure_storage_bucket(&app.s3_client, &app.config.storage.bucket).await;

    // Close the pool to simulate a database error
    app.pool.close().await;

    let resp = app.client.get(format!("{}/readyz", app.mgmt_url)).send().await.unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "error");
    assert_eq!(body["database"], "error");
    assert_eq!(body["storage"], "ok");
}

// --- Health check failure branch tests (timeout and pubsub error paths) ---

/// Helper to create an S3 client pointing to a non-routable address.
/// Requests to this client will hang, allowing timeout tests.
async fn create_unreachable_s3_client() -> aws_sdk_s3::Client {
    let config = obscura_server::config::StorageConfig {
        endpoint: Some("http://192.0.2.1:9999".to_string()),
        access_key: Some("fake".to_string()),
        secret_key: Some("fake".to_string()),
        force_path_style: true,
        ..Default::default()
    };
    obscura_server::initialize_s3_client(&config).await
}

/// Helper to create a DB pool that will hang on queries (non-routable address).
fn create_unreachable_pool() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect_lazy("postgres://user:password@192.0.2.1:5432/nonexistent")
        .expect("Failed to create lazy pool")
}

/// Covers the `Err(_) => "Database connection timed out"` branch in `check_db`.
#[tokio::test]
async fn test_health_check_db_timeout() {
    let app = common::TestApp::spawn().await;

    let health = HealthService::new(
        create_unreachable_pool(),
        app.s3_client.clone(),
        Arc::clone(&app.resources.pubsub),
        app.config.storage.bucket.clone(),
        HealthConfig {
            db_timeout_ms: std::num::NonZeroU64::new(50).unwrap(),
            storage_timeout_ms: std::num::NonZeroU64::new(2000).unwrap(),
            pubsub_timeout_ms: std::num::NonZeroU64::new(2000).unwrap(),
        },
    );

    let result = health.check_db().await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Database connection timed out");
}

/// Covers the `Err(_) => "Storage connection timed out"` branch in `check_storage`.
#[tokio::test]
async fn test_health_check_storage_timeout() {
    let app = common::TestApp::spawn().await;

    let health = HealthService::new(
        app.pool.clone(),
        create_unreachable_s3_client().await,
        Arc::clone(&app.resources.pubsub),
        "test-bucket".to_string(),
        HealthConfig {
            db_timeout_ms: std::num::NonZeroU64::new(2000).unwrap(),
            storage_timeout_ms: std::num::NonZeroU64::new(50).unwrap(),
            pubsub_timeout_ms: std::num::NonZeroU64::new(2000).unwrap(),
        },
    );

    let result = health.check_storage().await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Storage connection timed out");
}

/// Covers the readyz endpoint when both database and storage fail simultaneously.
#[tokio::test]
async fn test_readyz_database_and_storage_error() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("nonexistent-bucket-{}", uuid::Uuid::new_v4());

    let app = common::TestApp::spawn_with_config(config).await;

    // Close the pool to trigger database error
    app.pool.close().await;

    let resp = app.client.get(format!("{}/readyz", app.mgmt_url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "error");
    assert_eq!(body["database"], "error");
    assert_eq!(body["storage"], "error");
}
