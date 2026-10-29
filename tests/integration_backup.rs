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
use obscura_server::adapters::database::backup_repo::BackupRepository;
use obscura_server::adapters::storage::S3Storage;
use obscura_server::workers::BackupCleanupWorker;
use reqwest::StatusCode;
use std::sync::Arc;
use uuid::Uuid;

mod common;

#[tokio::test]
async fn test_backup_lifecycle() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-backup-{}", &Uuid::new_v4().to_string()[..8]);
    config.backup.min_size_bytes = 0;

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("backup_user")).await;

    // 1. Initial State: No backup
    let resp_404 = app
        .client
        .get(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_404.status(), StatusCode::NOT_FOUND);

    // 2. Upload (First time, If-Match: 0)
    let content = b"Backup Data v1";
    let resp_up = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-None-Match", "*")
        .body(content.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp_up.status(), StatusCode::OK);
    let etag_up = resp_up.headers().get("ETag").unwrap().to_str().unwrap().to_string();
    assert_eq!(etag_up, "\"1\"");

    // 3. Download
    let resp_down = app
        .client
        .get(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_down.status(), StatusCode::OK);
    assert_eq!(resp_down.headers().get("Content-Type").unwrap(), "application/octet-stream");
    let etag = resp_down.headers().get("ETag").unwrap().to_str().unwrap().to_string();
    assert_eq!(etag, "\"1\"");
    assert_eq!(resp_down.bytes().await.unwrap(), content.to_vec());

    // 4. Upload (Update, If-Match: 1)
    let content_v2 = b"Backup Data v2";
    let resp_up_v2 = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-Match", "1")
        .body(content_v2.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp_up_v2.status(), StatusCode::OK);
    let etag_up_v2 = resp_up_v2.headers().get("ETag").unwrap().to_str().unwrap().to_string();
    assert_eq!(etag_up_v2, "\"2\"");

    // 5. Download v2
    let resp_down_v2 = app
        .client
        .get(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_down_v2.status(), StatusCode::OK);
    assert_eq!(resp_down_v2.headers().get("Content-Type").unwrap(), "application/octet-stream");
    let etag_v2 = resp_down_v2.headers().get("ETag").unwrap().to_str().unwrap().to_string();
    assert_eq!(etag_v2, "\"2\"");
    assert_eq!(resp_down_v2.bytes().await.unwrap(), content_v2.to_vec());

    // 6. Conflict (If-Match Mismatch)
    let resp_conflict = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-Match", "1") // Should be 2
        .body(b"Conflict".to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp_conflict.status(), StatusCode::PRECONDITION_FAILED);

    // 7. Head
    let resp_head = app
        .client
        .head(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_head.status(), StatusCode::OK);
    assert_eq!(resp_head.headers().get("Content-Type").unwrap(), "application/octet-stream");
    let etag_head = resp_head.headers().get("ETag").unwrap().to_str().unwrap();
    assert_eq!(etag_head, "\"2\"");
    let len_head = resp_head.headers().get("Content-Length").unwrap().to_str().unwrap();
    assert_eq!(len_head, content_v2.len().to_string());
}

#[tokio::test]
async fn test_backup_min_size() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-backup-min-{}", &Uuid::new_v4().to_string()[..8]);
    config.backup.min_size_bytes = 10;

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("backup_min")).await;

    // Upload too small
    let content = b"TooSmall"; // 8 bytes
    let resp = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-None-Match", "*")
        .header("Content-Length", content.len().to_string())
        .body(content.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_backup_max_size() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-backup-max-{}", &Uuid::new_v4().to_string()[..8]);
    config.backup.max_size_bytes = 100; // Small limit for test
    config.backup.min_size_bytes = 0;

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("backup_max")).await;

    // 1. Upload too large (Header check)
    let content = vec![0u8; 101]; // Over 100 limit
    let resp = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-None-Match", "*")
        .header("Content-Length", content.len().to_string())
        .body(content)
        .send()
        .await
        .unwrap();

    // BackupService now returns 413
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_backup_head_404() {
    let app = common::TestApp::spawn().await;
    let user = app.register_user(&common::generate_username("head_404")).await;

    let resp = app
        .client
        .head(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_backup_takeover_stale_upload() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-backup-takeover-{}", &Uuid::new_v4().to_string()[..8]);
    config.backup.min_size_bytes = 0;
    config.backup.stale_threshold_mins = 0; // Immediate stale for takeover test

    let app = common::TestApp::spawn_with_config(config).await;
    common::ensure_storage_bucket(&app.s3_client, &app.config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("takeover")).await;

    // 1. Act: Start an upload (Version 1)
    let resp_v1 = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-None-Match", "*")
        .body(b"Version 1 Data".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp_v1.status(), StatusCode::OK);

    // 2. Act: Immediate takeover attempt (Version 2)
    // Should succeed because threshold is 0
    let resp_takeover = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-Match", "1")
        .body(b"Takeover Data Content".to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp_takeover.status(), StatusCode::OK);

    // 3. Verify via API: Check ETag is "2"
    let mut version_match = false;
    for _ in 0..10 {
        let head = app
            .client
            .head(format!("{}/v1/backup", app.server_url))
            .header("Authorization", format!("Bearer {}", user.token))
            .send()
            .await
            .unwrap();
        if head.status() == StatusCode::OK {
            let etag = head.headers().get("ETag").unwrap().to_str().unwrap();
            if etag == "\"2\"" {
                version_match = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(version_match, "Backup version should have been updated to 2 via takeover");
}

#[tokio::test]
async fn test_backup_concurrent_upload_conflict() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-backup-conflict-{}", &Uuid::new_v4().to_string()[..8]);
    config.backup.min_size_bytes = 0;
    config.backup.stale_threshold_mins = 60; // Long threshold to ensure it stays "fresh"

    let app = common::TestApp::spawn_with_config(config).await;
    common::ensure_storage_bucket(&app.s3_client, &app.config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("conflict")).await;

    // 1. Act: Start a legitimate upload
    // We simulate a "stuck" concurrent upload by manually putting the record into UPLOADING state
    // with a FRESH timestamp (NOW).
    sqlx::query("INSERT INTO backups (device_id, current_version, pending_version, state, pending_at) VALUES ($1, 0, 1, 'UPLOADING', NOW())")
        .bind(user.device_id).execute(&app.pool).await.unwrap();

    // 2. Verify: A new attempt with the same version (0) should now conflict (409)
    let resp_conflict = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-None-Match", "*")
        .body(b"Conflict data".to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp_conflict.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_backup_cleanup() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-cleanup-{}", &Uuid::new_v4().to_string()[..8]);
    config.backup.stale_threshold_mins = 10; // 10 minute threshold so it does not sweep other tests' 2-min fixtures

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("cleanup")).await;
    let user_id = user.device_id;

    // 1. Setup Stale DB State (20 minutes ago)
    sqlx::query(
        "INSERT INTO backups (device_id, current_version, pending_version, state, pending_at)
         VALUES ($1, 1, 2, 'UPLOADING', NOW() - INTERVAL '20 minutes')",
    )
    .bind(user_id)
    .execute(&app.pool)
    .await
    .unwrap();

    // 2. Setup "Pending" S3 Object
    let pending_key = format!("{}{}/v2", config.backup.prefix, user_id);

    app.s3_client
        .put_object()
        .bucket(&config.storage.bucket)
        .key(&pending_key)
        .body(aws_sdk_s3::primitives::ByteStream::from(b"zombie data".to_vec()))
        .send()
        .await
        .unwrap();

    // 3. Instantiate Worker
    let storage_adapter = Arc::new(S3Storage::new(app.s3_client.clone(), config.storage.bucket.clone()));
    let worker =
        BackupCleanupWorker::new(app.pool.clone(), BackupRepository::new(), storage_adapter, config.backup.clone());

    // 4. Execution
    let cleaned_count = worker.cleanup_stale().await.expect("Cleanup failed");
    assert!(cleaned_count >= 1);

    // 5. Verification: DB State for OUR specific user
    let backup: (String, Option<i32>) =
        sqlx::query_as("SELECT state, pending_version FROM backups WHERE device_id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();

    assert_eq!(backup.0, "ACTIVE");
    assert!(backup.1.is_none());

    // 6. Verification: S3 Object is GONE
    let head_res = app.s3_client.head_object().bucket(&config.storage.bucket).key(&pending_key).send().await;

    assert!(head_res.is_err(), "Pending object should have been deleted from S3");
}

#[tokio::test]
async fn test_backup_version_rotation_and_cleanup() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-versioning-{}", &Uuid::new_v4().to_string()[..8]);
    config.backup.min_size_bytes = 0;

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("version")).await;
    let user_id = user.device_id;

    // 1. Upload Version 1
    let content_v1 = b"Version 1 Data";
    let resp_v1 = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-None-Match", "*")
        .body(content_v1.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp_v1.status(), StatusCode::OK);

    // Verify v1 exists in S3
    let key_v1 = format!("{}{}/v1", config.backup.prefix, user_id);
    let head_v1 = app.s3_client.head_object().bucket(&config.storage.bucket).key(&key_v1).send().await;
    assert!(head_v1.is_ok(), "v1 should exist in S3");

    // 2. Upload Version 2
    let content_v2 = b"Version 2 Data";
    let resp_v2 = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-Match", "1")
        .body(content_v2.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp_v2.status(), StatusCode::OK);

    // Verify v2 exists in S3
    let key_v2 = format!("{}{}/v2", config.backup.prefix, user_id);
    let head_v2 = app.s3_client.head_object().bucket(&config.storage.bucket).key(&key_v2).send().await;
    assert!(head_v2.is_ok(), "v2 should exist in S3");

    // 3. Verify v1 is GONE (Cleanup)
    // The cleanup is fired in a background task, so we might need a small wait
    let mut v1_deleted = false;
    for _ in 0..10 {
        let head_v1_check = app.s3_client.head_object().bucket(&config.storage.bucket).key(&key_v1).send().await;
        if head_v1_check.is_err() {
            v1_deleted = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(v1_deleted, "Old version v1 should have been deleted from S3");

    // 4. Verify Final DB State
    let version: (i32,) = sqlx::query_as("SELECT current_version FROM backups WHERE device_id = $1")
        .bind(user_id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(version.0, 2);
}

#[tokio::test]
async fn test_backup_stream_limits() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-backup-stream-{}", &Uuid::new_v4().to_string()[..8]);
    config.backup.min_size_bytes = 10;
    config.backup.max_size_bytes = 20;

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    // 1. Chunked Upload - Rejected (Missing Content-Length)
    let user1 = app.register_user(&common::generate_username("backup_stream_1")).await;
    let stream_small = futures::stream::iter(vec![Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![0u8; 5]))]);
    let resp_rejected = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user1.token))
        .header("If-None-Match", "*")
        .body(reqwest::Body::wrap_stream(stream_small))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_rejected.status(), StatusCode::LENGTH_REQUIRED);

    // 2. Upload - Too Small (Header fast-fail)
    let user2 = app.register_user(&common::generate_username("backup_stream_2")).await;
    let resp_small = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user2.token))
        .header("If-None-Match", "*")
        .header("Content-Length", "5") // Too small for config (min 10)
        .body(vec![0u8; 5])
        .send()
        .await
        .unwrap();
    assert_eq!(resp_small.status(), StatusCode::BAD_REQUEST);

    // 3. Upload - Too Large (Header fast-fail)
    let user3 = app.register_user(&common::generate_username("backup_stream_3")).await;
    let resp_large = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user3.token))
        .header("If-None-Match", "*")
        .header("Content-Length", "25") // Too large for config (max 20)
        .body(vec![0u8; 25])
        .send()
        .await
        .unwrap();
    assert_eq!(resp_large.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // 4. Stream Upload - OK
    let user4 = app.register_user(&common::generate_username("backup_stream_4")).await;
    let stream_ok = futures::stream::iter(vec![Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![0u8; 15]))]);
    let resp_ok = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user4.token))
        .header("If-None-Match", "*")
        .header("Content-Length", "15")
        .body(reqwest::Body::wrap_stream(stream_ok))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_ok.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_backup_conditional_download() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-backup-cond-{}", &Uuid::new_v4().to_string()[..8]);
    config.backup.min_size_bytes = 0;

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("cond_user")).await;

    // 1. Initial Upload
    let content = b"Backup Data v1";
    app.client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-None-Match", "*")
        .header("Content-Length", content.len().to_string())
        .body(content.to_vec())
        .send()
        .await
        .unwrap();

    // 2. Download with matching If-None-Match
    let resp_304 = app
        .client
        .get(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-None-Match", "\"1\"")
        .send()
        .await
        .unwrap();
    assert_eq!(resp_304.status(), StatusCode::NOT_MODIFIED);

    // 3. Download with non-matching If-None-Match
    let resp_200 = app
        .client
        .get(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-None-Match", "\"0\"")
        .send()
        .await
        .unwrap();
    assert_eq!(resp_200.status(), StatusCode::OK);
    assert_eq!(resp_200.bytes().await.unwrap(), content.to_vec());
}

#[tokio::test]
async fn test_backup_header_conflicts() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-backup-headers-{}", &Uuid::new_v4().to_string()[..8]);
    config.backup.min_size_bytes = 0;

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("headers_user")).await;

    // 1. Both If-Match and If-None-Match (Standard Precedence check)
    // Client sends both. RFC 7232 says If-None-Match takes precedence.
    // Our implementation correctly ignores If-Match and uses If-None-Match: *
    let resp_both = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-None-Match", "*")
        .header("If-Match", "\"5\"") // This should be ignored
        .header("Content-Length", "4")
        .body(b"data".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp_both.status(), StatusCode::OK);

    // 2. Invalid If-None-Match (not *)
    let resp_bad_none = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-None-Match", "\"1\"") // We only support * for upload
        .header("Content-Length", "4")
        .body(b"data".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp_bad_none.status(), StatusCode::BAD_REQUEST);

    // 3. Missing both headers
    let resp_missing = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Content-Length", "4")
        .body(b"data".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp_missing.status(), StatusCode::BAD_REQUEST);
}

/// When the DB has a committed backup (current_version > 0) but the S3 object
/// is missing, download should return 404 via the `StorageError::NotFound` mapping.
#[tokio::test]
async fn test_backup_download_orphaned_db_record() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-orphan-dl-{}", &Uuid::new_v4().to_string()[..8]);
    config.backup.min_size_bytes = 0;

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("orphan_dl")).await;

    // Insert a DB record claiming version 1 exists, but don't upload to S3
    sqlx::query("INSERT INTO backups (device_id, current_version, state) VALUES ($1, 1, 'ACTIVE')")
        .bind(user.device_id)
        .execute(&app.pool)
        .await
        .unwrap();

    let resp = app
        .client
        .get(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Same as above but for HEAD — covers the `StorageError::NotFound` mapping in `head()`.
#[tokio::test]
async fn test_backup_head_orphaned_db_record() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-orphan-hd-{}", &Uuid::new_v4().to_string()[..8]);
    config.backup.min_size_bytes = 0;

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("orphan_hd")).await;

    // Insert a DB record claiming version 1 exists, but don't upload to S3
    sqlx::query("INSERT INTO backups (device_id, current_version, state) VALUES ($1, 1, 'ACTIVE')")
        .bind(user.device_id)
        .execute(&app.pool)
        .await
        .unwrap();

    let resp = app
        .client
        .head(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Tests the actual stale-upload takeover path in `handle_upload`.
///
/// Manually puts the DB into UPLOADING state with an OLD `pending_at`, then
/// sends a new upload with the matching version. The service should detect
/// the stale upload and force-reserve a new slot (takeover).
#[tokio::test]
async fn test_backup_stale_takeover_via_db_state() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-stale-take-{}", &Uuid::new_v4().to_string()[..8]);
    config.backup.min_size_bytes = 0;
    config.backup.stale_threshold_mins = 1; // 1 minute threshold

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("stale_take")).await;

    // Upload v1 to S3 so there's a real backup on disk
    let key_v1 = format!("{}{}/v1", config.backup.prefix, user.device_id);
    app.s3_client
        .put_object()
        .bucket(&config.storage.bucket)
        .key(&key_v1)
        .body(aws_sdk_s3::primitives::ByteStream::from(b"original backup".to_vec()))
        .send()
        .await
        .unwrap();

    // Put DB into UPLOADING state with a STALE pending_at (2 minutes ago)
    // This simulates a previous upload that started but never completed.
    sqlx::query(
        "INSERT INTO backups (device_id, current_version, pending_version, state, pending_at) \
         VALUES ($1, 1, 2, 'UPLOADING', NOW() - INTERVAL '2 minutes')",
    )
    .bind(user.device_id)
    .execute(&app.pool)
    .await
    .unwrap();

    // Send a new upload with If-Match: 1 (matching current_version).
    // reserve_active_slot fails (state=UPLOADING), but the fallback detects
    // stale pending_at and performs a takeover via reserve_slot_force.
    let resp = app
        .client
        .post(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-Match", "1")
        .body(b"Takeover backup data".to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let etag = resp.headers().get("ETag").unwrap().to_str().unwrap();
    assert_eq!(etag, "\"2\"", "Takeover should produce version 2");

    // Verify the backup is downloadable
    let dl = app
        .client
        .get(format!("{}/v1/backup", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();
    assert_eq!(dl.status(), StatusCode::OK);
    assert_eq!(dl.bytes().await.unwrap(), b"Takeover backup data".as_ref());
}
