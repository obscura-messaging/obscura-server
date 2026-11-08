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
use reqwest::StatusCode;
use uuid::Uuid;

mod common;

#[tokio::test]
async fn test_attachment_lifecycle() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-bucket-{}", &Uuid::new_v4().to_string()[..8]);
    config.attachment.max_size_bytes = 100; // Small but enough for "hello"

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("att_life")).await;

    // 1. Upload Success
    let content = b"Hello Obscura!";
    let resp_up = app
        .client
        .post(format!("{}/v1/attachments", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Content-Length", content.len().to_string())
        .body(content.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp_up.status(), StatusCode::CREATED);
    let up_json: serde_json::Value = resp_up.json().await.unwrap();
    let attachment_id = up_json["id"].as_str().unwrap();

    // 2. Download Success
    let resp_down = app
        .client
        .get(format!("{}/v1/attachments/{}", app.server_url, attachment_id))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_down.status(), StatusCode::OK);
    assert_eq!(resp_down.bytes().await.unwrap(), content.to_vec());

    // 3. Upload Failure (Size Limit - Header check)
    let resp_big_header = app
        .client
        .post(format!("{}/v1/attachments", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Content-Length", "101") // Over 100 limit
        .body(vec![0u8; 101])
        .send()
        .await
        .unwrap();
    assert_eq!(resp_big_header.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // 4. Upload Failure (Size Limit - Stream check)
    let stream_data = vec![0u8; 150];
    let stream = futures::stream::iter(vec![Ok::<_, std::io::Error>(axum::body::Bytes::from(stream_data))]);
    let resp_big_stream = app
        .client
        .post(format!("{}/v1/attachments", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .unwrap();

    // Server should reject missing Content-Length with 411
    assert_eq!(resp_big_stream.status(), StatusCode::LENGTH_REQUIRED);

    // 5. Download Not Found
    let resp_404 = app
        .client
        .get(format!("{}/v1/attachments/{}", app.server_url, Uuid::new_v4()))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_404.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_attachment_cleanup() {
    use obscura_server::adapters::database::attachment_repo::AttachmentRepository;
    use obscura_server::adapters::storage::S3Storage;
    use obscura_server::workers::AttachmentCleanupWorker;
    use std::sync::Arc;
    use time::{Duration, OffsetDateTime};

    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-att-cleanup-{}", &Uuid::new_v4().to_string()[..8]);

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    // 1. Seed Expired Attachment
    let id = Uuid::new_v4();
    let expires_at = OffsetDateTime::now_utc() - Duration::days(1);
    {
        sqlx::query("INSERT INTO attachments (id, expires_at) VALUES ($1, $2)")
            .bind(id)
            .bind(expires_at)
            .execute(&app.pool)
            .await
            .unwrap();
    }

    // 2. Put file in S3
    let key = config.attachment.object_key(id);
    app.s3_client
        .put_object()
        .bucket(&config.storage.bucket)
        .key(&key)
        .body(aws_sdk_s3::primitives::ByteStream::from(b"expired data".to_vec()))
        .send()
        .await
        .unwrap();

    // 3. Instantiate Worker
    let storage_adapter = Arc::new(S3Storage::new(app.s3_client.clone(), config.storage.bucket.clone()));
    let service = obscura_server::services::attachment_service::AttachmentService::new(
        app.pool.clone(),
        AttachmentRepository::new(),
        storage_adapter,
        config.attachment.clone(),
        config.attachment.size_limits().unwrap(),
        config.ttl_days,
    );
    let worker = AttachmentCleanupWorker::new(service, config.attachment.cleanup_interval_secs);

    // 4. Execution
    let deleted_count = worker.cleanup_batch().await.expect("Worker cleanup failed");
    assert!(deleted_count >= 1);

    // 5. Verification: DB State
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attachments WHERE id = $1)")
        .bind(id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert!(!exists, "Attachment record should be deleted from DB");

    // 6. Verification: S3 Object is GONE
    let head_res = app.s3_client.head_object().bucket(&config.storage.bucket).key(&key).send().await;
    assert!(head_res.is_err(), "Attachment object should be deleted from S3");
}

#[tokio::test]
async fn test_attachment_min_size() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-att-min-{}", &Uuid::new_v4().to_string()[..8]);
    config.attachment.min_size_bytes = 5;

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("att_min")).await;

    // 1. Upload too small (Header check)
    let resp = app
        .client
        .post(format!("{}/v1/attachments", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Content-Length", "4")
        .body(vec![0u8; 4])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 2. Upload just enough (Header check)
    let resp_ok = app
        .client
        .post(format!("{}/v1/attachments", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Content-Length", "5")
        .body(vec![0u8; 5])
        .send()
        .await
        .unwrap();
    assert_eq!(resp_ok.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_attachment_conditional_download() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-att-cond-{}", &Uuid::new_v4().to_string()[..8]);

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let user = app.register_user(&common::generate_username("att_cond")).await;

    // 1. Initial Upload
    let content = b"Attachment Data";
    let resp_up = app
        .client
        .post(format!("{}/v1/attachments", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Content-Length", content.len().to_string())
        .body(content.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp_up.status(), StatusCode::CREATED);
    let id: String = resp_up.json::<serde_json::Value>().await.unwrap()["id"].as_str().unwrap().to_string();

    // 2. Download with matching If-None-Match
    let resp_304 = app
        .client
        .get(format!("{}/v1/attachments/{}", app.server_url, id))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-None-Match", format!("\"{id}\""))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_304.status(), StatusCode::NOT_MODIFIED);

    // 3. Download with non-matching If-None-Match
    let resp_200 = app
        .client
        .get(format!("{}/v1/attachments/{}", app.server_url, id))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("If-None-Match", "\"different-id\"")
        .send()
        .await
        .unwrap();
    assert_eq!(resp_200.status(), StatusCode::OK);
    assert_eq!(resp_200.bytes().await.unwrap(), content.to_vec());
}

#[tokio::test]
async fn test_attachment_exact_max_size_accepted() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-att-max-{}", &Uuid::new_v4().to_string()[..8]);
    config.attachment.max_size_bytes = 100;

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;
    let user = app.register_user(&common::generate_username("att_max")).await;

    let content = vec![7u8; 100];
    let resp = app
        .client
        .post(format!("{}/v1/attachments", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Content-Length", "100")
        .body(content.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "an attachment of exactly max_size_bytes is accepted");
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"].as_str().unwrap().to_string();

    let resp = app
        .client
        .get(format!("{}/v1/attachments/{}", app.server_url, id))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap(), content);
}

#[tokio::test]
async fn test_expired_attachment_is_not_downloadable() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-att-exp-{}", &Uuid::new_v4().to_string()[..8]);

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;
    let user = app.register_user(&common::generate_username("att_exp")).await;

    // Expired in the database, but the cleanup worker has not removed the object yet.
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO attachments (id, expires_at) VALUES ($1, NOW() - INTERVAL '1 day')")
        .bind(id)
        .execute(&app.pool)
        .await
        .unwrap();
    app.s3_client
        .put_object()
        .bucket(&config.storage.bucket)
        .key(config.attachment.object_key(id))
        .body(aws_sdk_s3::primitives::ByteStream::from(b"expired data".to_vec()))
        .send()
        .await
        .unwrap();

    let resp = app
        .client
        .get(format!("{}/v1/attachments/{}", app.server_url, id))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_attachment_missing_from_storage_is_not_found() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-att-gone-{}", &Uuid::new_v4().to_string()[..8]);

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;
    let user = app.register_user(&common::generate_username("att_gone")).await;

    // Unexpired in the database, but the object is missing from storage.
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO attachments (id, expires_at) VALUES ($1, NOW() + INTERVAL '1 day')")
        .bind(id)
        .execute(&app.pool)
        .await
        .unwrap();

    let resp = app
        .client
        .get(format!("{}/v1/attachments/{}", app.server_url, id))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
