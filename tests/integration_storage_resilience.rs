#![allow(
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
use futures::{StreamExt, stream};
use obscura_server::adapters::storage::{ObjectStorage, S3Storage};
use obscura_server::domain::attachment::SizeLimits;
use std::sync::Arc;
use uuid::Uuid;

mod common;

#[tokio::test]
async fn test_s3_storage_faulty_stream_resilience() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-faulty-{}", &Uuid::new_v4().to_string()[..8]);

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let storage = Arc::new(S3Storage::new(app.s3_client.clone(), config.storage.bucket.clone()));

    // 1. Create a stream that returns a technical error after the first chunk
    let faulty_stream =
        stream::iter(vec![Ok(bytes::Bytes::from("good data")), Err(std::io::Error::other("technical failure"))])
            .boxed();

    // 2. Attempt 'put'
    let key = "faulty-test-key";
    let res = storage.put(key, faulty_stream, None, SizeLimits::new(0, 1024).unwrap()).await;

    // 3. Verify it failed
    assert!(res.is_err(), "Storage 'put' should fail on faulty stream");

    // 4. Verify no partial object committed (cleanup check)
    let head_res = app.s3_client.head_object().bucket(&config.storage.bucket).key(key).send().await;

    assert!(head_res.is_err(), "No object should have been committed to S3 on stream failure");
}

#[tokio::test]
async fn test_s3_storage_max_size_enforcement() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-max-size-{}", &Uuid::new_v4().to_string()[..8]);

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let storage = Arc::new(S3Storage::new(app.s3_client.clone(), config.storage.bucket.clone()));

    // 1. Create a large stream (150 bytes) with a 100 byte limit
    let large_data = vec![0u8; 150];
    let stream = stream::iter(vec![Ok(bytes::Bytes::from(large_data))]).boxed();

    // 2. Attempt 'put'
    let key = "too-large-key";
    let res = storage.put(key, stream, None, SizeLimits::new(0, 100).unwrap()).await;

    // 3. Verify it failed
    assert!(res.is_err(), "Storage 'put' should fail when exceeding max size");

    // 4. Verify no partial object committed
    let head_res = app.s3_client.head_object().bucket(&config.storage.bucket).key(key).send().await;
    assert!(head_res.is_err(), "No object should have been committed to S3 when exceeding size limit");
}

#[tokio::test]
async fn test_s3_storage_min_size_enforcement() {
    let mut config = common::get_test_config();
    config.storage.bucket = format!("test-min-size-{}", &Uuid::new_v4().to_string()[..8]);

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let storage = Arc::new(S3Storage::new(app.s3_client.clone(), config.storage.bucket.clone()));

    // 1. Create a small stream (5 bytes) with a 10 byte minimum
    let small_data = vec![0u8; 5];
    let stream = stream::iter(vec![Ok(bytes::Bytes::from(small_data))]).boxed();

    // 2. Attempt 'put'
    let key = "too-small-key";
    let res = storage.put(key, stream, None, SizeLimits::new(10, 100).unwrap()).await;

    // 3. Verify it failed (min_size violation returns error)
    assert!(res.is_err(), "Storage 'put' should fail when below min size");

    // 4. Verify no partial object committed (should have been deleted)
    let head_res = app.s3_client.head_object().bucket(&config.storage.bucket).key(key).send().await;
    assert!(head_res.is_err(), "No object should remain in S3 when below min size");
}
