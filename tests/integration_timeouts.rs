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
use futures::stream;
use reqwest::StatusCode;
use std::time::Duration;
use uuid::Uuid;

mod common;

#[tokio::test]
async fn test_standard_request_timeout() {
    let mut config = common::get_test_config();
    // Set standard request timeout to 2s for better CI stability
    config.server.request_timeout_secs = 2;

    let app = common::TestApp::spawn_with_config(config).await;
    let username = common::generate_username("timeout_std");
    let user = app.register_user(&username).await;

    // Create a stream that waits 3 seconds (exceeding 2s timeout)
    let delayed_stream = stream::unfold(0, |state| async move {
        if state == 0 {
            tokio::time::sleep(Duration::from_millis(3000)).await;
            Some((Ok::<_, std::io::Error>(bytes::Bytes::from("slow data")), 1))
        } else {
            None
        }
    });

    let resp = app
        .client
        .post(format!("{}/v1/messages", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", "9")
        .body(reqwest::Body::wrap_stream(delayed_stream))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
}

#[tokio::test]
async fn test_attachment_upload_timeout() {
    let mut config = common::get_test_config();
    config.attachment.request_timeout_secs = 2; // 2 second limit

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let username = common::generate_username("timeout_up_att");
    let user = app.register_user(&username).await;

    // Create a stream that waits 3 seconds
    let delayed_stream = stream::unfold(0, |state| async move {
        if state == 0 {
            tokio::time::sleep(Duration::from_millis(3000)).await;
            Some((Ok::<_, std::io::Error>(bytes::Bytes::from("att data")), 1))
        } else {
            None
        }
    });

    let resp = app
        .client
        .post(format!("{}/v1/attachments", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Content-Length", "8")
        .body(reqwest::Body::wrap_stream(delayed_stream))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
}

#[tokio::test]
async fn test_global_safety_timeout() {
    let mut config = common::get_test_config();
    config.server.global_timeout_secs = 3; // Hard cap at 3s to allow registration
    // Make standard timeout longer so only global trips
    config.server.request_timeout_secs = 30;

    let app = common::TestApp::spawn_with_config(config).await;
    let username = common::generate_username("timeout_global");
    let user = app.register_user(&username).await;

    // Create a stream that takes 4 seconds (longer than global 3s, but shorter than request 30s)
    let delayed_stream = stream::unfold(0, |state| async move {
        if state == 0 {
            tokio::time::sleep(Duration::from_millis(4000)).await;
            Some((Ok::<_, std::io::Error>(bytes::Bytes::from("slow data")), 1))
        } else {
            None
        }
    });

    let resp = app
        .client
        .post(format!("{}/v1/attachments", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Content-Length", "9")
        .body(reqwest::Body::wrap_stream(delayed_stream))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
}

#[tokio::test]
async fn test_attachment_timeout_independence() {
    let mut config = common::get_test_config();

    // Set Attachment Timeout LONGER than Standard Request Timeout (1s)
    config.attachment.request_timeout_secs = 5;
    config.server.request_timeout_secs = 1;

    let app = common::TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let username = common::generate_username("timeout_indep");
    let user = app.register_user(&username).await;

    // Create a stream that takes 2 seconds (Longer than standard 1s, shorter than Attachment's 5s)
    let delayed_stream = stream::unfold(0, |state| async move {
        if state == 0 {
            tokio::time::sleep(Duration::from_millis(2000)).await;
            Some((Ok::<_, std::io::Error>(bytes::Bytes::from("slow data")), 1))
        } else {
            None
        }
    });

    let resp = app
        .client
        .post(format!("{}/v1/attachments", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Content-Length", "9")
        .body(reqwest::Body::wrap_stream(delayed_stream))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "Attachment upload should have succeeded with 5s attachment timeout despite 1s standard timeout."
    );
}
