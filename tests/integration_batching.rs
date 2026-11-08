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

mod common;

use std::collections::HashSet;
use std::time::Duration;

/// Verifies that sub-batching delivers all messages when the total payload
/// exceeds `max_batch_bytes`. Uses a very small limit (1 KiB) so even small
/// messages are forced into separate sub-batches, exercising the splitting logic.
#[tokio::test]
async fn test_sub_batching_delivers_all_messages() {
    let mut config = common::get_test_config();
    config.websocket.message_fetch_batch_size = std::num::NonZeroU32::new(20).unwrap();
    // 1 KiB limit forces virtually every message into its own sub-batch.
    config.websocket.max_batch_bytes = 1024;

    let app = common::TestApp::spawn_with_config(config).await;

    let user_a = app.register_user(&common::generate_username("alice")).await;
    let user_b = app.register_user(&common::generate_username("bob")).await;

    let message_count = 20;
    let mut expected_contents: Vec<Vec<u8>> = Vec::new();

    for i in 0..message_count {
        let content = format!("sub-batch message {i}").into_bytes();
        expected_contents.push(content.clone());
        app.send_message(&user_a.token, user_b.device_id, &content).await;
    }

    let mut ws = app.connect_ws(&user_b.token).await;

    let mut received_contents: Vec<Vec<u8>> = Vec::new();
    let timeout = Duration::from_secs(10);
    let start = std::time::Instant::now();

    while received_contents.len() < message_count && start.elapsed() < timeout {
        if let Some(env) = ws.receive_envelope_timeout(Duration::from_millis(2000)).await {
            received_contents.push(env.message);
        } else {
            break;
        }
    }

    assert_eq!(
        received_contents.len(),
        message_count,
        "Expected {message_count} messages, got {}",
        received_contents.len()
    );

    // Verify content integrity — every sent message must arrive.
    let expected_set: HashSet<&[u8]> = expected_contents.iter().map(Vec::as_slice).collect();
    let received_set: HashSet<&[u8]> = received_contents.iter().map(Vec::as_slice).collect();
    assert_eq!(expected_set, received_set, "Message contents do not match");
}

/// Verifies that large messages that individually exceed `max_batch_bytes` are
/// still delivered. A single envelope larger than the limit must be sent on its
/// own rather than being silently dropped.
#[tokio::test]
async fn test_oversized_single_message_still_delivered() {
    let mut config = common::get_test_config();
    config.websocket.message_fetch_batch_size = std::num::NonZeroU32::new(10).unwrap();
    // 1 KiB limit — each 4 KiB message exceeds it on its own.
    config.websocket.max_batch_bytes = 1024;

    let app = common::TestApp::spawn_with_config(config).await;

    let user_a = app.register_user(&common::generate_username("alice")).await;
    let user_b = app.register_user(&common::generate_username("bob")).await;

    let large_payload = vec![0xABu8; 4096];
    app.send_message(&user_a.token, user_b.device_id, &large_payload).await;

    let mut ws = app.connect_ws(&user_b.token).await;

    let env = ws.receive_envelope().await.expect("Oversized message was not delivered");
    assert_eq!(env.message, large_payload);
}

/// Verifies that a mix of small and large messages are all delivered when
/// sub-batching is active. The pump must correctly split around large messages
/// while still grouping small ones together.
#[tokio::test]
async fn test_mixed_size_messages_all_delivered() {
    let mut config = common::get_test_config();
    config.websocket.message_fetch_batch_size = std::num::NonZeroU32::new(20).unwrap();
    // 2 KiB limit — small messages batch together, large ones force splits.
    config.websocket.max_batch_bytes = 2048;

    let app = common::TestApp::spawn_with_config(config).await;

    let user_a = app.register_user(&common::generate_username("alice")).await;
    let user_b = app.register_user(&common::generate_username("bob")).await;

    let mut expected_contents: Vec<Vec<u8>> = Vec::new();
    for i in 0u8..15 {
        let content = if i % 3 == 0 {
            // ~3 KiB — exceeds max_batch_bytes on its own
            vec![i; 3000]
        } else {
            // Small message — multiple should fit in one batch
            format!("small {i}").into_bytes()
        };
        expected_contents.push(content.clone());
        app.send_message(&user_a.token, user_b.device_id, &content).await;
    }

    let mut ws = app.connect_ws(&user_b.token).await;

    let mut received_contents: Vec<Vec<u8>> = Vec::new();
    let timeout = Duration::from_secs(10);
    let start = std::time::Instant::now();

    while received_contents.len() < expected_contents.len() && start.elapsed() < timeout {
        if let Some(env) = ws.receive_envelope_timeout(Duration::from_millis(2000)).await {
            received_contents.push(env.message);
        } else {
            break;
        }
    }

    assert_eq!(
        received_contents.len(),
        expected_contents.len(),
        "Expected {} messages, got {}",
        expected_contents.len(),
        received_contents.len()
    );

    let expected_set: HashSet<&[u8]> = expected_contents.iter().map(Vec::as_slice).collect();
    let received_set: HashSet<&[u8]> = received_contents.iter().map(Vec::as_slice).collect();
    assert_eq!(expected_set, received_set, "Message contents do not match");
}

/// Verifies that batch delivery works with the default `max_batch_bytes` for a
/// normal workload (many small messages). This exercises the happy-path where
/// all messages fit in a single batch frame.
#[tokio::test]
async fn test_batch_delivery_default_config() {
    let app = common::TestApp::spawn().await;

    let user_a = app.register_user(&common::generate_username("alice")).await;
    let user_b = app.register_user(&common::generate_username("bob")).await;

    let message_count = 30;
    let mut expected: Vec<Vec<u8>> = Vec::new();

    for i in 0..message_count {
        let content = format!("batch default {i}").into_bytes();
        expected.push(content.clone());
        app.send_message(&user_a.token, user_b.device_id, &content).await;
    }

    let mut ws = app.connect_ws(&user_b.token).await;

    let mut received: Vec<Vec<u8>> = Vec::new();
    let timeout = Duration::from_secs(10);
    let start = std::time::Instant::now();

    while received.len() < message_count && start.elapsed() < timeout {
        if let Some(env) = ws.receive_envelope_timeout(Duration::from_millis(2000)).await {
            received.push(env.message);
        } else {
            break;
        }
    }

    assert_eq!(received.len(), message_count, "Expected {message_count} messages, got {}", received.len());

    let expected_set: HashSet<&[u8]> = expected.iter().map(Vec::as_slice).collect();
    let received_set: HashSet<&[u8]> = received.iter().map(Vec::as_slice).collect();
    assert_eq!(expected_set, received_set, "Message contents do not match");
}
