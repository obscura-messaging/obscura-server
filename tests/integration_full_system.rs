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

use common::{TestApp, notification_counts};
use obscura_server::proto::obscura::v1 as proto;
use prost::Message;
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
async fn test_full_system_flow() {
    common::setup_tracing();

    // 1. Setup Shared Configuration
    let mut config = common::get_test_config();
    // Enable push notifications with a delay to allow coalescing
    config.notifications.push_delay_secs = 2;
    config.notifications.worker_interval_secs = 1;
    // Ensure we can handle the batch size
    config.messaging.send_batch_limit = 100;

    // 2. Spawn 3 Nodes (A, B, C) sharing the same resources (DB, Redis)
    let app_a = TestApp::spawn_with_workers(config.clone()).await;
    let app_b = TestApp::spawn_with_workers(config.clone()).await;
    let app_c = TestApp::spawn_with_workers(config.clone()).await;

    // 3. Register Users
    // Sender on Node A
    let sender = app_a.register_user(&common::generate_username("sender")).await;
    // Receiver on Node B (initially)
    let receiver = app_b.register_user(&common::generate_username("receiver")).await;

    // 4. Register Push Token for Receiver (so they get offline notifications)
    // We can use the helper or direct SQL. Helper is cleaner if available, but TestApp doesn't expose one.
    // We'll use direct SQL via app_b's pool.
    {
        let mut conn = app_b.pool.acquire().await.unwrap();
        let repo = obscura_server::adapters::database::push_token_repo::PushTokenRepository::new();
        repo.upsert_token(&mut conn, receiver.device_id, &format!("token:{}", receiver.device_id)).await.unwrap();
    }

    // 5. Construct Batch of 50 Messages
    // - 20 Valid
    // - 1 Invalid (Bad Recipient)
    // - 29 Valid
    let mut messages = Vec::new();
    let mut expected_content = std::collections::HashSet::new();

    // First 20 Valid
    for i in 0..20 {
        let content = format!("Valid Message {i}").into_bytes();
        expected_content.insert(content.clone());
        messages.push(proto::send_message_request::Submission {
            submission_id: Uuid::new_v4().as_bytes().to_vec(),
            device_id: receiver.device_id.as_bytes().to_vec(),
            message: content.clone(),
        });
    }

    // 1 Invalid Recipient
    let invalid_device_id = Uuid::new_v4();
    messages.push(proto::send_message_request::Submission {
        submission_id: Uuid::new_v4().as_bytes().to_vec(),
        device_id: invalid_device_id.as_bytes().to_vec(),
        message: b"Invalid".to_vec(),
    });

    // Next 29 Valid
    for i in 20..49 {
        let content = format!("Valid Message {i}").into_bytes();
        expected_content.insert(content.clone());
        messages.push(proto::send_message_request::Submission {
            submission_id: Uuid::new_v4().as_bytes().to_vec(),
            device_id: receiver.device_id.as_bytes().to_vec(),
            message: content.clone(),
        });
    }

    let request = proto::SendMessageRequest { recipient_user_ids: Vec::new(), messages };
    let mut payload = Vec::new();
    request.encode(&mut payload).unwrap();

    // 6. Send Batch via Node A
    let resp = app_a
        .client
        .post(format!("{}/v1/messages", app_a.server_url))
        .header("Authorization", format!("Bearer {}", sender.token))
        .header("Content-Type", "application/x-protobuf")
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .body(payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let resp_bytes = resp.bytes().await.unwrap();
    let response = proto::SendMessageResponse::decode(resp_bytes).unwrap();

    // 7. Verify Partial Success
    // We expect exactly 1 failed message (the invalid recipient)
    assert_eq!(response.failed_submissions.len(), 1, "Expected 1 failed message in the batch");
    assert_eq!(
        response.failed_submissions[0].error_code,
        proto::send_message_response::ErrorCode::InvalidDevice as i32
    );

    // 8. Verify Push Coalescing
    // Receiver is offline, so push notification should fire.
    // We sent 49 valid messages. We expect EXACTLY 1 push notification due to coalescing/debouncing.
    // Wait for the push delay (2s) + buffer.
    tokio::time::sleep(Duration::from_secs(4)).await;

    let push_count = notification_counts().get(&receiver.device_id).map_or(0, |c| *c);
    assert_eq!(push_count, 1, "Expected exactly 1 coalesced push notification, got {push_count}");

    // 9. Connect Receiver to Node C (WebSocket)
    // This simulates roaming or load balancing.
    let mut ws = app_c.connect_ws(&receiver.token).await;

    // 10. Verify Message Delivery (49 messages)
    let mut received_count = 0;
    let start = std::time::Instant::now();

    while received_count < 49 && start.elapsed() < Duration::from_secs(10) {
        if let Some(env) = ws.receive_envelope_timeout(Duration::from_millis(500)).await {
            assert_eq!(env.sender_id, sender.user_id.as_bytes().to_vec());
            assert_eq!(env.sender_device_id, sender.device_id.as_bytes().to_vec());

            let content = env.message;
            if expected_content.remove(&content) {
                received_count += 1;
            }

            // Ack to verify it's removed from DB
            ws.send_ack(env.id).await;
        }
    }

    assert_eq!(received_count, 49, "Did not receive all 49 valid messages on Node C");
    assert!(expected_content.is_empty(), "Some messages were missed or mismatched: {expected_content:?}");

    // 11. Verify Push Job Cleanup (Explicit Redis Check)
    // The push job should be removed from the ZSET because the user connected (or acknowledged).
    // Note: The job might have been removed by the worker *processing* it (step 8),
    // BUT since we are testing system consistency, we ensure it's definitely gone now.
    let client = redis::Client::open(config.pubsub.url.clone()).unwrap();
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    let score: Option<f64> = redis::cmd("ZSCORE")
        .arg(&config.notifications.push_queue_key)
        .arg(receiver.device_id.to_string())
        .query_async(&mut conn)
        .await
        .unwrap();

    assert!(score.is_none(), "Push job should be removed from Redis");

    // 12. Verify Fast Path (No Extra Push)
    // Send 1 more message
    let single_msg_content = b"Fast Path".to_vec();
    app_a.send_message(&sender.token, receiver.device_id, &single_msg_content).await;

    let env = ws.receive_envelope().await.expect("Failed to receive fast-path message");
    assert_eq!(env.message, single_msg_content);

    // ACK the message so the server cancels the scheduled push job.
    // (notify() always schedules a fallback push; the ACK triggers cancel_pending_notifications.)
    ws.send_ack(env.id).await;

    // Ensure NO extra push was sent for this fast-path message
    // Wait a bit to be sure
    tokio::time::sleep(Duration::from_secs(3)).await;
    let final_push_count = notification_counts().get(&receiver.device_id).map_or(0, |c| *c);
    assert_eq!(final_push_count, 1, "Fast-path message should not trigger push");
}
