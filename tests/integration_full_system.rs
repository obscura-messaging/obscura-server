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

    // 5. Send 49 Valid Messages + 1 Invalid Device via Node A
    let mut expected_content = std::collections::HashSet::new();

    for i in 0..48 {
        let content = format!("Valid Message {i}").into_bytes();
        expected_content.insert(content.clone());
        app_a.send_message(&sender.token, receiver.device_id, &content).await;
    }

    let last_content = b"Valid Message 48".to_vec();
    expected_content.insert(last_content.clone());
    let invalid_device_id = Uuid::new_v4();
    let request = proto::SendMessageRequest {
        recipients: vec![proto::send_message_request::Recipient {
            user_id: receiver.user_id.as_bytes().to_vec(),
            submissions: vec![
                proto::send_message_request::Submission {
                    device_id: receiver.device_id.as_bytes().to_vec(),
                    message: last_content,
                },
                proto::send_message_request::Submission {
                    device_id: invalid_device_id.as_bytes().to_vec(),
                    message: b"Invalid".to_vec(),
                },
            ],
        }],
    };
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
    assert_eq!(response.invalid_device_ids, vec![invalid_device_id.as_bytes().to_vec()]);
    assert!(response.device_mismatches.is_empty(), "{:?}", response.device_mismatches);

    // 8. Verify Push Coalescing
    // Receiver is offline, so push notification should fire.
    // We sent 49 valid messages. We expect EXACTLY 1 push notification due to coalescing/debouncing.
    let pushed = app_a
        .wait_until(|| async { notification_counts().get(&receiver.device_id).is_some() }, Duration::from_secs(10))
        .await;
    assert!(pushed, "the coalesced push was never sent");

    // The worker removes a job only after sending its push, so once the job is gone, no further push can
    // come from it. Checked before the receiver connects, because connecting cancels the job too.
    let removed = app_a
        .wait_until(|| async { !app_a.push_job_scheduled(receiver.device_id).await }, Duration::from_secs(10))
        .await;
    assert!(removed, "the push job should be removed once its push is sent");

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
            assert_eq!(env.sender_user_id, sender.user_id.as_bytes().to_vec());
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

    // Wait for the ACKs to be processed. Each ACK also cancels pending pushes in the background, and those
    // cancels must finish before step 12, or they would remove the fast-path push job instead of its own ACK.
    app_c.assert_message_count(receiver.device_id, 0).await;

    // 11. Verify Push Job Cleanup (Explicit Redis Check)
    // The push job should be removed from the ZSET because the user connected (or acknowledged).
    // Note: The job might have been removed by the worker *processing* it (step 8),
    // BUT since we are testing system consistency, we ensure it's definitely gone now.
    assert!(!app_a.push_job_scheduled(receiver.device_id).await, "Push job should be removed from Redis");

    // 12. Verify Fast Path (No Extra Push)
    // Send 1 more message
    let single_msg_content = b"Fast Path".to_vec();
    app_a.send_message(&sender.token, receiver.device_id, &single_msg_content).await;

    // notify() always schedules a fallback push, before the send responds.
    assert!(app_a.push_job_scheduled(receiver.device_id).await, "sending should schedule a fallback push");

    let env = ws.receive_envelope().await.expect("Failed to receive fast-path message");
    assert_eq!(env.message, single_msg_content);
    assert!(app_a.push_job_scheduled(receiver.device_id).await, "only the ACK should cancel the fallback push");

    // ACK the message so the server cancels the scheduled push job.
    ws.send_ack(env.id).await;

    // The worker removes a job only after sending its push, so once the job is gone, any push it sent has
    // already been counted. A missed cancellation shows up as a second push, with no fixed wait.
    let removed = app_a
        .wait_until(|| async { !app_a.push_job_scheduled(receiver.device_id).await }, Duration::from_secs(10))
        .await;
    assert!(removed, "fallback push job was never removed");
    let final_push_count = notification_counts().get(&receiver.device_id).map_or(0, |c| *c);
    assert_eq!(final_push_count, 1, "Fast-path message should not trigger push");
}
