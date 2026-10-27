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

use common::TestApp;
use futures::SinkExt;
use obscura_server::proto::obscura::v1 as proto;
use prost::Message as ProstMessage;

use std::time::Duration;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use uuid::Uuid;

#[tokio::test]
async fn test_messaging_flow() {
    let app = TestApp::spawn_with_workers(common::get_test_config()).await;

    let user_a = app.register_user(&common::generate_username("alice")).await;
    let user_b = app.register_user(&common::generate_username("bob")).await;

    // Connect Bob's WebSocket FIRST to listen for real-time notifications
    let mut ws = app.connect_ws(&user_b.token).await;
    ws.ensure_subscribed().await;

    let content = b"Hello World".to_vec();
    app.send_message(&user_a.token, user_b.device_id, &content).await;

    let env = ws.receive_envelope().await.expect("Did not receive message");
    assert_eq!(env.message, content);
    // Signal-aligned Option B: the envelope carries BOTH the sending user and device.
    assert_eq!(env.sender_id.len(), 16, "sender_id must be a 16-byte UUID");
    assert_eq!(env.sender_id, user_a.user_id.as_bytes().to_vec(), "sender_id must be the sending user");
    assert_eq!(env.sender_device_id.len(), 16, "sender_device_id must be a 16-byte UUID");
    assert_eq!(
        env.sender_device_id,
        user_a.device_id.as_bytes().to_vec(),
        "sender_device_id must be the sending device"
    );

    ws.send_ack(env.id).await;
}

#[tokio::test]
async fn test_message_pagination_large_backlog() {
    let app = TestApp::spawn().await;

    let user_a = app.register_user(&common::generate_username("alice_pag")).await;
    let user_b = app.register_user(&common::generate_username("bob_pag")).await;

    let message_count = 125;
    for i in 0..message_count {
        let content = format!("Message {i}");
        app.send_message(&user_a.token, user_b.device_id, content.as_bytes()).await;
    }

    let mut ws = app.connect_ws(&user_b.token).await;

    let mut received_ids = Vec::new();
    let timeout = Duration::from_secs(10);
    let start = std::time::Instant::now();

    while received_ids.len() < message_count && start.elapsed() < timeout {
        if let Some(env) = ws.receive_envelope_timeout(Duration::from_millis(1000)).await {
            if !received_ids.contains(&env.id) {
                received_ids.push(env.id);
            }
        } else {
            break;
        }
    }

    assert_eq!(received_ids.len(), message_count, "Did not receive all messages");
}

#[tokio::test]
async fn test_ack_batching_behavior() {
    let mut config = common::get_test_config();
    config.websocket.ack_batch_size = 5;
    config.websocket.ack_flush_interval_ms = 1000;

    let app = TestApp::spawn_with_workers(config).await;

    let user_a = app.register_user(&common::generate_username("alice_ack")).await;
    let user_b = app.register_user(&common::generate_username("bob_ack")).await;

    // Connect Bob's WebSocket FIRST
    let mut ws = app.connect_ws(&user_b.token).await;
    ws.ensure_subscribed().await;

    for i in 0..3 {
        app.send_message(&user_a.token, user_b.device_id, format!("msg {i}").as_bytes()).await;
    }

    let mut message_ids = Vec::new();
    for _ in 0..3 {
        if let Some(env) = ws.receive_envelope().await {
            message_ids.push(env.id);
        }
    }
    assert_eq!(message_ids.len(), 3);

    for id in &message_ids {
        ws.send_ack(id.clone()).await;
    }

    // Verify NOT deleted immediately (Buffer < Batch Size)
    tokio::time::sleep(Duration::from_millis(200)).await;
    app.assert_message_count(user_b.device_id, 3).await;

    // Verify flushed after interval
    app.assert_message_count(user_b.device_id, 0).await;
}

#[tokio::test]
async fn test_send_message_recipient_not_found() {
    let app = TestApp::spawn().await;
    let user_a = app.register_user(&common::generate_username("alice_404")).await;
    let bad_id = Uuid::new_v4();

    let submission_id = Uuid::new_v4();
    let request = proto::SendMessageRequest {
        recipient_user_ids: Vec::new(),
        messages: vec![proto::send_message_request::Submission {
            submission_id: submission_id.as_bytes().to_vec(),
            device_id: bad_id.as_bytes().to_vec(),
            message: b"Hello".to_vec(),
        }],
    };
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    let resp = app
        .client
        .post(format!("{}/v1/messages", app.server_url))
        .header("Authorization", format!("Bearer {}", user_a.token))
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    let response = proto::SendMessageResponse::decode(body).unwrap();
    assert_eq!(response.failed_submissions.len(), 1);
    assert_eq!(response.failed_submissions[0].submission_id, submission_id.as_bytes().to_vec());
    assert_eq!(
        response.failed_submissions[0].error_code,
        proto::send_message_response::ErrorCode::InvalidDevice as i32
    );
}

#[tokio::test]
async fn test_send_message_malformed_protobuf() {
    let app = TestApp::spawn().await;
    let user = app.register_user(&common::generate_username("malformed")).await;

    let resp = app
        .client
        .post(format!("{}/v1/messages", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .header("Content-Type", "application/x-protobuf")
        .body(vec![0, 1, 2])
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_message_idempotency() {
    let app = TestApp::spawn().await;
    let user_a = app.register_user(&common::generate_username("alice_idem")).await;
    let user_b = app.register_user(&common::generate_username("bob_idem")).await;

    let idempotency_key = Uuid::new_v4();
    let content = b"Idempotent Hello".to_vec();

    let request = proto::SendMessageRequest {
        recipient_user_ids: Vec::new(),
        messages: vec![proto::send_message_request::Submission {
            submission_id: Uuid::new_v4().as_bytes().to_vec(),
            device_id: user_b.device_id.as_bytes().to_vec(),
            message: content.clone(),
        }],
    };
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    // First attempt
    let resp1 = app
        .client
        .post(format!("{}/v1/messages", app.server_url))
        .header("Authorization", format!("Bearer {}", user_a.token))
        .header("Idempotency-Key", idempotency_key.to_string())
        .header("Content-Type", "application/x-protobuf")
        .body(buf.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(resp1.status(), 200);
    let body1 = resp1.bytes().await.unwrap();

    // Second attempt (retry)
    let resp2 = app
        .client
        .post(format!("{}/v1/messages", app.server_url))
        .header("Authorization", format!("Bearer {}", user_a.token))
        .header("Idempotency-Key", idempotency_key.to_string())
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send()
        .await
        .unwrap();

    assert_eq!(resp2.status(), 200);
    let body2 = resp2.bytes().await.unwrap();

    // Verify bodies are identical (cached response)
    assert_eq!(body1, body2);

    // Verify only ONE message was queued
    app.assert_message_count(user_b.device_id, 1).await;
}

#[tokio::test]
async fn test_batch_partial_success() {
    let app = TestApp::spawn().await;
    let user_a = app.register_user(&common::generate_username("alice_mix")).await;
    let user_b = app.register_user(&common::generate_username("bob_mix")).await;
    let user_c = app.register_user(&common::generate_username("charlie_mix")).await;
    let bad_id = Uuid::new_v4();

    let submission_id_b = Uuid::new_v4();
    let submission_id_bad = Uuid::new_v4();
    let submission_id_c = Uuid::new_v4();

    let request = proto::SendMessageRequest {
        recipient_user_ids: Vec::new(),
        messages: vec![
            // 1. Valid (Bob)
            proto::send_message_request::Submission {
                submission_id: submission_id_b.as_bytes().to_vec(),
                device_id: user_b.device_id.as_bytes().to_vec(),
                message: b"Msg for Bob".to_vec(),
            },
            // 2. Invalid (Bad ID)
            proto::send_message_request::Submission {
                submission_id: submission_id_bad.as_bytes().to_vec(),
                device_id: bad_id.as_bytes().to_vec(),
                message: b"Msg for Nowhere".to_vec(),
            },
            // 3. Valid (Charlie)
            proto::send_message_request::Submission {
                submission_id: submission_id_c.as_bytes().to_vec(),
                device_id: user_c.device_id.as_bytes().to_vec(),
                message: b"Msg for Charlie".to_vec(),
            },
        ],
    };
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    let resp = app
        .client
        .post(format!("{}/v1/messages", app.server_url))
        .header("Authorization", format!("Bearer {}", user_a.token))
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    let response = proto::SendMessageResponse::decode(body).unwrap();

    // Verify Response: Should list ONLY the failed message
    assert_eq!(response.failed_submissions.len(), 1);
    assert_eq!(response.failed_submissions[0].submission_id, submission_id_bad.as_bytes().to_vec());
    assert_eq!(
        response.failed_submissions[0].error_code,
        proto::send_message_response::ErrorCode::InvalidDevice as i32
    );

    // Verify Delivery: Bob and Charlie should have messages
    app.assert_message_count(user_b.device_id, 1).await;
    app.assert_message_count(user_c.device_id, 1).await;
}

#[tokio::test]
async fn test_batch_empty() {
    let app = TestApp::spawn().await;
    let user = app.register_user(&common::generate_username("empty")).await;

    let request = proto::SendMessageRequest { recipient_user_ids: Vec::new(), messages: vec![] };
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    let resp = app
        .client
        .post(format!("{}/v1/messages", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    let response = proto::SendMessageResponse::decode(body).unwrap();
    assert!(response.failed_submissions.is_empty());
}

#[tokio::test]
async fn test_batch_too_large() {
    let mut config = common::get_test_config();
    config.messaging.send_batch_limit = 5;

    let app = TestApp::spawn_with_config(config).await;
    let user = app.register_user(&common::generate_username("limit")).await;

    let mut messages = Vec::new();
    for _ in 0..6 {
        messages.push(proto::send_message_request::Submission {
            submission_id: Uuid::new_v4().as_bytes().to_vec(),
            device_id: user.device_id.as_bytes().to_vec(),
            message: b"Msg".to_vec(),
        });
    }

    let request = proto::SendMessageRequest { recipient_user_ids: Vec::new(), messages };
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    let resp = app
        .client
        .post(format!("{}/v1/messages", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn test_websocket_auth_failure() {
    let app = TestApp::spawn().await;
    let res = tokio_tungstenite::connect_async(format!("{}?token=invalid", app.ws_url)).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_ack_buffer_saturation() {
    let mut config = common::get_test_config();
    config.websocket.ack_buffer_size = 5;
    config.websocket.ack_batch_size = 1;

    let app = TestApp::spawn_with_config(config).await;
    let user = app.register_user(&common::generate_username("ack_sat")).await;
    let mut client = app.connect_ws(&user.token).await;

    for _ in 0..15 {
        let ack = proto::AckMessage { message_ids: vec![Uuid::new_v4().as_bytes().to_vec()] };
        let frame = proto::WebSocketFrame { payload: Some(proto::web_socket_frame::Payload::Ack(ack)) };
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        client.sink.send(WsMessage::Binary(buf.into())).await.unwrap();
    }

    client.sink.send(WsMessage::Ping(vec![].into())).await.unwrap();
    assert!(client.receive_pong().await.is_some());
}

#[tokio::test]
async fn test_bulk_ack_processing() {
    let app = TestApp::spawn().await;

    let user_a = app.register_user(&common::generate_username("alice_bulk")).await;
    let user_b = app.register_user(&common::generate_username("bob_bulk")).await;

    // Send 5 messages
    for i in 0..5 {
        app.send_message(&user_a.token, user_b.device_id, format!("msg {i}").as_bytes()).await;
    }

    let mut ws = app.connect_ws(&user_b.token).await;

    // Receive all 5
    let mut message_ids = Vec::new();
    for _ in 0..5 {
        if let Some(env) = ws.receive_envelope().await {
            message_ids.push(env.id);
        }
    }
    assert_eq!(message_ids.len(), 5);

    // Send ONE bulk ACK
    let ack = proto::AckMessage { message_ids: message_ids.clone() };
    let frame = proto::WebSocketFrame { payload: Some(proto::web_socket_frame::Payload::Ack(ack)) };
    let mut buf = Vec::new();
    frame.encode(&mut buf).unwrap();
    ws.sink.send(WsMessage::Binary(buf.into())).await.unwrap();

    // Verify all 5 are deleted
    app.assert_message_count(user_b.device_id, 0).await;
}

#[tokio::test]
async fn test_ack_security_cross_user_deletion() {
    let app = TestApp::spawn().await;

    let user_a = app.register_user(&common::generate_username("alice_sec")).await;
    let user_b = app.register_user(&common::generate_username("bob_sec")).await;
    let user_c = app.register_user(&common::generate_username("eve_sec")).await;

    // A sends to B
    app.send_message(&user_a.token, user_b.device_id, b"Secret").await;

    // B connects and gets the message ID
    let mut ws_b = app.connect_ws(&user_b.token).await;
    let env = ws_b.receive_envelope().await.expect("Bob should receive message");
    let target_msg_id = env.id;

    // C tries to ACK B's message
    let mut ws_c = app.connect_ws(&user_c.token).await;
    ws_c.send_ack(target_msg_id.clone()).await;

    // Wait for async processing
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Assert message is STILL there for B (count should be 1)
    app.assert_message_count(user_b.device_id, 1).await;
}

#[tokio::test]
async fn test_send_message_invalid_uuid_bytes() {
    let app = TestApp::spawn().await;
    let user = app.register_user(&common::generate_username("malformed_bytes")).await;

    let request = proto::SendMessageRequest {
        recipient_user_ids: Vec::new(),
        messages: vec![proto::send_message_request::Submission {
            submission_id: Uuid::new_v4().as_bytes().to_vec(), // Valid
            device_id: vec![4, 5, 6],                          // Invalid length
            message: b"Hello".to_vec(),
        }],
    };
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    let resp = app
        .client
        .post(format!("{}/v1/messages", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    let response = proto::SendMessageResponse::decode(body).unwrap();

    assert_eq!(response.failed_submissions.len(), 1);
    assert_eq!(response.failed_submissions[0].error_message, "Invalid device_id UUID bytes (expected 16)");
    assert_eq!(
        response.failed_submissions[0].error_code,
        proto::send_message_response::ErrorCode::MalformedDeviceId as i32
    );
}

#[tokio::test]
async fn test_ack_invalid_uuid_bytes() {
    let app = TestApp::spawn().await;
    let user = app.register_user(&common::generate_username("ack_malformed")).await;
    let mut client = app.connect_ws(&user.token).await;

    // Send ACK with invalid length ID
    let ack = proto::AckMessage {
        message_ids: vec![
            vec![1, 2, 3, 4, 5], // 5 bytes instead of 16
            vec![0u8; 32],       // 32 bytes instead of 16
        ],
    };
    let frame = proto::WebSocketFrame { payload: Some(proto::web_socket_frame::Payload::Ack(ack)) };
    let mut buf = Vec::new();

    frame.encode(&mut buf).unwrap();

    client.sink.send(WsMessage::Binary(buf.into())).await.unwrap();

    // Verify connection stays alive (non-fatal error)
    client.sink.send(WsMessage::Ping(vec![].into())).await.unwrap();
    assert!(client.receive_pong().await.is_some());
}

#[tokio::test]
async fn test_send_message_malformed_submission_id() {
    let app = TestApp::spawn().await;
    let user = app.register_user(&common::generate_username("malformed_sub")).await;
    let recipient = app.register_user(&common::generate_username("recipient_sub")).await;

    let request = proto::SendMessageRequest {
        recipient_user_ids: Vec::new(),
        messages: vec![proto::send_message_request::Submission {
            submission_id: vec![1, 2, 3], // Invalid length
            device_id: recipient.device_id.as_bytes().to_vec(),
            message: b"Hello".to_vec(),
        }],
    };
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    let resp = app
        .client
        .post(format!("{}/v1/messages", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send()
        .await
        .unwrap();

    let body = resp.bytes().await.unwrap();
    let response = proto::SendMessageResponse::decode(body).unwrap();

    assert_eq!(response.failed_submissions.len(), 1);
    assert_eq!(
        response.failed_submissions[0].error_code,
        proto::send_message_response::ErrorCode::MalformedSubmissionId as i32
    );
}

#[tokio::test]
async fn test_send_message_missing_payload() {
    let app = TestApp::spawn().await;
    let user = app.register_user(&common::generate_username("missing_payload")).await;
    let recipient = app.register_user(&common::generate_username("recipient_payload")).await;

    let request = proto::SendMessageRequest {
        recipient_user_ids: Vec::new(),
        messages: vec![proto::send_message_request::Submission {
            submission_id: Uuid::new_v4().as_bytes().to_vec(),
            device_id: recipient.device_id.as_bytes().to_vec(),
            message: Vec::new(), // Missing payload
        }],
    };
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    let resp = app
        .client
        .post(format!("{}/v1/messages", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send()
        .await
        .unwrap();

    let body = resp.bytes().await.unwrap();
    let response = proto::SendMessageResponse::decode(body).unwrap();

    assert_eq!(response.failed_submissions.len(), 1);
    assert_eq!(
        response.failed_submissions[0].error_code,
        proto::send_message_response::ErrorCode::MessageMissing as i32
    );
}

#[tokio::test]
async fn test_multi_device_messaging() {
    let app = TestApp::spawn_with_workers(common::get_test_config()).await;
    let username = common::generate_username("multi_msg");

    // 1. Register Bob and give him TWO devices
    let bob = app.register_user_with_keys(&username, 111, 5).await;
    let bob_device2 = app.link_device(&bob).await;
    let device2_token = bob_device2.token;
    let device2_id = bob_device2.device_id;

    // 2. Register Alice (sender)
    let alice = app.register_user(&common::generate_username("alice_multi")).await;

    // 3. Connect WebSockets for Bob's two devices
    let mut ws1 = app.connect_ws(&bob.token).await;
    ws1.ensure_subscribed().await;

    let mut ws2 = app.connect_ws(&device2_token).await;
    ws2.ensure_subscribed().await;

    // 4. Alice sends a separately encrypted message to each of Bob's devices
    app.send_messages(&alice.token, &[(bob.device_id, b"For Device 1"), (device2_id, b"For Device 2")]).await;

    // 5. Each device receives exactly its own message
    let env1 = ws1.receive_envelope_timeout(Duration::from_secs(2)).await.expect("Device 1 should receive its message");
    assert_eq!(env1.message, b"For Device 1");
    let env2 = ws2.receive_envelope_timeout(Duration::from_secs(2)).await.expect("Device 2 should receive its message");
    assert_eq!(env2.message, b"For Device 2");

    assert!(ws1.receive_envelope_timeout(Duration::from_millis(500)).await.is_none());
    assert!(ws2.receive_envelope_timeout(Duration::from_millis(500)).await.is_none());
}
