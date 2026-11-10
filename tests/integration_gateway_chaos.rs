use futures::SinkExt;
use std::time::Duration;
use tokio::time::Instant;

mod common;

#[tokio::test]
async fn test_message_burst_no_drops() {
    // This test hammers the WebSocket with MessageReceived events. If try_recv() is incorrectly draining
    // channels, some notifications will be dropped, the message pump will stall, and the client won't
    // receive all 50 messages.
    let app = common::TestApp::spawn_with_workers(common::get_test_config()).await;
    let alice = app.register_user(&common::generate_username("alice_hammer")).await;
    let bob = app.register_user(&common::generate_username("bob_hammer")).await;

    let mut alice_ws = app.connect_ws(&alice.token).await;
    alice_ws.ensure_subscribed().await;

    for i in 0..50 {
        app.send_message(&bob.token, alice.device_id, format!("msg {i}").as_bytes()).await;
    }

    let mut received_messages = 0;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) && received_messages < 50 {
        if alice_ws.receive_envelope_timeout(Duration::from_millis(100)).await.is_some() {
            received_messages += 1;
        }
    }

    assert_eq!(
        received_messages, 50,
        "Expected 50 messages, but only received {received_messages}. Some notifications were dropped!"
    );
}

#[tokio::test]
async fn test_ack_batcher_does_not_drop_on_disconnect() {
    let mut config = common::get_test_config();
    config.websocket.ack_batch_size = std::num::NonZeroUsize::new(10).unwrap();
    // Set a very long flush interval so it definitely won't naturally flush during the test
    config.websocket.ack_flush_interval_ms = 10_000;

    let app = common::TestApp::spawn_with_config(config).await;

    let alice = app.register_user(&common::generate_username("alice_disconnect")).await;
    let bob = app.register_user(&common::generate_username("bob_disconnect")).await;

    // Bob sends 5 messages to Alice
    for i in 0..5 {
        app.send_message(&bob.token, alice.device_id, format!("msg {i}").as_bytes()).await;
    }

    let mut alice_ws = app.connect_ws(&alice.token).await;
    alice_ws.ensure_subscribed().await;

    // Receive the 5 messages
    let mut message_ids = Vec::new();
    for _ in 0..5 {
        if let Some(env) = alice_ws.receive_envelope().await {
            message_ids.push(env.id);
        }
    }
    assert_eq!(message_ids.len(), 5);

    // Send 5 ACKs. Because batch_size is 10 and interval is 10s,
    // these should be sitting purely in the AckBatcher's memory.
    for id in &message_ids {
        alice_ws.send_ack(id.clone()).await;
    }

    // Disconnect Alice right after her ACKs. The server reads her ACK frames before the close that follows them.
    let _ = alice_ws.sink.close().await;
    drop(alice_ws);

    // The disconnect closes the batcher's channel, which should flush the pending ACKs. Nothing else
    // could delete these messages within the 10s flush interval.
    app.assert_message_count(alice.device_id, 0).await;
}
