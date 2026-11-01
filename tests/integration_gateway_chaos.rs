use futures::SinkExt;
use std::time::Duration;
use tokio::time::Instant;

mod common;

#[tokio::test]
async fn test_concurrent_messages_and_prekeys_no_drops() {
    // This test hammers the WebSocket with concurrent MessageReceived and PreKeyLow events.
    // If try_recv() is incorrectly draining channels, some events will be dropped,
    // and the client won't receive all 50 messages or won't receive the disconnect.
    let app = common::TestApp::spawn_with_workers(common::get_test_config()).await;

    // Alice has 100 keys (threshold is 20, but we just want to fetch them to trigger PreKeyLow)
    // Actually, PreKeyLow is only triggered if count < threshold.
    // So we give Alice 21 keys, and fetch 100 times. Every fetch below 20 triggers PreKeyLow!
    let alice = app.register_user_with_keys(&common::generate_username("alice_hammer"), 123, 21).await;
    let bob = app.register_user(&common::generate_username("bob_hammer")).await;

    let mut alice_ws = app.connect_ws(&alice.token).await;
    alice_ws.ensure_subscribed().await;

    let _ = alice_ws.receive_prekey_status_timeout(Duration::from_secs(1)).await;

    // Send 50 messages and fetch 50 keys concurrently using join!
    // We just interleave sending messages and fetching keys to trigger both
    // MessageReceived and PreKeyLow events rapidly.

    let token = bob.token.clone();
    let alice_id = alice.device_id;

    for i in 0..50 {
        app.send_message(&token, alice_id, format!("msg {i}").as_bytes()).await;
        app.client
            .get(format!("{}/v1/keys/{}", app.server_url, alice.user_id))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .expect("Failed to fetch pre-key bundle");
    }

    // Now Alice must receive exactly 50 messages.
    // If the bug exists, some MessageReceived notifications will be swallowed by `try_recv`,
    // and since the message pump only runs on notification, it will stall and not fetch all 50.
    let mut received_messages = 0;

    // We give it a generous timeout to process everything.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if alice_ws.receive_envelope_timeout(Duration::from_millis(100)).await.is_some() {
            received_messages += 1;
        }

        // Also drain statuses so the channel doesn't block
        let _ = alice_ws.receive_prekey_status_timeout(Duration::from_millis(10)).await;

        if received_messages == 50 {
            break;
        }
    }

    // Since we sent 50 messages, the client MUST receive 50 messages.
    // If it's less than 50, the `try_recv` swallowed some notifications.
    assert_eq!(
        received_messages, 50,
        "Expected 50 messages, but only received {received_messages}. Some notifications were dropped!"
    );
}

#[tokio::test]
async fn test_ack_batcher_does_not_drop_on_disconnect() {
    let mut config = common::get_test_config();
    config.websocket.ack_batch_size = 10;
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

    // Wait a tiny bit just for the WebSocket to route the message to the batcher
    tokio::time::sleep(Duration::from_millis(100)).await;

    // VIOLENTLY DISCONNECT ALICE
    let _ = alice_ws.sink.close().await;
    drop(alice_ws);

    // Give the server a moment to process the disconnect and drop the session channel,
    // which should trigger the AckBatcher's `None` arm and force a flush.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Reconnect Alice. If the batcher dropped the state on disconnect,
    // the messages will still be in the database and she will receive them again.
    let mut new_alice_ws = app.connect_ws(&alice.token).await;
    new_alice_ws.ensure_subscribed().await;

    // Expect NO messages, as they should have been deleted.
    let env = new_alice_ws.receive_envelope_timeout(Duration::from_secs(2)).await;

    assert!(
        env.is_none(),
        "Alice received messages after reconnecting! The AckBatcher dropped the state on disconnect."
    );
}
