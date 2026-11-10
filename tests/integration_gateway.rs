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

use common::TestApp;
use futures::StreamExt;
use std::time::Duration;
use tokio_tungstenite::tungstenite::protocol::Message;

#[tokio::test]
async fn test_server_sends_ping() {
    let mut config = common::get_test_config();
    config.websocket.ping_interval_secs = std::num::NonZeroU64::new(1).unwrap(); // 1 second for fast testing
    config.websocket.ping_timeout_secs = 1;

    let app = TestApp::spawn_with_config(config).await;
    let user = app.register_user(&common::generate_username("ping_test")).await;

    let mut client = app.connect_ws(&user.token).await;

    // Wait for a Ping from the server
    let mut received_ping = false;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if let Some(Ok(msg)) = client.receive_raw_timeout(Duration::from_millis(500)).await
            && matches!(msg, Message::Ping(_))
        {
            received_ping = true;
            break;
        }
    }

    assert!(received_ping, "Server did not send a Ping within the expected interval");
}

#[tokio::test]
async fn test_heartbeat_timeout_closes_connection() {
    let mut config = common::get_test_config();
    config.websocket.ping_interval_secs = std::num::NonZeroU64::new(1).unwrap();
    config.websocket.ping_timeout_secs = 1;

    let app = TestApp::spawn_with_config(config).await;
    let user = app.register_user(&common::generate_username("timeout_test")).await;

    // Fetch a ticket for the user
    let ticket_resp = app
        .client
        .post(format!("{}/v1/gateway/ticket", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .expect("Failed to request ticket");

    let body: serde_json::Value = ticket_resp.json().await.unwrap();
    let ticket = body["ticket"].as_str().unwrap();

    // Connect manually so we can control Pong behavior (or just not read from it)
    let url = format!("{}?ticket={}", app.ws_url, ticket);
    let (ws_stream, _) = tokio_tungstenite::connect_async(url).await.expect("Failed to connect");

    let (_sink, mut stream) = ws_stream.split();

    // Now we STOP polling. tungstenite won't send automatic pongs.
    // The server should send a Ping at 1s, and when no Pong (or other activity)
    // arrives by 2s (interval + timeout), it should close the connection.

    // Let's wait 4 seconds to be sure.
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Now try to read from the stream. It should yield any buffered Pings and then close.
    let mut closed = false;
    let mut messages = Vec::new();

    // We expect at least one Ping and then a Close (or None)
    while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(500), stream.next()).await {
        match msg {
            Ok(Message::Close(_)) | Err(_) => {
                closed = true;
                break;
            }
            Ok(m) => messages.push(m),
        }
    }

    // If timeout reached and not closed, check if next is None
    if !closed {
        // stream.next() might return None immediately if closed
        if stream.next().await.is_none() {
            closed = true;
        }
    }

    assert!(closed, "Connection was not closed after timeout. Received: {messages:?}");
    println!("Successfully verified connection closure. Buffered messages: {messages:?}");
}
