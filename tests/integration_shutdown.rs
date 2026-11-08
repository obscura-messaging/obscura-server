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
use std::time::Duration;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

mod common;

#[tokio::test]
async fn test_graceful_websocket_shutdown() {
    let app = common::TestApp::spawn().await;
    let username = common::generate_username("shutdown_user");

    // 1. Register and connect WS
    let user = app.register_user(&username).await;
    let mut ws = app.connect_ws(&user.token).await;

    // 2. Trigger Shutdown
    let _ = app.shutdown_tx.send(true);

    // 3. Assert Close Frame received with GoingAway code
    let mut close_received = false;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if let Some(Ok(Message::Close(Some(cf)))) = ws.receive_raw_timeout(Duration::from_millis(100)).await {
            assert_eq!(cf.code, CloseCode::Away);
            assert_eq!(cf.reason, "Server shutting down");
            close_received = true;
            break;
        }
    }

    assert!(close_received, "Did not receive graceful close frame within timeout");
}
