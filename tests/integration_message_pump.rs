#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::todo,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    missing_debug_implementations,
    clippy::clone_on_ref_ptr,
    clippy::items_after_statements,
    unreachable_pub,
    clippy::print_stdout,
    clippy::similar_names
)]
//! Regression tests for `MessagePump` losing a delivery notification on a transient read failure.
//!
//! The pump is edge-triggered: `notify()` fires, it fetches, it sends. If the fetch errors, the
//! notification that woke it is already consumed, so nothing retries and the envelope waits for an
//! unrelated future event. A database blip therefore strands a message for the life of the
//! connection.
//!
//! The failure is injected by sizing the app's connection pool to one and holding that connection,
//! which makes `pool.acquire()` inside `fetch_pending_batch` time out. That is a real production
//! shape (pool saturation under load), and unlike killing Postgres it leaves the rest of the
//! system — Redis, the WebSocket, the sender — working, so the test isolates the pump.

mod common;

use common::TestApp;
use obscura_server::config::Config;
use obscura_server::domain::notification::DeviceEvent;
use std::time::Duration;
use uuid::Uuid;

/// One connection, and a short acquire timeout so starvation fails fast.
fn starvable_config() -> Config {
    let mut config = common::get_test_config();
    config.database.max_connections = 1;
    config.database.min_connections = 1;
    config.database.acquire_timeout_secs = 1;
    config
}

/// A message that arrives while the pump cannot read the database must still be delivered once the
/// database recovers, without the client reconnecting.
#[tokio::test]
async fn message_survives_a_transient_fetch_failure() {
    let config = starvable_config();
    let app = TestApp::spawn_with_workers(config.clone()).await;

    let alice = app.register_user(&common::generate_username("alice_pump")).await;
    let bob = app.register_user(&common::generate_username("bob_pump")).await;

    let mut alice_ws = app.connect_ws(&alice.token).await;
    alice_ws.ensure_subscribed().await;

    // Baseline: delivery works over this socket.
    app.send_message(&bob.token, alice.device_id, b"before").await;
    assert!(alice_ws.receive_envelope_timeout(Duration::from_secs(5)).await.is_some(), "baseline delivery failed");

    // Starve the pool: the app now has no connection to read with. Held across the send below, so
    // the fetch that the send's notification triggers is guaranteed to fail.
    let starve = app.pool.acquire().await.expect("hold the only connection");

    // The insert itself needs a connection, so it goes through a pool of our own. Kept to a single
    // connection: every test binary shares one Postgres, and the default pool reserves twenty.
    let side_pool = common::get_test_pool_with(&obscura_server::config::DatabaseConfig {
        url: config.database.url.clone(),
        max_connections: 1,
        min_connections: 1,
        ..Default::default()
    })
    .await;
    let message_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO messages (id, device_id, sender_id, sender_device_id, submission_id, content, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '1 day')",
    )
    .bind(message_id)
    .bind(alice.device_id)
    .bind(bob.user_id)
    .bind(bob.device_id)
    .bind(Uuid::new_v4())
    .bind(b"after".to_vec())
    .execute(&side_pool)
    .await
    .expect("insert message");

    // Wake the pump while it cannot read. Its fetch times out acquiring a connection, and the
    // notification that woke it is consumed.
    app.notifier.notify(&[alice.device_id], DeviceEvent::MessageReceived).await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Database is healthy again. Alice has NOT reconnected, and nothing else will notify the pump.
    drop(starve);

    let delivered = alice_ws.receive_envelope_timeout(Duration::from_secs(10)).await;
    assert!(delivered.is_some(), "message stranded: the pump swallowed its notification on a failed fetch");
}
