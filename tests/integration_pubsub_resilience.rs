#![allow(
    // For helper functions: clippy.toml allows unwrap only inside #[test] functions.
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
//! Regression tests for the pubsub listener surviving a Valkey outage.
//!
//! These use a TCP proxy rather than `CLIENT KILL` deliberately. Severing established connections
//! is not enough: with Valkey up the reconnect succeeds on the first attempt, so a `CLIENT KILL`
//! test passes against the broken listener. Reproducing the bug requires *connect* to keep failing,
//! which unbinding the proxy port provides.

mod common;

use common::TestApp;
use obscura_server::adapters::redis::RedisClient;

use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use uuid::Uuid;

/// Longer than the old bounded budget (1s + 2s + capped), short enough to keep the test quick.
const OUTAGE: Duration = Duration::from_secs(12);

/// A TCP proxy in front of Valkey that the test can unbind and rebind. Unbinding produces
/// `ECONNREFUSED` on connect; closing established connections alone does not.
struct RedisProxy {
    port: u16,
    upstream: String,
    accept_task: Option<tokio::task::JoinHandle<()>>,
}

impl RedisProxy {
    async fn start(upstream: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
        let port = listener.local_addr().unwrap().port();

        let mut proxy = Self { port, upstream: upstream.to_string(), accept_task: None };
        proxy.serve(listener);
        proxy
    }

    fn url(&self) -> String {
        format!("redis://127.0.0.1:{}", self.port)
    }

    fn serve(&mut self, listener: TcpListener) {
        let upstream = self.upstream.clone();

        self.accept_task = Some(tokio::spawn(async move {
            // Connections live in a set owned by this task, so aborting it drops the set and takes
            // every forwarded connection down with it.
            let mut conns = tokio::task::JoinSet::new();
            while let Ok((mut inbound, _)) = listener.accept().await {
                let upstream = upstream.clone();
                conns.spawn(async move {
                    if let Ok(mut outbound) = TcpStream::connect(&upstream).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        }));
    }

    /// Take Valkey away: unbind the port and drop every live connection.
    async fn cut(&mut self) {
        if let Some(task) = self.accept_task.take() {
            task.abort();
            let _ = task.await;
        }
        // Give the OS a moment to release the port so connects are refused rather than queued.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    /// Bring Valkey back on the same port.
    async fn restore(&mut self) {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.port)).await.expect("rebind proxy");
        self.serve(listener);
    }
}

fn upstream_from(url: &str) -> String {
    url.trim_start_matches("redis://").trim_end_matches('/').to_string()
}

/// Fast backoff so a recovered listener reconnects promptly inside the test's patience.
const fn fast_pubsub_config(url: String) -> obscura_server::config::PubSubConfig {
    obscura_server::config::PubSubConfig { url, min_backoff_secs: 1, max_backoff_secs: 2, stable_after_secs: 1 }
}

/// The regression test: the listener must survive an outage longer than the old bounded retry
/// budget. Against the pre-fix listener it exits, removes its pattern, and never delivers again.
#[tokio::test]
async fn pubsub_listener_survives_outage_longer_than_the_retry_budget() {
    let base = common::get_test_config();
    let mut proxy = RedisProxy::start(&upstream_from(&base.pubsub.url)).await;

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let config = fast_pubsub_config(proxy.url());
    let client =
        RedisClient::new(&config, std::num::NonZeroUsize::new(128).unwrap(), shutdown_rx).await.expect("redis client");

    let pattern = format!("outage-test:{}:*", Uuid::new_v4());
    let channel = pattern.replace('*', "device");
    let mut rx = client.subscribe(&pattern).expect("subscribe");

    publish_until_received(&client, &channel, &mut rx, b"before").await.expect("baseline delivery");

    proxy.cut().await;
    tokio::time::sleep(OUTAGE).await;
    proxy.restore().await;

    publish_until_received(&client, &channel, &mut rx, b"after")
        .await
        .expect("listener should have kept retrying and resumed delivery after the outage");
}

/// Stream loss with Valkey still healthy. Note this does not discriminate fixed from broken — with
/// Valkey up, reconnect succeeds first try. It guards the stream-loss path, nothing more.
#[tokio::test]
async fn pubsub_listener_recovers_from_connection_loss() {
    let base = common::get_test_config();
    let mut proxy = RedisProxy::start(&upstream_from(&base.pubsub.url)).await;

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let config = fast_pubsub_config(proxy.url());
    let client =
        RedisClient::new(&config, std::num::NonZeroUsize::new(128).unwrap(), shutdown_rx).await.expect("redis client");

    let pattern = format!("cut-test:{}:*", Uuid::new_v4());
    let channel = pattern.replace('*', "device");
    let mut rx = client.subscribe(&pattern).expect("subscribe");

    publish_until_received(&client, &channel, &mut rx, b"before").await.expect("baseline");

    // Momentary blip: connections die, but the port comes straight back.
    proxy.cut().await;
    proxy.restore().await;

    publish_until_received(&client, &channel, &mut rx, b"after").await.expect("should recover from a blip");
}

/// Publishes repeatedly until the payload arrives or the deadline passes. Redis pubsub is
/// at-most-once, so anything published while the listener is between connections is simply gone.
async fn publish_until_received(
    client: &RedisClient,
    channel: &str,
    rx: &mut tokio::sync::broadcast::Receiver<obscura_server::adapters::redis::PubSubMessage>,
    payload: &[u8],
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

    while tokio::time::Instant::now() < deadline {
        let mut conn = client.publisher();
        let _: Result<i64, _> = redis::cmd("PUBLISH").arg(channel).arg(payload).query_async(&mut conn).await;

        match tokio::time::timeout(Duration::from_millis(250), rx.recv()).await {
            Ok(Ok(msg)) if msg.payload == payload => return Ok(()),
            // A stale or lagged read is not a failure; keep waiting for the payload we want.
            Ok(_) | Err(_) => {}
        }
    }

    Err(format!("payload {payload:?} never arrived on {channel}"))
}

/// End-to-end: Alice holds one WebSocket across the outage and never reconnects, so delivery can
/// only resume because the listener recovered.
#[tokio::test]
async fn websocket_delivery_resumes_after_pubsub_outage() {
    let mut config = common::get_test_config();
    let mut proxy = RedisProxy::start(&upstream_from(&config.pubsub.url)).await;
    config.pubsub = fast_pubsub_config(proxy.url());

    let app = TestApp::spawn_with_workers(config).await;

    let alice = app.register_user(&common::generate_username("alice_pubsub")).await;
    let bob = app.register_user(&common::generate_username("bob_pubsub")).await;

    let mut alice_ws = app.connect_ws(&alice.token).await;
    alice_ws.ensure_subscribed().await;

    app.send_message(&bob.token, alice.device_id, b"before outage").await;
    assert!(
        alice_ws.receive_envelope_timeout(Duration::from_secs(5)).await.is_some(),
        "baseline delivery over the live socket failed"
    );

    proxy.cut().await;
    tokio::time::sleep(OUTAGE).await;
    proxy.restore().await;

    // Alice has NOT reconnected. Delivery has to resume purely because the listener recovered.
    // Sends are retried because one landing mid-reconnect loses its notification for good.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut delivered = false;
    while tokio::time::Instant::now() < deadline {
        app.send_message(&bob.token, alice.device_id, b"after outage").await;
        if alice_ws.receive_envelope_timeout(Duration::from_millis(500)).await.is_some() {
            delivered = true;
            break;
        }
    }

    assert!(delivered, "realtime delivery never resumed after the pubsub outage");
}
