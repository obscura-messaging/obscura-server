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
use obscura_server::adapters::database::message_repo::MessageRepository;
use reqwest::StatusCode;

mod common;

#[tokio::test]
async fn test_message_limit_fifo() {
    let app = common::TestApp::spawn().await;

    let user_a = app.register_user(&common::generate_username("alice")).await;
    let user_b = app.register_user(&common::generate_username("bob")).await;
    let user_c = app.register_user(&common::generate_username("carol")).await;

    // Flood Bob's inbox past the limit.
    for i in 0..1005 {
        let payload = format!("msg_{i}").into_bytes();
        app.send_message(&user_a.token, user_b.device_id, &payload).await;
    }
    // Carol's messages are the newest in the table. Pruning that ignored devices and kept the newest 1000
    // messages overall would keep these and drop 8 of Bob's instead of 5.
    for i in 0..3 {
        app.send_message(&user_a.token, user_c.device_id, format!("carol_{i}").as_bytes()).await;
    }

    // Pruning is per device, so other tests' messages in the shared table do not affect these counts.
    let repo = MessageRepository::new();
    let mut conn = app.pool.acquire().await.unwrap();
    repo.delete_global_overflow(&mut conn, 1000).await.expect("Failed to run cleanup");

    let count = |device_id| {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM messages WHERE device_id = $1")
            .bind(device_id)
            .fetch_one(&app.pool)
    };
    assert_eq!(count(user_b.device_id).await.unwrap(), 1000, "Bob's inbox should be capped at the limit");
    assert_eq!(count(user_c.device_id).await.unwrap(), 3, "Carol's inbox is under the limit and untouched");

    // The oldest messages are the ones dropped.
    let mut ws = app.connect_ws(&user_b.token).await;
    let env = ws.receive_envelope().await.expect("No messages received");
    assert_eq!(env.message, b"msg_5", "First message should be msg_5 (0-4 should have been pruned)");
}

#[tokio::test]
async fn test_rate_limiting() {
    // 1. Setup with strict limits (1 req/s)
    let mut config = common::get_test_config();
    config.rate_limit.per_second = std::num::NonZeroU32::new(1).unwrap();
    config.rate_limit.burst = std::num::NonZeroU32::new(1).unwrap();

    let app = common::TestApp::spawn_with_config(config).await;

    // 2. First request (OK - or 401/404 but not 429)
    // We use a random token to avoid auth processing cost affecting timing too much,
    // but rate limiting happens before auth in the middleware chain.
    let resp1 = app
        .client
        .get(format!("{}/v1/gateway?token=bad", app.server_url)) // HTTP request to upgrade endpoint
        .send()
        .await
        .unwrap();

    assert_ne!(resp1.status(), StatusCode::TOO_MANY_REQUESTS);

    // 3. Second request immediately (Should be 429)
    let resp2 = app.client.get(format!("{}/v1/gateway?token=bad", app.server_url)).send().await.unwrap();

    assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);
}
