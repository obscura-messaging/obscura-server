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
use futures::SinkExt;
use std::time::Duration;

#[tokio::test]
async fn test_multi_node_notification() {
    let config = common::get_test_config();
    let app_a = common::TestApp::spawn_with_workers(config.clone()).await;
    let app_b = common::TestApp::spawn_with_workers(config).await;

    let alice_name = common::generate_username("alice");
    let bob_name = common::generate_username("bob");

    let user_alice = app_a.register_user(&alice_name).await;
    let user_bob = app_b.register_user(&bob_name).await;

    let mut ws_bob = app_b.connect_ws(&user_bob.token).await;
    // Prove Node B is ready and has finished its initial poll
    ws_bob.ensure_subscribed().await;

    // MANDATORY PROOF: Verify the database is empty for Bob.
    // This ensures Bob cannot receive the message via the "initial connection poll".
    app_b.assert_message_count(user_bob.device_id, 0).await;

    let content = b"Cross-node message proved via PubSub".to_vec();
    app_a.send_message(&user_alice.token, user_bob.device_id, &content).await;

    // If Bob receives this now, it MUST be via the Redis notification path.
    let env = ws_bob.receive_envelope().await.expect("Bob did not receive message on Node B");
    assert_eq!(env.message, content);
}

#[tokio::test]
async fn test_multi_node_push_cancellation() {
    let config = common::get_test_config();
    let app_a = common::TestApp::spawn_with_config(config.clone()).await;
    let app_b = common::TestApp::spawn_with_config(config.clone()).await;

    let user = app_a.register_user(&common::generate_username("multi_cancel")).await;

    // 1. Manually schedule a push on the shared Redis queue
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let pubsub = obscura_server::adapters::redis::RedisClient::new(&app_a.config.pubsub, 1024, shutdown_rx.clone())
        .await
        .unwrap();

    let mut conn = pubsub.publisher();
    let run_at = time::OffsetDateTime::now_utc().unix_timestamp() + 30;
    let queue_key = config.notifications.push_queue_key.clone();

    redis::cmd("ZADD")
        .arg(&queue_key)
        .arg("NX")
        .arg(run_at as f64)
        .arg(user.device_id.to_string())
        .query_async::<i64>(&mut conn)
        .await
        .unwrap();

    // 2. Connect user to Node B
    let _ws = app_b.connect_ws(&user.token).await;

    // 3. Verify Node B cancelled the push scheduled by Node A
    let success = app_b
        .wait_until(
            || {
                let pubsub = pubsub.clone();
                let user_id = user.device_id;
                let queue_key = queue_key.clone();
                async move {
                    let mut conn = pubsub.publisher();
                    let score: Option<f64> = redis::cmd("ZSCORE")
                        .arg(&queue_key)
                        .arg(user_id.to_string())
                        .query_async(&mut conn)
                        .await
                        .unwrap();
                    score.is_none()
                }
            },
            Duration::from_secs(5),
        )
        .await;

    assert!(success, "Node B failed to cancel push scheduled by Node A");

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_multi_node_disconnect_notification() {
    let config = common::get_test_config();
    let app_a = common::TestApp::spawn_with_workers(config.clone()).await;
    let app_b = common::TestApp::spawn_with_workers(config).await;

    let alice = app_a.register_user(&common::generate_username("alice_unlink")).await;
    let linked = app_a.link_device(&alice).await;

    let mut ws_a = app_a.connect_ws(&linked.token).await;
    ws_a.ensure_subscribed().await;

    let resp = app_b
        .client
        .delete(format!("{}/v1/devices/{}", app_b.server_url, linked.device_id))
        .header("Authorization", format!("Bearer {}", alice.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "Unlink failed: {}", resp.text().await.unwrap());

    ws_a.assert_closed().await;
}

#[tokio::test]
async fn test_distributed_fan_out_disconnect() {
    let config = common::get_test_config();
    let app_a = common::TestApp::spawn_with_workers(config.clone()).await;
    let app_b = common::TestApp::spawn_with_workers(config.clone()).await;
    let app_c = common::TestApp::spawn_with_workers(config).await;

    let alice = app_a.register_user(&common::generate_username("alice_fanout")).await;
    let linked = app_a.link_device(&alice).await;
    let bob = app_a.register_user(&common::generate_username("bob_fanout")).await;

    let mut ws_a1 = app_a.connect_ws(&linked.token).await;
    let mut ws_b1 = app_b.connect_ws(&linked.token).await;
    let mut ws_b2 = app_b.connect_ws(&linked.token).await;
    let mut ws_bob = app_a.connect_ws(&bob.token).await;

    // Synchronize: Ensure all sessions are fully established and subscribed to Redis
    ws_a1.ensure_subscribed().await;
    ws_b1.ensure_subscribed().await;
    ws_b2.ensure_subscribed().await;
    ws_bob.ensure_subscribed().await;

    let resp = app_c
        .client
        .delete(format!("{}/v1/devices/{}", app_c.server_url, linked.device_id))
        .header("Authorization", format!("Bearer {}", linked.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    ws_a1.assert_closed().await;
    ws_b1.assert_closed().await;
    ws_b2.assert_closed().await;

    ws_bob.sink.send(tokio_tungstenite::tungstenite::Message::Ping(vec![1].into())).await.unwrap();
    let pong = ws_bob.receive_pong().await;
    assert!(pong.is_some(), "Bob should have stayed connected");
}

#[tokio::test]
async fn test_multi_node_provisioning_relay() {
    let config = common::get_test_config();
    let app_a = common::TestApp::spawn_with_config(config.clone()).await;
    let app_b = common::TestApp::spawn_with_config(config).await;

    let primary = app_a.register_user(&common::generate_username("relay_nodes")).await;
    let new_device_token = app_a.login_user_scoped(&primary.username).await;

    let resp = app_a
        .client
        .post(format!("{}/v1/provisioning", app_a.server_url))
        .header("Authorization", format!("Bearer {new_device_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let address = resp.json::<serde_json::Value>().await.unwrap()["address"].as_str().unwrap().to_string();

    let waiter = {
        let (client, url) = (app_a.client.clone(), format!("{}/v1/provisioning/{address}?wait=10", app_a.server_url));
        tokio::spawn(async move {
            let resp =
                client.get(url).header("Authorization", format!("Bearer {new_device_token}")).send().await.unwrap();
            (resp.status(), resp.bytes().await.unwrap().to_vec())
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resp = app_b
        .client
        .put(format!("{}/v1/provisioning/{address}", app_b.server_url))
        .header("Authorization", format!("Bearer {}", primary.token))
        .body(b"cross-node".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let (status, body) = tokio::time::timeout(Duration::from_secs(5), waiter).await.unwrap().unwrap();
    assert_eq!(status, 200);
    assert_eq!(body, b"cross-node");
}
