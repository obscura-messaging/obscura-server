use reqwest::StatusCode;
use std::time::Duration;

mod common;

#[tokio::test]
async fn test_prekey_signaling_realtime() {
    let app = common::TestApp::spawn_with_workers(common::get_test_config()).await;

    // 1. Register Bob with exactly 21 OTPKs (threshold is 20)
    let bob = app.register_user_with_keys(&common::generate_username("bob_rt"), 123, 21).await;

    // 2. Bob connects to Gateway
    let mut bob_ws = app.connect_ws(&bob.token).await;
    bob_ws.ensure_subscribed().await;

    // Clear the initial "on-connect" PreKeyStatus frame
    let _ = bob_ws.receive_prekey_status_timeout(Duration::from_secs(1)).await;

    // 3. Alice fetches Bob's pre-key bundle
    let alice = app.register_user(&common::generate_username("alice_rt")).await;
    let resp = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, bob.user_id))
        .header("Authorization", format!("Bearer {}", alice.token))
        .send()
        .await
        .expect("Failed to fetch pre-key bundle");
    assert_eq!(resp.status(), StatusCode::OK);

    // 4. Alice fetches Bob's bundle AGAIN.
    // Now count becomes 19. This should trigger the notification.
    let resp = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, bob.user_id))
        .header("Authorization", format!("Bearer {}", alice.token))
        .send()
        .await
        .expect("Failed to fetch pre-key bundle second time");
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. Check Bob's WS for PreKeyStatus
    // We use a loop to ensure we get the count of 19 (might be preceded by a count of 20 if timing is tight)
    let mut last_count = 21;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        if let Some(status) = bob_ws.receive_prekey_status_timeout(Duration::from_millis(500)).await {
            last_count = status.one_time_pre_key_count;
            if last_count == 19 {
                break;
            }
        }
    }

    assert_eq!(last_count, 19, "Bob should have received a PreKeyStatus frame with count 19");
}

#[tokio::test]
async fn test_prekey_signaling_exhausted() {
    let app = common::TestApp::spawn_with_workers(common::get_test_config()).await;

    // 1. Register Bob with 0 OTPKs
    let bob = app.register_user_with_keys(&common::generate_username("bob_exh"), 123, 0).await;

    // 2. Bob connects
    let mut bob_ws = app.connect_ws(&bob.token).await;
    bob_ws.ensure_subscribed().await;

    // Clear initial frame (count 0)
    let status = bob_ws.receive_prekey_status_timeout(Duration::from_secs(1)).await;
    assert!(status.is_some());

    let alice = app.register_user(&common::generate_username("alice_exh")).await;

    // 3. Alice fetches Bob's bundle (already 0)
    let resp = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, bob.user_id))
        .header("Authorization", format!("Bearer {}", alice.token))
        .send()
        .await
        .expect("Failed to fetch pre-key bundle");
    assert_eq!(resp.status(), StatusCode::OK);

    // 4. Bob should receive ANOTHER PreKeyStatus frame with count 0
    let status = bob_ws.receive_prekey_status_timeout(Duration::from_secs(2)).await;
    assert!(status.is_some(), "Bob should have received a notification even though keys were already at 0");
    assert_eq!(status.expect("Status should be present").one_time_pre_key_count, 0);
}

#[tokio::test]
async fn test_prekey_signaling_push() {
    let mut config = common::get_test_config();
    // Set a very low push delay for testing
    config.notifications.push_delay_secs = 0;
    let app = common::TestApp::spawn_with_workers(config).await;

    // 1. Register Bob with 21 keys, but NO WebSocket connection
    let bob = app.register_user_with_keys(&common::generate_username("bob_offline"), 123, 21).await;

    // Set a mock push token so Bob is eligible for pushes
    app.client
        .put(format!("{}/v1/push-tokens", app.server_url))
        .header("Authorization", format!("Bearer {}", bob.token))
        .json(&serde_json::json!({"token": format!("token:{}", bob.user_id)}))
        .send()
        .await
        .expect("Failed to set push token");

    let alice = app.register_user(&common::generate_username("alice_push")).await;

    // 2. Consume 2 keys to trigger the PreKeyLow event (21 -> 20 -> 19)
    for _ in 0..2 {
        app.client
            .get(format!("{}/v1/users/{}", app.server_url, bob.user_id))
            .header("Authorization", format!("Bearer {}", alice.token))
            .send()
            .await
            .expect("Failed to fetch pre-key bundle");
    }

    // 3. Wait for the push worker to process the job.
    // Since push_delay is 0, it should happen almost immediately.
    let success = app
        .wait_until(
            || async { *common::notification_counts().get(&bob.user_id).as_deref().unwrap_or(&0) > 0 },
            Duration::from_secs(5),
        )
        .await;

    assert!(success, "Bob should have received a push notification for low keys");
}

#[tokio::test]
async fn test_prekey_coalescing() {
    const FETCHES: u32 = 20;
    let mut config = common::get_test_config();
    // The burst below must not queue on the pool: this test is about debouncing, not pool capacity.
    config.database.max_connections = FETCHES * 2;
    let app = common::TestApp::spawn_with_workers(config).await;

    // 1. Bob with 25 keys
    let bob = app.register_user_with_keys(&common::generate_username("bob_co"), 123, 25).await;
    let mut bob_ws = app.connect_ws(&bob.token).await;
    bob_ws.ensure_subscribed().await;

    // Clear initial status frame
    let _ = bob_ws.receive_prekey_status_timeout(Duration::from_secs(1)).await;

    let alice = app.register_user(&common::generate_username("alice_co")).await;

    // 2. Alice fetches 20 keys CONCURRENTLY.
    // This will definitely dip Bob below the 20-key threshold multiple times.
    let mut handles = Vec::new();
    for _ in 0..FETCHES {
        let client = app.client.clone();
        let url = format!("{}/v1/users/{}", app.server_url, bob.user_id);
        let token = alice.token.clone();
        handles.push(tokio::spawn(async move {
            client
                .get(url)
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await
                .expect("Failed to fetch pre-key")
        }));
    }

    for h in handles {
        assert_eq!(h.await.unwrap().status(), StatusCode::OK, "every fetch must consume a key");
    }

    // Wait for the 500ms debounce window + some slack
    tokio::time::sleep(Duration::from_millis(800)).await;

    // 3. Bob should receive status frames.
    // Due to time-based debouncing, he should receive very few, and the last one
    // MUST reflect the final state.
    let mut last_count = 25;
    let mut frame_count = 0;

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if let Some(status) = bob_ws.receive_prekey_status_timeout(Duration::from_millis(500)).await {
            frame_count += 1;
            last_count = status.one_time_pre_key_count;
            if last_count == 5 {
                break;
            }
        }
    }

    assert!(frame_count > 0, "Bob should have received at least one notification");
    assert!(frame_count < 10, "Debouncing should have significantly reduced the number of frames");
    assert_eq!(last_count, 5, "Bob should eventually receive the final accurate count of 5");
}
