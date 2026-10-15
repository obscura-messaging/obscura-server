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
use reqwest::StatusCode;
use tokio_tungstenite::tungstenite;

mod common;

#[tokio::test]
async fn test_generate_websocket_ticket() {
    let app = common::TestApp::spawn().await;
    let username = common::generate_username("ticket_user");

    // 1. Register a user to get an auth token
    let user = app.register_user(&username).await;

    // 2. Request a WebSocket ticket
    let resp = app
        .client
        .post(format!("{}/v1/gateway/ticket", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED, "Failed to create ticket");

    let body: serde_json::Value = resp.json().await.unwrap();

    assert!(body.get("ticket").is_some(), "Response missing ticket field");
    let ticket = body["ticket"].as_str().unwrap();
    assert!(!ticket.is_empty(), "Ticket should not be empty");

    let cache = obscura_server::adapters::redis::RedisCache::new(
        std::sync::Arc::clone(&app.resources.pubsub),
        "ws:ticket:".to_string(),
        30,
    );

    // 3. Verify the ticket was saved in Redis
    let redis_ticket = cache.get(ticket).await.expect("Failed to query Redis").expect("Ticket not found in Redis");

    let cached_device_id = String::from_utf8(redis_ticket).expect("Invalid UTF-8 in cached device ID");
    assert_eq!(cached_device_id, user.device_id.to_string(), "Cached device ID does not match");
}

#[tokio::test]
async fn test_generate_websocket_ticket_unauthenticated() {
    let app = common::TestApp::spawn().await;

    // Request a WebSocket ticket without an auth header
    let resp = app.client.post(format!("{}/v1/gateway/ticket", app.server_url)).send().await.unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Expected unauthorized response");
}

// --- Gateway WebSocket ticket error path tests ---

/// Covers the `Ok(None)` branch in `websocket_handler` (ticket not found / expired).
#[tokio::test]
async fn test_websocket_with_nonexistent_ticket() {
    let app = common::TestApp::spawn().await;

    let url = format!("{}?ticket=nonexistent-ticket-value", app.ws_url);
    let result = tokio_tungstenite::connect_async(url).await;

    match result {
        Err(tungstenite::Error::Http(resp)) => {
            assert_eq!(resp.status(), 401, "Expected UNAUTHORIZED for missing ticket");
        }
        Err(e) => panic!("Expected HTTP 401 error, got: {e:?}"),
        Ok(_) => panic!("Expected connection failure for nonexistent ticket"),
    }
}

/// Covers the `Err("Invalid device ID format in cache")` branch in `websocket_handler`.
#[tokio::test]
async fn test_websocket_with_invalid_device_id_in_cache() {
    let app = common::TestApp::spawn().await;

    // Write a non-UUID string directly into the ticket cache
    let cache = obscura_server::adapters::redis::RedisCache::new(
        std::sync::Arc::clone(&app.resources.pubsub),
        "ws:ticket:".to_string(),
        30,
    );
    let ticket = "test-corrupt-ticket";
    cache.set(ticket, b"not-a-valid-uuid").await.expect("Failed to seed cache");

    let url = format!("{}?ticket={}", app.ws_url, ticket);
    let result = tokio_tungstenite::connect_async(url).await;

    match result {
        Err(tungstenite::Error::Http(resp)) => {
            assert_eq!(resp.status(), 401, "Expected UNAUTHORIZED for corrupt device ID");
        }
        Err(e) => panic!("Expected HTTP 401 error, got: {e:?}"),
        Ok(_) => panic!("Expected connection failure for invalid device ID in cache"),
    }
}

/// Covers the `Err("Invalid UTF-8 in cache")` branch in `websocket_handler`.
#[tokio::test]
async fn test_websocket_with_invalid_utf8_in_cache() {
    let app = common::TestApp::spawn().await;

    // Write invalid UTF-8 bytes directly into the ticket cache
    let cache = obscura_server::adapters::redis::RedisCache::new(
        std::sync::Arc::clone(&app.resources.pubsub),
        "ws:ticket:".to_string(),
        30,
    );
    let ticket = "test-invalid-utf8-ticket";
    cache.set(ticket, &[0xFF, 0xFE, 0x80, 0x81]).await.expect("Failed to seed cache");

    let url = format!("{}?ticket={}", app.ws_url, ticket);
    let result = tokio_tungstenite::connect_async(url).await;

    match result {
        Err(tungstenite::Error::Http(resp)) => {
            assert_eq!(resp.status(), 401, "Expected UNAUTHORIZED for invalid UTF-8");
        }
        Err(e) => panic!("Expected HTTP 401 error, got: {e:?}"),
        Ok(_) => panic!("Expected connection failure for invalid UTF-8 in cache"),
    }
}

async fn issue_ticket(app: &common::TestApp, token: &str) -> String {
    let resp = app
        .client
        .post(format!("{}/v1/gateway/ticket", app.server_url))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    resp.json::<serde_json::Value>().await.unwrap()["ticket"].as_str().unwrap().to_string()
}

async fn connect_status(app: &common::TestApp, ticket: &str) -> u16 {
    match tokio_tungstenite::connect_async(format!("{}?ticket={ticket}", app.ws_url)).await {
        Ok((_, resp)) => resp.status().as_u16(),
        Err(tungstenite::Error::Http(resp)) => resp.status().as_u16(),
        Err(e) => panic!("Unexpected WebSocket error: {e:?}"),
    }
}

#[tokio::test]
async fn test_ticket_is_redeemed_once_under_concurrency() {
    let app = common::TestApp::spawn().await;
    let user = app.register_user(&common::generate_username("ticket_race")).await;
    let ticket = issue_ticket(&app, &user.token).await;

    let attempts = (0..16).map(|_| async {
        match tokio_tungstenite::connect_async(format!("{}?ticket={ticket}", app.ws_url)).await {
            Ok((ws, _)) => Ok(ws),
            Err(tungstenite::Error::Http(resp)) => Err(resp.status().as_u16()),
            Err(e) => panic!("Unexpected WebSocket error: {e:?}"),
        }
    });
    let results = futures::future::join_all(attempts).await;

    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1, "Exactly one redemption may succeed");
    assert!(results.iter().filter_map(|r| r.as_ref().err()).all(|status| *status == 401));
    assert_eq!(connect_status(&app, &ticket).await, 401);
}

#[tokio::test]
async fn test_ticket_of_deleted_device_is_refused() {
    let app = common::TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ticket_deleted")).await;
    let linked = app.link_device(&primary).await;
    let ticket = issue_ticket(&app, &linked.token).await;

    let resp = app
        .client
        .delete(format!("{}/v1/devices/{}", app.server_url, linked.device_id))
        .header("Authorization", format!("Bearer {}", primary.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(connect_status(&app, &ticket).await, 401);
}
