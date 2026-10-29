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

use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::TestApp;
use reqwest::StatusCode;
use uuid::Uuid;

#[tokio::test]
async fn test_unauthenticated_access_denied() {
    let app = TestApp::spawn().await;
    let target_user_id = Uuid::new_v4();
    let target_resource_id = Uuid::new_v4();

    let endpoints = vec![
        ("GET", format!("{}/v1/users/{}", app.server_url, target_user_id)),
        ("POST", format!("{}/v1/devices/keys", app.server_url)),
        ("POST", format!("{}/v1/messages", app.server_url)),
        ("DELETE", format!("{}/v1/sessions", app.server_url)),
        ("POST", format!("{}/v1/attachments", app.server_url)),
        ("GET", format!("{}/v1/attachments/{}", app.server_url, target_resource_id)),
        ("GET", format!("{}/v1/backup", app.server_url)),
        ("HEAD", format!("{}/v1/backup", app.server_url)),
        ("POST", format!("{}/v1/backup", app.server_url)),
        ("PUT", format!("{}/v1/push-tokens", app.server_url)),
        ("POST", format!("{}/v1/gateway/ticket", app.server_url)),
        ("POST", format!("{}/v1/link-sessions", app.server_url)),
        ("PUT", format!("{}/v1/link-sessions/some-id", app.server_url)),
        ("GET", format!("{}/v1/link-sessions/some-id", app.server_url)),
    ];

    for (method, url) in endpoints {
        let resp = match method {
            "GET" => app.client.get(&url).send().await.unwrap(),
            "POST" => app.client.post(&url).send().await.unwrap(),
            "DELETE" => app.client.delete(&url).send().await.unwrap(),
            "PUT" => app.client.put(&url).send().await.unwrap(),
            "HEAD" => app.client.head(&url).send().await.unwrap(),
            _ => panic!("Unsupported method"),
        };

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Endpoint {method} {url} should require authentication");
    }
}

#[tokio::test]
async fn test_invalid_token_access_denied() {
    let app = TestApp::spawn().await;
    let target_user_id = Uuid::new_v4();

    let resp = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, target_user_id))
        .header("Authorization", "Bearer invalid-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_malformed_auth_header() {
    let app = TestApp::spawn().await;
    let target_user_id = Uuid::new_v4();

    let resp = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, target_user_id))
        .header("Authorization", "NotBearer some-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Verifies that all endpoints requiring a Device-Scoped JWT correctly return
/// 403 Forbidden when called with a valid User-Scoped JWT (missing `deviceId` claim).
/// This enforces RFC 6750 §3.1 `insufficient_scope` semantics.
#[tokio::test]
async fn test_user_scoped_token_rejected_on_device_endpoints() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("scope");

    // Register user and get a device-scoped token (we need the user to exist)
    let _user = app.register_user(&username).await;

    // Login WITHOUT a deviceId to obtain a User-Scoped JWT
    let login_resp = app
        .client
        .post(format!("{}/v1/sessions", app.server_url))
        .json(&serde_json::json!({
            "username": username,
            "password": "password12345"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(login_resp.status(), StatusCode::OK);
    let login_body: serde_json::Value = login_resp.json().await.unwrap();
    let user_token = login_body["token"].as_str().unwrap();
    assert!(
        login_body.get("deviceId").is_none() || login_body["deviceId"].is_null(),
        "Login without deviceId should return a user-scoped token"
    );

    let target_user_id = Uuid::new_v4();

    // All endpoints that require a Device-Scoped JWT
    let device_scoped_endpoints: Vec<(&str, String)> = vec![
        // Keys
        ("POST", format!("{}/v1/devices/keys", app.server_url)),
        ("GET", format!("{}/v1/users/{}", app.server_url, target_user_id)),
        ("GET", format!("{}/v1/users/{}/devices/{}", app.server_url, target_user_id, Uuid::new_v4())),
        // Messaging
        ("POST", format!("{}/v1/messages", app.server_url)),
        // Gateway
        ("POST", format!("{}/v1/gateway/ticket", app.server_url)),
        // Push tokens
        ("PUT", format!("{}/v1/push-tokens", app.server_url)),
        // Device management & linking
        ("PUT", format!("{}/v1/link-sessions/some-id", app.server_url)),
        ("GET", format!("{}/v1/devices/{}", app.server_url, Uuid::new_v4())),
        ("PUT", format!("{}/v1/devices/{}", app.server_url, Uuid::new_v4())),
        ("DELETE", format!("{}/v1/devices/{}", app.server_url, Uuid::new_v4())),
        // Attachments
        ("POST", format!("{}/v1/attachments", app.server_url)),
        ("GET", format!("{}/v1/attachments/{}", app.server_url, Uuid::new_v4())),
        // Backup (all three operations)
        ("POST", format!("{}/v1/backup", app.server_url)),
        ("GET", format!("{}/v1/backup", app.server_url)),
        ("HEAD", format!("{}/v1/backup", app.server_url)),
    ];

    for (method, url) in &device_scoped_endpoints {
        let mut req = match *method {
            "GET" => app.client.get(url),
            "POST" => app.client.post(url),
            "PUT" => app.client.put(url),
            "HEAD" => app.client.head(url),
            "DELETE" => app.client.delete(url),
            _ => panic!("Unsupported method"),
        };
        req = req.header("Authorization", format!("Bearer {user_token}"));

        // Provide valid-enough payloads so the scope check runs before body parse errors.
        // Axum's Json extractor runs BEFORE the handler body, so bodies must deserialize.
        if url.contains("/keys") && *method == "POST" {
            let key_body = serde_json::json!({
                "signedPreKey": {
                    "keyId": 1,
                    "publicKey": STANDARD.encode([0u8; 33]),
                    "signature": STANDARD.encode([0u8; 64])
                },
                "oneTimePreKeys": []
            });
            req = req.header("Content-Type", "application/json").body(key_body.to_string());
        } else if url.contains("/messages") {
            req = req
                .header("Idempotency-Key", Uuid::new_v4().to_string())
                .header("Content-Type", "application/x-protobuf")
                .body(vec![]);
        } else if url.contains("/push-tokens") {
            req = req.header("Content-Type", "application/json").body(r#"{"token":"test"}"#);
        } else if url.contains("/backup") && *method == "POST" {
            req = req.header("If-None-Match", "*").header("Content-Length", "64").body(vec![0u8; 64]);
        } else if url.contains("/attachments") && *method == "POST" {
            req = req.header("Content-Length", "4").body(vec![1u8; 4]);
        } else if url.contains("/devices/") && *method == "PUT" {
            req = req.header("Content-Type", "application/json").body(r#"{"name":"Phone"}"#);
        }

        let resp = req.send().await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "Endpoint {method} {url} should return 403 for user-scoped token, got {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn test_device_scoped_token_rejected_on_user_scoped_endpoints() {
    let app = TestApp::spawn().await;
    let user = app.register_user(&common::generate_username("user_scope")).await;
    let (device_payload, _) = common::generate_device_payload(1, 1);

    let resp = app
        .client
        .post(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&device_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    for (method, url) in [
        ("POST", format!("{}/v1/link-sessions", app.server_url)),
        ("GET", format!("{}/v1/link-sessions/some-id", app.server_url)),
    ] {
        let req = if method == "POST" { app.client.post(&url) } else { app.client.get(&url) };
        let resp = req.header("Authorization", format!("Bearer {}", user.token)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{method} {url} must reject a device-scoped token");
    }
}
