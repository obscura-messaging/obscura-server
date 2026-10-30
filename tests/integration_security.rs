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
        ("GET", format!("{}/v1/users/{}/devices/{}", app.server_url, target_user_id, target_resource_id)),
        ("GET", format!("{}/v1/devices", app.server_url)),
        ("DELETE", format!("{}/v1/devices/{}", app.server_url, target_resource_id)),
        ("POST", format!("{}/v1/devices/keys", app.server_url)),
        ("POST", format!("{}/v1/messages", app.server_url)),
        ("DELETE", format!("{}/v1/sessions", app.server_url)),
        ("POST", format!("{}/v1/attachments", app.server_url)),
        ("GET", format!("{}/v1/attachments/{}", app.server_url, target_resource_id)),
        ("PUT", format!("{}/v1/push-tokens", app.server_url)),
        ("POST", format!("{}/v1/gateway/ticket", app.server_url)),
        ("PUT", format!("{}/v1/link-sessions/some-id", app.server_url)),
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
