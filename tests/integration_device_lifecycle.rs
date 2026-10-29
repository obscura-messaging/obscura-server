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
use common::{TestApp, TestUser};
use futures::future::join_all;
use reqwest::StatusCode;
use serde_json::json;
use uuid::Uuid;

async fn post_device(app: &TestApp, token: &str, payload: &serde_json::Value) -> reqwest::Response {
    app.client
        .post(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {token}"))
        .json(payload)
        .send()
        .await
        .unwrap()
}

async fn delete_device(app: &TestApp, token: &str, device_id: Uuid) -> StatusCode {
    app.client
        .delete(format!("{}/v1/devices/{device_id}", app.server_url))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .status()
}

async fn reset_account(app: &TestApp, username: &str, password: &str) -> StatusCode {
    app.client
        .post(format!("{}/v1/account/reset", app.server_url))
        .json(&json!({ "username": username, "password": password }))
        .send()
        .await
        .unwrap()
        .status()
}

async fn list_devices(app: &TestApp, token: &str) -> Vec<serde_json::Value> {
    let resp = app
        .client
        .get(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    resp.json::<serde_json::Value>().await.unwrap()["devices"].as_array().unwrap().clone()
}

async fn account_identity(app: &TestApp, user_id: Uuid) -> Option<String> {
    let key: Option<Vec<u8>> = sqlx::query_scalar("SELECT identity_key FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    key.map(|k| STANDARD.encode(k))
}

async fn error_of(resp: reqwest::Response) -> String {
    resp.json::<serde_json::Value>().await.unwrap()["error"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn test_first_device_is_primary_and_sets_account_identity() {
    let app = TestApp::spawn().await;
    let user = app.register_user(&common::generate_username("first_primary")).await;

    let devices = list_devices(&app, &user.token).await;
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["deviceId"], user.device_id.to_string());
    assert_eq!(devices[0]["isPrimary"], json!(true));

    assert_eq!(account_identity(&app, user.user_id).await, Some(common::identity_public_key(&user.identity_key)));
}

#[tokio::test]
async fn test_linked_device_requires_approved_link_session() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("link_session")).await;
    let user_token = app.login_user_scoped(&primary.username).await;

    let payload = common::generate_device_payload_for(&primary.identity_key, 2, 1);
    let resp = post_device(&app, &user_token, &payload).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "Missing link session must be rejected");
    assert_eq!(error_of(resp).await, "Invalid link session");

    let mut unknown = payload.clone();
    unknown["linkSessionId"] = json!("not-a-real-session");
    let resp = post_device(&app, &user_token, &unknown).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "Unknown link session must be rejected");
    assert_eq!(error_of(resp).await, "Invalid link session");

    let mut unapproved = payload.clone();
    unapproved["linkSessionId"] = json!(app.create_link_session(&user_token).await);
    let resp = post_device(&app, &user_token, &unapproved).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "Unapproved link session must be rejected");
    assert_eq!(error_of(resp).await, "Invalid link session");

    let linked = app.link_device(&primary).await;
    let devices = list_devices(&app, &primary.token).await;
    let linked_entry = devices.iter().find(|d| d["deviceId"] == linked.device_id.to_string()).unwrap();
    assert_eq!(linked_entry["isPrimary"], json!(false));
    assert_eq!(devices.iter().filter(|d| d["isPrimary"] == json!(true)).count(), 1);
}

#[tokio::test]
async fn test_linked_device_identity_must_match_account() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("link_ik")).await;
    let (user_token, link_session_id) = app.approved_link_session(&primary).await;

    let (mut foreign, _) = common::generate_device_payload(2, 1);
    foreign["linkSessionId"] = json!(link_session_id);
    let resp = post_device(&app, &user_token, &foreign).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_of(resp).await, "Identity key does not match the account identity");

    // A signed pre-key that does not verify against the account identity is rejected too.
    let mut forged = common::generate_device_payload_for(&primary.identity_key, 2, 1);
    let (spk_pub, spk_sig) = common::generate_signed_pre_key(&common::generate_signing_key());
    forged["signedPreKey"] =
        json!({ "keyId": 1, "publicKey": STANDARD.encode(spk_pub), "signature": STANDARD.encode(spk_sig) });
    forged["linkSessionId"] = json!(link_session_id);
    let resp = post_device(&app, &user_token, &forged).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Neither failure consumed the link session.
    let mut valid = common::generate_device_payload_for(&primary.identity_key, 2, 1);
    valid["linkSessionId"] = json!(link_session_id);
    assert_eq!(post_device(&app, &user_token, &valid).await.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_delete_device_permissions() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("del_perm")).await;
    let linked_a = app.link_device(&primary).await;
    let linked_b = app.link_device(&primary).await;
    let stranger = app.register_user(&common::generate_username("del_stranger")).await;
    let user_token = app.login_user_scoped(&primary.username).await;

    assert_eq!(delete_device(&app, &user_token, linked_a.device_id).await, StatusCode::FORBIDDEN);
    assert_eq!(delete_device(&app, &primary.token, primary.device_id).await, StatusCode::FORBIDDEN);
    assert_eq!(delete_device(&app, &linked_a.token, primary.device_id).await, StatusCode::FORBIDDEN);
    assert_eq!(delete_device(&app, &linked_a.token, linked_b.device_id).await, StatusCode::FORBIDDEN);
    assert_eq!(delete_device(&app, &primary.token, stranger.device_id).await, StatusCode::NOT_FOUND);

    assert_eq!(delete_device(&app, &linked_a.token, linked_a.device_id).await, StatusCode::OK);
    assert_eq!(delete_device(&app, &primary.token, linked_b.device_id).await, StatusCode::OK);

    let devices = list_devices(&app, &primary.token).await;
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["deviceId"], primary.device_id.to_string());
}

#[tokio::test]
async fn test_deleted_device_tokens_rejected_and_gateway_closed() {
    let app = TestApp::spawn_with_workers(common::get_test_config()).await;
    let primary = app.register_user(&common::generate_username("del_tokens")).await;
    let linked = app.link_device(&primary).await;

    let mut ws = app.connect_ws(&linked.token).await;
    ws.ensure_subscribed().await;

    assert_eq!(delete_device(&app, &primary.token, linked.device_id).await, StatusCode::OK);

    ws.assert_closed().await;

    let resp = app
        .client
        .get(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {}", linked.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Access token of a deleted device must stop working");

    let resp = app
        .client
        .post(format!("{}/v1/gateway/ticket", app.server_url))
        .header("Authorization", format!("Bearer {}", linked.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app
        .client
        .post(format!("{}/v1/sessions/refresh", app.server_url))
        .json(&json!({ "refreshToken": linked.refresh_token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Refresh token of a deleted device must stop working");
}

#[tokio::test]
async fn test_queued_messages_survive_sender_device_deletion() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("del_sender")).await;
    let alice_linked = app.link_device(&alice).await;
    let bob = app.register_user(&common::generate_username("del_recipient")).await;

    app.send_message(&alice_linked.token, bob.device_id, b"sent before unlink").await;
    assert_eq!(delete_device(&app, &alice_linked.token, alice_linked.device_id).await, StatusCode::OK);

    app.assert_message_count(bob.device_id, 1).await;

    let mut ws = app.connect_ws(&bob.token).await;
    let envelope = ws.receive_envelope().await.expect("Bob should still receive the message");
    assert_eq!(envelope.message, b"sent before unlink");
    assert_eq!(envelope.sender_device_id, alice_linked.device_id.as_bytes().to_vec());
}

#[tokio::test]
async fn test_account_reset() {
    let app = TestApp::spawn_with_workers(common::get_test_config()).await;
    let primary = app.register_user(&common::generate_username("reset")).await;
    let linked = app.link_device(&primary).await;

    assert_eq!(reset_account(&app, &primary.username, "wrong-password").await, StatusCode::UNAUTHORIZED);
    assert_eq!(reset_account(&app, "no_such_user", "password12345").await, StatusCode::UNAUTHORIZED);
    assert_eq!(list_devices(&app, &primary.token).await.len(), 2, "Rejected resets must not delete devices");

    let mut ws = app.connect_ws(&linked.token).await;
    ws.ensure_subscribed().await;

    assert_eq!(reset_account(&app, &primary.username.to_uppercase(), "password12345").await, StatusCode::OK);
    let user_token = app.login_user_scoped(&primary.username).await;

    ws.assert_closed().await;
    assert!(list_devices(&app, &user_token).await.is_empty());
    assert_eq!(account_identity(&app, primary.user_id).await, None);
    for old in [&primary, &linked] {
        let resp = app
            .client
            .get(format!("{}/v1/devices", app.server_url))
            .header("Authorization", format!("Bearer {}", old.token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // The next device registers as a new primary with a new identity, without a link session.
    let (payload, new_identity) = common::generate_device_payload(9, 1);
    let resp = post_device(&app, &user_token, &payload).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let new_primary: serde_json::Value = resp.json().await.unwrap();
    let devices = list_devices(&app, &user_token).await;
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["deviceId"], new_primary["deviceId"]);
    assert_eq!(devices[0]["isPrimary"], json!(true));
    assert_eq!(account_identity(&app, primary.user_id).await, Some(common::identity_public_key(&new_identity)));
}

#[tokio::test]
async fn test_account_reset_is_rate_limited_like_auth() {
    let mut config = common::get_test_config();
    config.rate_limit.auth_per_second = 1;
    config.rate_limit.auth_burst = 1;
    let app = TestApp::spawn_with_config(config).await;
    let user: TestUser = app.register_user(&common::generate_username("reset_rl")).await;
    let ip = format!("10.9.{}.{}", rand::random::<u8>(), rand::random::<u8>());

    // Concurrent, because the limiter runs before the password check: sequential requests could be
    // spaced past the refill interval by a slow hash.
    let statuses: Vec<StatusCode> = join_all((0..3).map(|_| {
        app.client
            .post(format!("{}/v1/account/reset", app.server_url))
            .json(&json!({ "username": user.username, "password": "wrong-password" }))
            .header("X-Forwarded-For", &ip)
            .send()
    }))
    .await
    .into_iter()
    .map(|r| r.unwrap().status())
    .collect();
    assert_eq!(statuses.iter().filter(|s| **s == StatusCode::TOO_MANY_REQUESTS).count(), 2, "{statuses:?}");
}

#[tokio::test]
async fn test_device_deletion_and_account_reset_delete_backup_objects() {
    let config = common::get_test_config();
    let app = TestApp::spawn_with_config(config.clone()).await;
    common::ensure_storage_bucket(&app.s3_client, &config.storage.bucket).await;

    let primary = app.register_user(&common::generate_username("backup_del")).await;
    let linked = app.link_device(&primary).await;

    for device in [&primary, &linked] {
        let resp = app
            .client
            .post(format!("{}/v1/backup", app.server_url))
            .header("Authorization", format!("Bearer {}", device.token))
            .header("If-None-Match", "*")
            .header("Content-Length", "64")
            .body(vec![7u8; 64])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let s3_exists = |device_id: Uuid| {
        let s3 = app.s3_client.clone();
        let bucket = config.storage.bucket.clone();
        let key = format!("{}v1", format!("{}{device_id}/", config.backup.prefix));
        async move { s3.head_object().bucket(bucket).key(key).send().await.is_ok() }
    };

    assert!(s3_exists(primary.device_id).await);
    assert!(s3_exists(linked.device_id).await);

    assert_eq!(delete_device(&app, &primary.token, linked.device_id).await, StatusCode::OK);
    assert!(!s3_exists(linked.device_id).await, "Deleting a device must remove its S3 backup object");
    assert!(s3_exists(primary.device_id).await);

    assert_eq!(reset_account(&app, &primary.username, "password12345").await, StatusCode::OK);
    assert!(!s3_exists(primary.device_id).await, "Resetting an account must remove its devices' S3 backup objects");
}
