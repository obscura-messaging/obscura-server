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

use common::{TestApp, TestUser};
use reqwest::StatusCode;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

async fn request_code(app: &TestApp, token: &str) -> reqwest::Response {
    app.client
        .post(format!("{}/v1/devices/provisioning-code", app.server_url))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
}

async fn link_with_code(app: &TestApp, account: &TestUser, code: &str) -> StatusCode {
    let user_token = app.login_user_scoped(&account.username).await;
    let mut payload = common::generate_device_payload_for(&account.identity_key, 7, 1);
    payload["provisioningCode"] = json!(code);
    app.client
        .post(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {user_token}"))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .status()
}

async fn create_relay(app: &TestApp, token: &str) -> String {
    let resp = app
        .client
        .post(format!("{}/v1/provisioning", app.server_url))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    assert!((now + 590..=now + 610).contains(&body["expiresAt"].as_i64().unwrap()));
    body["address"].as_str().unwrap().to_string()
}

async fn put_relay(app: &TestApp, token: &str, address: &str, body: Vec<u8>) -> StatusCode {
    app.client
        .put(format!("{}/v1/provisioning/{address}", app.server_url))
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .unwrap()
        .status()
}

async fn get_relay(app: &TestApp, token: &str, address: &str, wait: u64) -> (StatusCode, Vec<u8>) {
    let resp = app
        .client
        .get(format!("{}/v1/provisioning/{address}?wait={wait}", app.server_url))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    (resp.status(), resp.bytes().await.unwrap().to_vec())
}

#[tokio::test]
async fn test_provisioning_code_issued_only_to_primary() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("code_primary")).await;
    let linked = app.link_device(&primary).await;
    let user_token = app.login_user_scoped(&primary.username).await;

    assert_eq!(request_code(&app, &user_token).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(request_code(&app, &linked.token).await.status(), StatusCode::FORBIDDEN);

    let resp = request_code(&app, &primary.token).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    let code = body["code"].as_str().unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    assert!((now + 590..=now + 610).contains(&body["expiresAt"].as_i64().unwrap()));

    let stored_plain: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM provisioning_codes WHERE code_hash = $1")
        .bind(code)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(stored_plain, 0, "The code itself must not be stored");
    let stored_hash: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM provisioning_codes WHERE code_hash = $1")
        .bind(hex::encode(Sha256::digest(code.as_bytes())))
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(stored_hash, 1);
}

#[tokio::test]
async fn test_provisioning_code_is_single_use() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("code_once")).await;
    let code = app.issue_provisioning_code(&primary.token).await;

    assert_eq!(link_with_code(&app, &primary, &code).await, StatusCode::CREATED);
    assert_eq!(link_with_code(&app, &primary, &code).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_provisioning_code_expires() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("code_expiry")).await;
    let code = app.issue_provisioning_code(&primary.token).await;

    sqlx::query("UPDATE provisioning_codes SET expires_at = NOW() - INTERVAL '1 second' WHERE code_hash = $1")
        .bind(hex::encode(Sha256::digest(code.as_bytes())))
        .execute(&app.pool)
        .await
        .unwrap();

    assert_eq!(link_with_code(&app, &primary, &code).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_provisioning_code_is_bound_to_its_user() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("code_alice")).await;
    let mallory = app.register_user(&common::generate_username("code_mallory")).await;
    let code = app.issue_provisioning_code(&alice.token).await;

    assert_eq!(link_with_code(&app, &mallory, &code).await, StatusCode::FORBIDDEN);
    assert_eq!(link_with_code(&app, &alice, &code).await, StatusCode::CREATED);
}

#[tokio::test]
async fn test_new_code_keeps_older_codes_valid() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("code_older")).await;
    let older = app.issue_provisioning_code(&primary.token).await;
    let newer = app.issue_provisioning_code(&primary.token).await;

    assert_eq!(link_with_code(&app, &primary, &older).await, StatusCode::CREATED);
    assert_eq!(link_with_code(&app, &primary, &newer).await, StatusCode::CREATED);
}

#[tokio::test]
async fn test_relay_round_trip_is_single_put_and_single_read() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("relay_trip")).await;
    let new_device_token = app.login_user_scoped(&primary.username).await;
    let address = create_relay(&app, &new_device_token).await;

    assert_eq!(get_relay(&app, &new_device_token, &address, 0).await, (StatusCode::NO_CONTENT, Vec::new()));

    assert_eq!(put_relay(&app, &primary.token, &address, b"ciphertext".to_vec()).await, StatusCode::OK);
    assert_eq!(put_relay(&app, &primary.token, &address, b"again".to_vec()).await, StatusCode::CONFLICT);

    assert_eq!(get_relay(&app, &new_device_token, &address, 0).await, (StatusCode::OK, b"ciphertext".to_vec()));
    assert_eq!(get_relay(&app, &new_device_token, &address, 0).await.0, StatusCode::NO_CONTENT);
    assert_eq!(put_relay(&app, &primary.token, &address, b"after read".to_vec()).await, StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_relay_put_requires_same_users_primary() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("relay_owner")).await;
    let linked = app.link_device(&primary).await;
    let stranger = app.register_user(&common::generate_username("relay_stranger")).await;
    let user_token = app.login_user_scoped(&primary.username).await;
    let address = create_relay(&app, &user_token).await;

    assert_eq!(put_relay(&app, &user_token, &address, b"x".to_vec()).await, StatusCode::FORBIDDEN);
    assert_eq!(put_relay(&app, &linked.token, &address, b"x".to_vec()).await, StatusCode::FORBIDDEN);
    assert_eq!(put_relay(&app, &stranger.token, &address, b"x".to_vec()).await, StatusCode::NOT_FOUND);
    assert_eq!(get_relay(&app, &stranger.token, &address, 0).await.0, StatusCode::NOT_FOUND);

    assert_eq!(put_relay(&app, &primary.token, &address, b"x".to_vec()).await, StatusCode::OK);
    assert_eq!(get_relay(&app, &linked.token, &address, 0).await, (StatusCode::OK, b"x".to_vec()));
}

#[tokio::test]
async fn test_relay_unknown_address_is_not_found() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("relay_unknown")).await;

    assert_eq!(put_relay(&app, &primary.token, "unknown", b"x".to_vec()).await, StatusCode::NOT_FOUND);
    assert_eq!(get_relay(&app, &primary.token, "unknown", 0).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_relay_body_size_cap() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("relay_size")).await;

    let address = create_relay(&app, &primary.token).await;
    assert_eq!(put_relay(&app, &primary.token, &address, vec![7; 64 * 1024 + 1]).await, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(put_relay(&app, &primary.token, &address, vec![7; 64 * 1024]).await, StatusCode::OK);
    assert_eq!(get_relay(&app, &primary.token, &address, 0).await.1.len(), 64 * 1024);
}

#[tokio::test]
async fn test_relay_expiry_purges_address_and_body() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("relay_expiry")).await;
    let address = create_relay(&app, &primary.token).await;
    assert_eq!(put_relay(&app, &primary.token, &address, b"x".to_vec()).await, StatusCode::OK);

    let mut conn = app.resources.pubsub.publisher();
    let address_key = format!("provisioning:{{{address}}}");
    let body_key = format!("provisioning:{{{address}}}:body");
    for key in [&address_key, &body_key] {
        let ttl: i64 = redis::cmd("PTTL").arg(key).query_async(&mut conn).await.unwrap();
        assert!((1..=600_000).contains(&ttl), "{key} must expire with the address, got {ttl}");
    }

    let _: () = redis::cmd("PEXPIRE").arg(&address_key).arg(1).query_async(&mut conn).await.unwrap();
    let _: () = redis::cmd("PEXPIRE").arg(&body_key).arg(1).query_async(&mut conn).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    assert_eq!(get_relay(&app, &primary.token, &address, 0).await.0, StatusCode::NOT_FOUND);
    assert_eq!(put_relay(&app, &primary.token, &address, b"y".to_vec()).await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_relay_get_waits_for_body() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("relay_wait")).await;
    let address = create_relay(&app, &primary.token).await;

    let started = Instant::now();
    assert_eq!(get_relay(&app, &primary.token, &address, 1).await.0, StatusCode::NO_CONTENT);
    assert!(started.elapsed() >= Duration::from_millis(900), "An empty wait should last about the requested time");

    let waiter = {
        let (client, url, token) = (
            app.client.clone(),
            format!("{}/v1/provisioning/{address}?wait=10", app.server_url),
            primary.token.clone(),
        );
        tokio::spawn(async move {
            let resp = client.get(url).header("Authorization", format!("Bearer {token}")).send().await.unwrap();
            (resp.status(), resp.bytes().await.unwrap().to_vec(), Instant::now())
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let put_at = Instant::now();
    assert_eq!(put_relay(&app, &primary.token, &address, b"late".to_vec()).await, StatusCode::OK);

    let (status, body, received_at) = waiter.await.unwrap();
    assert_eq!((status, body), (StatusCode::OK, b"late".to_vec()));
    assert!(received_at.duration_since(put_at) < Duration::from_secs(2), "The waiting GET should return on PUT");
}
