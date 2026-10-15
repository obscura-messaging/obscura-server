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

fn id_hash(id: &str) -> String {
    hex::encode(Sha256::digest(id.as_bytes()))
}

async fn create(app: &TestApp, token: &str) -> reqwest::Response {
    app.client
        .post(format!("{}/v1/link-sessions", app.server_url))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
}

async fn get(app: &TestApp, token: &str, id: &str, wait: u64) -> (StatusCode, Vec<u8>) {
    let resp = app
        .client
        .get(format!("{}/v1/link-sessions/{id}?wait={wait}", app.server_url))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    (resp.status(), resp.bytes().await.unwrap().to_vec())
}

async fn register_linked(app: &TestApp, account: &TestUser, user_token: &str, id: &str) -> StatusCode {
    let mut payload = common::generate_device_payload_for(&account.identity_key, 7, 1);
    payload["linkSessionId"] = json!(id);
    app.client
        .post(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {user_token}"))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .status()
}

async fn expire(app: &TestApp, id: &str) {
    sqlx::query("UPDATE link_sessions SET expires_at = NOW() - INTERVAL '1 second' WHERE id_hash = $1")
        .bind(id_hash(id))
        .execute(&app.pool)
        .await
        .unwrap();
}

async fn stored(app: &TestApp, id: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM link_sessions WHERE id_hash = $1)")
        .bind(id_hash(id))
        .fetch_one(&app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn test_create_requires_user_scoped_token_and_stores_only_a_hash() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_create")).await;
    assert_eq!(create(&app, &primary.token).await.status(), StatusCode::FORBIDDEN);

    let user_token = app.login_user_scoped(&primary.username).await;
    let resp = create(&app, &user_token).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    assert!((now + 590..=now + 610).contains(&body["expiresAt"].as_i64().unwrap()));

    let plain: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM link_sessions WHERE id_hash = $1)")
        .bind(id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert!(!plain, "The id itself must not be stored");
    assert!(stored(&app, id).await);
}

#[tokio::test]
async fn test_create_purges_expired_sessions() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_purge")).await;
    let user_token = app.login_user_scoped(&primary.username).await;
    let old = app.create_link_session(&user_token).await;
    expire(&app, &old).await;

    app.create_link_session(&user_token).await;
    assert!(!stored(&app, &old).await);
}

#[tokio::test]
async fn test_approval_requires_the_same_users_primary() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_owner")).await;
    let linked = app.link_device(&primary).await;
    let stranger = app.register_user(&common::generate_username("ls_stranger")).await;
    let user_token = app.login_user_scoped(&primary.username).await;
    let id = app.create_link_session(&user_token).await;

    assert_eq!(app.approve_link_session(&user_token, &id, b"x").await, StatusCode::FORBIDDEN);
    assert_eq!(app.approve_link_session(&linked.token, &id, b"x").await, StatusCode::FORBIDDEN);
    assert_eq!(app.approve_link_session(&stranger.token, &id, b"x").await, StatusCode::NOT_FOUND);
    assert_eq!(app.approve_link_session(&primary.token, "unknown", b"x").await, StatusCode::NOT_FOUND);

    assert_eq!(app.approve_link_session(&primary.token, &id, b"x").await, StatusCode::OK);
    assert_eq!(app.approve_link_session(&primary.token, &id, b"again").await, StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_body_size_cap() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_size")).await;
    let user_token = app.login_user_scoped(&primary.username).await;
    let id = app.create_link_session(&user_token).await;

    assert_eq!(app.approve_link_session(&primary.token, &id, &[7; 64 * 1024 + 1]).await, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(app.approve_link_session(&primary.token, &id, &[7; 64 * 1024]).await, StatusCode::OK);
    assert_eq!(get(&app, &user_token, &id, 0).await.1.len(), 64 * 1024);
}

#[tokio::test]
async fn test_read_returns_the_body_without_consuming_it() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_read")).await;
    let stranger = app.register_user(&common::generate_username("ls_read_stranger")).await;
    let stranger_token = app.login_user_scoped(&stranger.username).await;
    let user_token = app.login_user_scoped(&primary.username).await;
    let id = app.create_link_session(&user_token).await;

    assert_eq!(get(&app, &user_token, &id, 0).await, (StatusCode::NO_CONTENT, Vec::new()));
    assert_eq!(app.approve_link_session(&primary.token, &id, b"ciphertext").await, StatusCode::OK);

    assert_eq!(get(&app, &user_token, &id, 0).await, (StatusCode::OK, b"ciphertext".to_vec()));
    assert_eq!(get(&app, &user_token, &id, 0).await, (StatusCode::OK, b"ciphertext".to_vec()));
    assert_eq!(get(&app, &primary.token, &id, 0).await.0, StatusCode::FORBIDDEN);
    assert_eq!(get(&app, &stranger_token, &id, 0).await.0, StatusCode::NOT_FOUND);
    assert_eq!(get(&app, &user_token, "unknown", 0).await.0, StatusCode::NOT_FOUND);

    assert_eq!(register_linked(&app, &primary, &user_token, &id).await, StatusCode::CREATED);
}

#[tokio::test]
async fn test_read_waits_for_approval() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_wait")).await;
    let user_token = app.login_user_scoped(&primary.username).await;
    let id = app.create_link_session(&user_token).await;

    let started = Instant::now();
    assert_eq!(get(&app, &user_token, &id, 1).await.0, StatusCode::NO_CONTENT);
    assert!(started.elapsed() >= Duration::from_millis(900), "An unanswered wait should last about the requested time");

    let waiter = {
        let (client, url, token) =
            (app.client.clone(), format!("{}/v1/link-sessions/{id}?wait=10", app.server_url), user_token.clone());
        tokio::spawn(async move {
            let resp = client.get(url).header("Authorization", format!("Bearer {token}")).send().await.unwrap();
            (resp.status(), resp.bytes().await.unwrap().to_vec(), Instant::now())
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let approved_at = Instant::now();
    assert_eq!(app.approve_link_session(&primary.token, &id, b"late").await, StatusCode::OK);

    let (status, body, received_at) = waiter.await.unwrap();
    assert_eq!((status, body), (StatusCode::OK, b"late".to_vec()));
    assert!(received_at.duration_since(approved_at) < Duration::from_secs(2), "The waiting read should return soon");
}

#[tokio::test]
async fn test_expired_session_is_gone() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_expiry")).await;
    let (user_token, approved) = app.approved_link_session(&primary).await;
    let pending = app.create_link_session(&user_token).await;
    expire(&app, &approved).await;
    expire(&app, &pending).await;

    assert_eq!(get(&app, &user_token, &approved, 0).await.0, StatusCode::NOT_FOUND);
    assert_eq!(app.approve_link_session(&primary.token, &pending, b"x").await, StatusCode::NOT_FOUND);
    assert_eq!(register_linked(&app, &primary, &user_token, &approved).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_registration_consumes_the_session() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_consume")).await;
    let (user_token, id) = app.approved_link_session(&primary).await;

    assert_eq!(register_linked(&app, &primary, &user_token, &id).await, StatusCode::CREATED);
    assert!(!stored(&app, &id).await);
    assert_eq!(register_linked(&app, &primary, &user_token, &id).await, StatusCode::FORBIDDEN);
    assert_eq!(get(&app, &user_token, &id, 0).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_session_is_bound_to_its_user() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("ls_alice")).await;
    let mallory = app.register_user(&common::generate_username("ls_mallory")).await;
    let (alice_token, id) = app.approved_link_session(&alice).await;
    let mallory_token = app.login_user_scoped(&mallory.username).await;

    assert_eq!(register_linked(&app, &mallory, &mallory_token, &id).await, StatusCode::FORBIDDEN);
    assert_eq!(register_linked(&app, &alice, &alice_token, &id).await, StatusCode::CREATED);
}

#[tokio::test]
async fn test_account_reset_discards_sessions() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_reset")).await;
    let (_, id) = app.approved_link_session(&primary).await;

    let resp = app
        .client
        .post(format!("{}/v1/account/reset", app.server_url))
        .json(&json!({ "username": primary.username, "password": "password12345" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!stored(&app, &id).await);
}
