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

fn id_hash(id: &str) -> Vec<u8> {
    Sha256::digest(id.as_bytes()).to_vec()
}

async fn create(app: &TestApp, username: &str, password: &str) -> reqwest::Response {
    app.client
        .post(format!("{}/v1/link-sessions", app.server_url))
        .json(&json!({ "username": username, "password": password }))
        .send()
        .await
        .unwrap()
}

async fn get(app: &TestApp, id: &str) -> (StatusCode, Vec<u8>) {
    let resp = app.client.get(format!("{}/v1/link-sessions/{id}", app.server_url)).send().await.unwrap();
    (resp.status(), resp.bytes().await.unwrap().to_vec())
}

async fn register_linked(app: &TestApp, account: &TestUser, id: &str) -> StatusCode {
    let mut payload = common::generate_device_payload_for(&account.identity_key, 7, 1);
    payload["linkSessionId"] = json!(id);
    app.client.post(format!("{}/v1/devices", app.server_url)).json(&payload).send().await.unwrap().status()
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
async fn test_create_verifies_credentials_and_stores_only_a_hash() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_create")).await;
    assert_eq!(create(&app, &primary.username, "wrong-password").await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(create(&app, "no_such_user", "password12345").await.status(), StatusCode::UNAUTHORIZED);

    let resp = create(&app, &primary.username, "password12345").await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap();
    assert_eq!(body["userId"], primary.user_id.to_string());
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    assert!((now + 590..=now + 610).contains(&body["expiresAt"].as_i64().unwrap()));

    let plain: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM link_sessions WHERE id_hash = $1)")
        .bind(id.as_bytes())
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert!(!plain, "The id itself must not be stored");
    assert!(stored(&app, id).await);
}

#[tokio::test]
async fn test_create_replaces_previous_unapproved_session_and_purges_expired() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_purge")).await;
    let other = app.register_user(&common::generate_username("ls_purge_other")).await;

    let expired_other = app.create_link_session(&other.username).await;
    expire(&app, &expired_other).await;

    let first_unapproved = app.create_link_session(&primary.username).await;
    assert!(!stored(&app, &expired_other).await, "Expired sessions must be purged");
    assert!(stored(&app, &first_unapproved).await);

    let second_unapproved = app.create_link_session(&primary.username).await;
    assert!(!stored(&app, &first_unapproved).await, "Prior unapproved session for the same user must be replaced");
    assert!(stored(&app, &second_unapproved).await);
}

#[tokio::test]
async fn test_approval_requires_the_same_users_primary() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_owner")).await;
    let linked = app.link_device(&primary).await;
    let stranger = app.register_user(&common::generate_username("ls_stranger")).await;
    let id = app.create_link_session(&primary.username).await;

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
    let id = app.create_link_session(&primary.username).await;

    assert_eq!(app.approve_link_session(&primary.token, &id, &[7; 64 * 1024 + 1]).await, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(app.approve_link_session(&primary.token, &id, &[7; 64 * 1024]).await, StatusCode::OK);
    assert_eq!(get(&app, &id).await.1.len(), 64 * 1024);
}

#[tokio::test]
async fn test_read_returns_the_body_without_consuming_it() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_read")).await;
    let id = app.create_link_session(&primary.username).await;

    assert_eq!(get(&app, &id).await, (StatusCode::NO_CONTENT, Vec::new()));
    assert_eq!(app.approve_link_session(&primary.token, &id, b"ciphertext").await, StatusCode::OK);

    assert_eq!(get(&app, &id).await, (StatusCode::OK, b"ciphertext".to_vec()));
    assert_eq!(get(&app, &id).await, (StatusCode::OK, b"ciphertext".to_vec()));
    assert_eq!(get(&app, "unknown").await.0, StatusCode::NOT_FOUND);

    assert_eq!(register_linked(&app, &primary, &id).await, StatusCode::CREATED);
}

#[tokio::test]
async fn test_expired_session_is_gone() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_expiry")).await;
    let approved = app.approved_link_session(&primary).await;
    let pending = app.create_link_session(&primary.username).await;
    expire(&app, &approved).await;
    expire(&app, &pending).await;

    assert_eq!(get(&app, &approved).await.0, StatusCode::NOT_FOUND);
    assert_eq!(app.approve_link_session(&primary.token, &pending, b"x").await, StatusCode::NOT_FOUND);
    assert_eq!(register_linked(&app, &primary, &approved).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_registration_consumes_the_session() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_consume")).await;
    let id = app.approved_link_session(&primary).await;

    assert_eq!(register_linked(&app, &primary, &id).await, StatusCode::CREATED);
    assert!(!stored(&app, &id).await);
    assert_eq!(register_linked(&app, &primary, &id).await, StatusCode::FORBIDDEN);
    assert_eq!(get(&app, &id).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_session_is_bound_to_its_user() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("ls_alice")).await;
    let mallory = app.register_user(&common::generate_username("ls_mallory")).await;
    let id = app.approved_link_session(&alice).await;

    assert_eq!(register_linked(&app, &mallory, &id).await, StatusCode::FORBIDDEN);
    assert_eq!(register_linked(&app, &alice, &id).await, StatusCode::CREATED);
}

#[tokio::test]
async fn test_account_reset_discards_sessions() {
    let app = TestApp::spawn().await;
    let primary = app.register_user(&common::generate_username("ls_reset")).await;
    let id = app.approved_link_session(&primary).await;
    let (reset_payload, _) = common::generate_registration_payload(&primary.username, "password12345", 9, 1);

    let resp =
        app.client.post(format!("{}/v1/account/reset", app.server_url)).json(&reset_payload).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!stored(&app, &id).await);
}
