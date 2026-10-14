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
