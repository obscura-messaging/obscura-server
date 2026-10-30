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
use serde_json::json;

mod common;

#[tokio::test]
async fn test_register_flow() {
    let app = common::TestApp::spawn().await;
    let username = common::generate_username("user");

    // Step 1: Register account and primary device atomically
    let (payload, _identity_key) = common::generate_registration_payload(&username, "password12345", 123, 2);

    let resp = app.client.post(format!("{}/v1/users", app.server_url)).json(&payload).send().await.unwrap();

    assert_eq!(resp.status(), 201);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(json.get("token").is_some(), "Registration response must include token");
    assert!(json.get("refreshToken").is_some(), "Registration response must include refreshToken");
    assert!(json.get("expiresAt").is_some(), "Registration response must include expiresAt");
    assert!(json.get("deviceId").is_some(), "Registration response must include deviceId");

    let device_token = json["token"].as_str().unwrap().to_string();
    let device_id = json["deviceId"].as_str().unwrap().to_string();

    // Step 2: Login with the registered deviceId
    let login_payload = json!({
        "username": username,
        "password": "password12345",
        "deviceId": device_id,
    });

    let resp_login =
        app.client.post(format!("{}/v1/sessions", app.server_url)).json(&login_payload).send().await.unwrap();

    assert_eq!(resp_login.status(), StatusCode::OK);

    // Fetch user_id from database
    let user_id_record: (uuid::Uuid,) =
        sqlx::query_as("SELECT id FROM users WHERE username = $1").bind(&username).fetch_one(&app.pool).await.unwrap();
    let user_id = user_id_record.0;

    // Step 3: Fetch Keys (should succeed using user_id)
    let resp_keys = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, user_id))
        .header("Authorization", format!("Bearer {device_token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_keys.status(), StatusCode::OK);
}
