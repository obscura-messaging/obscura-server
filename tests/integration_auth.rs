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
async fn test_refresh_token_flow() {
    let app = common::TestApp::spawn().await;
    let username = common::generate_username("refresh_user");

    // 1. Register and get initial tokens
    let user = app.register_user(&username).await;

    // 2. Use Refresh Token to get new pair
    let refresh_payload = json!({
        "refreshToken": user.refresh_token
    });

    let resp_refresh =
        app.client.post(format!("{}/v1/sessions/refresh", app.server_url)).json(&refresh_payload).send().await.unwrap();

    assert_eq!(resp_refresh.status(), StatusCode::OK);

    let json_refresh: serde_json::Value = resp_refresh.json().await.unwrap();
    let access_token_2 = json_refresh["token"].as_str().unwrap().to_string();
    let refresh_token_2 = json_refresh["refreshToken"].as_str().unwrap().to_string();

    // Assert rotation occurred
    assert!(!user.token.is_empty());
    assert!(!access_token_2.is_empty());
    assert_ne!(user.refresh_token, refresh_token_2, "Refresh token should rotate");

    // 3. Verify Old Refresh Token is Invalid (Rotation Check)
    let resp_old_refresh = app
        .client
        .post(format!("{}/v1/sessions/refresh", app.server_url))
        .json(&refresh_payload) // sending refresh_token_1 again
        .send()
        .await
        .unwrap();

    assert_eq!(resp_old_refresh.status(), StatusCode::UNAUTHORIZED, "Old refresh token should be invalidated");
}

#[tokio::test]
async fn test_logout_revokes_refresh_token() {
    let app = common::TestApp::spawn().await;
    let username = common::generate_username("logout_user");

    // 1. Register
    let user = app.register_user(&username).await;

    // 2. Logout
    let resp_logout = app
        .client
        .delete(format!("{}/v1/sessions", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&json!({ "refreshToken": user.refresh_token }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_logout.status(), StatusCode::OK);

    // 3. Try to Refresh after Logout
    let resp_fail = app
        .client
        .post(format!("{}/v1/sessions/refresh", app.server_url))
        .json(&json!({ "refreshToken": user.refresh_token }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_fail.status(), StatusCode::UNAUTHORIZED, "Refresh token should be revoked after logout");
}

#[tokio::test]
async fn test_refresh_token_expiration() {
    // 1. Setup app with 0-day TTL (immediate expiration)
    let mut config = common::get_test_config();
    config.auth.refresh_token_ttl_days = 0;

    let app = common::TestApp::spawn_with_config(config).await;
    let username = common::generate_username("expire_user");

    // 2. Register
    let user = app.register_user(&username).await;

    // 3. Wait a moment to ensure clock ticks (1s)
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // 4. Try to Refresh (Should fail)
    let refresh_payload = json!({
        "refreshToken": user.refresh_token
    });

    let resp_refresh =
        app.client.post(format!("{}/v1/sessions/refresh", app.server_url)).json(&refresh_payload).send().await.unwrap();

    assert_eq!(resp_refresh.status(), StatusCode::UNAUTHORIZED, "Expired refresh token should be rejected");
}

#[tokio::test]
async fn test_password_strength() {
    let app = common::TestApp::spawn().await;
    let username = common::generate_username("weak_user");

    // Try to register with a weak password
    let (mut reg_payload, _) = common::generate_registration_payload(&username, "too_short", 123, 1);

    let resp = app.client.post(format!("{}/v1/users", app.server_url)).json(&reg_payload).send().await.unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("at least 12 characters"));

    // Try again with exactly 11 characters
    reg_payload["password"] = json!("12345678901");
    let resp = app.client.post(format!("{}/v1/users", app.server_url)).json(&reg_payload).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Try with exactly 12 characters (should pass)
    reg_payload["password"] = json!("123456789012");
    let resp = app.client.post(format!("{}/v1/users", app.server_url)).json(&reg_payload).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_request_id_propagation() {
    let app = common::TestApp::spawn().await;

    // 1. Client-provided Request ID
    let custom_id = "test-request-id-123";
    let resp = app
        .client
        .get(format!("{}/openapi.yaml", app.server_url))
        .header("x-request-id", custom_id)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.headers().get("x-request-id").unwrap(), custom_id);

    // 2. Server-generated Request ID
    let resp = app.client.get(format!("{}/openapi.yaml", app.server_url)).send().await.unwrap();

    assert!(resp.headers().contains_key("x-request-id"));
    let generated_id = resp.headers().get("x-request-id").unwrap().to_str().unwrap();
    assert!(!generated_id.is_empty());
    // Should be a UUID (approx check)
    assert_eq!(generated_id.split('-').count(), 5);
}

#[tokio::test]
async fn test_login_requires_matching_device_id() {
    let app = common::TestApp::spawn().await;
    let username = common::generate_username("login_device_id");

    // 1. Register and create a device (which gives us a valid device ID)
    let user = app.register_user_with_keys(&username, 123, 5).await;

    // 2. Login WITHOUT deviceId (should fail schema validation with 422)
    let login_payload_missing = json!({
        "username": username,
        "password": "password12345"
    });
    let resp_missing =
        app.client.post(format!("{}/v1/sessions", app.server_url)).json(&login_payload_missing).send().await.unwrap();
    assert_eq!(resp_missing.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // 3. Login with a deviceId that does not belong to the user (should return 409 Conflict)
    let login_payload_mismatch = json!({
        "username": username,
        "password": "password12345",
        "deviceId": uuid::Uuid::new_v4().to_string()
    });
    let resp_mismatch =
        app.client.post(format!("{}/v1/sessions", app.server_url)).json(&login_payload_mismatch).send().await.unwrap();
    assert_eq!(resp_mismatch.status(), StatusCode::CONFLICT);

    // 4. Login with a wrong password and a mismatched deviceId must return 401 (not 409)
    let login_payload_wrong_pw = json!({
        "username": username,
        "password": "wrongpassword123",
        "deviceId": uuid::Uuid::new_v4().to_string()
    });
    let resp_wrong_pw =
        app.client.post(format!("{}/v1/sessions", app.server_url)).json(&login_payload_wrong_pw).send().await.unwrap();
    assert_eq!(resp_wrong_pw.status(), StatusCode::UNAUTHORIZED);

    // 5. Login WITH matching deviceId (should return device session)
    let login_payload_device = json!({
        "username": username,
        "password": "password12345",
        "deviceId": user.device_id.to_string()
    });

    let resp_device =
        app.client.post(format!("{}/v1/sessions", app.server_url)).json(&login_payload_device).send().await.unwrap();

    assert_eq!(resp_device.status(), StatusCode::OK);
    let json_device: serde_json::Value = resp_device.json().await.unwrap();
    assert_eq!(
        json_device["deviceId"].as_str().unwrap(),
        user.device_id.to_string(),
        "Device login should return the correct deviceId"
    );
    assert!(json_device["refreshToken"].as_str().is_some());

    let device_token = json_device["token"].as_str().unwrap().to_string();

    // 6. Verify we can fetch keys
    let resp_keys = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, user.user_id))
        .header("Authorization", format!("Bearer {}", device_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_keys.status(), StatusCode::OK, "Should be able to use token on /keys");
}
