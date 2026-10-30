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
use uuid::Uuid;

mod common;

#[tokio::test]
async fn test_device_crud_lifecycle() {
    let app = common::TestApp::spawn().await;
    let username = common::generate_username("crud_device_user");

    // 1. Register user and primary device atomically
    let (reg_payload, identity_key) = common::generate_registration_payload(&username, "password12345", 111, 5);
    let resp_device1 = app.client.post(format!("{}/v1/users", app.server_url)).json(&reg_payload).send().await.unwrap();
    assert_eq!(resp_device1.status(), StatusCode::CREATED);

    let device1_json: serde_json::Value = resp_device1.json().await.unwrap();
    let device1_id = device1_json["deviceId"].as_str().unwrap().to_string();
    let device1_token = device1_json["token"].as_str().unwrap().to_string();

    // 2. Link Device 2 (with a name) through a link session the primary approved
    let link_session_id = app.create_link_session(&username).await;
    assert_eq!(app.approve_link_session(&device1_token, &link_session_id, b"message").await, StatusCode::OK);
    let mut dev2 = common::generate_device_payload_for(&identity_key, 222, 5);
    dev2["name"] = json!("My Phone");
    dev2["linkSessionId"] = json!(link_session_id);

    let resp_device2 = app.client.post(format!("{}/v1/devices", app.server_url)).json(&dev2).send().await.unwrap();

    assert_eq!(resp_device2.status(), StatusCode::CREATED);
    let device2_json: serde_json::Value = resp_device2.json().await.unwrap();
    let device2_id = device2_json["deviceId"].as_str().unwrap().to_string();

    // 3. List Devices (should show both, with only Device 1 primary)
    let resp_list = app
        .client
        .get(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {}", device1_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_list.status(), StatusCode::OK);
    let list_res: serde_json::Value = resp_list.json().await.unwrap();
    let list_devices = list_res["devices"].as_array().unwrap();
    assert_eq!(list_devices.len(), 2, "User should have 2 devices");

    let d1 = list_devices.iter().find(|d| d["deviceId"] == device1_id).unwrap();
    assert!(d1["name"].is_null(), "Device 1 should not have a name");
    assert_eq!(d1["isPrimary"], json!(true));

    let d2 = list_devices.iter().find(|d| d["deviceId"] == device2_id).unwrap();
    assert_eq!(d2["name"].as_str().unwrap(), "My Phone", "Device 2 should have the specified name");
    assert_eq!(d2["isPrimary"], json!(false));

    // 4. Send a message to Device 2 to verify cascade delete
    let device2_uuid = Uuid::parse_str(&device2_id).unwrap();
    let sender = app.register_user(&common::generate_username("crud_sender")).await;
    app.send_messages(&sender.token, &[(Uuid::parse_str(&device1_id).unwrap(), b"Ping"), (device2_uuid, b"Ping")])
        .await;
    app.assert_message_count(device2_uuid, 1).await;

    // 5. The primary deletes Device 2
    let resp_delete = app
        .client
        .delete(format!("{}/v1/devices/{}", app.server_url, device2_id))
        .header("Authorization", format!("Bearer {}", device1_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_delete.status(), StatusCode::OK);

    // 6. List devices again (should only have Device 1)
    let resp_list_after = app
        .client
        .get(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {}", device1_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_list_after.status(), StatusCode::OK);
    let list_res_after: serde_json::Value = resp_list_after.json().await.unwrap();
    let list_devices_after = list_res_after["devices"].as_array().unwrap();
    assert_eq!(list_devices_after.len(), 1, "User should have 1 device remaining");
    assert_eq!(list_devices_after[0]["deviceId"].as_str().unwrap(), device1_id);

    // 7. Verify cascade delete (keys and messages for Device 2 should be gone)
    let key_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM signed_pre_keys WHERE device_id = $1")
        .bind(device2_uuid)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(key_count, 0, "Signed pre-keys should be cascade deleted");

    app.assert_message_count(device2_uuid, 0).await;
}

#[tokio::test]
async fn test_device_limit_enforced() {
    let mut config = common::get_test_config();
    config.auth.max_devices_per_user = 3;
    let app = common::TestApp::spawn_with_config(config).await;

    // 1. A primary and two linked devices fill the limit
    let primary = app.register_user(&common::generate_username("dev_limit_user")).await;
    app.link_device(&primary).await;
    app.link_device(&primary).await;

    // 2. A 4th device is rejected even with an approved link session and the account identity
    let link_session_id = app.approved_link_session(&primary).await;
    let mut device4_payload = common::generate_device_payload_for(&primary.identity_key, 4, 5);
    device4_payload["linkSessionId"] = json!(link_session_id);
    let resp_device4 =
        app.client.post(format!("{}/v1/devices", app.server_url)).json(&device4_payload).send().await.unwrap();

    assert_eq!(resp_device4.status(), StatusCode::FORBIDDEN, "4th device should be rejected");

    let err_json: serde_json::Value = resp_device4.json().await.unwrap();
    assert_eq!(
        err_json["error"].as_str().unwrap(),
        "Device limit reached. Maximum allowed is 3.",
        "Should return correct error message"
    );
}
