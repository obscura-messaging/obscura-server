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

    // 1. Register User directly (no devices yet)
    let payload = json!({
        "username": username,
        "password": "password12345",
    });

    let resp_user = app.client.post(format!("{}/v1/users", app.server_url)).json(&payload).send().await.unwrap();
    assert_eq!(resp_user.status(), StatusCode::CREATED);

    let json_user: serde_json::Value = resp_user.json().await.unwrap();
    let user_token = json_user["token"].as_str().unwrap().to_string();

    // 2. List devices (should be empty initially)
    let resp_list_empty = app
        .client
        .get(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {}", user_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_list_empty.status(), StatusCode::OK);
    let list_empty_res: serde_json::Value = resp_list_empty.json().await.unwrap();
    let list_empty = list_empty_res["devices"].as_array().unwrap();
    assert!(list_empty.is_empty(), "User should have no devices initially");

    // 3. Create the primary device
    let (device1_payload, identity_key) = common::generate_device_payload(111, 5);
    let resp_device1 = app
        .client
        .post(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {}", user_token))
        .json(&device1_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp_device1.status(), StatusCode::CREATED);
    let device1_json: serde_json::Value = resp_device1.json().await.unwrap();
    let device1_id = device1_json["deviceId"].as_str().unwrap().to_string();
    let device1_token = device1_json["token"].as_str().unwrap().to_string();

    // 4. Link Device 2 (with a name) through a link session the primary approved
    let link_session_id = app.create_link_session(&user_token).await;
    assert_eq!(app.approve_link_session(&device1_token, &link_session_id, b"message").await, StatusCode::OK);
    let mut dev2 = common::generate_device_payload_for(&identity_key, 222, 5);
    dev2["name"] = json!("My Phone");
    dev2["linkSessionId"] = json!(link_session_id);

    let resp_device2 = app
        .client
        .post(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {}", user_token))
        .json(&dev2)
        .send()
        .await
        .unwrap();

    assert_eq!(resp_device2.status(), StatusCode::CREATED);
    let device2_json: serde_json::Value = resp_device2.json().await.unwrap();
    let device2_id = device2_json["deviceId"].as_str().unwrap().to_string();

    // 5. List Devices (should show both, with only Device 1 primary)
    let resp_list = app
        .client
        .get(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {}", user_token))
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

    // 6. Send a message to Device 2 to verify cascade delete
    let device2_uuid = Uuid::parse_str(&device2_id).unwrap();
    let sender = app.register_user(&common::generate_username("crud_sender")).await;
    app.send_messages(&sender.token, &[(Uuid::parse_str(&device1_id).unwrap(), b"Ping"), (device2_uuid, b"Ping")])
        .await;
    app.assert_message_count(device2_uuid, 1).await;

    // 7. The primary deletes Device 2
    let resp_delete = app
        .client
        .delete(format!("{}/v1/devices/{}", app.server_url, device2_id))
        .header("Authorization", format!("Bearer {}", device1_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_delete.status(), StatusCode::OK);

    // 8. List devices again (should only have Device 1)
    let resp_list_after = app
        .client
        .get(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {}", user_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_list_after.status(), StatusCode::OK);
    let list_res_after: serde_json::Value = resp_list_after.json().await.unwrap();
    let list_devices_after = list_res_after["devices"].as_array().unwrap();
    assert_eq!(list_devices_after.len(), 1, "User should have 1 device remaining");
    assert_eq!(list_devices_after[0]["deviceId"].as_str().unwrap(), device1_id);

    // 9. Verify cascade delete (keys and messages for Device 2 should be gone)
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
    let (user_token, link_session_id) = app.approved_link_session(&primary).await;
    let mut device4_payload = common::generate_device_payload_for(&primary.identity_key, 4, 5);
    device4_payload["linkSessionId"] = json!(link_session_id);
    let resp_device4 = app
        .client
        .post(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {}", user_token))
        .json(&device4_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp_device4.status(), StatusCode::FORBIDDEN, "4th device should be rejected");

    let err_json: serde_json::Value = resp_device4.json().await.unwrap();
    assert_eq!(
        err_json["error"].as_str().unwrap(),
        "Device limit reached. Maximum allowed is 3.",
        "Should return correct error message"
    );
}

#[tokio::test]
async fn test_get_and_put_device() {
    let app = common::TestApp::spawn().await;
    let username = common::generate_username("get_put_device_user");

    // 1. Register User
    let payload = json!({
        "username": username,
        "password": "password12345",
    });

    let resp_user = app.client.post(format!("{}/v1/users", app.server_url)).json(&payload).send().await.unwrap();
    let json_user: serde_json::Value = resp_user.json().await.unwrap();
    let user_token = json_user["token"].as_str().unwrap().to_string();

    // 2. Create Device
    let (device_payload, _) = common::generate_device_payload(111, 5);
    let resp_device = app
        .client
        .post(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {}", user_token))
        .json(&device_payload)
        .send()
        .await
        .unwrap();

    let device_json: serde_json::Value = resp_device.json().await.unwrap();
    let device_id = device_json["deviceId"].as_str().unwrap().to_string();

    // 3. GET Device (verify it returns successfully)
    let resp_get = app
        .client
        .get(format!("{}/v1/devices/{}", app.server_url, device_id))
        .header("Authorization", format!("Bearer {}", user_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_get.status(), StatusCode::OK);
    let get_json: serde_json::Value = resp_get.json().await.unwrap();
    assert_eq!(get_json["deviceId"].as_str().unwrap(), device_id);
    assert!(get_json["name"].is_null(), "Device should not have a name initially");

    // 4. PUT Device (update name)
    let update_payload = json!({
        "name": "Updated Phone"
    });

    let resp_put = app
        .client
        .put(format!("{}/v1/devices/{}", app.server_url, device_id))
        .header("Authorization", format!("Bearer {}", user_token))
        .json(&update_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp_put.status(), StatusCode::OK);
    let put_json: serde_json::Value = resp_put.json().await.unwrap();
    assert_eq!(put_json["deviceId"].as_str().unwrap(), device_id);
    assert_eq!(put_json["name"].as_str().unwrap(), "Updated Phone");

    // 5. GET Device again (verify name stuck)
    let resp_get_after = app
        .client
        .get(format!("{}/v1/devices/{}", app.server_url, device_id))
        .header("Authorization", format!("Bearer {}", user_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_get_after.status(), StatusCode::OK);
    let get_after_json: serde_json::Value = resp_get_after.json().await.unwrap();
    assert_eq!(get_after_json["name"].as_str().unwrap(), "Updated Phone");

    // 6. Target another user's device (should be 404 Not Found)
    let other_user = app.register_user(&common::generate_username("other_user")).await;
    let other_device_id = other_user.device_id;

    // Try to get other user's device with original user's token
    let resp_get_unauth = app
        .client
        .get(format!("{}/v1/devices/{}", app.server_url, other_device_id))
        .header("Authorization", format!("Bearer {}", user_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_get_unauth.status(), StatusCode::NOT_FOUND);

    // Try to put other user's device with original user's token
    let resp_put_unauth = app
        .client
        .put(format!("{}/v1/devices/{}", app.server_url, other_device_id))
        .header("Authorization", format!("Bearer {}", user_token))
        .json(&update_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp_put_unauth.status(), StatusCode::NOT_FOUND);
}
