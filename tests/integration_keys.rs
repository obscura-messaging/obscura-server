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
use common::TestApp;
use serde_json::json;
use xeddsa::xed25519::PrivateKey;
use xeddsa::{CalculateKeyPair, Sign};

#[tokio::test]
async fn test_format_typescript_standard() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("ts_std");

    // Step 1: Register user (auth-only)
    let reg_payload = json!({
        "username": username,
        "password": "password12345",
    });
    let resp = app.client.post(format!("{}/v1/users", app.server_url)).json(&reg_payload).send().await.unwrap();
    assert_eq!(resp.status(), 201);
    let user_token = resp.json::<serde_json::Value>().await.unwrap()["token"].as_str().unwrap().to_string();

    // Step 2: Create device with 33-byte key format
    let identity_key = common::generate_signing_key();
    let ik_priv = PrivateKey(identity_key);
    let (_, ik_pub_ed) = ik_priv.calculate_key_pair(0);
    let ik_pub_mont =
        curve25519_dalek::edwards::CompressedEdwardsY(ik_pub_ed).decompress().unwrap().to_montgomery().to_bytes();
    let mut ik_pub_wire = [0u8; 33];
    ik_pub_wire[0] = 0x05;
    ik_pub_wire[1..].copy_from_slice(&ik_pub_mont);

    let spk_bytes = common::generate_signing_key();
    let spk_priv = PrivateKey(spk_bytes);
    let (_, spk_pub_ed) = spk_priv.calculate_key_pair(0);
    let spk_pub_mont =
        curve25519_dalek::edwards::CompressedEdwardsY(spk_pub_ed).decompress().unwrap().to_montgomery().to_bytes();
    let mut spk_pub_wire = [0u8; 33];
    spk_pub_wire[0] = 0x05;
    spk_pub_wire[1..].copy_from_slice(&spk_pub_mont);

    let mut rng = rand::rng();
    let signature: [u8; 64] = ik_priv.sign(&spk_pub_wire, &mut rng);

    let device_payload = json!({
        "registrationId": 123,
        "identityKey": STANDARD.encode(ik_pub_wire),
        "signedPreKey": {
            "keyId": 1,
            "publicKey": STANDARD.encode(spk_pub_wire),
            "signature": STANDARD.encode(signature)
        },
        "oneTimePreKeys": []
    });

    let resp = app
        .client
        .post(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {user_token}"))
        .json(&device_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "Should accept 33-byte signed message");
}

#[tokio::test]
async fn test_format_pure_math_32_byte() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("pure_math");

    // Step 1: Register
    let reg_payload = json!({
        "username": username,
        "password": "password12345",
    });
    let resp = app.client.post(format!("{}/v1/users", app.server_url)).json(&reg_payload).send().await.unwrap();
    assert_eq!(resp.status(), 201);
    let user_token = resp.json::<serde_json::Value>().await.unwrap()["token"].as_str().unwrap().to_string();

    // Step 2: Create device with 32-byte signed message (Robust path)
    let identity_key = common::generate_signing_key();
    let ik_priv = PrivateKey(identity_key);
    let (_, ik_pub_ed) = ik_priv.calculate_key_pair(0);
    let ik_pub_mont =
        curve25519_dalek::edwards::CompressedEdwardsY(ik_pub_ed).decompress().unwrap().to_montgomery().to_bytes();
    let mut ik_pub_wire = [0u8; 33];
    ik_pub_wire[0] = 0x05;
    ik_pub_wire[1..].copy_from_slice(&ik_pub_mont);

    let spk_bytes = common::generate_signing_key();
    let spk_priv = PrivateKey(spk_bytes);
    let (_, spk_pub_ed) = spk_priv.calculate_key_pair(0);
    let spk_pub_mont =
        curve25519_dalek::edwards::CompressedEdwardsY(spk_pub_ed).decompress().unwrap().to_montgomery().to_bytes();
    let mut spk_pub_wire = [0u8; 33];
    spk_pub_wire[0] = 0x05;
    spk_pub_wire[1..].copy_from_slice(&spk_pub_mont);

    let mut rng = rand::rng();
    let signature: [u8; 64] = ik_priv.sign(&spk_pub_mont, &mut rng);

    let device_payload = json!({
        "registrationId": 123,
        "identityKey": STANDARD.encode(ik_pub_wire),
        "signedPreKey": {
            "keyId": 1,
            "publicKey": STANDARD.encode(spk_pub_wire),
            "signature": STANDARD.encode(signature)
        },
        "oneTimePreKeys": []
    });

    let resp = app
        .client
        .post(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {user_token}"))
        .json(&device_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "Should accept 32-byte signed message (Robust path)");
}

#[tokio::test]
async fn test_key_limit_enforced() {
    let mut config = common::get_test_config();
    config.messaging.max_pre_keys = 50;
    let app = TestApp::spawn_with_config(config).await;

    let username = common::generate_username("limit");
    // register_user_with_keys does two-step: register + create device with 40 OTPKs
    let user = app.register_user_with_keys(&username, 123, 40).await;

    let mut refill_keys = Vec::new();
    for i in 40..60 {
        refill_keys.push(json!({
            "keyId": i,
            "publicKey": STANDARD.encode([0x05; 33])
        }));
    }

    let (new_spk_pub, new_spk_sig) = common::generate_signed_pre_key(&user.identity_key);
    let refill_payload = json!({
        "registrationId": 123,
        "signedPreKey": {
            "keyId": 2,
            "publicKey": STANDARD.encode(&new_spk_pub),
            "signature": STANDARD.encode(&new_spk_sig)
        },
        "oneTimePreKeys": refill_keys
    });

    let resp = app
        .client
        .post(format!("{}/v1/devices/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&refill_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM one_time_pre_keys WHERE device_id = $1")
        .bind(user.device_id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 50, "Total keys should be capped at 50");
}

#[tokio::test]
async fn test_key_rotation_monotonic_check() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("rotate");
    let user = app.register_user_with_keys(&username, 123, 0).await;

    // Rotate to 11
    let (spk_pub_11, spk_sig_11) = common::generate_signed_pre_key(&user.identity_key);
    let resp_11 = app.client.post(format!("{}/v1/devices/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&json!({
            "registrationId": 123,
            "signedPreKey": { "keyId": 11, "publicKey": STANDARD.encode(&spk_pub_11), "signature": STANDARD.encode(&spk_sig_11) },
            "oneTimePreKeys": []
        })).send().await.unwrap();
    assert_eq!(resp_11.status(), 200);

    // Replay 10 (Fail - ID is smaller than current max)
    let (spk_pub_10, spk_sig_10) = common::generate_signed_pre_key(&user.identity_key);
    let resp_10 = app.client.post(format!("{}/v1/devices/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&json!({
            "registrationId": 123,
            "signedPreKey": { "keyId": 10, "publicKey": STANDARD.encode(&spk_pub_10), "signature": STANDARD.encode(&spk_sig_10) },
            "oneTimePreKeys": []
        })).send().await.unwrap();
    assert_eq!(resp_10.status(), 400);
}

#[tokio::test]
async fn test_key_rotation_cleanup() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("cleanup");
    let user = app.register_user_with_keys(&username, 123, 0).await;

    // Rotate to ID 10
    let (spk_pub, spk_sig) = common::generate_signed_pre_key(&user.identity_key);
    app.client.post(format!("{}/v1/devices/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&json!({
            "registrationId": 123,
            "signedPreKey": { "keyId": 10, "publicKey": STANDARD.encode(&spk_pub), "signature": STANDARD.encode(&spk_sig) },
            "oneTimePreKeys": []
        })).send().await.unwrap();

    // Verify DB
    let count_1: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM signed_pre_keys WHERE device_id = $1 AND id = 1")
        .bind(user.device_id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count_1, 0, "Old key ID 1 should be deleted");

    let count_10: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM signed_pre_keys WHERE device_id = $1 AND id = 10")
        .bind(user.device_id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count_10, 1, "New key ID 10 should exist");
}

#[tokio::test]
async fn test_prekey_status_low_keys() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("status_low");
    let user = app.register_user_with_keys(&username, 123, 0).await;
    let mut ws = app.connect_ws(&user.token).await;
    let status = ws.receive_prekey_status().await.expect("Did not receive PreKeyStatus");
    assert_eq!(status.one_time_pre_key_count, 0);
}

#[tokio::test]
async fn test_device_takeover_success() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("takeover");
    let user = app.register_user_with_keys(&username, 111, 1).await;
    let sender = app.register_user(&common::generate_username("takeover_sender")).await;

    app.send_message(&sender.token, user.device_id, b"hello").await;

    let new_identity_key = common::generate_signing_key();
    let (new_spk_pub, new_spk_sig) = common::generate_signed_pre_key(&new_identity_key);
    let (_, ik_pub_ed) = PrivateKey(new_identity_key).calculate_key_pair(0);
    let mut new_ik_wire = curve25519_dalek::edwards::CompressedEdwardsY(ik_pub_ed)
        .decompress()
        .unwrap()
        .to_montgomery()
        .to_bytes()
        .to_vec();
    new_ik_wire.insert(0, 0x05);

    let resp = app.client.post(format!("{}/v1/devices/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&json!({
            "identityKey": STANDARD.encode(&new_ik_wire),
            "registrationId": 456,
            "signedPreKey": { "keyId": 2, "publicKey": STANDARD.encode(&new_spk_pub), "signature": STANDARD.encode(&new_spk_sig) },
            "oneTimePreKeys": []
        })).send().await.unwrap();

    assert_eq!(resp.status(), 200);

    // Verify inbox is WIPED on takeover
    app.assert_message_count(user.device_id, 0).await;
}

#[tokio::test]
async fn test_upload_keys_bad_signature() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("bad_sig");
    let user = app.register_user(&username).await;

    let payload = json!({
        "signedPreKey": {
            "keyId": 5,
            "publicKey": STANDARD.encode([0x05; 33]),
            "signature": STANDARD.encode([0x00; 64]) // Invalid
        },
        "oneTimePreKeys": []
    });

    let resp = app
        .client
        .post(format!("{}/v1/devices/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fetch_keys_multiple_devices() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("multi_dev");

    // 1. Register user and create first device
    let user = app.register_user_with_keys(&username, 111, 10).await;

    // 2. Login to get a user-scoped token (no device_id)
    let login_payload = json!({
        "username": username,
        "password": "password12345"
    });
    let login_resp =
        app.client.post(format!("{}/v1/sessions", app.server_url)).json(&login_payload).send().await.unwrap();
    assert_eq!(login_resp.status(), 200);
    let user_token = login_resp.json::<serde_json::Value>().await.unwrap()["token"].as_str().unwrap().to_string();

    // 3. Create a second device using the user-scoped token
    let (device2_payload, _) = common::generate_device_payload(222, 10);
    let device2_resp = app
        .client
        .post(format!("{}/v1/devices", app.server_url))
        .header("Authorization", format!("Bearer {}", user_token))
        .json(&device2_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(device2_resp.status(), 201);

    let device2_id = device2_resp.json::<serde_json::Value>().await.unwrap()["deviceId"].as_str().unwrap().to_string();

    // 4. Verify that fetching keys with a user-scoped token fails (requires device-scoped)
    let failed_fetch_resp = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, user.user_id))
        .header("Authorization", format!("Bearer {}", user_token))
        .send()
        .await
        .unwrap();
    assert_eq!(failed_fetch_resp.status(), 403, "Should reject user-scoped token");

    // 5. Fetch keys with the first device's device-scoped token
    let fetch_resp = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, user.user_id))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();
    assert_eq!(fetch_resp.status(), 200);

    let bundles: Vec<serde_json::Value> = fetch_resp.json().await.unwrap();

    // We expect exactly 2 bundles, one for each device
    assert_eq!(bundles.len(), 2, "Should return an array of 2 bundles");

    let d1_bundle = bundles.iter().find(|b| b["deviceId"] == user.device_id.to_string());
    assert!(d1_bundle.is_some(), "Bundle for device 1 not found");
    let d2_bundle = bundles.iter().find(|b| b["deviceId"] == device2_id);
    assert!(d2_bundle.is_some(), "Bundle for device 2 not found");
}
