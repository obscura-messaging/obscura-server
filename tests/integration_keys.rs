#![allow(
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

    let reg_payload = json!({
        "username": username,
        "password": "password12345",
        "registrationId": 123,
        "identityKey": STANDARD.encode(ik_pub_wire),
        "signedPreKey": {
            "keyId": 1,
            "publicKey": STANDARD.encode(spk_pub_wire),
            "signature": STANDARD.encode(signature)
        },
        "lastResortKyberPreKey": common::generate_kyber_pre_key(&identity_key, 1),
        "oneTimePreKeys": [],
        "kyberPreKeys": []
    });

    let resp = app.client.post(format!("{}/v1/users", app.server_url)).json(&reg_payload).send().await.unwrap();
    assert_eq!(resp.status(), 201, "Should accept 33-byte signed message");
}

#[tokio::test]
async fn test_format_pure_math_32_byte() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("pure_math");

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

    let reg_payload = json!({
        "username": username,
        "password": "password12345",
        "registrationId": 123,
        "identityKey": STANDARD.encode(ik_pub_wire),
        "signedPreKey": {
            "keyId": 1,
            "publicKey": STANDARD.encode(spk_pub_wire),
            "signature": STANDARD.encode(signature)
        },
        "lastResortKyberPreKey": common::generate_kyber_pre_key(&identity_key, 1),
        "oneTimePreKeys": [],
        "kyberPreKeys": []
    });

    let resp = app.client.post(format!("{}/v1/users", app.server_url)).json(&reg_payload).send().await.unwrap();
    assert_eq!(resp.status(), 201, "Should accept 32-byte signed message (Robust path)");
}

#[tokio::test]
async fn test_key_limit_enforced() {
    let mut config = common::get_test_config();
    config.messaging.max_pre_keys = std::num::NonZeroU32::new(50).unwrap();
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

    let refill_kyber = common::generate_kyber_pre_keys(&user.identity_key, 20_000, 20);
    let refill_payload = common::refill_payload(&user.identity_key, 2, &refill_keys, &refill_kyber);

    let resp = app
        .client
        .post(format!("{}/v1/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&refill_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM one_time_pre_keys WHERE device_id = $1")
        .bind(user.device_id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 50, "Total keys should be capped at 50");

    let kyber_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kyber_pre_keys WHERE device_id = $1")
        .bind(user.device_id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(kyber_count, 50, "Kyber keys are capped at 50 too");
}

#[tokio::test]
async fn test_key_rotation_monotonic_check() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("rotate");
    let user = app.register_user_with_keys(&username, 123, 0).await;

    // Rotate to 11
    let resp_11 = app
        .client
        .post(format!("{}/v1/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&common::refill_payload(&user.identity_key, 11, &[], &[]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_11.status(), 204);

    // Replay 10 (Fail - ID is smaller than current max)
    let resp_10 = app
        .client
        .post(format!("{}/v1/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&common::refill_payload(&user.identity_key, 10, &[], &[]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_10.status(), 400);
}

#[tokio::test]
async fn test_key_rotation_cleanup() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("cleanup");
    let user = app.register_user_with_keys(&username, 123, 0).await;

    // Rotate to ID 10
    let resp = app
        .client
        .post(format!("{}/v1/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&common::refill_payload(&user.identity_key, 10, &[], &[]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

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

    let last_resort: Vec<i32> = sqlx::query_scalar("SELECT id FROM kyber_last_resort_pre_keys WHERE device_id = $1")
        .bind(user.device_id)
        .fetch_all(&app.pool)
        .await
        .unwrap();
    assert_eq!(last_resort, vec![10], "The last-resort Kyber pre-key is replaced, not added to");
}

#[tokio::test]
async fn test_prekey_status_low_keys() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("status_low");
    let user = app.register_user_with_keys(&username, 123, 0).await;
    let mut ws = app.connect_ws(&user.token).await;
    let status = ws.receive_prekey_status().await.expect("Did not receive PreKeyStatus");
    assert_eq!(status.one_time_pre_key_count, 0);
    assert_eq!(status.one_time_kyber_pre_key_count, 0);
}

#[tokio::test]
async fn test_prekey_status_reports_low_kyber_pool() {
    let app = TestApp::spawn().await;
    let user = app.register_user_with_keys(&common::generate_username("status_kyber"), 123, 0).await;
    let one_time: Vec<_> = (0..30).map(|i| json!({ "keyId": i, "publicKey": STANDARD.encode([0x05; 33]) })).collect();
    let resp = app
        .client
        .post(format!("{}/v1/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&common::refill_payload(&user.identity_key, 2, &one_time, &[]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let mut ws = app.connect_ws(&user.token).await;
    let status = ws.receive_prekey_status().await.expect("a low Kyber pool alone is reported");
    assert_eq!(status.one_time_pre_key_count, 30);
    assert_eq!(status.one_time_kyber_pre_key_count, 0);
}

#[tokio::test]
async fn test_upload_keys_verified_against_account_identity() {
    let app = TestApp::spawn().await;
    let user = app.register_user_with_keys(&common::generate_username("ik_upload"), 111, 1).await;
    let upload = |identity_key: &[u8; 32], key_id: i32| common::refill_payload(identity_key, key_id, &[], &[]);

    let other_identity = common::generate_signing_key();
    let resp = app
        .client
        .post(format!("{}/v1/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&upload(&other_identity, 2))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "A signed pre-key from another identity must not verify");

    let resp = app
        .client
        .post(format!("{}/v1/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&upload(&user.identity_key, 2))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn test_upload_keys_bad_signature() {
    let app = TestApp::spawn().await;
    let username = common::generate_username("bad_sig");
    let user = app.register_user(&username).await;

    let mut payload = common::refill_payload(&user.identity_key, 5, &[], &[]);
    payload["signedPreKey"]["signature"] = json!(STANDARD.encode([0x00; 64])); // Invalid

    let resp = app
        .client
        .post(format!("{}/v1/keys", app.server_url))
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

    // 2. Link a second device
    let device2 = app.link_device(&user).await;
    let device2_id = device2.device_id.to_string();

    // 3. Fetch keys with the first device's token
    let fetch_resp = app
        .client
        .get(format!("{}/v1/keys/{}", app.server_url, user.user_id))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();
    assert_eq!(fetch_resp.status(), 200);

    let body: serde_json::Value = fetch_resp.json().await.unwrap();
    let bundles = body["bundles"].as_array().expect("bundles array should be present");

    // We expect exactly 2 bundles, one for each device
    assert_eq!(bundles.len(), 2, "Should return an array of 2 bundles");

    let d1_bundle = bundles.iter().find(|b| b["deviceId"] == user.device_id.to_string());
    assert!(d1_bundle.is_some(), "Bundle for device 1 not found");
    let d2_bundle = bundles.iter().find(|b| b["deviceId"] == device2_id);
    assert!(d2_bundle.is_some(), "Bundle for device 2 not found");

    // Every bundle carries the account identity key; registration ids stay per device
    let account_identity = common::identity_public_key(&user.identity_key);
    assert!(bundles.iter().all(|b| b["identityKey"] == account_identity.as_str()));
    assert_eq!(d1_bundle.unwrap()["registrationId"], 111);
    assert_eq!(d2_bundle.unwrap()["registrationId"], 456);
}

#[tokio::test]
async fn test_fetch_one_device_bundle_consumes_only_that_device() {
    let app = TestApp::spawn().await;
    let user = app.register_user_with_keys(&common::generate_username("one_dev"), 111, 10).await;
    let linked = app.link_device(&user).await;
    let other = app.register_user(&common::generate_username("one_dev_other")).await;
    let remaining = |device_id: uuid::Uuid| {
        let pool = app.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM one_time_pre_keys WHERE device_id = $1")
                .bind(device_id)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    let fetch = |owner: uuid::Uuid, device: uuid::Uuid, token: String| {
        app.client
            .get(format!("{}/v1/keys/{owner}/devices/{device}", app.server_url))
            .header("Authorization", format!("Bearer {token}"))
            .send()
    };
    let before_primary = remaining(user.device_id).await;

    let resp = fetch(user.user_id, linked.device_id, other.token.clone()).await.unwrap();
    assert_eq!(resp.status(), 200);
    let bundle: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(bundle["deviceId"], linked.device_id.to_string());
    assert!(bundle["oneTimePreKey"].is_object(), "the linked device's one-time prekey is returned");
    assert_eq!(remaining(linked.device_id).await, 0);
    assert_eq!(remaining(user.device_id).await, before_primary, "other devices keep their one-time prekeys");

    let resp = fetch(other.user_id, linked.device_id, other.token.clone()).await.unwrap();
    assert_eq!(resp.status(), 404, "a device of another user is not found");
}

#[tokio::test]
async fn test_pre_key_batch_size_limit() {
    let mut config = common::get_test_config();
    config.messaging.max_pre_keys = std::num::NonZeroU32::new(50).unwrap();
    let app = TestApp::spawn_with_config(config).await;
    let user = app.register_user_with_keys(&common::generate_username("batch"), 123, 1).await;

    let upload = |count: i32| {
        let keys: Vec<_> =
            (100..100 + count).map(|i| json!({ "keyId": i, "publicKey": STANDARD.encode([0x05; 33]) })).collect();
        let payload = common::refill_payload(&user.identity_key, 2, &keys, &[]);
        app.client
            .post(format!("{}/v1/keys", app.server_url))
            .header("Authorization", format!("Bearer {}", user.token))
            .json(&payload)
            .send()
    };

    let resp = upload(51).await.unwrap();
    assert_eq!(resp.status(), 400, "a batch over max_pre_keys is rejected");

    let resp = upload(50).await.unwrap();
    assert_eq!(resp.status(), 204, "a batch of exactly max_pre_keys is accepted");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM one_time_pre_keys WHERE device_id = $1")
        .bind(user.device_id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 50);
}

#[tokio::test]
async fn test_kyber_batch_size_limit() {
    let mut config = common::get_test_config();
    config.messaging.max_pre_keys = std::num::NonZeroU32::new(50).unwrap();
    let app = TestApp::spawn_with_config(config).await;
    let user = app.register_user_with_keys(&common::generate_username("kyber_batch"), 123, 1).await;

    let kyber = common::generate_kyber_pre_keys(&user.identity_key, 100, 51);
    let resp = app
        .client
        .post(format!("{}/v1/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&common::refill_payload(&user.identity_key, 2, &[], &kyber))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "a Kyber batch over max_pre_keys is rejected");
}

#[tokio::test]
async fn test_bundle_serves_one_time_kyber_key_then_last_resort() {
    let app = TestApp::spawn().await;
    let user = app.register_user_with_keys(&common::generate_username("kyber_bundle"), 111, 1).await;
    let fetcher = app.register_user(&common::generate_username("kyber_fetcher")).await;
    let fetch = || async {
        let resp = app
            .client
            .get(format!("{}/v1/keys/{}/devices/{}", app.server_url, user.user_id, user.device_id))
            .header("Authorization", format!("Bearer {}", fetcher.token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        resp.json::<serde_json::Value>().await.unwrap()
    };

    let first = fetch().await;
    assert_eq!(first["kyberPreKey"]["keyId"], common::KYBER_ONE_TIME_ID_OFFSET, "the one-time key comes first");
    let public_key = STANDARD.decode(first["kyberPreKey"]["publicKey"].as_str().unwrap()).unwrap();
    assert_eq!((public_key.len(), public_key[0]), (1569, 0x08), "a prefixed Kyber1024 key");
    assert_eq!(STANDARD.decode(first["kyberPreKey"]["signature"].as_str().unwrap()).unwrap().len(), 64);

    for _ in 0..2 {
        let next = fetch().await;
        assert_eq!(next["kyberPreKey"]["keyId"], 1, "then the last-resort key, which is never consumed");
        assert!(next["oneTimePreKey"].is_null(), "the EC pool is empty too");
    }
}

#[tokio::test]
async fn test_upload_kyber_key_from_other_identity_rejected() {
    let app = TestApp::spawn().await;
    let user = app.register_user_with_keys(&common::generate_username("kyber_forged"), 111, 0).await;
    let other_identity = common::generate_signing_key();

    let mut payload = common::refill_payload(&user.identity_key, 2, &[], &[]);
    payload["kyberPreKeys"] = json!([common::generate_kyber_pre_key(&other_identity, 50)]);
    let resp = app
        .client
        .post(format!("{}/v1/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "a one-time Kyber key signed by another identity must not verify");

    let mut payload = common::refill_payload(&user.identity_key, 2, &[], &[]);
    payload["lastResortKyberPreKey"] = common::generate_kyber_pre_key(&other_identity, 2);
    let resp = app
        .client
        .post(format!("{}/v1/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "a last-resort Kyber key signed by another identity must not verify");

    let signed: Vec<i32> = sqlx::query_scalar("SELECT id FROM signed_pre_keys WHERE device_id = $1")
        .bind(user.device_id)
        .fetch_all(&app.pool)
        .await
        .unwrap();
    assert_eq!(signed, vec![1], "a rejected upload stores nothing");
}

#[tokio::test]
async fn test_registration_requires_kyber_keys() {
    let app = TestApp::spawn().await;
    let (mut payload, _) =
        common::generate_registration_payload(&common::generate_username("no_kyber"), "password12345", 1, 0);
    payload.as_object_mut().unwrap().remove("lastResortKyberPreKey");
    let resp = app.client.post(format!("{}/v1/users", app.server_url)).json(&payload).send().await.unwrap();
    assert!(resp.status().is_client_error(), "registration without a last-resort Kyber key is rejected");
    assert_ne!(resp.status(), 201);
}
