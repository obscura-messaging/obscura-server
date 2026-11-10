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

#[tokio::test]
async fn test_upload_replaces_one_time_keys() {
    let app = TestApp::spawn().await;
    let user = app.register_user_with_keys(&common::generate_username("replace"), 123, 40).await;

    let refill_keys: Vec<_> =
        (40..60).map(|i| json!({ "keyId": i, "publicKey": STANDARD.encode([0x05; 33]) })).collect();
    let refill_kyber = common::generate_kyber_pre_keys(&user.identity_key, 20_000, 20);
    let resp = app
        .client
        .post(format!("{}/v1/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&common::refill_payload(&user.identity_key, 2, &refill_keys, &refill_kyber))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let ids = |table: &'static str| {
        let pool = app.pool.clone();
        let device_id = user.device_id;
        async move {
            sqlx::query_scalar::<_, i32>(&format!("SELECT id FROM {table} WHERE device_id = $1 ORDER BY id"))
                .bind(device_id)
                .fetch_all(&pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(ids("one_time_pre_keys").await, (40..60).collect::<Vec<_>>(), "the 40 old EC keys are replaced");
    assert_eq!(ids("kyber_pre_keys").await, (20_000..20_020).collect::<Vec<_>>(), "and so are the Kyber keys");
}

#[tokio::test]
async fn test_upload_leaves_absent_parts_alone() {
    let app = TestApp::spawn().await;
    let user = app.register_user_with_keys(&common::generate_username("partial"), 123, 5).await;
    let upload = |body: serde_json::Value| {
        app.client
            .post(format!("{}/v1/keys", app.server_url))
            .header("Authorization", format!("Bearer {}", user.token))
            .json(&body)
            .send()
    };
    let snapshot = || {
        let pool = app.pool.clone();
        let device_id = user.device_id;
        async move {
            let count = |table: &str| format!("(SELECT COUNT(*) FROM {table} WHERE device_id = $1)");
            sqlx::query_as::<_, (i32, i32, i64, i64)>(&format!(
                "SELECT (SELECT MAX(id) FROM signed_pre_keys WHERE device_id = $1), \
                        (SELECT id FROM kyber_last_resort_pre_keys WHERE device_id = $1), {}, {}",
                count("one_time_pre_keys"),
                count("kyber_pre_keys")
            ))
            .bind(device_id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    assert_eq!(snapshot().await, (1, 1, 5, 5));

    assert_eq!(upload(json!({})).await.unwrap().status(), 204, "an empty upload is a no-op, as in Signal");
    assert_eq!(snapshot().await, (1, 1, 5, 5));

    let kyber = common::generate_kyber_pre_keys(&user.identity_key, 500, 3);
    assert_eq!(upload(json!({ "kyberPreKeys": kyber })).await.unwrap().status(), 204);
    assert_eq!(snapshot().await, (1, 1, 5, 3), "only the Kyber pool changed");

    let rotation = json!({ "lastResortKyberPreKey": common::generate_kyber_pre_key(&user.identity_key, 7) });
    assert_eq!(upload(rotation).await.unwrap().status(), 204);
    assert_eq!(snapshot().await, (1, 7, 5, 3), "only the last-resort key rotated");
}

#[tokio::test]
async fn test_rotation_replaces_signed_and_last_resort_keys() {
    let app = TestApp::spawn().await;
    let user = app.register_user_with_keys(&common::generate_username("rotate"), 123, 0).await;
    let current = || {
        let pool = app.pool.clone();
        let device_id = user.device_id;
        async move {
            let signed: Vec<i32> = sqlx::query_scalar("SELECT id FROM signed_pre_keys WHERE device_id = $1")
                .bind(device_id)
                .fetch_all(&pool)
                .await
                .unwrap();
            let last_resort: Vec<i32> =
                sqlx::query_scalar("SELECT id FROM kyber_last_resort_pre_keys WHERE device_id = $1")
                    .bind(device_id)
                    .fetch_all(&pool)
                    .await
                    .unwrap();
            (signed, last_resort)
        }
    };

    // Signal clients count IDs up from a random start and wrap at 2^24 - 1, so a new key's ID may be lower than
    // the old one's. Each rotation simply replaces the device's single signed and last-resort key.
    for key_id in [16_777_214, 3] {
        let resp = app
            .client
            .post(format!("{}/v1/keys", app.server_url))
            .header("Authorization", format!("Bearer {}", user.token))
            .json(&common::refill_payload(&user.identity_key, key_id, &[], &[]))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);
        assert_eq!(current().await, (vec![key_id], vec![key_id]), "one of each, the latest");
    }
}

#[tokio::test]
async fn test_pre_key_counts_track_uploads_and_fetches() {
    let app = TestApp::spawn().await;
    let user = app.register_user_with_keys(&common::generate_username("counts"), 123, 3).await;
    let fetcher = app.register_user(&common::generate_username("counts_fetcher")).await;
    let counts = || async {
        let resp = app
            .client
            .get(format!("{}/v1/keys", app.server_url))
            .header("Authorization", format!("Bearer {}", user.token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        (body["oneTimePreKeyCount"].as_u64().unwrap(), body["kyberPreKeyCount"].as_u64().unwrap())
    };
    assert_eq!(counts().await, (3, 3));

    let resp = app
        .client
        .get(format!("{}/v1/keys/{}/devices/{}", app.server_url, user.user_id, user.device_id))
        .header("Authorization", format!("Bearer {}", fetcher.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(counts().await, (2, 2), "a bundle fetch consumes one of each");

    let kyber = common::generate_kyber_pre_keys(&user.identity_key, 500, 10);
    let resp = app
        .client
        .post(format!("{}/v1/keys", app.server_url))
        .header("Authorization", format!("Bearer {}", user.token))
        .json(&json!({ "kyberPreKeys": kyber }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(counts().await, (2, 10), "a refill replaces that pool only");
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
    let app = TestApp::spawn().await;
    let user = app.register_user_with_keys(&common::generate_username("batch"), 123, 1).await;
    let upload = |ec: usize, kyber: usize| {
        let keys: Vec<_> = (0..ec).map(|i| json!({ "keyId": i, "publicKey": STANDARD.encode([0x05; 33]) })).collect();
        let kyber = common::generate_kyber_pre_keys(&user.identity_key, 1000, kyber);
        app.client
            .post(format!("{}/v1/keys", app.server_url))
            .header("Authorization", format!("Bearer {}", user.token))
            .json(&json!({ "oneTimePreKeys": keys, "kyberPreKeys": kyber }))
            .send()
    };

    assert_eq!(upload(101, 0).await.unwrap().status(), 400, "101 EC keys are over Signal's limit of 100");
    assert_eq!(upload(0, 101).await.unwrap().status(), 400, "and so are 101 Kyber keys");
    assert_eq!(upload(100, 100).await.unwrap().status(), 204, "exactly 100 of each is accepted");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM one_time_pre_keys WHERE device_id = $1")
        .bind(user.device_id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 100);
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

/// GETs `path` (under `/v1/keys/`) as `token` and returns the status and `Retry-After` header.
async fn fetch_bundle(app: &TestApp, token: &str, path: &str) -> (reqwest::StatusCode, Option<u64>) {
    let resp = app
        .client
        .get(format!("{}/v1/keys/{path}", app.server_url))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("bundle request");
    let retry_after = resp
        .headers()
        .get("retry-after")
        .map(|v| v.to_str().expect("ASCII header").parse().expect("Retry-After in whole seconds"));
    (resp.status(), retry_after)
}

#[tokio::test]
async fn test_bundle_fetches_are_limited_per_caller_and_target() {
    let app = TestApp::spawn().await;
    let target = app.register_user_with_keys(&common::generate_username("limited"), 123, 10).await;
    let caller = app.register_user(&common::generate_username("limited_caller")).await;
    let other_caller = app.register_user(&common::generate_username("limited_other")).await;
    let device = format!("{}/devices/{}", target.user_id, target.device_id);

    for _ in 0..6 {
        assert_eq!(fetch_bundle(&app, &caller.token, &device).await.0, 200, "6 fetches per 10 minutes, as Signal");
    }
    let (status, retry_after) = fetch_bundle(&app, &caller.token, &device).await;
    assert_eq!(status, 429, "the 7th is rejected");
    assert!(retry_after.is_some_and(|secs| (1..=600).contains(&secs)), "with Retry-After: {retry_after:?}");

    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM one_time_pre_keys WHERE device_id = $1")
        .bind(target.device_id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(remaining, 4, "a rejected fetch consumes nothing");

    assert_eq!(fetch_bundle(&app, &other_caller.token, &device).await.0, 200, "another caller has its own limit");
    assert_eq!(
        fetch_bundle(&app, &caller.token, &target.user_id.to_string()).await.0,
        200,
        "fetching all of the user's devices is a different target"
    );
}

#[tokio::test]
async fn test_all_devices_fetch_counts_once() {
    let app = TestApp::spawn().await;
    let target = app.register_user_with_keys(&common::generate_username("all_devices"), 123, 10).await;
    let linked = app.link_device(&target).await;
    let caller = app.register_user(&common::generate_username("all_devices_caller")).await;
    let all = target.user_id.to_string();

    for _ in 0..6 {
        assert_eq!(fetch_bundle(&app, &caller.token, &all).await.0, 200, "one count per request, not per device");
    }
    assert_eq!(fetch_bundle(&app, &caller.token, &all).await.0, 429);

    let device = format!("{}/devices/{}", target.user_id, linked.device_id);
    assert_eq!(fetch_bundle(&app, &caller.token, &device).await.0, 200, "a single device is a different target");
}
