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

use common::TestApp;
use obscura_server::proto::obscura::v1 as proto;
use prost::Message as ProstMessage;
use proto::send_message_response::{DeviceMismatch, ErrorCode};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

fn request(targets: &[(Uuid, Uuid)]) -> Vec<u8> {
    request_to(&[], targets)
}

async fn send_raw(
    client: &reqwest::Client,
    server_url: &str,
    token: &str,
    idempotency_key: Uuid,
    body: Vec<u8>,
) -> bytes::Bytes {
    let resp = client
        .post(format!("{server_url}/v1/messages"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Idempotency-Key", idempotency_key.to_string())
        .header("Content-Type", "application/x-protobuf")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.bytes().await.unwrap()
}

async fn send(app: &TestApp, token: &str, targets: &[(Uuid, Uuid)]) -> proto::SendMessageResponse {
    let body = send_raw(&app.client, &app.server_url, token, Uuid::new_v4(), request(targets)).await;
    proto::SendMessageResponse::decode(body).unwrap()
}

fn failure_codes(response: &proto::SendMessageResponse) -> Vec<(Vec<u8>, i32)> {
    response.failed_submissions.iter().map(|f| (f.submission_id.clone(), f.error_code)).collect()
}

fn mismatch(user_id: Uuid, missing: &[Uuid]) -> DeviceMismatch {
    DeviceMismatch {
        user_id: user_id.as_bytes().to_vec(),
        missing_device_ids: missing.iter().map(|id| id.as_bytes().to_vec()).collect(),
    }
}

fn sorted(mut ids: Vec<Uuid>) -> Vec<Uuid> {
    ids.sort();
    ids
}

#[tokio::test]
async fn test_complete_device_set_is_accepted() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("cd_alice")).await;
    let bob_name = common::generate_username("cd_bob");
    let bob1 = app.register_user(&bob_name).await;
    let bob2 = app.link_device(&bob1).await;

    let response =
        send(&app, &alice.token, &[(Uuid::new_v4(), bob1.device_id), (Uuid::new_v4(), bob2.device_id)]).await;

    assert!(response.failed_submissions.is_empty());
    assert!(response.device_mismatches.is_empty());
    app.assert_message_count(bob1.device_id, 1).await;
    app.assert_message_count(bob2.device_id, 1).await;
}

#[tokio::test]
async fn test_missing_device_rejects_all_of_that_users_submissions() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("cd_alice")).await;
    let bob_name = common::generate_username("cd_bob");
    let bob1 = app.register_user(&bob_name).await;
    let bob2 = app.link_device(&bob1).await;
    let bob3 = app.link_device(&bob1).await;

    let submission = Uuid::new_v4();
    let response = send(&app, &alice.token, &[(submission, bob1.device_id)]).await;

    assert_eq!(failure_codes(&response), vec![(submission.as_bytes().to_vec(), ErrorCode::DeviceMismatch as i32)]);
    assert_eq!(response.device_mismatches, vec![mismatch(bob1.user_id, &sorted(vec![bob2.device_id, bob3.device_id]))]);
    app.assert_message_count(bob1.device_id, 0).await;
}

#[tokio::test]
async fn test_self_sync_excludes_the_sending_device() {
    let app = TestApp::spawn().await;
    let alice_name = common::generate_username("cd_alice");
    let alice1 = app.register_user(&alice_name).await;
    let alice2 = app.link_device(&alice1).await;
    let bob = app.register_user(&common::generate_username("cd_bob")).await;

    let response =
        send(&app, &alice1.token, &[(Uuid::new_v4(), alice2.device_id), (Uuid::new_v4(), bob.device_id)]).await;
    assert!(response.failed_submissions.is_empty());
    assert!(response.device_mismatches.is_empty());
    app.assert_message_count(alice2.device_id, 1).await;
    app.assert_message_count(bob.device_id, 1).await;

    let response = send(&app, &alice2.token, &[(Uuid::new_v4(), alice1.device_id)]).await;
    assert!(response.failed_submissions.is_empty());
    assert!(response.device_mismatches.is_empty());
    app.assert_message_count(alice1.device_id, 1).await;

    let to_self = Uuid::new_v4();
    let to_other = Uuid::new_v4();
    let response = send(&app, &alice1.token, &[(to_self, alice1.device_id), (to_other, alice2.device_id)]).await;
    assert_eq!(failure_codes(&response), vec![(to_self.as_bytes().to_vec(), ErrorCode::InvalidDevice as i32)]);
    assert!(response.device_mismatches.is_empty(), "Targeting the sending device must not make a mismatch");
    app.assert_message_count(alice1.device_id, 1).await;
    app.assert_message_count(alice2.device_id, 2).await;
}

#[tokio::test]
async fn test_mixed_batch_rejects_only_the_incomplete_user() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("cd_alice")).await;
    let bob_name = common::generate_username("cd_bob");
    let bob1 = app.register_user(&bob_name).await;
    let bob2 = app.link_device(&bob1).await;
    let carol_name = common::generate_username("cd_carol");
    let carol1 = app.register_user(&carol_name).await;
    let carol2 = app.link_device(&carol1).await;

    let to_bob = Uuid::new_v4();
    let response = send(
        &app,
        &alice.token,
        &[(to_bob, bob2.device_id), (Uuid::new_v4(), carol1.device_id), (Uuid::new_v4(), carol2.device_id)],
    )
    .await;

    assert_eq!(failure_codes(&response), vec![(to_bob.as_bytes().to_vec(), ErrorCode::DeviceMismatch as i32)]);
    assert_eq!(response.device_mismatches, vec![mismatch(bob1.user_id, &[bob1.device_id])]);
    app.assert_message_count(bob2.device_id, 0).await;
    app.assert_message_count(carol1.device_id, 1).await;
    app.assert_message_count(carol2.device_id, 1).await;
}

#[tokio::test]
async fn test_unknown_device_fails_individually() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("cd_alice")).await;
    let bob = app.register_user(&common::generate_username("cd_bob")).await;

    let to_unknown = Uuid::new_v4();
    let response = send(&app, &alice.token, &[(Uuid::new_v4(), bob.device_id), (to_unknown, Uuid::new_v4())]).await;

    assert_eq!(failure_codes(&response), vec![(to_unknown.as_bytes().to_vec(), ErrorCode::InvalidDevice as i32)]);
    assert!(response.device_mismatches.is_empty());
    app.assert_message_count(bob.device_id, 1).await;
}

/// Waits until a backend is blocked by `pid` and returns the blocked backend's pid.
async fn backend_blocked_by(app: &TestApp, pid: i32) -> i32 {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let blocked: Option<i32> =
            sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) LIMIT 1")
                .bind(pid)
                .fetch_optional(&app.pool)
                .await
                .unwrap();
        if let Some(blocked) = blocked {
            return blocked;
        }
        assert!(std::time::Instant::now() < deadline, "no backend got blocked by {pid}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn test_device_added_during_send_is_not_silently_skipped() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("cd_alice")).await;
    let bob = app.register_user(&common::generate_username("cd_bob")).await;
    let link_session_id = app.approved_link_session(&bob).await;

    // Hold the link session row so the registration stops after locking bob's user row.
    let mut holder = app.pool.begin().await.unwrap();
    let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *holder).await.unwrap();
    sqlx::query("SELECT 1 FROM link_sessions WHERE user_id = $1 FOR UPDATE")
        .bind(bob.user_id)
        .execute(&mut *holder)
        .await
        .unwrap();

    let registering = tokio::spawn({
        let client = app.client.clone();
        let url = format!("{}/v1/devices", app.server_url);
        let mut payload = common::generate_device_payload_for(&bob.identity_key, 2, 1);
        payload["linkSessionId"] = json!(link_session_id);
        async move {
            let resp = client.post(url).json(&payload).send().await;
            resp.unwrap().json::<serde_json::Value>().await.unwrap()
        }
    });
    let registration_pid = backend_blocked_by(&app, holder_pid).await;

    let submission = Uuid::new_v4();
    let sending = tokio::spawn({
        let client = app.client.clone();
        let server_url = app.server_url.clone();
        let token = alice.token.clone();
        let body = request(&[(submission, bob.device_id)]);
        async move { send_raw(&client, &server_url, &token, Uuid::new_v4(), body).await }
    });
    backend_blocked_by(&app, registration_pid).await;
    holder.rollback().await.unwrap();

    let new_device = Uuid::parse_str(registering.await.unwrap()["deviceId"].as_str().unwrap()).unwrap();
    let response = proto::SendMessageResponse::decode(sending.await.unwrap()).unwrap();
    assert_eq!(failure_codes(&response), vec![(submission.as_bytes().to_vec(), ErrorCode::DeviceMismatch as i32)]);
    assert_eq!(response.device_mismatches, vec![mismatch(bob.user_id, &[new_device])]);
    app.assert_message_count(bob.device_id, 0).await;
}

#[tokio::test]
async fn test_concurrent_sends_to_the_same_recipient_do_not_block_each_other() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("cd_alice")).await;
    let carol = app.register_user(&common::generate_username("cd_carol")).await;
    let bob = app.register_user(&common::generate_username("cd_bob")).await;

    // An uncommitted message with the same submission id holds alice's send open after it took its locks.
    let submission = Uuid::new_v4();
    let mut holder = app.pool.begin().await.unwrap();
    let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *holder).await.unwrap();
    sqlx::query(
        r#"
        INSERT INTO messages (sender_id, sender_device_id, device_id, submission_id, content, expires_at)
        VALUES ($1, $2, $3, $4, 'held', NOW() + INTERVAL '1 day')
        "#,
    )
    .bind(alice.user_id)
    .bind(alice.device_id)
    .bind(bob.device_id)
    .bind(submission)
    .execute(&mut *holder)
    .await
    .unwrap();

    let held_send = tokio::spawn({
        let client = app.client.clone();
        let server_url = app.server_url.clone();
        let token = alice.token.clone();
        let body = request(&[(submission, bob.device_id)]);
        async move { send_raw(&client, &server_url, &token, Uuid::new_v4(), body).await }
    });
    backend_blocked_by(&app, holder_pid).await;

    let response =
        tokio::time::timeout(Duration::from_secs(5), send(&app, &carol.token, &[(Uuid::new_v4(), bob.device_id)]))
            .await
            .expect("a send must not wait for another send to the same recipient");
    assert!(response.failed_submissions.is_empty());
    assert!(response.device_mismatches.is_empty());
    app.assert_message_count(bob.device_id, 1).await;

    holder.rollback().await.unwrap();
    let response = proto::SendMessageResponse::decode(held_send.await.unwrap()).unwrap();
    assert!(response.failed_submissions.is_empty());
    assert!(response.device_mismatches.is_empty());
    app.assert_message_count(bob.device_id, 2).await;
}

#[tokio::test]
async fn test_idempotency_key_reuse_returns_the_cached_mismatch() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("cd_alice")).await;
    let bob_name = common::generate_username("cd_bob");
    let bob1 = app.register_user(&bob_name).await;
    let bob2 = app.link_device(&bob1).await;

    let key = Uuid::new_v4();
    let incomplete = request(&[(Uuid::new_v4(), bob1.device_id)]);
    let first = send_raw(&app.client, &app.server_url, &alice.token, key, incomplete).await;
    assert_eq!(
        proto::SendMessageResponse::decode(first.clone()).unwrap().device_mismatches,
        vec![mismatch(bob1.user_id, &[bob2.device_id])]
    );

    let complete = request(&[(Uuid::new_v4(), bob1.device_id), (Uuid::new_v4(), bob2.device_id)]);
    let replay = send_raw(&app.client, &app.server_url, &alice.token, key, complete.clone()).await;
    assert_eq!(replay, first);
    app.assert_message_count(bob1.device_id, 0).await;
    app.assert_message_count(bob2.device_id, 0).await;

    let retry = send_raw(&app.client, &app.server_url, &alice.token, Uuid::new_v4(), complete).await;
    let retry = proto::SendMessageResponse::decode(retry).unwrap();
    assert!(retry.failed_submissions.is_empty());
    assert!(retry.device_mismatches.is_empty());
    app.assert_message_count(bob1.device_id, 1).await;
    app.assert_message_count(bob2.device_id, 1).await;
}

fn request_to(recipients: &[Uuid], targets: &[(Uuid, Uuid)]) -> Vec<u8> {
    proto::SendMessageRequest {
        recipient_user_ids: recipients.iter().map(|id| id.as_bytes().to_vec()).collect(),
        messages: targets
            .iter()
            .map(|(submission_id, device_id)| proto::send_message_request::Submission {
                submission_id: submission_id.as_bytes().to_vec(),
                device_id: device_id.as_bytes().to_vec(),
                message: b"payload".to_vec(),
            })
            .collect(),
    }
    .encode_to_vec()
}

async fn send_to(
    app: &TestApp,
    token: &str,
    recipients: &[Uuid],
    targets: &[(Uuid, Uuid)],
) -> proto::SendMessageResponse {
    let body = send_raw(&app.client, &app.server_url, token, Uuid::new_v4(), request_to(recipients, targets)).await;
    proto::SendMessageResponse::decode(body).unwrap()
}

#[tokio::test]
async fn test_a_listed_recipient_with_no_targets_is_checked() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("cd_alice")).await;
    let bob = app.register_user(&common::generate_username("cd_bob")).await;
    let bob2 = app.link_device(&bob).await;

    let response = send_to(&app, &alice.token, &[bob.user_id], &[]).await;

    assert!(response.failed_submissions.is_empty());
    assert_eq!(response.device_mismatches, vec![mismatch(bob.user_id, &sorted(vec![bob.device_id, bob2.device_id]))]);
}

#[tokio::test]
async fn test_listing_the_sender_reveals_its_unknown_devices() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("cd_alice")).await;

    let alone = send_to(&app, &alice.token, &[alice.user_id], &[]).await;
    assert!(alone.device_mismatches.is_empty(), "the sending device alone is complete");

    let alice2 = app.link_device(&alice).await;
    let response = send_to(&app, &alice.token, &[alice.user_id], &[]).await;
    assert_eq!(response.device_mismatches, vec![mismatch(alice.user_id, &[alice2.device_id])]);
}

#[tokio::test]
async fn test_a_listed_recipient_whose_known_devices_are_gone_reports_the_current_ones() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("cd_alice")).await;
    let bob = app.register_user(&common::generate_username("cd_bob")).await;
    let stale = (Uuid::new_v4(), Uuid::new_v4());

    let response = send_to(&app, &alice.token, &[bob.user_id], &[stale]).await;

    assert_eq!(failure_codes(&response), vec![(stale.0.as_bytes().to_vec(), ErrorCode::InvalidDevice as i32)]);
    assert_eq!(response.device_mismatches, vec![mismatch(bob.user_id, &[bob.device_id])]);
}

#[tokio::test]
async fn test_too_many_recipient_user_ids_is_rejected_with_413() {
    let mut config = common::get_test_config();
    config.messaging.send_batch_limit = 2;
    let app = TestApp::spawn_with_config(config).await;
    let alice = app.register_user(&common::generate_username("cd_limit")).await;

    let body = request_to(&[Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()], &[]);
    let resp = app
        .client
        .post(format!("{}/v1/messages", app.server_url))
        .header("Authorization", format!("Bearer {}", alice.token))
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .header("Content-Type", "application/x-protobuf")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
}
