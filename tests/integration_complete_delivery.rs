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
    proto::SendMessageRequest {
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
    assert_eq!(
        failure_codes(&response),
        vec![
            (to_self.as_bytes().to_vec(), ErrorCode::DeviceMismatch as i32),
            (to_other.as_bytes().to_vec(), ErrorCode::DeviceMismatch as i32),
        ]
    );
    assert_eq!(response.device_mismatches, vec![mismatch(alice1.user_id, &[])]);
    app.assert_message_count(alice2.device_id, 1).await;
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

#[tokio::test]
async fn test_device_added_during_send_is_not_silently_skipped() {
    let app = TestApp::spawn().await;
    let alice = app.register_user(&common::generate_username("cd_alice")).await;
    let bob = app.register_user(&common::generate_username("cd_bob")).await;

    let mut linking = app.pool.begin().await.unwrap();
    let linking_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *linking).await.unwrap();
    let new_device: Uuid =
        sqlx::query_scalar("INSERT INTO devices (user_id, registration_id) VALUES ($1, 1) RETURNING id")
            .bind(bob.user_id)
            .fetch_one(&mut *linking)
            .await
            .unwrap();

    let submission = Uuid::new_v4();
    let sending = tokio::spawn({
        let client = app.client.clone();
        let server_url = app.server_url.clone();
        let token = alice.token.clone();
        let body = request(&[(submission, bob.device_id)]);
        async move { send_raw(&client, &server_url, &token, Uuid::new_v4(), body).await }
    });

    let blocked = app
        .wait_until(
            || {
                let pool = app.pool.clone();
                async move {
                    sqlx::query_scalar::<_, bool>(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))",
                    )
                    .bind(linking_pid)
                    .fetch_one(&pool)
                    .await
                    .unwrap()
                }
            },
            Duration::from_secs(5),
        )
        .await;
    assert!(blocked, "the send must wait for the concurrent device insert");
    linking.commit().await.unwrap();

    let response = proto::SendMessageResponse::decode(sending.await.unwrap()).unwrap();
    assert_eq!(failure_codes(&response), vec![(submission.as_bytes().to_vec(), ErrorCode::DeviceMismatch as i32)]);
    assert_eq!(response.device_mismatches, vec![mismatch(bob.user_id, &[new_device])]);
    app.assert_message_count(bob.device_id, 0).await;
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
