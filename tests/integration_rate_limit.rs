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
use axum::http::StatusCode;
use futures::future::join_all;
use reqwest::Client;
use std::time::Duration;
use uuid::Uuid;

mod common;

#[tokio::test]
async fn test_rate_limit_isolation() {
    let mut config = common::get_test_config();
    config.rate_limit.per_second = 1;
    config.rate_limit.burst = 2;
    let app = common::TestApp::spawn_with_config(config).await;
    let user = app.register_user(&common::generate_username("rate_user_iso")).await;

    let user_a = "1.1.1.1";
    let user_b = "2.2.2.2";

    for i in 1..=2 {
        let resp = app
            .client
            .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
            .header("Authorization", format!("Bearer {}", user.token))
            .header("X-Forwarded-For", user_a)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "Request {i} for User A should succeed");
    }

    let resp_a = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("X-Forwarded-For", user_a)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_a.status(), StatusCode::TOO_MANY_REQUESTS, "User A should now be blocked");

    let resp_b = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("X-Forwarded-For", user_b)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_b.status(), StatusCode::NOT_FOUND, "User B should be perfectly fine");
}

#[tokio::test]
async fn test_rate_limit_proxy_chain() {
    let mut config = common::get_test_config();
    config.rate_limit.per_second = 1;
    config.rate_limit.burst = 2;
    let app = common::TestApp::spawn_with_config(config).await;
    let user = app.register_user(&common::generate_username("rate_user_chain")).await;

    let chain = "9.9.9.9, 1.1.1.1, 2.2.2.2";

    for _ in 0..2 {
        let resp = app
            .client
            .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
            .header("Authorization", format!("Bearer {}", user.token))
            .header("X-Forwarded-For", chain)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    let resp = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("X-Forwarded-For", "different.spoof, 2.2.2.2")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "Should block based on the rightmost untrusted IP");
}

#[tokio::test]
async fn test_rate_limit_concurrency() {
    let mut config = common::get_test_config();
    config.rate_limit.per_second = 1;
    config.rate_limit.burst = 2;
    let app = common::TestApp::spawn_with_config(config).await;
    let user = app.register_user(&common::generate_username("rate_user_conc")).await;

    let mut tasks = vec![];
    let client = Client::new();

    for i in 0..20 {
        let url = app.server_url.clone();
        let c = client.clone();
        let token = user.token.clone();
        tasks.push(tokio::spawn(async move {
            let ip = format!("10.10.10.{i}");
            c.get(format!("{}/v1/users/{}", url, Uuid::new_v4()))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Forwarded-For", ip)
                .send()
                .await
                .unwrap()
        }));
    }

    for res in join_all(tasks).await {
        let resp = res.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "All concurrent unique IPs should succeed");
    }
}

#[tokio::test]
async fn test_rate_limit_fallback_to_peer_ip() {
    let mut config = common::get_test_config();
    config.rate_limit.per_second = 1;
    config.rate_limit.burst = 2;
    let app = common::TestApp::spawn_with_config(config).await;
    let user = app.register_user(&common::generate_username("rate_user_fall")).await;

    for _ in 0..2 {
        let resp = app
            .client
            .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
            .header("Authorization", format!("Bearer {}", user.token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
    let resp = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
        .header("Authorization", format!("Bearer {}", user.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "Should have fallen back to local peer IP and blocked");
}

#[tokio::test]
async fn test_rate_limit_spoofing_protection() {
    let mut config = common::get_test_config();
    config.rate_limit.per_second = 1;
    config.rate_limit.burst = 1;
    let app = common::TestApp::spawn_with_config(config).await;
    let user = app.register_user(&common::generate_username("rate_user_spoof")).await;

    let spoofed_ip = "1.2.3.4";
    let real_attacker_ip = "5.6.7.8";

    let _ = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("X-Forwarded-For", format!("{spoofed_ip}, {real_attacker_ip}"))
        .send()
        .await
        .unwrap();

    let resp = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("X-Forwarded-For", format!("9.9.9.9, {real_attacker_ip}"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Should block based on real IP, ignoring the spoofed part"
    );

    let resp_ok = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("X-Forwarded-For", spoofed_ip)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_ok.status(), StatusCode::NOT_FOUND, "The spoofed IP itself should not be affected");
}

#[tokio::test]
async fn test_rate_limit_tiers() {
    let mut config = common::get_test_config();
    config.rate_limit.per_second = 10;
    config.rate_limit.burst = 10;
    config.rate_limit.auth_per_second = 1;
    config.rate_limit.auth_burst = 1;
    let app = common::TestApp::spawn_with_config(config).await;

    let ip = "1.2.3.4";

    // 1. Register a user for standard tier requests BEFORE exhausting the auth tier
    let user = app.register_user(&common::generate_username("tier_std_user")).await;

    // 2. Exhaust Auth Tier (Registration)
    // Use unique usernames to avoid 409 logs
    for i in 0..2 {
        let username = common::generate_username(&format!("tier_auth_{i}"));
        let (reg_payload, _) = common::generate_registration_payload(&username, "password12345", 123, 0);
        let _ = app.client.post(format!("{}/v1/users", app.server_url)).json(&reg_payload).send().await.unwrap();
    }

    // 3. Standard Tier should still work
    for _ in 0..5 {
        let resp = app
            .client
            .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
            .header("Authorization", format!("Bearer {}", user.token))
            .header("X-Forwarded-For", ip)
            .send()
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Standard tier should not be affected by auth exhaustion"
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn test_rate_limit_recovery() {
    let mut config = common::get_test_config();
    config.rate_limit.per_second = 1;
    config.rate_limit.burst = 1;
    let app = common::TestApp::spawn_with_config(config).await;
    let user = app.register_user(&common::generate_username("rate_user_recov")).await;

    let ip = "5.5.5.5";

    let _ = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("X-Forwarded-For", ip)
        .send()
        .await
        .unwrap();

    let resp = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("X-Forwarded-For", ip)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "Should be blocked initially");

    tokio::time::sleep(Duration::from_millis(1100)).await;

    let resp_ok = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("X-Forwarded-For", ip)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_ok.status(), StatusCode::NOT_FOUND, "Should be unblocked after wait");
}

#[tokio::test]
async fn test_rate_limit_retry_after_header() {
    let mut config = common::get_test_config();
    config.rate_limit.per_second = 1;
    config.rate_limit.burst = 1;
    let app = common::TestApp::spawn_with_config(config).await;
    let user = app.register_user(&common::generate_username("rate_user_retry")).await;

    let ip = "7.7.7.7";

    app.client
        .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("X-Forwarded-For", ip)
        .send()
        .await
        .unwrap();

    let resp = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("X-Forwarded-For", ip)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    let retry_after: u64 = resp
        .headers()
        .get("retry-after")
        .expect("Retry-After header should be present")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry_after >= 1, "a sub-second wait must not be advertised as 0");

    tokio::time::sleep(Duration::from_secs(retry_after)).await;
    let retried = app
        .client
        .get(format!("{}/v1/users/{}", app.server_url, Uuid::new_v4()))
        .header("Authorization", format!("Bearer {}", user.token))
        .header("X-Forwarded-For", ip)
        .send()
        .await
        .unwrap();
    assert_eq!(retried.status(), StatusCode::NOT_FOUND, "waiting Retry-After seconds must be enough");
}
