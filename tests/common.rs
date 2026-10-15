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
#![allow(dead_code)]
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use obscura_server::{
    adapters,
    adapters::push::{PushError, PushProvider},
    api::app_router,
    config::{AuthConfig, Config, NotificationConfig, PubSubConfig, RateLimitConfig, ServerConfig, StorageConfig},
    proto::obscura::v1 as proto,
    services::notification_service::NotificationService,
};

use prost::Message as ProstMessage;
use rand::Rng;
use reqwest::Client;
use serde_json::json;
use sqlx::PgPool;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::{WebSocketStream, connect_async, tungstenite::protocol::Message};
use uuid::Uuid;
use xeddsa::xed25519::PrivateKey;
use xeddsa::{CalculateKeyPair, Sign};

static INIT: OnceLock<()> = OnceLock::new();

pub fn setup_tracing() {
    INIT.get_or_init(|| {
        obscura_server::telemetry::init_test_telemetry();
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "warn".into())
            .add_directive("tower=warn".parse().unwrap())
            .add_directive("sqlx=warn".parse().unwrap())
            .add_directive("hyper=warn".parse().unwrap())
            .add_directive("reqwest=warn".parse().unwrap())
            .add_directive("rustls=warn".parse().unwrap())
            .add_directive("tungstenite=warn".parse().unwrap())
            .add_directive("aws=warn".parse().unwrap());

        let format = std::env::var("OBSCURA_LOG_FORMAT").unwrap_or_else(|_| "text".to_string());
        use tracing_subscriber::fmt::format::FmtSpan;

        match format.as_str() {
            "json" => {
                tracing_subscriber::fmt().json().with_env_filter(filter).with_span_events(FmtSpan::CLOSE).init();
            }
            _ => {
                tracing_subscriber::fmt().with_env_filter(filter).init();
            }
        }
    });
}

/// Shared global state for all test providers to report to.
pub fn notification_counts() -> &'static DashMap<Uuid, u32> {
    static COUNTS: OnceLock<DashMap<Uuid, u32>> = OnceLock::new();
    COUNTS.get_or_init(DashMap::new)
}

#[derive(Debug, Default)]
pub struct SharedMockPushProvider;

#[async_trait]
impl PushProvider for SharedMockPushProvider {
    async fn send_push(&self, token: &str) -> Result<(), PushError> {
        if let Some(user_id_str) = token.strip_prefix("token:")
            && let Ok(user_id) = Uuid::parse_str(user_id_str)
        {
            *notification_counts().entry(user_id).or_insert(0) += 1;
        }
        Ok(())
    }
}

pub async fn get_test_pool() -> PgPool {
    let database_url = std::env::var("OBSCURA_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://user:password@localhost/signal_server".to_string());

    get_test_pool_with(&obscura_server::config::DatabaseConfig { url: database_url, ..Default::default() }).await
}

/// Builds a pool from `config`, so a test can size it (e.g. to starve a component of connections).
pub async fn get_test_pool_with(config: &obscura_server::config::DatabaseConfig) -> PgPool {
    setup_tracing();

    let pool = adapters::database::init_pool(config).await.expect("Failed to connect to DB. Is Postgres running?");

    sqlx::migrate!().run(&pool).await.expect("Failed to run migrations");

    pool
}

pub async fn ensure_storage_bucket(s3_client: &aws_sdk_s3::Client, bucket: &str) {
    let _ = s3_client.create_bucket().bucket(bucket).send().await;
}

pub fn get_test_config() -> Config {
    let database_url = std::env::var("OBSCURA_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://user:password@localhost/signal_server".to_string());

    // Test Isolation
    let run_id = Uuid::new_v4().to_string()[..8].to_string();

    Config {
        ttl_days: 30,
        database: obscura_server::config::DatabaseConfig { url: database_url, ..Default::default() },
        server: ServerConfig {
            port: 0,
            mgmt_port: 0,
            trusted_proxies: vec!["127.0.0.1/32".parse().unwrap(), "::1/128".parse().unwrap()],
            ..Default::default()
        },
        auth: AuthConfig { jwt_secret: "test_secret".to_string(), ..Default::default() },
        rate_limit: RateLimitConfig { per_second: 10000, burst: 10000, auth_per_second: 10000, auth_burst: 10000 },
        storage: StorageConfig {
            bucket: "test-bucket".to_string(),
            endpoint: Some(
                std::env::var("OBSCURA_STORAGE_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".to_string()),
            ),
            access_key: Some("minioadmin".to_string()),
            secret_key: Some("minioadmin".to_string()),
            force_path_style: true,
            ..Default::default()
        },
        pubsub: PubSubConfig {
            url: std::env::var("OBSCURA_PUBSUB_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            ..Default::default()
        },
        notifications: NotificationConfig {
            push_queue_key: format!("jobs:test:{run_id}"),
            channel_prefix: format!("test:{run_id}:"),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn generate_username(prefix: &str) -> String {
    format!("{prefix}_{}", &Uuid::new_v4().to_string()[..8])
}

pub fn generate_signing_key() -> [u8; 32] {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

pub fn generate_signed_pre_key(identity_key_bytes: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    // Generate SPK
    let spk_bytes = generate_signing_key();
    let spk_priv = PrivateKey(spk_bytes);
    let (_, spk_pub_ed) = spk_priv.calculate_key_pair(0);
    // Convert to Montgomery and add prefix
    let spk_pub_mont =
        curve25519_dalek::edwards::CompressedEdwardsY(spk_pub_ed).decompress().unwrap().to_montgomery().to_bytes();
    let mut spk_pub_wire = [0u8; 33];
    spk_pub_wire[0] = 0x05;
    spk_pub_wire[1..].copy_from_slice(&spk_pub_mont);

    // Sign SPK pub key (33-byte wire format) with Identity Key
    let ik_priv = PrivateKey(*identity_key_bytes);
    let mut rng = rand::rng();
    let signature: [u8; 64] = ik_priv.sign(&spk_pub_wire, &mut rng);

    (spk_pub_wire.to_vec(), signature.to_vec())
}

pub fn generate_registration_payload(
    username: &str,
    password: &str,
    reg_id: u32,
    otpk_count: usize,
) -> (serde_json::Value, [u8; 32]) {
    let identity_key = generate_signing_key();
    let ik_priv = PrivateKey(identity_key);
    let (_, ik_pub_ed) = ik_priv.calculate_key_pair(0);
    let ik_pub_mont =
        curve25519_dalek::edwards::CompressedEdwardsY(ik_pub_ed).decompress().unwrap().to_montgomery().to_bytes();
    let mut ik_pub_wire = [0u8; 33];
    ik_pub_wire[0] = 0x05;
    ik_pub_wire[1..].copy_from_slice(&ik_pub_mont);

    let (spk_pub, spk_sig) = generate_signed_pre_key(&identity_key);

    let mut otpk = Vec::new();
    for i in 0..otpk_count {
        let key_bytes = generate_signing_key();
        let key_priv = PrivateKey(key_bytes);
        let (_, key_pub_ed) = key_priv.calculate_key_pair(0);
        let key_pub_mont =
            curve25519_dalek::edwards::CompressedEdwardsY(key_pub_ed).decompress().unwrap().to_montgomery().to_bytes();
        let mut key_pub_wire = [0u8; 33];
        key_pub_wire[0] = 0x05;
        key_pub_wire[1..].copy_from_slice(&key_pub_mont);

        otpk.push(json!({
            "keyId": i,
            "publicKey": STANDARD.encode(key_pub_wire)
        }));
    }

    let payload = json!({
        "username": username,
        "password": password,
        "registrationId": reg_id,
        "identityKey": STANDARD.encode(ik_pub_wire),
        "signedPreKey": {
            "keyId": 1,
            "publicKey": STANDARD.encode(&spk_pub),
            "signature": STANDARD.encode(&spk_sig)
        },
        "oneTimePreKeys": otpk
    });

    (payload, identity_key)
}

/// Generates a device creation payload (keys without username/password) for POST /v1/devices.
pub fn generate_device_payload(reg_id: u32, otpk_count: usize) -> (serde_json::Value, [u8; 32]) {
    let identity_key = generate_signing_key();
    (generate_device_payload_for(&identity_key, reg_id, otpk_count), identity_key)
}

/// Encodes the public half of an identity key in the 33-byte wire format, base64.
pub fn identity_public_key(identity_key: &[u8; 32]) -> String {
    let (_, ik_pub_ed) = PrivateKey(*identity_key).calculate_key_pair(0);
    let ik_pub_mont =
        curve25519_dalek::edwards::CompressedEdwardsY(ik_pub_ed).decompress().unwrap().to_montgomery().to_bytes();
    let mut ik_pub_wire = [0u8; 33];
    ik_pub_wire[0] = 0x05;
    ik_pub_wire[1..].copy_from_slice(&ik_pub_mont);
    STANDARD.encode(ik_pub_wire)
}

/// Generates a device creation payload whose keys belong to the given identity key.
pub fn generate_device_payload_for(identity_key: &[u8; 32], reg_id: u32, otpk_count: usize) -> serde_json::Value {
    let (spk_pub, spk_sig) = generate_signed_pre_key(identity_key);

    let mut otpk = Vec::new();
    for i in 0..otpk_count {
        let key_bytes = generate_signing_key();
        let key_priv = PrivateKey(key_bytes);
        let (_, key_pub_ed) = key_priv.calculate_key_pair(0);
        let key_pub_mont =
            curve25519_dalek::edwards::CompressedEdwardsY(key_pub_ed).decompress().unwrap().to_montgomery().to_bytes();
        let mut key_pub_wire = [0u8; 33];
        key_pub_wire[0] = 0x05;
        key_pub_wire[1..].copy_from_slice(&key_pub_mont);

        otpk.push(json!({
            "keyId": i,
            "publicKey": STANDARD.encode(key_pub_wire)
        }));
    }

    json!({
        "registrationId": reg_id,
        "identityKey": identity_public_key(identity_key),
        "signedPreKey": {
            "keyId": 1,
            "publicKey": STANDARD.encode(&spk_pub),
            "signature": STANDARD.encode(&spk_sig)
        },
        "oneTimePreKeys": otpk
    })
}

pub struct TestUser {
    pub username: String,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub token: String,
    pub refresh_token: String,
    pub identity_key: [u8; 32],
}

pub struct TestApp {
    pub pool: PgPool,
    pub config: Config,
    pub resources: obscura_server::Resources,
    pub server_url: String,
    pub mgmt_url: String,
    pub ws_url: String,
    pub client: Client,
    pub s3_client: aws_sdk_s3::Client,
    pub notifier: NotificationService,
    pub shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Keeps spawned workers alive: dropping a `JoinSet` aborts every task in it. Binding it to a
    /// local in `spawn_internal` would kill the workers when that function returns.
    _worker_tasks: Option<tokio::task::JoinSet<&'static str>>,
}

impl TestApp {
    pub(crate) async fn spawn() -> Self {
        Self::spawn_internal(get_test_config(), false).await
    }

    pub(crate) async fn spawn_with_config(config: Config) -> Self {
        Self::spawn_internal(config, false).await
    }

    pub(crate) async fn spawn_with_workers(config: Config) -> Self {
        Self::spawn_internal(config, true).await
    }

    async fn spawn_internal(config: Config, start_workers: bool) -> Self {
        let pool = get_test_pool_with(&config.database).await;
        let mut config = config;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        config.server.port = addr.port();

        let mgmt_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mgmt_addr = mgmt_listener.local_addr().unwrap();
        config.server.mgmt_port = mgmt_addr.port();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let pubsub = adapters::redis::RedisClient::new(
            &config.pubsub,
            config.notifications.global_channel_capacity,
            shutdown_rx.clone(),
        )
        .await
        .expect("Failed to create RedisClient for tests. Is Redis running?");

        let s3_client = obscura_server::initialize_s3_client(&config.storage).await;

        let push_provider = Arc::new(SharedMockPushProvider);
        let app = obscura_server::AppBuilder::new(config.clone())
            .with_database(pool.clone())
            .with_pubsub(pubsub.clone())
            .with_s3(s3_client.clone())
            .with_push_provider(push_provider)
            .with_shutdown_rx(shutdown_rx.clone())
            .initialize()
            .await
            .expect("Failed to build application for tests");

        // Spawn workers explicitly in tests only if requested
        let worker_tasks = start_workers.then(|| app.workers.spawn_all(shutdown_rx.clone()));

        let notifier = app.services.notification_service.clone();
        let app_router = app_router(&config, app.services, shutdown_rx.clone());
        let mgmt_app =
            obscura_server::api::mgmt_router(obscura_server::api::MgmtState { health_service: app.health_service });

        let server_url = format!("http://{addr}");
        let mgmt_url = format!("http://{mgmt_addr}");
        let ws_url = format!("ws://{addr}/v1/gateway");

        tokio::spawn(async move {
            axum::serve(listener, app_router.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await
                .unwrap();
        });

        tokio::spawn(async move {
            axum::serve(mgmt_listener, mgmt_app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await
                .unwrap();
        });

        Self {
            pool,
            config,
            resources: app.resources,
            server_url,
            mgmt_url,
            ws_url,
            client: Client::new(),
            s3_client,
            notifier,
            shutdown_tx,
            _worker_tasks: worker_tasks,
        }
    }

    pub(crate) async fn register_user(&self, username: &str) -> TestUser {
        self.register_user_with_keys(username, 123, 1).await
    }

    pub(crate) async fn register_user_with_keys(&self, username: &str, reg_id: u32, otpk_count: usize) -> TestUser {
        // Step 1: Register user (auth-only, no keys)
        let reg_payload = json!({
            "username": username,
            "password": "password12345"
        });

        let resp = self.client.post(format!("{}/v1/users", self.server_url)).json(&reg_payload).send().await.unwrap();

        assert_eq!(resp.status(), 201, "User registration failed: {}", resp.text().await.unwrap());
        let body = resp.json::<serde_json::Value>().await.unwrap();
        let user_token = body["token"].as_str().unwrap().to_string();

        let parts: Vec<&str> = user_token.split('.').collect();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        let user_id = Uuid::parse_str(claims["sub"].as_str().unwrap()).unwrap();

        // Step 2: Create device (with keys) to get device-scoped JWT
        let (device_payload, identity_key) = generate_device_payload(reg_id, otpk_count);

        let resp = self
            .client
            .post(format!("{}/v1/devices", self.server_url))
            .header("Authorization", format!("Bearer {user_token}"))
            .json(&device_payload)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 201, "Device creation failed: {}", resp.text().await.unwrap());
        let body = resp.json::<serde_json::Value>().await.unwrap();
        let token = body["token"].as_str().unwrap().to_string();
        let refresh_token = body["refreshToken"].as_str().unwrap().to_string();
        let device_id = Uuid::parse_str(body["deviceId"].as_str().unwrap()).unwrap();

        TestUser { username: username.to_string(), user_id, device_id, token, refresh_token, identity_key }
    }

    /// Logs in with the test password and returns a user-scoped token.
    pub(crate) async fn login_user_scoped(&self, username: &str) -> String {
        let resp = self
            .client
            .post(format!("{}/v1/sessions", self.server_url))
            .json(&json!({ "username": username, "password": "password12345" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "Login failed: {}", resp.text().await.unwrap());
        resp.json::<serde_json::Value>().await.unwrap()["token"].as_str().unwrap().to_string()
    }

    /// Creates a link session with the given user-scoped token and returns its id.
    pub(crate) async fn create_link_session(&self, user_token: &str) -> String {
        let resp = self
            .client
            .post(format!("{}/v1/link-sessions", self.server_url))
            .header("Authorization", format!("Bearer {user_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "Creating link session failed: {}", resp.text().await.unwrap());
        resp.json::<serde_json::Value>().await.unwrap()["id"].as_str().unwrap().to_string()
    }

    /// Stores the provisioning message of a link session with the given device token, approving it.
    pub(crate) async fn approve_link_session(&self, device_token: &str, id: &str, body: &[u8]) -> reqwest::StatusCode {
        self.client
            .put(format!("{}/v1/link-sessions/{id}", self.server_url))
            .header("Authorization", format!("Bearer {device_token}"))
            .header("Content-Type", "application/octet-stream")
            .body(body.to_vec())
            .send()
            .await
            .unwrap()
            .status()
    }

    /// Returns a fresh user-scoped token of the primary's account and a link session the primary approved.
    pub(crate) async fn approved_link_session(&self, primary: &TestUser) -> (String, String) {
        let user_token = self.login_user_scoped(&primary.username).await;
        let id = self.create_link_session(&user_token).await;
        assert_eq!(self.approve_link_session(&primary.token, &id, b"provisioning message").await, 200);
        (user_token, id)
    }

    /// Registers a device linked to the primary's account, sharing its identity key.
    pub(crate) async fn link_device(&self, primary: &TestUser) -> TestUser {
        let (user_token, link_session_id) = self.approved_link_session(primary).await;

        let mut payload = generate_device_payload_for(&primary.identity_key, 456, 1);
        payload["linkSessionId"] = json!(link_session_id);

        let resp = self
            .client
            .post(format!("{}/v1/devices", self.server_url))
            .header("Authorization", format!("Bearer {user_token}"))
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "Linking device failed: {}", resp.text().await.unwrap());
        let body = resp.json::<serde_json::Value>().await.unwrap();

        TestUser {
            username: primary.username.clone(),
            user_id: primary.user_id,
            device_id: Uuid::parse_str(body["deviceId"].as_str().unwrap()).unwrap(),
            token: body["token"].as_str().unwrap().to_string(),
            refresh_token: body["refreshToken"].as_str().unwrap().to_string(),
            identity_key: primary.identity_key,
        }
    }

    pub(crate) async fn send_message(&self, token: &str, device_id: Uuid, content: &[u8]) {
        self.send_messages(token, &[(device_id, content)]).await;
    }

    pub(crate) async fn send_messages(&self, token: &str, messages: &[(Uuid, &[u8])]) {
        let outgoing = messages
            .iter()
            .map(|(device_id, content)| proto::send_message_request::Submission {
                submission_id: Uuid::new_v4().as_bytes().to_vec(),
                device_id: device_id.as_bytes().to_vec(),
                message: content.to_vec(),
            })
            .collect();

        let request = proto::SendMessageRequest { messages: outgoing };
        let mut buf = Vec::new();
        request.encode(&mut buf).unwrap();

        let resp = self
            .client
            .post(format!("{}/v1/messages", self.server_url))
            .header("Authorization", format!("Bearer {token}"))
            .header("Idempotency-Key", Uuid::new_v4().to_string())
            .header("Content-Type", "application/x-protobuf")
            .body(buf)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200, "Message sending failed: {}", resp.text().await.unwrap());
        let response = proto::SendMessageResponse::decode(resp.bytes().await.unwrap()).unwrap();
        assert!(
            response.failed_submissions.is_empty() && response.device_mismatches.is_empty(),
            "Message sending was rejected: {response:?}"
        );
    }

    pub(crate) async fn connect_ws(&self, token: &str) -> TestWsClient {
        // Fetch a ticket first using the auth token
        let ticket_resp = self
            .client
            .post(format!("{}/v1/gateway/ticket", self.server_url))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .expect("Failed to request ticket");

        assert_eq!(ticket_resp.status(), 201, "Failed to create ticket");
        let body: serde_json::Value = ticket_resp.json().await.expect("Failed to parse ticket JSON");
        let ticket = body["ticket"].as_str().expect("Ticket string not found in response");

        let (ws_stream, _) =
            connect_async(format!("{}?ticket={}", self.ws_url, ticket)).await.expect("Failed to connect WS");
        let (sink, stream) = ws_stream.split();
        let (tx_env, rx_env) = tokio::sync::mpsc::unbounded_channel();
        let (tx_status, rx_status) = tokio::sync::mpsc::unbounded_channel();
        let (tx_pong, rx_pong) = tokio::sync::mpsc::unbounded_channel();
        let (tx_raw, rx_raw) = tokio::sync::mpsc::unbounded_channel();

        let mut stream = stream;
        tokio::spawn(async move {
            while let Some(msg) = stream.next().await {
                if let Ok(m) = &msg {
                    let _ = tx_raw.send(Ok(m.clone()));
                }
                match msg {
                    Ok(Message::Binary(bin)) => {
                        if let Ok(frame) = proto::WebSocketFrame::decode(bin.as_ref()) {
                            match frame.payload {
                                Some(proto::web_socket_frame::Payload::EnvelopeBatch(batch)) => {
                                    for e in batch.envelopes {
                                        if tx_env.send(e).is_err() {
                                            break;
                                        }
                                    }
                                }
                                Some(proto::web_socket_frame::Payload::PreKeyStatus(s)) => {
                                    let _ = tx_status.send(s);
                                }
                                _ => {}
                            }
                        }
                    }
                    Ok(Message::Pong(p)) => {
                        let _ = tx_pong.send(p);
                    }
                    _ => {}
                }
            }
        });

        TestWsClient { sink, rx_env, rx_status, rx_pong, rx_raw }
    }

    pub(crate) async fn wait_until<F, Fut>(&self, mut condition: F, timeout: Duration) -> bool
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if condition().await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    pub(crate) async fn assert_message_count(&self, device_id: Uuid, expected: i64) {
        let success = self
            .wait_until(
                || async {
                    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE device_id = $1")
                        .bind(device_id)
                        .fetch_one(&self.pool)
                        .await
                        .unwrap();
                    count == expected
                },
                Duration::from_secs(5),
            )
            .await;

        if !success {
            let actual: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE device_id = $1")
                .bind(device_id)
                .fetch_one(&self.pool)
                .await
                .unwrap();
            panic!("Message count assertion failed. Expected {expected}, got {actual}");
        }
    }
}

pub struct TestWsClient {
    pub sink:
        futures::stream::SplitSink<WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>,
    pub rx_env: tokio::sync::mpsc::UnboundedReceiver<proto::Envelope>,
    pub rx_status: tokio::sync::mpsc::UnboundedReceiver<proto::PreKeyStatus>,
    pub rx_pong: tokio::sync::mpsc::UnboundedReceiver<tokio_tungstenite::tungstenite::Bytes>,
    pub rx_raw: tokio::sync::mpsc::UnboundedReceiver<Result<Message, tokio_tungstenite::tungstenite::Error>>,
}

impl TestWsClient {
    /// Waits until the server closes the connection.
    pub(crate) async fn assert_closed(&mut self) {
        let closed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match self.rx_raw.recv().await {
                    Some(Ok(Message::Close(_)) | Err(_)) | None => return,
                    Some(Ok(_)) => {}
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "WebSocket was not closed by the server");
    }

    pub(crate) async fn receive_pong(&mut self) -> Option<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(5), self.rx_pong.recv()).await.ok().flatten().map(|b| b.to_vec())
    }

    pub(crate) async fn receive_envelope(&mut self) -> Option<proto::Envelope> {
        self.receive_envelope_timeout(Duration::from_secs(5)).await
    }

    pub(crate) async fn receive_envelope_timeout(&mut self, timeout: Duration) -> Option<proto::Envelope> {
        tokio::time::timeout(timeout, self.rx_env.recv()).await.ok().flatten()
    }

    pub(crate) async fn receive_prekey_status(&mut self) -> Option<proto::PreKeyStatus> {
        self.receive_prekey_status_timeout(Duration::from_secs(5)).await
    }

    pub(crate) async fn receive_prekey_status_timeout(&mut self, timeout: Duration) -> Option<proto::PreKeyStatus> {
        tokio::time::timeout(timeout, self.rx_status.recv()).await.ok().flatten()
    }

    pub(crate) async fn receive_raw_timeout(
        &mut self,
        timeout: Duration,
    ) -> Option<Result<Message, tokio_tungstenite::tungstenite::Error>> {
        tokio::time::timeout(timeout, self.rx_raw.recv()).await.ok().flatten()
    }

    pub(crate) async fn send_ack(&mut self, message_id: Vec<u8>) {
        let ack = proto::AckMessage { message_ids: vec![message_id] };
        let frame = proto::WebSocketFrame { payload: Some(proto::web_socket_frame::Payload::Ack(ack)) };
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        self.sink.send(Message::Binary(buf.into())).await.unwrap();
    }

    /// Sends a ping and waits for a pong to ensure the session is fully established
    /// and any initial processing (like the first message poll) is complete.
    pub(crate) async fn ensure_subscribed(&mut self) {
        self.sink.send(Message::Ping(vec![1].into())).await.unwrap();
        self.receive_pong().await.expect("Session did not become ready in time");
    }
}
