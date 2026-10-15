use crate::Services;
use crate::adapters::redis::RedisCache;
use crate::api::rate_limit::log_rate_limit_events;
use crate::config::Config;
use crate::services::attachment_service::AttachmentService;
use crate::services::auth_service::AuthService;
use crate::services::backup_service::BackupService;
use crate::services::device_service::DeviceService;
use crate::services::gateway::GatewayService;
use crate::services::health_service::HealthService;
use crate::services::key_service::KeyService;
use crate::services::link_session_service::LinkSessionService;
use crate::services::message_service::MessageService;
use crate::services::push_token_service::PushTokenService;
use crate::services::rate_limit_service::RateLimitService;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{
    Router,
    middleware::from_fn_with_state,
    routing::{delete, get, head, post, put},
};
use std::sync::Arc;
use std::time::Duration;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_http::request_id::{PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

pub mod attachments;
pub mod auth;
pub mod backup;
pub mod devices;
pub mod docs;
pub mod gateway;
pub mod health;
pub mod keys;
pub mod link_sessions;
pub mod messages;
pub mod middleware;
pub mod push_tokens;
pub mod rate_limit;
pub mod schemas;

#[derive(Clone, Debug)]
pub(crate) struct AppState {
    pub(crate) config: Config,
    pub(crate) key_service: KeyService,
    pub(crate) attachment_service: AttachmentService,
    pub(crate) backup_service: BackupService,
    pub(crate) device_service: DeviceService,
    pub(crate) auth_service: AuthService,
    pub(crate) message_service: MessageService,
    pub(crate) gateway_service: GatewayService,
    pub(crate) link_session_service: LinkSessionService,
    pub(crate) push_token_service: PushTokenService,
    pub(crate) rate_limit_service: RateLimitService,
    pub(crate) submission_cache: RedisCache,
    pub(crate) ws_ticket_cache: RedisCache,
    pub(crate) shutdown_rx: tokio::sync::watch::Receiver<bool>,
}

impl AppState {
    pub(crate) fn new(config: &Config, services: Services, shutdown_rx: tokio::sync::watch::Receiver<bool>) -> Self {
        Self {
            config: config.clone(),
            key_service: services.key_service,
            attachment_service: services.attachment_service,
            backup_service: services.backup_service,
            device_service: services.device_service,
            auth_service: services.auth_service,
            message_service: services.message_service,
            gateway_service: services.gateway_service,
            link_session_service: services.link_session_service,
            push_token_service: services.push_token_service,
            rate_limit_service: services.rate_limit_service,
            submission_cache: services.submission_cache,
            ws_ticket_cache: services.ws_ticket_cache,
            shutdown_rx,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MgmtState {
    pub health_service: HealthService,
}

fn auth_router(
    config: &Config,
    rate_limit_extractor: crate::services::rate_limit_service::IpKeyExtractor,
) -> Router<AppState> {
    // Auth Tier: Stricter limits for expensive/sensitive registration & login
    let auth_interval_ns = 1_000_000_000 / config.rate_limit.auth_per_second.max(1);
    let auth_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_nanosecond(u64::from(auth_interval_ns))
            .burst_size(config.rate_limit.auth_burst)
            .key_extractor(rate_limit_extractor)
            .finish()
            .expect("Failed to build auth rate limiter config"),
    );

    let standard_timeout = TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        Duration::from_secs(config.server.request_timeout_secs),
    );

    Router::new()
        .route("/users", post(auth::register))
        .route("/sessions", post(auth::login))
        .route("/sessions", delete(auth::logout))
        .route("/sessions/refresh", post(auth::refresh))
        .route("/account/reset", post(devices::reset_account))
        .layer(GovernorLayer::new(auth_conf))
        .layer(standard_timeout)
}

fn api_router(
    config: &Config,
    rate_limit_extractor: crate::services::rate_limit_service::IpKeyExtractor,
) -> Router<AppState> {
    let std_interval_ns = 1_000_000_000 / config.rate_limit.per_second.max(1);
    let standard_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_nanosecond(u64::from(std_interval_ns))
            .burst_size(config.rate_limit.burst)
            .key_extractor(rate_limit_extractor)
            .finish()
            .expect("Failed to build standard rate limiter config"),
    );

    let standard_routes = Router::new()
        .route("/devices", post(devices::create_device))
        .route("/devices", get(devices::list_devices))
        .route(
            "/devices/{deviceId}",
            delete(devices::delete_device).get(devices::get_device).put(devices::update_device),
        )
        .route("/devices/keys", post(keys::upload_keys))
        .route("/link-sessions", post(link_sessions::create_link_session))
        .route("/link-sessions/{id}", put(link_sessions::approve_link_session).get(link_sessions::get_link_session))
        .route("/users/{userId}", get(keys::get_pre_key_bundles))
        .route("/messages", post(messages::send_messages))
        .route("/gateway", get(gateway::websocket_handler))
        .route("/gateway/ticket", post(gateway::generate_ticket))
        .route("/push-tokens", put(push_tokens::register_token));

    Router::new()
        .merge(standard_routes)
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(config.server.request_timeout_secs),
        ))
        .layer(GovernorLayer::new(standard_conf))
}

fn storage_router(config: &Config) -> Router<AppState> {
    let attachment_timeout = TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        Duration::from_secs(config.attachment.request_timeout_secs),
    );
    let backup_timeout = TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        Duration::from_secs(config.backup.request_timeout_secs),
    );

    let attachment_routes = Router::new()
        .route("/attachments", post(attachments::upload_attachment))
        .route("/attachments/{id}", get(attachments::download_attachment))
        .layer(attachment_timeout);

    let backup_routes = Router::new()
        .route("/backup", get(backup::download_backup))
        .route("/backup", post(backup::upload_backup))
        .route("/backup", head(backup::head_backup))
        .layer(backup_timeout);

    attachment_routes.merge(backup_routes)
}

fn apply_middleware(router: Router<AppState>, config: &Config, state: AppState) -> Router {
    router
        .layer(from_fn_with_state(state.clone(), log_rate_limit_events))
        .layer(PropagateRequestIdLayer::new(axum::http::HeaderName::from_static("x-request-id")))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(config.server.global_timeout_secs),
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(move |request: &Request<Body>| {
                    let request_id = request
                        .extensions()
                        .get::<tower_http::request_id::RequestId>()
                        .map(|id| id.header_value().to_str().unwrap_or_default())
                        .unwrap_or_default()
                        .to_string();

                    tracing::info_span!(
                        "request",
                        "request.id" = %request_id,
                        "http.request.method" = %request.method(),
                        "url.path" = %request.uri().path(),
                        "http.response.status_code" = tracing::field::Empty,
                        "otel.kind" = "server",
                        "user.id" = tracing::field::Empty,
                        "device.id" = tracing::field::Empty,
                    )
                })
                .on_response(|response: &axum::http::Response<_>, latency: Duration, _span: &tracing::Span| {
                    let status = response.status();
                    tracing::Span::current().record("http.response.status_code", status.as_u16());

                    if status.is_server_error() {
                        tracing::error!(
                            latency_ms = %latency.as_millis(),
                            status = %status.as_u16(),
                            "request completed with server error"
                        );
                    } else if status.is_client_error() {
                        tracing::warn!(
                            latency_ms = %latency.as_millis(),
                            status = %status.as_u16(),
                            "request completed with client error"
                        );
                    } else {
                        tracing::info!(
                            latency_ms = %latency.as_millis(),
                            status = %status.as_u16(),
                            "request completed"
                        );
                    }
                })
                .on_failure(|error, _latency, _span: &tracing::Span| {
                    tracing::error!(error = %error, "request failed");
                }),
        )
        .layer(SetRequestIdLayer::new(
            axum::http::HeaderName::from_static("x-request-id"),
            middleware::MakeRequestUuidOrHeader,
        ))
        .with_state(state)
}

/// Configures and returns the primary application router.
///
/// # Panics
/// Panics if the rate limiter configuration cannot be constructed.
pub fn app_router(config: &Config, services: Services, shutdown_rx: tokio::sync::watch::Receiver<bool>) -> Router {
    let extractor = services.rate_limit_service.extractor.clone();
    let state = AppState::new(config, services, shutdown_rx);

    let routes = Router::new().route("/openapi.yaml", get(docs::openapi_yaml)).nest(
        "/v1",
        auth_router(config, extractor.clone()).merge(api_router(config, extractor)).merge(storage_router(config)),
    );

    apply_middleware(routes, config, state)
}

pub fn mgmt_router(state: MgmtState) -> Router {
    Router::new().route("/livez", get(health::livez)).route("/readyz", get(health::readyz)).with_state(state)
}
