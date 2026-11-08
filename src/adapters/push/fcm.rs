use crate::adapters::push::{PushError, PushProvider};
use crate::config::FcmSettings;
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// How many seconds before expiry to proactively refresh the token.
const REFRESH_MARGIN_SECS: u64 = 300;

/// Lifetime of the signed assertion exchanged for an access token. Google accepts at most an hour.
const ASSERTION_TTL_SECS: u64 = 3600;

/// Seconds since the UNIX epoch.
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Google `OAuth2` scope required for FCM.
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// Google token endpoint.
const GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// Grant type for JWT bearer assertion (RFC 7523).
const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Fields parsed from a Google service account JSON file.
#[derive(Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
}

impl std::fmt::Debug for ServiceAccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccountKey").field("client_email", &self.client_email).finish_non_exhaustive()
    }
}

/// JWT claims for the Google `OAuth2` token exchange.
#[derive(Debug, Serialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    iat: u64,
    exp: u64,
}

impl Claims {
    /// The assertion a service account signs at `now` to request an access token from `audience`.
    fn assertion(client_email: &str, audience: &str, now: u64) -> Self {
        Self {
            iss: client_email.to_string(),
            scope: FCM_SCOPE.to_string(),
            aud: audience.to_string(),
            iat: now,
            exp: now.saturating_add(ASSERTION_TTL_SECS),
        }
    }
}

/// Response from Google's token endpoint.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse").field("expires_in", &self.expires_in).finish_non_exhaustive()
    }
}

/// A cached `OAuth2` access token with its expiry.
#[derive(Clone)]
struct CachedToken {
    access_token: String,
    /// Absolute time (seconds since UNIX epoch) when this token expires.
    expires_at: u64,
}

impl std::fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedToken").field("expires_at", &self.expires_at).finish_non_exhaustive()
    }
}

impl CachedToken {
    /// A token received at `now` that the token endpoint said expires in `expires_in` seconds.
    const fn new(access_token: String, now: u64, expires_in: u64) -> Self {
        Self { access_token, expires_at: now.saturating_add(expires_in) }
    }

    /// Returns `true` if, at `now`, the token is expired or within the refresh margin of expiring.
    const fn needs_refresh(&self, now: u64) -> bool {
        now.saturating_add(REFRESH_MARGIN_SECS) >= self.expires_at
    }
}

/// FCM HTTP v1 push notification provider.
///
/// Uses a Google service account to acquire `OAuth2` access tokens via the JWT
/// bearer assertion flow (RFC 7523), caches them with proactive refresh, and
/// sends data-only messages to the FCM API.
#[derive(Debug)]
pub struct FcmPushProvider {
    project_id: String,
    client_email: String,
    encoding_key: EncodingKey,
    http: reqwest::Client,
    token_cache: Arc<RwLock<Option<CachedToken>>>,
    /// Time-to-live for push notifications in seconds.
    ttl_secs: u64,
    /// Base URL for the FCM API. Defaults to `https://fcm.googleapis.com`.
    /// Overridden in tests to point at a mock server.
    fcm_base_url: String,
    /// Token endpoint URL. Defaults to Google's `OAuth2` token endpoint.
    /// Overridden in tests to point at a mock server.
    token_endpoint: String,
}

/// FCM error detail returned in the response body.
#[derive(Debug, Deserialize)]
struct FcmErrorResponse {
    error: Option<FcmErrorBody>,
}

#[derive(Debug, Deserialize)]
struct FcmErrorBody {
    status: Option<String>,
    details: Option<Vec<FcmErrorDetail>>,
}

#[derive(Debug, Deserialize)]
struct FcmErrorDetail {
    #[serde(rename = "errorCode")]
    error_code: Option<String>,
    /// Field violations from `google.rpc.BadRequest` details.
    /// Present when `@type` is `type.googleapis.com/google.rpc.BadRequest`.
    #[serde(rename = "fieldViolations")]
    field_violations: Option<Vec<FieldViolation>>,
}

#[derive(Debug, Deserialize)]
struct FieldViolation {
    field: Option<String>,
}

impl FcmErrorResponse {
    /// Classifies a failed send from its HTTP status and response body: whether the device token is gone
    /// for good, the quota is exhausted, or the failure is something else worth retrying.
    fn classify(status: reqwest::StatusCode, body: &str) -> PushError {
        // Map HTTP status codes and FCM error codes to PushError variants
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return PushError::QuotaExceeded;
        }

        // 404 UNREGISTERED: token is no longer valid
        if status == reqwest::StatusCode::NOT_FOUND {
            return PushError::Unregistered;
        }

        // 403 SENDER_ID_MISMATCH: token belongs to a different sender and will never work
        if status == reqwest::StatusCode::FORBIDDEN {
            return PushError::Unregistered;
        }

        // Parse the error body for specific FCM error codes
        if let Ok(error_resp) = serde_json::from_str::<Self>(body)
            && let Some(ref error) = error_resp.error
        {
            // Check top-level status for token-is-gone errors
            if let Some(ref s) = error.status
                && (s == "NOT_FOUND" || s == "UNREGISTERED" || s == "SENDER_ID_MISMATCH")
            {
                return PushError::Unregistered;
            }

            // Check error details for UNREGISTERED error code
            if let Some(ref details) = error.details {
                for detail in details {
                    if let Some(ref code) = detail.error_code
                        && code == "UNREGISTERED"
                    {
                        return PushError::Unregistered;
                    }
                }
            }

            // 400 INVALID_ARGUMENT: could be a bad token format or a payload
            // issue (message too big, reserved data key, invalid TTL, etc.).
            // Parse the google.rpc.BadRequest field violations to distinguish:
            // a violation on "message.token" means the token itself is invalid
            // and will never succeed, so treat it as Unregistered.
            if status == reqwest::StatusCode::BAD_REQUEST
                && let Some(ref s) = error.status
                && s == "INVALID_ARGUMENT"
            {
                let is_token_violation = error.details.as_ref().is_some_and(|details| {
                    details.iter().any(|d| {
                        d.field_violations.as_ref().is_some_and(|fvs| {
                            fvs.iter().any(|fv| fv.field.as_ref().is_some_and(|f| f == "message.token"))
                        })
                    })
                });

                if is_token_violation {
                    return PushError::Unregistered;
                }

                tracing::warn!("FCM returned INVALID_ARGUMENT (not a token issue), check payload: {body}");
            }
        }
        PushError::Other(anyhow::anyhow!("FCM request failed with HTTP {status}: {body}"))
    }
}

/// FCM message payload.
#[derive(Debug, Serialize)]
struct FcmRequest {
    message: FcmMessage,
}

#[derive(Debug, Serialize)]
struct FcmMessage {
    token: String,
    data: FcmData,
    android: FcmAndroid,
    apns: FcmApns,
}

#[derive(Debug, Serialize)]
struct FcmData {
    action: String,
}

#[derive(Debug, Serialize)]
struct FcmAndroid {
    #[serde(rename = "collapseKey")]
    collapse_key: String,
    priority: String,
    ttl: String,
}

/// APNs configuration for iOS silent push via FCM.
#[derive(Debug, Serialize)]
struct FcmApns {
    headers: FcmApnsHeaders,
    payload: FcmApnsPayload,
}

#[derive(Debug, Serialize)]
struct FcmApnsHeaders {
    #[serde(rename = "apns-push-type")]
    push_type: String,
    #[serde(rename = "apns-priority")]
    priority: String,
    #[serde(rename = "apns-collapse-id")]
    collapse_id: String,
}

#[derive(Debug, Serialize)]
struct FcmApnsPayload {
    aps: FcmAps,
}

#[derive(Debug, Serialize)]
struct FcmAps {
    #[serde(rename = "content-available")]
    content_available: u8,
}

impl FcmPushProvider {
    /// Creates a new `FcmPushProvider` by reading the service account key from a file.
    ///
    /// # Errors
    /// Returns an error if the credentials file cannot be read or parsed.
    pub fn new(settings: FcmSettings<'_>, ttl_secs: u64) -> Result<Self, anyhow::Error> {
        let FcmSettings { project_id, credentials_file } = settings;

        let key_json = std::fs::read_to_string(credentials_file)
            .map_err(|e| anyhow::anyhow!("Failed to read FCM credentials file '{credentials_file}': {e}"))?;

        let sa_key: ServiceAccountKey = serde_json::from_str(&key_json)
            .map_err(|e| anyhow::anyhow!("Failed to parse FCM service account JSON: {e}"))?;

        let encoding_key = EncodingKey::from_rsa_pem(sa_key.private_key.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to parse RSA private key from service account: {e}"))?;

        Ok(Self {
            project_id: project_id.to_string(),
            client_email: sa_key.client_email,
            encoding_key,
            http: reqwest::Client::new(),
            token_cache: Arc::new(RwLock::new(None)),
            ttl_secs,
            fcm_base_url: "https://fcm.googleapis.com".to_string(),
            token_endpoint: GOOGLE_TOKEN_URI.to_string(),
        })
    }

    /// Returns a valid `OAuth2` access token, refreshing if necessary.
    ///
    /// Uses a read-biased caching strategy: most callers take a read lock and
    /// get the cached token. Only when the token is missing or near expiry does
    /// a single caller acquire a write lock and refresh.
    #[tracing::instrument(level = "debug", skip(self), err)]
    async fn get_access_token(&self) -> Result<String, PushError> {
        let now = now_secs();

        // Fast path: read lock
        {
            let cache = self.token_cache.read().await;
            if let Some(ref cached) = *cache
                && !cached.needs_refresh(now)
            {
                return Ok(cached.access_token.clone());
            }
        }

        // Slow path: write lock to refresh
        let mut cache = self.token_cache.write().await;

        // Double-check after acquiring write lock (another task may have refreshed)
        if let Some(ref cached) = *cache
            && !cached.needs_refresh(now)
        {
            return Ok(cached.access_token.clone());
        }

        let token = self.fetch_access_token(now).await?;
        let access_token = token.access_token.clone();
        *cache = Some(token);
        drop(cache);
        Ok(access_token)
    }

    /// Performs the JWT bearer assertion flow to obtain a new access token.
    #[tracing::instrument(level = "debug", skip(self), err)]
    async fn fetch_access_token(&self, now: u64) -> Result<CachedToken, PushError> {
        let claims = Claims::assertion(&self.client_email, &self.token_endpoint, now);

        let header = Header::new(Algorithm::RS256);
        let assertion = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|e| PushError::Other(anyhow::anyhow!("Failed to encode JWT assertion: {e}")))?;

        let resp = self
            .http
            .post(&self.token_endpoint)
            .form(&[("grant_type", JWT_BEARER_GRANT_TYPE), ("assertion", &assertion)])
            .send()
            .await
            .map_err(|e| PushError::Other(anyhow::anyhow!("Token exchange request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(PushError::Other(anyhow::anyhow!("Token exchange failed with HTTP {status}: {body}")));
        }

        let token_resp: TokenResponse =
            resp.json().await.map_err(|e| PushError::Other(anyhow::anyhow!("Failed to parse token response: {e}")))?;

        Ok(CachedToken::new(token_resp.access_token, now, token_resp.expires_in))
    }

    /// Sends a data-only push notification via the FCM HTTP v1 API.
    #[tracing::instrument(level = "debug", skip(self, device_token), err)]
    async fn send_fcm_message(&self, device_token: &str) -> Result<(), PushError> {
        let access_token = self.get_access_token().await?;

        let url = format!("{}/v1/projects/{}/messages:send", self.fcm_base_url, self.project_id);

        let ttl_string = format!("{}s", self.ttl_secs);

        let body = FcmRequest {
            message: FcmMessage {
                token: device_token.to_string(),
                data: FcmData { action: "check".to_string() },
                android: FcmAndroid {
                    collapse_key: "obscura_check".to_string(),
                    priority: "HIGH".to_string(),
                    ttl: ttl_string,
                },
                apns: FcmApns {
                    headers: FcmApnsHeaders {
                        push_type: "background".to_string(),
                        priority: "5".to_string(),
                        collapse_id: "obscura_check".to_string(),
                    },
                    payload: FcmApnsPayload { aps: FcmAps { content_available: 1 } },
                },
            },
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| PushError::Other(anyhow::anyhow!("FCM request failed: {e}")))?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }

        let body = resp.text().await.unwrap_or_default();
        Err(FcmErrorResponse::classify(status, &body))
    }
}

#[async_trait]
impl PushProvider for FcmPushProvider {
    #[tracing::instrument(level = "debug", skip(self, token), err)]
    async fn send_push(&self, token: &str) -> Result<(), PushError> {
        self.send_fcm_message(token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::post;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Test-only RSA private key (PKCS#1 PEM). NOT a real credential.
    const TEST_RSA_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEogIBAAKCAQEAwnscBbw1dzfjJFcauXIdZgHu5toKxIOkFNemPMDwPNXPsZxa\n\
nq5BXzRxcgeAsFLCzGbXgjNNc8Ooiu4YWPqK6IW0g0CA3EKfLc/grfJ2U9Jfpa9k\n\
ByIDe589zRn3Dh24bSAh7kRVTpv6UAe2JxOFbJ039YNhxysWQr9HLfjBZygGvH95\n\
Cd54+sgp4ejesqNcyNPHvxd+FhFzJ634OoB9EvUywbXxke3sdSZcywlTX+fliQOc\n\
gzvshQL95tptdABDKf2fqpzffMjvGX0C3OL9K0NrpDxLeC31r7JAyOGFP1H+N0Jh\n\
h99D7dZQkuwLzBmDoxCWzuBMhDhVNHRLlxJPxQIDAQABAoIBACpisOCKHJ/zSPic\n\
WEl29rPK85GSD1s1co8NUeB3T1R+5+FmeXSQd1Rjxl7LBk/HdcedGVZ5zmVOzP6c\n\
did8UUZsj4M0jXETvwP5xJa8m2/Yz3o5f8QzNE2eztYS1N6ZeR6lbGe0sl/rzDHh\n\
gGBDV6asnCvQusBw4kzhScbZ6nLL6yIjPl8HAmU9QZw5rCfPvpR8T6RAwzu59nWG\n\
Xj33wkyiUhzNx8PKNyBqrAHggc+sD2LSakN7BJW/Z+6L5672pZEzx/cAdU+kZpdj\n\
+CE16bZlqCwTdhdtdYT7AmKeBSaiWEaEfyTUAS0u60FuK7atuPAn1iIH/KWqaLVY\n\
gdcvQIkCgYEA/VplpX3X4RaTeZLu5gCVEcirWqhWK2YeSmikb99WL5OcistEjUPC\n\
LjFy5OB6O4UjnBUKm80xLzPNNbQ/+mbjhy2Nkke7fX/DKy9N/9HcpC8Szo9/ZOsk\n\
hlBgzR5wA8T97sNJAYbDZRLxeqRNWGBBr+NNXcjk3bGqO/DiifqITy0CgYEAxINB\n\
nrRwov2GISOg/WxL5YZgfwmntOfycFzW94EvQPCT6O+lxC8FWVZQNQx92QkPVr2Z\n\
jUQPOmOF7k2SUAy+TlOL8S3fze2q54uOvkTZMRZVQ9wzm1D2VHmv34G7ly4Q0IXl\n\
lcSNlDqY1XpPMQLVNCxKe6+quNZvNeMUvUi6ofkCgYB72kMyodB1Ivo5RpEvMz2s\n\
kfLiwMRPNv671Wf9oKqbW4f9ed0rSeKVfmryZKKckjuUQ90JyUewEZzSEinsmXvF\n\
S4mX5yVK9rhMVjXFR6ybPr/s5s2aYjFaz9RiseyEizqwDBuWeXDv6lDOaZ++AmBa\n\
Qb5CiMEJd58G6n10gls8iQKBgCyDQtDtNHpnDQPiqyvcZRC3sJH2IOvkglEbZoIn\n\
3AlMtWRVLGpU8FQ9LevmSXdpCvVt+yM5oG1sb8D8B0FksZLSb+eQqZpe1JCgVxQY\n\
Sk5JLcUyUupCm5mk+saY/2IOSDbDra6QGDXUVBw/GUMTzjGEOtbrgrNdt1Ewf9kk\n\
aUoZAoGAcCvFslTy2JkFimXr0o0vJ2PflUyqP9alCRIEZpISE6H8zxlOdnmDOJJ7\n\
EK65OGSutSasp2ajzr2/7xgNRmRyIbG1jynwl6R7b2ifjqoKVQlgz/BIjuzRy4Rs\n\
wxOWCSTHCchvQGrMpJlCSygGPUKmT/nl464SFJsQcyZLhrwKKW8=\n\
-----END RSA PRIVATE KEY-----\n";

    // ── Helpers ─────────────────────────────────────────────────────────

    /// Creates an `FcmPushProvider` whose HTTP traffic is routed to a local
    /// mock server and whose token cache is pre-populated so no real `OAuth2`
    /// exchange is needed.
    fn mock_provider(fcm_base_url: &str) -> FcmPushProvider {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        FcmPushProvider {
            project_id: "test-project".to_string(),
            client_email: "test@sa.iam.gserviceaccount.com".to_string(),
            encoding_key: EncodingKey::from_secret(b"unused"),
            http: reqwest::Client::new(),
            token_cache: Arc::new(RwLock::new(Some(CachedToken {
                access_token: "mock_token".to_string(),
                expires_at: now + 3600,
            }))),
            ttl_secs: 604_800,
            fcm_base_url: fcm_base_url.to_string(),
            token_endpoint: "http://unused".to_string(),
        }
    }

    /// Starts a one-route axum server and returns the `http://host:port` base URL.
    async fn start_mock_fcm(status: StatusCode, body: &'static str) -> String {
        let app =
            Router::new().route("/v1/projects/{project_id}/messages:send", post(move || async move { (status, body) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());
        format!("http://{addr}")
    }

    // ── Debug redaction tests ────────────────────────────────────────────

    #[test]
    fn service_account_key_debug_is_redacted() {
        let key = ServiceAccountKey {
            client_email: "test@sa.iam.gserviceaccount.com".to_string(),
            private_key: "super-secret-private-key".to_string(),
        };
        let debug = format!("{key:?}");
        assert!(debug.contains("client_email"));
        assert!(!debug.contains("super-secret-private-key"));
    }

    #[test]
    fn cached_token_debug_is_redacted() {
        let token = CachedToken { access_token: "super-secret-access-token".to_string(), expires_at: 12345 };
        let debug = format!("{token:?}");
        assert!(debug.contains("expires_at"));
        assert!(!debug.contains("super-secret-access-token"));
    }

    #[test]
    fn token_response_debug_is_redacted() {
        let resp = TokenResponse { access_token: "super-secret-access-token".to_string(), expires_in: 3600 };
        let debug = format!("{resp:?}");
        assert!(debug.contains("expires_in"));
        assert!(!debug.contains("super-secret-access-token"));
    }

    // ── CachedToken tests ───────────────────────────────────────────────

    #[test]
    fn cached_token_expires_after_its_lifetime() {
        let token = CachedToken::new("test".to_string(), 1_000, 3_600);
        assert_eq!(token.expires_at, 4_600);
    }

    #[test]
    fn cached_token_needs_refresh_from_the_margin_on() {
        let token = CachedToken::new("test".to_string(), 1_000, 3_600);
        assert!(!token.needs_refresh(1_000), "fresh");
        assert!(!token.needs_refresh(4_600 - REFRESH_MARGIN_SECS - 1), "just outside the margin");
        assert!(token.needs_refresh(4_600 - REFRESH_MARGIN_SECS), "at the margin");
        assert!(token.needs_refresh(10_000), "expired");
    }

    #[test]
    fn assertion_is_valid_for_its_ttl() {
        let claims = Claims::assertion("sa@example.com", "https://token.example", 1_000);
        assert_eq!((claims.iat, claims.exp), (1_000, 1_000 + ASSERTION_TTL_SECS));
        assert_eq!((claims.iss.as_str(), claims.aud.as_str()), ("sa@example.com", "https://token.example"));
        assert_eq!(claims.scope, FCM_SCOPE);
    }

    // ── Token cache tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn get_access_token_returns_cached_value() {
        let provider = mock_provider("http://unused");

        let t1 = provider.get_access_token().await.unwrap();
        let t2 = provider.get_access_token().await.unwrap();
        assert_eq!(t1, "mock_token");
        assert_eq!(t2, "mock_token");
    }

    #[tokio::test]
    async fn get_access_token_refreshes_when_expired() {
        // Start a mock token endpoint that returns a fresh token
        let app = Router::new().route(
            "/token",
            post(|| async {
                (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "access_token": "refreshed_token",
                        "expires_in": 3600
                    })),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());
        let token_url = format!("http://{addr}/token");

        let encoding_key = EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).unwrap();

        let provider = FcmPushProvider {
            project_id: "test-project".to_string(),
            client_email: "test@sa.iam.gserviceaccount.com".to_string(),
            encoding_key,
            http: reqwest::Client::new(),
            token_cache: Arc::new(RwLock::new(Some(CachedToken {
                access_token: "stale_token".to_string(),
                expires_at: 0, // Already expired
            }))),
            ttl_secs: 604_800,
            fcm_base_url: "http://unused".to_string(),
            token_endpoint: token_url,
        };

        let token = provider.get_access_token().await.unwrap();
        assert_eq!(token, "refreshed_token");
    }

    #[tokio::test]
    async fn fetch_access_token_error_on_non_success() {
        let app = Router::new().route("/token", post(|| async { (StatusCode::UNAUTHORIZED, "invalid_grant") }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());
        let token_url = format!("http://{addr}/token");

        let encoding_key = EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).unwrap();

        let provider = FcmPushProvider {
            project_id: "test-project".to_string(),
            client_email: "test@sa.iam.gserviceaccount.com".to_string(),
            encoding_key,
            http: reqwest::Client::new(),
            token_cache: Arc::new(RwLock::new(None)),
            ttl_secs: 604_800,
            fcm_base_url: "http://unused".to_string(),
            token_endpoint: token_url,
        };

        let result = provider.fetch_access_token(now_secs()).await;
        assert!(matches!(result, Err(PushError::Other(_))));
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Token exchange failed"), "Unexpected error: {err_msg}");
    }

    // ── Deserialization tests ───────────────────────────────────────────

    #[test]
    fn parse_fcm_error_with_unregistered_detail() {
        let body = r#"{"error":{"status":"INVALID_ARGUMENT","details":[{"errorCode":"UNREGISTERED"}]}}"#;
        let error_resp: FcmErrorResponse = serde_json::from_str(body).unwrap();
        let error = error_resp.error.unwrap();
        let details = error.details.unwrap();
        assert_eq!(details[0].error_code.as_deref(), Some("UNREGISTERED"));
    }

    #[test]
    fn parse_fcm_error_with_not_found_status() {
        let body = r#"{"error":{"status":"NOT_FOUND"}}"#;
        let error_resp: FcmErrorResponse = serde_json::from_str(body).unwrap();
        let error = error_resp.error.unwrap();
        assert_eq!(error.status.as_deref(), Some("NOT_FOUND"));
    }

    #[test]
    fn parse_fcm_error_with_no_details() {
        let body = r#"{"error":{"status":"INTERNAL"}}"#;
        let error_resp: FcmErrorResponse = serde_json::from_str(body).unwrap();
        let error = error_resp.error.unwrap();
        assert_eq!(error.status.as_deref(), Some("INTERNAL"));
        assert!(error.details.is_none());
    }

    #[test]
    fn parse_fcm_error_with_field_violations() {
        let body = r#"{"error":{"status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"message.token","description":"Invalid registration token"}]}]}}"#;
        let error_resp: FcmErrorResponse = serde_json::from_str(body).unwrap();
        let error = error_resp.error.unwrap();
        assert_eq!(error.status.as_deref(), Some("INVALID_ARGUMENT"));
        let details = error.details.unwrap();
        let fvs = details[0].field_violations.as_ref().unwrap();
        assert_eq!(fvs[0].field.as_deref(), Some("message.token"));
    }

    #[test]
    fn parse_service_account_key() {
        let json = r#"{"client_email":"test@test.iam.gserviceaccount.com","private_key":"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----\n"}"#;
        let key: ServiceAccountKey = serde_json::from_str(json).unwrap();
        assert_eq!(key.client_email, "test@test.iam.gserviceaccount.com");
        assert!(key.private_key.contains("RSA PRIVATE KEY"));
    }

    #[test]
    fn fcm_request_serializes_to_v1_format() {
        let req = FcmRequest {
            message: FcmMessage {
                token: "device_token".to_string(),
                data: FcmData { action: "check".to_string() },
                android: FcmAndroid {
                    collapse_key: "obscura_check".to_string(),
                    priority: "HIGH".to_string(),
                    ttl: "604800s".to_string(),
                },
                apns: FcmApns {
                    headers: FcmApnsHeaders {
                        push_type: "background".to_string(),
                        priority: "5".to_string(),
                        collapse_id: "obscura_check".to_string(),
                    },
                    payload: FcmApnsPayload { aps: FcmAps { content_available: 1 } },
                },
            },
        };
        let json = serde_json::to_value(&req).unwrap();

        // Android config
        let android = &json["message"]["android"];
        assert_eq!(android["collapseKey"], "obscura_check");
        assert!(android.get("collapse_key").is_none(), "should use camelCase collapseKey, not snake_case");
        assert_eq!(android["priority"], "HIGH");
        assert_eq!(android["ttl"], "604800s");

        // APNs config for iOS silent push
        let apns = &json["message"]["apns"];
        assert_eq!(apns["headers"]["apns-push-type"], "background");
        assert_eq!(apns["headers"]["apns-priority"], "5");
        assert_eq!(apns["headers"]["apns-collapse-id"], "obscura_check");
        assert_eq!(apns["payload"]["aps"]["content-available"], 1);
    }

    // ── send_fcm_message error-mapping tests ────────────────────────────

    #[tokio::test]
    async fn send_push_success_returns_ok() {
        let url = start_mock_fcm(StatusCode::OK, r#"{"name":"projects/test/messages/123"}"#).await;
        let provider = mock_provider(&url);
        let result = provider.send_push("device_token_abc").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn send_push_429_returns_quota_exceeded() {
        let url = start_mock_fcm(StatusCode::TOO_MANY_REQUESTS, r#"{"error":{"status":"RESOURCE_EXHAUSTED"}}"#).await;
        let provider = mock_provider(&url);
        let result = provider.send_push("device_token_abc").await;
        assert!(matches!(result, Err(PushError::QuotaExceeded)));
    }

    #[tokio::test]
    async fn send_push_body_unregistered_detail_returns_unregistered() {
        let url = start_mock_fcm(
            StatusCode::BAD_REQUEST,
            r#"{"error":{"status":"INVALID_ARGUMENT","details":[{"errorCode":"UNREGISTERED"}]}}"#,
        )
        .await;
        let provider = mock_provider(&url);
        let result = provider.send_push("device_token_abc").await;
        assert!(matches!(result, Err(PushError::Unregistered)));
    }

    #[tokio::test]
    async fn send_push_unparseable_error_body_returns_other() {
        let url = start_mock_fcm(StatusCode::BAD_REQUEST, "not json at all").await;
        let provider = mock_provider(&url);
        let result = provider.send_push("device_token_abc").await;
        assert!(matches!(result, Err(PushError::Other(_))));
    }

    #[test]
    fn classify_failures() {
        use reqwest::StatusCode as S;
        let token_violation = r#"{"error":{"status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"message.token","description":"Invalid registration token"}]}]}}"#;
        let payload_violation = r#"{"error":{"status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"message.data","description":"Payload too large"}]}]}}"#;
        let cases = [
            (S::TOO_MANY_REQUESTS, r#"{"error":{"status":"RESOURCE_EXHAUSTED"}}"#, "quota"),
            (S::TOO_MANY_REQUESTS, "", "quota"),
            (S::NOT_FOUND, r#"{"error":{"status":"NOT_FOUND"}}"#, "unregistered"),
            (S::NOT_FOUND, "", "unregistered"),
            (S::FORBIDDEN, r#"{"error":{"status":"SENDER_ID_MISMATCH"}}"#, "unregistered"),
            (S::BAD_REQUEST, r#"{"error":{"status":"NOT_FOUND"}}"#, "unregistered"),
            (S::BAD_REQUEST, r#"{"error":{"status":"UNREGISTERED"}}"#, "unregistered"),
            (S::BAD_REQUEST, r#"{"error":{"status":"SENDER_ID_MISMATCH"}}"#, "unregistered"),
            (
                S::BAD_REQUEST,
                r#"{"error":{"status":"INVALID_ARGUMENT","details":[{"errorCode":"UNREGISTERED"}]}}"#,
                "unregistered",
            ),
            (S::BAD_REQUEST, token_violation, "unregistered"),
            (S::BAD_REQUEST, payload_violation, "other"),
            (S::BAD_REQUEST, r#"{"error":{"status":"INVALID_ARGUMENT"}}"#, "other"),
            (S::INTERNAL_SERVER_ERROR, token_violation, "other"),
            (S::INTERNAL_SERVER_ERROR, r#"{"error":{"status":"INTERNAL"}}"#, "other"),
            (S::SERVICE_UNAVAILABLE, r#"{"error":{"status":"UNAVAILABLE"}}"#, "other"),
            (S::UNAUTHORIZED, r#"{"error":{"status":"THIRD_PARTY_AUTH_ERROR"}}"#, "other"),
            (S::BAD_REQUEST, "not json at all", "other"),
            (S::BAD_REQUEST, r#"{"error":null}"#, "other"),
        ];
        for (status, body, expected) in cases {
            let got = match FcmErrorResponse::classify(status, body) {
                PushError::Unregistered => "unregistered",
                PushError::QuotaExceeded => "quota",
                PushError::Other(_) => "other",
            };
            assert_eq!(got, expected, "HTTP {status} with body {body}");
        }
    }

    // ── FcmPushProvider::new() constructor tests ────────────────────────

    #[test]
    fn new_nonexistent_file_returns_error() {
        let settings = FcmSettings { project_id: "project", credentials_file: "/tmp/does_not_exist_12345.json" };
        let result = FcmPushProvider::new(settings, 60);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read"));
    }

    #[test]
    fn new_invalid_json_returns_error() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "not valid json").unwrap();
        let path = file.path().to_string_lossy();
        let result = FcmPushProvider::new(FcmSettings { project_id: "project", credentials_file: &path }, 60);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parse FCM service account"));
    }

    #[test]
    fn new_invalid_private_key_returns_error() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, r#"{{"client_email":"test@sa.iam.gserviceaccount.com","private_key":"not-a-pem-key"}}"#).unwrap();
        let path = file.path().to_string_lossy();
        let result = FcmPushProvider::new(FcmSettings { project_id: "project", credentials_file: &path }, 60);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("RSA private key"));
    }

    #[test]
    fn new_valid_credentials_succeeds() {
        let mut file = NamedTempFile::new().unwrap();
        let sa_json = serde_json::json!({
            "client_email": "test@sa.iam.gserviceaccount.com",
            "private_key": TEST_RSA_PEM,
        });
        write!(file, "{sa_json}").unwrap();
        let path = file.path().to_string_lossy();
        let settings = FcmSettings { project_id: "my-project-123", credentials_file: &path };
        let provider = FcmPushProvider::new(settings, 604_800).unwrap();
        assert_eq!(provider.project_id, "my-project-123");
        assert_eq!(provider.client_email, "test@sa.iam.gserviceaccount.com");
        assert_eq!(provider.ttl_secs, 604_800);
    }

    // ── LoggingPushProvider test ────────────────────────────────────────

    #[tokio::test]
    async fn logging_provider_returns_ok() {
        let provider = super::super::LoggingPushProvider;
        let result = provider.send_push("any_token").await;
        assert!(result.is_ok());
    }
}
