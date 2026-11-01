use crate::api::AppState;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use ipnetwork::IpNetwork;
use opentelemetry::{KeyValue, global, metrics::Counter};
use std::net::{IpAddr, SocketAddr};
use tower_governor::GovernorError;
use tower_governor::key_extractor::KeyExtractor;
use tracing::warn;

#[derive(Clone, Debug)]
pub struct Metrics {
    pub(crate) decisions_total: Counter<u64>,
}

impl Metrics {
    #[must_use]
    pub(crate) fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            decisions_total: meter
                .u64_counter("obscura_rate_limit_decisions_total")
                .with_description("Rate limit decisions (allowed/throttled)")
                .build(),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct IpKeyExtractor {
    pub(crate) trusted_proxies: Vec<IpNetwork>,
}

impl IpKeyExtractor {
    #[must_use]
    pub(crate) const fn new(trusted_proxies: Vec<IpNetwork>) -> Self {
        Self { trusted_proxies }
    }

    #[must_use]
    pub(crate) fn identify_client_ip(&self, headers: &axum::http::HeaderMap, peer_addr: IpAddr) -> IpAddr {
        if !self.is_trusted(&peer_addr) {
            return peer_addr;
        }

        let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());

        if let Some(xff_val) = xff
            && let Some(real_ip) =
                xff_val.rsplit(',').filter_map(|s| s.trim().parse::<IpAddr>().ok()).find(|ip| !self.is_trusted(ip))
        {
            return real_ip;
        }

        peer_addr
    }

    fn is_trusted(&self, ip: &IpAddr) -> bool {
        self.trusted_proxies.iter().any(|net| net.contains(*ip))
    }
}

impl KeyExtractor for IpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        let peer_ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
            .ok_or(GovernorError::UnableToExtractKey)?;

        Ok(self.identify_client_ip(req.headers(), peer_ip))
    }
}

#[derive(Clone, Debug)]
pub struct RateLimiter {
    pub extractor: IpKeyExtractor,
    pub metrics: Metrics,
}

impl RateLimiter {
    #[must_use]
    pub fn new(trusted_proxies: Vec<IpNetwork>) -> Self {
        Self { extractor: IpKeyExtractor::new(trusted_proxies), metrics: Metrics::new() }
    }

    pub fn log_decision(&self, status: StatusCode, ratelimit_after: Option<String>) {
        let label = if status == StatusCode::TOO_MANY_REQUESTS {
            if let Some(after) = ratelimit_after {
                warn!("Rate limit exceeded (retry allowed after {}s)", after);
            }
            "throttled"
        } else {
            "allowed"
        };

        self.metrics.decisions_total.add(1, &[KeyValue::new("status", label)]);
    }
}

/// Middleware to log rate limit events and make `Retry-After` a wait that always suffices.
///
/// The limiter reports its wait floored to whole seconds, so a sub-second wait arrives as `0` and a
/// client that honours it is throttled again.
///
/// # Panics
/// Panics if the limiter's `x-ratelimit-after` header is not an integer.
pub(crate) async fn log_rate_limit_events(State(state): State<AppState>, req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;

    let status = response.status();
    let retry_after =
        if status == StatusCode::TOO_MANY_REQUESTS {
            response.headers().get("x-ratelimit-after").and_then(|v| v.to_str().ok()).map(|floored| {
                retry_after_secs(floored.parse().expect("x-ratelimit-after is whole seconds")).to_string()
            })
        } else {
            None
        };

    state.rate_limiter.log_decision(status, retry_after.clone());

    if let Some(after) = retry_after {
        let value: HeaderValue = after.parse().expect("an integer is a valid header value");
        response.headers_mut().insert("retry-after", value.clone());
        response.headers_mut().insert("x-ratelimit-after", value);
    }

    response
}

/// The limiter's true wait is in `[floored, floored + 1)` seconds.
const fn retry_after_secs(floored: u64) -> u64 {
    floored + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extractor_with_trusted(cidrs: &[&str]) -> IpKeyExtractor {
        let trusted = cidrs.iter().map(|c| c.parse().expect("valid CIDR")).collect();
        IpKeyExtractor::new(trusted)
    }

    #[test]
    fn retry_after_rounds_a_floored_wait_up() {
        assert_eq!(retry_after_secs(0), 1);
        assert_eq!(retry_after_secs(4), 5);
    }

    #[test]
    fn test_direct_connection_no_forwarding() {
        let extractor = extractor_with_trusted(&["10.0.0.0/8"]);
        let headers = axum::http::HeaderMap::new();
        let peer: IpAddr = "203.0.113.5".parse().expect("valid IP");
        assert_eq!(extractor.identify_client_ip(&headers, peer), peer);
    }

    #[test]
    fn test_untrusted_peer_ignores_xff() {
        let extractor = extractor_with_trusted(&["10.0.0.0/8"]);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4".parse().expect("valid header"));
        let peer: IpAddr = "203.0.113.5".parse().expect("valid IP");
        assert_eq!(extractor.identify_client_ip(&headers, peer), peer);
    }

    #[test]
    fn test_trusted_peer_uses_xff() {
        let extractor = extractor_with_trusted(&["10.0.0.0/8"]);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50".parse().expect("valid header"));
        let peer: IpAddr = "10.0.0.1".parse().expect("valid IP");
        let expected: IpAddr = "203.0.113.50".parse().expect("valid IP");
        assert_eq!(extractor.identify_client_ip(&headers, peer), expected);
    }

    #[test]
    fn test_trusted_peer_xff_chain_picks_rightmost_untrusted() {
        let extractor = extractor_with_trusted(&["10.0.0.0/8"]);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "1.1.1.1, 2.2.2.2, 10.0.0.5".parse().expect("valid header"));
        let peer: IpAddr = "10.0.0.1".parse().expect("valid IP");
        let expected: IpAddr = "2.2.2.2".parse().expect("valid IP");
        assert_eq!(extractor.identify_client_ip(&headers, peer), expected);
    }

    #[test]
    fn test_trusted_peer_no_xff_falls_back_to_peer() {
        let extractor = extractor_with_trusted(&["10.0.0.0/8"]);
        let headers = axum::http::HeaderMap::new();
        let peer: IpAddr = "10.0.0.1".parse().expect("valid IP");
        assert_eq!(extractor.identify_client_ip(&headers, peer), expected_peer(peer));
    }

    const fn expected_peer(peer: IpAddr) -> IpAddr {
        peer
    }

    #[test]
    fn test_is_trusted_matching_cidr() {
        let extractor = extractor_with_trusted(&["192.168.1.0/24"]);
        assert!(extractor.is_trusted(&"192.168.1.50".parse().expect("valid IP")));
    }

    #[test]
    fn test_is_trusted_non_matching() {
        let extractor = extractor_with_trusted(&["192.168.1.0/24"]);
        assert!(!extractor.is_trusted(&"10.0.0.1".parse().expect("valid IP")));
    }
}
