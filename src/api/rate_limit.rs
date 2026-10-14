use crate::api::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

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

    state.rate_limit_service.log_decision(status, retry_after.clone());

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

    #[test]
    fn retry_after_rounds_a_floored_wait_up() {
        assert_eq!(retry_after_secs(0), 1);
        assert_eq!(retry_after_secs(4), 5);
    }
}
