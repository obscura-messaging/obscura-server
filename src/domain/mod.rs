//! The server's rules, as types and functions that take plain data and do no I/O.
//!
//! Nothing here knows about HTTP. Errors: rules return [`crate::error::AppError`], the error every
//! layer shares, and the API decides what response each variant becomes. A rule gets its own error type
//! only when an adapter must return the error itself, as storage does with [`attachment::SizeViolation`].

pub mod attachment;
pub mod auth;
pub mod crypto;
pub mod device;
pub mod keys;
pub mod message;
pub mod notification;
pub mod user;

use std::num::NonZeroU32;
use time::OffsetDateTime;

/// When something created at `now` expires, `ttl_days` days later.
#[must_use]
pub fn expires_after_days(now: OffsetDateTime, ttl_days: NonZeroU32) -> OffsetDateTime {
    now + time::Duration::days(i64::from(ttl_days.get()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expires_after_days() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let expires = expires_after_days(now, NonZeroU32::new(30).unwrap());
        assert_eq!(expires - now, time::Duration::days(30));
    }
}
