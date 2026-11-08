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
