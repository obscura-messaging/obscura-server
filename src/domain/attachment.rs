use crate::error::AppError;
use thiserror::Error;
use uuid::Uuid;

/// Allowed attachment sizes in bytes, inclusive at both ends. Only constructed through [`SizeLimits::new`],
/// so the minimum never exceeds the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeLimits {
    min: u64,
    max: u64,
}

/// How an attachment size falls outside its [`SizeLimits`].
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeViolation {
    #[error("Attachment too small")]
    TooSmall,
    #[error("Attachment too large")]
    TooLarge,
}

impl SizeLimits {
    /// The limits from `min` to `max`, or `None` if `min` exceeds `max`, which would reject every size.
    #[must_use]
    pub const fn new(min: u64, max: u64) -> Option<Self> {
        if min > max {
            return None;
        }
        Some(Self { min, max })
    }

    /// Checks the size of a complete attachment.
    ///
    /// # Errors
    /// Returns the [`SizeViolation`] if `total` is outside the limits.
    pub const fn check(&self, total: u64) -> Result<(), SizeViolation> {
        if total < self.min {
            return Err(SizeViolation::TooSmall);
        }
        self.check_partial(total)
    }

    /// Checks the bytes received so far of an attachment still streaming in. Only the maximum applies,
    /// because more bytes may still arrive.
    ///
    /// # Errors
    /// Returns [`SizeViolation::TooLarge`] if `so_far` already exceeds the maximum.
    pub const fn check_partial(&self, so_far: u64) -> Result<(), SizeViolation> {
        if so_far > self.max {
            return Err(SizeViolation::TooLarge);
        }
        Ok(())
    }
}

impl From<SizeViolation> for AppError {
    fn from(violation: SizeViolation) -> Self {
        match violation {
            SizeViolation::TooSmall => Self::BadRequest(violation.to_string()),
            SizeViolation::TooLarge => Self::PayloadTooLarge,
        }
    }
}

/// The `ETag` of an attachment: its ID, quoted. Attachments never change, so the ID identifies the content.
#[must_use]
pub fn etag(id: Uuid) -> String {
    format!("\"{id}\"")
}

/// Whether an `If-None-Match` request header matches the attachment `id`.
///
/// Follows RFC 9110's weak comparison: `*`, or any tag in a comma-separated list, with or without a `W/`
/// prefix.
#[must_use]
pub fn etag_matches(id: Uuid, if_none_match: &str) -> bool {
    let quoted = etag(id);
    if_none_match.split(',').map(str::trim).any(|tag| {
        let tag = tag.strip_prefix("W/").unwrap_or(tag);
        tag == "*" || tag == quoted
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etag_header_value_is_the_quoted_id() {
        let id = Uuid::new_v4();
        assert_eq!(etag(id), format!("\"{id}\""));
    }

    #[test]
    fn test_etag_matches() {
        let id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let matches = |header: &str| etag_matches(id, header);
        assert!(matches(&format!("\"{id}\"")));
        assert!(matches(&format!("W/\"{id}\"")), "weak comparison ignores W/");
        assert!(matches(&format!("\"{other}\", \"{id}\"")), "any tag in a list");
        assert!(matches("*"));
        assert!(!matches(&id.to_string()), "an unquoted ID is not an entity tag");
        assert!(!matches(&format!("\"{other}\"")));
        assert!(!matches(""));
        assert!(!matches(&format!("\"{id}")), "a malformed tag does not match");
    }

    #[test]
    fn test_new_rejects_inverted_limits() {
        assert_eq!(SizeLimits::new(11, 10), None);
        assert!(SizeLimits::new(10, 10).is_some(), "equal limits allow exactly one size");
        assert!(SizeLimits::new(0, 10).is_some());
    }

    #[test]
    fn test_check_is_inclusive_at_both_ends() {
        let limits = SizeLimits::new(5, 10).unwrap();
        assert_eq!(limits.check(4), Err(SizeViolation::TooSmall));
        assert_eq!(limits.check(5), Ok(()));
        assert_eq!(limits.check(10), Ok(()));
        assert_eq!(limits.check(11), Err(SizeViolation::TooLarge));
    }

    #[test]
    fn test_check_partial_ignores_the_minimum() {
        let limits = SizeLimits::new(5, 10).unwrap();
        assert_eq!(limits.check_partial(0), Ok(()), "more bytes may still arrive");
        assert_eq!(limits.check_partial(10), Ok(()));
        assert_eq!(limits.check_partial(11), Err(SizeViolation::TooLarge));
    }

    #[test]
    fn test_violations_map_to_api_errors() {
        assert!(matches!(AppError::from(SizeViolation::TooLarge), AppError::PayloadTooLarge));
        assert!(
            matches!(AppError::from(SizeViolation::TooSmall), AppError::BadRequest(msg) if msg == "Attachment too small")
        );
    }
}
