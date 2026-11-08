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

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
#[error("Attachment minimum size {min} exceeds maximum size {max}")]
pub struct InvertedSizeLimits {
    pub min: u64,
    pub max: u64,
}

impl SizeLimits {
    /// # Errors
    /// Returns [`InvertedSizeLimits`] if `min` exceeds `max`, which would reject every size.
    pub const fn new(min: u64, max: u64) -> Result<Self, InvertedSizeLimits> {
        if min > max {
            return Err(InvertedSizeLimits { min, max });
        }
        Ok(Self { min, max })
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

/// The entity tag of an attachment. Attachments never change, so the ID alone identifies the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachmentEtag(Uuid);

impl AttachmentEtag {
    #[must_use]
    pub const fn new(id: Uuid) -> Self {
        Self(id)
    }

    /// The value of the `ETag` response header: the ID as a quoted string.
    #[must_use]
    pub fn header_value(&self) -> String {
        format!("\"{}\"", self.0)
    }

    /// Whether an `If-None-Match` request header matches this tag. Follows RFC 9110's weak comparison:
    /// `*`, or any tag in a comma-separated list, with or without a `W/` prefix. A bare unquoted ID also
    /// matches, as earlier versions accepted it.
    #[must_use]
    pub fn matches(&self, if_none_match: &str) -> bool {
        let quoted = self.header_value();
        if_none_match.split(',').map(str::trim).any(|tag| {
            let tag = tag.strip_prefix("W/").unwrap_or(tag);
            tag == "*" || tag == quoted || tag == self.0.to_string()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etag_header_value_is_the_quoted_id() {
        let id = Uuid::new_v4();
        assert_eq!(AttachmentEtag::new(id).header_value(), format!("\"{id}\""));
    }

    #[test]
    fn test_etag_matches() {
        let id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let etag = AttachmentEtag::new(id);
        assert!(etag.matches(&format!("\"{id}\"")));
        assert!(etag.matches(&format!("W/\"{id}\"")), "weak comparison ignores W/");
        assert!(etag.matches(&format!("\"{other}\", \"{id}\"")), "any tag in a list");
        assert!(etag.matches("*"));
        assert!(etag.matches(&id.to_string()), "bare IDs keep working");
        assert!(!etag.matches(&format!("\"{other}\"")));
        assert!(!etag.matches(""));
        assert!(!etag.matches(&format!("\"{id}")), "a malformed tag does not match");
    }

    #[test]
    fn test_new_rejects_inverted_limits() {
        assert_eq!(SizeLimits::new(11, 10), Err(InvertedSizeLimits { min: 11, max: 10 }));
        assert!(SizeLimits::new(10, 10).is_ok(), "equal limits allow exactly one size");
        assert!(SizeLimits::new(0, 10).is_ok());
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
