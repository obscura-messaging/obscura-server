use crate::error::AppError;
use thiserror::Error;

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

#[cfg(test)]
mod tests {
    use super::*;

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
