use crate::domain::crypto::{PublicKey, Signature};
use crate::error::AppError;
use std::num::NonZeroU32;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SignedPreKey {
    pub key_id: i32,
    pub public_key: PublicKey,
    pub signature: Signature,
}

impl SignedPreKey {
    /// Verifies that this signed pre-key was signed by `identity_key` (accepting either 33-byte wire
    /// format or 32-byte raw key bytes).
    ///
    /// # Errors
    /// Returns an error if the signature does not verify against `identity_key`.
    pub fn verify(&self, identity_key: &PublicKey) -> Result<(), String> {
        if identity_key.verify_signature(self.public_key.as_bytes(), &self.signature).is_ok() {
            return Ok(());
        }
        identity_key.verify_signature(self.public_key.as_crypto_bytes(), &self.signature)
    }
}

#[derive(Debug, Clone)]
pub struct OneTimePreKey {
    pub key_id: i32,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    pub device_id: Uuid,
    pub registration_id: i32,
    pub identity_key: PublicKey,
    pub signed_pre_key: SignedPreKey,
    pub one_time_pre_key: Option<OneTimePreKey>,
}

/// A device's one-time pre-key count, reported because it is below the refill threshold. Only
/// [`PreKeyStatus::if_low`] creates one, so a status always means the device is low.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreKeyStatus {
    count: u32,
    threshold: u32,
}

impl PreKeyStatus {
    /// The status of a device holding `count` one-time pre-keys, or `None` if it is not below `threshold`.
    #[must_use]
    pub fn if_low(count: i64, threshold: u32) -> Option<Self> {
        let count = u32::try_from(count).ok().filter(|count| *count < threshold)?;
        Some(Self { count, threshold })
    }

    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    #[must_use]
    pub const fn threshold(&self) -> u32 {
        self.threshold
    }
}

/// Checks that an upload of `len` one-time pre-keys stays within `max_pre_keys`, the most a device may hold,
/// which is also the most one upload may carry.
///
/// # Errors
/// Returns `AppError::BadRequest` if the upload is larger.
pub fn check_pre_key_batch(max_pre_keys: NonZeroU32, len: usize) -> Result<(), AppError> {
    if u32::try_from(len).map_or(true, |len| len > max_pre_keys.get()) {
        return Err(AppError::BadRequest(format!("Batch too large. Limit is {max_pre_keys}")));
    }
    Ok(())
}

/// How many of a device's oldest one-time pre-keys to delete so that its `current` keys plus `incoming` new
/// ones fit within `max_pre_keys`.
#[must_use]
pub fn excess_pre_keys(max_pre_keys: NonZeroU32, current: i64, incoming: usize) -> i64 {
    let total = current.saturating_add(i64::try_from(incoming).unwrap_or(i64::MAX));
    total.saturating_sub(i64::from(max_pre_keys.get())).max(0)
}

#[derive(Debug, Clone)]
pub struct PreKeyUpload {
    pub signed_pre_key: SignedPreKey,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(max: u32) -> NonZeroU32 {
        NonZeroU32::new(max).unwrap()
    }

    #[test]
    fn test_if_low_is_strictly_below_the_threshold() {
        assert_eq!(PreKeyStatus::if_low(20, 20), None);
        let status = PreKeyStatus::if_low(19, 20).unwrap();
        assert_eq!((status.count(), status.threshold()), (19, 20));
        assert_eq!(PreKeyStatus::if_low(0, 20).map(|s| s.count()), Some(0));
        assert_eq!(PreKeyStatus::if_low(0, 0), None, "a threshold of 0 never reports");
    }

    #[test]
    fn test_check_batch_allows_exactly_the_limit() {
        assert!(check_pre_key_batch(limit(50), 50).is_ok());
        assert!(
            matches!(check_pre_key_batch(limit(50), 51), Err(AppError::BadRequest(msg)) if msg == "Batch too large. Limit is 50")
        );
        assert!(check_pre_key_batch(limit(50), 0).is_ok());
    }

    #[test]
    fn test_excess_is_what_does_not_fit() {
        assert_eq!(excess_pre_keys(limit(50), 40, 20), 10);
        assert_eq!(excess_pre_keys(limit(50), 40, 10), 0, "exactly at the limit");
        assert_eq!(excess_pre_keys(limit(50), 0, 0), 0);
        assert_eq!(excess_pre_keys(limit(50), 60, 0), 10, "already over, from before a lower limit");
    }
}
