use crate::domain::crypto::{KemPublicKey, PublicKey, Signature};
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

/// A Kyber pre-key for PQXDH, signed by the account identity key. A device uploads a pool of one-time
/// Kyber pre-keys and one last-resort Kyber pre-key, which is served whenever the pool is empty.
#[derive(Debug, Clone)]
pub struct KyberPreKey {
    pub key_id: i32,
    pub public_key: KemPublicKey,
    pub signature: Signature,
}

impl KyberPreKey {
    /// Verifies that this Kyber pre-key was signed by `identity_key` over its prefixed wire bytes.
    ///
    /// # Errors
    /// Returns an error if the signature does not verify against `identity_key`.
    pub fn verify(&self, identity_key: &PublicKey) -> Result<(), String> {
        identity_key
            .verify_signature(self.public_key.as_bytes(), &self.signature)
            .map_err(|_| format!("Invalid signature on Kyber pre-key {}", self.key_id))
    }
}

/// Everything a client needs to start a PQXDH session with one device. The Kyber pre-key is a
/// one-time key when the device has one left, and its last-resort key otherwise.
#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    pub device_id: Uuid,
    pub registration_id: i32,
    pub identity_key: PublicKey,
    pub signed_pre_key: SignedPreKey,
    pub kyber_pre_key: KyberPreKey,
    pub one_time_pre_key: Option<OneTimePreKey>,
}

/// A device's one-time EC and Kyber pre-key counts, reported because at least one is low.
///
/// Only [`PreKeyStatus::below_threshold`] creates one, so a status always means the device is below the
/// refill threshold in at least one pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreKeyStatus {
    count: u32,
    kyber_count: u32,
    threshold: u32,
}

impl PreKeyStatus {
    /// The status of a device holding `count` one-time EC and `kyber_count` one-time Kyber pre-keys, or
    /// `None` if neither is below `threshold`.
    #[must_use]
    pub const fn below_threshold(count: u32, kyber_count: u32, threshold: u32) -> Option<Self> {
        if count < threshold || kyber_count < threshold { Some(Self { count, kyber_count, threshold }) } else { None }
    }

    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    #[must_use]
    pub const fn kyber_count(&self) -> u32 {
        self.kyber_count
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
pub fn excess_pre_keys(max_pre_keys: NonZeroU32, current: u32, incoming: usize) -> u32 {
    let incoming = u32::try_from(incoming).unwrap_or(u32::MAX);
    current.saturating_add(incoming).saturating_sub(max_pre_keys.get())
}

/// The pre-keys a device publishes, at provisioning and on every refill. Each upload rotates the signed
/// pre-key and the last-resort Kyber pre-key, and adds to both one-time pools.
#[derive(Debug, Clone)]
pub struct PreKeyUpload {
    pub signed_pre_key: SignedPreKey,
    pub last_resort_kyber_pre_key: KyberPreKey,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
    pub kyber_pre_keys: Vec<KyberPreKey>,
}

impl PreKeyUpload {
    /// Verifies the signed pre-key and every Kyber pre-key against `identity_key`.
    ///
    /// # Errors
    /// Returns an error naming the first key whose signature does not verify.
    pub fn verify(&self, identity_key: &PublicKey) -> Result<(), String> {
        self.signed_pre_key.verify(identity_key)?;
        self.last_resort_kyber_pre_key.verify(identity_key)?;
        self.kyber_pre_keys.iter().try_for_each(|key| key.verify(identity_key))
    }

    /// Checks that neither one-time pool in this upload exceeds `max_pre_keys`.
    ///
    /// # Errors
    /// Returns `AppError::BadRequest` if either batch is larger.
    pub fn check_batches(&self, max_pre_keys: NonZeroU32) -> Result<(), AppError> {
        check_pre_key_batch(max_pre_keys, self.one_time_pre_keys.len())?;
        check_pre_key_batch(max_pre_keys, self.kyber_pre_keys.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(max: u32) -> NonZeroU32 {
        NonZeroU32::new(max).unwrap()
    }

    #[test]
    fn test_below_threshold_is_strict() {
        assert_eq!(PreKeyStatus::below_threshold(20, 20, 20), None);
        let status = PreKeyStatus::below_threshold(19, 20, 20).unwrap();
        assert_eq!((status.count(), status.kyber_count(), status.threshold()), (19, 20, 20));
        assert_eq!(PreKeyStatus::below_threshold(0, 50, 20).map(|s| s.count()), Some(0));
        assert_eq!(PreKeyStatus::below_threshold(0, 0, 0), None, "a threshold of 0 never reports");
    }

    #[test]
    fn test_below_threshold_reports_either_pool() {
        let status = PreKeyStatus::below_threshold(50, 3, 20).expect("Kyber pool is low");
        assert_eq!((status.count(), status.kyber_count()), (50, 3));
        assert!(PreKeyStatus::below_threshold(3, 50, 20).is_some(), "EC pool is low");
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
        assert_eq!(excess_pre_keys(limit(50), u32::MAX, usize::MAX), u32::MAX - 50, "saturates, never wraps");
    }
}
