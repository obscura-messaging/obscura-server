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
    /// Verifies that this signed pre-key was signed by `identity_key` over its 33-byte wire format, which is
    /// what libsignal signs and what a peer's libsignal checks when it starts a session.
    ///
    /// # Errors
    /// Returns an error if the signature does not verify against `identity_key`.
    pub fn verify(&self, identity_key: &PublicKey) -> Result<(), String> {
        identity_key.verify_signature(self.public_key.as_bytes(), &self.signature)
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

/// How many one-time pre-keys of each kind a device has left on the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreKeyCounts {
    pub one_time: u32,
    pub kyber: u32,
}

/// Checks that an upload of `len` one-time pre-keys of one kind stays within `max_pre_keys`. An upload replaces
/// the stored keys of that kind, so this is also the most a device ever holds.
///
/// # Errors
/// Returns `AppError::BadRequest` if the upload is larger.
pub fn check_pre_key_batch(max_pre_keys: NonZeroU32, len: usize) -> Result<(), AppError> {
    if u32::try_from(len).map_or(true, |len| len > max_pre_keys.get()) {
        return Err(AppError::BadRequest(format!("Batch too large. Limit is {max_pre_keys}")));
    }
    Ok(())
}

/// The complete set of pre-keys a device publishes when it is provisioned (registration, linking, account
/// reset). Every part is required, so a provisioned device can always serve a PQXDH bundle.
#[derive(Debug, Clone)]
pub struct DevicePreKeys {
    pub signed_pre_key: SignedPreKey,
    pub last_resort_kyber_pre_key: KyberPreKey,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
    pub kyber_pre_keys: Vec<KyberPreKey>,
}

impl DevicePreKeys {
    /// Verifies the signed pre-key and every Kyber pre-key against `identity_key`.
    ///
    /// # Errors
    /// Returns an error naming the first key whose signature does not verify.
    pub fn verify(&self, identity_key: &PublicKey) -> Result<(), String> {
        self.signed_pre_key.verify(identity_key)?;
        self.last_resort_kyber_pre_key.verify(identity_key)?;
        self.kyber_pre_keys.iter().try_for_each(|key| key.verify(identity_key))
    }

    /// Checks that neither one-time list exceeds `max_pre_keys`.
    ///
    /// # Errors
    /// Returns `AppError::BadRequest` if either list is larger.
    pub fn check_batches(&self, max_pre_keys: NonZeroU32) -> Result<(), AppError> {
        check_pre_key_batch(max_pre_keys, self.one_time_pre_keys.len())?;
        check_pre_key_batch(max_pre_keys, self.kyber_pre_keys.len())
    }
}

/// Pre-keys a provisioned device uploads later, as Signal clients do: any subset of the four parts.
///
/// The client rotates the signed and last-resort Kyber pre-keys on a schedule and refills a one-time pool when
/// it runs low; a non-empty one-time list replaces the stored keys of that kind.
#[derive(Debug, Clone, Default)]
pub struct PreKeyUpload {
    pub signed_pre_key: Option<SignedPreKey>,
    pub last_resort_kyber_pre_key: Option<KyberPreKey>,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
    pub kyber_pre_keys: Vec<KyberPreKey>,
}

impl PreKeyUpload {
    /// Verifies every signed key present against `identity_key`.
    ///
    /// # Errors
    /// Returns an error naming the first key whose signature does not verify.
    pub fn verify(&self, identity_key: &PublicKey) -> Result<(), String> {
        if let Some(signed) = &self.signed_pre_key {
            signed.verify(identity_key)?;
        }
        if let Some(last_resort) = &self.last_resort_kyber_pre_key {
            last_resort.verify(identity_key)?;
        }
        self.kyber_pre_keys.iter().try_for_each(|key| key.verify(identity_key))
    }

    /// Checks that neither one-time list exceeds `max_pre_keys`.
    ///
    /// # Errors
    /// Returns `AppError::BadRequest` if either list is larger.
    pub fn check_batches(&self, max_pre_keys: NonZeroU32) -> Result<(), AppError> {
        check_pre_key_batch(max_pre_keys, self.one_time_pre_keys.len())?;
        check_pre_key_batch(max_pre_keys, self.kyber_pre_keys.len())
    }
}

impl From<DevicePreKeys> for PreKeyUpload {
    fn from(keys: DevicePreKeys) -> Self {
        Self {
            signed_pre_key: Some(keys.signed_pre_key),
            last_resort_kyber_pre_key: Some(keys.last_resort_kyber_pre_key),
            one_time_pre_keys: keys.one_time_pre_keys,
            kyber_pre_keys: keys.kyber_pre_keys,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(max: u32) -> NonZeroU32 {
        NonZeroU32::new(max).unwrap()
    }

    fn hex_field(v: &serde_json::Value, field: &str) -> Vec<u8> {
        hex::decode(v[field].as_str().expect(field)).expect(field)
    }

    /// The signatures in `testdata/libsignal-signatures.json` come from libsignal itself, so these keys are
    /// exactly what a Signal client uploads.
    #[test]
    fn test_libsignal_signed_keys_verify() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("testdata/libsignal-signatures.json")).expect("valid fixture");
        for v in doc["vectors"].as_array().expect("vectors") {
            let identity = PublicKey::try_from(hex_field(v, "identityKey")).expect("identity key");
            let signed = SignedPreKey {
                key_id: 1,
                public_key: PublicKey::try_from(hex_field(v, "signedPreKey")).expect("EC key"),
                signature: Signature::try_from(hex_field(v, "signedPreKeySignature")).expect("signature"),
            };
            let kyber = KyberPreKey {
                key_id: 2,
                public_key: KemPublicKey::try_from(hex_field(v, "kyberPreKey")).expect("Kyber key"),
                signature: Signature::try_from(hex_field(v, "kyberPreKeySignature")).expect("signature"),
            };
            assert!(signed.verify(&identity).is_ok());
            assert!(kyber.verify(&identity).is_ok());
            let other = PublicKey::try_from(hex_field(&doc["vectors"][0], "signedPreKey")).expect("EC key");
            assert!(signed.verify(&other).is_err(), "another key's signature does not verify");
        }
    }

    #[test]
    fn test_signed_pre_key_signature_must_cover_the_prefix() {
        use rand::Rng;
        use xeddsa::xed25519::PrivateKey;
        use xeddsa::{CalculateKeyPair, Sign};

        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let identity_private = PrivateKey(seed);
        let (_, ed_public) = identity_private.calculate_key_pair(0);
        let montgomery = curve25519_dalek::edwards::CompressedEdwardsY(ed_public)
            .decompress()
            .expect("valid Edwards key")
            .to_montgomery()
            .to_bytes();
        let mut identity_wire = [crate::domain::crypto::DJB_KEY_PREFIX; 33];
        identity_wire[1..].copy_from_slice(&montgomery);
        let identity = PublicKey::new(identity_wire);

        let mut pre_key_wire = [crate::domain::crypto::DJB_KEY_PREFIX; 33];
        rand::rng().fill_bytes(&mut pre_key_wire[1..]);
        let sign = |message: &[u8]| Signature::new(identity_private.sign(message, rand::rng()));
        let key = |signature| SignedPreKey { key_id: 1, public_key: PublicKey::new(pre_key_wire), signature };

        assert!(key(sign(&pre_key_wire)).verify(&identity).is_ok(), "signed over the 33-byte wire format");
        assert!(key(sign(&pre_key_wire[1..])).verify(&identity).is_err(), "libsignal never signs the bare 32 bytes");
    }

    #[test]
    fn test_check_batch_allows_exactly_the_limit() {
        assert!(check_pre_key_batch(limit(50), 50).is_ok());
        assert!(
            matches!(check_pre_key_batch(limit(50), 51), Err(AppError::BadRequest(msg)) if msg == "Batch too large. Limit is 50")
        );
        assert!(check_pre_key_batch(limit(50), 0).is_ok());
    }
}
