use crate::domain::crypto::{PublicKey, Signature};
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

#[derive(Debug, Clone)]
pub struct PreKeyStatus {
    pub one_time_pre_key_count: i32,
    pub min_threshold: i32,
}

#[derive(Debug, Clone)]
pub struct PreKeyUpload {
    pub signed_pre_key: SignedPreKey,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
}
