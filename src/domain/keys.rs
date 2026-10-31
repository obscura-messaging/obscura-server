use crate::domain::crypto::{PublicKey, Signature};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SignedPreKey {
    pub key_id: i32,
    pub public_key: PublicKey,
    pub signature: Signature,
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
