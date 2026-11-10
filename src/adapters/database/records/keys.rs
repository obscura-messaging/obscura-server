use crate::domain::crypto::{KemPublicKey, PublicKey, Signature};
use crate::domain::keys::{KyberPreKey, OneTimePreKey, SignedPreKey};

#[derive(Debug, sqlx::FromRow)]
pub struct SignedPreKeyRecord {
    pub(crate) id: i32,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

impl TryFrom<SignedPreKeyRecord> for SignedPreKey {
    type Error = String;
    fn try_from(record: SignedPreKeyRecord) -> Result<Self, Self::Error> {
        let public_key = PublicKey::try_from(record.public_key)?;
        let signature = Signature::try_from(record.signature)?;
        Ok(Self { key_id: record.id, public_key, signature })
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct ConsumedPreKeyRecord {
    pub(crate) id: i32,
    pub(crate) public_key: Vec<u8>,
}

impl TryFrom<ConsumedPreKeyRecord> for OneTimePreKey {
    type Error = String;
    fn try_from(record: ConsumedPreKeyRecord) -> Result<Self, Self::Error> {
        Ok(Self { key_id: record.id, public_key: PublicKey::try_from(record.public_key)? })
    }
}

/// A one-time Kyber pre-key consumed by a bundle fetch, or a device's last-resort Kyber pre-key.
#[derive(Debug, sqlx::FromRow)]
pub struct KyberPreKeyRecord {
    pub(crate) id: i32,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

impl TryFrom<KyberPreKeyRecord> for KyberPreKey {
    type Error = String;
    fn try_from(record: KyberPreKeyRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            key_id: record.id,
            public_key: KemPublicKey::try_from(record.public_key)?,
            signature: Signature::try_from(record.signature)?,
        })
    }
}
