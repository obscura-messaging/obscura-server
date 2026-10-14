use crate::domain::crypto::{PublicKey, Signature};
use crate::domain::keys::{OneTimePreKey, SignedPreKey};

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
    pub(crate) remaining_count: Option<i64>,
}

impl TryFrom<ConsumedPreKeyRecord> for (OneTimePreKey, i64) {
    type Error = String;
    fn try_from(record: ConsumedPreKeyRecord) -> Result<Self, Self::Error> {
        let public_key = PublicKey::try_from(record.public_key)?;
        let count = record.remaining_count.unwrap_or(0);
        Ok((OneTimePreKey { key_id: record.id, public_key }, count))
    }
}
