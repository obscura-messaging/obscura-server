use crate::domain::crypto::{PublicKey, Signature};
use crate::domain::keys::{OneTimePreKey, SignedPreKey};

#[derive(Debug, sqlx::FromRow)]
pub struct IdentityKeyRecord {
    #[sqlx(rename = "identity_key")]
    pub(crate) key: Vec<u8>,
    pub(crate) registration_id: i32,
}

impl TryFrom<IdentityKeyRecord> for PublicKey {
    type Error = String;
    fn try_from(record: IdentityKeyRecord) -> Result<Self, Self::Error> {
        Self::try_from_bytes(&record.key)
    }
}

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
