use crate::api::schemas::crypto::{PublicKey, Signature};
use crate::domain::crypto;
use crate::domain::keys;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPreKey {
    pub key_id: i32,
    pub public_key: PublicKey,
    pub signature: Signature,
}

impl From<keys::SignedPreKey> for SignedPreKey {
    fn from(k: keys::SignedPreKey) -> Self {
        Self { key_id: k.key_id, public_key: k.public_key.into(), signature: k.signature.into() }
    }
}

impl TryFrom<SignedPreKey> for keys::SignedPreKey {
    type Error = String;
    fn try_from(schema: SignedPreKey) -> Result<Self, Self::Error> {
        Ok(Self {
            key_id: schema.key_id,
            public_key: crypto::PublicKey::try_from(schema.public_key)?,
            signature: crypto::Signature::try_from(schema.signature)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OneTimePreKey {
    pub key_id: i32,
    pub public_key: PublicKey,
}

impl From<keys::OneTimePreKey> for OneTimePreKey {
    fn from(k: keys::OneTimePreKey) -> Self {
        Self { key_id: k.key_id, public_key: k.public_key.into() }
    }
}

impl TryFrom<OneTimePreKey> for keys::OneTimePreKey {
    type Error = String;
    fn try_from(schema: OneTimePreKey) -> Result<Self, Self::Error> {
        Ok(Self { key_id: schema.key_id, public_key: crypto::PublicKey::try_from(schema.public_key)? })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyUploadRequest {
    pub identity_key: Option<PublicKey>,
    pub signed_pre_key: SignedPreKey,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
}

impl PreKeyUploadRequest {
    /// Validates the pre-key upload payload.
    ///
    /// # Errors
    /// Returns an error if there are duplicate pre-key IDs.
    pub fn validate(&self) -> Result<(), String> {
        let mut unique_ids = std::collections::HashSet::with_capacity(self.one_time_pre_keys.len());
        for pk in &self.one_time_pre_keys {
            if !unique_ids.insert(pk.key_id) {
                return Err(format!("Duplicate prekey ID: {}", pk.key_id));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::schemas::crypto::PublicKey as SchemaPublicKey;

    fn mock_upload() -> PreKeyUploadRequest {
        PreKeyUploadRequest {
            identity_key: None,
            signed_pre_key: SignedPreKey {
                key_id: 1,
                public_key: SchemaPublicKey("A".repeat(44)),
                signature: Signature("B".repeat(88)),
            },
            one_time_pre_keys: vec![],
        }
    }

    #[test]
    fn test_upload_validation_standard_refill() {
        let upload = mock_upload();
        assert!(upload.validate().is_ok());
    }

    #[test]
    fn test_upload_validation_duplicate_keys() {
        let mut upload = mock_upload();
        upload.one_time_pre_keys = vec![
            OneTimePreKey { key_id: 1, public_key: SchemaPublicKey("A".repeat(44)) },
            OneTimePreKey { key_id: 1, public_key: SchemaPublicKey("B".repeat(44)) },
        ];
        let res = upload.validate();
        assert!(res.is_err());
        assert_eq!(res.expect_err("Duplicate prekey IDs should fail"), "Duplicate prekey ID: 1");
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyBundleResponse {
    pub device_id: String,
    pub registration_id: i32,
    pub identity_key: PublicKey,
    pub signed_pre_key: SignedPreKey,
    pub one_time_pre_key: Option<OneTimePreKey>,
}

impl From<keys::PreKeyBundle> for PreKeyBundleResponse {
    fn from(b: keys::PreKeyBundle) -> Self {
        Self {
            device_id: b.device_id.to_string(),
            registration_id: b.registration_id,
            identity_key: b.identity_key.into(),
            signed_pre_key: b.signed_pre_key.into(),
            one_time_pre_key: b.one_time_pre_key.map(Into::into),
        }
    }
}
