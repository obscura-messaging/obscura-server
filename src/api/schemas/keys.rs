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

/// Parses and validates a batch of one-time pre-keys, rejecting duplicate key IDs.
///
/// # Errors
/// Returns an error if any key ID is duplicated or any public key is malformed.
pub fn parse_one_time_pre_keys(keys: Vec<OneTimePreKey>) -> Result<Vec<keys::OneTimePreKey>, String> {
    let mut unique_ids = std::collections::HashSet::with_capacity(keys.len());
    let mut parsed = Vec::with_capacity(keys.len());
    for pk in keys {
        if !unique_ids.insert(pk.key_id) {
            return Err(format!("Duplicate prekey ID: {}", pk.key_id));
        }
        parsed.push(pk.try_into()?);
    }
    Ok(parsed)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyUploadRequest {
    pub signed_pre_key: SignedPreKey,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
}

impl TryFrom<PreKeyUploadRequest> for keys::PreKeyUpload {
    type Error = String;

    fn try_from(req: PreKeyUploadRequest) -> Result<Self, Self::Error> {
        let one_time_pre_keys = parse_one_time_pre_keys(req.one_time_pre_keys)?;
        Ok(Self { signed_pre_key: req.signed_pre_key.try_into()?, one_time_pre_keys })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::api::schemas::crypto::PublicKey as SchemaPublicKey;
    use crate::domain::crypto::DJB_KEY_PREFIX;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    fn valid_pk() -> SchemaPublicKey {
        let mut bytes = [0u8; 33];
        bytes[0] = DJB_KEY_PREFIX;
        SchemaPublicKey(STANDARD.encode(bytes))
    }

    fn valid_sig() -> Signature {
        Signature(STANDARD.encode([0u8; 64]))
    }

    fn mock_upload() -> PreKeyUploadRequest {
        PreKeyUploadRequest {
            signed_pre_key: SignedPreKey { key_id: 1, public_key: valid_pk(), signature: valid_sig() },
            one_time_pre_keys: vec![],
        }
    }

    #[test]
    fn test_upload_validation_standard_refill() {
        let upload = mock_upload();
        assert!(keys::PreKeyUpload::try_from(upload).is_ok());
    }

    #[test]
    fn test_upload_validation_duplicate_keys() {
        let mut upload = mock_upload();
        upload.one_time_pre_keys = vec![
            OneTimePreKey { key_id: 1, public_key: valid_pk() },
            OneTimePreKey { key_id: 1, public_key: valid_pk() },
        ];
        let res = keys::PreKeyUpload::try_from(upload);
        assert!(res.is_err());
        assert_eq!(res.expect_err("Duplicate prekey IDs should fail"), "Duplicate prekey ID: 1");
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyBundleListResponse {
    pub bundles: Vec<PreKeyBundleResponse>,
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
