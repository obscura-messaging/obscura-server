use crate::api::schemas::crypto::{KemPublicKey, PublicKey, Signature};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KyberPreKey {
    pub key_id: i32,
    pub public_key: KemPublicKey,
    pub signature: Signature,
}

impl From<keys::KyberPreKey> for KyberPreKey {
    fn from(k: keys::KyberPreKey) -> Self {
        Self { key_id: k.key_id, public_key: k.public_key.into(), signature: k.signature.into() }
    }
}

impl TryFrom<KyberPreKey> for keys::KyberPreKey {
    type Error = String;
    fn try_from(schema: KyberPreKey) -> Result<Self, Self::Error> {
        Ok(Self {
            key_id: schema.key_id,
            public_key: crypto::KemPublicKey::try_from(schema.public_key)?,
            signature: crypto::Signature::try_from(schema.signature)?,
        })
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

/// Parses a batch of one-time Kyber pre-keys, rejecting duplicate key IDs and any that reuse the ID of the
/// last-resort Kyber pre-key uploaded with them: a client looks both up by ID in one store.
///
/// # Errors
/// Returns an error if any key ID is duplicated or any key is malformed.
pub fn parse_kyber_pre_keys(
    keys: Vec<KyberPreKey>,
    last_resort_id: Option<i32>,
) -> Result<Vec<keys::KyberPreKey>, String> {
    let mut unique_ids = std::collections::HashSet::with_capacity(keys.len() + 1);
    unique_ids.extend(last_resort_id);
    let mut parsed = Vec::with_capacity(keys.len());
    for pk in keys {
        if !unique_ids.insert(pk.key_id) {
            return Err(format!("Duplicate Kyber prekey ID: {}", pk.key_id));
        }
        parsed.push(pk.try_into()?);
    }
    Ok(parsed)
}

/// The pre-keys of a device being provisioned, flattened into its registration, link or reset payload. Every
/// part is required.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePreKeysRequest {
    pub signed_pre_key: SignedPreKey,
    pub last_resort_kyber_pre_key: KyberPreKey,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
    pub kyber_pre_keys: Vec<KyberPreKey>,
}

impl TryFrom<DevicePreKeysRequest> for keys::DevicePreKeys {
    type Error = String;

    fn try_from(req: DevicePreKeysRequest) -> Result<Self, Self::Error> {
        let one_time_pre_keys = parse_one_time_pre_keys(req.one_time_pre_keys)?;
        let kyber_pre_keys = parse_kyber_pre_keys(req.kyber_pre_keys, Some(req.last_resort_kyber_pre_key.key_id))?;
        Ok(Self {
            signed_pre_key: req.signed_pre_key.try_into()?,
            last_resort_kyber_pre_key: req.last_resort_kyber_pre_key.try_into()?,
            one_time_pre_keys,
            kyber_pre_keys,
        })
    }
}

/// `POST /v1/keys`: any subset of a device's pre-keys, as in Signal's `SetKeysRequest`.
///
/// A present signed or last-resort Kyber pre-key replaces the stored one, a non-empty one-time list replaces
/// the stored keys of that kind, and absent parts are left as they are.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyUploadRequest {
    pub signed_pre_key: Option<SignedPreKey>,
    pub last_resort_kyber_pre_key: Option<KyberPreKey>,
    #[serde(default)]
    pub one_time_pre_keys: Vec<OneTimePreKey>,
    #[serde(default)]
    pub kyber_pre_keys: Vec<KyberPreKey>,
}

impl TryFrom<PreKeyUploadRequest> for keys::PreKeyUpload {
    type Error = String;

    fn try_from(req: PreKeyUploadRequest) -> Result<Self, Self::Error> {
        let last_resort_id = req.last_resort_kyber_pre_key.as_ref().map(|key| key.key_id);
        Ok(Self {
            signed_pre_key: req.signed_pre_key.map(TryInto::try_into).transpose()?,
            last_resort_kyber_pre_key: req.last_resort_kyber_pre_key.map(TryInto::try_into).transpose()?,
            one_time_pre_keys: parse_one_time_pre_keys(req.one_time_pre_keys)?,
            kyber_pre_keys: parse_kyber_pre_keys(req.kyber_pre_keys, last_resort_id)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::api::schemas::crypto::PublicKey as SchemaPublicKey;
    use crate::domain::crypto::{DJB_KEY_PREFIX, KYBER1024_KEY_PREFIX, KYBER1024_PUBLIC_KEY_LENGTH};
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    fn valid_pk() -> SchemaPublicKey {
        let mut bytes = [0u8; 33];
        bytes[0] = DJB_KEY_PREFIX;
        SchemaPublicKey(STANDARD.encode(bytes))
    }

    fn valid_sig() -> Signature {
        Signature(STANDARD.encode([0u8; 64]))
    }

    fn kyber(key_id: i32) -> KyberPreKey {
        let mut bytes = vec![0u8; KYBER1024_PUBLIC_KEY_LENGTH + 1];
        bytes[0] = KYBER1024_KEY_PREFIX;
        KyberPreKey { key_id, public_key: KemPublicKey(STANDARD.encode(bytes)), signature: valid_sig() }
    }

    fn mock_upload() -> PreKeyUploadRequest {
        PreKeyUploadRequest {
            signed_pre_key: Some(SignedPreKey { key_id: 1, public_key: valid_pk(), signature: valid_sig() }),
            last_resort_kyber_pre_key: Some(kyber(1000)),
            one_time_pre_keys: vec![],
            kyber_pre_keys: vec![],
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

    #[test]
    fn test_upload_validation_kyber_keys() {
        let mut upload = mock_upload();
        upload.kyber_pre_keys = vec![kyber(1), kyber(2)];
        let parsed = keys::PreKeyUpload::try_from(upload).expect("distinct Kyber IDs are valid");
        assert_eq!(parsed.kyber_pre_keys.len(), 2);
        assert_eq!(parsed.last_resort_kyber_pre_key.map(|k| k.key_id), Some(1000));
    }

    #[test]
    fn test_upload_validation_duplicate_kyber_keys() {
        let mut upload = mock_upload();
        upload.kyber_pre_keys = vec![kyber(1), kyber(1)];
        let err = keys::PreKeyUpload::try_from(upload).expect_err("duplicate Kyber IDs should fail");
        assert_eq!(err, "Duplicate Kyber prekey ID: 1");
    }

    #[test]
    fn test_upload_validation_kyber_key_reuses_last_resort_id() {
        let mut upload = mock_upload();
        upload.kyber_pre_keys = vec![kyber(1000)];
        let err = keys::PreKeyUpload::try_from(upload).expect_err("a one-time key may not reuse the last-resort ID");
        assert_eq!(err, "Duplicate Kyber prekey ID: 1000");
    }

    #[test]
    fn test_upload_validation_rejects_ec_key_as_kyber() {
        let mut upload = mock_upload();
        upload.last_resort_kyber_pre_key = Some(KyberPreKey { public_key: KemPublicKey(valid_pk().0), ..kyber(1000) });
        let err = keys::PreKeyUpload::try_from(upload).expect_err("an EC key is not a Kyber key");
        assert!(err.contains("Invalid KEM key length"), "{err}");
    }

    #[test]
    fn test_upload_parts_are_optional() {
        let upload: PreKeyUploadRequest = serde_json::from_value(serde_json::json!({})).expect("an empty upload");
        let parsed = keys::PreKeyUpload::try_from(upload).expect("is valid");
        assert!(parsed.signed_pre_key.is_none() && parsed.last_resort_kyber_pre_key.is_none());
        assert!(parsed.one_time_pre_keys.is_empty() && parsed.kyber_pre_keys.is_empty());

        let mut upload = mock_upload();
        upload.last_resort_kyber_pre_key = None;
        upload.kyber_pre_keys = vec![kyber(1000)];
        assert!(keys::PreKeyUpload::try_from(upload).is_ok(), "without a last-resort key, any one-time ID is free");
    }

    #[test]
    fn test_provisioning_requires_every_part() {
        let json = serde_json::json!({
            "signedPreKey": { "keyId": 1, "publicKey": valid_pk().0, "signature": valid_sig().0 },
            "oneTimePreKeys": [],
            "kyberPreKeys": []
        });
        let err = serde_json::from_value::<DevicePreKeysRequest>(json).expect_err("last resort key is required");
        assert!(err.to_string().contains("lastResortKyberPreKey"), "{err}");
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
    pub kyber_pre_key: KyberPreKey,
    pub one_time_pre_key: Option<OneTimePreKey>,
}

impl From<keys::PreKeyBundle> for PreKeyBundleResponse {
    fn from(b: keys::PreKeyBundle) -> Self {
        Self {
            device_id: b.device_id.to_string(),
            registration_id: b.registration_id,
            identity_key: b.identity_key.into(),
            signed_pre_key: b.signed_pre_key.into(),
            kyber_pre_key: b.kyber_pre_key.into(),
            one_time_pre_key: b.one_time_pre_key.map(Into::into),
        }
    }
}
