use crate::api::schemas::crypto::PublicKey;
use crate::api::schemas::keys::{OneTimePreKey, SignedPreKey, parse_one_time_pre_keys};
use crate::services::device_service::NewDeviceKeys;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyPayload {
    pub name: Option<String>,
    pub identity_key: PublicKey,
    pub registration_id: i32,
    pub signed_pre_key: SignedPreKey,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
}

impl TryFrom<DeviceKeyPayload> for NewDeviceKeys {
    type Error = String;

    fn try_from(payload: DeviceKeyPayload) -> Result<Self, Self::Error> {
        let one_time_pre_keys = parse_one_time_pre_keys(payload.one_time_pre_keys)?;
        Ok(Self {
            name: payload.name,
            identity_key: payload.identity_key.try_into()?,
            registration_id: payload.registration_id,
            signed_pre_key: payload.signed_pre_key.try_into()?,
            one_time_pre_keys,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDeviceRequest {
    pub link_session_id: String,
    #[serde(flatten)]
    pub device: DeviceKeyPayload,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    pub device_id: String,
    pub name: Option<String>,
    pub is_primary: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceListResponse {
    pub devices: Vec<DeviceResponse>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::schemas::crypto::Signature;
    use crate::domain::crypto::DJB_KEY_PREFIX;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    fn valid_pk() -> PublicKey {
        let mut bytes = [0u8; 33];
        bytes[0] = DJB_KEY_PREFIX;
        PublicKey(STANDARD.encode(bytes))
    }

    fn mock_device_request(key_ids: Vec<i32>) -> DeviceKeyPayload {
        DeviceKeyPayload {
            name: Some("test-device".to_string()),
            identity_key: valid_pk(),
            registration_id: 1,
            signed_pre_key: SignedPreKey {
                key_id: 1,
                public_key: valid_pk(),
                signature: Signature(STANDARD.encode([0u8; 64])),
            },
            one_time_pre_keys: key_ids
                .into_iter()
                .map(|id| OneTimePreKey { key_id: id, public_key: valid_pk() })
                .collect(),
        }
    }

    #[test]
    fn test_validate_unique_prekey_ids() {
        let req = mock_device_request(vec![1, 2, 3]);
        assert!(NewDeviceKeys::try_from(req).is_ok());
    }

    #[test]
    fn test_validate_duplicate_prekey_ids() {
        let req = mock_device_request(vec![1, 2, 1]);
        let result = NewDeviceKeys::try_from(req);
        assert!(result.is_err());
        assert!(result.expect_err("should fail for duplicate IDs").contains("Duplicate prekey ID: 1"));
    }

    #[test]
    fn test_validate_empty_prekeys() {
        let req = mock_device_request(vec![]);
        assert!(NewDeviceKeys::try_from(req).is_ok());
    }
}
