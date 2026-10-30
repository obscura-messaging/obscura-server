use crate::api::schemas::crypto::PublicKey;
use crate::api::schemas::keys::{OneTimePreKey, SignedPreKey};
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

impl DeviceKeyPayload {
    /// Validates the device key payload.
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

impl TryFrom<DeviceKeyPayload> for NewDeviceKeys {
    type Error = String;

    fn try_from(payload: DeviceKeyPayload) -> Result<Self, Self::Error> {
        payload.validate()?;
        Ok(Self {
            name: payload.name,
            identity_key: payload.identity_key.try_into()?,
            registration_id: payload.registration_id,
            signed_pre_key: payload.signed_pre_key.try_into()?,
            one_time_pre_keys: payload
                .one_time_pre_keys
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
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

    fn mock_device_request(key_ids: Vec<i32>) -> DeviceKeyPayload {
        DeviceKeyPayload {
            name: Some("test-device".to_string()),
            identity_key: PublicKey("A".repeat(44)),
            registration_id: 1,
            signed_pre_key: SignedPreKey {
                key_id: 1,
                public_key: PublicKey("B".repeat(44)),
                signature: Signature("C".repeat(88)),
            },
            one_time_pre_keys: key_ids
                .into_iter()
                .map(|id| OneTimePreKey { key_id: id, public_key: PublicKey("D".repeat(44)) })
                .collect(),
        }
    }

    #[test]
    fn test_validate_unique_prekey_ids() {
        let req = mock_device_request(vec![1, 2, 3]);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_validate_duplicate_prekey_ids() {
        let req = mock_device_request(vec![1, 2, 1]);
        let result = req.validate();
        assert!(result.is_err());
        assert!(result.expect_err("should fail for duplicate IDs").contains("Duplicate prekey ID: 1"));
    }

    #[test]
    fn test_validate_empty_prekeys() {
        let req = mock_device_request(vec![]);
        assert!(req.validate().is_ok());
    }
}
