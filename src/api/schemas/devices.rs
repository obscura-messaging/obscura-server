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
        let identity_key: crate::domain::crypto::PublicKey = payload.identity_key.try_into()?;
        let signed_pre_key: crate::domain::keys::SignedPreKey = payload.signed_pre_key.try_into()?;
        signed_pre_key.verify(&identity_key)?;
        let one_time_pre_keys = parse_one_time_pre_keys(payload.one_time_pre_keys)?;
        Ok(Self {
            name: payload.name,
            identity_key,
            registration_id: payload.registration_id,
            signed_pre_key,
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
}

impl From<crate::domain::device::Device> for DeviceResponse {
    fn from(d: crate::domain::device::Device) -> Self {
        Self { device_id: d.id.to_string(), name: d.name, is_primary: d.is_primary }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceListResponse {
    pub devices: Vec<DeviceResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateLinkSessionRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkSessionResponse {
    pub id: String,
    pub user_id: String,
    pub expires_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::schemas::crypto::Signature;
    use crate::domain::crypto::DJB_KEY_PREFIX;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use xeddsa::xed25519::PrivateKey;
    use xeddsa::{CalculateKeyPair, Sign};

    fn valid_pk() -> PublicKey {
        let mut bytes = [0u8; 33];
        bytes[0] = DJB_KEY_PREFIX;
        PublicKey(STANDARD.encode(bytes))
    }

    fn mock_device_request(key_ids: Vec<i32>) -> DeviceKeyPayload {
        let ik_priv = PrivateKey([7u8; 32]);
        let (_, ik_pub_ed) = ik_priv.calculate_key_pair(0);
        let ik_mont = CompressedEdwardsY(ik_pub_ed).decompress().expect("valid edwards").to_montgomery().to_bytes();
        let mut ik_wire = [0u8; 33];
        ik_wire[0] = DJB_KEY_PREFIX;
        ik_wire[1..].copy_from_slice(&ik_mont);

        let spk_priv = PrivateKey([9u8; 32]);
        let (_, spk_pub_ed) = spk_priv.calculate_key_pair(0);
        let spk_mont = CompressedEdwardsY(spk_pub_ed).decompress().expect("valid edwards").to_montgomery().to_bytes();
        let mut spk_wire = [0u8; 33];
        spk_wire[0] = DJB_KEY_PREFIX;
        spk_wire[1..].copy_from_slice(&spk_mont);

        let mut rng = rand::rng();
        let sig: [u8; 64] = ik_priv.sign(&spk_wire, &mut rng);

        DeviceKeyPayload {
            name: Some("test-device".to_string()),
            identity_key: PublicKey(STANDARD.encode(ik_wire)),
            registration_id: 1,
            signed_pre_key: SignedPreKey {
                key_id: 1,
                public_key: PublicKey(STANDARD.encode(spk_wire)),
                signature: Signature(STANDARD.encode(sig)),
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

    #[test]
    fn test_invalid_signature_rejected_at_parse_time() {
        let mut req = mock_device_request(vec![1]);
        req.signed_pre_key.signature = Signature(STANDARD.encode([0u8; 64]));
        let result = NewDeviceKeys::try_from(req);
        assert_eq!(result.expect_err("should fail for bad signature"), "Invalid signature");
    }
}
