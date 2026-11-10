use crate::domain::crypto;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey(pub String);

impl From<crypto::PublicKey> for PublicKey {
    fn from(pk: crypto::PublicKey) -> Self {
        Self(STANDARD.encode(pk.as_bytes()))
    }
}

impl TryFrom<PublicKey> for crypto::PublicKey {
    type Error = String;
    fn try_from(schema: PublicKey) -> Result<Self, Self::Error> {
        let bytes = STANDARD.decode(&schema.0).map_err(|e| e.to_string())?;
        Self::try_from_bytes(&bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KemPublicKey(pub String);

impl From<crypto::KemPublicKey> for KemPublicKey {
    fn from(pk: crypto::KemPublicKey) -> Self {
        Self(STANDARD.encode(pk.as_bytes()))
    }
}

impl TryFrom<KemPublicKey> for crypto::KemPublicKey {
    type Error = String;
    fn try_from(schema: KemPublicKey) -> Result<Self, Self::Error> {
        let bytes = STANDARD.decode(&schema.0).map_err(|e| e.to_string())?;
        Self::try_from_bytes(&bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Signature(pub String);

impl From<crypto::Signature> for Signature {
    fn from(sig: crypto::Signature) -> Self {
        Self(STANDARD.encode(sig.as_bytes()))
    }
}

impl TryFrom<Signature> for crypto::Signature {
    type Error = String;
    fn try_from(schema: Signature) -> Result<Self, Self::Error> {
        let bytes = STANDARD.decode(&schema.0).map_err(|e| e.to_string())?;
        Self::try_from(bytes.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::crypto::DJB_KEY_PREFIX;

    #[test]
    fn test_public_key_schema_conversion() {
        let mut bytes = [0u8; 33];
        bytes[0] = DJB_KEY_PREFIX;
        let b64 = STANDARD.encode(bytes);

        let schema = PublicKey(b64);
        let domain: crypto::PublicKey = schema.try_into().expect("Valid schema conversion");
        assert_eq!(domain.as_bytes(), &bytes);
    }

    #[test]
    fn test_public_key_schema_malformed_base64() {
        let schema = PublicKey("!!!invalid!!!".to_string());
        let result: Result<crypto::PublicKey, _> = schema.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_schema_invalid_length() {
        let b64 = STANDARD.encode([0u8; 32]); // Missing prefix byte
        let schema = PublicKey(b64);
        let result: Result<crypto::PublicKey, _> = schema.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_schema_conversion() {
        let bytes = [0u8; 64];
        let b64 = STANDARD.encode(bytes);

        let schema = Signature(b64);
        let domain: crypto::Signature = schema.try_into().expect("Valid schema conversion");
        assert_eq!(domain.as_bytes(), &bytes);
    }

    #[test]
    fn test_signature_schema_invalid_length() {
        let b64 = STANDARD.encode([0u8; 63]);
        let schema = Signature(b64);
        let result: Result<crypto::Signature, _> = schema.try_into();
        assert!(result.is_err());
    }
}
