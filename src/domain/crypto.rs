use base64::Engine;
use sha2::{Digest, Sha256};

/// Prefix byte used by Signal/DJB for Montgomery (X25519) keys.
pub const DJB_KEY_PREFIX: u8 = 0x05;

/// Generates a 256-bit cryptographically random URL-safe base64 token (no padding).
#[must_use]
pub fn generate_opaque_token() -> String {
    let bytes = rand::random::<[u8; 32]>();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Hashes an opaque token with SHA-256.
#[must_use]
pub fn hash_opaque_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Strong type for public keys.
/// We store the full 33-byte wire format (`DJB_KEY_PREFIX` + 32-byte Montgomery key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey([u8; 33]);

impl PublicKey {
    #[must_use]
    pub const fn new(bytes: [u8; 33]) -> Self {
        Self(bytes)
    }

    /// Returns the inner 32 bytes for cryptographic operations.
    ///
    /// # Panics
    /// Panics if the internal buffer is not exactly 33 bytes.
    #[must_use]
    pub fn as_crypto_bytes(&self) -> &[u8; 32] {
        self.0[1..].try_into().expect("PublicKey must be 33 bytes")
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    /// Tries to create a `PublicKey` from wire bytes (MUST be 33 bytes with 0x05 prefix).
    ///
    /// # Errors
    /// Returns an error if the length is not 33 bytes or the prefix is incorrect.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 33 {
            return Err(format!("Invalid key length: {} (expected 33 bytes with 0x05 prefix)", bytes.len()));
        }
        if bytes[0] != DJB_KEY_PREFIX {
            return Err(format!("Invalid key prefix (expected 0x{DJB_KEY_PREFIX:02x})"));
        }
        let mut arr = [0u8; 33];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = String;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes)
    }
}

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = String;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from_bytes(&bytes)
    }
}

impl From<PublicKey> for Vec<u8> {
    fn from(key: PublicKey) -> Self {
        key.0.to_vec()
    }
}

/// Strong type for 64-byte Ed25519 signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    #[must_use]
    pub const fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = String;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() == 64 {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(bytes);
            Ok(Self(arr))
        } else {
            Err(format!("Invalid signature length: {} (expected 64)", bytes.len()))
        }
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = String;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl From<Signature> for Vec<u8> {
    fn from(sig: Signature) -> Self {
        sig.0.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_crypto_bytes() {
        let mut bytes = [2u8; 33];
        bytes[0] = DJB_KEY_PREFIX;
        let inner = [3u8; 32];
        bytes[1..].copy_from_slice(&inner);

        let key = PublicKey::try_from_bytes(&bytes).expect("Valid public key bytes");
        assert_eq!(key.as_crypto_bytes(), &inner);
    }

    #[test]
    fn test_public_key_invalid_length() {
        let result = PublicKey::try_from_bytes(&[0u8; 32]);
        assert!(result.expect_err("should fail for wrong length").contains("Invalid key length"));
    }

    #[test]
    fn test_public_key_invalid_prefix() {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x04;
        let result = PublicKey::try_from_bytes(&bytes);
        assert!(result.expect_err("should fail for wrong prefix").contains("Invalid key prefix"));
    }

    #[test]
    fn test_public_key_from_vec() {
        let mut bytes = vec![0u8; 33];
        bytes[0] = DJB_KEY_PREFIX;
        let key = PublicKey::try_from(bytes).expect("Valid public key from Vec");
        assert_eq!(key.as_bytes()[0], DJB_KEY_PREFIX);
    }

    #[test]
    fn test_public_key_into_vec() {
        let mut bytes = [0u8; 33];
        bytes[0] = DJB_KEY_PREFIX;
        let key = PublicKey::new(bytes);
        let vec: Vec<u8> = key.into();
        assert_eq!(vec.len(), 33);
        assert_eq!(vec[0], DJB_KEY_PREFIX);
    }

    #[test]
    fn test_signature_invalid_length() {
        let result = Signature::try_from([0u8; 63].as_slice());
        assert!(result.expect_err("should fail for wrong length").contains("Invalid signature length"));
    }

    #[test]
    fn test_signature_from_vec() {
        let bytes = vec![0u8; 64];
        let sig = Signature::try_from(bytes).expect("Valid signature from Vec");
        assert_eq!(sig.as_bytes().len(), 64);
    }

    #[test]
    fn test_signature_into_vec() {
        let sig = Signature::new([1u8; 64]);
        let vec: Vec<u8> = sig.into();
        assert_eq!(vec.len(), 64);
        assert_eq!(vec[0], 1);
    }

    #[test]
    fn test_opaque_token_logic() {
        let token1 = generate_opaque_token();
        let token2 = generate_opaque_token();

        assert_ne!(token1, token2);

        let hash1 = hash_opaque_token(&token1);
        let hash2 = hash_opaque_token(&token1);
        assert_eq!(hash1, hash2);
    }
}
