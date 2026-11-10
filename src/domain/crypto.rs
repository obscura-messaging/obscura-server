use base64::Engine;
use ed25519_dalek::Verifier;
use sha2::{Digest, Sha256};
use xeddsa::ConvertMont;

/// Prefix byte used by Signal/DJB for Montgomery (X25519) keys.
pub const DJB_KEY_PREFIX: u8 = 0x05;

/// Prefix byte libsignal uses for Kyber1024 KEM public keys.
pub const KYBER1024_KEY_PREFIX: u8 = 0x08;

/// Length of a Kyber1024 public key, excluding its prefix byte.
pub const KYBER1024_PUBLIC_KEY_LENGTH: usize = 1568;

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

    /// Verifies an `XEdDSA` signature against this Montgomery (Curve25519) public key, as libsignal does.
    ///
    /// A Montgomery key maps to two Edwards keys of opposite sign. libsignal's signer records the sign of its
    /// Edwards key in the top bit of the signature's last byte, and its verifier checks against exactly that
    /// key (`verify_signature` in libsignal's `rust/core/src/curve/curve25519.rs`), so this does the same and
    /// never accepts a signature a libsignal client would reject.
    ///
    /// # Errors
    /// Returns an error if the signature is invalid.
    pub fn verify_signature(&self, message: &[u8], signature: &Signature) -> Result<(), String> {
        let mut sig = *signature.as_bytes();
        let sign_bit = sig[63] >> 7;
        sig[63] &= 0x7F;

        let ed_pk = xeddsa::xed25519::PublicKey(*self.as_crypto_bytes())
            .convert_mont(sign_bit)
            .ok()
            .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok())
            .ok_or("Invalid signature")?;
        ed_pk.verify(message, &ed25519_dalek::Signature::from_bytes(&sig)).map_err(|_| "Invalid signature".into())
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

/// Strong type for KEM public keys used by PQXDH, in libsignal's wire format: the
/// [`KYBER1024_KEY_PREFIX`] type byte followed by the 1568-byte Kyber1024 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemPublicKey(Vec<u8>);

impl KemPublicKey {
    /// The wire bytes, including the type prefix. This is also what the identity key signs.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Tries to create a `KemPublicKey` from wire bytes (MUST be a prefixed Kyber1024 key).
    ///
    /// # Errors
    /// Returns an error if the length or the type prefix is wrong.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != KYBER1024_PUBLIC_KEY_LENGTH + 1 {
            return Err(format!(
                "Invalid KEM key length: {} (expected {} bytes with 0x{KYBER1024_KEY_PREFIX:02x} prefix)",
                bytes.len(),
                KYBER1024_PUBLIC_KEY_LENGTH + 1
            ));
        }
        if bytes[0] != KYBER1024_KEY_PREFIX {
            return Err(format!("Invalid KEM key prefix (expected 0x{KYBER1024_KEY_PREFIX:02x})"));
        }
        Ok(Self(bytes.to_vec()))
    }
}

impl TryFrom<Vec<u8>> for KemPublicKey {
    type Error = String;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from_bytes(&bytes)
    }
}

impl From<KemPublicKey> for Vec<u8> {
    fn from(key: KemPublicKey) -> Self {
        key.0
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

    fn kyber_bytes() -> Vec<u8> {
        let mut bytes = vec![7u8; KYBER1024_PUBLIC_KEY_LENGTH + 1];
        bytes[0] = KYBER1024_KEY_PREFIX;
        bytes
    }

    #[test]
    fn test_kem_public_key_roundtrip() {
        let key = KemPublicKey::try_from(kyber_bytes()).expect("valid Kyber1024 key");
        assert_eq!(key.as_bytes(), kyber_bytes().as_slice());
        assert_eq!(Vec::from(key), kyber_bytes());
    }

    #[test]
    fn test_kem_public_key_invalid_length() {
        let mut bytes = kyber_bytes();
        bytes.pop();
        let err = KemPublicKey::try_from(bytes).expect_err("should fail for wrong length");
        assert!(err.contains("Invalid KEM key length: 1568"), "{err}");
    }

    #[test]
    fn test_kem_public_key_invalid_prefix() {
        let mut bytes = kyber_bytes();
        bytes[0] = DJB_KEY_PREFIX;
        let err = KemPublicKey::try_from(bytes).expect_err("should fail for an EC prefix");
        assert!(err.contains("Invalid KEM key prefix"), "{err}");
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

    /// One libsignal-produced signing vector; see `testdata/libsignal-signatures.json`.
    struct LibsignalVector {
        sign_bit: u8,
        identity_key: PublicKey,
        signed_pre_key: Vec<u8>,
        signed_pre_key_signature: Signature,
        kyber_pre_key: Vec<u8>,
        kyber_pre_key_signature: Signature,
    }

    fn libsignal_vectors() -> Vec<LibsignalVector> {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("testdata/libsignal-signatures.json")).expect("valid fixture");
        let bytes = |v: &serde_json::Value, field: &str| hex::decode(v[field].as_str().expect(field)).expect(field);
        doc["vectors"]
            .as_array()
            .expect("vectors")
            .iter()
            .map(|v| LibsignalVector {
                sign_bit: u8::try_from(v["signBit"].as_u64().expect("signBit")).expect("a bit"),
                identity_key: PublicKey::try_from(bytes(v, "identityKey")).expect("identity key"),
                signed_pre_key: bytes(v, "signedPreKey"),
                signed_pre_key_signature: Signature::try_from(bytes(v, "signedPreKeySignature")).expect("signature"),
                kyber_pre_key: bytes(v, "kyberPreKey"),
                kyber_pre_key_signature: Signature::try_from(bytes(v, "kyberPreKeySignature")).expect("signature"),
            })
            .collect()
    }

    fn flip_sign_bit(signature: &Signature) -> Signature {
        let mut bytes = *signature.as_bytes();
        bytes[63] ^= 0x80;
        Signature::new(bytes)
    }

    #[test]
    fn test_verify_accepts_libsignal_signatures() {
        let vectors = libsignal_vectors();
        assert_eq!(vectors.iter().map(|v| v.sign_bit).collect::<Vec<_>>(), vec![0, 1], "one vector per sign");
        for v in &vectors {
            assert!(
                v.identity_key.verify_signature(&v.signed_pre_key, &v.signed_pre_key_signature).is_ok(),
                "EC pre-key, sign bit {}",
                v.sign_bit
            );
            assert!(
                v.identity_key.verify_signature(&v.kyber_pre_key, &v.kyber_pre_key_signature).is_ok(),
                "Kyber pre-key, sign bit {}",
                v.sign_bit
            );
        }
    }

    #[test]
    fn test_verify_rejects_signature_with_flipped_sign_bit() {
        // libsignal verifies against the Edwards key the sign bit names, so it rejects these; so must we.
        for v in libsignal_vectors() {
            let flipped = flip_sign_bit(&v.signed_pre_key_signature);
            assert!(
                v.identity_key.verify_signature(&v.signed_pre_key, &flipped).is_err(),
                "flipped sign bit on a sign-bit-{} signature",
                v.sign_bit
            );
        }
    }

    #[test]
    fn test_verify_signature_exhaustive_robustness() {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use rand::Rng;
        use xeddsa::xed25519::PrivateKey;
        use xeddsa::{CalculateKeyPair, Sign};

        let mut rng = rand::rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let xed_priv = PrivateKey(seed);

        for ik_sign in [0, 1] {
            let (_, ed_pub) = xed_priv.calculate_key_pair(ik_sign);
            let mont_pub = CompressedEdwardsY(ed_pub)
                .decompress()
                .expect("Failed to decompress Edwards public key")
                .to_montgomery()
                .to_bytes();

            let mut ik_wire = [0u8; 33];
            ik_wire[0] = DJB_KEY_PREFIX;
            ik_wire[1..].copy_from_slice(&mont_pub);
            let ik_pub = PublicKey::new(ik_wire);

            let msg_32 = [0x42u8; 32];
            let mut msg_33 = [0x00u8; 33];
            msg_33[0] = DJB_KEY_PREFIX;
            msg_33[1..].copy_from_slice(&msg_32);

            let sig_32 = Signature::new(xed_priv.sign(&msg_32, &mut rng));
            let sig_33 = Signature::new(xed_priv.sign(&msg_33, &mut rng));

            assert!(ik_pub.verify_signature(&msg_32, &sig_32).is_ok(), "Failed 32-byte msg for ik_sign={ik_sign}");
            assert!(ik_pub.verify_signature(&msg_33, &sig_33).is_ok(), "Failed 33-byte msg for ik_sign={ik_sign}");
        }
    }
}
