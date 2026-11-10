use crate::api::schemas::devices::DeviceKeyPayload;
use crate::domain::auth::AuthSession;
use crate::domain::user::Username;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRequest {
    pub username: String,
    pub password: String,
    #[serde(flatten)]
    pub device: DeviceKeyPayload,
}

impl RegistrationRequest {
    /// Validates the registration credentials and returns the canonical [`Username`].
    ///
    /// # Errors
    /// Returns an error if the password is too short or username is invalid.
    pub fn validate(&self) -> Result<Username, String> {
        let username = Username::parse(&self.username)?;

        if self.password.len() < 12 {
            return Err("Password must be at least 12 characters long".into());
        }

        Ok(username)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::schemas::crypto::{KemPublicKey, PublicKey, Signature};
    use crate::api::schemas::keys::{DevicePreKeysRequest, KyberPreKey, SignedPreKey};

    fn mock_registration(password: &str) -> RegistrationRequest {
        RegistrationRequest {
            username: "testuser".into(),
            password: password.into(),
            device: DeviceKeyPayload {
                name: None,
                identity_key: PublicKey("A".repeat(44)),
                registration_id: 1,
                pre_keys: DevicePreKeysRequest {
                    signed_pre_key: SignedPreKey {
                        key_id: 1,
                        public_key: PublicKey("B".repeat(44)),
                        signature: Signature("C".repeat(88)),
                    },
                    last_resort_kyber_pre_key: KyberPreKey {
                        key_id: 1,
                        public_key: KemPublicKey("D".repeat(2092)),
                        signature: Signature("C".repeat(88)),
                    },
                    one_time_pre_keys: Vec::new(),
                    kyber_pre_keys: Vec::new(),
                },
            },
        }
    }

    #[test]
    fn test_registration_validation_valid() {
        let reg = mock_registration("password12345");
        assert!(reg.validate().is_ok());
    }

    #[test]
    fn test_registration_validation_too_short() {
        let reg = mock_registration("short");
        let res = reg.validate();
        assert!(res.is_err());
        assert_eq!(res.expect_err("Password too short should fail"), "Password must be at least 12 characters long");
    }

    #[test]
    fn test_registration_validation_username_empty() {
        let mut reg = mock_registration("password12345");
        reg.username = String::new();
        let res = reg.validate();
        assert!(res.is_err());
        assert_eq!(res.expect_err("Empty username should fail"), "Username cannot be empty");
    }

    #[test]
    fn test_registration_validation_username_whitespace() {
        let mut reg = mock_registration("password12345");
        reg.username = "   ".into();
        let res = reg.validate();
        assert!(res.is_err());
        assert_eq!(res.expect_err("Whitespace username should fail"), "Username cannot be empty");
    }

    #[test]
    fn test_registration_validation_username_too_long() {
        let mut reg = mock_registration("password12345");
        reg.username = "a".repeat(51);
        let res = reg.validate();
        assert!(res.is_err());
        assert_eq!(
            res.expect_err("Username too long should fail"),
            "Username must be between 3 and 50 characters and can only contain letters, numbers, and underscores"
        );
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub device_id: uuid::Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetAccountRequest {
    pub username: String,
    pub password: String,
    #[serde(flatten)]
    pub device: DeviceKeyPayload,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub user_id: String,
    pub device_id: String,
}

impl From<AuthSession> for AuthResponse {
    fn from(session: AuthSession) -> Self {
        Self {
            token: session.token,
            refresh_token: session.refresh_token,
            expires_at: session.expires_at,
            user_id: session.user_id.to_string(),
            device_id: session.device_id.to_string(),
        }
    }
}
