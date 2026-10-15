use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static USERNAME_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_]{3,50}$").expect("Hardcoded username validation regex should compile"));

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRequest {
    pub username: String,
    pub password: String,
}

impl RegistrationRequest {
    /// Validates the registration payload.
    ///
    /// # Errors
    /// Returns an error if the password is too short or username is invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.username.trim().is_empty() {
            return Err("Username cannot be empty".into());
        }

        if !USERNAME_REGEX.is_match(&self.username) {
            return Err(
                "Username must be between 3 and 50 characters and can only contain letters, numbers, and underscores"
                    .into(),
            );
        }

        if self.password.len() < 12 {
            return Err("Password must be at least 12 characters long".into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_registration(password: &str) -> RegistrationRequest {
        RegistrationRequest { username: "testuser".into(), password: password.into() }
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
    pub device_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetAccountRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}
