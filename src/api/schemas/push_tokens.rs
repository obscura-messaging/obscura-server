use crate::domain::device::PushToken;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RegisterPushTokenRequest {
    pub token: String,
}

impl TryFrom<RegisterPushTokenRequest> for PushToken {
    type Error = String;

    fn try_from(req: RegisterPushTokenRequest) -> Result<Self, Self::Error> {
        Self::parse(&req.token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_token_success() {
        let req = RegisterPushTokenRequest { token: "  valid_fcm_token_123  ".into() };
        let token = PushToken::try_from(req).expect("Valid token");
        assert_eq!(token.as_str(), "valid_fcm_token_123");
    }

    #[test]
    fn test_validate_token_empty() {
        let req = RegisterPushTokenRequest { token: "   ".into() };
        let res = PushToken::try_from(req);
        assert!(res.is_err());
        assert_eq!(res.expect_err("Token should be empty"), "Token cannot be empty");
    }

    #[test]
    fn test_validate_token_too_long() {
        let req = RegisterPushTokenRequest { token: "A".repeat(4097) };
        let res = PushToken::try_from(req);
        assert!(res.is_err());
        assert_eq!(res.expect_err("Token should be too long"), "Token is too long (max 4096 characters)");
    }

    #[test]
    fn test_validate_token_at_max_length() {
        let max = "A".repeat(4096);
        let req = RegisterPushTokenRequest { token: format!("  {max}  ") };
        let token = PushToken::try_from(req).expect("a 4096-character token is allowed, measured after trimming");
        assert_eq!(token.as_str(), max);
    }
}
