use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Claims {
    pub sub: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<Uuid>,
    pub exp: usize,
}
impl Claims {
    #[must_use]
    pub(crate) const fn new(user_id: Uuid, device_id: Option<Uuid>, exp: usize) -> Self {
        Self { sub: user_id, device_id, exp }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Jwt(pub String);
impl Jwt {
    #[must_use]
    pub const fn new(token: String) -> Self {
        Self(token)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Jwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Jwt(***)")
    }
}

impl std::fmt::Display for Jwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "***")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_jwt_debug_is_redacted() {
        let jwt = Jwt::new("super-secret-token".to_string());
        let debug = format!("{jwt:?}");
        assert_eq!(debug, "Jwt(***)");
        assert!(!debug.contains("super-secret-token"));
    }

    #[test]
    fn test_jwt_display_is_redacted() {
        let jwt = Jwt::new("super-secret-token".to_string());
        let display = format!("{jwt}");
        assert_eq!(display, "***");
        assert!(!display.contains("super-secret-token"));
    }

    #[test]
    fn test_jwt_as_str_returns_inner_value() {
        let jwt = Jwt::new("my-token".to_string());
        assert_eq!(jwt.as_str(), "my-token");
    }

    #[test]
    fn test_claims_new_with_device_id() {
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let claims = Claims::new(user_id, Some(device_id), 3600);
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.device_id, Some(device_id));
        assert_eq!(claims.exp, 3600);
    }

    #[test]
    fn test_claims_new_without_device_id() {
        let user_id = Uuid::new_v4();
        let claims = Claims::new(user_id, None, 7200);
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.device_id, None);
        assert_eq!(claims.exp, 7200);
    }
}
