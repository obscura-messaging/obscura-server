use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: Option<String>,
    pub is_primary: bool,
}

/// Validated push notification token for a device (non-empty, trimmed, at most 4096 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushToken(String);

impl PushToken {
    /// Parses and validates a push token string.
    ///
    /// # Errors
    /// Returns an error if the trimmed token is empty or exceeds 4096 characters.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("Token cannot be empty".into());
        }
        if trimmed.len() > 4096 {
            return Err("Token is too long (max 4096 characters)".into());
        }
        Ok(Self(trimmed.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
