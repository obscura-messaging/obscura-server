use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: Option<String>,
    pub role: DeviceRole,
}

/// Whether a device is its account's primary device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRole {
    Primary,
    Linked,
}

impl DeviceRole {
    /// For the database and API, which store and show the role as a flag.
    #[must_use]
    pub const fn from_is_primary(is_primary: bool) -> Self {
        if is_primary { Self::Primary } else { Self::Linked }
    }

    #[must_use]
    pub const fn is_primary(self) -> bool {
        matches!(self, Self::Primary)
    }
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

/// The largest registration ID libsignal generates: they are 14-bit numbers, and Signal's server rejects any
/// outside `1..=0x3FFF` (`Device.MAX_REGISTRATION_ID`).
pub const MAX_REGISTRATION_ID: i32 = 0x3FFF;

/// Checks that `id` is a registration ID libsignal could have generated.
///
/// # Errors
/// Returns an error if `id` is outside `1..=MAX_REGISTRATION_ID`.
pub fn check_registration_id(id: i32) -> Result<(), String> {
    if (1..=MAX_REGISTRATION_ID).contains(&id) {
        Ok(())
    } else {
        Err(format!("Registration ID must be between 1 and {MAX_REGISTRATION_ID}"))
    }
}
