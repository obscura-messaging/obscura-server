use crate::domain::device::{Device, DeviceRole};
use crate::error::AppError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub user_id: Uuid,
    pub device_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Claims {
    pub sub: Uuid,
    pub device_id: Uuid,
    pub exp: usize,
}
impl Claims {
    #[must_use]
    pub(crate) const fn new(user_id: Uuid, device_id: Uuid, exp: usize) -> Self {
        Self { sub: user_id, device_id, exp }
    }

    /// Claims for a token issued at `now` and valid for `ttl_secs`, with `now` in seconds since the UNIX
    /// epoch. Returns `None` if the expiry does not fit in a timestamp.
    #[must_use]
    pub(crate) fn expiring(user_id: Uuid, device_id: Uuid, now: u64, ttl_secs: u64) -> Option<Self> {
        let exp = usize::try_from(now.checked_add(ttl_secs)?).ok()?;
        Some(Self::new(user_id, device_id, exp))
    }
}

/// The authenticated device making a request. Only the API's auth extractor creates one, from a verified
/// access token whose device still exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    user_id: Uuid,
    device_id: Uuid,
    role: DeviceRole,
}

impl Caller {
    #[must_use]
    pub(crate) const fn new(user_id: Uuid, device_id: Uuid, role: DeviceRole) -> Self {
        Self { user_id, device_id, role }
    }

    #[must_use]
    pub const fn user_id(&self) -> Uuid {
        self.user_id
    }

    #[must_use]
    pub const fn device_id(&self) -> Uuid {
        self.device_id
    }

    #[must_use]
    pub const fn role(&self) -> DeviceRole {
        self.role
    }

    /// # Errors
    /// Returns `AppError::Forbidden` unless the caller is the primary device.
    pub fn require_primary(&self) -> Result<(), AppError> {
        match self.role {
            DeviceRole::Primary => Ok(()),
            DeviceRole::Linked => Err(AppError::Forbidden("Primary device required".into())),
        }
    }

    /// Decides whether the caller may delete the device `target_id`, given the caller's own account's
    /// device with that ID, if any. The primary may delete any other device, any device may delete itself,
    /// and the primary itself is only removed by an account reset.
    ///
    /// # Errors
    /// Returns `AppError::Forbidden` if the caller may not delete the device. A linked device asking about
    /// any other device gets this whether or not the device exists.
    /// Returns `AppError::NotFound` if the caller's account has no such device.
    pub fn authorize_deletion(&self, target_id: Uuid, target: Option<&Device>) -> Result<(), AppError> {
        if target_id != self.device_id && self.role == DeviceRole::Linked {
            return Err(AppError::Forbidden("Only the primary device can delete other devices".into()));
        }
        match target {
            None => Err(AppError::NotFound),
            Some(device) if device.role == DeviceRole::Primary => {
                Err(AppError::Forbidden("The primary device cannot be deleted; reset the account instead".into()))
            }
            Some(_) => Ok(()),
        }
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

    #[test]
    fn test_expiring_adds_the_ttl_to_now() {
        let (user, device) = (Uuid::new_v4(), Uuid::new_v4());
        let claims = Claims::expiring(user, device, 1_000, 900).unwrap();
        assert_eq!(claims, Claims::new(user, device, 1_900));
        assert_eq!(Claims::expiring(user, device, u64::MAX, 1), None, "an overflowing expiry is rejected");
    }

    #[test]
    fn test_require_primary() {
        let (user, device) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(Caller::new(user, device, DeviceRole::Primary).require_primary().is_ok());
        assert!(matches!(Caller::new(user, device, DeviceRole::Linked).require_primary(), Err(AppError::Forbidden(_))));
    }

    #[test]
    fn test_authorize_deletion() {
        let user = Uuid::new_v4();
        let (primary_id, linked_id, other_linked_id, missing_id) =
            (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let device =
            |id, is_primary| Device { id, user_id: user, name: None, role: DeviceRole::from_is_primary(is_primary) };
        let primary = Caller::new(user, primary_id, DeviceRole::Primary);
        let linked = Caller::new(user, linked_id, DeviceRole::Linked);

        let outcome = |caller: Caller, target_id, target: Option<Device>| match caller
            .authorize_deletion(target_id, target.as_ref())
        {
            Ok(()) => "ok",
            Err(AppError::NotFound) => "not found",
            Err(AppError::Forbidden(msg)) if msg.starts_with("Only the primary") => "only primary",
            Err(AppError::Forbidden(msg)) if msg.starts_with("The primary device cannot") => "primary kept",
            Err(_) => "unexpected error",
        };

        assert_eq!(outcome(primary, linked_id, Some(device(linked_id, false))), "ok");
        assert_eq!(outcome(linked, linked_id, Some(device(linked_id, false))), "ok", "a device may delete itself");
        assert_eq!(outcome(primary, primary_id, Some(device(primary_id, true))), "primary kept");
        assert_eq!(outcome(linked, primary_id, Some(device(primary_id, true))), "only primary");
        assert_eq!(outcome(linked, other_linked_id, Some(device(other_linked_id, false))), "only primary");
        assert_eq!(outcome(primary, missing_id, None), "not found");
        assert_eq!(
            outcome(linked, missing_id, None),
            "only primary",
            "a linked device learns nothing about whether other devices exist"
        );
        assert_eq!(outcome(linked, linked_id, None), "not found", "deleted concurrently");
    }
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
        let claims = Claims::new(user_id, device_id, 3600);
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.device_id, device_id);
        assert_eq!(claims.exp, 3600);
    }
}
