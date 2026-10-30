use regex::Regex;
use std::sync::LazyLock;
use time::OffsetDateTime;
use uuid::Uuid;

static USERNAME_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_]{3,50}$").expect("Hardcoded username validation regex should compile"));

/// Canonical, lowercase username.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Username(String);

impl Username {
    /// Validates a registration username and normalizes it to lowercase.
    ///
    /// # Errors
    /// Returns an error if the username is empty or does not match `^[a-zA-Z0-9_]{3,50}$`.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.trim().is_empty() {
            return Err("Username cannot be empty".into());
        }
        if !USERNAME_REGEX.is_match(raw) {
            return Err(
                "Username must be between 3 and 50 characters and can only contain letters, numbers, and underscores"
                    .into(),
            );
        }
        Ok(Self(raw.to_lowercase()))
    }

    /// Normalizes an input username to lowercase for credential lookup.
    #[must_use]
    pub fn normalize(raw: &str) -> Self {
        Self(raw.to_lowercase())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub created_at: Option<OffsetDateTime>,
}
