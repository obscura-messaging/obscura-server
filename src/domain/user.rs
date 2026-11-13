use uuid::Uuid;

/// Whether `raw` matches `^[a-zA-Z0-9_]{3,50}$`. Every allowed character is one byte, so bytes count characters.
fn is_valid_username(raw: &str) -> bool {
    (3..=50).contains(&raw.len()) && raw.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

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
        if !is_valid_username(raw) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_accepts_3_to_50_letters_digits_and_underscores() {
        for ok in ["abc", "A_b_9", &"x".repeat(50)] {
            assert!(Username::parse(ok).is_ok(), "{ok:?} should be accepted");
        }
        assert_eq!(Username::parse("MiXeD_1").expect("valid").as_str(), "mixed_1");
    }

    #[test]
    fn username_rejects_bad_length_or_characters() {
        for bad in ["", "   ", "ab", &"x".repeat(51), "has space", "dash-ed", "dot.ted", "émile", "ab\n"] {
            assert!(Username::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
