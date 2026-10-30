use crate::adapters::database::records::UserRecord;
use crate::domain::crypto::PublicKey;
use crate::domain::user::{User, Username};
use crate::error::{AppError, Result};
use sqlx::PgConnection;
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
pub struct UserRepository {}

impl UserRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Creates a new user record with its initial account identity key.
    ///
    /// # Errors
    /// Returns `AppError::Conflict` if the username already exists.
    /// Returns `AppError::Database` for other database failures.
    #[tracing::instrument(level = "debug", skip(self, conn, password_hash, identity_key), err)]
    pub(crate) async fn create(
        &self,
        conn: &mut PgConnection,
        username: &Username,
        password_hash: &str,
        identity_key: &PublicKey,
    ) -> Result<User> {
        let user = sqlx::query_as::<_, UserRecord>(
            r#"
            INSERT INTO users (username, password_hash, identity_key)
            VALUES ($1, $2, $3)
            RETURNING id, username, password_hash, created_at
            "#,
        )
        .bind(username.as_str())
        .bind(password_hash)
        .bind(identity_key.as_bytes())
        .fetch_one(conn)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e
                && db_err.code().as_deref() == Some("23505")
            {
                return AppError::Conflict("Username already exists".into());
            }
            AppError::Database(e)
        })?;

        Ok(user.into())
    }

    /// Finds a user by their username.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn find_by_username(&self, conn: &mut PgConnection, username: &Username) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, UserRecord>(
            r#"
            SELECT id, username, password_hash, created_at
            FROM users
            WHERE username = $1
            "#,
        )
        .bind(username.as_str())
        .fetch_optional(conn)
        .await?;

        Ok(user.map(Into::into))
    }

    /// Locks the user row `FOR UPDATE` and returns the account identity key.
    /// Holding the lock serializes changes to the user's devices. Every device insert must hold it; see
    /// `MessageRepository::lock_device_sets`.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    /// Returns `AppError::Internal` if stored data is corrupt.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn lock_identity_key(&self, conn: &mut PgConnection, user_id: Uuid) -> Result<PublicKey> {
        let bytes: Vec<u8> = sqlx::query_scalar("SELECT identity_key FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(conn)
            .await?;

        PublicKey::try_from_bytes(&bytes).map_err(|e| {
            tracing::error!(error = %e, "Database data corruption: Invalid identity key format");
            AppError::Internal
        })
    }

    /// Replaces the account identity key.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the update fails.
    #[tracing::instrument(level = "debug", skip(self, conn, identity_key), err)]
    pub(crate) async fn set_identity_key(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        identity_key: &PublicKey,
    ) -> Result<()> {
        sqlx::query("UPDATE users SET identity_key = $2 WHERE id = $1")
            .bind(user_id)
            .bind(identity_key.as_bytes())
            .execute(conn)
            .await?;
        Ok(())
    }
}
