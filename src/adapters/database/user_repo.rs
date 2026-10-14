use crate::adapters::database::records::UserRecord;
use crate::domain::crypto::PublicKey;
use crate::domain::user::User;
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

    /// Creates a new user record.
    ///
    /// # Errors
    /// Returns `AppError::Conflict` if the username already exists.
    /// Returns `AppError::Database` for other database failures.
    #[tracing::instrument(level = "debug", skip(self, conn, password_hash), err)]
    pub(crate) async fn create(&self, conn: &mut PgConnection, username: &str, password_hash: &str) -> Result<User> {
        let user = sqlx::query_as::<_, UserRecord>(
            r#"
            INSERT INTO users (username, password_hash)
            VALUES ($1, $2)
            RETURNING id, username, password_hash, created_at
            "#,
        )
        .bind(username)
        .bind(password_hash)
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
    pub(crate) async fn find_by_username(&self, conn: &mut PgConnection, username: &str) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, UserRecord>(
            r#"
            SELECT id, username, password_hash, created_at
            FROM users
            WHERE username = $1
            "#,
        )
        .bind(username)
        .fetch_optional(conn)
        .await?;

        Ok(user.map(Into::into))
    }

    /// Locks the user row and returns the account identity key, if one is set.
    /// Holding the lock serializes device registrations and account resets for the user.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    /// Returns `AppError::Internal` if stored data is corrupt.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn lock_identity_key(&self, conn: &mut PgConnection, user_id: Uuid) -> Result<Option<PublicKey>> {
        let bytes: Option<Vec<u8>> = sqlx::query_scalar("SELECT identity_key FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(conn)
            .await?;

        bytes
            .map(|b| {
                PublicKey::try_from_bytes(&b).map_err(|e| {
                    tracing::error!(error = %e, "Database data corruption: Invalid identity key format");
                    AppError::Internal
                })
            })
            .transpose()
    }

    /// Sets or clears the account identity key.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the update fails.
    #[tracing::instrument(level = "debug", skip(self, conn, identity_key), err)]
    pub(crate) async fn set_identity_key(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        identity_key: Option<&PublicKey>,
    ) -> Result<()> {
        sqlx::query("UPDATE users SET identity_key = $2 WHERE id = $1")
            .bind(user_id)
            .bind(identity_key.map(PublicKey::as_bytes))
            .execute(conn)
            .await?;
        Ok(())
    }
}
