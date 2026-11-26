use crate::error::{AppError, Result};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
pub struct RefreshTokenRepository {}

impl RefreshTokenRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Creates a new refresh token record for a device, replacing any prior refresh tokens for that device.
    /// Note: We store the HASH, not the raw token.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the insert fails.
    #[tracing::instrument(level = "debug", skip(self, conn, token_hash), err)]
    pub(crate) async fn create(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        token_hash: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<()> {
        sqlx::query("DELETE FROM refresh_tokens WHERE device_id = $1")
            .bind(device_id)
            .execute(&mut *conn)
            .await
            .map_err(AppError::Database)?;

        sqlx::query("INSERT INTO refresh_tokens (token_hash, device_id, expires_at) VALUES ($1, $2, $3)")
            .bind(token_hash)
            .bind(device_id)
            .bind(expires_at)
            .execute(conn)
            .await
            .map_err(AppError::Database)?;

        Ok(())
    }

    /// Atomically rotates a refresh token.
    /// Deletes the old token and inserts a new one only if the old one was not expired.
    /// Returns the `(user_id, device_id)` of its device if successful, or None if the old token was invalid or
    /// expired.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the operation fails.
    #[tracing::instrument(level = "debug", skip(self, conn, old_hash, new_hash), err)]
    pub(crate) async fn rotate_unexpired(
        &self,
        conn: &mut PgConnection,
        old_hash: &[u8],
        new_hash: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<Option<(Uuid, Uuid)>> {
        let row = sqlx::query_as::<_, (Uuid, Uuid)>(
            r#"
            WITH deleted AS (
                DELETE FROM refresh_tokens
                WHERE token_hash = $1
                RETURNING device_id, expires_at
            ), inserted AS (
                INSERT INTO refresh_tokens (token_hash, device_id, expires_at)
                SELECT $2, device_id, $3
                FROM deleted
                WHERE expires_at > NOW()
                RETURNING device_id
            )
            SELECT d.user_id, d.id FROM inserted JOIN devices d ON d.id = inserted.device_id
            "#,
        )
        .bind(old_hash)
        .bind(new_hash)
        .bind(expires_at)
        .fetch_optional(conn)
        .await?;

        Ok(row)
    }

    /// Revokes all refresh tokens for a device (Logout).
    ///
    /// # Errors
    /// Returns `AppError::Database` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn delete_for_device(&self, conn: &mut PgConnection, device_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM refresh_tokens WHERE device_id = $1")
            .bind(device_id)
            .execute(conn)
            .await
            .map_err(AppError::Database)?;
        Ok(())
    }

    /// Deletes all expired refresh tokens.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub async fn delete_expired(&self, conn: &mut PgConnection) -> Result<u64> {
        let result = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < NOW()")
            .execute(conn)
            .await
            .map_err(AppError::Database)?;
        Ok(result.rows_affected())
    }
}
