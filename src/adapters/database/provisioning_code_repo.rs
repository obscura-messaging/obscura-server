use crate::error::Result;
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
pub struct ProvisioningCodeRepository {}

impl ProvisioningCodeRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Stores the hash of a provisioning code issued by a device.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the insert fails.
    #[tracing::instrument(level = "debug", skip(self, conn, code_hash), err)]
    pub(crate) async fn create(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        code_hash: &str,
        expires_at: OffsetDateTime,
    ) -> Result<()> {
        sqlx::query("INSERT INTO provisioning_codes (code_hash, device_id, expires_at) VALUES ($1, $2, $3)")
            .bind(code_hash)
            .bind(device_id)
            .bind(expires_at)
            .execute(conn)
            .await?;
        Ok(())
    }

    /// Deletes the expired codes issued by a device.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn delete_expired_for_device(&self, conn: &mut PgConnection, device_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM provisioning_codes WHERE device_id = $1 AND expires_at <= NOW()")
            .bind(device_id)
            .execute(conn)
            .await?;
        Ok(())
    }

    /// Consumes an unexpired code issued by one of the user's devices.
    /// Returns true if such a code existed.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn, code_hash), err)]
    pub(crate) async fn consume(&self, conn: &mut PgConnection, user_id: Uuid, code_hash: &str) -> Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM provisioning_codes c
            USING devices d
            WHERE c.code_hash = $1 AND c.device_id = d.id AND d.user_id = $2 AND c.expires_at > NOW()
            "#,
        )
        .bind(code_hash)
        .bind(user_id)
        .execute(conn)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}
