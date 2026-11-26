use crate::error::Result;
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
pub struct AttachmentRepository {}

impl AttachmentRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Records a new attachment in the database.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the insert fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn create(&self, conn: &mut PgConnection, id: Uuid, expires_at: OffsetDateTime) -> Result<()> {
        sqlx::query("INSERT INTO attachments (id, expires_at) VALUES ($1, $2)")
            .bind(id)
            .bind(expires_at)
            .execute(conn)
            .await?;
        Ok(())
    }

    /// Checks whether an unexpired attachment with the given ID exists.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn exists_unexpired(&self, conn: &mut PgConnection, id: Uuid) -> Result<bool> {
        let exists =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attachments WHERE id = $1 AND expires_at > NOW())")
                .bind(id)
                .fetch_one(conn)
                .await?;

        Ok(exists)
    }

    /// Deletes an attachment record.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn delete(&self, conn: &mut PgConnection, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM attachments WHERE id = $1").bind(id).execute(conn).await?;
        Ok(())
    }

    /// Fetches a batch of expired attachment IDs.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn fetch_expired(&self, conn: &mut PgConnection, limit: i64) -> Result<Vec<Uuid>> {
        let ids = sqlx::query_scalar("SELECT id FROM attachments WHERE expires_at < NOW() LIMIT $1")
            .bind(limit)
            .fetch_all(conn)
            .await?;

        Ok(ids)
    }
}
