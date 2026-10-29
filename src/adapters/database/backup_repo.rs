use crate::adapters::database::records::BackupRecord;
use crate::domain::backup::Backup;
use crate::error::Result;
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
pub struct BackupRepository {}

impl BackupRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Finds a backup record by device ID.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn find_by_device_id(&self, conn: &mut PgConnection, device_id: Uuid) -> Result<Option<Backup>> {
        let record = sqlx::query_as::<_, BackupRecord>("SELECT * FROM backups WHERE device_id = $1")
            .bind(device_id)
            .fetch_optional(conn)
            .await?;

        Ok(record.map(Into::into))
    }

    /// Creates a new backup record if it doesn't exist.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn create_if_not_exists(&self, conn: &mut PgConnection, device_id: Uuid) -> Result<Backup> {
        let record = sqlx::query_as::<_, BackupRecord>(
            r#"
            INSERT INTO backups (device_id)
            VALUES ($1)
            ON CONFLICT (device_id) DO UPDATE SET device_id = EXCLUDED.device_id
            RETURNING *
            "#,
        )
        .bind(device_id)
        .fetch_one(conn)
        .await?;

        Ok(record.into())
    }

    /// Reserves a slot for uploading a new backup version.
    /// Returns the updated backup record if successful (version matched).
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn reserve_active_slot(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        expected_version: i32,
    ) -> Result<Option<Backup>> {
        let record = sqlx::query_as::<_, BackupRecord>(
            r#"
            UPDATE backups
            SET 
                state = 'UPLOADING',
                pending_version = current_version + 1,
                pending_at = NOW()
            WHERE device_id = $1 AND current_version = $2 AND state = 'ACTIVE'
            RETURNING *
            "#,
        )
        .bind(device_id)
        .bind(expected_version)
        .fetch_optional(conn)
        .await?;

        Ok(record.map(Into::into))
    }

    /// Reserves a slot without checking version (force update).
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn reserve_slot_force(&self, conn: &mut PgConnection, device_id: Uuid) -> Result<Backup> {
        let record = sqlx::query_as::<_, BackupRecord>(
            r#"
            UPDATE backups
            SET 
                state = 'UPLOADING',
                pending_version = current_version + 1,
                pending_at = NOW()
            WHERE device_id = $1
            RETURNING *
            "#,
        )
        .bind(device_id)
        .fetch_one(conn)
        .await?;
        Ok(record.into())
    }

    /// Commits the pending version.
    ///
    /// # Errors
    /// Returns `AppError::Conflict` if the upload slot was lost concurrently.
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn commit_version(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        pending_version: i32,
    ) -> Result<()> {
        let result = sqlx::query(
            r#"
            UPDATE backups
            SET 
                current_version = $2,
                pending_version = NULL,
                state = 'ACTIVE',
                updated_at = NOW(),
                pending_at = NULL
            WHERE device_id = $1 AND pending_version = $2 AND state = 'UPLOADING'
            "#,
        )
        .bind(device_id)
        .bind(pending_version)
        .execute(conn)
        .await?;
        if result.rows_affected() == 0 {
            return Err(crate::error::AppError::Conflict("Concurrent modification".into()));
        }
        Ok(())
    }

    /// Fetches stale uploads for cleanup.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn fetch_stale_uploads(
        &self,
        conn: &mut PgConnection,
        threshold: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<Backup>> {
        let records = sqlx::query_as::<_, BackupRecord>(
            "SELECT * FROM backups WHERE state = 'UPLOADING' AND pending_at < $1 LIMIT $2",
        )
        .bind(threshold)
        .bind(limit)
        .fetch_all(conn)
        .await?;

        Ok(records.into_iter().map(Into::into).collect())
    }

    /// Resets a stale upload to ACTIVE state only if it is still stale.
    /// Returns true if the row was reset.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn reset_stale(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        threshold: OffsetDateTime,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE backups SET state = 'ACTIVE', pending_version = NULL, pending_at = NULL \
             WHERE device_id = $1 AND state = 'UPLOADING' AND pending_at < $2",
        )
        .bind(device_id)
        .bind(threshold)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Finds all backup records belonging to any device of the user.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn find_by_user_id(&self, conn: &mut PgConnection, user_id: Uuid) -> Result<Vec<Backup>> {
        let records = sqlx::query_as::<_, BackupRecord>(
            "SELECT b.* FROM backups b JOIN devices d ON d.id = b.device_id WHERE d.user_id = $1",
        )
        .bind(user_id)
        .fetch_all(conn)
        .await?;

        Ok(records.into_iter().map(Into::into).collect())
    }
}
