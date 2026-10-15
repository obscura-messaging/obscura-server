use crate::adapters::database::records::DeviceRecord;
use crate::domain::device::Device;
use crate::error::Result;
use sqlx::PgConnection;
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
pub struct DeviceRepository {}

impl DeviceRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Creates a new device for a user.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the insert fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn create(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        name: Option<&str>,
        registration_id: i32,
        is_primary: bool,
    ) -> Result<Device> {
        let record = sqlx::query_as::<_, DeviceRecord>(
            r#"
            INSERT INTO devices (user_id, name, registration_id, is_primary)
            VALUES ($1, $2, $3, $4)
            RETURNING id, user_id, name, is_primary, created_at
            "#,
        )
        .bind(user_id)
        .bind(name)
        .bind(registration_id)
        .bind(is_primary)
        .fetch_one(conn)
        .await?;

        Ok(record.into())
    }

    /// Lists all devices for a user.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn find_by_user(&self, conn: &mut PgConnection, user_id: Uuid) -> Result<Vec<Device>> {
        let records = sqlx::query_as::<_, DeviceRecord>(
            "SELECT id, user_id, name, is_primary, created_at FROM devices WHERE user_id = $1 ORDER BY created_at ASC",
        )
        .bind(user_id)
        .fetch_all(conn)
        .await?;

        Ok(records.into_iter().map(Into::into).collect())
    }

    /// Deletes a device owned by a specific user.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn delete(&self, conn: &mut PgConnection, device_id: Uuid, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM devices WHERE id = $1 AND user_id = $2")
            .bind(device_id)
            .bind(user_id)
            .execute(conn)
            .await?;
        Ok(())
    }

    /// Deletes every device of a user and returns their ids.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn delete_all_for_user(&self, conn: &mut PgConnection, user_id: Uuid) -> Result<Vec<Uuid>> {
        let ids = sqlx::query_scalar("DELETE FROM devices WHERE user_id = $1 RETURNING id")
            .bind(user_id)
            .fetch_all(conn)
            .await?;

        Ok(ids)
    }

    /// Fetches a single device owned by a specific user.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn find_by_id(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Device>> {
        let record = sqlx::query_as::<_, DeviceRecord>(
            "SELECT id, user_id, name, is_primary, created_at FROM devices WHERE id = $1 AND user_id = $2",
        )
        .bind(device_id)
        .bind(user_id)
        .fetch_optional(conn)
        .await?;

        Ok(record.map(Into::into))
    }

    /// Updates the name of a device owned by a specific user.
    /// Returns the updated device, or `None` if not found or not owned.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the update fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn update_name(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        user_id: Uuid,
        name: Option<&str>,
    ) -> Result<Option<Device>> {
        let record = sqlx::query_as::<_, DeviceRecord>(
            r#"
            UPDATE devices SET name = $1
            WHERE id = $2 AND user_id = $3
            RETURNING id, user_id, name, is_primary, created_at
            "#,
        )
        .bind(name)
        .bind(device_id)
        .bind(user_id)
        .fetch_optional(conn)
        .await?;

        Ok(record.map(Into::into))
    }

    /// Checks if a device belongs to a specific user.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn belongs_to_user(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool> {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1 AND user_id = $2)")
            .bind(device_id)
            .bind(user_id)
            .fetch_one(conn)
            .await?;

        Ok(exists)
    }

    /// Checks if a device exists.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn exists(&self, conn: &mut PgConnection, device_id: Uuid) -> Result<bool> {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1)")
            .bind(device_id)
            .fetch_one(conn)
            .await?;

        Ok(exists)
    }

    /// Counts the number of devices for a user.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn count_by_user(&self, conn: &mut PgConnection, user_id: Uuid) -> Result<i64> {
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM devices WHERE user_id = $1").bind(user_id).fetch_one(conn).await?;

        Ok(count)
    }
}
