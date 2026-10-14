use crate::adapters::database::records::MessageRecord;
use crate::domain::message::Message;
use crate::error::{AppError, Result};
use sqlx::PgConnection;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
pub struct MessageRepository {}

impl MessageRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Locks the device sets of the sender and of every user owning one of `target_device_ids`, and
    /// returns `(device_id, user_id)` for each of their devices.
    ///
    /// The user rows are locked `FOR UPDATE` in id order. Inserting a device takes `FOR KEY SHARE` on
    /// its user row through the foreign key, so no device can be added to these users until the
    /// transaction ends; the devices are locked `FOR KEY SHARE`, so none can be deleted either. The
    /// sender is locked too because inserting messages takes `FOR KEY SHARE` on the sender's row, and
    /// locking it in the same ordered statement keeps two users sending to each other deadlock-free.
    ///
    /// # Errors
    /// Returns `AppError::Database` if a query fails.
    #[tracing::instrument(level = "debug", skip(self, conn))]
    pub(crate) async fn lock_device_sets(
        &self,
        conn: &mut PgConnection,
        sender_id: Uuid,
        target_device_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, Uuid)>> {
        let user_ids: Vec<Uuid> = sqlx::query_scalar(
            r#"
            SELECT id FROM users
            WHERE id = $1 OR id IN (SELECT user_id FROM devices WHERE id = ANY($2))
            ORDER BY id
            FOR UPDATE
            "#,
        )
        .bind(sender_id)
        .bind(target_device_ids)
        .fetch_all(&mut *conn)
        .await?;

        let devices = sqlx::query_as("SELECT id, user_id FROM devices WHERE user_id = ANY($1) FOR KEY SHARE")
            .bind(user_ids)
            .fetch_all(conn)
            .await?;

        Ok(devices)
    }

    /// Inserts a batch of messages.
    ///
    /// Ignores duplicate messages (based on `sender_device_id` and `submission_id`) via `ON CONFLICT DO NOTHING`.
    /// Returns the list of `(device_id, submission_id)` that were successfully inserted.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the insert fails.
    #[tracing::instrument(level = "debug", skip(self, conn, messages))]
    pub(crate) async fn create_batch(
        &self,
        conn: &mut PgConnection,
        sender_id: Uuid,
        sender_device_id: Uuid,
        messages: Vec<(Uuid, Uuid, Vec<u8>)>,
        ttl_days: i64,
    ) -> Result<Vec<(Uuid, Uuid)>> {
        if messages.is_empty() {
            return Ok(Vec::new());
        }

        let expires_at = OffsetDateTime::now_utc() + Duration::days(ttl_days);

        let mut device_ids = Vec::with_capacity(messages.len());
        let mut submission_ids = Vec::with_capacity(messages.len());
        let mut contents = Vec::with_capacity(messages.len());

        for (device_id, submission_id, content) in messages {
            device_ids.push(device_id);
            submission_ids.push(submission_id);
            contents.push(content);
        }

        let inserted = sqlx::query_as::<_, (Uuid, Uuid)>(
            r#"
            INSERT INTO messages (sender_id, sender_device_id, device_id, submission_id, content, expires_at)
            SELECT $1, $2, u.d_id, u.s_id, u.content, $6
            FROM UNNEST($3::uuid[], $4::uuid[], $5::bytea[]) AS u(d_id, s_id, content)
            ON CONFLICT (sender_device_id, submission_id) DO NOTHING
            RETURNING device_id, submission_id
            "#,
        )
        .bind(sender_id)
        .bind(sender_device_id)
        .bind(device_ids)
        .bind(submission_ids)
        .bind(contents)
        .bind(expires_at)
        .fetch_all(conn)
        .await
        .map_err(AppError::Database)?;

        Ok(inserted)
    }

    /// Fetches a batch of pending messages for a device.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn))]
    pub(crate) async fn fetch_pending_batch(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        cursor: Option<(OffsetDateTime, Uuid)>,
        limit: i64,
    ) -> Result<Vec<Message>> {
        let messages = match cursor {
            Some((last_ts, last_id)) => {
                sqlx::query_as::<_, MessageRecord>(
                    r#"
                    SELECT id, sender_id, sender_device_id, content, created_at
                    FROM messages
                    WHERE device_id = $1
                      AND expires_at > NOW()
                      AND (created_at, id) > ($2, $3)
                    ORDER BY created_at ASC, id ASC
                    LIMIT $4
                    "#,
                )
                .bind(device_id)
                .bind(last_ts)
                .bind(last_id)
                .bind(limit)
                .fetch_all(conn)
                .await?
            }
            None => {
                sqlx::query_as::<_, MessageRecord>(
                    r#"
                    SELECT id, sender_id, sender_device_id, content, created_at
                    FROM messages
                    WHERE device_id = $1
                      AND expires_at > NOW()
                    ORDER BY created_at ASC, id ASC
                    LIMIT $2
                    "#,
                )
                .bind(device_id)
                .bind(limit)
                .fetch_all(conn)
                .await?
            }
        };

        Ok(messages.into_iter().map(Into::into).collect())
    }

    /// Deletes a batch of messages for a specific device.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn))]
    pub(crate) async fn delete_batch(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        message_ids: &[Uuid],
    ) -> Result<()> {
        if message_ids.is_empty() {
            return Ok(());
        }
        sqlx::query("DELETE FROM messages WHERE id = ANY($1) AND device_id = $2")
            .bind(message_ids)
            .bind(device_id)
            .execute(conn)
            .await?;
        Ok(())
    }

    /// Deletes all expired messages.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub async fn delete_expired(&self, conn: &mut PgConnection) -> Result<u64> {
        let result = sqlx::query("DELETE FROM messages WHERE expires_at < NOW()").execute(conn).await?;
        Ok(result.rows_affected())
    }

    /// Enforces global inbox limits by pruning the oldest messages per device.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub async fn delete_global_overflow(&self, conn: &mut PgConnection, limit: i64) -> Result<u64> {
        // Deletes messages that exceed the 'limit' per device
        let result = sqlx::query(
            r#"
            DELETE FROM messages
            WHERE id IN (
                SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY created_at DESC) as rn
                    FROM messages
                ) t WHERE t.rn > $1
            )
            "#,
        )
        .bind(limit)
        .execute(conn)
        .await?;
        Ok(result.rows_affected())
    }

    /// Deletes all messages for a specific device (Inbox wipe).
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn))]
    pub(crate) async fn delete_all_for_device(&self, conn: &mut PgConnection, device_id: Uuid) -> Result<u64> {
        let result = sqlx::query("DELETE FROM messages WHERE device_id = $1").bind(device_id).execute(conn).await?;
        Ok(result.rows_affected())
    }
}
