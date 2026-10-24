use crate::error::Result;
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
pub struct LinkSessionRepository {}

impl LinkSessionRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Stores a new, unapproved link session by the hash of its id.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the insert fails.
    #[tracing::instrument(level = "debug", skip(self, conn, id_hash), err)]
    pub(crate) async fn create(
        &self,
        conn: &mut PgConnection,
        id_hash: &str,
        user_id: Uuid,
        expires_at: OffsetDateTime,
    ) -> Result<()> {
        sqlx::query("INSERT INTO link_sessions (id_hash, user_id, expires_at) VALUES ($1, $2, $3)")
            .bind(id_hash)
            .bind(user_id)
            .bind(expires_at)
            .execute(conn)
            .await?;
        Ok(())
    }

    /// Deletes every expired link session.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn delete_expired(&self, conn: &mut PgConnection) -> Result<()> {
        sqlx::query("DELETE FROM link_sessions WHERE expires_at <= NOW()").execute(conn).await?;
        Ok(())
    }

    /// Stores the body of an unexpired, unapproved session of the user, which approves it.
    /// Returns true if the body was stored.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the update fails.
    #[tracing::instrument(level = "debug", skip(self, conn, id_hash, body), err)]
    pub(crate) async fn approve(
        &self,
        conn: &mut PgConnection,
        id_hash: &str,
        user_id: Uuid,
        body: &[u8],
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE link_sessions SET body = $3
            WHERE id_hash = $1 AND user_id = $2 AND expires_at > NOW() AND body IS NULL
            "#,
        )
        .bind(id_hash)
        .bind(user_id)
        .bind(body)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Returns the body of an unexpired session of the user: `None` if there is no such session, `Some(None)`
    /// if it is not approved yet.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn, id_hash), err)]
    pub(crate) async fn find_body(
        &self,
        conn: &mut PgConnection,
        id_hash: &str,
        user_id: Uuid,
    ) -> Result<Option<Option<Vec<u8>>>> {
        let body = sqlx::query_scalar(
            "SELECT body FROM link_sessions WHERE id_hash = $1 AND user_id = $2 AND expires_at > NOW()",
        )
        .bind(id_hash)
        .bind(user_id)
        .fetch_optional(conn)
        .await?;
        Ok(body)
    }

    /// Deletes an unexpired, approved session of the user. Returns true if there was one.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn, id_hash), err)]
    pub(crate) async fn consume_approved(&self, conn: &mut PgConnection, id_hash: &str, user_id: Uuid) -> Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM link_sessions
            WHERE id_hash = $1 AND user_id = $2 AND expires_at > NOW() AND body IS NOT NULL
            "#,
        )
        .bind(id_hash)
        .bind(user_id)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Deletes every link session of the user.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn delete_all_for_user(&self, conn: &mut PgConnection, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM link_sessions WHERE user_id = $1").bind(user_id).execute(conn).await?;
        Ok(())
    }
}
