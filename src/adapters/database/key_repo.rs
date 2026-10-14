use crate::adapters::database::records::{ConsumedPreKeyRecord, IdentityKeyRecord, SignedPreKeyRecord};
use crate::domain::crypto::{PublicKey, Signature};
use crate::domain::keys::{OneTimePreKey, PreKeyBundle, SignedPreKey};
use crate::error::{AppError, Result};
use sqlx::PgConnection;
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
pub struct KeyRepository {}

impl KeyRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Upserts an identity key for a device.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database operation fails.
    #[tracing::instrument(level = "debug", skip(self, conn, identity_key), err)]
    pub(crate) async fn upsert_identity_key(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        identity_key: &PublicKey,
        registration_id: i32,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO identity_keys (device_id, identity_key, registration_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (device_id) DO UPDATE
            SET identity_key = $2, registration_id = $3
            "#,
        )
        .bind(device_id)
        .bind(identity_key.as_bytes())
        .bind(registration_id)
        .execute(conn)
        .await?;
        Ok(())
    }

    /// Upserts a signed pre-key for a device.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database operation fails.
    #[tracing::instrument(level = "debug", skip(self, conn, public_key, signature))]
    pub(crate) async fn upsert_signed_pre_key(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        key_id: i32,
        public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO signed_pre_keys (id, device_id, public_key, signature)
            VALUES ($2, $1, $3, $4)
            ON CONFLICT (id, device_id) DO UPDATE
            SET public_key = $3, signature = $4
            "#,
        )
        .bind(device_id)
        .bind(key_id)
        .bind(public_key.as_bytes())
        .bind(signature.as_bytes())
        .execute(conn)
        .await?;
        Ok(())
    }

    /// Inserts a batch of one-time pre-keys.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database operation fails.
    #[tracing::instrument(level = "debug", skip(self, conn, keys))]
    pub(crate) async fn insert_one_time_pre_keys(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        keys: &[OneTimePreKey],
    ) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }

        let mut ids = Vec::with_capacity(keys.len());
        let mut device_ids = Vec::with_capacity(keys.len());
        let mut pub_keys = Vec::with_capacity(keys.len());

        for k in keys {
            ids.push(k.key_id);
            device_ids.push(device_id);
            pub_keys.push(k.public_key.as_bytes());
        }

        sqlx::query(
            r#"
            INSERT INTO one_time_pre_keys (id, device_id, public_key)
            SELECT * FROM UNNEST($1::int4[], $2::uuid[], $3::bytea[])
            ON CONFLICT (id, device_id) DO NOTHING
            "#,
        )
        .bind(&ids)
        .bind(&device_ids)
        .bind(&pub_keys)
        .execute(conn)
        .await?;

        Ok(())
    }

    /// Fetches a pre-key bundle for a single device and consumes one one-time pre-key.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database operation fails.
    /// Returns `AppError::Internal` if stored data is corrupt.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn fetch_pre_key_bundle(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
    ) -> Result<Option<PreKeyBundle>> {
        // Fetch identity
        let identity_rec = sqlx::query_as::<_, IdentityKeyRecord>(
            "SELECT identity_key, registration_id FROM identity_keys WHERE device_id = $1",
        )
        .bind(device_id)
        .fetch_optional(&mut *conn)
        .await?;

        let Some(identity_rec) = identity_rec else {
            return Ok(None);
        };

        let registration_id = identity_rec.registration_id;
        let identity_key = PublicKey::try_from(identity_rec).map_err(|e| {
            tracing::error!(error = %e, "Database data corruption: Invalid identity key format");
            AppError::Internal
        })?;

        // Fetch latest signed pre key
        let signed_rec = sqlx::query_as::<_, SignedPreKeyRecord>(
            r#"
            SELECT id, public_key, signature
            FROM signed_pre_keys WHERE device_id = $1
            ORDER BY created_at DESC LIMIT 1
            "#,
        )
        .bind(device_id)
        .fetch_optional(&mut *conn)
        .await?;

        let Some(signed_rec) = signed_rec else {
            return Ok(None);
        };

        let signed_pre_key = SignedPreKey::try_from(signed_rec).map_err(|e| {
            tracing::error!(error = %e, "Database data corruption: Invalid signed pre-key format");
            AppError::Internal
        })?;

        // Fetch one one-time pre key and delete it
        let otpk_rec = sqlx::query_as::<_, ConsumedPreKeyRecord>(
            r#"
            WITH target AS (
                SELECT id FROM one_time_pre_keys
                WHERE device_id = $1
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            DELETE FROM one_time_pre_keys
            WHERE id IN (SELECT id FROM target) AND device_id = $1
            RETURNING id, public_key
            "#,
        )
        .bind(device_id)
        .fetch_optional(&mut *conn)
        .await?;

        let one_time_pre_key = otpk_rec.map(OneTimePreKey::try_from).transpose().map_err(|e| {
            tracing::error!(error = %e, "Database data corruption: Invalid one-time pre-key format");
            AppError::Internal
        })?;

        Ok(Some(PreKeyBundle { device_id, registration_id, identity_key, signed_pre_key, one_time_pre_key }))
    }

    /// Fetches exactly one pre-key bundle for every device owned by a specific user.
    /// Mutates the database to consume one one-time pre-key per device.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database operation fails.
    /// Returns `AppError::Internal` if stored data is corrupt.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn get_all_bundles_for_user(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<Vec<PreKeyBundle>> {
        let device_ids: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM devices WHERE user_id = $1").bind(user_id).fetch_all(&mut *conn).await?;

        tracing::info!(user.id = %user_id, count = %device_ids.len(), "Found devices for user");

        let mut bundles = Vec::new();

        for id in device_ids {
            if let Some(bundle_result) = self.fetch_pre_key_bundle(&mut *conn, id).await? {
                bundles.push(bundle_result);
            } else {
                tracing::info!(device.id = %id, "fetch_pre_key_bundle returned None");
            }
        }

        Ok(bundles)
    }

    /// Fetches the identity key for a device.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    /// Returns `AppError::Internal` if stored data is corrupt.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn fetch_identity_key(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
    ) -> Result<Option<PublicKey>> {
        let rec = sqlx::query_as::<_, IdentityKeyRecord>(
            "SELECT identity_key, registration_id FROM identity_keys WHERE device_id = $1",
        )
        .bind(device_id)
        .fetch_optional(conn)
        .await?;

        match rec {
            Some(r) => {
                let pk = PublicKey::try_from(r).map_err(|e| {
                    tracing::error!(error = %e, "Database data corruption: Invalid identity key format");
                    AppError::Internal
                })?;
                Ok(Some(pk))
            }
            None => Ok(None),
        }
    }

    /// Fetches the identity key for update (with LOCK).
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    /// Returns `AppError::Internal` if stored data is corrupt.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn fetch_identity_key_for_update(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
    ) -> Result<Option<PublicKey>> {
        let rec = sqlx::query_as::<_, IdentityKeyRecord>(
            "SELECT identity_key, registration_id FROM identity_keys WHERE device_id = $1 FOR UPDATE",
        )
        .bind(device_id)
        .fetch_optional(conn)
        .await?;

        match rec {
            Some(r) => {
                let pk = PublicKey::try_from(r).map_err(|e| {
                    tracing::error!(error = %e, "Database data corruption: Invalid identity key format");
                    AppError::Internal
                })?;
                Ok(Some(pk))
            }
            None => Ok(None),
        }
    }

    /// Deletes all signed pre-keys for a device.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn delete_all_signed_pre_keys(&self, conn: &mut PgConnection, device_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM signed_pre_keys WHERE device_id = $1").bind(device_id).execute(conn).await?;
        Ok(())
    }

    /// Deletes all one-time pre-keys for a device.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn delete_all_one_time_pre_keys(&self, conn: &mut PgConnection, device_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM one_time_pre_keys WHERE device_id = $1").bind(device_id).execute(conn).await?;
        Ok(())
    }

    /// Counts the remaining one-time pre-keys for a device.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn count_one_time_pre_keys(&self, conn: &mut PgConnection, device_id: Uuid) -> Result<i64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM one_time_pre_keys WHERE device_id = $1")
            .bind(device_id)
            .fetch_one(conn)
            .await?;
        Ok(count)
    }

    /// Finds the maximum signed pre-key ID currently stored for a device.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn find_max_signed_pre_key_id(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
    ) -> Result<Option<i32>> {
        let max_id: Option<i32> = sqlx::query_scalar("SELECT MAX(id) FROM signed_pre_keys WHERE device_id = $1")
            .bind(device_id)
            .fetch_one(conn)
            .await?;
        Ok(max_id)
    }

    /// Deletes signed pre-keys with an ID smaller than the threshold.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn delete_signed_pre_keys_older_than(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        threshold_id: i32,
    ) -> Result<()> {
        sqlx::query("DELETE FROM signed_pre_keys WHERE device_id = $1 AND id < $2")
            .bind(device_id)
            .bind(threshold_id)
            .execute(conn)
            .await?;
        Ok(())
    }

    /// Deletes the oldest one-time pre-keys for a device up to the specified limit.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the deletion fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn delete_oldest_one_time_pre_keys(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        limit: i64,
    ) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM one_time_pre_keys
            WHERE device_id = $1 AND id IN (
                SELECT id FROM one_time_pre_keys
                WHERE device_id = $1
                ORDER BY created_at ASC
                LIMIT $2
            )
            "#,
        )
        .bind(device_id)
        .bind(limit)
        .execute(conn)
        .await?;
        Ok(())
    }
}
