use crate::adapters::database::records::{ConsumedPreKeyRecord, KyberPreKeyRecord, SignedPreKeyRecord};
use crate::domain::crypto::{PublicKey, Signature};
use crate::domain::keys::{KyberPreKey, OneTimePreKey, PreKeyBundle, SignedPreKey};
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

    /// Returns the account identity key of a device's owner without locking anything.
    /// Returns `None` if the device does not exist.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    /// Returns `AppError::Internal` if stored data is corrupt.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn find_device_identity_key(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
    ) -> Result<Option<PublicKey>> {
        let row: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT u.identity_key FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id = $1")
                .bind(device_id)
                .fetch_optional(conn)
                .await?;

        row.as_deref().map(decode_identity_key).transpose()
    }

    /// Locks the device row and returns the account identity key of its owner.
    /// Returns `None` if the device does not exist.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    /// Returns `AppError::Internal` if stored data is corrupt.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn lock_device_identity_key(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
    ) -> Result<Option<PublicKey>> {
        let row: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT u.identity_key FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id = $1 FOR UPDATE OF d",
        )
        .bind(device_id)
        .fetch_optional(conn)
        .await?;

        row.as_deref().map(decode_identity_key).transpose()
    }

    /// Replaces a device's signed pre-key.
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
            INSERT INTO signed_pre_keys (device_id, id, public_key, signature)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (device_id) DO UPDATE
            SET id = $2, public_key = $3, signature = $4
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

    /// Replaces all of a device's one-time EC pre-keys with `keys`.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database operation fails.
    #[tracing::instrument(level = "debug", skip(self, conn, keys))]
    pub(crate) async fn replace_one_time_pre_keys(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        keys: &[OneTimePreKey],
    ) -> Result<()> {
        sqlx::query("DELETE FROM one_time_pre_keys WHERE device_id = $1").bind(device_id).execute(&mut *conn).await?;

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
            "#,
        )
        .bind(&ids)
        .bind(&device_ids)
        .bind(&pub_keys)
        .execute(conn)
        .await?;

        Ok(())
    }

    /// Replaces a device's last-resort Kyber pre-key.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database operation fails.
    #[tracing::instrument(level = "debug", skip(self, conn, key))]
    pub(crate) async fn upsert_last_resort_kyber_pre_key(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        key: &KyberPreKey,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO kyber_last_resort_pre_keys (device_id, id, public_key, signature)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (device_id) DO UPDATE
            SET id = $2, public_key = $3, signature = $4
            "#,
        )
        .bind(device_id)
        .bind(key.key_id)
        .bind(key.public_key.as_bytes())
        .bind(key.signature.as_bytes())
        .execute(conn)
        .await?;
        Ok(())
    }

    /// Replaces all of a device's one-time Kyber pre-keys with `keys`.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database operation fails.
    #[tracing::instrument(level = "debug", skip(self, conn, keys))]
    pub(crate) async fn replace_kyber_pre_keys(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        keys: &[KyberPreKey],
    ) -> Result<()> {
        sqlx::query("DELETE FROM kyber_pre_keys WHERE device_id = $1").bind(device_id).execute(&mut *conn).await?;

        let mut ids = Vec::with_capacity(keys.len());
        let mut device_ids = Vec::with_capacity(keys.len());
        let mut pub_keys = Vec::with_capacity(keys.len());
        let mut signatures = Vec::with_capacity(keys.len());

        for k in keys {
            ids.push(k.key_id);
            device_ids.push(device_id);
            pub_keys.push(k.public_key.as_bytes());
            signatures.push(k.signature.as_bytes().as_slice());
        }

        sqlx::query(
            r#"
            INSERT INTO kyber_pre_keys (id, device_id, public_key, signature)
            SELECT * FROM UNNEST($1::int4[], $2::uuid[], $3::bytea[], $4::bytea[])
            "#,
        )
        .bind(&ids)
        .bind(&device_ids)
        .bind(&pub_keys)
        .bind(&signatures)
        .execute(conn)
        .await?;

        Ok(())
    }

    /// Consumes one of a device's one-time Kyber pre-keys, or returns its last-resort Kyber pre-key when none
    /// is left (or all are locked by concurrent fetches). Returns `None` only if the device has neither.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database operation fails.
    /// Returns `AppError::Internal` if stored data is corrupt.
    async fn take_kyber_pre_key(&self, conn: &mut PgConnection, device_id: Uuid) -> Result<Option<KyberPreKey>> {
        let one_time = sqlx::query_as::<_, KyberPreKeyRecord>(
            r#"
            WITH target AS (
                SELECT id FROM kyber_pre_keys
                WHERE device_id = $1
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            DELETE FROM kyber_pre_keys
            WHERE id IN (SELECT id FROM target) AND device_id = $1
            RETURNING id, public_key, signature
            "#,
        )
        .bind(device_id)
        .fetch_optional(&mut *conn)
        .await?;

        let record = match one_time {
            Some(record) => Some(record),
            None => {
                sqlx::query_as::<_, KyberPreKeyRecord>(
                    "SELECT id, public_key, signature FROM kyber_last_resort_pre_keys WHERE device_id = $1",
                )
                .bind(device_id)
                .fetch_optional(&mut *conn)
                .await?
            }
        };

        record.map(KyberPreKey::try_from).transpose().map_err(|e| {
            tracing::error!(error = %e, "Database data corruption: Invalid Kyber pre-key format");
            AppError::Internal
        })
    }

    /// Fetches a pre-key bundle for a single device, consuming one one-time EC pre-key and one one-time Kyber
    /// pre-key where available. Returns `None` if the device has no signed pre-key or no Kyber pre-key.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database operation fails.
    /// Returns `AppError::Internal` if stored data is corrupt.
    #[tracing::instrument(level = "debug", skip(self, conn, identity_key), err)]
    async fn fetch_pre_key_bundle(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        registration_id: i32,
        identity_key: PublicKey,
    ) -> Result<Option<PreKeyBundle>> {
        let signed_rec = sqlx::query_as::<_, SignedPreKeyRecord>(
            r#"
            SELECT id, public_key, signature
            FROM signed_pre_keys WHERE device_id = $1
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

        // Every provisioning path stores a last-resort Kyber pre-key, so this is `None` only for a device that
        // never finished provisioning. Checked before consuming the EC pre-key so a miss consumes nothing.
        let Some(kyber_pre_key) = self.take_kyber_pre_key(&mut *conn, device_id).await? else {
            return Ok(None);
        };

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

        Ok(Some(PreKeyBundle {
            device_id,
            registration_id,
            identity_key,
            signed_pre_key,
            kyber_pre_key,
            one_time_pre_key,
        }))
    }

    /// Fetches one pre-key bundle for each of a user's devices, or for `device_id` only, each carrying the
    /// account identity key. Consumes one one-time pre-key per returned device.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database operation fails.
    /// Returns `AppError::Internal` if stored data is corrupt.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn get_bundles(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        device_id: Option<Uuid>,
    ) -> Result<Vec<PreKeyBundle>> {
        let identity: Option<Vec<u8>> = sqlx::query_scalar("SELECT identity_key FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&mut *conn)
            .await?;

        let Some(identity) = identity else {
            return Ok(Vec::new());
        };
        let identity_key = decode_identity_key(&identity)?;

        let devices: Vec<(Uuid, i32)> = sqlx::query_as(
            "SELECT id, registration_id FROM devices WHERE user_id = $1 AND ($2::uuid IS NULL OR id = $2) ORDER BY created_at ASC",
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_all(&mut *conn)
        .await?;

        let mut bundles = Vec::with_capacity(devices.len());
        for (device_id, registration_id) in devices {
            if let Some(bundle) =
                self.fetch_pre_key_bundle(&mut *conn, device_id, registration_id, identity_key.clone()).await?
            {
                bundles.push(bundle);
            }
        }

        Ok(bundles)
    }

    /// Counts the remaining one-time pre-keys for a device, saturating at `u32::MAX`.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn count_one_time_pre_keys(&self, conn: &mut PgConnection, device_id: Uuid) -> Result<u32> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM one_time_pre_keys WHERE device_id = $1")
            .bind(device_id)
            .fetch_one(conn)
            .await?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    /// Counts the remaining one-time Kyber pre-keys for a device, saturating at `u32::MAX`.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    #[tracing::instrument(level = "debug", skip(self, conn), err)]
    pub(crate) async fn count_kyber_pre_keys(&self, conn: &mut PgConnection, device_id: Uuid) -> Result<u32> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kyber_pre_keys WHERE device_id = $1")
            .bind(device_id)
            .fetch_one(conn)
            .await?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }
}

fn decode_identity_key(bytes: &[u8]) -> Result<PublicKey> {
    PublicKey::try_from_bytes(bytes).map_err(|e| {
        tracing::error!(error = %e, "Database data corruption: Invalid identity key format");
        AppError::Internal
    })
}
