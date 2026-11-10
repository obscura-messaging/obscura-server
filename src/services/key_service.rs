use crate::adapters::database::DbPool;
use crate::adapters::database::key_repo::KeyRepository;
use crate::config::MessagingConfig;
use crate::domain::keys::{DevicePreKeys, PreKeyBundle, PreKeyCounts, PreKeyUpload};
use crate::error::{AppError, Result};
use sqlx::PgConnection;
use std::num::NonZeroU32;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct KeyService {
    pool: DbPool,
    repo: KeyRepository,
    max_pre_keys: NonZeroU32,
}

impl KeyService {
    #[must_use]
    pub const fn new(pool: DbPool, repo: KeyRepository, config: &MessagingConfig) -> Self {
        Self { pool, repo, max_pre_keys: config.max_pre_keys }
    }

    /// The most one-time pre-keys of each kind (EC and Kyber) one upload may carry, and so a device may hold.
    #[must_use]
    pub(crate) const fn max_pre_keys(&self) -> NonZeroU32 {
        self.max_pre_keys
    }

    /// Fetches one pre-key bundle for each of a user's devices, or for `device_id` only, consuming a
    /// one-time EC and Kyber pre-key on each where available.
    ///
    /// # Errors
    /// Returns `AppError::Database` if database query fails.
    #[tracing::instrument(skip(self), fields(user.id = %user_id), err)]
    pub(crate) async fn get_pre_key_bundles(
        &self,
        user_id: Uuid,
        device_id: Option<Uuid>,
    ) -> Result<Vec<PreKeyBundle>> {
        let mut conn = self.pool.begin().await?;
        let bundles = self.repo.get_bundles(&mut conn, user_id, device_id).await?;
        conn.commit().await?;
        Ok(bundles)
    }

    /// How many one-time EC and Kyber pre-keys a device has left. Clients check this to decide when to refill,
    /// as Signal clients do with `GET /v2/keys`.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the database operation fails.
    #[tracing::instrument(err, skip(self), fields(device.id = %device_id))]
    pub(crate) async fn pre_key_counts(&self, device_id: Uuid) -> Result<PreKeyCounts> {
        let mut conn = self.pool.acquire().await?;
        let one_time = self.repo.count_one_time_pre_keys(&mut conn, device_id).await?;
        let kyber = self.repo.count_kyber_pre_keys(&mut conn, device_id).await?;
        Ok(PreKeyCounts { one_time, kyber })
    }

    /// Applies a device's pre-key upload, as Signal's server does: each part present replaces what is stored
    /// (a non-empty one-time list replaces the stored keys of that kind) and absent parts are left as they are.
    ///
    /// # Errors
    /// Returns `AppError::BadRequest` if any signature does not verify against the account identity or a list is
    /// too large.
    /// Returns `AppError::Database` if the database operation fails.
    #[tracing::instrument(skip(self, upload), fields(device.id = %device_id), err(level = "warn"))]
    pub(crate) async fn upload_keys(&self, device_id: Uuid, upload: PreKeyUpload) -> Result<()> {
        upload.check_batches(self.max_pre_keys)?;

        let mut tx = self.pool.begin().await?;

        let identity_key =
            self.repo.lock_device_identity_key(&mut tx, device_id).await?.ok_or(AppError::Unauthorized)?;
        upload.verify(&identity_key).map_err(AppError::BadRequest)?;

        self.store_pre_keys(&mut tx, device_id, &upload).await?;

        tx.commit().await?;
        Ok(())
    }

    /// Stores the initial pre-keys of a newly provisioned device in the enclosing transaction.
    /// Their signatures were already verified against the identity key at parse time.
    ///
    /// # Errors
    /// Returns `AppError::BadRequest` if a list is too large.
    /// Returns `AppError::Database` if the database operation fails.
    pub(crate) async fn store_new_device_keys(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        pre_keys: DevicePreKeys,
    ) -> Result<()> {
        pre_keys.check_batches(self.max_pre_keys)?;
        self.store_pre_keys(conn, device_id, &pre_keys.into()).await
    }

    async fn store_pre_keys(&self, conn: &mut PgConnection, device_id: Uuid, upload: &PreKeyUpload) -> Result<()> {
        if let Some(signed) = &upload.signed_pre_key {
            self.repo
                .upsert_signed_pre_key(&mut *conn, device_id, signed.key_id, &signed.public_key, &signed.signature)
                .await?;
        }
        if let Some(last_resort) = &upload.last_resort_kyber_pre_key {
            self.repo.upsert_last_resort_kyber_pre_key(&mut *conn, device_id, last_resort).await?;
        }
        if !upload.one_time_pre_keys.is_empty() {
            self.repo.replace_one_time_pre_keys(&mut *conn, device_id, &upload.one_time_pre_keys).await?;
        }
        if !upload.kyber_pre_keys.is_empty() {
            self.repo.replace_kyber_pre_keys(&mut *conn, device_id, &upload.kyber_pre_keys).await?;
        }
        Ok(())
    }
}
