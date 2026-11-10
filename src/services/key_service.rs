use crate::adapters::database::DbPool;
use crate::adapters::database::key_repo::KeyRepository;
use crate::adapters::redis::RateLimitCounter;
use crate::domain::keys::{DevicePreKeys, PreKeyBundle, PreKeyCounts, PreKeyUpload};
#[cfg(doc)]
use crate::domain::keys::{PRE_KEY_FETCH_WINDOW_SECS, PRE_KEY_FETCHES_PER_WINDOW};
use crate::error::{AppError, Result};
use sqlx::PgConnection;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct KeyService {
    pool: DbPool,
    repo: KeyRepository,
    fetch_limiter: RateLimitCounter,
}

impl KeyService {
    /// `fetch_limiter` counts bundle fetches; build it with [`PRE_KEY_FETCHES_PER_WINDOW`] and
    /// [`PRE_KEY_FETCH_WINDOW_SECS`].
    #[must_use]
    pub const fn new(pool: DbPool, repo: KeyRepository, fetch_limiter: RateLimitCounter) -> Self {
        Self { pool, repo, fetch_limiter }
    }

    /// Fetches, for the device `caller`, one pre-key bundle for each of a user's devices, or for `device_id`
    /// only, consuming a one-time EC and Kyber pre-key on each where available.
    ///
    /// As on Signal's server, `caller` may fetch the same target (one device, or all of the user's devices) at
    /// most [`PRE_KEY_FETCHES_PER_WINDOW`] times per [`PRE_KEY_FETCH_WINDOW_SECS`], so no account can use up
    /// another device's one-time pre-keys. The limit is checked before anything is consumed. If Valkey is
    /// unreachable the fetch is allowed: running out of one-time keys only means new sessions use the
    /// last-resort keys, which is better than no new sessions at all.
    ///
    /// # Errors
    /// Returns `AppError::TooManyRequests` if `caller` is over the limit for this target.
    /// Returns `AppError::Database` if database query fails.
    #[tracing::instrument(skip(self), fields(device.id = %caller, user.id = %user_id), err(level = "warn"))]
    pub(crate) async fn get_pre_key_bundles(
        &self,
        caller: Uuid,
        user_id: Uuid,
        device_id: Option<Uuid>,
    ) -> Result<Vec<PreKeyBundle>> {
        let target = device_id.map_or_else(|| "*".to_string(), |id| id.to_string());
        match self.fetch_limiter.hit(&format!("{caller}:{user_id}:{target}")).await {
            Ok(None) => {}
            Ok(Some(retry_after_secs)) => return Err(AppError::TooManyRequests { retry_after_secs }),
            Err(e) => tracing::warn!(error = %e, "Pre-key fetch limit unavailable; allowing the fetch"),
        }

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
    /// Returns `AppError::BadRequest` if any signature does not verify against the account identity.
    /// Returns `AppError::Conflict` if the account identity changed while the upload was being verified.
    /// Returns `AppError::Database` if the database operation fails.
    #[tracing::instrument(skip(self, upload), fields(device.id = %device_id), err(level = "warn"))]
    pub(crate) async fn upload_keys(&self, device_id: Uuid, upload: PreKeyUpload) -> Result<()> {
        // A full upload is about a hundred signature checks, so they run on a blocking thread and before the
        // device row is locked, as Signal's server checks them before touching storage.
        let identity_key = {
            let mut conn = self.pool.acquire().await?;
            self.repo.find_device_identity_key(&mut conn, device_id).await?.ok_or(AppError::Unauthorized)?
        };
        let verify_key = identity_key.clone();
        let upload = tokio::task::spawn_blocking(move || upload.verify(&verify_key).map(|()| upload))
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Pre-key verification task failed");
                AppError::Internal
            })?
            .map_err(AppError::BadRequest)?;

        let mut tx = self.pool.begin().await?;
        let locked_identity_key =
            self.repo.lock_device_identity_key(&mut tx, device_id).await?.ok_or(AppError::Unauthorized)?;
        if locked_identity_key != identity_key {
            // The account was taken over between the check and the lock; the keys were signed by the old identity.
            return Err(AppError::Conflict("Identity key changed during upload".to_string()));
        }

        self.store_pre_keys(&mut tx, device_id, &upload).await?;

        tx.commit().await?;
        Ok(())
    }

    /// Stores the initial pre-keys of a newly provisioned device in the enclosing transaction.
    /// They were validated and verified against the identity key at parse time.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the database operation fails.
    pub(crate) async fn store_new_device_keys(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        pre_keys: DevicePreKeys,
    ) -> Result<()> {
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
