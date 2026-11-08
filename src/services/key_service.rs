use crate::adapters::database::DbPool;
use crate::adapters::database::key_repo::KeyRepository;
use crate::config::MessagingConfig;
use crate::domain::keys::{OneTimePreKey, PreKeyBundle, PreKeyLimit, PreKeyStatus, PreKeyUpload, SignedPreKey};
use crate::domain::notification::DeviceEvent;
use crate::error::{AppError, Result};
use crate::services::notification_service::NotificationService;
use opentelemetry::{global, metrics::Counter};
use sqlx::PgConnection;
use uuid::Uuid;

#[derive(Clone, Debug)]
struct Metrics {
    prekey_low_total: Counter<u64>,
}

impl Metrics {
    fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            prekey_low_total: meter
                .u64_counter("obscura_prekey_threshold_reached_total")
                .with_description("Events where devices dipped below prekey threshold")
                .build(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct KeyService {
    pool: DbPool,
    repo: KeyRepository,
    notifier: NotificationService,
    config: MessagingConfig,
    pre_key_limit: PreKeyLimit,
    metrics: Metrics,
}

impl KeyService {
    #[must_use]
    pub fn new(pool: DbPool, repo: KeyRepository, notifier: NotificationService, config: MessagingConfig) -> Self {
        let pre_key_limit = PreKeyLimit::new(config.max_pre_keys);
        Self { pool, repo, notifier, config, pre_key_limit, metrics: Metrics::new() }
    }

    /// The most one-time pre-keys a device may hold or upload at once.
    #[must_use]
    pub(crate) const fn pre_key_limit(&self) -> PreKeyLimit {
        self.pre_key_limit
    }

    /// Fetches one pre-key bundle for each of a user's devices, or for `device_id` only, consuming a
    /// one-time pre-key on each. Notifies any device that drops below the refill threshold.
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

        // Counted after commit: a count inside the consuming statement misses concurrent consumers,
        // so under a burst no fetch would see the device go low. The last fetch to commit sees all.
        for bundle in &bundles {
            if let Some(status) = self.check_pre_key_status(bundle.device_id).await? {
                tracing::warn!(
                    device.id = %bundle.device_id,
                    remaining = %status.count(),
                    "Pre-keys falling below minimum threshold"
                );
                self.notifier.notify(&[bundle.device_id], DeviceEvent::PreKeyLow).await;
            }
        }

        Ok(bundles)
    }

    /// Checks if a device needs to refill their one-time pre-keys.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the database operation fails.
    #[tracing::instrument(err, skip(self), fields(device.id = %device_id))]
    pub async fn check_pre_key_status(&self, device_id: Uuid) -> Result<Option<PreKeyStatus>> {
        let mut conn = self.pool.acquire().await?;
        let count = self.repo.count_one_time_pre_keys(&mut conn, device_id).await?;
        let status = PreKeyStatus::if_low(count, self.config.pre_key_refill_threshold);
        if status.is_some() {
            self.metrics.prekey_low_total.add(1, &[]);
        }
        Ok(status)
    }

    /// Uploads a new signed pre-key and one-time pre-keys for an existing device.
    ///
    /// # Errors
    /// Returns `AppError::BadRequest` if the signature does not verify against the account identity, the signed
    /// pre-key id does not increase, or the batch is too large.
    /// Returns `AppError::Database` if the database operation fails.
    #[tracing::instrument(skip(self, upload), fields(device.id = %device_id), err(level = "warn"))]
    pub(crate) async fn upload_keys(&self, device_id: Uuid, upload: PreKeyUpload) -> Result<()> {
        self.pre_key_limit.check_batch(upload.one_time_pre_keys.len())?;

        let mut tx = self.pool.begin().await?;

        let identity_key =
            self.repo.lock_device_identity_key(&mut tx, device_id).await?.ok_or(AppError::Unauthorized)?;
        upload.signed_pre_key.verify(&identity_key).map_err(AppError::BadRequest)?;

        let max_id = self.repo.find_max_signed_pre_key_id(&mut tx, device_id).await?;
        if let Some(current_max) = max_id
            && upload.signed_pre_key.key_id <= current_max
        {
            return Err(AppError::BadRequest(format!(
                "Signed Pre-Key ID {} must be greater than current ID {}",
                upload.signed_pre_key.key_id, current_max
            )));
        }

        let current_count = self.repo.count_one_time_pre_keys(&mut tx, device_id).await?;
        let excess = self.pre_key_limit.excess(current_count, upload.one_time_pre_keys.len());
        if excess > 0 {
            self.repo.delete_oldest_one_time_pre_keys(&mut tx, device_id, excess).await?;
        }

        self.store_pre_keys(&mut tx, device_id, &upload.signed_pre_key, &upload.one_time_pre_keys).await?;
        self.repo.delete_signed_pre_keys_older_than(&mut tx, device_id, upload.signed_pre_key.key_id).await?;

        tx.commit().await?;
        Ok(())
    }

    /// Stores the initial pre-keys of a newly provisioned device in the enclosing transaction.
    /// The signed pre-key signature was already verified against the identity key at parse time.
    ///
    /// # Errors
    /// Returns `AppError::BadRequest` if the batch is too large.
    /// Returns `AppError::Database` if the database operation fails.
    pub(crate) async fn store_new_device_keys(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        signed_pre_key: &SignedPreKey,
        one_time_pre_keys: &[OneTimePreKey],
    ) -> Result<()> {
        self.pre_key_limit.check_batch(one_time_pre_keys.len())?;
        self.store_pre_keys(conn, device_id, signed_pre_key, one_time_pre_keys).await
    }

    async fn store_pre_keys(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        signed_pre_key: &SignedPreKey,
        one_time_pre_keys: &[OneTimePreKey],
    ) -> Result<()> {
        self.repo
            .upsert_signed_pre_key(
                &mut *conn,
                device_id,
                signed_pre_key.key_id,
                &signed_pre_key.public_key,
                &signed_pre_key.signature,
            )
            .await?;
        self.repo.insert_one_time_pre_keys(&mut *conn, device_id, one_time_pre_keys).await
    }
}
