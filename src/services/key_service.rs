use crate::adapters::database::DbPool;
use crate::adapters::database::key_repo::KeyRepository;
use crate::config::MessagingConfig;
use crate::domain::crypto::PublicKey;
use crate::domain::keys::{OneTimePreKey, PreKeyBundle, PreKeyStatus, SignedPreKey};
use crate::domain::notification::UserEvent;
use crate::error::{AppError, Result};
use crate::services::crypto_service::CryptoService;
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
    crypto_service: CryptoService,
    notifier: NotificationService,
    config: MessagingConfig,
    metrics: Metrics,
}

#[derive(Debug)]
pub struct KeyUploadParams {
    pub device_id: Uuid,
    pub signed_pre_key: SignedPreKey,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
}

impl KeyService {
    #[must_use]
    pub fn new(
        pool: DbPool,
        repo: KeyRepository,
        crypto_service: CryptoService,
        notifier: NotificationService,
        config: MessagingConfig,
    ) -> Self {
        Self { pool, repo, crypto_service, notifier, config, metrics: Metrics::new() }
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
                    remaining = %status.one_time_pre_key_count,
                    "Pre-keys falling below minimum threshold"
                );
                self.notifier.notify(&[bundle.device_id], UserEvent::PreKeyLow).await;
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
        if count < i64::from(self.config.pre_key_refill_threshold) {
            self.metrics.prekey_low_total.add(1, &[]);

            Ok(Some(PreKeyStatus {
                one_time_pre_key_count: i32::try_from(count).unwrap_or(i32::MAX),
                min_threshold: self.config.pre_key_refill_threshold,
            }))
        } else {
            Ok(None)
        }
    }

    /// Uploads a new signed pre-key and one-time pre-keys for an existing device.
    ///
    /// # Errors
    /// Returns `AppError::BadRequest` if the signature does not verify against the account identity, the signed
    /// pre-key id does not increase, or the batch is too large.
    /// Returns `AppError::Database` if the database operation fails.
    #[tracing::instrument(skip(self, params), fields(device.id = %params.device_id), err(level = "warn"))]
    pub(crate) async fn upload_keys(&self, params: KeyUploadParams) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        let identity_key =
            self.repo.lock_device_identity_key(&mut tx, params.device_id).await?.ok_or(AppError::NotFound)?;
        self.verify_keys(&identity_key, &params.signed_pre_key)?;
        self.check_batch_size(&params.one_time_pre_keys)?;

        let max_id = self.repo.find_max_signed_pre_key_id(&mut tx, params.device_id).await?;
        if let Some(current_max) = max_id
            && params.signed_pre_key.key_id <= current_max
        {
            return Err(AppError::BadRequest(format!(
                "Signed Pre-Key ID {} must be greater than current ID {}",
                params.signed_pre_key.key_id, current_max
            )));
        }

        let current_count = self.repo.count_one_time_pre_keys(&mut tx, params.device_id).await?;
        let new_keys_count = i64::try_from(params.one_time_pre_keys.len()).unwrap_or(i64::MAX);
        if current_count + new_keys_count > self.config.max_pre_keys {
            let to_delete = (current_count + new_keys_count) - self.config.max_pre_keys;
            self.repo.delete_oldest_one_time_pre_keys(&mut tx, params.device_id, to_delete).await?;
        }

        self.store_pre_keys(&mut tx, params.device_id, &params.signed_pre_key, &params.one_time_pre_keys).await?;
        self.repo.delete_signed_pre_keys_older_than(&mut tx, params.device_id, params.signed_pre_key.key_id).await?;

        tx.commit().await?;
        Ok(())
    }

    /// Stores the first keys of a device created in the same transaction, verified against the account
    /// identity key.
    ///
    /// # Errors
    /// Returns `AppError::BadRequest` if the signature does not verify or the batch is too large.
    /// Returns `AppError::Database` if the database operation fails.
    pub(crate) async fn store_new_device_keys(
        &self,
        conn: &mut PgConnection,
        device_id: Uuid,
        identity_key: &PublicKey,
        signed_pre_key: &SignedPreKey,
        one_time_pre_keys: &[OneTimePreKey],
    ) -> Result<()> {
        self.verify_keys(identity_key, signed_pre_key)?;
        self.check_batch_size(one_time_pre_keys)?;
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

    fn check_batch_size(&self, one_time_pre_keys: &[OneTimePreKey]) -> Result<()> {
        if i64::try_from(one_time_pre_keys.len()).unwrap_or(i64::MAX) > self.config.max_pre_keys {
            return Err(AppError::BadRequest(format!("Batch too large. Limit is {}", self.config.max_pre_keys)));
        }
        Ok(())
    }

    fn verify_keys(&self, ik: &PublicKey, signed_pre_key: &SignedPreKey) -> Result<()> {
        // libsignal-protocol-typescript's generateSignedPreKey signs the 33-byte publicKey ArrayBuffer.
        // However, some versions or test polyfills might sign the 32-byte raw key.
        // We try both to be absolutely robust.
        let raw_32 = signed_pre_key.public_key.as_crypto_bytes();
        let wire_33 = signed_pre_key.public_key.as_bytes();

        if self.crypto_service.verify_signature(ik, wire_33, &signed_pre_key.signature).is_ok() {
            return Ok(());
        }

        self.crypto_service.verify_signature(ik, raw_32, &signed_pre_key.signature)
    }
}
