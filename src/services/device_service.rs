use crate::adapters::database::DbPool;
use crate::adapters::database::device_repo::DeviceRepository;
use crate::adapters::database::link_session_repo::LinkSessionRepository;
use crate::adapters::database::user_repo::UserRepository;
use crate::domain::auth_session::AuthSession;
use crate::domain::crypto::PublicKey;
use crate::domain::device::Device;
use crate::domain::keys::{OneTimePreKey, SignedPreKey};
use crate::domain::notification::UserEvent;
use crate::error::{AppError, Result};
use crate::services::auth_service::AuthService;
use crate::services::key_service::{IDENTITY_KEY_MISMATCH, KeyService};
use crate::services::notification_service::NotificationService;
use opentelemetry::{global, metrics::Counter};
use uuid::Uuid;

pub(crate) const INVALID_LINK_SESSION: &str = "Invalid link session";
pub(crate) const DEVICE_SCOPE_REQUIRED: &str = "Device-scoped token required";

#[derive(Clone, Debug)]
struct Metrics {
    devices_created: Counter<u64>,
    devices_deleted: Counter<u64>,
    account_resets: Counter<u64>,
}

impl Metrics {
    fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            devices_created: meter
                .u64_counter("obscura_devices_created_total")
                .with_description("Total number of devices provisioned")
                .build(),
            devices_deleted: meter
                .u64_counter("obscura_devices_deleted_total")
                .with_description("Total number of devices deleted")
                .build(),
            account_resets: meter
                .u64_counter("obscura_account_resets_total")
                .with_description("Total number of account resets")
                .build(),
        }
    }
}

#[derive(Debug)]
pub struct NewDevice {
    pub name: Option<String>,
    pub identity_key: PublicKey,
    pub registration_id: i32,
    pub signed_pre_key: SignedPreKey,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
    pub link_session_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DeviceService {
    pool: DbPool,
    device_repo: DeviceRepository,
    user_repo: UserRepository,
    link_session_repo: LinkSessionRepository,
    key_service: KeyService,
    auth_service: AuthService,
    notifier: NotificationService,
    metrics: Metrics,
    max_devices_per_user: i64,
}

impl DeviceService {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: DbPool,
        device_repo: DeviceRepository,
        user_repo: UserRepository,
        link_session_repo: LinkSessionRepository,
        key_service: KeyService,
        auth_service: AuthService,
        notifier: NotificationService,
        max_devices_per_user: i64,
    ) -> Self {
        Self {
            pool,
            device_repo,
            user_repo,
            link_session_repo,
            key_service,
            auth_service,
            notifier,
            metrics: Metrics::new(),
            max_devices_per_user,
        }
    }

    /// Creates a device with its keys and returns a device-scoped session.
    /// The first device of an account becomes the primary and sets the account identity; any later device
    /// must present the account identity and an approved link session, which is consumed.
    ///
    /// # Errors
    /// Returns `AppError::Forbidden` if the device limit is reached, the link session is invalid, or the
    /// identity key is not the account identity.
    /// Returns `AppError::BadRequest` if the keys do not verify.
    /// Returns `AppError::Database` if any database operation fails.
    #[tracing::instrument(
        skip(self, device),
        fields(user.id = %user_id, device.id = tracing::field::Empty),
        err(level = "warn")
    )]
    pub(crate) async fn create_device(&self, user_id: Uuid, device: NewDevice) -> Result<AuthSession> {
        let mut tx = self.pool.begin().await?;

        let account_identity = self.user_repo.lock_identity_key(&mut tx, user_id).await?;
        let device_count = self.device_repo.count_by_user(&mut tx, user_id).await?;
        if device_count >= self.max_devices_per_user {
            return Err(AppError::Forbidden(format!(
                "Device limit reached. Maximum allowed is {}.",
                self.max_devices_per_user
            )));
        }

        let is_primary = device_count == 0;
        if is_primary {
            self.user_repo.set_identity_key(&mut tx, user_id, Some(&device.identity_key)).await?;
        } else {
            if account_identity.as_ref() != Some(&device.identity_key) {
                return Err(AppError::Forbidden(IDENTITY_KEY_MISMATCH.into()));
            }
            let consumed = match device.link_session_id.as_deref() {
                Some(id) => {
                    self.link_session_repo
                        .consume_approved(&mut tx, &AuthService::hash_opaque_token(id), user_id)
                        .await?
                }
                None => false,
            };
            if !consumed {
                return Err(AppError::Forbidden(INVALID_LINK_SESSION.into()));
            }
        }

        let created = self
            .device_repo
            .create(&mut tx, user_id, device.name.as_deref(), device.registration_id, is_primary)
            .await?;
        tracing::Span::current().record("device.id", tracing::field::display(created.id));

        self.key_service
            .store_new_device_keys(
                &mut tx,
                created.id,
                &device.identity_key,
                &device.signed_pre_key,
                &device.one_time_pre_keys,
            )
            .await?;

        let session = self.auth_service.create_session(&mut tx, user_id, Some(created.id)).await?;

        tx.commit().await?;

        tracing::info!(is_primary, "Device provisioned successfully");
        self.metrics.devices_created.add(1, &[]);

        Ok(session)
    }

    /// Lists all devices for a user.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the query fails.
    #[tracing::instrument(skip(self), fields(user.id = %user_id), err)]
    pub(crate) async fn list_devices(&self, user_id: Uuid) -> Result<Vec<Device>> {
        let mut conn = self.pool.acquire().await?;
        self.device_repo.find_by_user(&mut conn, user_id).await
    }

    /// Deletes a device of the caller's account and closes its gateway connection. The primary may delete
    /// any other device, and any other device may delete itself. The primary itself is only removed by an
    /// account reset.
    ///
    /// # Errors
    /// Returns `AppError::NotFound` if the device doesn't exist or isn't owned by the user.
    /// Returns `AppError::Forbidden` if the caller may not delete the device.
    #[tracing::instrument(skip(self), fields(user.id = %user_id, device.id = %device_id), err(level = "warn"))]
    pub(crate) async fn delete_device(
        &self,
        user_id: Uuid,
        caller_device_id: Option<Uuid>,
        device_id: Uuid,
    ) -> Result<()> {
        let caller_device_id = caller_device_id.ok_or_else(|| AppError::Forbidden(DEVICE_SCOPE_REQUIRED.into()))?;

        let mut conn = self.pool.acquire().await?;
        let target = self.device_repo.find_by_id(&mut conn, device_id, user_id).await?.ok_or(AppError::NotFound)?;
        if target.is_primary {
            return Err(AppError::Forbidden("The primary device cannot be deleted; reset the account instead".into()));
        }
        if caller_device_id != device_id {
            let caller = self.device_repo.find_by_id(&mut conn, caller_device_id, user_id).await?;
            if !caller.is_some_and(|c| c.is_primary) {
                return Err(AppError::Forbidden("Only the primary device can delete other devices".into()));
            }
        }

        if !self.device_repo.delete(&mut conn, device_id, user_id).await? {
            return Err(AppError::NotFound);
        }

        self.notifier.notify(&[device_id], UserEvent::Disconnect).await;

        tracing::info!("Device deleted");
        self.metrics.devices_deleted.add(1, &[]);

        Ok(())
    }

    /// Deletes every device and link session of the account and clears the account identity, so the next
    /// registered device becomes a new primary. Authorized by the account password.
    ///
    /// # Errors
    /// Returns `AppError::AuthError` if the credentials are invalid.
    /// Returns `AppError::Database` if any database operation fails.
    #[tracing::instrument(skip(self, username, password), fields(user.id = tracing::field::Empty), err(level = "warn"))]
    pub(crate) async fn reset_account(&self, username: &str, password: &str) -> Result<()> {
        let user_id = self.auth_service.verify_credentials(username, password).await?;

        let mut tx = self.pool.begin().await?;
        self.user_repo.lock_identity_key(&mut tx, user_id).await?;
        let deleted = self.device_repo.delete_all_for_user(&mut tx, user_id).await?;
        self.link_session_repo.delete_all_for_user(&mut tx, user_id).await?;
        self.user_repo.set_identity_key(&mut tx, user_id, None).await?;
        tx.commit().await?;

        self.notifier.notify(&deleted, UserEvent::Disconnect).await;

        tracing::info!(devices = deleted.len(), "Account reset");
        self.metrics.account_resets.add(1, &[]);
        self.metrics.devices_deleted.add(deleted.len() as u64, &[]);

        Ok(())
    }

    /// Checks if a device exists.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the query fails.
    pub(crate) async fn device_exists(&self, device_id: Uuid) -> Result<bool> {
        let mut conn = self.pool.acquire().await?;
        self.device_repo.exists(&mut conn, device_id).await
    }

    /// Fetches a single device by ID, verifying ownership.
    ///
    /// # Errors
    /// Returns `AppError::NotFound` if the device doesn't exist or isn't owned by the user.
    #[tracing::instrument(skip(self), fields(user.id = %user_id, device.id = %device_id), err)]
    pub(crate) async fn get_device(&self, device_id: Uuid, user_id: Uuid) -> Result<Device> {
        let mut conn = self.pool.acquire().await?;
        self.device_repo.find_by_id(&mut conn, device_id, user_id).await?.ok_or(AppError::NotFound)
    }

    /// Updates a device's name, verifying ownership.
    ///
    /// # Errors
    /// Returns `AppError::NotFound` if the device doesn't exist or isn't owned by the user.
    #[tracing::instrument(skip(self), fields(user.id = %user_id, device.id = %device_id), err)]
    pub(crate) async fn update_device(&self, device_id: Uuid, user_id: Uuid, name: Option<String>) -> Result<Device> {
        let mut conn = self.pool.acquire().await?;
        let device = self
            .device_repo
            .update_name(&mut conn, device_id, user_id, name.as_deref())
            .await?
            .ok_or(AppError::NotFound)?;

        tracing::info!("Device updated");
        Ok(device)
    }
}
