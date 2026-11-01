use crate::adapters::database::DbPool;
use crate::adapters::database::device_repo::DeviceRepository;
use crate::adapters::database::link_session_repo::LinkSessionRepository;
use crate::adapters::database::user_repo::UserRepository;
use crate::domain::auth::AuthSession;
use crate::domain::crypto::{PublicKey, generate_opaque_token, hash_opaque_token};
use crate::domain::device::Device;
use crate::domain::keys::{OneTimePreKey, SignedPreKey};
use crate::domain::notification::DeviceEvent;
use crate::error::{AppError, Result};
use crate::services::auth_service::AuthService;
use crate::services::key_service::KeyService;
use crate::services::notification_service::NotificationService;
use opentelemetry::{global, metrics::Counter};
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

const INVALID_LINK_SESSION: &str = "Invalid link session";
const IDENTITY_KEY_MISMATCH: &str = "Identity key does not match the account identity";
const LINK_SESSION_TTL: Duration = Duration::from_secs(600);
const MAX_LINK_SESSION_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
struct Metrics {
    registered_total: Counter<u64>,
    devices_created: Counter<u64>,
    devices_deleted: Counter<u64>,
    account_resets: Counter<u64>,
}

impl Metrics {
    fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            registered_total: meter
                .u64_counter("obscura_registrations_total")
                .with_description("Total number of successful user registrations")
                .build(),
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
pub struct NewDeviceKeys {
    pub name: Option<String>,
    pub identity_key: PublicKey,
    pub registration_id: i32,
    pub signed_pre_key: SignedPreKey,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
}

#[derive(Debug)]
pub struct NewLinkedDevice {
    pub link_session_id: String,
    pub keys: NewDeviceKeys,
}

#[derive(Debug)]
pub struct NewLinkSession {
    pub id: String,
    pub user_id: Uuid,
    pub expires_at: OffsetDateTime,
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

    /// Creates a new user account and provisions its primary device in one transaction.
    ///
    /// # Errors
    /// Returns `AppError::Conflict` if the username is already taken.
    /// Returns `AppError::BadRequest` if the keys do not verify.
    /// Returns `AppError::Database` if any database operation fails.
    #[tracing::instrument(
        skip(self, username, password, keys),
        fields(user.id = tracing::field::Empty, device.id = tracing::field::Empty),
        err(level = "warn")
    )]
    pub(crate) async fn register_account(
        &self,
        username: &crate::domain::user::Username,
        password: String,
        keys: NewDeviceKeys,
    ) -> Result<AuthSession> {
        self.key_service.check_batch_size(&keys.one_time_pre_keys)?;
        let password_hash = self.auth_service.hash_password(&password).await?;

        let mut tx = self.pool.begin().await?;
        let user = self.user_repo.create(&mut tx, username, &password_hash, &keys.identity_key).await?;
        tracing::Span::current().record("user.id", tracing::field::display(user.id));

        let session = self.provision_device(&mut tx, user.id, keys, true).await?;
        tx.commit().await?;

        tracing::info!("Account registered and primary device provisioned");
        self.metrics.registered_total.add(1, &[]);
        self.metrics.devices_created.add(1, &[]);

        Ok(session)
    }

    /// Verifies the account credentials and creates a link session bound to the user, replacing any
    /// previous unapproved session of the user and purging expired sessions.
    ///
    /// # Errors
    /// Returns `AppError::Unauthorized` if the credentials are invalid.
    /// Returns `AppError::Database` if any database operation fails.
    #[tracing::instrument(skip(self, username, password), fields(user.id = tracing::field::Empty), err(level = "warn"))]
    pub(crate) async fn create_link_session(&self, username: &str, password: &str) -> Result<NewLinkSession> {
        let user_id = self.auth_service.verify_credentials(username, password).await?;
        let id = generate_opaque_token();
        let expires_at = OffsetDateTime::now_utc() + LINK_SESSION_TTL;

        let mut tx = self.pool.begin().await?;
        self.link_session_repo.create(&mut tx, &hash_opaque_token(&id), user_id, expires_at).await?;
        tx.commit().await?;

        Ok(NewLinkSession { id, user_id, expires_at })
    }

    /// Approves a link session of the user by storing its body. Only the primary device may approve, and a
    /// session is approved at most once.
    ///
    /// # Errors
    /// Returns `AppError::Forbidden` if the caller is not the primary device.
    /// Returns `AppError::PayloadTooLarge` if the body exceeds the size cap.
    /// Returns `AppError::NotFound` if the session is unknown, expired, or another user's.
    /// Returns `AppError::Conflict` if the session is already approved.
    #[tracing::instrument(skip(self, id, body), fields(user.id = %user_id, body.len = body.len()), err(level = "warn"))]
    pub(crate) async fn approve_link_session(
        &self,
        user_id: Uuid,
        caller_is_primary: bool,
        id: &str,
        body: &[u8],
    ) -> Result<()> {
        if !caller_is_primary {
            return Err(AppError::Forbidden("Primary device required".into()));
        }
        if body.len() > MAX_LINK_SESSION_BODY_BYTES {
            return Err(AppError::PayloadTooLarge);
        }

        let mut conn = self.pool.acquire().await?;
        let id_hash = hash_opaque_token(id);
        if self.link_session_repo.approve(&mut conn, &id_hash, user_id, body).await? {
            return Ok(());
        }
        match self.link_session_repo.find_body_for_user(&mut conn, &id_hash, user_id).await? {
            Some(_) => Err(AppError::Conflict("Link session already approved".into())),
            None => Err(AppError::NotFound),
        }
    }

    /// Returns the body of an approved link session, or `None` if it is not approved yet.
    ///
    /// # Errors
    /// Returns `AppError::NotFound` if the session is unknown, expired, or consumed.
    #[tracing::instrument(skip(self, id), err(level = "warn"))]
    pub(crate) async fn get_link_session_body(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let id_hash = hash_opaque_token(id);
        let mut conn = self.pool.acquire().await?;
        self.link_session_repo.find_body(&mut conn, &id_hash).await?.ok_or(AppError::NotFound)
    }

    /// Deletes all expired link sessions.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the deletion fails.
    pub async fn cleanup_expired_link_sessions(&self) -> Result<u64> {
        let mut conn = self.pool.acquire().await?;
        self.link_session_repo.delete_expired(&mut conn).await
    }

    /// Provisions a linked device authorized by an approved link session and returns its session.
    ///
    /// # Errors
    /// Returns `AppError::Forbidden` if the link session is invalid, the device limit is reached, or the
    /// identity key is not the account identity.
    /// Returns `AppError::BadRequest` if the keys do not verify.
    /// Returns `AppError::Database` if any database operation fails.
    #[tracing::instrument(
        skip(self, device),
        fields(user.id = tracing::field::Empty, device.id = tracing::field::Empty),
        err(level = "warn")
    )]
    pub(crate) async fn create_linked_device(&self, device: NewLinkedDevice) -> Result<AuthSession> {
        self.key_service.check_batch_size(&device.keys.one_time_pre_keys)?;
        let id_hash = hash_opaque_token(&device.link_session_id);
        let mut tx = self.pool.begin().await?;

        let user_id = self
            .link_session_repo
            .find_approved_user_id(&mut tx, &id_hash)
            .await?
            .ok_or_else(|| AppError::Forbidden(INVALID_LINK_SESSION.into()))?;
        tracing::Span::current().record("user.id", tracing::field::display(user_id));

        // Lock the user row FOR UPDATE before touching link_sessions or devices (see MessageRepository::lock_device_sets).
        let account_identity = self.user_repo.lock_identity_key(&mut tx, user_id).await?;
        if !self.link_session_repo.consume_approved(&mut tx, &id_hash, user_id).await? {
            return Err(AppError::Forbidden(INVALID_LINK_SESSION.into()));
        }

        let device_count = self.device_repo.count_by_user(&mut tx, user_id).await?;
        if device_count >= self.max_devices_per_user {
            return Err(AppError::Forbidden(format!(
                "Device limit reached. Maximum allowed is {}.",
                self.max_devices_per_user
            )));
        }
        if account_identity != device.keys.identity_key {
            return Err(AppError::Forbidden(IDENTITY_KEY_MISMATCH.into()));
        }

        let session = self.provision_device(&mut tx, user_id, device.keys, false).await?;
        tx.commit().await?;

        tracing::info!("Linked device provisioned successfully");
        self.metrics.devices_created.add(1, &[]);

        Ok(session)
    }

    async fn provision_device(
        &self,
        tx: &mut sqlx::PgConnection,
        user_id: Uuid,
        keys: NewDeviceKeys,
        is_primary: bool,
    ) -> Result<AuthSession> {
        let created =
            self.device_repo.create(&mut *tx, user_id, keys.name.as_deref(), keys.registration_id, is_primary).await?;
        tracing::Span::current().record("device.id", tracing::field::display(created.id));

        self.key_service
            .store_new_device_keys(&mut *tx, created.id, &keys.signed_pre_key, &keys.one_time_pre_keys)
            .await?;

        self.auth_service.create_session(&mut *tx, user_id, created.id).await
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
        caller_device_id: Uuid,
        caller_is_primary: bool,
        device_id: Uuid,
    ) -> Result<()> {
        if caller_device_id != device_id && !caller_is_primary {
            return Err(AppError::Forbidden("Only the primary device can delete other devices".into()));
        }

        let mut tx = self.pool.begin().await?;
        self.user_repo.lock_identity_key(&mut tx, user_id).await?;
        let target = self.device_repo.find_by_id(&mut tx, device_id, user_id).await?.ok_or(AppError::NotFound)?;
        if target.is_primary {
            return Err(AppError::Forbidden("The primary device cannot be deleted; reset the account instead".into()));
        }
        self.device_repo.delete(&mut tx, device_id, user_id).await?;
        tx.commit().await?;

        self.notifier.notify(&[device_id], DeviceEvent::Disconnect).await;

        tracing::info!("Device deleted");
        self.metrics.devices_deleted.add(1, &[]);

        Ok(())
    }

    /// Deletes every device and link session of the account, replaces the account identity, and provisions
    /// a new primary device in one transaction. Authorized by the account password.
    ///
    /// # Errors
    /// Returns `AppError::Unauthorized` if the credentials are invalid.
    /// Returns `AppError::BadRequest` if the batch is too large.
    /// Returns `AppError::Database` if any database operation fails.
    #[tracing::instrument(
        skip(self, username, password, keys),
        fields(user.id = tracing::field::Empty, device.id = tracing::field::Empty),
        err(level = "warn")
    )]
    pub(crate) async fn reset_account(
        &self,
        username: &str,
        password: &str,
        keys: NewDeviceKeys,
    ) -> Result<AuthSession> {
        self.key_service.check_batch_size(&keys.one_time_pre_keys)?;
        let user_id = self.auth_service.verify_credentials(username, password).await?;

        let mut tx = self.pool.begin().await?;
        self.user_repo.lock_identity_key(&mut tx, user_id).await?;
        let deleted = self.device_repo.delete_all_for_user(&mut tx, user_id).await?;
        self.link_session_repo.delete_all_for_user(&mut tx, user_id).await?;
        self.user_repo.set_identity_key(&mut tx, user_id, &keys.identity_key).await?;
        let session = self.provision_device(&mut tx, user_id, keys, true).await?;
        tx.commit().await?;

        self.notifier.notify(&deleted, DeviceEvent::Disconnect).await;

        tracing::info!(devices = deleted.len(), "Account reset and new primary provisioned");
        self.metrics.account_resets.add(1, &[]);
        self.metrics.devices_deleted.add(deleted.len() as u64, &[]);
        self.metrics.devices_created.add(1, &[]);

        Ok(session)
    }
}
