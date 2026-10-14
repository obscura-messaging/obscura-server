use crate::adapters::database::DbPool;
use crate::adapters::database::device_repo::DeviceRepository;
use crate::adapters::database::provisioning_code_repo::ProvisioningCodeRepository;
use crate::adapters::redis::ProvisioningRelay;
use crate::adapters::redis::provisioning_relay::RelayPut;
use crate::error::{AppError, Result};
use crate::services::auth_service::AuthService;
use crate::services::device_service::DEVICE_SCOPE_REQUIRED;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

pub(crate) const PROVISIONING_TTL: Duration = Duration::from_secs(600);
pub(crate) const MAX_RELAY_BODY_BYTES: usize = 64 * 1024;
pub(crate) const MAX_RELAY_WAIT: Duration = Duration::from_secs(25);

/// A secret paired with the moment it stops being accepted.
#[derive(Debug)]
pub struct Expiring {
    pub value: String,
    pub expires_at: OffsetDateTime,
}

/// Provisioning codes, which authorize registering a device on an account that has one, and the relay that
/// carries the primary's encrypted provisioning message to the new device.
#[derive(Clone, Debug)]
pub struct ProvisioningService {
    pool: DbPool,
    device_repo: DeviceRepository,
    code_repo: ProvisioningCodeRepository,
    relay: ProvisioningRelay,
}

impl ProvisioningService {
    #[must_use]
    pub const fn new(
        pool: DbPool,
        device_repo: DeviceRepository,
        code_repo: ProvisioningCodeRepository,
        relay: ProvisioningRelay,
    ) -> Self {
        Self { pool, device_repo, code_repo, relay }
    }

    /// Issues a single-use provisioning code. Only the primary device may issue one.
    ///
    /// # Errors
    /// Returns `AppError::Forbidden` if the caller is not the primary device.
    /// Returns `AppError::Database` if any database operation fails.
    #[tracing::instrument(skip(self), fields(user.id = %user_id), err(level = "warn"))]
    pub(crate) async fn issue_code(&self, user_id: Uuid, caller_device_id: Option<Uuid>) -> Result<Expiring> {
        let mut conn = self.pool.acquire().await?;
        let device_id = self.require_primary(&mut conn, user_id, caller_device_id).await?;

        let code = AuthService::generate_opaque_token();
        let expires_at = OffsetDateTime::now_utc() + PROVISIONING_TTL;
        self.code_repo.delete_expired_for_device(&mut conn, device_id).await?;
        self.code_repo.create(&mut conn, device_id, &AuthService::hash_opaque_token(&code), expires_at).await?;

        Ok(Expiring { value: code, expires_at })
    }

    /// Creates a relay address bound to the user.
    ///
    /// # Errors
    /// Returns `AppError::InternalMsg` if the relay store fails.
    #[tracing::instrument(skip(self), fields(user.id = %user_id), err(level = "warn"))]
    pub(crate) async fn create_relay(&self, user_id: Uuid) -> Result<Expiring> {
        let address = AuthService::generate_opaque_token();
        let expires_at = OffsetDateTime::now_utc() + PROVISIONING_TTL;
        self.relay.create(&address, user_id, PROVISIONING_TTL).await.map_err(relay_error)?;
        Ok(Expiring { value: address, expires_at })
    }

    /// Stores the provisioning message for a relay address of the user. Only the primary device may store
    /// one, and only once per address.
    ///
    /// # Errors
    /// Returns `AppError::Forbidden` if the caller is not the primary device.
    /// Returns `AppError::PayloadTooLarge` if the body exceeds the size cap.
    /// Returns `AppError::NotFound` if the address is unknown, expired, or another user's.
    /// Returns `AppError::Conflict` if the address already received a body.
    #[tracing::instrument(skip(self, body), fields(user.id = %user_id, body.len = body.len()), err(level = "warn"))]
    pub(crate) async fn put_relay(
        &self,
        user_id: Uuid,
        caller_device_id: Option<Uuid>,
        address: &str,
        body: &[u8],
    ) -> Result<()> {
        let mut conn = self.pool.acquire().await?;
        self.require_primary(&mut conn, user_id, caller_device_id).await?;
        drop(conn);

        if body.len() > MAX_RELAY_BODY_BYTES {
            return Err(AppError::PayloadTooLarge);
        }

        match self.relay.put(address, user_id, body).await.map_err(relay_error)? {
            RelayPut::Stored => Ok(()),
            RelayPut::NotFound => Err(AppError::NotFound),
            RelayPut::AlreadyStored => Err(AppError::Conflict("Provisioning message already stored".into())),
        }
    }

    /// Removes and returns the provisioning message of a relay address of the user, waiting up to `wait`
    /// (capped) for it to arrive. Returns `None` if nothing arrived.
    ///
    /// # Errors
    /// Returns `AppError::NotFound` if the address is unknown, expired, or another user's.
    #[tracing::instrument(skip(self), fields(user.id = %user_id), err(level = "warn"))]
    pub(crate) async fn take_relay(&self, user_id: Uuid, address: &str, wait: Duration) -> Result<Option<Vec<u8>>> {
        if self.relay.owner(address).await.map_err(relay_error)? != Some(user_id) {
            return Err(AppError::NotFound);
        }
        self.relay.take(address, wait.min(MAX_RELAY_WAIT)).await.map_err(relay_error)
    }

    async fn require_primary(
        &self,
        conn: &mut sqlx::PgConnection,
        user_id: Uuid,
        caller_device_id: Option<Uuid>,
    ) -> Result<Uuid> {
        let device_id = caller_device_id.ok_or_else(|| AppError::Forbidden(DEVICE_SCOPE_REQUIRED.into()))?;
        let device = self.device_repo.find_by_id(conn, device_id, user_id).await?;
        if !device.is_some_and(|d| d.is_primary) {
            return Err(AppError::Forbidden("Primary device required".into()));
        }
        Ok(device_id)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn relay_error(e: anyhow::Error) -> AppError {
    tracing::error!(error = %e, "Provisioning relay store failed");
    AppError::InternalMsg("Provisioning relay unavailable".into())
}
