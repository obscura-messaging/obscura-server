use crate::adapters::database::DbPool;
use crate::adapters::database::device_repo::DeviceRepository;
use crate::adapters::database::provisioning_code_repo::ProvisioningCodeRepository;
use crate::error::{AppError, Result};
use crate::services::auth_service::AuthService;
use crate::services::device_service::DEVICE_SCOPE_REQUIRED;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

pub(crate) const PROVISIONING_TTL: Duration = Duration::from_secs(600);

/// A secret paired with the moment it stops being accepted.
#[derive(Debug)]
pub struct Expiring {
    pub value: String,
    pub expires_at: OffsetDateTime,
}

/// Provisioning codes, which authorize registering a device on an account that has one.
#[derive(Clone, Debug)]
pub struct ProvisioningService {
    pool: DbPool,
    device_repo: DeviceRepository,
    code_repo: ProvisioningCodeRepository,
}

impl ProvisioningService {
    #[must_use]
    pub const fn new(pool: DbPool, device_repo: DeviceRepository, code_repo: ProvisioningCodeRepository) -> Self {
        Self { pool, device_repo, code_repo }
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
