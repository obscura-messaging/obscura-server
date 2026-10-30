use crate::adapters::database::DbPool;
use crate::adapters::database::device_repo::DeviceRepository;
use crate::adapters::database::link_session_repo::LinkSessionRepository;
use crate::error::{AppError, Result};
use crate::services::auth_service::AuthService;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

pub(crate) const LINK_SESSION_TTL: Duration = Duration::from_secs(600);
pub(crate) const MAX_LINK_SESSION_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct NewLinkSession {
    pub id: String,
    pub user_id: Uuid,
    pub expires_at: OffsetDateTime,
}

/// Link sessions: created with account credentials, approved by the primary with the encrypted
/// provisioning message, and consumed when registering the linked device.
#[derive(Clone, Debug)]
pub struct LinkSessionService {
    pool: DbPool,
    auth_service: AuthService,
    device_repo: DeviceRepository,
    repo: LinkSessionRepository,
}

impl LinkSessionService {
    #[must_use]
    pub const fn new(
        pool: DbPool,
        auth_service: AuthService,
        device_repo: DeviceRepository,
        repo: LinkSessionRepository,
    ) -> Self {
        Self { pool, auth_service, device_repo, repo }
    }

    /// Verifies the account credentials and creates a link session bound to the user, replacing any
    /// previous unapproved session of the user and purging expired sessions.
    ///
    /// # Errors
    /// Returns `AppError::AuthError` if the credentials are invalid.
    /// Returns `AppError::Database` if any database operation fails.
    #[tracing::instrument(skip(self, username, password), fields(user.id = tracing::field::Empty), err(level = "warn"))]
    pub(crate) async fn create(&self, username: &str, password: &str) -> Result<NewLinkSession> {
        let user_id = self.auth_service.verify_credentials(username, password).await?;
        let id = AuthService::generate_opaque_token();
        let expires_at = OffsetDateTime::now_utc() + LINK_SESSION_TTL;

        let mut conn = self.pool.acquire().await?;
        self.repo.create(&mut conn, &AuthService::hash_opaque_token(&id), user_id, expires_at).await?;

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
    pub(crate) async fn approve(&self, user_id: Uuid, caller_device_id: Uuid, id: &str, body: &[u8]) -> Result<()> {
        let mut conn = self.pool.acquire().await?;
        let caller = self.device_repo.find_by_id(&mut conn, caller_device_id, user_id).await?;
        if !caller.is_some_and(|d| d.is_primary) {
            return Err(AppError::Forbidden("Primary device required".into()));
        }
        if body.len() > MAX_LINK_SESSION_BODY_BYTES {
            return Err(AppError::PayloadTooLarge);
        }

        let id_hash = AuthService::hash_opaque_token(id);
        if self.repo.approve(&mut conn, &id_hash, user_id, body).await? {
            return Ok(());
        }
        match self.repo.find_body_for_user(&mut conn, &id_hash, user_id).await? {
            Some(_) => Err(AppError::Conflict("Link session already approved".into())),
            None => Err(AppError::NotFound),
        }
    }

    /// Returns the body of an approved link session, or `None` if it is not approved yet.
    ///
    /// # Errors
    /// Returns `AppError::NotFound` if the session is unknown, expired, or consumed.
    #[tracing::instrument(skip(self, id), err(level = "warn"))]
    pub(crate) async fn get_body(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let id_hash = AuthService::hash_opaque_token(id);
        let mut conn = self.pool.acquire().await?;
        self.repo.find_body(&mut conn, &id_hash).await?.ok_or(AppError::NotFound)
    }
}
