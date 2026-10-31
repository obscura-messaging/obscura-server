use crate::adapters::database::DbPool;
use crate::adapters::database::push_token_repo::PushTokenRepository;
use crate::domain::device::PushToken;
use crate::error::Result;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct PushTokenService {
    pool: DbPool,
    repo: PushTokenRepository,
}

impl PushTokenService {
    #[must_use]
    pub const fn new(pool: DbPool, repo: PushTokenRepository) -> Self {
        Self { pool, repo }
    }

    /// Registers or updates a push token for a device.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub async fn register_token(&self, device_id: Uuid, token: &PushToken) -> Result<()> {
        let mut conn = self.pool.acquire().await?;
        self.repo.upsert_token(&mut conn, device_id, token.as_str()).await
    }

    /// Finds push tokens for a batch of devices.
    ///
    /// # Errors
    /// Returns an error if the database query fails.
    pub async fn find_tokens_for_devices(&self, device_ids: &[Uuid]) -> Result<Vec<(Uuid, String)>> {
        let mut conn = self.pool.acquire().await?;
        self.repo.find_tokens_for_devices(&mut conn, device_ids).await
    }

    /// Deletes a batch of push tokens that the push provider reported as unregistered.
    ///
    /// # Errors
    /// Returns an error if the database deletion fails.
    pub async fn delete_tokens_batch(&self, tokens: &[String]) -> Result<()> {
        let mut conn = self.pool.acquire().await?;
        self.repo.delete_tokens_batch(&mut conn, tokens).await
    }
}
