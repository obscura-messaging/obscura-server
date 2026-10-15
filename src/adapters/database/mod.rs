pub mod attachment_repo;
pub mod backup_repo;
pub mod device_repo;
pub mod key_repo;
pub mod link_session_repo;
pub mod message_repo;
pub mod push_token_repo;
pub mod records;
pub mod refresh_token_repo;
pub mod user_repo;

use crate::config::DatabaseConfig;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use std::time::Duration;

pub type DbPool = Pool<Postgres>;

/// Initializes the database connection pool.
///
/// # Errors
/// Returns `sqlx::Error` if the connection fails.
pub async fn init_pool(config: &DatabaseConfig) -> Result<DbPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(Duration::from_secs(config.acquire_timeout_secs))
        .idle_timeout(Duration::from_secs(config.idle_timeout_secs))
        .max_lifetime(Duration::from_secs(config.max_lifetime_secs))
        .connect(&config.url)
        .await
}
