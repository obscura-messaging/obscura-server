use crate::adapters::database::DbPool;
use crate::adapters::database::device_repo::DeviceRepository;
use crate::adapters::database::refresh_token_repo::RefreshTokenRepository;
use crate::adapters::database::user_repo::UserRepository;
use crate::config::AuthConfig;
use crate::domain::auth::{Claims, Jwt};
use crate::domain::auth_session::AuthSession;
use crate::error::{AppError, Result};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use base64::Engine;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use opentelemetry::{global, metrics::Counter};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Clone, Debug)]
struct Metrics {
    registered_total: Counter<u64>,
    login: Counter<u64>,
    refresh: Counter<u64>,
    logout: Counter<u64>,
}

impl Metrics {
    #[must_use]
    fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            registered_total: meter
                .u64_counter("obscura_registrations_total")
                .with_description("Total number of successful user registrations")
                .build(),
            login: meter
                .u64_counter("obscura_logins_total")
                .with_description("Total number of successful login attempts")
                .build(),
            refresh: meter
                .u64_counter("obscura_token_refreshes_total")
                .with_description("Total number of successful token rotations")
                .build(),
            logout: meter
                .u64_counter("obscura_logouts_total")
                .with_description("Total number of successful logout attempts")
                .build(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthService {
    config: AuthConfig,
    pool: DbPool,
    user_repo: UserRepository,
    refresh_repo: RefreshTokenRepository,
    device_repo: DeviceRepository,
    metrics: Metrics,
}

impl AuthService {
    #[must_use]
    pub fn new(
        config: AuthConfig,
        pool: DbPool,
        user_repo: UserRepository,
        refresh_repo: RefreshTokenRepository,
        device_repo: DeviceRepository,
    ) -> Self {
        Self { config, pool, user_repo, refresh_repo, device_repo, metrics: Metrics::new() }
    }

    /// Authenticates an existing device of a user and returns a device-scoped session.
    ///
    /// # Errors
    /// Returns `AppError::AuthError` if credentials are invalid.
    /// Returns `AppError::Conflict` if `device_id` does not belong to the user.
    #[tracing::instrument(
        skip(self, username, password),
        fields(user.id = tracing::field::Empty, device.id = %device_id),
        err(level = "warn")
    )]
    pub(crate) async fn login(&self, username: &str, password: String, device_id: Uuid) -> Result<AuthSession> {
        let user_id = self.verify_credentials(username, &password).await?;

        let mut conn = self.pool.acquire().await?;
        if !self.device_repo.belongs_to_user(&mut conn, device_id, user_id).await? {
            tracing::warn!(device_id = %device_id, "Login rejected: device does not belong to user");
            return Err(AppError::Conflict("Device does not belong to this account".into()));
        }

        let session = self.create_session(&mut conn, user_id, device_id).await?;
        self.metrics.login.add(1, &[]);
        Ok(session)
    }

    pub(crate) fn record_registration(&self) {
        self.metrics.registered_total.add(1, &[]);
    }

    /// Verifies a username and password and returns the user's id.
    ///
    /// # Errors
    /// Returns `AppError::AuthError` if credentials are invalid.
    pub(crate) async fn verify_credentials(&self, username: &str, password: &str) -> Result<Uuid> {
        let username = crate::domain::user::Username::normalize(username);
        let mut conn = self.pool.acquire().await?;
        let Some(user) = self.user_repo.find_by_username(&mut conn, &username).await? else {
            tracing::warn!("Credentials rejected: user not found");
            return Err(AppError::AuthError);
        };
        drop(conn);

        tracing::Span::current().record("user.id", tracing::field::display(user.id));

        if !self.verify_password(password, &user.password_hash).await? {
            tracing::warn!("Credentials rejected: invalid password");
            return Err(AppError::AuthError);
        }
        Ok(user.id)
    }

    /// Hashes a password using Argon2.
    ///
    /// # Errors
    /// Returns `AppError::Internal` if hashing fails.
    #[tracing::instrument(err, skip(self, password))]
    pub(crate) async fn hash_password(&self, password: &str) -> Result<String> {
        let password = password.to_string();
        tokio::task::spawn_blocking(move || {
            let argon2 = Argon2::default();
            argon2.hash_password(password.as_bytes()).map_err(|_| AppError::Internal).map(|h| h.to_string())
        })
        .await
        .map_err(|_| AppError::Internal)?
    }

    /// Verifies a password against a hash.
    ///
    /// # Errors
    /// Returns `AppError::Internal` if verification logic fails.
    #[tracing::instrument(err, skip(self, password, password_hash))]
    pub(crate) async fn verify_password(&self, password: &str, password_hash: &str) -> Result<bool> {
        let password = password.to_string();
        let password_hash = password_hash.to_string();
        tokio::task::spawn_blocking(move || {
            let parsed_hash = PasswordHash::new(&password_hash).map_err(|_| AppError::Internal)?;
            Ok(Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok())
        })
        .await
        .map_err(|_| AppError::Internal)?
    }

    /// Creates a device-scoped session with a refresh token.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the session cannot be saved.
    #[tracing::instrument(err, skip(self, conn), fields(user.id = %user_id, device.id = %device_id))]
    pub(crate) async fn create_session(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        device_id: Uuid,
    ) -> Result<AuthSession> {
        let (token, expires_at) = self.issue_access_token(user_id, device_id)?;
        let refresh_token = Self::generate_opaque_token();
        let refresh_hash = Self::hash_opaque_token(&refresh_token);
        self.refresh_repo.create(conn, device_id, &refresh_hash, self.config.refresh_token_ttl_days).await?;

        Ok(AuthSession { token, refresh_token, expires_at, device_id })
    }

    /// Refreshes a device-scoped session.
    ///
    /// # Errors
    /// Returns `AppError::AuthError` if the refresh token is invalid.
    #[tracing::instrument(err, skip(self, refresh_token))]
    pub(crate) async fn refresh_session(&self, refresh_token: String) -> Result<AuthSession> {
        let mut conn = self.pool.acquire().await?;
        let old_hash = Self::hash_opaque_token(&refresh_token);
        let new_refresh_token = Self::generate_opaque_token();
        let new_hash = Self::hash_opaque_token(&new_refresh_token);

        let (user_id, device_id) = self
            .refresh_repo
            .rotate_unexpired(&mut conn, &old_hash, &new_hash, self.config.refresh_token_ttl_days)
            .await?
            .ok_or(AppError::AuthError)?;

        tracing::Span::current().record("user_id", tracing::field::display(user_id));

        let (token, expires_at) = self.issue_access_token(user_id, device_id)?;

        tracing::info!("Tokens rotated successfully");
        self.metrics.refresh.add(1, &[]);

        Ok(AuthSession { token, refresh_token: new_refresh_token, expires_at, device_id })
    }

    fn issue_access_token(&self, user_id: Uuid, device_id: Uuid) -> Result<(String, i64)> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_secs();
        let exp = now.checked_add(self.config.access_token_ttl_secs).ok_or(AppError::Internal)?;
        let claims = Claims::new(user_id, device_id, usize::try_from(exp).map_err(|_| AppError::Internal)?);
        let jwt = self.encode_jwt(&claims)?;
        Ok((jwt.0, i64::try_from(exp).map_err(|_| AppError::Internal)?))
    }

    /// Logs out a user by deleting their refresh token.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the token cannot be deleted.
    #[tracing::instrument(err, skip(self, refresh_token), fields(user.id = %user_id))]
    pub(crate) async fn logout(&self, user_id: Uuid, refresh_token: String) -> Result<()> {
        let mut conn = self.pool.acquire().await?;
        let hash = Self::hash_opaque_token(&refresh_token);
        self.refresh_repo.delete_owned(&mut conn, &hash, user_id).await?;
        self.metrics.logout.add(1, &[]);
        Ok(())
    }

    /// Verifies a JWT access token and that its device still exists. Returns (`user_id`, `device_id`).
    ///
    /// # Errors
    /// Returns `AppError::AuthError` if the token is invalid, expired, or names a deleted device.
    /// Returns `AppError::Database` if the device lookup fails.
    pub(crate) async fn authenticate(&self, jwt: &Jwt) -> Result<(Uuid, Uuid)> {
        let (user_id, device_id) = self.verify_token(jwt)?;
        let mut conn = self.pool.acquire().await?;
        if !self.device_repo.belongs_to_user(&mut conn, device_id, user_id).await? {
            return Err(AppError::AuthError);
        }
        Ok((user_id, device_id))
    }

    /// Verifies a JWT access token and returns (`user_id`, `device_id`).
    ///
    /// # Errors
    /// Returns `AppError::AuthError` if the token is invalid or expired.
    fn verify_token(&self, jwt: &Jwt) -> Result<(Uuid, Uuid)> {
        let token_data = decode::<Claims>(
            jwt.as_str(),
            &DecodingKey::from_secret(self.config.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| AppError::AuthError)?;

        Ok((token_data.claims.sub, token_data.claims.device_id))
    }

    fn encode_jwt(&self, claims: &Claims) -> Result<Jwt> {
        let token = encode(&Header::default(), claims, &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()))
            .map_err(|_| AppError::Internal)?;

        Ok(Jwt(token))
    }

    pub(crate) fn generate_opaque_token() -> String {
        let bytes = rand::random::<[u8; 32]>();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    pub(crate) fn hash_opaque_token(token: &str) -> [u8; 32] {
        Sha256::digest(token.as_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::database::device_repo::DeviceRepository;
    use crate::adapters::database::refresh_token_repo::RefreshTokenRepository;
    use crate::config::AuthConfig;

    fn setup_service() -> AuthService {
        let config = AuthConfig {
            jwt_secret: "test_secret".to_string(),
            access_token_ttl_secs: 3600,
            refresh_token_ttl_days: 7,
            refresh_token_cleanup_interval_secs: 3600,
            max_devices_per_user: 10,
        };
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").expect("Valid test pool");
        AuthService::new(config, pool, UserRepository::new(), RefreshTokenRepository::new(), DeviceRepository::new())
    }

    #[tokio::test]
    async fn test_jwt_roundtrip() {
        let service = setup_service();
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let exp = 10_000_000_000;
        let claims = Claims::new(user_id, device_id, exp);

        let jwt = service.encode_jwt(&claims).expect("Failed to encode JWT");
        let (decoded_user, decoded_device) = service.verify_token(&jwt).expect("Failed to verify valid token");

        assert_eq!(user_id, decoded_user);
        assert_eq!(device_id, decoded_device);
    }

    #[tokio::test]
    async fn test_password_hashing() {
        let service = setup_service();
        let password = "password12345";
        let hash = service.hash_password(password).await.expect("Failed to hash password");

        assert!(service.verify_password(password, &hash).await.expect("Failed to verify password"));
        assert!(!service.verify_password("wrong_password", &hash).await.expect("Failed to verify password"));
    }

    #[tokio::test]
    async fn test_opaque_token_logic() {
        let token1 = AuthService::generate_opaque_token();
        let token2 = AuthService::generate_opaque_token();

        assert_ne!(token1, token2);

        let hash1 = AuthService::hash_opaque_token(&token1);
        let hash2 = AuthService::hash_opaque_token(&token1);
        assert_eq!(hash1, hash2);
    }
}
