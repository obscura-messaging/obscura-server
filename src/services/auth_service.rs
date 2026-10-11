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

    /// Registers a new user account. Returns a user-only JWT (no `device_id`).
    ///
    /// # Errors
    /// Returns `AppError::Conflict` if the username already exists.
    /// Returns `AppError::Database` if any of the underlying operations fail.
    #[tracing::instrument(
        skip(self, username, password),
        fields(user.id = tracing::field::Empty),
        err(level = "warn")
    )]
    pub(crate) async fn register(&self, username: String, password: String) -> Result<AuthSession> {
        let password_hash = self.hash_password(&password).await?;
        let mut tx = self.pool.begin().await?;
        let user = self.user_repo.create(&mut tx, &username, &password_hash).await?;
        tracing::Span::current().record("user_id", tracing::field::display(user.id));
        let session = self.create_session(&mut tx, user.id, None).await?;
        tx.commit().await?;
        tracing::info!("User registered successfully");
        self.metrics.registered_total.add(1, &[]);
        Ok(session)
    }

    /// Authenticates a user. If `device_id` is provided and belongs to user, returns a full JWT.
    /// Otherwise returns a user-only JWT.
    ///
    /// # Errors
    /// Returns `AppError::AuthError` if credentials are invalid.
    #[tracing::instrument(
        skip(self, username, password),
        fields(user.id = tracing::field::Empty),
        err(level = "warn")
    )]
    pub(crate) async fn login(
        &self,
        username: String,
        password: String,
        device_id: Option<Uuid>,
    ) -> Result<AuthSession> {
        let mut conn = self.pool.acquire().await?;
        let Some(user) = self.user_repo.find_by_username(&mut conn, &username).await? else {
            tracing::warn!("Login failed: user not found");
            return Err(AppError::AuthError);
        };

        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        let is_valid = self.verify_password(&password, &user.password_hash).await?;

        if !is_valid {
            tracing::warn!("Login failed: invalid password");
            return Err(AppError::AuthError);
        }

        // If device_id provided, validate it belongs to this user
        let validated_device_id = if let Some(did) = device_id {
            if self.device_repo.belongs_to_user(&mut conn, did, user.id).await? {
                Some(did)
            } else {
                tracing::warn!(device_id = %did, "Login with unknown device_id, issuing user-only JWT");
                None
            }
        } else {
            None
        };

        // Generate Tokens
        let session = self.create_session(&mut conn, user.id, validated_device_id).await?;
        self.metrics.login.add(1, &[]);
        Ok(session)
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

    /// Creates a new authenticated session with optional `device_id`.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the session cannot be saved.
    #[tracing::instrument(err, skip(self, conn), fields(user.id = %user_id))]
    pub(crate) async fn create_session(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        device_id: Option<Uuid>,
    ) -> Result<AuthSession> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_secs();

        let exp = now.checked_add(self.config.access_token_ttl_secs).ok_or(AppError::Internal)?;
        let exp_usize = usize::try_from(exp).map_err(|_| AppError::Internal)?;

        let claims = Claims::new(user_id, device_id, exp_usize);
        let jwt = self.encode_jwt(&claims)?;

        let refresh_token = Self::generate_opaque_token();
        let refresh_hash = Self::hash_opaque_token(&refresh_token);

        self.refresh_repo.create(conn, user_id, device_id, &refresh_hash, self.config.refresh_token_ttl_days).await?;

        Ok(AuthSession {
            token: jwt.as_str().to_string(),
            refresh_token,
            expires_at: i64::try_from(exp).map_err(|_| AppError::Internal)?,
            device_id,
        })
    }

    /// Refreshes an existing session. Preserves the `device_id` from the original refresh token.
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

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_secs();

        let exp = now.checked_add(self.config.access_token_ttl_secs).ok_or(AppError::Internal)?;
        let exp_usize = usize::try_from(exp).map_err(|_| AppError::Internal)?;

        let claims = Claims::new(user_id, device_id, exp_usize);
        let new_jwt = self.encode_jwt(&claims)?;

        tracing::info!("Tokens rotated successfully");
        self.metrics.refresh.add(1, &[]);

        Ok(AuthSession {
            token: new_jwt.as_str().to_string(),
            refresh_token: new_refresh_token,
            expires_at: i64::try_from(exp).map_err(|_| AppError::Internal)?,
            device_id,
        })
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

    /// Verifies a JWT access token and returns (`user_id`, `device_id`).
    ///
    /// # Errors
    /// Returns `AppError::AuthError` if the token is invalid or expired.
    pub(crate) fn verify_token(&self, jwt: &Jwt) -> Result<(Uuid, Option<Uuid>)> {
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

    fn generate_opaque_token() -> String {
        let bytes = rand::random::<[u8; 32]>();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn hash_opaque_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
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
        let device_id = Some(Uuid::new_v4());
        let exp = 10_000_000_000;
        let claims = Claims::new(user_id, device_id, exp);

        let jwt = service.encode_jwt(&claims).expect("Failed to encode JWT");
        let (decoded_user, decoded_device) = service.verify_token(&jwt).expect("Failed to verify valid token");

        assert_eq!(user_id, decoded_user);
        assert_eq!(device_id, decoded_device);
    }

    #[tokio::test]
    async fn test_jwt_roundtrip_no_device() {
        let service = setup_service();
        let user_id = Uuid::new_v4();
        let exp = 10_000_000_000;
        let claims = Claims::new(user_id, None, exp);

        let jwt = service.encode_jwt(&claims).expect("Failed to encode JWT");
        let (decoded_user, decoded_device) = service.verify_token(&jwt).expect("Failed to verify valid token");

        assert_eq!(user_id, decoded_user);
        assert_eq!(decoded_device, None);
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
