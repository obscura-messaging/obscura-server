use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub device_id: Uuid,
}
