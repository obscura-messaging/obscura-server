use crate::domain::user::User;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct UserRecord {
    pub(crate) id: Uuid,
    pub(crate) username: String,
    pub(crate) password_hash: String,
}

impl From<UserRecord> for User {
    fn from(record: UserRecord) -> Self {
        Self { id: record.id, username: record.username, password_hash: record.password_hash }
    }
}
