use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: Option<String>,
    pub is_primary: bool,
    pub created_at: Option<OffsetDateTime>,
}
