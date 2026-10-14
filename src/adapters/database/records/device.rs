use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct DeviceRecord {
    pub(crate) id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) name: Option<String>,
    pub(crate) is_primary: bool,
    pub(crate) created_at: Option<OffsetDateTime>,
}

impl From<DeviceRecord> for crate::domain::device::Device {
    fn from(record: DeviceRecord) -> Self {
        Self {
            id: record.id,
            user_id: record.user_id,
            name: record.name,
            is_primary: record.is_primary,
            created_at: record.created_at,
        }
    }
}
