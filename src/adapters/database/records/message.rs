use crate::domain::message::Message;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct MessageRecord {
    pub(crate) id: Uuid,
    pub(crate) sender_id: Uuid,
    pub(crate) sender_device_id: Uuid,
    pub(crate) content: Vec<u8>,
    pub(crate) created_at: OffsetDateTime,
}

impl From<MessageRecord> for Message {
    fn from(record: MessageRecord) -> Self {
        Self {
            id: record.id,
            sender_id: record.sender_id,
            sender_device_id: record.sender_device_id,
            content: record.content,
            created_at: record.created_at,
        }
    }
}
