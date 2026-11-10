//! Conversions from domain values to the protobuf frames sent over the WebSocket.

use crate::domain::message::Message;
use crate::proto::obscura::v1 as proto;

impl From<Message> for proto::Envelope {
    fn from(message: Message) -> Self {
        Self {
            id: message.id.as_bytes().to_vec(),
            sender_user_id: message.sender_user_id.as_bytes().to_vec(),
            sender_device_id: message.sender_device_id.as_bytes().to_vec(),
            // Milliseconds since the UNIX epoch.
            timestamp: u64::try_from(message.created_at.unix_timestamp_nanos() / 1_000_000).unwrap_or(0),
            message: message.content,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_envelope_from_message() {
        let (id, sender_user_id, sender_device_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let created_at = time::OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_123_456_789).unwrap();
        let envelope = proto::Envelope::from(Message {
            id,
            sender_user_id,
            sender_device_id,
            content: b"hello".to_vec(),
            created_at,
        });

        assert_eq!(envelope.id, id.as_bytes().to_vec());
        assert_eq!(envelope.sender_user_id, sender_user_id.as_bytes().to_vec());
        assert_eq!(envelope.sender_device_id, sender_device_id.as_bytes().to_vec());
        assert_eq!(envelope.timestamp, 1_700_000_000_123, "milliseconds, truncated");
        assert_eq!(envelope.message, b"hello");
    }
}
