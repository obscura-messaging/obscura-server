//! Conversions from domain values to the protobuf frames sent over the WebSocket.

use crate::domain::keys::PreKeyStatus;
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

impl From<PreKeyStatus> for proto::PreKeyStatus {
    fn from(status: PreKeyStatus) -> Self {
        Self {
            one_time_pre_key_count: i32::try_from(status.count()).unwrap_or(i32::MAX),
            min_threshold: i32::try_from(status.threshold()).unwrap_or(i32::MAX),
            one_time_kyber_pre_key_count: i32::try_from(status.kyber_count()).unwrap_or(i32::MAX),
        }
    }
}

impl From<PreKeyStatus> for proto::WebSocketFrame {
    fn from(status: PreKeyStatus) -> Self {
        Self { payload: Some(proto::web_socket_frame::Payload::PreKeyStatus(status.into())) }
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

    #[test]
    fn test_pre_key_status_frame() {
        let status = PreKeyStatus::below_threshold(5, 30, 20).unwrap();
        let frame = proto::WebSocketFrame::from(status);
        assert_eq!(
            frame.payload,
            Some(proto::web_socket_frame::Payload::PreKeyStatus(proto::PreKeyStatus {
                one_time_pre_key_count: 5,
                min_threshold: 20,
                one_time_kyber_pre_key_count: 30,
            }))
        );
    }
}
