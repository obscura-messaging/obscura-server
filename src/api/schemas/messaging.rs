use crate::domain::message::{DeviceSubmission, Message, RecipientSubmissions, SubmissionOutcome};
use crate::error::{AppError, Result};
use crate::proto::obscura::v1 as proto;
use std::collections::HashSet;
use uuid::Uuid;

pub(crate) fn parse_send_request(
    sender_device_id: Uuid,
    batch_limit: usize,
    request: proto::SendMessageRequest,
) -> Result<Vec<RecipientSubmissions>> {
    let total_submissions: usize = request.recipients.iter().map(|r| r.submissions.len()).sum();
    if request.recipients.len() > batch_limit || total_submissions > batch_limit {
        return Err(AppError::PayloadTooLarge);
    }

    let mut seen_users = HashSet::with_capacity(request.recipients.len());
    let mut seen_devices = HashSet::with_capacity(total_submissions);
    let mut recipients = Vec::with_capacity(request.recipients.len());

    for recipient in request.recipients {
        let user_id = Uuid::from_slice(&recipient.user_id)
            .map_err(|_| AppError::BadRequest("Invalid recipient user_id UUID bytes (expected 16)".to_string()))?;
        if !seen_users.insert(user_id) {
            return Err(AppError::BadRequest("Duplicate recipient user_id".to_string()));
        }

        let mut submissions = Vec::with_capacity(recipient.submissions.len());
        for sub in recipient.submissions {
            let device_id = Uuid::from_slice(&sub.device_id)
                .map_err(|_| AppError::BadRequest("Invalid device_id UUID bytes (expected 16)".to_string()))?;
            if device_id == sender_device_id {
                return Err(AppError::BadRequest("Cannot send to the sending device".to_string()));
            }
            if !seen_devices.insert(device_id) {
                return Err(AppError::BadRequest("Duplicate target device_id".to_string()));
            }
            if sub.message.is_empty() {
                return Err(AppError::BadRequest("Missing message payload".to_string()));
            }
            submissions.push(DeviceSubmission { device_id, message: sub.message });
        }

        recipients.push(RecipientSubmissions { user_id, submissions });
    }

    Ok(recipients)
}

impl From<SubmissionOutcome> for proto::SendMessageResponse {
    fn from(outcome: SubmissionOutcome) -> Self {
        Self {
            invalid_device_ids: outcome.invalid_device_ids.into_iter().map(|id| id.as_bytes().to_vec()).collect(),
            device_mismatches: outcome
                .device_mismatches
                .into_iter()
                .map(|m| proto::send_message_response::DeviceMismatch {
                    user_id: m.user_id.as_bytes().to_vec(),
                    missing_device_ids: m.missing_device_ids.iter().map(|id| id.as_bytes().to_vec()).collect(),
                })
                .collect(),
        }
    }
}

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
