use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub(crate) struct Message {
    pub id: Uuid,
    pub sender_user_id: Uuid,
    pub sender_device_id: Uuid,
    pub content: Vec<u8>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceSubmission {
    pub device_id: Uuid,
    pub message: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecipientSubmissions {
    pub user_id: Uuid,
    pub submissions: Vec<DeviceSubmission>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmissionOutcome {
    pub invalid_device_ids: Vec<Uuid>,
    pub device_mismatches: Vec<DeviceMismatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceMismatch {
    pub user_id: Uuid,
    pub missing_device_ids: Vec<Uuid>,
}
