use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub(crate) struct Message {
    pub id: Uuid,
    pub sender_id: Uuid,
    pub sender_device_id: Uuid,
    pub content: Vec<u8>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub(crate) struct RawSubmission {
    pub submission_id: Vec<u8>,
    pub device_id: Vec<u8>,
    pub message: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmissionOutcome {
    pub failed_submissions: Vec<FailedSubmission>,
    pub device_mismatches: Vec<DeviceMismatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceMismatch {
    pub user_id: Uuid,
    pub missing_device_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedSubmission {
    pub submission_id: Vec<u8>, // Use raw bytes to preserve whatever the client sent
    pub error_code: SubmissionErrorCode,
    pub error_message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmissionErrorCode {
    InvalidDevice,
    MalformedDeviceId,
    MalformedSubmissionId,
    MessageMissing,
    DeviceMismatch,
}
