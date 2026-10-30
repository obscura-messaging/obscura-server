use crate::adapters::database::DbPool;
use crate::adapters::database::message_repo::MessageRepository;
use crate::config::MessagingConfig;
use crate::domain::message::{
    DeviceMismatch, FailedSubmission, Message, RawSubmission, SubmissionErrorCode, SubmissionOutcome,
};
use crate::domain::notification::UserEvent;
use crate::error::Result;
use crate::services::notification_service::NotificationService;
use opentelemetry::{
    KeyValue, global,
    metrics::{Counter, Histogram},
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub(crate) struct Metrics {
    pub(crate) sent_total: Counter<u64>,
    pub(crate) fetch_batch_size: Histogram<u64>,
}

impl Metrics {
    fn new() -> Self {
        let meter = global::meter("obscura-server");
        Self {
            sent_total: meter
                .u64_counter("obscura_messages_sent_total")
                .with_description("Total messages successfully sent")
                .build(),
            fetch_batch_size: meter
                .u64_histogram("obscura_message_fetch_batch_size")
                .with_description("Number of messages fetched in a single batch")
                .build(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MessageService {
    pool: DbPool,
    repo: MessageRepository,
    notifier: NotificationService,
    ttl_days: i64,
    metrics: Metrics,
}

impl MessageService {
    #[must_use]
    pub(crate) fn new(
        pool: DbPool,
        repo: MessageRepository,
        notifier: NotificationService,
        _config: MessagingConfig,
        ttl_days: i64,
    ) -> Self {
        Self { pool, repo, notifier, ttl_days, metrics: Metrics::new() }
    }

    /// Processes a batch of raw submissions.
    /// Performs structural validation, device checking, the complete-delivery check per target user,
    /// and bulk insertion, with the target users' device sets locked from the check to the commit.
    ///
    /// # Errors
    /// Returns `AppError::Database` if any database operation fails.
    #[tracing::instrument(
        err(level = "warn"),
        skip(self, submissions),
        fields(sender_id = %sender_id, sender_device_id = %sender_device_id, count = submissions.len())
    )]
    pub(crate) async fn send(
        &self,
        sender_id: Uuid,
        sender_device_id: Uuid,
        recipient_user_ids: &BTreeSet<Uuid>,
        submissions: Vec<RawSubmission>,
    ) -> Result<SubmissionOutcome> {
        let mut failed_submissions = Vec::new();
        let mut potential_valid = Vec::with_capacity(submissions.len());
        let mut device_ids_to_check = HashSet::new();

        // Pass 1: Structural Validation
        for raw in submissions {
            let Ok(submission_id) = Uuid::from_slice(&raw.submission_id) else {
                failed_submissions.push(FailedSubmission {
                    submission_id: raw.submission_id,
                    error_code: SubmissionErrorCode::MalformedSubmissionId,
                    error_message: "Invalid submission_id UUID bytes (expected 16)".to_string(),
                });
                continue;
            };

            let Ok(device_id) = Uuid::from_slice(&raw.device_id) else {
                failed_submissions.push(FailedSubmission {
                    submission_id: raw.submission_id,
                    error_code: SubmissionErrorCode::MalformedDeviceId,
                    error_message: "Invalid device_id UUID bytes (expected 16)".to_string(),
                });
                continue;
            };

            if device_id == sender_device_id {
                failed_submissions.push(FailedSubmission {
                    submission_id: raw.submission_id,
                    error_code: SubmissionErrorCode::InvalidDevice,
                    error_message: "Cannot send to the sending device".to_string(),
                });
                continue;
            }

            if raw.message.is_empty() {
                failed_submissions.push(FailedSubmission {
                    submission_id: raw.submission_id,
                    error_code: SubmissionErrorCode::MessageMissing,
                    error_message: "Missing message payload".to_string(),
                });
                continue;
            }

            device_ids_to_check.insert(device_id);
            potential_valid.push((device_id, submission_id, raw.message));
        }

        if potential_valid.is_empty() && recipient_user_ids.is_empty() {
            return Ok(SubmissionOutcome { failed_submissions, device_mismatches: Vec::new() });
        }

        // Pass 2: Business Validation (Device Existence and Complete Delivery)
        let mut tx = self.pool.begin().await?;
        let check_ids: Vec<Uuid> = device_ids_to_check.into_iter().collect();
        let explicit_user_ids: Vec<Uuid> = recipient_user_ids.iter().copied().collect();
        let mut owner_of = HashMap::new();
        let mut current_devices: BTreeMap<Uuid, BTreeSet<Uuid>> = BTreeMap::new();
        for (device_id, user_id) in self.repo.lock_device_sets(&mut tx, &check_ids, &explicit_user_ids).await? {
            owner_of.insert(device_id, user_id);
            if device_id != sender_device_id {
                current_devices.entry(user_id).or_default().insert(device_id);
            }
        }

        // A listed user is checked even when the request targets none of its devices.
        let mut targeted: BTreeMap<Uuid, BTreeSet<Uuid>> =
            recipient_user_ids.iter().map(|user_id| (*user_id, BTreeSet::new())).collect();
        for (device_id, _, _) in &potential_valid {
            if let Some(user_id) = owner_of.get(device_id) {
                targeted.entry(*user_id).or_default().insert(*device_id);
            }
        }

        let mut device_mismatches = Vec::new();
        for (user_id, targets) in &targeted {
            let current = current_devices.remove(user_id).unwrap_or_default();
            let missing_device_ids: Vec<Uuid> = current.difference(targets).copied().collect();
            if !missing_device_ids.is_empty() {
                device_mismatches.push(DeviceMismatch { user_id: *user_id, missing_device_ids });
            }
        }
        let mismatched: HashSet<Uuid> = device_mismatches.iter().map(|m| m.user_id).collect();

        let mut to_insert = Vec::with_capacity(potential_valid.len());
        for (d_id, s_id, msg) in potential_valid {
            match owner_of.get(&d_id) {
                None => failed_submissions.push(FailedSubmission {
                    submission_id: s_id.as_bytes().to_vec(),
                    error_code: SubmissionErrorCode::InvalidDevice,
                    error_message: "Device not found".to_string(),
                }),
                Some(user_id) if mismatched.contains(user_id) => failed_submissions.push(FailedSubmission {
                    submission_id: s_id.as_bytes().to_vec(),
                    error_code: SubmissionErrorCode::DeviceMismatch,
                    error_message: "Targeted devices do not match the user's current devices".to_string(),
                }),
                Some(_) => to_insert.push((d_id, s_id, msg)),
            }
        }

        // Pass 3: Bulk Insert
        if to_insert.is_empty() {
            tx.commit().await?;
        } else {
            let inserted =
                self.repo.create_batch(&mut tx, sender_id, sender_device_id, to_insert, self.ttl_days).await?;
            tx.commit().await?;

            self.metrics.sent_total.add(inserted.len() as u64, &[KeyValue::new("status", "success")]);

            // Notify target devices
            let inserted_device_ids: Vec<Uuid> = inserted.into_iter().map(|(id, _)| id).collect();
            self.notifier.notify(&inserted_device_ids, UserEvent::MessageReceived).await;
        }

        Ok(SubmissionOutcome { failed_submissions, device_mismatches })
    }

    /// Fetches a batch of pending messages for a device.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the query fails.
    #[tracing::instrument(
        err(level = "warn"),
        skip(self),
        fields(device.id = %device_id, batch_limit = %limit)
    )]
    pub(crate) async fn fetch_pending_batch(
        &self,
        device_id: Uuid,
        cursor: Option<(time::OffsetDateTime, Uuid)>,
        limit: i64,
    ) -> Result<Vec<Message>> {
        let mut conn = self.pool.acquire().await?;
        let messages = self.repo.fetch_pending_batch(&mut conn, device_id, cursor, limit).await?;

        self.metrics.fetch_batch_size.record(messages.len() as u64, &[]);

        Ok(messages)
    }

    /// Deletes a batch of messages.
    ///
    /// # Errors
    /// Returns `AppError::Database` if the deletion fails.
    #[tracing::instrument(
        err,
        skip(self),
        fields(batch_count = message_ids.len())
    )]
    pub(crate) async fn delete_batch(&self, device_id: Uuid, message_ids: &[Uuid]) -> Result<()> {
        let mut conn = self.pool.acquire().await?;
        self.repo.delete_batch(&mut conn, device_id, message_ids).await
    }
}
