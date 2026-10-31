use crate::adapters::database::DbPool;
use crate::adapters::database::message_repo::MessageRepository;
use crate::adapters::redis::RedisCache;
use crate::domain::message::{
    DeviceMismatch, FailedSubmission, Message, RawSubmission, SubmissionErrorCode, SubmissionOutcome,
};
use crate::domain::notification::DeviceEvent;
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
    pub(crate) inbox_overflow: Counter<u64>,
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
            inbox_overflow: meter
                .u64_counter("obscura_messages_overflow_total")
                .with_description("Total messages deleted due to inbox overflow")
                .build(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidSubmission {
    device_id: Uuid,
    submission_id: Uuid,
    message: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct DeliveryPlan {
    to_insert: Vec<(Uuid, Uuid, Vec<u8>)>,
    outcome: SubmissionOutcome,
}

/// Pure structural validation of raw submissions before touching the database.
fn parse_submissions(
    sender_device_id: Uuid,
    submissions: Vec<RawSubmission>,
) -> (Vec<ValidSubmission>, Vec<FailedSubmission>) {
    let mut failed_submissions = Vec::new();
    let mut valid = Vec::with_capacity(submissions.len());

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

        valid.push(ValidSubmission { device_id, submission_id, message: raw.message });
    }

    (valid, failed_submissions)
}

/// Pure complete-delivery evaluation against the locked `(device_id, user_id)` pairs from the database.
fn resolve_delivery(
    sender_device_id: Uuid,
    recipient_user_ids: &BTreeSet<Uuid>,
    valid: Vec<ValidSubmission>,
    locked_devices: Vec<(Uuid, Uuid)>,
    mut failed_submissions: Vec<FailedSubmission>,
) -> DeliveryPlan {
    let mut owner_of = HashMap::new();
    let mut current_devices: BTreeMap<Uuid, BTreeSet<Uuid>> = BTreeMap::new();
    for (device_id, user_id) in locked_devices {
        owner_of.insert(device_id, user_id);
        if device_id != sender_device_id {
            current_devices.entry(user_id).or_default().insert(device_id);
        }
    }

    // A listed user is checked even when the request targets none of its devices.
    let mut targeted: BTreeMap<Uuid, BTreeSet<Uuid>> =
        recipient_user_ids.iter().map(|user_id| (*user_id, BTreeSet::new())).collect();
    for sub in &valid {
        if let Some(user_id) = owner_of.get(&sub.device_id) {
            targeted.entry(*user_id).or_default().insert(sub.device_id);
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

    let mut to_insert = Vec::with_capacity(valid.len());
    for sub in valid {
        match owner_of.get(&sub.device_id) {
            None => failed_submissions.push(FailedSubmission {
                submission_id: sub.submission_id.as_bytes().to_vec(),
                error_code: SubmissionErrorCode::InvalidDevice,
                error_message: "Device not found".to_string(),
            }),
            Some(user_id) if mismatched.contains(user_id) => failed_submissions.push(FailedSubmission {
                submission_id: sub.submission_id.as_bytes().to_vec(),
                error_code: SubmissionErrorCode::DeviceMismatch,
                error_message: "Targeted devices do not match the user's current devices".to_string(),
            }),
            Some(_) => to_insert.push((sub.device_id, sub.submission_id, sub.message)),
        }
    }

    DeliveryPlan { to_insert, outcome: SubmissionOutcome { failed_submissions, device_mismatches } }
}

#[derive(Clone, Debug)]
pub struct MessageService {
    pool: DbPool,
    repo: MessageRepository,
    notifier: NotificationService,
    submission_cache: RedisCache,
    max_inbox_size: i64,
    ttl_days: i64,
    metrics: Metrics,
}

impl MessageService {
    #[must_use]
    pub fn new(
        pool: DbPool,
        repo: MessageRepository,
        notifier: NotificationService,
        submission_cache: RedisCache,
        max_inbox_size: i64,
        ttl_days: i64,
    ) -> Self {
        Self { pool, repo, notifier, submission_cache, max_inbox_size, ttl_days, metrics: Metrics::new() }
    }

    /// Processes an idempotent batch of raw submissions.
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
        idempotency_key: Uuid,
        recipient_user_ids: &BTreeSet<Uuid>,
        submissions: Vec<RawSubmission>,
    ) -> Result<SubmissionOutcome> {
        let cache_key = idempotency_key.to_string();
        if let Ok(Some(cached)) = self.submission_cache.get(&cache_key).await
            && let Ok(outcome) = serde_json::from_slice::<SubmissionOutcome>(&cached)
        {
            tracing::info!(key = %idempotency_key, "Returning cached idempotency response");
            return Ok(outcome);
        }

        let (valid, failed_submissions) = parse_submissions(sender_device_id, submissions);
        if valid.is_empty() && recipient_user_ids.is_empty() {
            let outcome = SubmissionOutcome { failed_submissions, device_mismatches: Vec::new() };
            self.cache_outcome(&cache_key, &outcome).await;
            return Ok(outcome);
        }

        let check_ids: Vec<Uuid> = valid.iter().map(|s| s.device_id).collect::<HashSet<_>>().into_iter().collect();
        let explicit_user_ids: Vec<Uuid> = recipient_user_ids.iter().copied().collect();

        let mut tx = self.pool.begin().await?;
        let locked_devices = self.repo.lock_device_sets(&mut tx, &check_ids, &explicit_user_ids).await?;
        let plan = resolve_delivery(sender_device_id, recipient_user_ids, valid, locked_devices, failed_submissions);

        if plan.to_insert.is_empty() {
            tx.commit().await?;
        } else {
            let inserted =
                self.repo.create_batch(&mut tx, sender_id, sender_device_id, plan.to_insert, self.ttl_days).await?;
            tx.commit().await?;

            self.metrics.sent_total.add(inserted.len() as u64, &[KeyValue::new("status", "success")]);

            let inserted_device_ids: Vec<Uuid> = inserted.into_iter().map(|(id, _)| id).collect();
            self.notifier.notify(&inserted_device_ids, DeviceEvent::MessageReceived).await;
        }

        self.cache_outcome(&cache_key, &plan.outcome).await;
        Ok(plan.outcome)
    }

    async fn cache_outcome(&self, key: &str, outcome: &SubmissionOutcome) {
        if let Ok(bytes) = serde_json::to_vec(outcome)
            && let Err(e) = self.submission_cache.set(key, &bytes).await
        {
            tracing::error!(error = %e, "Failed to cache idempotency response");
        }
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

    /// Deletes expired messages and prunes per-device queues exceeding `max_inbox_size`.
    ///
    /// # Errors
    /// Returns `AppError::Database` if a database operation fails.
    #[tracing::instrument(
        skip(self),
        err,
        fields(expired_deleted = tracing::field::Empty, overflow_deleted = tracing::field::Empty)
    )]
    pub async fn cleanup_expired_and_overflow(&self) -> Result<()> {
        let res_expiry = if let Ok(mut conn) = self.pool.acquire().await {
            self.repo.delete_expired(&mut conn).await
        } else {
            Err(crate::error::AppError::Internal)
        };

        match res_expiry {
            Ok(count) => {
                if count > 0 {
                    tracing::info!(count = %count, "Deleted expired messages");
                    tracing::Span::current().record("expired_deleted", count);
                }
            }
            Err(e) => tracing::error!(error = ?e, "Cleanup error (expiry)"),
        }

        let res_overflow = if let Ok(mut conn) = self.pool.acquire().await {
            self.repo.delete_global_overflow(&mut conn, self.max_inbox_size).await
        } else {
            Err(crate::error::AppError::Internal)
        };

        match res_overflow {
            Ok(count) => {
                if count > 0 {
                    tracing::info!(count = %count, "Pruned overflow messages");
                    self.metrics.inbox_overflow.add(count, &[]);
                    tracing::Span::current().record("overflow_deleted", count);
                }
            }
            Err(e) => tracing::error!(error = ?e, "Cleanup error (overflow)"),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_submissions_classifies_structural_errors() {
        let sender_device = Uuid::new_v4();
        let target_device = Uuid::new_v4();
        let sub_self = Uuid::new_v4();
        let sub_empty = Uuid::new_v4();
        let sub_ok = Uuid::new_v4();

        let raw = vec![
            RawSubmission { submission_id: vec![1, 2], device_id: target_device.as_bytes().to_vec(), message: vec![1] },
            RawSubmission {
                submission_id: Uuid::new_v4().as_bytes().to_vec(),
                device_id: vec![3, 4],
                message: vec![1],
            },
            RawSubmission {
                submission_id: sub_self.as_bytes().to_vec(),
                device_id: sender_device.as_bytes().to_vec(),
                message: vec![1],
            },
            RawSubmission {
                submission_id: sub_empty.as_bytes().to_vec(),
                device_id: target_device.as_bytes().to_vec(),
                message: vec![],
            },
            RawSubmission {
                submission_id: sub_ok.as_bytes().to_vec(),
                device_id: target_device.as_bytes().to_vec(),
                message: vec![9, 9],
            },
        ];

        let (valid, failed) = parse_submissions(sender_device, raw);
        assert_eq!(
            valid,
            vec![ValidSubmission { device_id: target_device, submission_id: sub_ok, message: vec![9, 9] }]
        );
        assert_eq!(
            failed.iter().map(|f| f.error_code).collect::<Vec<_>>(),
            vec![
                SubmissionErrorCode::MalformedSubmissionId,
                SubmissionErrorCode::MalformedDeviceId,
                SubmissionErrorCode::InvalidDevice,
                SubmissionErrorCode::MessageMissing,
            ]
        );
    }

    #[test]
    fn test_resolve_delivery_enforces_complete_delivery_per_user() {
        let sender_device = Uuid::new_v4();
        let bob = Uuid::new_v4();
        let bob_d1 = Uuid::new_v4();
        let bob_d2 = Uuid::new_v4();
        let carol = Uuid::new_v4();
        let carol_d1 = Uuid::new_v4();
        let unknown_device = Uuid::new_v4();

        let sub_bob = Uuid::new_v4();
        let sub_carol = Uuid::new_v4();
        let sub_unknown = Uuid::new_v4();

        let valid = vec![
            ValidSubmission { device_id: bob_d1, submission_id: sub_bob, message: vec![1] },
            ValidSubmission { device_id: carol_d1, submission_id: sub_carol, message: vec![2] },
            ValidSubmission { device_id: unknown_device, submission_id: sub_unknown, message: vec![3] },
        ];
        let locked = vec![(bob_d1, bob), (bob_d2, bob), (carol_d1, carol)];

        let plan = resolve_delivery(sender_device, &BTreeSet::new(), valid, locked, Vec::new());

        assert_eq!(plan.to_insert, vec![(carol_d1, sub_carol, vec![2])]);
        assert_eq!(
            plan.outcome.device_mismatches,
            vec![DeviceMismatch { user_id: bob, missing_device_ids: vec![bob_d2] }]
        );
        assert_eq!(
            plan.outcome.failed_submissions.iter().map(|f| (f.submission_id.clone(), f.error_code)).collect::<Vec<_>>(),
            vec![
                (sub_bob.as_bytes().to_vec(), SubmissionErrorCode::DeviceMismatch),
                (sub_unknown.as_bytes().to_vec(), SubmissionErrorCode::InvalidDevice),
            ]
        );
    }
}
