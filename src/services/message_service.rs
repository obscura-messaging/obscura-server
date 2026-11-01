use crate::adapters::database::DbPool;
use crate::adapters::database::message_repo::MessageRepository;
use crate::adapters::redis::RedisCache;
use crate::domain::message::{DeviceMismatch, Message, RecipientSubmissions, SubmissionOutcome};
use crate::domain::notification::DeviceEvent;
use crate::error::Result;
use crate::services::notification_service::NotificationService;
use opentelemetry::{
    KeyValue, global,
    metrics::{Counter, Histogram},
};
use std::collections::{BTreeSet, HashMap};
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

#[derive(Debug, PartialEq, Eq)]
struct DeliveryPlan {
    to_insert: Vec<(Uuid, Vec<u8>)>,
    outcome: SubmissionOutcome,
}

/// Pure complete-delivery evaluation against the locked `(device_id, user_id)` pairs from the database.
fn resolve_delivery(
    sender_device_id: Uuid,
    recipients: Vec<RecipientSubmissions>,
    locked_devices: Vec<(Uuid, Uuid)>,
) -> DeliveryPlan {
    let mut current_devices: HashMap<Uuid, BTreeSet<Uuid>> = HashMap::new();
    for (device_id, user_id) in locked_devices {
        if device_id != sender_device_id {
            current_devices.entry(user_id).or_default().insert(device_id);
        }
    }

    let mut invalid_device_ids = Vec::new();
    let mut device_mismatches = Vec::new();
    let mut to_insert = Vec::new();

    for recipient in recipients {
        let current = current_devices.remove(&recipient.user_id).unwrap_or_default();
        let mut targeted_valid = BTreeSet::new();
        let mut valid_subs = Vec::with_capacity(recipient.submissions.len());

        for sub in recipient.submissions {
            if current.contains(&sub.device_id) {
                targeted_valid.insert(sub.device_id);
                valid_subs.push((sub.device_id, sub.message));
            } else {
                invalid_device_ids.push(sub.device_id);
            }
        }

        let missing_device_ids: Vec<Uuid> = current.difference(&targeted_valid).copied().collect();
        if missing_device_ids.is_empty() {
            to_insert.extend(valid_subs);
        } else {
            device_mismatches.push(DeviceMismatch { user_id: recipient.user_id, missing_device_ids });
        }
    }

    DeliveryPlan { to_insert, outcome: SubmissionOutcome { invalid_device_ids, device_mismatches } }
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

    /// Processes an idempotent batch of recipient submissions.
    /// Evaluates device membership and complete delivery per target user, and bulk-inserts valid
    /// messages with the target users' device sets locked from the check to the commit.
    ///
    /// # Errors
    /// Returns `AppError::Database` if any database operation fails.
    #[tracing::instrument(
        err(level = "warn"),
        skip(self, recipients),
        fields(sender_user_id = %sender_user_id, sender_device_id = %sender_device_id, recipients = recipients.len())
    )]
    pub(crate) async fn send(
        &self,
        sender_user_id: Uuid,
        sender_device_id: Uuid,
        idempotency_key: Uuid,
        recipients: Vec<RecipientSubmissions>,
    ) -> Result<SubmissionOutcome> {
        let cache_key = format!("{sender_device_id}:{idempotency_key}");
        if let Ok(Some(cached)) = self.submission_cache.get(&cache_key).await
            && let Ok(outcome) = serde_json::from_slice::<SubmissionOutcome>(&cached)
        {
            tracing::info!(key = %idempotency_key, "Returning cached idempotency response");
            return Ok(outcome);
        }

        if recipients.is_empty() {
            let outcome = SubmissionOutcome { invalid_device_ids: Vec::new(), device_mismatches: Vec::new() };
            self.cache_outcome(&cache_key, &outcome).await;
            return Ok(outcome);
        }

        let recipient_user_ids: Vec<Uuid> = recipients.iter().map(|r| r.user_id).collect();

        let mut tx = self.pool.begin().await?;
        let locked_devices = self.repo.lock_device_sets(&mut tx, &recipient_user_ids).await?;
        let plan = resolve_delivery(sender_device_id, recipients, locked_devices);

        if plan.to_insert.is_empty() {
            tx.commit().await?;
        } else {
            let inserted = self
                .repo
                .create_batch(&mut tx, sender_user_id, sender_device_id, idempotency_key, plan.to_insert, self.ttl_days)
                .await?;
            tx.commit().await?;

            self.metrics.sent_total.add(inserted.len() as u64, &[KeyValue::new("status", "success")]);

            self.notifier.notify(&inserted, DeviceEvent::MessageReceived).await;
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
    use crate::api::schemas::messaging::parse_send_request;
    use crate::domain::message::DeviceSubmission;
    use crate::error::AppError;
    use crate::proto::obscura::v1 as proto;

    #[test]
    fn test_parse_send_request_rejects_structural_errors() {
        let sender_device = Uuid::new_v4();
        let user = Uuid::new_v4();
        let target_device = Uuid::new_v4();

        // Malformed user_id
        let err = parse_send_request(
            sender_device,
            10,
            proto::SendMessageRequest {
                recipients: vec![proto::send_message_request::Recipient { user_id: vec![1, 2], submissions: vec![] }],
            },
        )
        .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));

        // Self-send
        let err = parse_send_request(
            sender_device,
            10,
            proto::SendMessageRequest {
                recipients: vec![proto::send_message_request::Recipient {
                    user_id: user.as_bytes().to_vec(),
                    submissions: vec![proto::send_message_request::Submission {
                        device_id: sender_device.as_bytes().to_vec(),
                        message: vec![1],
                    }],
                }],
            },
        )
        .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));

        // Duplicate device_id
        let err = parse_send_request(
            sender_device,
            10,
            proto::SendMessageRequest {
                recipients: vec![proto::send_message_request::Recipient {
                    user_id: user.as_bytes().to_vec(),
                    submissions: vec![
                        proto::send_message_request::Submission {
                            device_id: target_device.as_bytes().to_vec(),
                            message: vec![1],
                        },
                        proto::send_message_request::Submission {
                            device_id: target_device.as_bytes().to_vec(),
                            message: vec![2],
                        },
                    ],
                }],
            },
        )
        .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
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

        let recipients = vec![
            RecipientSubmissions {
                user_id: bob,
                submissions: vec![DeviceSubmission { device_id: bob_d1, message: vec![1] }],
            },
            RecipientSubmissions {
                user_id: carol,
                submissions: vec![
                    DeviceSubmission { device_id: carol_d1, message: vec![2] },
                    DeviceSubmission { device_id: unknown_device, message: vec![3] },
                ],
            },
        ];
        let locked = vec![(bob_d1, bob), (bob_d2, bob), (carol_d1, carol)];

        let plan = resolve_delivery(sender_device, recipients, locked);

        assert_eq!(plan.to_insert, vec![(carol_d1, vec![2])]);
        assert_eq!(
            plan.outcome.device_mismatches,
            vec![DeviceMismatch { user_id: bob, missing_device_ids: vec![bob_d2] }]
        );
        assert_eq!(plan.outcome.invalid_device_ids, vec![unknown_device]);
    }
}
