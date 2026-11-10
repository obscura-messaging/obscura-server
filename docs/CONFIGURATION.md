# Configuration

Every option is a flag or an environment variable; flags win. `cargo run -- --help` prints the same list. A test (`test_docs_up_to_date` in `src/config.rs`) fails if this table drifts from the code, so keep the row format.

For production, set at least the JWT secret and the database, Valkey and storage options. Storage credentials fall back to the AWS SDK's default chain when unset.

Startup fails on a configuration that cannot work: a value below 1 for an option marked "At least 1.", a sampling ratio outside 0.0 to 1.0, an attachment minimum above the maximum, or only one of the two FCM values. Unmarked numeric options accept 0, for example to send pushes with no delay or keep no idle connections open. The marks are checked against the code by `test_docs_up_to_date`.

| Flag | Environment variable | Default | Description |
|---|---|---|---|
| **General** | | | |
| `--ttl-days` | `OBSCURA_TTL_DAYS` | `30` | Lifetime of queued messages and attachments, in days. At least 1. |
| **Server** | | | |
| `--server-host` | `OBSCURA_SERVER_HOST` | `0.0.0.0` | Bind address for both ports. |
| `--server-port` | `OBSCURA_SERVER_PORT` | `3000` | API and WebSocket port. |
| `--server-mgmt-port` | `OBSCURA_SERVER_MGMT_PORT` | `9090` | `/livez` and `/readyz`. |
| `--server-shutdown-timeout-secs` | `OBSCURA_SERVER_SHUTDOWN_TIMEOUT_SECS` | `5` | Wait for background tasks on shutdown. |
| `--server-request-timeout-secs` | `OBSCURA_SERVER_REQUEST_TIMEOUT_SECS` | `30` | Timeout for non-upload API requests (returns 408). At least 1. |
| `--server-global-timeout-secs` | `OBSCURA_SERVER_GLOBAL_TIMEOUT_SECS` | `600` | Outer timeout for every request. At least 1. |
| `--trusted-proxies` | `OBSCURA_SERVER_TRUSTED_PROXIES` | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1/32` | CIDRs whose `X-Forwarded-For` is honoured. The client IP (for rate limits) is the rightmost untrusted address. |
| **PostgreSQL** | | | |
| `--db-url` | `OBSCURA_DATABASE_URL` | `postgres://user:password@localhost/signal_server` | Connection string. Requires PostgreSQL 18+. |
| `--db-max-connections` | `OBSCURA_DATABASE_MAX_CONNECTIONS` | `20` | Pool maximum. At least 1. |
| `--db-min-connections` | `OBSCURA_DATABASE_MIN_CONNECTIONS` | `5` | Idle connections kept open. |
| `--db-acquire-timeout-secs` | `OBSCURA_DATABASE_ACQUIRE_TIMEOUT_SECS` | `3` | Wait for a pooled connection. At least 1. |
| `--db-idle-timeout-secs` | `OBSCURA_DATABASE_IDLE_TIMEOUT_SECS` | `600` | Close idle connections after this. |
| `--db-max-lifetime-secs` | `OBSCURA_DATABASE_MAX_LIFETIME_SECS` | `1800` | Replace connections after this. |
| **Valkey / Redis** | | | |
| `--pubsub-url` | `OBSCURA_PUBSUB_URL` | `redis://localhost:6379` | Pub/sub, push queue, idempotency and ticket cache. |
| `--pubsub-min-backoff-secs` | `OBSCURA_PUBSUB_MIN_BACKOFF_SECS` | `1` | Initial reconnect backoff. |
| `--pubsub-max-backoff-secs` | `OBSCURA_PUBSUB_MAX_BACKOFF_SECS` | `30` | Maximum reconnect backoff. |
| `--pubsub-stable-after-secs` | `OBSCURA_PUBSUB_STABLE_AFTER_SECS` | `30` | Subscription uptime after which backoff resets. |
| **Auth** | | | |
| `--auth-jwt-secret` | `OBSCURA_AUTH_JWT_SECRET` | `change_me_in_production` | JWT signing secret. Change it. |
| `--auth-token-ttl-secs` | `OBSCURA_AUTH_TOKEN_TTL_SECS` | `900` | Access token lifetime. At least 1. |
| `--auth-refresh-token-ttl-days` | `OBSCURA_AUTH_REFRESH_TOKEN_TTL_DAYS` | `30` | Refresh token lifetime. At least 1. |
| `--auth-refresh-token-cleanup-interval-secs` | `OBSCURA_AUTH_REFRESH_TOKEN_CLEANUP_INTERVAL_SECS` | `86400` | Expired refresh token sweep. At least 1. |
| `--auth-max-devices-per-user` | `OBSCURA_AUTH_MAX_DEVICES_PER_USER` | `10` | Devices per user. At least 1. |
| **Rate limits** (per client IP; attachment routes are not limited) | | | |
| `--rate-limit-per-second` | `OBSCURA_RATE_LIMIT_PER_SECOND` | `10` | Standard API routes. At least 1. |
| `--rate-limit-burst` | `OBSCURA_RATE_LIMIT_BURST` | `20` | Standard API burst. At least 1. |
| `--auth-rate-limit-per-second` | `OBSCURA_RATE_LIMIT_AUTH_PER_SECOND` | `1` | `/v1/users*`, `/v1/session*`, and `POST /v1/link-sessions`. At least 1. |
| `--auth-rate-limit-burst` | `OBSCURA_RATE_LIMIT_AUTH_BURST` | `3` | Auth burst. At least 1. |
| **Messaging and keys** | | | |
| `--messaging-inbox-max-size` | `OBSCURA_MESSAGING_INBOX_MAX_SIZE` | `1000` | Queued messages per device; the cleanup worker deletes the oldest beyond this. At least 1. |
| `--messaging-cleanup-interval-secs` | `OBSCURA_MESSAGING_CLEANUP_INTERVAL_SECS` | `300` | Expiry and inbox-limit sweep. At least 1. |
| `--messaging-send-batch-limit` | `OBSCURA_MESSAGING_SEND_BATCH_LIMIT` | `100` | Submissions per `POST /v1/messages`; more returns 413. At least 1. |
| `--messaging-idempotency-ttl-secs` | `OBSCURA_MESSAGING_IDEMPOTENCY_TTL_SECS` | `86400` | How long a send response is replayed for the same `Idempotency-Key`. At least 1. |
| `--messaging-pre-key-refill-threshold` | `OBSCURA_PRE_KEY_REFILL_THRESHOLD` | `20` | Below this many one-time EC or Kyber prekeys, the device gets a `PreKeyStatus` frame and a push. |
| `--messaging-pre-keys-max` | `OBSCURA_PRE_KEYS_MAX` | `100` | Most one-time prekeys of each kind (EC and Kyber) per upload. An upload replaces the device's stored keys of that kind, so this is also the most a device holds. At least 1. |
| **Notifications** | | | |
| `--notifications-cleanup-interval-secs` | `OBSCURA_NOTIFICATIONS_CLEANUP_INTERVAL_SECS` | `60` | Reclaim per-device channels with no listener. At least 1. |
| `--notifications-global-channel-capacity` | `OBSCURA_NOTIFICATIONS_GLOBAL_CHANNEL_CAPACITY` | `1024` | Pub/sub dispatcher buffer. At least 1. |
| `--notifications-device-channel-capacity` | `OBSCURA_NOTIFICATIONS_DEVICE_CHANNEL_CAPACITY` | `64` | Per-device event buffer. At least 1. |
| `--notifications-push-delay-secs` | `OBSCURA_NOTIFICATIONS_PUSH_DELAY_SECS` | `2` | Push is sent after this unless the device connects or acks first. |
| `--notifications-worker-interval-secs` | `OBSCURA_NOTIFICATIONS_WORKER_INTERVAL_SECS` | `1` | Push queue poll interval. At least 1. |
| `--notifications-worker-concurrency` | `OBSCURA_NOTIFICATIONS_WORKER_CONCURRENCY` | `100` | Concurrent pushes; also jobs leased per poll. At least 1. |
| `--notifications-push-queue-key` | `OBSCURA_NOTIFICATIONS_PUSH_QUEUE_KEY` | `jobs:push_notifications` | Push queue key. |
| `--notifications-channel-prefix` | `OBSCURA_NOTIFICATIONS_CHANNEL_PREFIX` | `device:` | Pub/sub channel prefix (suffix is the device ID). |
| `--notifications-visibility-timeout-secs` | `OBSCURA_NOTIFICATIONS_VISIBILITY_TIMEOUT_SECS` | `30` | Push job lease. At least 1. |
| `--notifications-invalid-token-cleanup-interval-secs` | `OBSCURA_NOTIFICATIONS_INVALID_TOKEN_CLEANUP_INTERVAL_SECS` | `5` | Flush tokens FCM rejected. At least 1. |
| `--notifications-invalid-token-cleanup-batch-size` | `OBSCURA_NOTIFICATIONS_INVALID_TOKEN_CLEANUP_BATCH_SIZE` | `50` | Tokens deleted per batch. At least 1. |
| `--notifications-invalid-token-cleanup-channel-capacity` | `OBSCURA_NOTIFICATIONS_INVALID_TOKEN_CLEANUP_CHANNEL_CAPACITY` | `256` | Pending invalid-token buffer. At least 1. |
| **Attachments** | | | |
| `--attachment-prefix` | `OBSCURA_ATTACHMENT_PREFIX` | `attachments/` | S3 key prefix. |
| `--attachment-max-size-bytes` | `OBSCURA_ATTACHMENT_MAX_SIZE_BYTES` | `52428800` | 50 MiB. |
| `--attachment-min-size-bytes` | `OBSCURA_ATTACHMENT_MIN_SIZE_BYTES` | `1` | Minimum size. Must not exceed the maximum, or startup fails. |
| `--attachment-timeout-secs` | `OBSCURA_ATTACHMENT_TIMEOUT_SECS` | `120` | Upload/download request timeout. At least 1. |
| `--attachment-cleanup-interval-secs` | `OBSCURA_ATTACHMENT_CLEANUP_INTERVAL_SECS` | `3600` | Expired attachment sweep. At least 1. |
| `--attachment-cleanup-batch-size` | `OBSCURA_ATTACHMENT_CLEANUP_BATCH_SIZE` | `100` | Attachments deleted per batch. At least 1. |
| **S3 storage** | | | |
| `--storage-bucket` | `OBSCURA_STORAGE_BUCKET` | `obscura-storage` | Bucket; must already exist. |
| `--storage-region` | `OBSCURA_STORAGE_REGION` | `us-east-1` | Region. |
| `--storage-endpoint` | `OBSCURA_STORAGE_ENDPOINT` | None | Custom endpoint, e.g. MinIO. |
| `--storage-access-key` | `OBSCURA_STORAGE_ACCESS_KEY` | None | Access key ID. |
| `--storage-secret-key` | `OBSCURA_STORAGE_SECRET_KEY` | None | Secret key. |
| `--storage-force-path-style` | `OBSCURA_STORAGE_FORCE_PATH_STYLE` | `false` | Path-style URLs; needed for most MinIO setups. |
| **WebSocket gateway** | | | |
| `--ws-outbound-buffer-size` | `OBSCURA_WS_OUTBOUND_BUFFER_SIZE` | `32` | Outbound frame buffer per socket. At least 1. |
| `--ws-ack-buffer-size` | `OBSCURA_WS_ACK_BUFFER_SIZE` | `1000` | Pending acks per socket; acks beyond this are dropped and the messages redelivered later. At least 1. |
| `--ws-ack-batch-size` | `OBSCURA_WS_ACK_BATCH_SIZE` | `100` | Acks per delete. At least 1. |
| `--ws-ack-flush-interval-ms` | `OBSCURA_WS_ACK_FLUSH_INTERVAL_MS` | `500` | Max delay before acked messages are deleted. |
| `--ws-prekey-debounce-interval-ms` | `OBSCURA_WS_PREKEY_DEBOUNCE_INTERVAL_MS` | `500` | Debounce for `PreKeyStatus` frames. |
| `--ws-ping-interval-secs` | `OBSCURA_WS_PING_INTERVAL_SECS` | `30` | Ping interval; `0` means 1 s. At least 1. |
| `--ws-ping-timeout-secs` | `OBSCURA_WS_PING_TIMEOUT_SECS` | `10` | Close if nothing is received for ping interval plus this. |
| `--ws-message-fetch-batch-size` | `OBSCURA_WS_MESSAGE_FETCH_BATCH_SIZE` | `50` | Messages per query and per `EnvelopeBatch`. At least 1. |
| `--ws-max-batch-bytes` | `OBSCURA_WS_MAX_BATCH_BYTES` | `8388608` | Split batches above 8 MiB, below common client frame limits (tungstenite: 16 MiB). |
| `--ws-fetch-retry-budget-ms` | `OBSCURA_WS_FETCH_RETRY_BUDGET_MS` | `10000` | How long a failed queue read is retried. |
| `--ws-ticket-ttl-secs` | `OBSCURA_WS_TICKET_TTL_SECS` | `30` | Single-use gateway ticket lifetime. At least 1. |
| **Health** | | | |
| `--health-db-timeout-ms` | `OBSCURA_HEALTH_DB_TIMEOUT_MS` | `2000` | `/readyz` database check. At least 1. |
| `--health-storage-timeout-ms` | `OBSCURA_HEALTH_STORAGE_TIMEOUT_MS` | `2000` | `/readyz` bucket check. At least 1. |
| `--health-pubsub-timeout-ms` | `OBSCURA_HEALTH_PUBSUB_TIMEOUT_MS` | `2000` | `/readyz` Valkey check. At least 1. |
| **Push (FCM)**: set both of the first two, or neither to only log pushes. Setting one alone fails startup. | | | |
| `--fcm-project-id` | `OBSCURA_FCM_PROJECT_ID` | None | Google Cloud project ID. |
| `--fcm-credentials-file` | `OBSCURA_FCM_CREDENTIALS_FILE` | None | Service account JSON path. |
| `--fcm-ttl-secs` | `OBSCURA_FCM_TTL_SECS` | `604800` | Push TTL (7 days). |
| **Telemetry** | | | |
| `--telemetry-otlp-endpoint` | `OBSCURA_TELEMETRY_OTLP_ENDPOINT` | None | OTLP gRPC endpoint for traces, metrics and logs; unset means stdout logs only. |
| `--telemetry-log-format` | `OBSCURA_TELEMETRY_LOG_FORMAT` | `text` | `text` or `json`. Filter with `RUST_LOG`. |
| `--telemetry-trace-sampling-ratio` | `OBSCURA_TELEMETRY_TRACE_SAMPLING_RATIO` | `1` | Share of traces kept, from 0.0 to 1.0. A percentage such as `10` is rejected. |
| `--telemetry-metrics-export-interval-secs` | `OBSCURA_TELEMETRY_METRICS_EXPORT_INTERVAL_SECS` | `60` | Metric export interval. At least 1. |
| `--telemetry-export-timeout-secs` | `OBSCURA_TELEMETRY_EXPORT_TIMEOUT_SECS` | `10` | OTLP export timeout. At least 1. |
