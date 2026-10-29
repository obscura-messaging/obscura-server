# Architecture

Endpoint details are in [openapi.yaml](../openapi.yaml); WebSocket frame semantics are in the [transport contract](https://github.com/obscura-messaging/obscura-proto/blob/main/TRANSPORT.md).

## Message flow

```mermaid
sequenceDiagram
    participant A as Alice's device
    participant S as Server
    participant B as Bob's device

    A->>S: POST /v1/users (user-scoped JWT), then POST /v1/devices with keys (primary, device-scoped JWT)
    B->>S: same (additional devices link via /v1/link-sessions approved by the primary)
    A->>S: GET /v1/users/{bob} (or /devices/{id}): bundle(s) with shared account identity, consumes a one-time prekey
    A->>A: X3DH, encrypt once per device
    A->>S: POST /v1/messages (protobuf, recipient_user_ids + submissions, Idempotency-Key)
    S->>S: lock recipient device sets, enforce complete delivery, queue per device, publish on Valkey
    S-->>B: EnvelopeBatch over /v1/gateway, if connected
    S-->>B: FCM wake-up after the push delay, unless B connected or acked first
    B->>S: AckMessage: server deletes the acked messages
```

## Components

| Component | Code | Role |
|---|---|---|
| REST API | `src/api` | Accounts (`/v1/account/reset`), devices, link sessions (`/v1/link-sessions`), keys, sending, attachments, backups, push tokens. `/openapi.yaml` serves the spec. |
| Gateway | `src/services/gateway` | One WebSocket per device, opened with a single-use ticket. Pumps queued messages in batches and batches acks into deletes. |
| Management | port 9090 | `/livez`; `/readyz` checks Postgres, the storage bucket and Valkey. |
| PostgreSQL | `migrations/` | Users (with account identity), devices, link sessions, keys, message queue, attachment and backup metadata, push tokens, refresh tokens. |
| Valkey/Redis | `src/adapters/redis` | Cross-node pub/sub (channel per device/user), push job queue, idempotency cache, WebSocket tickets. Nodes are otherwise stateless. |
| S3 | `src/adapters/storage` | Encrypted attachments (`attachments/`, expire after `--ttl-days`) and backups (`backups/{device}/v{n}`, versioned, deleted when a device is deleted or the account is reset). |
| FCM | `src/adapters/push` | Content-free wake-up (Android and APNs via FCM, collapse key `obscura_check`). Without FCM config, pushes are only logged. |

## Background workers

| Worker | Does |
|---|---|
| Message cleanup | Deletes expired messages, then the oldest beyond `--messaging-inbox-max-size` per device. |
| Attachment cleanup | Deletes expired attachments from S3 and Postgres. |
| Backup cleanup | Resets uploads stuck in `UPLOADING` past `--backup-stale-threshold-mins` and deletes their objects. |
| Refresh-token cleanup | Deletes expired refresh tokens and expired link sessions. |
| Notification | Receives pub/sub events for local sockets and link-session waiters; reclaims idle channels. |
| Push notification | Leases due jobs from Valkey, sends them to FCM, deletes tokens FCM reports as invalid. |

A worker that exits outside shutdown stops the server.
