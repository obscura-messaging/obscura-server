# Architecture

Endpoint details are in [openapi.yaml](../openapi.yaml); WebSocket frame semantics are in the [transport contract](https://github.com/obscura-messaging/obscura-proto/blob/main/TRANSPORT.md).

## Message flow

```mermaid
sequenceDiagram
    participant A as Alice's device
    participant S as Server
    participant B as Bob's device

    A->>S: POST /v1/users, then POST /v1/devices with keys (device-scoped JWT)
    B->>S: same
    A->>S: GET /v1/users/{bob}: one bundle per device, consumes a one-time prekey each
    A->>A: X3DH, encrypt once per device
    A->>S: POST /v1/messages (protobuf, Idempotency-Key)
    S->>S: queue per recipient device, publish on Valkey
    S-->>B: EnvelopeBatch over /v1/gateway, if connected
    S-->>B: FCM wake-up after the push delay, unless B connected or acked first
    B->>S: AckMessage: server deletes the acked messages
```

## Components

| Component | Code | Role |
|---|---|---|
| REST API | `src/api` | Accounts, devices, keys, sending, attachments, backups, push tokens. `/openapi.yaml` serves the spec. |
| Gateway | `src/services/gateway` | One WebSocket per device, opened with a single-use ticket. Pumps queued messages in batches and batches acks into deletes. |
| Management | port 9090 | `/livez`; `/readyz` checks Postgres, the storage bucket and Valkey. |
| PostgreSQL | `migrations/` | Users, devices, keys, message queue, attachment and backup metadata, push tokens, refresh tokens. |
| Valkey/Redis | `src/adapters/redis` | Cross-node pub/sub (channel per device), push job queue, idempotency cache, WebSocket tickets. Nodes are otherwise stateless. |
| S3 | `src/adapters/storage` | Encrypted attachments (`attachments/`, expire after `--ttl-days`) and backups (`backups/{device}/v{n}`, versioned, no expiry). |
| FCM | `src/adapters/push` | Content-free wake-up (Android and APNs via FCM, collapse key `obscura_check`). Without FCM config, pushes are only logged. |

## Background workers

| Worker | Does |
|---|---|
| Message cleanup | Deletes expired messages, then the oldest beyond `--messaging-inbox-max-size` per device. |
| Attachment cleanup | Deletes expired attachments from S3 and Postgres. |
| Backup cleanup | Resets uploads stuck in `UPLOADING` past `--backup-stale-threshold-mins` and deletes their objects. |
| Refresh-token cleanup | Deletes expired refresh tokens. |
| Notification | Receives pub/sub events for local sockets; reclaims idle per-device channels. |
| Push notification | Leases due jobs from Valkey, sends them to FCM, deletes tokens FCM reports as invalid. |

A worker that exits outside shutdown stops the server.
