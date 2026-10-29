# Obscura Server

Relay server for Obscura, an end-to-end encrypted messenger built on the Signal Protocol. It stores public keys and queues opaque encrypted messages and attachments; it never holds private keys or plaintext.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![CI](https://github.com/obscura-messaging/obscura-server/actions/workflows/ci.yml/badge.svg)](https://github.com/obscura-messaging/obscura-server/actions/workflows/ci.yml)

## Threat model

Content stays confidential even if the server is fully compromised.

- **Server sees:** usernames, user and device IDs, public keys, push tokens, IP addresses, and per-message metadata (sender user and device, recipient device, time, size). The account password reaches the server at login and is stored Argon2-hashed.
- **Server cannot see:** message or attachment plaintext; private keys.
- **Not addressed:** traffic analysis. There is no padding, mixing or sealed sender.

## Quick start

```bash
git clone --recurse-submodules https://github.com/obscura-messaging/obscura-server.git
cd obscura-server
docker compose up -d                                   # Postgres, Valkey, MinIO, Grafana LGTM, server
docker compose exec minio mkdir -p /data/test-bucket   # nothing else creates the bucket
curl http://localhost:9090/readyz                      # 503 until DB, bucket and Valkey are reachable
curl http://localhost:3000/openapi.yaml
```

Grafana is on `localhost:3001`.

## Development

Needs stable Rust, `protoc` and [`just`](https://github.com/casey/just). Runtime needs PostgreSQL 18+ (migrations use `uuidv7()`), Valkey or Redis, and S3-compatible storage. Migrations run on startup.

```bash
just services   # start db, minio, valkey and create test-bucket
OBSCURA_STORAGE_BUCKET=test-bucket OBSCURA_STORAGE_ENDPOINT=http://localhost:9000 \
OBSCURA_STORAGE_ACCESS_KEY=minioadmin OBSCURA_STORAGE_SECRET_KEY=minioadmin \
OBSCURA_STORAGE_FORCE_PATH_STYLE=true cargo run
just test       # integration tests need `just services` running
just ci         # fmt-check, clippy, coverage (fails under 80% lines)
just            # list all recipes
```

The database and Valkey defaults already match `just services`.

## Docs

- [openapi.yaml](./openapi.yaml): REST and gateway API
- [docs/CONFIGURATION.md](./docs/CONFIGURATION.md): every flag and environment variable
- [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md): components and message flow
- [docs/RELEASING.md](./docs/RELEASING.md): release process
- [docs/planning/](./docs/planning/): unbuilt features
- [obscura-proto](https://github.com/obscura-messaging/obscura-proto): wire schema and transport contract

# License

Copyright (c) 2026 Nolan Cooper

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
