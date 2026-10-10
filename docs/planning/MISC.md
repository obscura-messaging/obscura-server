# Backlog

None of these has started.

- **Fuzzing**: `cargo-fuzz` targets for protobuf decoding and key/signature parsing.
- **Load testing**: peak WebSocket concurrency with k6 or similar; then performance regression checks in CI.
- **FCM end-to-end test**: worker tests use a fake provider; add a mock FCM HTTP server to cover payloads and error mapping through the real `FcmPushProvider`.
- **Config reload**: decide whether SIGHUP reload is worth it over restarting.
