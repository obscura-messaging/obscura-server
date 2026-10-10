# Sealed sender

**Status: not started.** Today every `Envelope` carries a server-stamped `sender_id` and `sender_device_id` taken from the sender's device-scoped JWT, so the server knows who messages whom. There is no server-side blocking.

## Goal

Hide the sender from the server while still limiting abuse, following Signal's unidentified delivery.

## Intended approach

1. **Sender certificates.** `GET /v1/certificate` returns a short-lived certificate (user ID, device ID, expiry) signed with a server Ed25519 key.
2. **Sealed envelope.** The client encrypts its certificate and identity to the recipient's identity key. The server routes on the destination device only and accepts the message without a sender JWT.
3. **Delivery tokens.** A recipient may require a token: it uploads a hash of a random token and shares the token with contacts. The server rejects sealed messages without a matching token. Blocking someone means rotating the token and sending it to everyone except them.

## Open questions

- How unauthenticated sends are rate limited, since the server can no longer key limits on the sender.
- Default mode for new accounts: open to any certificate holder, or token required.
- Wire changes: `Envelope.sender_id`/`sender_device_id` become optional and `SendMessageRequest` needs a sealed variant, a coordinated change in obscura-proto.
- What `Idempotency-Key` caching and push wake-ups reveal once the sender is hidden.
