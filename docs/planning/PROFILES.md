# Profiles

**Status: not started.** No profile endpoint, avatar column or persistent attachment exists.

## Problem

Users want to share a display name and avatar without the server seeing either. Attachments expire after `--ttl-days`, so an avatar uploaded as one disappears.

## Intended approach

- Client encrypts the avatar with a random key and uploads it as an attachment.
- Display name, avatar attachment ID and avatar key form a client-encrypted profile, shared with contacts through the encrypted channel (a "profile key").
- `PUT /v1/profile` sets `users.avatar_id` (nullable, indexed FK to `attachments`). Attachment cleanup skips referenced attachments, so a replaced avatar simply expires.

## Open questions

- Persistence by reference (above) or an `is_persisted` flag on attachments? The old draft proposed both.
- Where the profile blob lives: an attachment, a backup-style versioned object, or a column.
- Attachment downloads are authenticated only by a random UUID; is that enough against scraping avatars?
