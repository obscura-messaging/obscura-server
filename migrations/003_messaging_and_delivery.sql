CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- No foreign key: recipients still need the sender device id after the sender device is deleted.
    sender_device_id UUID NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    submission_id UUID NOT NULL,
    content BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    -- Deduplication constraint: A sending device cannot send the same submission_id twice.
    UNIQUE (sender_device_id, submission_id)
);

CREATE INDEX idx_messages_fetch ON messages(device_id, created_at);
CREATE INDEX idx_messages_expires_at ON messages(expires_at);

CREATE TABLE attachments (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_attachments_expires_at ON attachments(expires_at);

CREATE TABLE push_tokens (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_push_tokens_updated_at ON push_tokens(updated_at);
CREATE INDEX idx_push_tokens_token ON push_tokens(token);

CREATE TABLE backups (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    current_version INT NOT NULL DEFAULT 0,
    pending_version INT,
    state VARCHAR NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'PENDING', 'FAILED'
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    pending_at TIMESTAMPTZ
);

CREATE INDEX idx_backups_state_pending_at ON backups(state, pending_at);
