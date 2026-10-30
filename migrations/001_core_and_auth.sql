CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    username VARCHAR(50) NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9_]{3,50}$'),
    password_hash VARCHAR(255) NOT NULL,
    identity_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100),
    registration_id INTEGER NOT NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_devices_user_id ON devices(user_id);
CREATE UNIQUE INDEX idx_devices_one_primary_per_user ON devices(user_id) WHERE is_primary;

CREATE TABLE refresh_tokens (
    token_hash BYTEA NOT NULL PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_device_id ON refresh_tokens(device_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- A session is approved once the primary has stored its body.
CREATE TABLE link_sessions (
    id_hash BYTEA PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body BYTEA,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_link_sessions_user_id ON link_sessions(user_id);
CREATE INDEX idx_link_sessions_expires_at ON link_sessions(expires_at);
