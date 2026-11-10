-- Pre-keys are stored as Signal's server stores them: each device has exactly one signed pre-key and one
-- last-resort Kyber pre-key, replaced on upload, and a pool of one-time EC and Kyber pre-keys, replaced
-- wholesale on upload and consumed one per bundle.

CREATE TABLE signed_pre_keys (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    id INTEGER NOT NULL,
    public_key BYTEA NOT NULL,
    signature BYTEA NOT NULL
);

CREATE TABLE kyber_last_resort_pre_keys (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    id INTEGER NOT NULL,
    public_key BYTEA NOT NULL,
    signature BYTEA NOT NULL
);

CREATE TABLE one_time_pre_keys (
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    id INTEGER NOT NULL,
    public_key BYTEA NOT NULL,
    PRIMARY KEY (device_id, id)
);

CREATE TABLE kyber_pre_keys (
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    id INTEGER NOT NULL,
    public_key BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    PRIMARY KEY (device_id, id)
);
