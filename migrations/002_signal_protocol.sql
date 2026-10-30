CREATE TABLE signed_pre_keys (
    id INTEGER NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (device_id, id)
);

CREATE TABLE one_time_pre_keys (
    id INTEGER NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (device_id, id)
);
