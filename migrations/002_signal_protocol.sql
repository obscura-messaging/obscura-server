CREATE TABLE signed_pre_keys (
    id INTEGER NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, id)
);

CREATE TABLE one_time_pre_keys (
    id INTEGER NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, id)
);

-- PQXDH: one-time Kyber pre-keys, consumed one per bundle like one_time_pre_keys.
CREATE TABLE kyber_pre_keys (
    id INTEGER NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, id)
);

-- PQXDH: each device's last-resort Kyber pre-key, served whenever its one-time pool is empty.
CREATE TABLE kyber_last_resort_pre_keys (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    id INTEGER NOT NULL,
    public_key BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
