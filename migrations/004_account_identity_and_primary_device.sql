-- Recipients still need the sender device id after the sender device is deleted.
ALTER TABLE messages DROP CONSTRAINT messages_sender_device_id_fkey;

ALTER TABLE users ADD COLUMN identity_key BYTEA;
ALTER TABLE devices ADD COLUMN registration_id INTEGER;
ALTER TABLE devices ADD COLUMN is_primary BOOLEAN NOT NULL DEFAULT FALSE;

-- Devices are created together with their keys, so a device without them cannot be used.
DELETE FROM devices d WHERE NOT EXISTS (SELECT 1 FROM identity_keys k WHERE k.device_id = d.id);

UPDATE devices d SET registration_id = k.registration_id FROM identity_keys k WHERE k.device_id = d.id;

UPDATE devices d SET is_primary = TRUE
FROM (
    SELECT DISTINCT ON (user_id) id FROM devices ORDER BY user_id, created_at ASC NULLS LAST, id ASC
) oldest
WHERE d.id = oldest.id;

UPDATE users u SET identity_key = k.identity_key
FROM devices d JOIN identity_keys k ON k.device_id = d.id
WHERE d.user_id = u.id AND d.is_primary;

-- Under the old model these were independent installations, not linked devices.
DELETE FROM devices d
USING users u, identity_keys k
WHERE d.user_id = u.id AND k.device_id = d.id AND NOT d.is_primary AND k.identity_key <> u.identity_key;

DROP TABLE identity_keys;

ALTER TABLE devices ALTER COLUMN registration_id SET NOT NULL;

CREATE UNIQUE INDEX idx_devices_one_primary_per_user ON devices(user_id) WHERE is_primary;

CREATE TABLE provisioning_codes (
    code_hash VARCHAR PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_provisioning_codes_device_id ON provisioning_codes(device_id);
