-- kdeviced schema v3 (RFC-0063 events split)
-- The supervisor's own lifecycle log: user daemons spawned and stopped,
-- sudoers changes, restarts. Device authority's record lives with device
-- authority — the per-user event logs hold each user's activity, and neither
-- writes into the other's file. Unsigned: the HMAC chain key is derived from
-- a user's master secret, which this process must never hold.
CREATE TABLE IF NOT EXISTS device_events (
    id        TEXT    PRIMARY KEY,
    category  TEXT    NOT NULL,   -- 'lifecycle' | 'sudoers' | 'daemon'
    message   TEXT    NOT NULL,
    payload   TEXT,
    timestamp INTEGER NOT NULL    -- Unix seconds
);
CREATE INDEX IF NOT EXISTS idx_device_events_ts ON device_events (timestamp);
