-- Per-user agent database, schema v6 (RFC-0063 events split).
--
-- The event log is the user's activity record, chained under a key derived
-- from *their* master secret — the machine-wide log signed by one user's key
-- was wrong in both directions (the ordering note's finding). Consolidated
-- final shape of legacy 0001 + 0008 (iso_timestamp) + 0009 (hmac).
--
-- The chain starts fresh here: legacy rows were unsigned sentinels (the
-- arming constructor was never called in production), and they stay readable
-- in the machine file until stage 3c retires it. Supervisor lifecycle events
-- (spawn, stop, sudoers) are kdeviced's and land in device.db.

CREATE TABLE IF NOT EXISTS events (
    id            TEXT    PRIMARY KEY,
    category      TEXT    NOT NULL,
    level         TEXT    NOT NULL,
    message       TEXT    NOT NULL,
    payload       TEXT,
    timestamp     INTEGER NOT NULL,  -- Unix seconds
    iso_timestamp TEXT,
    -- HMAC-SHA256(key, prev_hmac || id || payload); X'' sentinel when unarmed.
    hmac          BLOB    NOT NULL DEFAULT X''
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_category  ON events (category);
CREATE INDEX IF NOT EXISTS idx_events_level     ON events (level);
