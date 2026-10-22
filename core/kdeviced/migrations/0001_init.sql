-- kdeviced schema v1
-- Sudoers set: DIDs with device-owner authority.
CREATE TABLE IF NOT EXISTS sudoers (
    did       TEXT PRIMARY KEY,
    added_at  INTEGER NOT NULL,
    added_by  TEXT NOT NULL
);

-- Device-level key/value settings (e.g. device_name).
CREATE TABLE IF NOT EXISTS device_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
