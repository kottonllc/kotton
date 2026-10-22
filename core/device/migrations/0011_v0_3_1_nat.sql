-- v0.3.1 NAT traversal — device configuration key-value store
--
-- Stores per-device settings that can be updated at runtime via IPC without
-- requiring a daemon restart. Current keys (all optional):
--
--   coord_url   — URL of the kotton-coord peer-address exchange server
--   turn_url    — URL of the TURN relay server (RFC 5766)
--
-- Additional keys may be added in future migrations; old rows are never
-- removed automatically (DELETE is safe from application code).

CREATE TABLE IF NOT EXISTS device_config (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);
