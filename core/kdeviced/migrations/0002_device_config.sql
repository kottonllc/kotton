-- kdeviced schema v2 (RFC-0063 stage 3a)
-- Device-wide key/value configuration: relay/TURN/STUN URLs, gateway flags,
-- peer listen port, device name. Moved here from the machine-wide agent.db —
-- device configuration is device authority, and this file is the device's.
--
-- IF NOT EXISTS because an unsupervised kuserd (dev/test boots where kdeviced
-- never ran) creates this table additively with the same DDL; this migration
-- must land cleanly on such a file.
CREATE TABLE IF NOT EXISTS device_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
