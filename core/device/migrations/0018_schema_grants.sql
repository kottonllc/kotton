-- Schema grants and per-(app_id, nsid) write quotas  (RFC-0003)
--
-- Tracks explicit read/write/register permissions for installed apps accessing
-- schema NSIDs, plus runtime quota counters for write-limit enforcement.
--
-- Schema:
--   app_id        — reverse-domain app identifier (e.g. "sh.kotton.notes-app")
--   nsid          — schema NSID this grant covers (e.g. "sh.kotton.notes")
--   can_read      — 1 = may query records; 0 = denied
--   can_write     — 1 = may insert / delete records; 0 = denied
--   can_register  — 1 = may register / update this schema definition; 0 = denied
--   record_quota  — max live records allowed; 0 = unlimited (default 50 000)
--   byte_quota    — max total body bytes; 0 = unlimited (default 100 MiB = 104 857 600)
--   record_count  — live record count (daemon increments on insert, decrements on delete)
--   byte_count    — total body bytes (daemon increments on insert, decrements on delete)
--   granted_at    — Unix seconds when this row was last written

CREATE TABLE IF NOT EXISTS schema_grants (
    app_id        TEXT    NOT NULL,
    nsid          TEXT    NOT NULL,
    can_read      INTEGER NOT NULL DEFAULT 0,
    can_write     INTEGER NOT NULL DEFAULT 0,
    can_register  INTEGER NOT NULL DEFAULT 0,
    record_quota  INTEGER NOT NULL DEFAULT 50000,
    byte_quota    INTEGER NOT NULL DEFAULT 104857600,
    record_count  INTEGER NOT NULL DEFAULT 0,
    byte_count    INTEGER NOT NULL DEFAULT 0,
    granted_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (app_id, nsid)
);

CREATE INDEX IF NOT EXISTS idx_schema_grants_app  ON schema_grants (app_id);
CREATE INDEX IF NOT EXISTS idx_schema_grants_nsid ON schema_grants (nsid);
