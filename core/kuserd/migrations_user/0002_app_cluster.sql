-- Per-user agent database, schema v2 (RFC-0063 stage 3b-ii): the app cluster.
--
-- Four tables move out of the machine-wide system/agent.db. None of them ever
-- carried a user column — they were machine-wide by accident of the process
-- they were written in — so in this database they are per-user by
-- construction. The DDL is each legacy table's final shape (base migration
-- plus its ALTERs, consolidated), column order preserved so the drain's
-- INSERT ... SELECT is a plain copy.

-- Installed WASM apps (legacy 0006 + 0007 wasm_hash + 0016 bundle_path/dev).
CREATE TABLE IF NOT EXISTS app_registry (
    app_id        TEXT NOT NULL PRIMARY KEY,
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    -- JSON-encoded array of capability strings, e.g. ["schema.read:sh.kotton.notes"]
    capabilities  TEXT NOT NULL DEFAULT '[]',
    -- Absolute filesystem path to the compiled .wasm file
    wasm_path     TEXT NOT NULL,
    -- ISO 8601 installation timestamp
    installed_at  TEXT NOT NULL,
    -- SHA-256 hex of the embedded WASM bytes at install time; compared at boot
    -- so a rebuilt bundle reinstalls without wiping the data directory.
    wasm_hash     TEXT NOT NULL DEFAULT '',
    -- Absolute path to a pre-built web bundle directory; NULL for WASM-only.
    bundle_path   TEXT,
    -- 1 = registered with `app dev` (live build dir); not exportable.
    dev           INTEGER NOT NULL DEFAULT 0
);

-- Which app handles which schema NSID (legacy 0005).
CREATE TABLE IF NOT EXISTS handler_registry (
    app_id        TEXT    NOT NULL,
    nsid          TEXT    NOT NULL,
    is_default    INTEGER NOT NULL DEFAULT 0,
    registered_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (app_id, nsid)
);
CREATE INDEX IF NOT EXISTS idx_handler_registry_nsid      ON handler_registry (nsid);
CREATE INDEX IF NOT EXISTS idx_handler_registry_nsid_dflt ON handler_registry (nsid, is_default);

-- Named system roles -> installed app ids (legacy 0017). "Which app is the
-- shell" is now each user's answer, which is what a per-person shell means.
CREATE TABLE IF NOT EXISTS app_roles (
    role    TEXT NOT NULL PRIMARY KEY,
    app_id  TEXT NOT NULL
);

-- Schema grants and per-(app_id, nsid) write quotas (legacy 0018, RFC-0003).
-- Quota counters are finally an honest number: one user's records, counted in
-- that user's database.
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
