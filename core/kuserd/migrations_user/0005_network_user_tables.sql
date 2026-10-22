-- Per-user agent database, schema v5 (RFC-0063 stage 3b-v): the network user
-- tables — the last user-scoped domain out of the machine-wide agent.db.
-- All four carried a user_id column all along; only the file was shared.
--
-- The node_id columns no longer carry a REFERENCES clause: paired_nodes stays
-- in the machine-wide database until stage 4 turns the allowlist into live
-- per-daemon contributions, so the FK would point across files. The legacy
-- constraint was belt-and-suspenders (the daemon validates node ids on every
-- write); it returns when paired_nodes moves.

CREATE TABLE IF NOT EXISTS sync_rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       TEXT    NOT NULL,
    node_id       TEXT    NOT NULL,
    path          TEXT    NOT NULL,
    watch         INTEGER NOT NULL DEFAULT 0,
    configured_at INTEGER NOT NULL,
    UNIQUE (user_id, node_id, path)
);
CREATE INDEX IF NOT EXISTS idx_sync_rules_user ON sync_rules (user_id);

CREATE TABLE IF NOT EXISTS mount_configs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id            TEXT    NOT NULL,
    node_id            TEXT    NOT NULL,
    remote_path        TEXT    NOT NULL,
    local_path         TEXT    NOT NULL,
    cache_budget_bytes INTEGER,
    pins               TEXT    NOT NULL DEFAULT '[]',
    mounted_at         INTEGER NOT NULL,
    UNIQUE (user_id, local_path)
);
CREATE INDEX IF NOT EXISTS idx_mount_configs_user ON mount_configs (user_id);

CREATE TABLE IF NOT EXISTS ephemeral_sessions (
    id           TEXT    PRIMARY KEY,
    user_id      TEXT    NOT NULL,
    guest_did    TEXT    NOT NULL,
    guest_pubkey BLOB    NOT NULL,
    grant_json   TEXT    NOT NULL,
    issued_at    INTEGER NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user      ON ephemeral_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_guest_did ON ephemeral_sessions (guest_did);

CREATE TABLE IF NOT EXISTS web_shell_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    token_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    UNIQUE(user_id, name)
);
