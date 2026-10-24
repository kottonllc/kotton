-- A paired node's row is the person's, keyed by the person and the node's DID
-- (kotton #99). Until now `id`, the label a node was paired under, was the
-- primary key across every person on the machine and `device_did` was unique
-- across them too, and every writer is `INSERT OR REPLACE`: so a label or a DID
-- written for one person replaced whichever row held it, another person's
-- included, and that person's drive then named a node that was not theirs. A
-- label is a name the person reads, and it may come from elsewhere (the name a
-- device announces at a join, a drive's label handed at one), so it is kept
-- beside the key, as text to show, and keys nothing. One person may hold two
-- rows under one label; a verb that names a node by label says which one it
-- means (`kotton_peer::daemon::db::paired_node_named`).
--
-- SQLite changes a primary key by rebuilding the table. The machine
-- database's own `sync_rules` and `mount_configs`, created beside
-- `paired_nodes` in 0002 and carried over to each person's database since,
-- still reference `paired_nodes(id)`; a reference to a column that keys
-- nothing is one SQLite refuses every write through, and dropping the parent
-- under it would cascade into them. So they are rebuilt first, without the
-- reference, as the person's database already holds them
-- (`kuserd/migrations_user/0005_network_user_tables.sql`), every row kept.

CREATE TABLE sync_rules_0027 (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       TEXT    NOT NULL,
    node_id       TEXT    NOT NULL,
    path          TEXT    NOT NULL,
    watch         INTEGER NOT NULL DEFAULT 0,
    configured_at INTEGER NOT NULL,
    UNIQUE (user_id, node_id, path)
);
INSERT INTO sync_rules_0027 (id, user_id, node_id, path, watch, configured_at)
    SELECT id, user_id, node_id, path, watch, configured_at FROM sync_rules;
DROP TABLE sync_rules;
ALTER TABLE sync_rules_0027 RENAME TO sync_rules;
CREATE INDEX IF NOT EXISTS idx_sync_rules_user ON sync_rules (user_id);

CREATE TABLE mount_configs_0027 (
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
INSERT INTO mount_configs_0027
    (id, user_id, node_id, remote_path, local_path, cache_budget_bytes, pins, mounted_at)
    SELECT id, user_id, node_id, remote_path, local_path, cache_budget_bytes, pins, mounted_at
    FROM mount_configs;
DROP TABLE mount_configs;
ALTER TABLE mount_configs_0027 RENAME TO mount_configs;
CREATE INDEX IF NOT EXISTS idx_mount_configs_user ON mount_configs (user_id);

-- The rows, re-keyed. Every row carries over: `device_did` was unique across
-- the machine, so no two rows share the new key.
CREATE TABLE paired_nodes_0027 (
    user_id     TEXT    NOT NULL,
    device_did  TEXT    NOT NULL,        -- did:key:... of the paired device
    id          TEXT    NOT NULL,        -- the label it is shown under; keys nothing
    public_key  BLOB    NOT NULL,        -- raw Ed25519 pubkey, 32 bytes
    addresses   TEXT    NOT NULL,        -- JSON-encoded Vec<SocketAddr>
    paired_at   INTEGER NOT NULL,        -- Unix timestamp (seconds)
    posture     TEXT,
    relay_url   TEXT,
    PRIMARY KEY (user_id, device_did)
);
INSERT INTO paired_nodes_0027
    (user_id, device_did, id, public_key, addresses, paired_at, posture, relay_url)
    SELECT user_id, device_did, id, public_key, addresses, paired_at, posture, relay_url
    FROM paired_nodes;
DROP TABLE paired_nodes;
ALTER TABLE paired_nodes_0027 RENAME TO paired_nodes;
CREATE INDEX IF NOT EXISTS idx_paired_nodes_user ON paired_nodes (user_id);
-- The handshake's lookups, which name a key and no person.
CREATE INDEX IF NOT EXISTS idx_paired_nodes_key ON paired_nodes (public_key);
