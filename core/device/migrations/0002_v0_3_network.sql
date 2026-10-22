-- v0.3 network layer tables
-- Adds persistence for: paired nodes, sync rules, lazy mount configs,
-- and ephemeral session tickets.

-- ---------------------------------------------------------------------------
-- Paired nodes (trusted device tier)
-- ---------------------------------------------------------------------------
-- Each row represents a device whose Ed25519 identity key has been allowlisted
-- through the pairing ceremony. The `public_key` blob is the raw 32-byte
-- Ed25519 key; it is also embedded in `device_did` but stored separately for
-- fast allowlist lookups without DID parsing.

CREATE TABLE IF NOT EXISTS paired_nodes (
    id          TEXT    PRIMARY KEY,     -- human label chosen at pairing time, e.g. "my-vps"
    user_id     TEXT    NOT NULL,
    device_did  TEXT    NOT NULL UNIQUE, -- did:key:... of the paired device
    public_key  BLOB    NOT NULL,        -- raw Ed25519 pubkey, 32 bytes
    addresses   TEXT    NOT NULL,        -- JSON-encoded Vec<SocketAddr>, updated on each connect
    paired_at   INTEGER NOT NULL         -- Unix timestamp (seconds)
);

CREATE INDEX IF NOT EXISTS idx_paired_nodes_user ON paired_nodes (user_id);

-- ---------------------------------------------------------------------------
-- Background sync rules
-- ---------------------------------------------------------------------------
-- Each row configures continuous or on-demand sync between a local path and
-- a paired node. When `watch = 1` the daemon uses filesystem notifications to
-- sync on change; when `watch = 0` sync only runs on explicit request.

CREATE TABLE IF NOT EXISTS sync_rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       TEXT    NOT NULL,
    node_id       TEXT    NOT NULL REFERENCES paired_nodes(id) ON DELETE CASCADE,
    path          TEXT    NOT NULL,      -- local path prefix, e.g. "/notes"
    watch         INTEGER NOT NULL DEFAULT 0,  -- boolean (0 = off, 1 = on)
    configured_at INTEGER NOT NULL,      -- Unix timestamp (seconds)
    UNIQUE (user_id, node_id, path)
);

CREATE INDEX IF NOT EXISTS idx_sync_rules_user ON sync_rules (user_id);

-- ---------------------------------------------------------------------------
-- Lazy mount configurations
-- ---------------------------------------------------------------------------
-- A mount maps a local VFS path to a remote node's storage tree.
-- It is NOT an OS-level mount — it is internal to the Lettuce daemon VFS.
-- `cache_budget_bytes` is NULL when the device-level default applies.
-- `pins` is a JSON-encoded Vec<String> of subpaths to keep pinned (pre-fetched,
-- never evicted from the local cache).

CREATE TABLE IF NOT EXISTS mount_configs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id            TEXT    NOT NULL,
    node_id            TEXT    NOT NULL REFERENCES paired_nodes(id) ON DELETE CASCADE,
    remote_path        TEXT    NOT NULL, -- path exported by the remote node
    local_path         TEXT    NOT NULL, -- local VFS path at which the tree appears
    cache_budget_bytes INTEGER,          -- NULL = use device default
    pins               TEXT    NOT NULL DEFAULT '[]',  -- JSON Vec<String>
    mounted_at         INTEGER NOT NULL, -- Unix timestamp (seconds)
    UNIQUE (user_id, local_path)
);

CREATE INDEX IF NOT EXISTS idx_mount_configs_user ON mount_configs (user_id);

-- ---------------------------------------------------------------------------
-- Ephemeral session tickets
-- ---------------------------------------------------------------------------
-- A session grants a guest device time-limited, path-scoped access without
-- a full pairing ceremony. The guest_pubkey is the raw 32-byte Ed25519 key;
-- guest_did is the corresponding did:key string.
-- `paths` is a JSON-encoded Vec<String>; `permissions` is "Read" or "ReadWrite".
-- Revoked sessions have `revoked = 1` and must be rejected even before expiry.

CREATE TABLE IF NOT EXISTS ephemeral_sessions (
    id              TEXT    PRIMARY KEY,  -- UUID v4
    user_id         TEXT    NOT NULL,
    guest_did       TEXT    NOT NULL,     -- did:key:... of the guest device
    guest_pubkey    BLOB    NOT NULL,     -- raw Ed25519 pubkey, 32 bytes
    paths           TEXT    NOT NULL,     -- JSON-encoded Vec<String>
    permissions     TEXT    NOT NULL,     -- "Read" | "ReadWrite"
    expires_at      INTEGER NOT NULL,     -- Unix timestamp (seconds)
    issued_at       INTEGER NOT NULL,     -- Unix timestamp (seconds)
    revoked         INTEGER NOT NULL DEFAULT 0  -- boolean (0 = active, 1 = revoked)
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires   ON ephemeral_sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user      ON ephemeral_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_guest_did ON ephemeral_sessions (guest_did);
