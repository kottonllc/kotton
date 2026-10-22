-- Browser devices admitted to the sealed channel (RFC-0078, the reach tier).
--
-- A browser holds a per-device Ed25519 key it generated itself; this table is the
-- set of keys the node will admit by signature alone. A key gets here one way:
-- a human on this node's own screen compared six digits with the phone and said
-- yes (`WebShellPair`). Revoking a row is revoking the browser.
--
-- The public key is the credential. Nothing secret is stored.
CREATE TABLE IF NOT EXISTS browser_devices (
    -- UUID v4, generated at admission.
    id TEXT PRIMARY KEY,
    -- The user this browser may act for.
    user_id TEXT NOT NULL,
    -- The name the browser proposed and the human accepted, e.g. "Austin's phone".
    name TEXT NOT NULL,
    -- The browser's Ed25519 public key (32 bytes).
    device_pub BLOB NOT NULL,
    -- Unix seconds when the human admitted it.
    created_at INTEGER NOT NULL,
    -- Unix seconds of the most recent channel; NULL until first return visit.
    last_used_at INTEGER,
    UNIQUE(user_id, name),
    UNIQUE(user_id, device_pub)
);
