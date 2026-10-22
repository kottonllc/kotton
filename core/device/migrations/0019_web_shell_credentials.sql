-- Browser credentials for the HTTP gateway (RFC-0016).
--
-- Each row represents a named token that a browser can use to authenticate
-- against `khttpd`'s POST /auth endpoint.  The raw token is shown to the
-- operator once (base58-encoded) and never stored; only the BLAKE3 hash is
-- kept here so a database compromise cannot be used to impersonate sessions.
CREATE TABLE IF NOT EXISTS web_shell_credentials (
    -- UUID v4, generated at add time.
    id TEXT PRIMARY KEY,
    -- User DID (or user_id) that owns this credential.
    user_id TEXT NOT NULL,
    -- Human-readable label assigned by the operator, e.g. "iphone".
    name TEXT NOT NULL,
    -- BLAKE3 hash of the raw 32-byte token (32 bytes, stored as BLOB).
    token_hash BLOB NOT NULL,
    -- Unix seconds when the credential was created.
    created_at INTEGER NOT NULL,
    -- Unix seconds of the most recent successful login; NULL until first use.
    last_used_at INTEGER,
    -- Enforce unique label per user so revoke-by-name is unambiguous.
    UNIQUE(user_id, name)
);
