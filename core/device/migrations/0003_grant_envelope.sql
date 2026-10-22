-- Migration 0003: replace paths+permissions columns with grant_json in ephemeral_sessions.
--
-- EphemeralSession now embeds a full GrantEnvelope (JSON) instead of the
-- flat `paths` + `permissions` + `expires_at` columns. Expiry is read from
-- grant_json->>'expires_at'. Existing rows are non-recoverable placeholder
-- data and are intentionally dropped.

DROP TABLE IF EXISTS ephemeral_sessions;

CREATE TABLE IF NOT EXISTS ephemeral_sessions (
    id           TEXT    PRIMARY KEY,  -- UUID v4 (== grant envelope id)
    user_id      TEXT    NOT NULL,
    guest_did    TEXT    NOT NULL,     -- did:key:... of the guest device
    guest_pubkey BLOB    NOT NULL,     -- raw Ed25519 pubkey, 32 bytes (placeholder until handshake)
    grant_json   TEXT    NOT NULL,     -- JSON-encoded GrantEnvelope
    issued_at    INTEGER NOT NULL,     -- Unix timestamp (seconds)
    revoked      INTEGER NOT NULL DEFAULT 0  -- boolean (0 = active, 1 = revoked)
);

CREATE INDEX IF NOT EXISTS idx_sessions_user      ON ephemeral_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_guest_did ON ephemeral_sessions (guest_did);
