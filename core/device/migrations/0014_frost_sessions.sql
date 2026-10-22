-- FROST threshold signature tables — Step 10 (identity_model sprint)
--
-- frost_orgs:
--   One row per FROST-keyed org created on this device. The initiator holds
--   both their own KeyPackage and the PublicKeyPackage. Other participants hold
--   only their KeyPackage (stored in frost_key_packages), not the pubkey.
--
-- frost_key_packages:
--   Per-participant key material on this device. Keyed by org_did so that
--   `org grant issue` and `frost sign-contribute` can look up material by name.
--
-- frost_signing_sessions:
--   Tracks an in-progress FROST signing ceremony.  Created when the initiator
--   runs `org grant issue` on a FROST org. Holds the pending GrantEnvelope
--   content (message_hex) and this device's round-1 nonces. Deleted after the
--   ceremony completes or is abandoned.
--
-- frost_signing_contributions:
--   Round-1 commitments collected from co-signers. Keyed by
--   (session_id, participant_id_hex).

CREATE TABLE IF NOT EXISTS frost_orgs (
    org_did            TEXT    NOT NULL PRIMARY KEY,
    name               TEXT    NOT NULL,
    owner_did          TEXT    NOT NULL,
    threshold          INTEGER NOT NULL,   -- t in t-of-n
    total              INTEGER NOT NULL,   -- n in t-of-n
    pubkey_package_hex TEXT    NOT NULL,   -- serialised PublicKeyPackage (serde_json → hex)
    created_at         INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_frost_orgs_owner ON frost_orgs (owner_did);

CREATE TABLE IF NOT EXISTS frost_key_packages (
    org_did             TEXT    NOT NULL PRIMARY KEY,
    key_package_hex     TEXT    NOT NULL,   -- serialised KeyPackage (serde_json → hex)
    participant_idx     INTEGER NOT NULL,   -- 1-based; matches the FROST Identifier
    participant_id_hex  TEXT    NOT NULL    -- serialised FROST Identifier (for round 2)
);

CREATE TABLE IF NOT EXISTS frost_signing_sessions (
    session_id       TEXT    NOT NULL PRIMARY KEY,
    org_did          TEXT    NOT NULL,
    user_id          TEXT    NOT NULL,
    -- Pending GrantEnvelope fields (all except the signature, which is computed last)
    member_did       TEXT    NOT NULL,
    caps_json        TEXT    NOT NULL,
    ttl_secs         INTEGER,
    node_did         TEXT,
    -- Round-1 state
    message_hex      TEXT    NOT NULL,   -- canonical bytes that will be signed
    nonces_hex       TEXT    NOT NULL,   -- this device's SigningNonces (secret)
    commitment_hex   TEXT    NOT NULL,   -- this device's SigningCommitments (broadcast)
    participant_id_hex TEXT  NOT NULL,   -- this device's FROST Identifier
    state            TEXT    NOT NULL DEFAULT 'pending',   -- 'pending' | 'signed'
    created_at       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_frost_sign_org  ON frost_signing_sessions (org_did);
CREATE INDEX IF NOT EXISTS idx_frost_sign_user ON frost_signing_sessions (user_id);

CREATE TABLE IF NOT EXISTS frost_signing_contributions (
    session_id         TEXT    NOT NULL,
    participant_id_hex TEXT    NOT NULL,   -- serialised FROST Identifier of the contributor
    commitment_hex     TEXT    NOT NULL,
    share_hex          TEXT    NOT NULL,   -- round-2 signature share
    PRIMARY KEY (session_id, participant_id_hex)
);
