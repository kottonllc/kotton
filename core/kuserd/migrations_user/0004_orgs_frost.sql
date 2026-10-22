-- Per-user agent database, schema v4 (RFC-0063 stage 3b-iv): orgs and FROST.
--
-- Org rows are the owner's bookkeeping (orgs I created, envelopes I issued);
-- FROST rows are this participant's ceremony state. Both were machine-wide by
-- accident of the process they were written in. The one deliberately shared
-- remainder is the org-revocation channel, which stays in the machine-wide
-- revocation_list until revocation propagation gets its sync design.
-- DDL matches legacy 0013/0014 so the drain is a plain (filtered) copy.

CREATE TABLE IF NOT EXISTS org_identities (
    org_did    TEXT    NOT NULL PRIMARY KEY,
    name       TEXT    NOT NULL,
    owner_did  TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_org_owner ON org_identities (owner_did);

CREATE TABLE IF NOT EXISTS org_members (
    org_did     TEXT    NOT NULL,
    member_did  TEXT    NOT NULL,
    envelope_id TEXT    NOT NULL,
    issued_at   INTEGER NOT NULL,
    PRIMARY KEY (org_did, envelope_id)
);
CREATE INDEX IF NOT EXISTS idx_org_members_org    ON org_members (org_did);
CREATE INDEX IF NOT EXISTS idx_org_members_member ON org_members (member_did);

CREATE TABLE IF NOT EXISTS frost_orgs (
    org_did            TEXT    NOT NULL PRIMARY KEY,
    name               TEXT    NOT NULL,
    owner_did          TEXT    NOT NULL,
    threshold          INTEGER NOT NULL,
    total              INTEGER NOT NULL,
    pubkey_package_hex TEXT    NOT NULL,
    created_at         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_frost_orgs_owner ON frost_orgs (owner_did);

CREATE TABLE IF NOT EXISTS frost_key_packages (
    org_did             TEXT    NOT NULL PRIMARY KEY,
    key_package_hex     TEXT    NOT NULL,
    participant_idx     INTEGER NOT NULL,
    participant_id_hex  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS frost_signing_sessions (
    session_id       TEXT    NOT NULL PRIMARY KEY,
    org_did          TEXT    NOT NULL,
    user_id          TEXT    NOT NULL,
    member_did       TEXT    NOT NULL,
    caps_json        TEXT    NOT NULL,
    ttl_secs         INTEGER,
    node_did         TEXT,
    message_hex      TEXT    NOT NULL,
    nonces_hex       TEXT    NOT NULL,
    commitment_hex   TEXT    NOT NULL,
    participant_id_hex TEXT  NOT NULL,
    state            TEXT    NOT NULL DEFAULT 'pending',
    created_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_frost_sign_org  ON frost_signing_sessions (org_did);
CREATE INDEX IF NOT EXISTS idx_frost_sign_user ON frost_signing_sessions (user_id);

CREATE TABLE IF NOT EXISTS frost_signing_contributions (
    session_id         TEXT    NOT NULL,
    participant_id_hex TEXT    NOT NULL,
    commitment_hex     TEXT    NOT NULL,
    share_hex          TEXT    NOT NULL,
    PRIMARY KEY (session_id, participant_id_hex)
);
