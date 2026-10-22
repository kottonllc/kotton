-- Per-user agent database, schema v3 (RFC-0063 stage 3b-iii): the grant cluster.
--
-- A capability grant names one user's authority over one user's data; storing
-- it beside every other user's was the shared-process shape. The envelopes
-- remain the cryptographic authority (signed, verified at every call) — this
-- move changes where the records sit, not what proves them. DDL matches the
-- legacy 0010/0012 migrations so the drain is a plain copy.

-- Signed GrantEnvelope JSON blobs bound to an installed app.
CREATE TABLE IF NOT EXISTS app_grant_envelopes (
    id            TEXT    NOT NULL PRIMARY KEY,  -- GrantEnvelope.id (UUID)
    app_id        TEXT    NOT NULL,              -- reverse-domain app identifier
    envelope_json TEXT    NOT NULL,              -- full JSON, including issuer_signature
    stored_at     INTEGER NOT NULL               -- Unix seconds (UTC)
);
CREATE INDEX IF NOT EXISTS idx_age_app_id ON app_grant_envelopes (app_id);

-- Envelope IDs that have been revoked.
CREATE TABLE IF NOT EXISTS revocation_list (
    envelope_id TEXT    NOT NULL PRIMARY KEY,
    revoked_at  INTEGER NOT NULL
);

-- DIDs whose cross-DID grants are accepted without extra prompting.
CREATE TABLE IF NOT EXISTS trusted_issuers (
    did      TEXT    NOT NULL PRIMARY KEY,
    added_at INTEGER NOT NULL
);

-- Cross-DID GrantEnvelopes imported via `kotton grant import` — issued by an
-- org DID to this user.
CREATE TABLE IF NOT EXISTS imported_grant_envelopes (
    id            TEXT    NOT NULL PRIMARY KEY,
    issuer_did    TEXT    NOT NULL,
    subject_did   TEXT    NOT NULL,
    envelope_json TEXT    NOT NULL,
    imported_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ige_issuer_did  ON imported_grant_envelopes (issuer_did);
CREATE INDEX IF NOT EXISTS idx_ige_subject_did ON imported_grant_envelopes (subject_did);
