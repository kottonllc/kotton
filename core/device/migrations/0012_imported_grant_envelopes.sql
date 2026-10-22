-- Imported grant envelopes — Step 8 (identity_model sprint)
--
-- Cross-DID GrantEnvelopes imported via `kotton grant import`.
-- Unlike app_grant_envelopes (which are bound to a specific installed app),
-- these envelopes are stored at the user level and represent capability grants
-- issued by an org DID to this user.
--
-- Enforcement: the WIT host checks these in addition to app-bound envelopes
-- when evaluating IPC calls from apps.

CREATE TABLE IF NOT EXISTS imported_grant_envelopes (
    id            TEXT    NOT NULL PRIMARY KEY,  -- GrantEnvelope.id (UUID)
    issuer_did    TEXT    NOT NULL,              -- org DID that signed this envelope
    subject_did   TEXT    NOT NULL,              -- user DID this envelope was issued to
    envelope_json TEXT    NOT NULL,              -- full JSON, including issuer_signature
    imported_at   INTEGER NOT NULL               -- Unix seconds (UTC)
);

CREATE INDEX IF NOT EXISTS idx_ige_issuer_did  ON imported_grant_envelopes (issuer_did);
CREATE INDEX IF NOT EXISTS idx_ige_subject_did ON imported_grant_envelopes (subject_did);
