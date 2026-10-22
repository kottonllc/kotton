-- Grant enforcement tables — Step 7 (identity_model sprint)
--
-- app_grant_envelopes: signed GrantEnvelope JSON blobs bound to an installed app
-- revocation_list:     envelope IDs that have been revoked
-- trusted_issuers:     DIDs whose cross-DID grants are accepted without extra prompting

CREATE TABLE IF NOT EXISTS app_grant_envelopes (
    id            TEXT    NOT NULL PRIMARY KEY,  -- GrantEnvelope.id (UUID)
    app_id        TEXT    NOT NULL,              -- reverse-domain app identifier
    envelope_json TEXT    NOT NULL,              -- full JSON, including issuer_signature
    stored_at     INTEGER NOT NULL               -- Unix seconds (UTC)
);

CREATE INDEX IF NOT EXISTS idx_age_app_id ON app_grant_envelopes (app_id);

CREATE TABLE IF NOT EXISTS revocation_list (
    envelope_id TEXT    NOT NULL PRIMARY KEY,    -- GrantEnvelope.id that was revoked
    revoked_at  INTEGER NOT NULL                 -- Unix seconds (UTC)
);

CREATE TABLE IF NOT EXISTS trusted_issuers (
    did      TEXT    NOT NULL PRIMARY KEY,       -- fully-qualified did:key string
    added_at INTEGER NOT NULL                    -- Unix seconds (UTC)
);
