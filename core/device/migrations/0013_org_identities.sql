-- Org identity tables — Step 9 (identity_model sprint)
--
-- org_identities: one row per org DID created by this user.
--   The org private key is NOT stored here; it lives in the OS keychain
--   under the key `kotton:org_key:{org_did}` (hex-encoded 32-byte scalar).
--
-- org_members: tracks every GrantEnvelope issued by an org to a member.
--   Used by `org member remove` to revoke all outstanding envelopes for a
--   given subject DID.

CREATE TABLE IF NOT EXISTS org_identities (
    org_did    TEXT    NOT NULL PRIMARY KEY,   -- fully-qualified did:key:…
    name       TEXT    NOT NULL,               -- human-readable label
    owner_did  TEXT    NOT NULL,               -- user DID that created this org
    created_at INTEGER NOT NULL               -- Unix seconds (UTC)
);

CREATE INDEX IF NOT EXISTS idx_org_owner ON org_identities (owner_did);

CREATE TABLE IF NOT EXISTS org_members (
    org_did     TEXT    NOT NULL,   -- the org that issued the grant
    member_did  TEXT    NOT NULL,   -- subject_did of the issued GrantEnvelope
    envelope_id TEXT    NOT NULL,   -- GrantEnvelope.id — used to revoke
    issued_at   INTEGER NOT NULL,   -- Unix seconds (UTC)
    PRIMARY KEY (org_did, envelope_id)
);

CREATE INDEX IF NOT EXISTS idx_org_members_org    ON org_members (org_did);
CREATE INDEX IF NOT EXISTS idx_org_members_member ON org_members (member_did);
