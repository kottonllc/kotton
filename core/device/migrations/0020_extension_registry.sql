-- Installed confined extensions (RFC-0049 / RFC-0050).
--
-- Deliberately separate from `app_registry` rather than a `kind` column on it.
-- An app declares which of the user's data it wants; an extension declares
-- which *class* it is, and the class picks the WIT world, which decides what it
-- can reach at all. The two have different fields, different consent text, and
-- different failure modes -- sharing a table would invite a query that forgets
-- to discriminate.
--
-- What is NOT here: the capability grants. Those live in the signed
-- `GrantEnvelope` (grant_db), so the authority an extension holds is verified
-- cryptographically at every call rather than read from a row an attacker with
-- database write access could edit.
CREATE TABLE IF NOT EXISTS extension_registry (
    -- Reverse-domain id from the manifest, validated at install. Also names
    -- the extension's quarantine namespace, which is why it must be boring.
    extension_id TEXT PRIMARY KEY,
    -- Display name and version, for listings and consent.
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    -- "fetcher" | "storage-backend" -- the WIT world discriminator.
    class TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    -- Absolute path to the installed component.
    wasm_path TEXT NOT NULL,
    -- BLAKE3 hex of the component bytes. Re-checked on load, so a swapped
    -- binary refuses to run (RFC-0050 double integrity).
    content_hash TEXT NOT NULL,
    -- Publisher DID, or NULL when the package was unsigned. NULL is a fact to
    -- surface to the user, not an error -- provenance is shown, not gated
    -- (RFC-0013: no mandatory gatekeeper).
    publisher_did TEXT,
    -- JSON: the declared network posture, as consented. Either
    -- {"endpoints":[...]} or {"dynamic":true} or null for no network. Stored so
    -- a later run enforces exactly what the user approved, not whatever a
    -- re-read of the manifest on disk might say.
    network_json TEXT,
    -- JSON array of declared credential slot names. The secrets themselves live
    -- in the OS keychain, never here.
    credential_slots TEXT NOT NULL DEFAULT '[]',
    -- Unix seconds.
    installed_at INTEGER NOT NULL
);
