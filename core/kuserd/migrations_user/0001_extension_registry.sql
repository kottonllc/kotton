-- Per-user agent database, schema v1 (RFC-0063 stage 3b-i).
--
-- First domain moved out of the machine-wide system/agent.db: installed
-- confined extensions (RFC-0049 / RFC-0050). The DDL matches the legacy
-- 0020_extension_registry.sql so the first-contact drain is a plain row copy.
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
