-- v0.5 Document Model — handler registry table
--
-- Stores which app handles which schema NSID (equivalent to macOS UTIs /
-- Launch Services).  A WASM app declares `handler_for` in its manifest;
-- the daemon writes those declarations here on install.
--
-- Columns:
--   app_id         — Reverse-domain app identifier, e.g. "com.acme.notes-pro"
--   nsid           — Schema NSID this app can render, e.g. "sh.kotton.notes"
--   is_default     — 1 if this is the user's preferred handler for the NSID,
--                    0 otherwise.  Only one row per NSID may have is_default=1.
--   registered_at  — Unix timestamp (seconds) when this handler was registered.

CREATE TABLE IF NOT EXISTS handler_registry (
    app_id        TEXT    NOT NULL,
    nsid          TEXT    NOT NULL,
    is_default    INTEGER NOT NULL DEFAULT 0,
    registered_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (app_id, nsid)
);

-- Fast lookup: "which apps handle this NSID?"
CREATE INDEX IF NOT EXISTS idx_handler_registry_nsid       ON handler_registry (nsid);
-- Fast lookup: "what is the default handler for this NSID?"
CREATE INDEX IF NOT EXISTS idx_handler_registry_nsid_dflt  ON handler_registry (nsid, is_default);
