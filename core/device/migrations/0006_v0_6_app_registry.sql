-- M18b: app_registry table
--
-- Stores installed WASM apps. Each row represents one installed app.
-- The WASM bytes are stored on disk at `wasm_path`; this table stores metadata.

CREATE TABLE IF NOT EXISTS app_registry (
    app_id        TEXT NOT NULL PRIMARY KEY,
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    -- JSON-encoded array of capability strings, e.g. ["schema.read:sh.kotton.notes"]
    capabilities  TEXT NOT NULL DEFAULT '[]',
    -- Absolute filesystem path to the compiled .wasm file
    wasm_path     TEXT NOT NULL,
    -- ISO 8601 installation timestamp
    installed_at  TEXT NOT NULL
);
