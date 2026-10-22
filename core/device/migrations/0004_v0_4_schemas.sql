-- v0.4 Schema Layer — app schema registry table
--
-- Stores JSON-serialized SchemaDefinition records for app-supplied schemas.
-- Core schemas (sh.kotton.*) are compiled into the binary and never appear
-- in this table.
--
-- Columns:
--   nsid             — Reverse-domain NSID (primary key). e.g. io.myapp.posts
--   version          — Integer schema version (starts at 1, incremented on update)
--   definition_json  — Full JSON-encoded SchemaDefinition (fields, extends, description)
--   registered_at    — Unix timestamp (seconds) when the schema was first registered

CREATE TABLE IF NOT EXISTS app_schemas (
    nsid             TEXT    NOT NULL PRIMARY KEY,
    version          INTEGER NOT NULL,
    definition_json  TEXT    NOT NULL,
    registered_at    INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE INDEX IF NOT EXISTS idx_app_schemas_version ON app_schemas (version);
