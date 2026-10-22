-- Per-user app schema registry — RFC-0063 stage 3b.
--
-- App-supplied schema definitions, so a registration survives a daemon restart.
-- Before this table was written, registrations lived only in memory: a restart
-- left the user's records on disk and unreadable (`record_cmds::query` refuses
-- an NSID the registry does not know) and made every replicated row under a
-- custom schema get skipped. See
-- governance/records/TASK-custom-schemas-do-not-survive-a-restart.md.
--
-- **This is the per-user side, deliberately.** A machine-wide `app_schemas`
-- table exists in `migrations/0004_v0_4_schemas.sql` and was never read or
-- written by any code, so there is nothing to drain and it needs no entry in
-- `DRAINED_TABLES`. It also could not have served: it has no owner column, so
-- it cannot express which principal registered what — and NSIDs are
-- reverse-domain app names, which makes an unscoped list a readout of which
-- apps a machine's other users run.
--
-- No owner column is needed *here* because the database is the principal.
--
--   nsid            — the schema's NSID (primary key within this user)
--   version         — integer schema version
--   definition_json — the full JSON-encoded SchemaDefinition
--   registered_at   — unix seconds, first registration by this user

CREATE TABLE IF NOT EXISTS app_schemas (
    nsid             TEXT    NOT NULL PRIMARY KEY,
    version          INTEGER NOT NULL,
    definition_json  TEXT    NOT NULL,
    registered_at    INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
