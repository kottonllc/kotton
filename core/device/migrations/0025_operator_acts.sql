-- Which operator key said each of the landlord's verbs over the wire
-- (`TASK-a-device-has-operators-not-an-operator`). A vault admits a set of
-- operator keys now, not one, so "the operator did it" no longer names anyone:
-- the row that does is the key.
--
-- `public_key` is the key the connection authenticated as at the handshake —
-- the act was carried on a session only that key's holder could open, and read
-- per request against `operator_key` before it ran. `verb` is the request's
-- variant name; `pool` the pool it named, or empty for `Tenants`; `ok` whether
-- the vault answered it without an error.
--
-- **The column is `pool`, not `user_id`, on purpose.** `kvaultd::tenancy`
-- treats every table with a `user_id` column as a tenant's, sweeping it on a
-- drop and reading it back as a name the vault keeps. This is the landlord's
-- own record of what their operators did — a dropped pool's drop included —
-- and nobody's tenancy, so it is neither.
CREATE TABLE IF NOT EXISTS operator_acts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key BLOB NOT NULL,
    verb TEXT NOT NULL,
    pool TEXT NOT NULL,
    ok INTEGER NOT NULL,
    at INTEGER NOT NULL
);
