-- kdeviced schema v4: a device has operators, not an operator
-- (TASK-a-device-has-operators-not-an-operator).
--
-- `sudoers` was a set of DIDs and nothing more: a key on the list stood for
-- nobody in particular, so two people sharing one key would have been one
-- operator, and an act by either answerable to neither. Each row now names the
-- person — an account on this device — the key answers for, and a key is the
-- primary key, so no key is ever two people's. A person may hold more than one
-- (the machine's warm key and their identity's own, say).
--
-- `person` is NULL only for the key that enrolled itself on first run (trust on
-- first use, DEC-0017) until an operator binds it; rows carried over from
-- `sudoers` start NULL and `kdeviced` binds each whose key is itself an
-- account's DID (an account from before DIDs were `did:kel`) when it opens the
-- file.
CREATE TABLE IF NOT EXISTS operators (
    did       TEXT PRIMARY KEY,
    person    TEXT,
    added_at  INTEGER NOT NULL,
    added_by  TEXT NOT NULL
);

-- Only keys are carried. `kctl user create` used to add each new account's own
-- DID to `sudoers`, and an account's DID is a `did:kel`: it names a person and
-- signs nothing, so no caller could ever authenticate as that row. Carried
-- over, it would count toward "not the last operator" while standing for
-- nobody who can act — the last real key could then be removed. Those rows
-- never admitted anyone, so leaving them behind takes no one's standing.
INSERT OR IGNORE INTO operators (did, person, added_at, added_by)
    SELECT did, NULL, added_at, added_by FROM sudoers WHERE did LIKE 'did:key:%';

-- Before those rows go, they say whose each key is. `kctl user create` added an
-- account's DID with `added_by` the key it authenticated with, so a carried key
-- answers for the first account its holder created — the person who set the
-- device up. Without this, every carried key would answer for nobody, and the
-- next `kctl user create` would take the second person for the first and bind
-- the device's key to them.
UPDATE operators SET person = (
    SELECT s.did FROM sudoers s
     WHERE s.did LIKE 'did:kel:%' AND s.added_by = operators.did
     ORDER BY s.added_at ASC, s.did ASC LIMIT 1
) WHERE person IS NULL;

DROP TABLE sudoers;

-- Every act an operator takes, under the key that authenticated the connection
-- it was said on — the key whose signature over this connection's nonce
-- admitted it, and whose row was read again before the act ran. `act` is the
-- request's variant name, `subject` what it named (a user, a key, a name), `ok`
-- whether it was carried out. Kept apart from `device_events`, which is the
-- supervisor's lifecycle log and records things nobody asked for.
CREATE TABLE IF NOT EXISTS operator_acts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    did      TEXT    NOT NULL,
    act      TEXT    NOT NULL,
    subject  TEXT    NOT NULL,
    ok       INTEGER NOT NULL,
    at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_operator_acts_did ON operator_acts (did);
