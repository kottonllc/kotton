# kotton-record

The record crate, in two layers.

## The connection pool

`open_sqlite` opens or creates a SQLite database as a `sqlx` pool in WAL mode, and `migrate`
runs a `Migrator` against such a pool. The daemon's event log and a device's database open
their pools with it.

## `RecordStore` — a person's records

`RecordStore` is the async trait and `SqliteRecordStore` its implementation, on rusqlite with
SQLCipher. Each person has their own `records.db`, opened with their key (`SqliteRecordStore::open`
takes the key, or none for an unkeyed store in a test). A table is created on demand from a
`SchemaDefinition`, one per schema, by a name that is that schema's alone: `r_` and the first
32 hex characters of BLAKE3 over the schema's identity, `<publisher>/<name>` (the protocol's
decision *A schema is named by the key that publishes it*). A digest rather than a readable
encoding because SQLite folds a table name's case and a publisher is a case-sensitive
`did:key`, so no readable encoding is both injective and case-safe; the name need only be
distinct, since every row carries its identity in `schema_nsid` and every statement holds a
row to it. A table written under an earlier name is split on open, each row to the table of
the identity it names, and a row written under one of the old core names is read as the
identity that name became. Where that table already holds the row's id, in the same root, the
two are versions of one row, and the split keeps the newer by `(updated_at, revision)`, as a
merge does, and drops the older. Once it commits it logs, per schema, only counts: rows moved,
rows that replaced an older copy, rows dropped as the older, rows left; never a record's id or
when it was written. The tables are in `STRICT` mode under the WAL journal. `insert`, `query`
and `delete` take the `SchemaId` they act on, and `RecordFilter::new()` builds a query by its
methods: a field equal to a value, a text search, a limit and an offset, a cursor, the roots.

`SchemaRegistry` keeps the schemas a store knows. `record_cmds::Record` is what the daemon's
record verbs call.

## Records travel in `personal`

A record is the person's, kept on each of their devices and sealed into their first drive,
`personal`. Before a pass over mount `local`, the tree a device keeps of `personal`,
`replication::log_records` seals every version the log does not already carry into one
`Entry::Record` segment of the history log (`kotton-store`'s `provider/history.rs`); after the
pass, `replication::apply_record_segments` merges every segment the drive delivered, last
write wins, into this device's `records.db`. This is the one path a record takes between
devices: a record put on one device is read on another after a `sync` on each, wherever
`personal` lives, since `drive move personal` carries the drive's sealed bytes whole and every
device's tree follows it. A device that keeps `personal` on demand receives every record too:
segments ride in index packs, which every pass takes.

**No record byte, id or schema identity is readable at the vault.** A segment is sealed under `K_log`,
derived from the master secret, inside a pack sealed under the CEK, under a blinded key, in a
pack of fixed size. The vault holds neither key. `records_drive` in the integration suite reads
every file under the vault's directory twice. The first time is before `drive move personal`,
at the vault that keeps `personal`. The second is after it, at the vault `personal` moved to
and at the one it left. Where the vault keeps `personal`, the scan reads at least the files
and bytes the vault lists in the drive's tree (`users/<user>/drives/<tree>`), so it is shown
to have read the drive. Nowhere does it find a record's fields, its id (as written or as
bytes) or its schema's identity.

The log that rides in `personal` carries every root's rows this device holds, each with its
root (`replication::log_records` exports the whole changeset): a record of an organisation's
project written on this device rides there too, sealed under the person's `K_log`, readable by
the person's own devices and never by the root's other members. Of those rows, Personal's are
the `record` verbs' to reach. A write that names no root is Personal's
(`roots::RootAccess::write`). A request may also name Personal by the word
`kotton_wire::ipc::PERSONAL_ROOT` rather than by its id, and then reads, writes and deletes in
Personal alone; the word is the person's, and a request from an app that names it is refused
(`daemon::records`). A device must know a record's schema to merge it. One it does not know is
carried and kept verbatim, not dropped (`replication::snapshot_records`).

`schema list|show|register` are the schema verbs (`schema_cmds`). A device knows the core set,
compiled in, and what `schema register` was handed: a definition signed by its publisher, the
key its identity names, checked by `kotton_crypto::schema_signature` before anything is
migrated or kept. The signature is over the 49-byte message the protocol's decision *A schema
is named by the key that publishes it* names, the tag `kotton-schema-v1`, a zero byte and the
definition's digest, never the bare digest. A definition that is unsigned, signed by another
key, signed over the bare digest, or changed under its signature is refused; so is a document
that is not the definition and nothing beside it, since the digest is taken over the
definition's canonical form; and so is one naming a core schema, which changes in the tree and
not through registration.

Three of the core set, `secret`, `access-log` and `petname`, are kept from every app, a refusal
held for those identities by name (`CoreSchema::is_kept_from_apps`), not for being core. No app
is granted one: a grant on one is refused when set, and the check every app's record verb
passes (`kotton_grant`'s `check_read`, `check_write` and `check_register`) refuses it whatever
row the grant store holds. No manifest claims to handle or asks for one, no handler is
registered or answered for one, the runner's records verbs refuse one, and `Record::search`
returns no row of one to any caller, with no schema named or with one of them named. All three
are known to every device. The person reaches `secret` at their own terminal with the `secret`
verbs, in Personal, `access-log` with the record verbs there, and `petname` with the record
verbs and at a grant prompt's first meeting with a key; no verb writes a log entry for a daemon
request yet, which is the `log` noun's own issue. `petname` is kept because a grant prompt
trusts what a petname says (the decision *A schema is named by the key that publishes it*): an
app that could write one could name itself.

**A petname is held at insert**, in `record_cmds::insert`, for that one identity by name, as
`replication` holds `access-log`: its body keeps `kotton_schemas::petname::check` (`key` a
`did:key`; `name` not empty, at most 64 characters, no `/`, no control or
bidirectional-formatting character, not beginning `did:`, and `kotton` for Kotton's publisher
alone), and it is written in Personal and no other root. The refusal names the rule broken and
says no more of the body than the name. **One record per key**: a petname for a key already
named replaces the one before it, the others naming that key in Personal removed once the new
one is written, so the person renames a key by naming it again. A row merged from another
device is not held here; the reader ignores one that breaks a rule, and of two for one key reads
the one filed last.

**The access log is kept on the device that wrote it** (#450). The protocol's *The first release
is a platform a stranger can use from the command line* keeps the log on the device and puts it
in a drive only if the person pins it there. `replication` holds the identity by name, not by a
schema flag: `log_records` logs no row of `access-log`, and `snapshot_records` puts none of this
device's rows of it in a snapshot's base, carrying instead the newest version of each row of it
the log already carries, verbatim. Those are the two paths by which a row leaves this device's
store for a drive; the retired peer verb was the third (module doc). Both carry this device's
log only when its own setting pins it to `personal` (`replication::AccessLogPin`, kept in the
device's database by `kotton_device::users::log_pin`, migration `0033`, and read by the sync
engine for each pass of `personal`'s mount). There is no verb for the setting until the `log`
noun's issue; `log_pin::set` on the device's database is the handle. Pinned, the device's log
rides the record log to `personal` like any record, its rows from before the pin among them.
Unpinned again, no new row leaves; a row already logged stays in the drive and nothing is
retracted. A row of it from another of the person's devices, one that pinned its log, is merged
here as any row is.

**Writing a log record starts no pass**, and tells no one it was written. The store wakes the
sync engine itself after an insert or a delete of any schema but `access-log`
(`SqliteRecordStore::with_write_signal`, `replication::a_write_wakes_a_pass`), and the wake is
kept while a pass runs, so writes during a background pass are followed by exactly one more
(`kotton_sync::engine::SyncWake::wake_pending`). A write that lands while a pass the person
asked for holds the drive is not followed by one: the background pass skips a drive already
being passed over, and the write rides the next wake or the periodic tick (#485). On a device
with a sync sidecar, a record write also used to start a pass over drives the watcher does not
watch, since the sidecar asked for every drive; it now reaches watched drives only, as a write
on any other device does. The engine's filesystem watcher, which cannot
tell one schema's write from another's, neither wakes on a change to `records.db` or the three
files SQLite keeps beside it nor sends a `VfsWatch` frame for one: they are not files of any
drive's tree. Before that a frame went to every subscriber for each record write, and the sync
sidecar, which runs on any device with a paired node and syncs on every frame, started a pass
for each, an access-log record's among them; a session at `Remote` read the timestamps. Now a
pinned log rides the next pass that runs anyway and adds no rhythm a host can read.

A pass's own writes wake no pass: the engine reads and writes through
`SqliteRecordStore::without_write_signal` (`kotton_sync::engine::records_for_a_pass`), so the
whole-keeper claim a pass makes or withdraws and a pin setting it moves out of the drive do not
arm the next pass. Nothing else that changes only `records.db` wakes one either, and none
should: a merge of rows from the log, which a pass makes; a table's creation, or its migration;
the cleanup of old tombstones; and the split and respelling of old tables when the store is
opened. None is a row the person or an app wrote, and the rows they touch were logged already
or ride the next pass that runs anyway.

A row of `secret` reaches a device only as every record does, in the record log of
`personal`, sealed under the person's `K_log`, which their own devices alone hold: a member of
a root the person shares holds no key to that log and writes no segment a pass applies here.

## The `record` verbs

`record list|get|put|rm --schema <schema>` is the shell's `record` noun
(`client/shell/src/commands/record.rs`), one parser for the REPL and `kotton record`. Each
verb is one request this crate's daemon handlers already answer: `RecordQuery` (for `list`,
and for `get` by the record's id), `RecordInsert` and `RecordDelete`. **Each names Personal**
(`PERSONAL_ROOT`), so a record in another root the person is a member of, such as an
organisation's project, is not listed, read, written or removed by them. A schema is cited by
its identity, `did:key:…/<name>`, or as `<petname>/<name>`, the person's own name for the key,
resolved on the device (`kotton_shell::petnames`, the one parser and the one reader of
petnames): `kotton/notes` on every device. A petname no key has is refused saying so, and one
that names several keys is refused naming them; output prints the short form wherever the
publisher has a name. A request always carries the whole identity. An id no record has in
Personal exits 1, and so does a schema this device does not know, by name. `get` prints the record as the row holds it, its `id` among its fields, and
`list --json` prints each row the same way; neither prints the fields the daemon adds to an
answer (`_id`, `_filed_at`, `_root`), because every verb here names Personal and `_root` would
be Personal's id, a durable identifier, on every row. `record import|export` are in the tree
(#454).

**An insert takes only what its schema declares.** `RecordInsert`, from any client, is refused,
naming the field, when the body carries a top-level field beginning with `_` (the daemon's: an
answer adds `_id`, `_filed_at` and `_root`, and a body fed back from one would store Personal's
id as a field and log it to every device) or a field the schema does not declare. `id` is the
store's and is taken whether the schema declares it or not. The check is in
`record_cmds::insert`, before the store; replication's merge, which carries rows another device
already accepted, does not meet it, and a row already stored with such a field is left as it is,
nothing rewritten on open. No schema allows open fields: `SchemaDefinition` declares its fields
and nothing more, and `FieldType` is closed, with no type that admits an undeclared name (a
`map` is declared, and holds one value type), so there is no exception to state.

`secret set|get|list|rm|generate <label>` is the keychain
(`client/shell/src/commands/secret.rs`), the same requests under `secret`, each naming
Personal: one record per label, under the id the store gave it, so a label is never written
into a record's URL. `set` never takes the value on the line; it reads it at a hidden prompt
at a terminal, and with no terminal `kotton secret set` reads the one line piped to it; in the
REPL, whose stdin is its script, it reads nothing and is refused. `get` prints the value
alone; `list` never prints one.

**A kept schema answers only the person's own terminal.** `RecordInsert`, `RecordQuery`,
`RecordDelete` and `RecordOpen` (by the schema its URL names) on `secret`, `access-log` or
`petname` are refused, naming no app or one, unless the connection's origin is `Local`, a
client on this device's own socket (`daemon::records::refuse_kept_off_terminal`). The origin is
the one `Authenticate` bound from the credential, read by the door and handed to the verb; a
remote client or an admitted browser names no app and is not thereby the person at their
terminal.
`RecordSearch` answers no row of one to anyone.

## The grant prompt

`app sideload <path>` previews what an app asks for before anything is installed
(`client/shell/src/commands/app.rs`), and `app grants <id>` lists what it asked for and what it
holds; both say who stands behind what they show by the rule of the decision *A schema is named
by the key that publishes it* (`kotton_shell::grant_prompt`). **What the device says comes
first**, on lines of its own in a fixed shape: who stands behind the app, by the person's
petname for the key, marked as theirs ("This app's code is signed by a publisher you call "My
Bank"."), or "a publisher you have not named" with the key, or "an app nobody signed". **It says
only what was checked**: the publisher's signature covers the digest of the app's code alone, so
the next line says that what the app asks for is not signed by anyone, and a schema is a
publisher's only when this device holds its signed definition; one it does not hold is "a schema
this device does not hold", attributed to no one. A line says so when the app's code is not a
schema's publisher's, an unsigned app's included. A name the person gave more than one key is
shown as shared, with the key it is; when the names cannot be read, the prompt says so and shows
keys as keys. **Every string another party chose** (the app's name, version, id, description,
paths, labels, a schema's name) follows, each on a line beginning ` | `, which no line of the
device's does, labelled as whose and quoted: whitespace one space, control, bidirectional,
separator, zero-width and tag characters removed, combining marks at most four to a character,
and at most 64 characters shown, saying when it was cut. At a terminal, once the prompt has been
shown, a key it shows unnamed is offered to be named, the first meeting; a name that already
names another key is said to, with that key, and kept only on an explicit yes. The answer is a
petname written through the ordinary insert, held to its rules, and the prompt is shown again
with it. With nobody to ask, nothing is asked and the key is shown not named. `record import`
refuses `petname`: a name is given one at a time.
