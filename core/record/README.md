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
migrated or kept. A definition that is unsigned, signed by another key, or changed under its
signature is refused; so is a document that is not the definition and nothing beside it, since
the digest is taken over the definition's canonical form; and so is one naming a core schema,
which changes in the tree and not through registration. Two of the core set, `secret` and
`access-log`, are published and not yet known to a device: no record is kept under either
until the grant refusal and the search exclusion they need are built.

## The `record` verbs

`record list|get|put|rm --schema <publisher>/<name>` is the shell's `record` noun
(`client/shell/src/commands/record.rs`), one parser for the REPL and `kotton record`. Each
verb is one request this crate's daemon handlers already answer: `RecordQuery` (for `list`,
and for `get` by the record's id), `RecordInsert` and `RecordDelete`. **Each names Personal**
(`PERSONAL_ROOT`), so a record in another root the person is a member of, such as an
organisation's project, is not listed, read, written or removed by them. A schema is cited by
its identity. An id no record has in Personal exits 1, and so does a schema this device does not
know, by name. `get` prints the record as the row holds it, its `id` among its fields, and
`list --json` prints each row the same way; neither prints the fields the daemon adds to an
answer (`_id`, `_filed_at`, `_root`), because every verb here names Personal and `_root` would
be Personal's id, a durable identifier, on every row. `record import|export` are not in the
tree yet (#454).

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
