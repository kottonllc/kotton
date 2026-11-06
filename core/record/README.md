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
`SchemaDefinition`, one per schema NSID (`sh.kotton.notes` becomes `sh_kotton_notes`), in
`STRICT` mode under the WAL journal. `insert`, `query` and `delete` take the `Nsid` they act on,
and `RecordFilter::new()` builds a query by its methods: a field equal to a value, a text
search, a limit and an offset, a cursor, the roots.

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

**No record byte, id or NSID is readable at the vault.** A segment is sealed under `K_log`,
derived from the master secret, inside a pack sealed under the CEK, under a blinded key, in a
pack of fixed size. The vault holds neither key. `records_drive` in the integration suite reads
every file under the vault's directory twice. The first time is before `drive move personal`,
at the vault that keeps `personal`. The second is after it, at the vault `personal` moved to
and at the one it left. Where the vault keeps `personal`, the scan reads at least the files
and bytes the vault lists in the drive's tree (`users/<user>/drives/<tree>`), so it is shown
to have read the drive. Nowhere does it find a record's fields, its id (as written or as
bytes) or its schema's NSID.

Records are in Personal, which rides in `personal`, for now. A write that names no root is
Personal's (`roots::RootAccess::write`). A request may also name Personal by the word
`kotton_wire::ipc::PERSONAL_ROOT` rather than by its id, and then reads, writes and deletes in
Personal alone. A device must know a record's schema to merge it. One it does not know is
carried and kept verbatim, not dropped (`replication::snapshot_records`).

## The `record` verbs

`record list|get|put|rm --schema <nsid>` is the shell's `record` noun
(`client/shell/src/commands/record.rs`), one parser for the REPL and `kotton record`. Each
verb is one request this crate's daemon handlers already answer: `RecordQuery` (for `list`,
and for `get` by the record's id), `RecordInsert` and `RecordDelete`. **Each names Personal**
(`PERSONAL_ROOT`), so a record in another root the person is a member of, such as an
organisation's project, is not listed, read, written or removed by them. A schema is cited by
its NSID. An id no record has in Personal exits 1, and so does a schema this device does not
know, by name. `record import|export` are not in the tree yet (#454).
