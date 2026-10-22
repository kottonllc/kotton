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
