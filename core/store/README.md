# kotton-store

A person's sealed tree of objects: how a device keeps it, how a vault keeps it, and what
moves between the two. Nothing that leaves a device through this crate can be read where it
lands; a vault holds only fixed-size packs and superblocks under blinded keys.

## The stack

`stack::build_local_store` assembles one mount from these layers, outermost first:

- **`PackedObjectStorage`** (`provider/packed.rs`): a write lands loose, and a packing pass
  gathers loose objects into **packs** of a fixed size (`pack.rs`). A *content pack* holds
  file content; an *index pack* holds the manifest (`manifest.rs`, which maps each path to
  its chunks) and the history log's segments, and is sealed at the smaller index size when it
  fits. A **superblock** (`superblock.rs`) is the root pointer, committed crash-atomically
  under a generation-numbered key. Files are cut by content-defined chunking (`chunker.rs`),
  so an edit moves a bounded neighbourhood.
- **`BlindedObjectStorage`** (`blinded.rs`): the key the shelf sees is a keyed derivation of
  the path; the path travels inside the sealed body.
- **`EncryptedObjectStorage`** (`encrypted.rs`): every object under a fresh DEK, the DEK
  wrapped with the person's CEK. On a node that holds no data keys (a vault, a cosigner)
  **`SealedOnlyStorage`** (`sealed_only.rs`) stands in its place: it carries what was sealed
  elsewhere, verbatim, and refuses to put or get content, so it cannot write any in the clear.
- **The shelf** (`shelf.rs`): what the mount rests on, a directory (`LocalShelves`) or, at a
  vault whose landlord chose one, an S3-compatible bucket (`provider/s3.rs`). Nothing above
  the shelf can tell which.

## The history log, and the records in it

Changes are **facts** in a sealed log (`provider/history.rs`), replayed into current state
by a pure function (`replay.rs`): a file written or removed, and a **record** changed. A
record entry is an opaque payload here; `kotton_record::replication` writes it from the
person's record store before a pass and merges what the log carries after one. Each segment
is sealed twice: inside, under `K_log`, derived from the master secret, and so in the record
key domain rather than the content one; outside, as a chunk of an index pack. A device
holding only the CEK carries segments without reading them, and a vault reads neither seal.

Segments ride in **index packs**, and every device takes every index pack of a drive at
each pass, whatever it keeps of the content. So a device that keeps `personal` on demand
receives every record, and fetches a content pack only when something opens it (`fetch.rs`).

## Mounts, drives and a pass

`runtime::user::UserStore` holds a person's mounts, their configured remotes
(`runtime/config.rs`), the path router (`runtime/router.rs`), their roots
(`runtime/roots.rs`), and their private objects, which no sync carries
(`runtime/private.rs`). Mount `local` is the tree this device keeps of the person's first
drive, `personal`: one drive, at one vault, which every device's tree syncs with wherever it
lives, and which `drive move` carries sealed, byte for byte, to another vault.

A pass (`runtime/user/sync.rs`) first **transfers** sealed bytes, packs and superblocks being
unique-named and immutable so the transfer is a set union that destroys neither side, then
**reconciles** by replaying the union of segments. `runtime/maintenance.rs` packs, compacts
and recovers a mount by scanning its packs.

## What a vault can read

At a vault, a person's drive is a directory (or a bucket prefix) of packs of their class's
fixed size and superblocks of one length, under blinded keys. It says nothing of a file's
name or size, and nothing of a record: not its fields, its id, or its schema's NSID. Two
integration tests hold this off the vault's own disk: `vault::the_pool_holds_only_packs`
for the shape, and `records_drive` for a record's bytes, id and NSID, at the vault
`personal` is moved from and the one it is moved to.

## Depends on

`kotton-sys` (the storage traits and the storage key), `kotton-sealed` (replication's view of
a store), `kotton-crypto` and `kotton-context` (path blinding), `kotton-wire`,
`kotton-schemas`, `kotton-common`. It never depends on `kotton-record`: the record layer
names only the `SyncableStore` capability, and this crate provides it.
