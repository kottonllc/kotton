# kotton-schemas

User record schema definitions for the Kotton data layer.

This crate is distinct from `kotton-wire` (IPC wire types). It provides the vocabulary for
structured user data: what a schema is, how it is named, how its definition is digested and
signed, and the core set every device holds.

## A schema is named by the key that publishes it

The protocol's decision *A schema is named by the key that publishes it* fixes a schema's
identity and its version. The identity is `<publisher>/<name>`: the publisher is the `did:key`
of the key that publishes the schema and signs its definition, and the name is one or more
dot-separated segments of lowercase letters, digits and hyphens, each beginning with a letter.
Nothing resolves, registers or reserves a name; nobody can publish under a key they do not
hold. The version is the digest of the definition: BLAKE3 over the document `publisher`,
`name`, `revision`, `fields`, `description` serialised by the JSON Canonicalization Scheme
(RFC 8785), as lowercase hex. The signature is Ed25519 under the publisher's key over a
domain-tagged message, not the bare digest: the 16 ASCII bytes `kotton-schema-v1`, one zero
byte, and the 32-byte digest, 49 bytes in all, so 32 bytes the key signed for another purpose
are not a schema's signature. It is carried beside the definition as `signature`, base64, and
checked by `kotton_crypto::schema_signature`; a definition whose signature does not check is
no schema, and neither is one signed over the bare digest.

Kotton's own schemas are published under Kotton's release key
(`infra/release/allowed_signers`), `did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB`;
`kotton_common::namespace` holds each identity as a constant. "Core" means present on every
device and nothing more: a core schema has no reach another lacks. Before the first tag the
core files carry no signature, and the registry admits them as core without one.

## Modules

| Module       | Contents                                                                                         |
| ------------ | ------------------------------------------------------------------------------------------------ |
| `schema_id`  | `SchemaId`, `Publisher`, `SchemaName` — a schema's identity, `<did:key:…>/<name>`                |
| `canonical`  | `canonical_json` — RFC 8785 for what the digest is over; a non-integer number is refused         |
| `definition` | `SchemaDefinition` — the revisioned field list, its `id()`, `digest()` and `signature`           |
| `app_id`     | `AppId` — an app's reverse-domain id, which is not a schema's identity                           |
| `field`      | `FieldType`, `SchemaField` — column type declarations                                            |
| `capability` | `CapabilityGrant`, `CapabilitySet` — minimum-surface access declarations and runtime checking    |
| `core`       | `CoreSchema` — the core set, the files under `schemas/kotton/`, parsed at use                    |
| `petname`    | `Petnames`, `check` — the person's names for keys, the rules a petname keeps, and its reader     |
| `record_url` | `RecordUrl` — `kotton://records/<publisher>/<name>/<id>`                                         |

## The core set

The files under `schemas/kotton/`, one per schema, in the form a schema is published: its
publisher, its name, its revision, its fields and a description. Each is the protocol's file
of the same name under kotton-protocol's `schemas/kotton/`, but `petname`, which waits on a
pull request there; `cargo xtask schemas-check` holds every copy here to the protocol's file
byte for byte, or names it as not yet published.

```
notes               — title, body, tags, created_at, updated_at
contacts            — display_name, dids, emails, phones
calendar            — title, start_at, end_at, participants, location?
messages            — sender_did, body, thread_id, sent_at
tasks               — title, due_at?, completed, parent_task_id?
clipboard           — source_schema, source_id, snapshot_json, copied_at
message.v1          — the encrypted message envelope
channel.key-grant   — one epoch of a channel key, sealed to a member
model               — an installed model's manifest, and whether it is active
pin                 — retired; read once and moved into the device's own database
keeps-whole         — that one device keeps one drive whole
secret              — label, value, kind, note?
access-log          — device, at, asker, door, act, what
petname             — key, name
governance.record   — one record file of the project's board, as a row
```

Three of them, `secret`, `access-log` and `petname`, are kept from every app
(`CoreSchema::is_kept_from_apps`), a refusal held for those identities by name and not for
being core: no app is granted one, reads or writes a row of one, handles one, or finds one in
record search, and only the person's own terminal reaches them.

A core schema changes in this tree, not through registration. An app's schema is its
publisher's own: it forks a core schema by copying it and recording `forked_from`, which is
provenance and not a type relation.

## Petnames, and what a grant prompt says

The decision *A schema is named by the key that publishes it* has a grant prompt show a
schema's name as its publisher wrote it, and say who stands behind it only by the person's own
name for the publisher's key, or by its absence: "your *notes* records from **kotton**", or
"from a publisher you have not named". An app is shown the same way, by the key that signed its
manifest, and an app with no `[publisher]` block is "from an app nobody signed". A string a
publisher or an app chose is never shown as who stands behind anything.

That name is a petname, a record of `petname` in Personal: `key`, a `did:key`, and `name`, one
record per key. `petname::check` holds a body to its rules: `key` parses as a `did:key`, and
`name` is not empty, at most 64 characters, holds no `/` and no control or
bidirectional-formatting character, does not begin with `did:`, and is `kotton` for Kotton's
publisher alone. The record daemon asks it at insert, and `Petnames::from_records`, the reader,
asks it of every stored record, so one that breaks a rule (written before the rule, or merged
from another device) is never a name. `kotton` names Kotton's publisher on every device with no
record, and a record for that key replaces it. Because a prompt trusts what a petname says,
`petname` is kept from every app: nothing but the person's own terminal writes one.
