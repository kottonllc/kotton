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
| `record_url` | `RecordUrl` — `kotton://records/<publisher>/<name>/<id>`                                         |

## The core set

The files under `schemas/kotton/`, one per schema, in the form a schema is published: its
publisher, its name, its revision, its fields and a description. Three are the protocol's
(`secret`, `keeps-whole`, `access-log`, from kotton-protocol's `schemas/kotton/`) and the rest
are today's set republished under the release key, each to join the protocol by a pull
request there; `cargo xtask schemas-check` holds every copy here to the protocol's file of the
same name byte for byte, or names it as not yet published.

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
governance.record   — one record file of the project's board, as a row
```

A core schema changes in this tree, not through registration. An app's schema is its
publisher's own: it forks a core schema by copying it and recording `forked_from`, which is
provenance and not a type relation.
