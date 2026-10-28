// SPDX-License-Identifier: AGPL-3.0-or-later
//! Core schemas — the standard schemas compiled into the daemon binary.
//!
//! These are the common vocabulary that apps and the AI use to interoperate.
//! Core schemas are:
//! - Narrow: only fields every implementation needs
//! - Sealed: nobody modifies `sh.kotton.*` — apps extend via [`SchemaDefinition::extends`]
//! - Versioned with the daemon binary — updated via daemon release cycles
//!
//! | Schema                        | Purpose                                    |
//! |-------------------------------|--------------------------------------------|
//! | `sh.kotton.notes`             | Titled text notes with tags                |
//! | `sh.kotton.contacts`          | Person identity and contact details        |
//! | `sh.kotton.calendar`          | Timed events with participants             |
//! | `sh.kotton.messages`          | Chat messages in threads                   |
//! | `sh.kotton.tasks`             | Completable work items                     |
//! | `sh.kotton.clipboard`         | Snapshots of records the user has copied   |
//! | `sh.kotton.message.v1`        | Opaque encrypted message envelope          |
//! | `sh.kotton.channel.key-grant` | A channel key sealed to a new member's DID |
//! | `sh.kotton.model`             | An installed model's manifest              |
//! | `sh.kotton.pin`               | What one of the person's devices keeps     |
//!
//! The table is gated against [`CoreSchema::all`] in this module's tests, so it
//! cannot drift from the set again. It had drifted to three different counts at
//! once: a five-row table, prose saying six, and a test named for five that
//! asserted eight.

use crate::{
    definition::SchemaDefinition,
    field::{FieldType, SchemaField},
    nsid::Nsid,
};
use kotton_common::namespace as ns;
use serde_json::json;

/// Enumeration of the core schemas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoreSchema {
    Notes,
    Contacts,
    Calendar,
    Messages,
    Tasks,
    /// Clipboard entries — structured snapshots of records the user has copied.
    ///
    /// Each entry records what was copied (`source_nsid`, `source_id`), a
    /// JSON snapshot of the record body at copy time, and when it was copied.
    Clipboard,
    /// Encrypted peer-to-peer and channel message envelope (M34+).
    ///
    /// The daemon stores and relays these opaque encrypted envelopes without
    /// being able to read the plaintext.  Decryption is always client-side.
    MessageV1,
    /// Channel key-grant envelope — distributes a channel symmetric key to a
    /// new member encrypted to their DID public key (X25519 ECDH, M34+).
    ChannelKeyGrant,
    /// An installed model's manifest (RFC-0085 *The model as content*,
    /// `DEC-0073`).
    ///
    /// **Why this is in the core set and not a locally declared shape.** The
    /// importer's fork is deliberately *not* `sh.kotton.*`, because a shape an
    /// importer declares is not the commons — and the consequence written down
    /// beside it is the reason this one has to be: *"a device that has never
    /// seen the declaration skips the rows"*
    /// (`kotton_record::replication::apply_record_segments`). A model's manifest
    /// has to arrive on a second device, which is half of RFC-0085's first Done
    /// criterion, so its declaration must already be on every device. Core
    /// schemas are *"versioned with the daemon binary"*, which is exactly what
    /// this shape is: the daemon writes it, the daemon reads it, and no app
    /// negotiates over it — the standing `MessageV1` and `ChannelKeyGrant`
    /// already have.
    Model,
    /// One pin setting: what one of the person's devices keeps of their
    /// drives (kotton #55). Core for the reason [`CoreSchema::Model`] is: the
    /// daemon writes it and reads it, and it must arrive on every device of
    /// the person's, whose declaration has to be there before it does.
    Pin,
}

impl CoreSchema {
    /// Return all core schemas in a stable order.
    pub fn all() -> &'static [CoreSchema] {
        &[
            CoreSchema::Notes,
            CoreSchema::Contacts,
            CoreSchema::Calendar,
            CoreSchema::Messages,
            CoreSchema::Tasks,
            CoreSchema::Clipboard,
            CoreSchema::MessageV1,
            CoreSchema::ChannelKeyGrant,
            CoreSchema::Model,
            CoreSchema::Pin,
        ]
    }

    /// Return the NSID for this core schema.
    pub fn nsid(self) -> Nsid {
        Nsid::from_static(match self {
            CoreSchema::Notes => ns::NSID_NOTES,
            CoreSchema::Contacts => ns::NSID_CONTACTS,
            CoreSchema::Calendar => ns::NSID_CALENDAR,
            CoreSchema::Messages => ns::NSID_MESSAGES,
            CoreSchema::Tasks => ns::NSID_TASKS,
            CoreSchema::Clipboard => ns::NSID_CLIPBOARD,
            CoreSchema::MessageV1 => ns::NSID_MESSAGE_V1,
            CoreSchema::ChannelKeyGrant => ns::NSID_CHANNEL_KEY_GRANT,
            CoreSchema::Model => ns::NSID_MODEL,
            CoreSchema::Pin => ns::NSID_PIN,
        })
    }

    /// Return the full [`SchemaDefinition`] for this core schema.
    pub fn definition(self) -> SchemaDefinition {
        match self {
            CoreSchema::Notes => notes(),
            CoreSchema::Contacts => contacts(),
            CoreSchema::Calendar => calendar(),
            CoreSchema::Messages => messages(),
            CoreSchema::Tasks => tasks(),
            CoreSchema::Clipboard => clipboard(),
            CoreSchema::MessageV1 => message_v1(),
            CoreSchema::ChannelKeyGrant => channel_key_grant(),
            CoreSchema::Model => model(),
            CoreSchema::Pin => pin(),
        }
    }
}

// ---------------------------------------------------------------------------
// Schema definitions
// ---------------------------------------------------------------------------

fn notes() -> SchemaDefinition {
    SchemaDefinition::new(
        Nsid::from_static(ns::NSID_NOTES),
        1,
        vec![
            SchemaField::required("title", FieldType::String),
            SchemaField::required("body", FieldType::String),
            SchemaField::required("tags", FieldType::List(Box::new(FieldType::String))),
            SchemaField::required("created_at", FieldType::Datetime),
            SchemaField::required("updated_at", FieldType::Datetime),
        ],
    )
    .with_description("Titled text notes with optional tags.")
}

fn contacts() -> SchemaDefinition {
    SchemaDefinition::new(
        Nsid::from_static(ns::NSID_CONTACTS),
        1,
        vec![
            SchemaField::required("display_name", FieldType::String),
            SchemaField::required("dids", FieldType::List(Box::new(FieldType::String))),
            SchemaField::required("emails", FieldType::List(Box::new(FieldType::String))),
            SchemaField::required("phones", FieldType::List(Box::new(FieldType::String))),
        ],
    )
    .with_description("Person identity and contact details.")
}

fn calendar() -> SchemaDefinition {
    SchemaDefinition::new(
        Nsid::from_static(ns::NSID_CALENDAR),
        1,
        vec![
            SchemaField::required("title", FieldType::String),
            SchemaField::required("start_at", FieldType::Datetime),
            SchemaField::required("end_at", FieldType::Datetime),
            SchemaField::required("participants", FieldType::List(Box::new(FieldType::String))),
            SchemaField::nullable("location", FieldType::String),
        ],
    )
    .with_description("Timed calendar events with optional location and participants.")
}

fn messages() -> SchemaDefinition {
    SchemaDefinition::new(
        Nsid::from_static(ns::NSID_MESSAGES),
        1,
        vec![
            SchemaField::required("sender_did", FieldType::String),
            SchemaField::required("body", FieldType::String),
            SchemaField::required("thread_id", FieldType::String),
            SchemaField::required("sent_at", FieldType::Datetime),
        ],
    )
    .with_description("Chat messages in threads, identified by sender DID.")
}

fn tasks() -> SchemaDefinition {
    SchemaDefinition::new(
        Nsid::from_static(ns::NSID_TASKS),
        1,
        vec![
            SchemaField::required("title", FieldType::String),
            SchemaField::nullable("due_at", FieldType::Datetime),
            SchemaField::with_default("completed", FieldType::Bool, json!(false)),
            SchemaField::nullable("parent_task_id", FieldType::String),
        ],
    )
    .with_description("Completable work items, optionally nested.")
}

fn clipboard() -> SchemaDefinition {
    SchemaDefinition::new(
        Nsid::from_static(ns::NSID_CLIPBOARD),
        1,
        vec![
            SchemaField::required("source_nsid", FieldType::String),
            SchemaField::required("source_id", FieldType::String),
            SchemaField::required("snapshot_json", FieldType::String),
            SchemaField::required("copied_at", FieldType::Datetime),
        ],
    )
    .with_description(
        "Clipboard entries — a structured snapshot of a record the user has copied, \
         anchored to its source NSID and record ID.",
    )
}

/// Encrypted peer-to-peer / channel message envelope (M34).
///
/// The daemon stores these opaque envelopes without holding any decryption key.
/// All plaintext operations happen client-side.
///
/// Sender-side encryption (DM): ephemeral X25519 ECDH → HKDF-SHA-256 → 32-byte
/// symmetric key → ChaCha20-Poly1305 seal.
///
/// Sender-side encryption (channel): ChaCha20-Poly1305 with the pre-distributed
/// channel symmetric key (`channel_key` from `sh.kotton.channel.key-grant`).
fn message_v1() -> SchemaDefinition {
    SchemaDefinition::new(
        Nsid::from_static(ns::NSID_MESSAGE_V1),
        1,
        vec![
            // Routing
            SchemaField::required("from_did", FieldType::String),
            SchemaField::nullable("to_did", FieldType::String),
            SchemaField::nullable("channel_did", FieldType::String),
            // Threading
            SchemaField::required("thread_id", FieldType::String),
            // Encrypted payload
            SchemaField::required("body", FieldType::String), // base64 ciphertext
            SchemaField::required("nonce", FieldType::String), // base64 12 bytes
            SchemaField::nullable("ephemeral_pub", FieldType::String), // base64 32 bytes (DM only)
            // Which channel key epoch sealed this message. Null for DMs, which
            // have no channel key. Absent on a channel message means epoch 0 —
            // every message written before epochs existed belongs to the
            // channel's first key.
            SchemaField::nullable("epoch", FieldType::Int),
            // Metadata
            SchemaField::required("sent_at", FieldType::Int), // unix seconds u64
            // "text" | "share" (a file handed to a person, RFC-0090: the body is
            // its manifest) | "attachment_ref" (declared; nothing produces it)
            SchemaField::required("type", FieldType::String),
        ],
    )
    .with_description(
        "Encrypted peer-to-peer or channel message envelope. \
         The daemon stores and relays opaque ciphertext; decryption is always client-side.",
    )
}

/// Channel key-grant envelope (M34).
///
/// The channel creator sends one of these to every new member.  The hosting node
/// relays the encrypted blob without being able to read its contents.
///
/// A channel key belongs to an **epoch**. Every membership change mints a new
/// epoch and distributes a fresh key, so which epochs a member holds grants is
/// exactly which stretch of the conversation they can read. One member therefore
/// holds several of these for one channel — one per epoch they were granted.
fn channel_key_grant() -> SchemaDefinition {
    SchemaDefinition::new(
        Nsid::from_static(ns::NSID_CHANNEL_KEY_GRANT),
        1,
        vec![
            SchemaField::required("channel_did", FieldType::String),
            SchemaField::required("to_did", FieldType::String),
            SchemaField::required("enc_key", FieldType::String), // base64 ChaCha enc of 32-byte key
            SchemaField::required("nonce", FieldType::String),   // base64 12 bytes
            SchemaField::required("ephemeral_pub", FieldType::String), // base64 32 bytes
            // Which channel key this grant carries. Required of every writer;
            // absent only on grants written before epochs existed, which are
            // read as epoch 0 so an existing conversation stays readable by the
            // people already in it.
            SchemaField::required("epoch", FieldType::Int),
            SchemaField::required("granted_at", FieldType::Int), // unix seconds u64
            // The epoch's roster — every member its key was granted to, each as
            // `{did, key, reach, kel}`: the identity key, the reach note and the
            // key log the minting member held for them, the key believed only
            // when the log yields it (since 2026-10-09; DIDs alone before) —
            // sealed under that epoch's channel key by whoever minted it
            // (base64 ciphertext and its 12-byte nonce). Opened by unwrapping this grant's key and
            // nothing else, so only the key's holders learn who else holds it
            // and how to reach them (RFC-0064, the notes of 2026-10-08 and
            // 2026-10-09). Null on a grant minted before rosters, whose
            // membership is counted instead. The field stays one string: the
            // shape is inside the seal.
            SchemaField::nullable("roster", FieldType::String),
            SchemaField::nullable("roster_nonce", FieldType::String),
        ],
    )
    .with_description(
        "Channel key-grant envelope — distributes one epoch of the channel symmetric key to a \
         member, encrypted to their DID public key (X25519 ECDH). \
         The hosting node relays these as opaque blobs and cannot decrypt them.",
    )
}

/// One pin setting (kotton #55; kotton-protocol #20's record): `device`, the
/// DID of the device it is about; `scope`, `default`, `drive` or `folder`, with
/// `drive` naming the drive for the last two and `folder` the folder for the
/// last; and `value`, `whole` or `on-demand`. The record id is derived from the
/// device and the scope, so a device setting a scope again replaces its one
/// record for it, and `default` at a drive or folder is that record deleted.
/// Field for field `kotton_wire::ipc::PinSetting`, flattened, because a scope is
/// three cases and a record's fields are one shape.
fn pin() -> SchemaDefinition {
    SchemaDefinition::new(
        Nsid::from_static(ns::NSID_PIN),
        1,
        vec![
            SchemaField::required("device", FieldType::String),
            SchemaField::required("scope", FieldType::String),
            SchemaField::nullable("drive", FieldType::String),
            SchemaField::nullable("folder", FieldType::String),
            SchemaField::required("value", FieldType::String),
        ],
    )
    .with_description("What one of the person's devices keeps of their drives: its default, or a drive or folder set the other way.")
}

/// An installed model (RFC-0085, `DEC-0073`).
///
/// The first twelve fields are [`crate::ModelManifest`]'s, name for name, so a
/// record body deserialises straight back into a manifest and the manifest is
/// what gets stored, unchanged in shape; a test in [`crate::model_manifest`]
/// holds the two together. `licence` is the facet `DEC-0043`
/// added [`FieldType::Record`] for, rather than two flattened columns, because
/// it is one thing — an identifier and the hash of the text it names.
///
/// The last two are the host's and could not be the manifest's: a manifest
/// describes a model, and *which* installed model answers is a fact about this
/// person's installation. `active` is `DEC-0073`'s rule — *"One model per kind
/// is active, and the person chooses it"* — held as a field rather than as a
/// pointer somewhere else, so the choice travels with the model to every device
/// the person owns.
fn model() -> SchemaDefinition {
    SchemaDefinition::new(
        Nsid::from_static(ns::NSID_MODEL),
        1,
        vec![
            // ── `ModelManifest`, field for field ─────────────────────────────
            SchemaField::required("name", FieldType::String),
            SchemaField::required("version", FieldType::String),
            // The model's identity: the BLAKE3 hex of the sealed weights.
            SchemaField::required("weights", FieldType::String),
            SchemaField::required("format", FieldType::String),
            SchemaField::required("kind", FieldType::String),
            SchemaField::required("parameters", FieldType::Int),
            SchemaField::required("quantisation", FieldType::String),
            SchemaField::required("size", FieldType::Int),
            SchemaField::required("context_window", FieldType::Int),
            SchemaField::required("template", FieldType::String),
            SchemaField::required(
                "licence",
                FieldType::Record(vec![
                    SchemaField::required("spdx", FieldType::String),
                    SchemaField::required("text_hash", FieldType::String),
                ]),
            ),
            // A display string, never a signature Kotton makes (`DEC-0073`).
            SchemaField::nullable("publisher", FieldType::String),
            // ── The host's two ──────────────────────────────────────────────
            SchemaField::with_default("active", FieldType::Bool, json!(false)),
            SchemaField::required("installed_at", FieldType::Datetime),
        ],
    )
    .with_description(
        "An installed model: its manifest, whether it is the active model of its kind, \
         and when the person installed it. The weights are a sealed object this record \
         names by hash.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_core_schema_is_in_all_and_in_the_module_table() {
        assert_eq!(CoreSchema::all().len(), 10);
        for schema in CoreSchema::all() {
            let def = schema.definition();
            assert!(!def.fields.is_empty(), "{} has no fields", def.nsid);
            assert_eq!(def.version, 1);
            assert_eq!(def.nsid, schema.nsid());
        }

        // The module table is the first thing anyone reads about the core set,
        // and it had drifted to three different counts at once. A prose table
        // nobody checks is how that happens — so this checks it.
        let table: Vec<&str> = include_str!("core.rs")
            .lines()
            // The module's doc block, after the SPDX line the file opens with.
            .skip_while(|l| !l.starts_with("//!"))
            .take_while(|l| l.starts_with("//!"))
            .filter(|l| l.contains("| `sh.kotton."))
            .collect();
        assert_eq!(
            table.len(),
            CoreSchema::all().len(),
            "the module table has {} rows for {} core schemas",
            table.len(),
            CoreSchema::all().len()
        );
        for schema in CoreSchema::all() {
            let nsid = schema.nsid();
            let needle = format!("`{}`", nsid.as_str());
            assert!(
                table.iter().any(|row| row.contains(&needle)),
                "{nsid} is a core schema but has no row in the module table"
            );
        }
    }

    #[test]
    fn notes_has_required_fields() {
        let def = CoreSchema::Notes.definition();
        assert!(def.field("title").is_some());
        assert!(def.field("body").is_some());
        assert!(def.field("tags").is_some());
        assert!(def.field("created_at").is_some());
        assert!(def.field("updated_at").is_some());
    }

    #[test]
    fn tasks_completed_has_default() {
        let def = CoreSchema::Tasks.definition();
        let f = def.field("completed").expect("completed field");
        assert_eq!(f.default, Some(serde_json::json!(false)));
    }

    #[test]
    fn nsid_roundtrip() {
        for schema in CoreSchema::all() {
            let nsid = schema.nsid();
            assert!(nsid.as_str().starts_with("sh.kotton."));
        }
    }
}
