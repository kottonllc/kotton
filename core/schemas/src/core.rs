// SPDX-License-Identifier: AGPL-3.0-or-later
//! Core schemas — the schemas compiled into the daemon binary.
//!
//! The core set is the files under `core/schemas/schemas/kotton/`, each one schema's
//! definition as it is published: `publisher`, `name`, `revision`, `fields` and
//! `description`. They are the protocol's files (kotton-protocol's `schemas/kotton/`),
//! published under Kotton's release key, the key that signs a release; `cargo xtask
//! schemas-check` holds each copy here to the protocol's byte for byte, or names it as not
//! yet published there. A schema is named by the key that publishes it (the protocol's
//! decision of that title), so every identity here is that key and a name.
//!
//! **Core means present on every device, and nothing more.** A core schema has no reach
//! another schema lacks and refuses nothing another does not; it is compiled in because the
//! daemon writes it and reads it on every device of a person's, and a device that has never
//! seen a declaration skips its rows. Two identities among them, `secret` and `access-log`,
//! are kept from every app ([`CoreSchema::is_kept_from_apps`]): a refusal held for those two
//! by name, not for being core. Before the first tag the files carry no `signature`, as
//! the decision says: nothing depends on a schema by version yet, the release key never
//! leaves the maintainer's machine, and the files are what every page of the protocol is, a
//! change the maintainer signed off. The registry admits them as core without one.
//!
//! | Schema               | Purpose                                                   |
//! |----------------------|-----------------------------------------------------------|
//! | `notes`              | Titled text notes with tags                               |
//! | `contacts`           | Person identity and contact details                       |
//! | `calendar`           | Timed events with participants                            |
//! | `messages`           | Chat messages in threads                                  |
//! | `tasks`              | Completable work items                                    |
//! | `clipboard`          | Snapshots of records the user has copied                  |
//! | `message.v1`         | Opaque encrypted message envelope                         |
//! | `channel.key-grant`  | A channel key sealed to a new member's DID                |
//! | `model`              | An installed model's manifest                             |
//! | `pin`                | Retired: a setting #155 kept in a drive                   |
//! | `keeps-whole`        | That a device keeps a drive whole                         |
//! | `secret`             | A password or a token in the person's keychain            |
//! | `access-log`         | One thing a device's daemon was asked                     |
//! | `governance.record`  | One record file of the project's board, as a row          |
//!
//! The table is gated against [`CoreSchema::all`] in this module's tests, so it
//! cannot drift from the set again. It had drifted to three different counts at
//! once: a five-row table, prose saying six, and a test named for five that
//! asserted eight. The same tests hold the set to the directory, both ways.

use crate::{definition::SchemaDefinition, schema_id::SchemaId};
use kotton_common::namespace as ns;

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
    /// Each entry records what was copied (`source_schema`, `source_id`), a
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
    /// importer's fork is deliberately not core, because a shape an
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
    /// One pin setting as kotton #155 wrote it, a record in the person's
    /// drive. **Retired** (kotton #171, kotton-protocol #26): a setting is the
    /// device's own and is kept in its own database. Declared still so that
    /// the device that wrote one can read it once, move it there and delete
    /// it from the drive (`kotton_device::users::pins::migrate`); nothing
    /// writes one.
    Pin,
    /// A whole-keeper claim: that one of the person's devices keeps one drive
    /// whole (kotton #171; the protocol's storage model, kotton-protocol #26). A
    /// record in that drive, written and withdrawn by that device alone.
    /// Core for the reason [`CoreSchema::Model`] is: the daemon writes it and
    /// reads it, and it must arrive on every device of the person's.
    KeepsWhole,
    /// A password or a token in the person's keychain: `label`, `value`, `kind`
    /// (`password` or `token`) and `note`. Registered, and kept from every app
    /// ([`CoreSchema::is_kept_from_apps`]): no app is granted it, reads or writes a row of
    /// it, or handles it, and record search returns none of its rows. The person reaches it
    /// with the `secret` verbs at their own terminal, which read and write Personal alone.
    Secret,
    /// One thing a device's daemon was asked: `device`, `at`, `asker`, `door`,
    /// `act` and `what`. Kept on that device, and in a drive only when the
    /// person pins the log there. Kept from every app as `secret` is
    /// ([`CoreSchema::is_kept_from_apps`]), and published and not registered yet
    /// ([`CoreSchema::is_held_back`]): no record can be put under it until the access
    /// log's own change (#450), which builds on this declaration.
    AccessLog,
    /// A governance record: one record file of the project's board as a row
    /// (RFC-0088), the schema `client/record-file` converts to and from. Core
    /// because Kotton's own records app and converter read it on every device
    /// of a project's members, and a schema of Kotton's that must be on a
    /// device before the first tag can only travel compiled in: a definition
    /// a request carries is checked against its publisher's signature, and the
    /// release key signs nothing until then.
    GovernanceRecord,
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
            CoreSchema::KeepsWhole,
            CoreSchema::Secret,
            CoreSchema::AccessLog,
            CoreSchema::GovernanceRecord,
        ]
    }

    /// Return `true` for a core schema that is published and not yet registered:
    /// `access-log`. Its file is here and its identity is core, so `schema register` refuses
    /// it, but the registry does not admit it: a schema in the registry is one a record can
    /// be put under. It is held back until the access log's own change (#450). `secret` was
    /// held back with it until its refusal to apps ([`CoreSchema::is_kept_from_apps`]) was
    /// built (#449).
    pub fn is_held_back(self) -> bool {
        matches!(self, CoreSchema::AccessLog)
    }

    /// Return `true` for a core schema kept from every app: `secret` and `access-log`.
    ///
    /// A schema is named by the key that publishes it (the protocol's decision of that
    /// title), and these two identities, under Kotton's release key, are refused to every
    /// app: no app is granted either, reads or writes a row of either whatever grant is
    /// stored, claims to handle either, or finds a row of either in record search. Only the
    /// person's own terminal reaches them. **The refusal is held for these identities by
    /// name, and is not a property of being core:** being core confers nothing (module doc),
    /// and another core schema is reachable by an app exactly as any schema is. Every place
    /// an app could reach a schema asks [`CoreSchema::kept_from_apps`].
    pub fn is_kept_from_apps(self) -> bool {
        matches!(self, CoreSchema::Secret | CoreSchema::AccessLog)
    }

    /// The core schema kept from apps ([`CoreSchema::is_kept_from_apps`]) that `nsid` names,
    /// or `None`. Asked of the whole identity, parsed, so a string that is not an identity
    /// names none and a name under another publisher is that publisher's own schema.
    pub fn kept_from_apps(nsid: &str) -> Option<CoreSchema> {
        let id = SchemaId::parse(nsid).ok()?;
        CoreSchema::all().iter().copied().find(|cs| cs.is_kept_from_apps() && cs.id() == id)
    }

    /// What an app is told when it reaches for this schema, kept from it: one sentence that
    /// names the schema, for every site that refuses it.
    pub fn kept_from_apps_refusal(self) -> String {
        format!(
            "{} is kept from every app: no app is granted it, reads or writes it, or handles it; \
             only the person's own terminal reaches it",
            self.id()
        )
    }

    /// What a connection that is not the person's own terminal is told when it reaches for this
    /// schema, kept from apps: a remote or paired session naming no app is refused as an app
    /// is, in one sentence that names the schema.
    pub fn kept_off_terminal_refusal(self) -> String {
        format!(
            "{} is the person's own terminal's: it is answered only to a client on this \
             device's own socket, never to a remote or paired session",
            self.id()
        )
    }

    /// Return the identity of this core schema: Kotton's publisher and its name.
    pub fn id(self) -> SchemaId {
        SchemaId::from_static(match self {
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
            CoreSchema::KeepsWhole => ns::NSID_KEEPS_WHOLE,
            CoreSchema::Secret => ns::NSID_SECRET,
            CoreSchema::AccessLog => ns::NSID_ACCESS_LOG,
            CoreSchema::GovernanceRecord => ns::NSID_GOVERNANCE_RECORD,
        })
    }

    /// The file this core schema is published as, under `core/schemas/schemas/kotton/`.
    pub fn file(self) -> &'static str {
        match self {
            CoreSchema::Notes => include_str!("../schemas/kotton/notes.json"),
            CoreSchema::Contacts => include_str!("../schemas/kotton/contacts.json"),
            CoreSchema::Calendar => include_str!("../schemas/kotton/calendar.json"),
            CoreSchema::Messages => include_str!("../schemas/kotton/messages.json"),
            CoreSchema::Tasks => include_str!("../schemas/kotton/tasks.json"),
            CoreSchema::Clipboard => include_str!("../schemas/kotton/clipboard.json"),
            CoreSchema::MessageV1 => include_str!("../schemas/kotton/message.v1.json"),
            CoreSchema::ChannelKeyGrant => include_str!("../schemas/kotton/channel.key-grant.json"),
            CoreSchema::Model => include_str!("../schemas/kotton/model.json"),
            CoreSchema::Pin => include_str!("../schemas/kotton/pin.json"),
            CoreSchema::KeepsWhole => include_str!("../schemas/kotton/keeps-whole.json"),
            CoreSchema::Secret => include_str!("../schemas/kotton/secret.json"),
            CoreSchema::AccessLog => include_str!("../schemas/kotton/access-log.json"),
            CoreSchema::GovernanceRecord => include_str!("../schemas/kotton/governance.record.json"),
        }
    }

    /// Return the full [`SchemaDefinition`] for this core schema, parsed from its file.
    ///
    /// # Panics
    /// Panics if the file does not parse or is not the schema it is named for: the files are
    /// compiled in, and a test holds every one, so a panic here is a defect in the tree and
    /// never an input's.
    pub fn definition(self) -> SchemaDefinition {
        let def: SchemaDefinition = serde_json::from_str(self.file())
            .unwrap_or_else(|e| panic!("the core schema file for {self:?} does not parse: {e}"));
        assert_eq!(def.id(), self.id(), "the core schema file for {self:?} is another schema's");
        def
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names of the files under `core/schemas/schemas/kotton/`, sorted.
    fn files_in_the_directory() -> Vec<String> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/kotton");
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        names
    }

    /// Every file parses as the schema it is named for, under Kotton's publisher, at
    /// revision 1, unsigned before the first tag; and the set and the directory are one
    /// list, both ways.
    #[test]
    fn every_file_parses_and_the_set_is_the_directory_both_ways() {
        let mut named: Vec<String> = Vec::new();
        for schema in CoreSchema::all() {
            let def = schema.definition();
            assert!(!def.fields.is_empty(), "{} has no fields", def.id());
            assert_eq!(def.revision, 1);
            assert_eq!(def.publisher.as_str(), ns::NSID_PREFIX);
            assert!(def.signature.is_none(), "{}: unsigned before the first tag", def.id());
            assert!(def.forked_from.is_none(), "{}: a core schema is nobody's fork", def.id());
            assert!(def.description.is_some(), "{}: a core schema says what it is", def.id());
            named.push(format!("{}.json", def.name));
            // The file is the definition indented for reading, and nothing else.
            let mut written = serde_json::to_string_pretty(&def).unwrap();
            written.push('\n');
            assert_eq!(schema.file(), written, "{}.json is not its definition pretty-printed", def.name);
        }
        named.sort();
        assert_eq!(named, files_in_the_directory(), "the set and the directory differ");
        assert_eq!(CoreSchema::all().len(), 14);
    }

    /// The module table is the first thing anyone reads about the core set,
    /// and it had drifted to three different counts at once. A prose table
    /// nobody checks is how that happens — so this checks it.
    #[test]
    fn the_module_table_is_the_set() {
        let table: Vec<&str> = include_str!("core.rs")
            .lines()
            // The module's doc block, after the SPDX line the file opens with.
            .skip_while(|l| !l.starts_with("//!"))
            .take_while(|l| l.starts_with("//!"))
            .filter(|l| l.starts_with("//! | `"))
            .collect();
        assert_eq!(
            table.len(),
            CoreSchema::all().len(),
            "the module table has {} rows for {} core schemas",
            table.len(),
            CoreSchema::all().len()
        );
        for schema in CoreSchema::all() {
            let id = schema.id();
            let needle = format!("| `{}`", id.name());
            assert!(
                table.iter().any(|row| row.contains(&needle)),
                "{id} is a core schema but has no row in the module table"
            );
        }
    }

    /// `secret` and `access-log` are kept from apps, by their whole identities; no other core
    /// schema is, a name of theirs under another key is not, and a string that is no identity
    /// names none. `secret` is registered now; `access-log` is still held back.
    #[test]
    fn two_identities_are_kept_from_apps_by_name() {
        let kept: Vec<CoreSchema> =
            CoreSchema::all().iter().copied().filter(|cs| cs.is_kept_from_apps()).collect();
        assert_eq!(kept, vec![CoreSchema::Secret, CoreSchema::AccessLog]);
        assert_eq!(CoreSchema::kept_from_apps(ns::NSID_SECRET), Some(CoreSchema::Secret));
        assert_eq!(CoreSchema::kept_from_apps(ns::NSID_ACCESS_LOG), Some(CoreSchema::AccessLog));
        assert_eq!(CoreSchema::kept_from_apps(ns::NSID_NOTES), None);
        let theirs = "did:key:z6MkeXBLjYiSvqnhFb6D7sHm8yKm4jV45wwBFRaatf1cfZ76/secret";
        assert_eq!(CoreSchema::kept_from_apps(theirs), None);
        assert_eq!(CoreSchema::kept_from_apps("secret"), None);
        assert!(CoreSchema::Secret.kept_from_apps_refusal().contains(ns::NSID_SECRET));
        assert!(!CoreSchema::Secret.is_held_back());
        assert!(CoreSchema::AccessLog.is_held_back());
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

    /// Every core identity is Kotton's publisher and a name, and every one has a digest: no
    /// core schema's default is a float.
    #[test]
    fn every_core_schema_is_kottons_and_has_a_digest() {
        for schema in CoreSchema::all() {
            let id = schema.id();
            assert_eq!(id.publisher().as_str(), ns::NSID_PREFIX);
            let def = schema.definition();
            let hex = def.digest_hex().unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(hex.len(), 64);
        }
    }
}
