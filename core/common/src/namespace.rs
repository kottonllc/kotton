// SPDX-License-Identifier: AGPL-3.0-or-later
//! Kotton's schema identities.
//!
//! A schema is named by the key that publishes it: its identity is `<publisher>/<name>`,
//! the publisher being the `did:key` of the key that publishes it and signs its definition
//! (the protocol's decision *A schema is named by the key that publishes it*). Kotton's own
//! schemas are published under Kotton's release key, the key that signs a release
//! (`infra/release/allowed_signers`), which is [`NSID_PREFIX`]; every identity below is that
//! key and a name. Nothing resolves, registers or reserves a name, and "core" means present
//! on every device and nothing more.
//!
//! The constants keep the `NSID_` names they had when the identity was a reverse-domain
//! string: forty files use them, and the rename is a hygiene pass of its own, after the
//! identity itself has landed. Their values are the new identities.

/// Kotton's publisher: the `did:key` of the release key, the public half the first line of
/// `infra/release/allowed_signers` carries. A test in `kotton-crypto` derives it from that
/// file.
pub const NSID_PREFIX: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB";

/// The primary Kotton domain (forward form).
pub const APP_DOMAIN: &str = "kotton.sh";

// ── Core schema identities ────────────────────────────────────────────────────

pub const NSID_NOTES: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes";
pub const NSID_CONTACTS: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/contacts";
pub const NSID_CALENDAR: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/calendar";
pub const NSID_MESSAGES: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/messages";
pub const NSID_TASKS: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/tasks";
pub const NSID_CLIPBOARD: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/clipboard";

/// Peer-to-peer and channel messages — encrypted transport envelope.
///
/// Body fields: `from_did`, `to_did` (null for channel messages),
/// `channel_did` (null for DMs), `body` (base64 ChaCha20-Poly1305 ciphertext),
/// `nonce` (base64 12 bytes), `ephemeral_pub` (base64 X25519 32 bytes, null
/// for channel messages using the channel symmetric key), `sent_at` (u64 unix
/// seconds), `type` ("text" | "attachment_ref").
pub const NSID_MESSAGE_V1: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/message.v1";

/// Channel key-grant envelope — distributes a channel's symmetric key to a member.
///
/// The hosting node relays these as opaque blobs; it never holds a key that
/// decrypts them.  Body fields: `channel_did`, `to_did`, `enc_key` (base64
/// X25519-ECDH-encrypted channel key), `nonce` (base64), `ephemeral_pub`
/// (base64), `granted_at` (u64 unix seconds).
pub const NSID_CHANNEL_KEY_GRANT: &str =
    "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/channel.key-grant";

/// An installed model's manifest — the record half of a model (RFC-0085,
/// *The model as content*; `DEC-0073`).
///
/// The record *is* `kotton_schemas::ModelManifest`'s fields, plus the two the
/// host owns and the manifest cannot carry: `active` (one model per kind
/// answers, chosen by the person) and `installed_at`. Its record id is the
/// weights hash, because that hash is what a model *is* — two manifests naming
/// it describe the same model however they spell the name.
pub const NSID_MODEL: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/model";

/// One pin setting as kotton #155 wrote it, a record in the person's drive.
/// **Retired** (kotton #171, kotton-protocol #26): a pin setting is the
/// device's own, kept in its own database, and nothing of it replicates. The
/// identity stays declared so the device that wrote such a record can read it once,
/// move it into its own database and delete it from the drive
/// (`kotton_device::users::pins::migrate`).
pub const NSID_PIN: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/pin";

/// A whole-keeper claim: that one of the person's devices keeps one drive
/// whole (kotton #171; the protocol's storage model, kotton-protocol #26). A sealed record in that drive, written by that device alone and
/// deleted when it stops keeping the drive whole; its fields are the device and
/// the drive's id, and nothing else. The daemon writes it, and every device of
/// the person's reads every device's, which is why it is core: a device that
/// has never seen a declaration skips the rows.
pub const NSID_KEEPS_WHOLE: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/keeps-whole";

/// A password or a token in the person's keychain (the protocol's `schemas/kotton/secret`):
/// `label`, `value`, `kind` (`password` or `token`) and `note`. Registered, and kept from
/// every app by its identity (`kotton_schemas::CoreSchema::is_kept_from_apps`): no app is
/// granted it, reads or writes it, or handles it, and record search returns none of it. The
/// person reaches it with the `secret` verbs, in Personal.
pub const NSID_SECRET: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/secret";

/// One thing a device's daemon was asked (the protocol's `schemas/kotton/access-log`):
/// `device`, `at`, `asker`, `door`, `act` and `what`. Kept on that device, and in a drive
/// only when the person pins the log there. Kept from every app as `secret` is, and published
/// and not registered yet: no record can be put under it until #450, the access log's issue.
pub const NSID_ACCESS_LOG: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/access-log";

/// A governance record: one record file of the project's board as a row (RFC-0088), the
/// schema `client/record-file` converts to and from. Core because Kotton's own records app
/// and converter read it on every device of a project's members, and a schema of Kotton's
/// that must be on a device before the first tag can only travel compiled in.
pub const NSID_GOVERNANCE_RECORD: &str =
    "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/governance.record";

// ── Meta schema identity (schema publication) ────────────────────────────────

/// The identity of the shape an `.ics` import writes its events as: Kotton's, and not in
/// the core set. `calendar` has no field for an event's recurrence rule, zone, all-day flag
/// or `UID`, and it is published, so the reader writes this fork of it instead; the daemon
/// declares it on the device that imports (`kotton_record::import_cmds`). It is here, beside
/// the core identities, so a client can name it without reaching into the daemon.
pub const NSID_IMPORTED_CALENDAR: &str =
    "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/import.calendar.event";

/// The identity of a schema publication record.
///
/// A `meta.schema` record body contains the full `SchemaDefinition` JSON for a third-party
/// schema, signed by its publisher. Declared and not defined: no definition of it is in the
/// core set, and nothing writes one.
pub const NSID_META_SCHEMA: &str = "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/meta.schema";

#[cfg(test)]
mod tests {
    use super::*;

    /// Every identity is Kotton's publisher, a `/`, and a name.
    #[test]
    fn every_identity_is_under_kottons_publisher() {
        for (id, name) in [
            (NSID_NOTES, "notes"),
            (NSID_CONTACTS, "contacts"),
            (NSID_CALENDAR, "calendar"),
            (NSID_MESSAGES, "messages"),
            (NSID_TASKS, "tasks"),
            (NSID_CLIPBOARD, "clipboard"),
            (NSID_MESSAGE_V1, "message.v1"),
            (NSID_CHANNEL_KEY_GRANT, "channel.key-grant"),
            (NSID_MODEL, "model"),
            (NSID_PIN, "pin"),
            (NSID_KEEPS_WHOLE, "keeps-whole"),
            (NSID_SECRET, "secret"),
            (NSID_ACCESS_LOG, "access-log"),
            (NSID_GOVERNANCE_RECORD, "governance.record"),
            (NSID_META_SCHEMA, "meta.schema"),
            (NSID_IMPORTED_CALENDAR, "import.calendar.event"),
        ] {
            assert_eq!(id, format!("{NSID_PREFIX}/{name}"));
        }
    }
}
