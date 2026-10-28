// SPDX-License-Identifier: AGPL-3.0-or-later
//! Kotton namespace constants.
//!
//! All official Kotton schema NSIDs are rooted at [`NSID_PREFIX`]. Using these
//! constants (rather than inline strings) means a domain change only requires
//! editing this file.

/// The reverse-domain prefix for all Kotton-official schemas and apps.
///
/// Derived from the primary domain `kotton.sh`.
pub const NSID_PREFIX: &str = "sh.kotton";

/// The primary Kotton domain (forward form).
pub const APP_DOMAIN: &str = "kotton.sh";

// ── Core schema NSIDs ─────────────────────────────────────────────────────────

pub const NSID_NOTES: &str = "sh.kotton.notes";
pub const NSID_CONTACTS: &str = "sh.kotton.contacts";
pub const NSID_CALENDAR: &str = "sh.kotton.calendar";
pub const NSID_MESSAGES: &str = "sh.kotton.messages";
pub const NSID_TASKS: &str = "sh.kotton.tasks";
pub const NSID_CLIPBOARD: &str = "sh.kotton.clipboard";

/// Peer-to-peer and channel messages — encrypted transport envelope.
///
/// Body fields: `from_did`, `to_did` (null for channel messages),
/// `channel_did` (null for DMs), `body` (base64 ChaCha20-Poly1305 ciphertext),
/// `nonce` (base64 12 bytes), `ephemeral_pub` (base64 X25519 32 bytes, null
/// for channel messages using the channel symmetric key), `sent_at` (u64 unix
/// seconds), `type` ("text" | "attachment_ref").
pub const NSID_MESSAGE_V1: &str = "sh.kotton.message.v1";

/// Channel key-grant envelope — distributes a channel's symmetric key to a member.
///
/// The hosting node relays these as opaque blobs; it never holds a key that
/// decrypts them.  Body fields: `channel_did`, `to_did`, `enc_key` (base64
/// X25519-ECDH-encrypted channel key), `nonce` (base64), `ephemeral_pub`
/// (base64), `granted_at` (u64 unix seconds).
pub const NSID_CHANNEL_KEY_GRANT: &str = "sh.kotton.channel.key-grant";

/// An installed model's manifest — the record half of a model (RFC-0085,
/// *The model as content*; `DEC-0073`).
///
/// The record *is* `kotton_schemas::ModelManifest`'s fields, plus the two the
/// host owns and the manifest cannot carry: `active` (one model per kind
/// answers, chosen by the person) and `installed_at`. Its record id is the
/// weights hash, because that hash is what a model *is* — two manifests naming
/// it describe the same model however they spell the name.
pub const NSID_MODEL: &str = "sh.kotton.model";

/// One pin setting — what one of the person's devices keeps of their drives:
/// its default, or a drive or a folder set the other way (kotton #55;
/// kotton-protocol #20, `kotton_wire::ipc::PinSetting`). The daemon writes it,
/// the daemon reads it, and every device of the person's reads every device's,
/// which is why it is core: a device that has never seen a declaration skips
/// the rows.
pub const NSID_PIN: &str = "sh.kotton.pin";

// ── Meta schema NSID (schema publication) ────────────────────────────────────

/// Well-known NSID for schema publication records.
///
/// A `sh.kotton.meta.schema` record body contains the full [`SchemaDefinition`]
/// JSON for a third-party schema, signed by the publisher's DID. Index nodes
/// store and serve these records for discovery.
pub const NSID_META_SCHEMA: &str = "sh.kotton.meta.schema";
