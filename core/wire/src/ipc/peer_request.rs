// SPDX-License-Identifier: AGPL-3.0-or-later
//! `PeerRequest` — what a paired peer may ask a device's daemon on its own
//! standing, and the type `kuserd`'s peer acceptor decodes.
//!
//! The peer acceptor is reached by any key the handshake admits: the person's
//! own devices, a vault, a cosigner, a gateway, a guest holding a session, a
//! device presenting a recovery claim. It decoded the local door's whole
//! [`UserRequest`] until this type existed, every door verb in it —
//! `RecordInsert`, `RecordQuery` and some two hundred more — and then refused
//! by a table what was "not permitted over a peer connection". That table was
//! evidence the door's verbs were reachable at the peer's decoder. Now they
//! are not on this wire at all: a door verb arriving here fails to
//! deserialize, unconstructible rather than refused (kotton #231). The same
//! rule [`super::vault_request::VaultRequest`] holds for a vault's door, and
//! [`super::vault_peer_request::VaultPeerRequest`] for a vault's peer acceptor,
//! whose verbs are not these: one acceptor, one request type.
//!
//! **What a peer may ask, by kind:**
//!
//! | verbs | asked by | what they reach |
//! |---|---|---|
//! | `ReadFile`, `WriteFile`, `ListFiles`, `DeleteFile` | a paired device, or a guest within its session's path grant | the person's resident object store, at a path |
//! | `ReadSealed`, `ListSealed`, `WriteSealed` | a paired device | the same store's sealed objects, verbatim |
//! | `SyncAvailable`, `RecordSyncAvailable` | a paired device | a wake of this device's own sync pass; they carry no object and no record |
//! | `RecoveryFetch`, `RecoveryStore` | a paired device, or (fetch only) one admitted on a recovery claim | the public key-event chain and the phrase-sealed recovery copy |
//! | `FrostSignRound` | a paired cosigner | one round over this node's threshold share |
//! | `NodeRelay` | a paired device, or a gateway | where this node reserves |
//! | `Introduce` | a paired device | a listener for one introduced address |
//! | `BrowserFrame` | a gateway, for the person whose row pairs it as theirs | the browser's sealed channel — see below |
//!
//! **No verb here writes a record.** Records move between devices as sealed
//! segments of the record log, which `WriteSealed` carries like any other
//! object and the sync pass merges; `RecordSyncAvailable` wakes that pass and
//! carries no record. The test at the bottom holds that no record verb of the
//! door's decodes as this type.
//!
//! **`BrowserFrame` is the exception in kind, not in type.** A frame is
//! ciphertext the gateway cannot read; once the browser's channel is
//! established, each frame carries one of the person's own door verbs, which
//! the daemon dispatches under the browser's session minted at admission —
//! `RecordInsert` among them. That is the person's reach, through their
//! browser, and not a peer's on its own standing; it is the gateway path's to
//! state (`kuserd::agent::handle_gateway_request`).
//!
//! Every variant mirrors the [`UserRequest`] variant of the same name byte for
//! byte — same name, same fields, same `serde` attributes — so a device's peer
//! client, which builds `UserRequest`, and a gateway, which does too, drive this
//! acceptor unchanged. The tests at the bottom hold the mirror, and
//! `cargo xtask wire-check` holds this type's surface in
//! `core/wire/peer-request-surface.txt`.

use serde::{Deserialize, Serialize};

#[cfg(doc)]
use super::UserRequest;

/// One request on the device's peer wire. See the module documentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerRequest {
    // -- Files, at a path: the person's devices, and a guest within its grant --
    /// [`UserRequest::ReadFile`].
    ReadFile {
        user_id: String,
        path: String,
        offset: u64,
        length: u32,
    },
    /// [`UserRequest::WriteFile`].
    WriteFile {
        user_id: String,
        path: String,
        #[serde(with = "crate::base64_bytes")]
        data: Vec<u8>,
        offset: u64,
        total_size: u64,
        content_hash: String,
    },
    /// [`UserRequest::ListFiles`].
    ListFiles {
        user_id: String,
        prefix: String,
    },
    /// [`UserRequest::DeleteFile`].
    DeleteFile {
        user_id: String,
        path: String,
    },

    // -- Sealed replication: the person's own devices --------------------------
    /// [`UserRequest::ReadSealed`].
    ReadSealed {
        user_id: String,
        mount: String,
        path: String,
        offset: u64,
        length: u32,
    },
    /// [`UserRequest::ListSealed`].
    ListSealed {
        user_id: String,
        mount: String,
        prefix: String,
    },
    /// [`UserRequest::WriteSealed`].
    WriteSealed {
        user_id: String,
        mount: String,
        path: String,
        #[serde(with = "crate::base64_bytes")]
        blob: Vec<u8>,
        domain_id: String,
        offset: u64,
        total_size: u64,
        content_hash: String,
    },

    // -- Wakes: they carry nothing ---------------------------------------------
    /// [`UserRequest::SyncAvailable`].
    SyncAvailable {
        user_id: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        paths: Vec<String>,
    },
    /// [`UserRequest::RecordSyncAvailable`]: wakes the record sync pass, and
    /// carries the namespaces as information only — no record.
    RecordSyncAvailable {
        user_id: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        nsids: Vec<String>,
    },

    // -- Recovery ----------------------------------------------------------------
    /// [`UserRequest::RecoveryFetch`].
    RecoveryFetch {
        user_id: String,
    },
    /// [`UserRequest::RecoveryStore`].
    RecoveryStore {
        user_id: String,
        bundle: String,
        #[serde(default)]
        kel: Vec<crate::kel::KelEvent>,
    },

    // -- Membership: the node's own answers --------------------------------------
    /// [`UserRequest::FrostSignRound`].
    FrostSignRound {
        user_id: String,
        payload: String,
    },
    /// [`UserRequest::NodeRelay`].
    NodeRelay {
        user_id: String,
    },
    /// [`UserRequest::Introduce`].
    Introduce {
        user_id: String,
        addr: String,
        token: crate::ipc::SecretText,
        #[serde(default)]
        router: Option<String>,
    },

    // -- A gateway's one verb ------------------------------------------------------
    /// [`UserRequest::BrowserFrame`]. On this wire it names its person.
    BrowserFrame {
        #[serde(with = "crate::base64_bytes")]
        bytes: Vec<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        channel: Option<String>,
    },
}

impl PeerRequest {
    /// The variant's name, as it is spelled on the wire.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::ReadFile { .. } => "ReadFile",
            Self::WriteFile { .. } => "WriteFile",
            Self::ListFiles { .. } => "ListFiles",
            Self::DeleteFile { .. } => "DeleteFile",
            Self::ReadSealed { .. } => "ReadSealed",
            Self::ListSealed { .. } => "ListSealed",
            Self::WriteSealed { .. } => "WriteSealed",
            Self::SyncAvailable { .. } => "SyncAvailable",
            Self::RecordSyncAvailable { .. } => "RecordSyncAvailable",
            Self::RecoveryFetch { .. } => "RecoveryFetch",
            Self::RecoveryStore { .. } => "RecoveryStore",
            Self::FrostSignRound { .. } => "FrostSignRound",
            Self::NodeRelay { .. } => "NodeRelay",
            Self::Introduce { .. } => "Introduce",
            Self::BrowserFrame { .. } => "BrowserFrame",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{SecretText, UserRequest};

    /// The peer wire's recorded surface, and the door's.
    const PEER_SURFACE: &str = include_str!("../../peer-request-surface.txt");
    const DOOR_SURFACE: &str = include_str!("../../wire-surface.txt");

    /// Variant names of a recorded surface: its unindented, uncommented lines.
    fn variants(surface: &str) -> Vec<&str> {
        surface
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with(' ') && !l.starts_with('#'))
            .map(str::trim)
            .collect()
    }

    /// Every variant, built: what a device's client and a gateway send.
    fn every_peer_verb_as_the_door_spells_it() -> Vec<UserRequest> {
        let user_id = || "alice".to_string();
        vec![
            UserRequest::ReadFile { user_id: user_id(), path: "/a".into(), offset: 1, length: 2 },
            UserRequest::WriteFile {
                user_id: user_id(),
                path: "/a".into(),
                data: vec![1, 2, 3],
                offset: 0,
                total_size: 3,
                content_hash: "h".into(),
            },
            UserRequest::ListFiles { user_id: user_id(), prefix: "/".into() },
            UserRequest::DeleteFile { user_id: user_id(), path: "/a".into() },
            UserRequest::ReadSealed {
                user_id: user_id(),
                mount: "local".into(),
                path: "p".into(),
                offset: 0,
                length: 9,
            },
            UserRequest::ListSealed { user_id: user_id(), mount: "local".into(), prefix: "".into() },
            UserRequest::WriteSealed {
                user_id: user_id(),
                mount: "local".into(),
                path: "p".into(),
                blob: vec![9],
                domain_id: "d".into(),
                offset: 0,
                total_size: 1,
                content_hash: "h".into(),
            },
            UserRequest::SyncAvailable { user_id: user_id(), paths: vec![] },
            UserRequest::SyncAvailable { user_id: user_id(), paths: vec!["/a".into()] },
            UserRequest::RecordSyncAvailable { user_id: user_id(), nsids: vec!["sh.kotton.notes".into()] },
            UserRequest::RecoveryFetch { user_id: user_id() },
            UserRequest::RecoveryStore { user_id: user_id(), bundle: "b".into(), kel: vec![] },
            UserRequest::FrostSignRound { user_id: user_id(), payload: "{}".into() },
            UserRequest::NodeRelay { user_id: user_id() },
            UserRequest::Introduce {
                user_id: user_id(),
                addr: "127.0.0.1:1".into(),
                token: SecretText::new("00"),
                router: Some("ab".into()),
            },
            UserRequest::BrowserFrame { bytes: vec![4, 5], user_id: Some(user_id()), channel: None },
            UserRequest::BrowserFrame { bytes: vec![], user_id: None, channel: Some("c".into()) },
        ]
    }

    /// The peer wire's variants are `UserRequest`'s, byte for byte: what a
    /// device's client or a gateway sends for these verbs decodes here and
    /// re-encodes to the same bytes, and the name each answers to is its own.
    #[test]
    fn the_peer_wire_mirrors_the_door_for_its_verbs() {
        let sent = every_peer_verb_as_the_door_spells_it();
        let mut named: Vec<&str> = Vec::new();
        for req in &sent {
            let bytes = serde_json::to_vec(req).unwrap();
            let peer: PeerRequest = serde_json::from_slice(&bytes)
                .unwrap_or_else(|e| panic!("{} must decode on the peer wire: {e}", req.variant_name()));
            assert_eq!(serde_json::to_vec(&peer).unwrap(), bytes, "{} re-encodes byte for byte", req.variant_name());
            assert_eq!(peer.variant_name(), req.variant_name());
            named.push(peer.variant_name());
        }
        named.sort_unstable();
        named.dedup();
        let mut recorded = variants(PEER_SURFACE);
        recorded.sort_unstable();
        assert_eq!(named, recorded, "every recorded peer verb is exercised here, and no other");
    }

    /// Each peer verb's recorded fields are its door twin's, line for line: the
    /// surface is the wire, so a field that drifted on one side is caught here
    /// before a device and a gateway of different builds disagree.
    #[test]
    fn each_peer_verb_records_the_fields_of_its_door_twin() {
        fn block<'s>(surface: &'s str, name: &str) -> Vec<&'s str> {
            let mut lines = surface.lines().skip_while(|l| l.trim_end() != name);
            assert!(lines.next().is_some(), "{name} is not on the surface");
            lines.take_while(|l| l.starts_with(' ')).collect()
        }
        for name in variants(PEER_SURFACE) {
            assert_eq!(block(PEER_SURFACE, name), block(DOOR_SURFACE, name), "{name}'s fields");
        }
    }

    /// **No verb on the peer wire writes or reads a record.** Every door verb
    /// that is not a peer verb — the record verbs among them — is an unknown
    /// variant at this decoder, so it cannot be built here, whatever its
    /// fields; and the one peer verb that names records, `RecordSyncAvailable`,
    /// carries namespaces and no record.
    #[test]
    fn no_door_verb_but_the_peer_verbs_decodes_on_the_peer_wire() {
        let peer = variants(PEER_SURFACE);
        let door = variants(DOOR_SURFACE);
        assert!(door.len() > 150, "the door's surface no longer parses: {} variants", door.len());
        let mut refused = 0;
        for name in door.iter().filter(|n| !peer.contains(n)) {
            let err = serde_json::from_str::<PeerRequest>(&format!(r#"{{"{name}":{{}}}}"#))
                .expect_err(&format!("{name} is a door verb and decoded on the peer wire"));
            assert!(err.to_string().contains("unknown variant"), "{name}: {err}");
            refused += 1;
        }
        assert_eq!(refused + peer.len(), door.len(), "every peer verb is a door verb");

        // The record verbs by name, so this test says what it is for even if
        // the surfaces it reads were emptied.
        for writes_or_reads_a_record in ["RecordInsert", "RecordDelete", "RecordQuery", "RecordSearch", "RecordOpen"] {
            assert!(door.contains(&writes_or_reads_a_record), "{writes_or_reads_a_record} left the door");
            assert!(!peer.contains(&writes_or_reads_a_record), "{writes_or_reads_a_record} is on the peer wire");
        }
        let record_named: Vec<&&str> = peer.iter().filter(|n| n.starts_with("Record")).collect();
        assert_eq!(record_named, [&"RecordSyncAvailable"], "the peer wire's only record-named verb is the wake");
        let mut fields = PEER_SURFACE
            .lines()
            .skip_while(|l| l.trim_end() != "RecordSyncAvailable")
            .skip(1)
            .take_while(|l| l.starts_with(' '))
            .filter(|l| !l.trim_start().starts_with('#'))
            .map(str::trim);
        assert_eq!(fields.next(), Some("user_id: String"));
        assert_eq!(fields.next(), Some("nsids: Vec<String>"), "the wake carries namespaces, never a record");
        assert_eq!(fields.next(), None);
    }

    /// A live write verb, with every field it takes, is refused by the decoder
    /// by its name — the shape the door and the gateway's `RemoteRequest` share.
    #[test]
    fn a_live_record_insert_is_unknown_on_the_peer_wire() {
        let insert = UserRequest::RecordInsert {
            user_id: "alice".into(),
            schema_nsid: "sh.kotton.notes".into(),
            record: serde_json::json!({ "title": "planted", "body": "planted" }),
            root: None,
            app_id: None,
        };
        let err = serde_json::from_slice::<PeerRequest>(&serde_json::to_vec(&insert).unwrap())
            .expect_err("a record insert decoded on the peer wire");
        assert!(err.to_string().contains("unknown variant `RecordInsert`"), "{err}");
    }

    /// The token an introduction carries prints `<redacted>`, as on the door.
    #[test]
    fn an_introductions_token_never_prints() {
        let req = PeerRequest::Introduce {
            user_id: "alice".into(),
            addr: "127.0.0.1:1".into(),
            token: SecretText::new("TOKEN-OF-THE-INTRODUCTION"),
            router: None,
        };
        let printed = format!("{req:?}");
        assert!(!printed.contains("TOKEN-OF-THE-INTRODUCTION") && printed.contains("<redacted>"), "{printed}");
    }
}
