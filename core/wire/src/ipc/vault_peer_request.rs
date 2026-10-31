// SPDX-License-Identifier: AGPL-3.0-or-later
//! `VaultPeerRequest` — what a paired device, or the vault's operator key, may
//! ask a vault on the peer transport, and the type `kvaultd`'s peer acceptor
//! decodes.
//!
//! The vault's peer acceptor is reached by any key the handshake admits: a
//! tenant's device, a phrase-only device on a recovery claim, the operator's
//! key, a stranger. It decoded the device's whole [`UserRequest`] until this
//! type existed — `ReadFile`, `RecordInsert` and every other door verb of a
//! device — and then refused by arm what was "not a vault's verb". That arm was
//! evidence a device's verbs were reachable at the vault's decoder. Now they
//! are not on this wire at all: a verb that is not the vault's fails to
//! deserialize, unconstructible rather than refused (kotton #239). The same
//! rule [`super::vault_request::VaultRequest`] holds for the vault's door and
//! [`super::peer_request::PeerRequest`] for a device's peer acceptor: one
//! acceptor, one request type.
//!
//! **Why not [`PeerRequest`](super::peer_request::PeerRequest).** The two
//! acceptors share six verbs — the sealed read, write and list, the recovery
//! copy fetched and kept, and where the node reserves — and nothing else. A
//! device's peer answers plaintext file verbs, sync wakes, an introduction,
//! a cosigner's round and a gateway's frame; a vault answers none of those and
//! fifteen a device does not. One type for both would put each acceptor's
//! verbs on the other's wire, which is the widening this type exists to undo.
//!
//! **What reaches the vault here, by kind.** Who may say which is decided by
//! standing, in one table (`kvaultd::peer::reaches`); this type says only what
//! exists to be said.
//!
//! | verbs | said by | what they reach |
//! |---|---|---|
//! | `ReadSealed`, `WriteSealed`, `ListSealed` | a tenant's device | the person's sealed objects, verbatim — a vault holds no key |
//! | `RecoveryFetch`, `RecoveryStore` | a tenant's device, or (fetch only) one on a recovery claim | the public key-event chain and the phrase-sealed recovery copy |
//! | `NodeRelay` | a tenant's device | the relay this vault reserves at, by the key the person is invited under |
//! | `VaultCapacity` | a tenant's device | the meter's readout for its own pool |
//! | `HoldDoors`, `TakeDeliveries`, `CarryFrame` | a tenant's device | the doors held for the person, what arrived at them, and what the vault carries while the person's devices sleep |
//! | `TenantDevice` | a tenant's device, under the identity's signature | which of the person's devices the vault admits |
//! | `TenantDriveMake`, `TenantDrives`, `TenantDriveName`, `TenantDriveRetire` | a tenant's device | the person's drives kept here (the drive decision) |
//! | `DeviceInvite`, `InviteDigits`, `Tenants`, `SetQuota`, `DropTenant`, `StandAt` | the vault's operator key | the landlord's acts over pools, and where the vault stands |
//!
//! **No verb here is plaintext, and none writes or reads a record.** A vault
//! holds no key; records reach it as sealed segments of the record log, which
//! `WriteSealed` carries like any other object. The tests at the bottom hold
//! that no other door verb of a device decodes as this type.
//!
//! Every variant mirrors the [`UserRequest`] variant of the same name byte for
//! byte — same name, same fields, same `serde` attributes — so a vault and a
//! device of different builds agree on each verb's bytes, and a device's sync
//! pass, which reads and writes sealed objects at a peer that may be either,
//! speaks one spelling to both. The tests at the bottom hold the mirror, and
//! `cargo xtask wire-check` holds this type's surface in
//! `core/wire/vault-peer-request-surface.txt`.

use serde::{Deserialize, Serialize};

#[cfg(doc)]
use super::UserRequest;

/// One request on a vault's peer wire. See the module documentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultPeerRequest {
    // -- Sealed objects: a tenant's device, to its own pool ----------------------
    /// [`UserRequest::ReadSealed`].
    ReadSealed {
        user_id: String,
        mount: String,
        path: String,
        offset: u64,
        length: u32,
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
    /// [`UserRequest::ListSealed`].
    ListSealed {
        user_id: String,
        mount: String,
        prefix: String,
    },

    // -- Recovery ------------------------------------------------------------------
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

    // -- Reach and room ------------------------------------------------------------
    /// [`UserRequest::NodeRelay`].
    NodeRelay {
        user_id: String,
    },
    /// [`UserRequest::VaultCapacity`].
    VaultCapacity {
        user_id: String,
    },

    // -- Doors and carrying, while the person's devices sleep -----------------------
    /// [`UserRequest::HoldDoors`].
    HoldDoors {
        user_id: String,
        doors: Vec<crate::ipc::HeldDoor>,
    },
    /// [`UserRequest::TakeDeliveries`].
    TakeDeliveries {
        user_id: String,
        ack: Vec<String>,
    },
    /// [`UserRequest::CarryFrame`].
    CarryFrame {
        user_id: String,
        messages: Vec<crate::ipc::CarriedMessage>,
        drop: Vec<String>,
    },

    // -- The person's devices and drives here ----------------------------------------
    /// [`UserRequest::TenantDevice`].
    TenantDevice {
        user_id: String,
        change: crate::ipc::TenantDeviceChange,
        signature: Vec<u8>,
    },
    /// [`UserRequest::TenantDriveMake`].
    TenantDriveMake {
        user_id: String,
        drive: crate::ipc::MadeDrive,
        #[serde(with = "crate::base64_bytes")]
        sealed_name: Vec<u8>,
    },
    /// [`UserRequest::TenantDrives`].
    TenantDrives {
        user_id: String,
    },
    /// [`UserRequest::TenantDriveName`].
    TenantDriveName {
        user_id: String,
        drive: crate::ipc::MadeDrive,
        #[serde(with = "crate::base64_bytes")]
        sealed_name: Vec<u8>,
    },
    /// [`UserRequest::TenantDriveRetire`].
    TenantDriveRetire {
        user_id: String,
        drive: crate::ipc::MadeDrive,
    },

    // -- The landlord's, under the vault's operator key ------------------------------
    /// [`UserRequest::DeviceInvite`].
    DeviceInvite {
        user_id: String,
        ttl_seconds: u64,
        #[serde(default)]
        as_name: Option<String>,
    },
    /// [`UserRequest::InviteDigits`].
    InviteDigits {
        user_id: String,
    },
    /// [`UserRequest::Tenants`].
    Tenants,
    /// [`UserRequest::SetQuota`].
    SetQuota {
        user_id: String,
        quota: u64,
    },
    /// [`UserRequest::DropTenant`].
    DropTenant {
        user_id: String,
    },
    /// [`UserRequest::StandAt`].
    StandAt {
        relays: Vec<crate::rendezvous::Stand>,
    },
}

impl VaultPeerRequest {
    /// The variant's name, as it is spelled on the wire.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::ReadSealed { .. } => "ReadSealed",
            Self::WriteSealed { .. } => "WriteSealed",
            Self::ListSealed { .. } => "ListSealed",
            Self::RecoveryFetch { .. } => "RecoveryFetch",
            Self::RecoveryStore { .. } => "RecoveryStore",
            Self::NodeRelay { .. } => "NodeRelay",
            Self::VaultCapacity { .. } => "VaultCapacity",
            Self::HoldDoors { .. } => "HoldDoors",
            Self::TakeDeliveries { .. } => "TakeDeliveries",
            Self::CarryFrame { .. } => "CarryFrame",
            Self::TenantDevice { .. } => "TenantDevice",
            Self::TenantDriveMake { .. } => "TenantDriveMake",
            Self::TenantDrives { .. } => "TenantDrives",
            Self::TenantDriveName { .. } => "TenantDriveName",
            Self::TenantDriveRetire { .. } => "TenantDriveRetire",
            Self::DeviceInvite { .. } => "DeviceInvite",
            Self::InviteDigits { .. } => "InviteDigits",
            Self::Tenants => "Tenants",
            Self::SetQuota { .. } => "SetQuota",
            Self::DropTenant { .. } => "DropTenant",
            Self::StandAt { .. } => "StandAt",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::UserRequest;
    use crate::recorded_surface::read;

    /// The vault's peer wire's recorded surface, the door's, and a device's
    /// peer wire's.
    const VAULT_PEER_SURFACE: &str = include_str!("../../vault-peer-request-surface.txt");
    const DOOR_SURFACE: &str = include_str!("../../wire-surface.txt");
    const PEER_SURFACE: &str = include_str!("../../peer-request-surface.txt");

    /// Variant names of a recorded surface, read by the one reader of the format,
    /// which holds the recording to its own `# variants: N` header.
    fn variants(surface: &str) -> Vec<&str> {
        read(surface)
            .unwrap_or_else(|e| panic!("a recorded surface cannot be read as one: {e}"))
            .into_iter()
            .map(|b| b.name)
            .collect()
    }

    /// Each verb of `twin` records its block in the door's recording, line for line.
    fn each_verb_records_its_door_twin(twin_file: &str, twin: &str) {
        let door = read(DOOR_SURFACE).unwrap_or_else(|e| panic!("wire-surface.txt: {e}"));
        for block in read(twin).unwrap_or_else(|e| panic!("{twin_file}: {e}")) {
            let Some(door_block) = door.iter().find(|d| d.name == block.name) else {
                panic!("{} ({twin_file}:{}) is not on the door's surface", block.name, block.at);
            };
            assert_eq!(
                block.texts(),
                door_block.texts(),
                "{}'s fields: {twin_file}:{} against wire-surface.txt:{}",
                block.name,
                block.at,
                door_block.at
            );
        }
    }

    /// Every variant, built as the door spells it.
    fn every_vault_verb_as_the_door_spells_it() -> Vec<UserRequest> {
        let user_id = || "alice".to_string();
        let drive = crate::ipc::MadeDrive([7; 16]);
        vec![
            UserRequest::ReadSealed {
                user_id: user_id(),
                mount: "local".into(),
                path: "p".into(),
                offset: 0,
                length: 9,
            },
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
            UserRequest::ListSealed { user_id: user_id(), mount: "local".into(), prefix: "".into() },
            UserRequest::RecoveryFetch { user_id: user_id() },
            UserRequest::RecoveryStore { user_id: user_id(), bundle: "b".into(), kel: vec![] },
            UserRequest::NodeRelay { user_id: user_id() },
            UserRequest::VaultCapacity { user_id: user_id() },
            UserRequest::HoldDoors { user_id: user_id(), doors: vec![] },
            UserRequest::TakeDeliveries { user_id: user_id(), ack: vec!["a".into()] },
            UserRequest::CarryFrame { user_id: user_id(), messages: vec![], drop: vec!["x".into()] },
            UserRequest::TenantDevice {
                user_id: user_id(),
                change: crate::ipc::TenantDeviceChange {
                    act: crate::ipc::TenantDeviceAct::Admit,
                    device_did: "did:key:z".into(),
                    public_key: [3; 32],
                    said_at_ms: 5,
                },
                signature: vec![1, 2],
            },
            UserRequest::TenantDriveMake { user_id: user_id(), drive, sealed_name: vec![4] },
            UserRequest::TenantDrives { user_id: user_id() },
            UserRequest::TenantDriveName { user_id: user_id(), drive, sealed_name: vec![5] },
            UserRequest::TenantDriveRetire { user_id: user_id(), drive },
            UserRequest::DeviceInvite { user_id: user_id(), ttl_seconds: 60, as_name: Some("n".into()) },
            UserRequest::DeviceInvite { user_id: user_id(), ttl_seconds: 60, as_name: None },
            UserRequest::InviteDigits { user_id: user_id() },
            UserRequest::Tenants,
            UserRequest::SetQuota { user_id: user_id(), quota: 1 << 30 },
            UserRequest::DropTenant { user_id: user_id() },
            UserRequest::StandAt { relays: vec![] },
        ]
    }

    /// The vault's peer wire's variants are `UserRequest`'s, byte for byte:
    /// what the door's spelling of each verb sends decodes here and re-encodes
    /// to the same bytes, and the name each answers to is its own.
    #[test]
    fn the_vault_peer_wire_mirrors_the_door_for_its_verbs() {
        let mut named: Vec<&str> = Vec::new();
        for req in every_vault_verb_as_the_door_spells_it() {
            let bytes = serde_json::to_vec(&req).unwrap();
            let vault: VaultPeerRequest = serde_json::from_slice(&bytes)
                .unwrap_or_else(|e| panic!("{} must decode on the vault's peer wire: {e}", req.variant_name()));
            assert_eq!(serde_json::to_vec(&vault).unwrap(), bytes, "{} re-encodes byte for byte", req.variant_name());
            assert_eq!(vault.variant_name(), req.variant_name());
            named.push(vault.variant_name());
        }
        named.sort_unstable();
        named.dedup();
        let mut recorded = variants(VAULT_PEER_SURFACE);
        recorded.sort_unstable();
        assert_eq!(named, recorded, "every recorded vault verb is exercised here, and no other");
    }

    /// Each vault verb's recorded fields are its door twin's, line for line.
    #[test]
    fn each_vault_verb_records_the_fields_of_its_door_twin() {
        each_verb_records_its_door_twin("vault-peer-request-surface.txt", VAULT_PEER_SURFACE);
    }

    /// **No door verb but the vault's decodes on the vault's peer wire** — the
    /// plaintext verbs and the record verbs among them — and the verbs it shares
    /// with a device's peer wire are the six that move sealed objects, the
    /// recovery copy and the node's relay, and no more.
    #[test]
    fn no_door_verb_but_the_vaults_decodes_on_the_vaults_peer_wire() {
        let vault = variants(VAULT_PEER_SURFACE);
        let door = variants(DOOR_SURFACE);
        assert!(door.len() > 150, "the door's surface no longer parses: {} variants", door.len());
        let mut refused = 0;
        for name in door.iter().filter(|n| !vault.contains(n)) {
            let err = serde_json::from_str::<VaultPeerRequest>(&format!(r#"{{"{name}":{{}}}}"#))
                .expect_err(&format!("{name} is not a vault's verb and decoded on its peer wire"));
            assert!(err.to_string().contains("unknown variant"), "{name}: {err}");
            refused += 1;
        }
        assert_eq!(refused + vault.len(), door.len(), "every vault verb is a door verb");

        // The verbs that read plaintext or touch a record, by name, so this
        // test says what it is for even if the surfaces it reads were emptied.
        for absent in ["ReadFile", "WriteFile", "ListFiles", "RecordInsert", "RecordDelete", "RecordQuery", "RecordSyncAvailable"] {
            assert!(door.contains(&absent), "{absent} left the door");
            assert!(!vault.contains(&absent), "{absent} is on the vault's peer wire");
        }

        let mut shared: Vec<&str> = vault.iter().copied().filter(|n| variants(PEER_SURFACE).contains(n)).collect();
        shared.sort_unstable();
        assert_eq!(
            shared,
            ["ListSealed", "NodeRelay", "ReadSealed", "RecoveryFetch", "RecoveryStore", "WriteSealed"],
            "the vault's and a device's peer wires share these and nothing else"
        );
    }

    /// A live write verb, with every field it takes, is refused by the
    /// vault's decoder by its name (kotton #230).
    #[test]
    fn a_live_record_insert_is_unknown_on_the_vaults_peer_wire() {
        let insert = UserRequest::RecordInsert {
            user_id: "alice".into(),
            schema_nsid: "sh.kotton.notes".into(),
            record: serde_json::json!({ "title": "planted", "body": "planted" }),
            root: None,
            app_id: None,
        };
        let err = serde_json::from_slice::<VaultPeerRequest>(&serde_json::to_vec(&insert).unwrap())
            .expect_err("a record insert decoded on the vault's peer wire");
        assert!(err.to_string().contains("unknown variant `RecordInsert`"), "{err}");
    }
}
