// SPDX-License-Identifier: AGPL-3.0-or-later
//! `SealedVerb`: the six verbs a device says alike to a peer that may be
//! another of the person's devices or a vault.
//!
//! A device's sync pass reads, writes and lists sealed objects at a peer, keeps
//! and fetches the recovery copy, and asks where the peer reserves. It does not
//! know, and need not know, which kind of peer it reached. The two peer
//! acceptors decode different types: a device's decodes
//! [`PeerRequest`](super::PeerRequest), and a vault's decodes
//! [`VaultPeerRequest`](super::VaultPeerRequest). These six verbs are the only
//! ones the two share, and each acceptor spells each of them the same way the
//! door does.
//!
//! Before this type, those verbs were sent as the device's whole
//! [`UserRequest`](super::UserRequest), and a peer client could send any door
//! verb to either acceptor. Three spellings then agreed only because tests held
//! them to it. This type makes the set a type on the sending side
//! (kotton #254): `KottonPeerObjectStorage::send_sealed` takes one of these six
//! and nothing else. The client's `send(&UserRequest)` is not retired yet. A
//! device peer's own verbs still go through it, and so does one `RecoveryStore`
//! caller. Retiring it is left open on #254.
//!
//! **It has no `serde` of its own.** It goes on the wire through
//! [`VaultPeerRequest::from`](super::VaultPeerRequest), which is one of the
//! spellings already recorded (`core/wire/vault-peer-request-surface.txt`).
//! So a sealed verb is spelled once, by a recorded type, and is not a fourth
//! spelling beside the door's and the two peer wires'. The test below holds
//! that both conversions give the same bytes, so a device's acceptor reads what
//! a vault's reads.

use super::{PeerRequest, VaultPeerRequest};

/// One of the six verbs a device says alike to a device and to a vault. See
/// the module documentation.
#[derive(Debug, Clone)]
pub enum SealedVerb {
    /// Read a chunk of a sealed object, verbatim.
    ReadSealed {
        user_id: String,
        mount: String,
        path: String,
        offset: u64,
        length: u32,
    },
    /// Write a chunk of a sealed object, verbatim.
    WriteSealed {
        user_id: String,
        mount: String,
        path: String,
        blob: Vec<u8>,
        domain_id: String,
        offset: u64,
        total_size: u64,
        content_hash: String,
    },
    /// List the sealed objects under a prefix.
    ListSealed {
        user_id: String,
        mount: String,
        prefix: String,
    },
    /// Fetch the public key-event chain and the phrase-sealed recovery copy.
    RecoveryFetch {
        user_id: String,
    },
    /// Keep the phrase-sealed recovery copy, with the events that authorize it.
    RecoveryStore {
        user_id: String,
        bundle: String,
        kel: Vec<crate::kel::KelEvent>,
    },
    /// Where the peer reserves.
    NodeRelay {
        user_id: String,
    },
}

/// Defines both conversions from one list of the six, so the two peer wires
/// cannot be given different field sets by hand.
macro_rules! into_peer_wire {
    ($($target:ident),+) => {$(
        impl From<SealedVerb> for $target {
            fn from(verb: SealedVerb) -> Self {
                match verb {
                    SealedVerb::ReadSealed { user_id, mount, path, offset, length } => {
                        Self::ReadSealed { user_id, mount, path, offset, length }
                    }
                    SealedVerb::WriteSealed {
                        user_id,
                        mount,
                        path,
                        blob,
                        domain_id,
                        offset,
                        total_size,
                        content_hash,
                    } => Self::WriteSealed { user_id, mount, path, blob, domain_id, offset, total_size, content_hash },
                    SealedVerb::ListSealed { user_id, mount, prefix } => Self::ListSealed { user_id, mount, prefix },
                    SealedVerb::RecoveryFetch { user_id } => Self::RecoveryFetch { user_id },
                    SealedVerb::RecoveryStore { user_id, bundle, kel } => Self::RecoveryStore { user_id, bundle, kel },
                    SealedVerb::NodeRelay { user_id } => Self::NodeRelay { user_id },
                }
            }
        }
    )+};
}
into_peer_wire!(VaultPeerRequest, PeerRequest);

impl SealedVerb {
    /// The verb's name, as it is spelled on the wire.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::ReadSealed { .. } => "ReadSealed",
            Self::WriteSealed { .. } => "WriteSealed",
            Self::ListSealed { .. } => "ListSealed",
            Self::RecoveryFetch { .. } => "RecoveryFetch",
            Self::RecoveryStore { .. } => "RecoveryStore",
            Self::NodeRelay { .. } => "NodeRelay",
        }
    }

    /// The bytes a peer receives: the verb as the vault's peer wire spells
    /// it, which is how a device's spells it too (the test below).
    pub fn to_wire(self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(&VaultPeerRequest::from(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::UserRequest;

    fn every_sealed_verb() -> Vec<SealedVerb> {
        let u = || "alice".to_string();
        vec![
            SealedVerb::ReadSealed { user_id: u(), mount: "local".into(), path: "p".into(), offset: 3, length: 9 },
            SealedVerb::WriteSealed {
                user_id: u(),
                mount: "local".into(),
                path: "p".into(),
                blob: vec![0, 1, 255],
                domain_id: "d".into(),
                offset: 0,
                total_size: 3,
                content_hash: "h".into(),
            },
            SealedVerb::ListSealed { user_id: u(), mount: "local".into(), prefix: "x/".into() },
            SealedVerb::RecoveryFetch { user_id: u() },
            SealedVerb::RecoveryStore { user_id: u(), bundle: "b".into(), kel: vec![] },
            SealedVerb::NodeRelay { user_id: u() },
        ]
    }

    /// **A sealed verb reads the same at a device and at a vault.** Its bytes
    /// are the vault's peer wire's, and the same bytes come from the device's
    /// peer wire's spelling. They decode on both acceptors and as the door's
    /// `UserRequest`, under the verb's own name, and each decode re-encodes to
    /// the same bytes. The names exercised are the six, each once.
    #[test]
    fn a_sealed_verb_is_spelled_alike_on_both_peer_wires_and_the_door() {
        let mut named: Vec<&str> = Vec::new();
        for verb in every_sealed_verb() {
            let name = verb.variant_name();
            let as_vault = verb.clone().to_wire().unwrap();
            let as_device = serde_json::to_vec(&PeerRequest::from(verb)).unwrap();
            assert_eq!(as_vault, as_device, "{name}: the two peer wires spell it differently");

            let vault: VaultPeerRequest = serde_json::from_slice(&as_vault).unwrap();
            let device: PeerRequest = serde_json::from_slice(&as_vault).unwrap();
            let door: UserRequest = serde_json::from_slice(&as_vault).unwrap();
            assert_eq!(vault.variant_name(), name);
            assert_eq!(device.variant_name(), name);
            assert_eq!(door.variant_name(), name);
            assert_eq!(serde_json::to_vec(&vault).unwrap(), as_vault, "{name} re-encodes at a vault");
            assert_eq!(serde_json::to_vec(&device).unwrap(), as_vault, "{name} re-encodes at a device");
            assert_eq!(serde_json::to_vec(&door).unwrap(), as_vault, "{name} re-encodes at the door");
            named.push(name);
        }
        named.sort_unstable();
        named.dedup();
        assert_eq!(
            named,
            ["ListSealed", "NodeRelay", "ReadSealed", "RecoveryFetch", "RecoveryStore", "WriteSealed"]
        );
    }
}
