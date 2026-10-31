// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a peer's request is lent of the machine, one handle per thing a peer verb
//! does (kotton #242).
//!
//! The peer path used to hold the whole `DeviceRuntime`, which carries the base
//! directory and the keychain a record store opens from
//! (`kotton_record::open`), the resident object stores, the sessions, the
//! dialer and every other part of the machine. No peer verb opened a record
//! store, but nothing in the type stopped one. These handles are what the verbs
//! use instead, and each has private fields and the methods its verbs ask —
//! so `handle_peer_request`, in the parent module, can reach nothing of these
//! fields but what a method here answers. That is module privacy; what a method
//! does with a field it holds is this module's discipline, not a type's.
//!
//! The introductions are the device's own lent handle,
//! `kotton_device::Introducer`: the listeners open now and the key they present.
//!
//! One of these holds the whole keychain, `Arc<dyn SecretsStore>`, because
//! what it answers is kept there (a second, `file_host::PeerStoreHost`, holds
//! it for a mount's key domain): [`FrostSigner`] reads this node's FROST share
//! for a person and answers one signing round with it. It hands neither the
//! keychain nor the share back, and reads only `frost_share` — but that is true
//! of its method, not its type. `PeerStoreHost` reads and writes
//! `sealed_mount_domain` and reads `operational_cek` — or the person's **root
//! seed** `seed32` when no CEK is stored — and it holds the keychain beside
//! the resident stores, each of which answers its base directory
//! (`UserStore::base_dir`), so the inputs a record store opens from still sit
//! together there, kept apart by its methods. Lending each only its labels,
//! and no handle a base directory beside them, is kotton #256.
//!
//! [`GuestSessions`] holds no keychain and no base directory (kotton #262): it
//! holds a read-only view of the agent databases the daemon has already opened
//! (`user_db::OpenAgentDbs`), and answers
//! from a database only when the daemon opened it on its own account — at boot,
//! sign-in or unlock — never because a peer named its person. It cannot open,
//! create or migrate one, because it does not hold what opening takes, and
//! cannot add a slot to the map, because its view has no method that writes —
//! both held by its field types, not its method.
//! Every `user_id` these handles are asked about is a
//! [`crate::device_users::UserId`], parsed from the request before any of
//! them is reached.
use crate::device_users::UserId;
use kotton_device::users::admission::{Chains, PeerStanding};
use kotton_sys::secret::SecretsStore;
use kotton_wire::ipc::UserResponse;
use kotton_wire::peer::EphemeralSession;
use sqlx::SqlitePool;
use std::collections::HashSet;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// Who a peer is to a person: the paired-node rows, the live allowlist a
/// proof-admitted peer is written into, and the identity chains
/// ([`Chains`]) — never the keychain.
pub(super) struct Standing {
    db: Arc<SqlitePool>,
    paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    chains: Chains,
}

impl Standing {
    pub(super) fn new(
        db: Arc<SqlitePool>,
        paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
        chains: Chains,
    ) -> Self {
        Self { db, paired_keys, chains }
    }

    /// `kotton_device::users::admission::peer_standing`, on what this handle holds.
    pub(super) async fn of(
        &self,
        peer_did: &str,
        peer_pubkey: Option<[u8; 32]>,
        user_id: &UserId,
    ) -> io::Result<PeerStanding> {
        kotton_device::users::admission::peer_standing_in(
            &self.chains,
            &self.db,
            &self.paired_keys,
            peer_did,
            peer_pubkey,
            Some(user_id.as_str()),
        )
        .await
    }

    /// The identity `user_id` is registered as, which a recovery claim must name.
    pub(super) fn aid_of(&self, user_id: &UserId) -> Option<String> {
        self.chains.aid_of(user_id.as_str())
    }
}

/// The guest sessions a stranger's key may hold: found in the person's own
/// database, and checked against the ones revoked since they were read.
///
/// Holds a read-only view of the agent databases the daemon has open
/// (`user_db::OpenAgentDbs`) and the revoked set, and nothing a database opens
/// from: no base directory, no keychain, no schema registry (kotton #262). A database the daemon has not opened — the
/// person is not taken up here, or their keys did not resolve — reads as no
/// session, and the lookup leaves the map as it found it
/// (`OpenAgentDbs::get`, the view's one method). So a peer naming a person it has no standing
/// with makes this node open, create, migrate or remember nothing for that
/// name, and reads no secret for it. The pool is not handed out.
pub(super) struct GuestSessions {
    user_dbs: crate::db::user_db::OpenAgentDbs,
    revoked: Arc<RwLock<HashSet<String>>>,
}

impl GuestSessions {
    pub(super) fn new(
        user_dbs: crate::db::user_db::OpenAgentDbs,
        revoked: Arc<RwLock<HashSet<String>>>,
    ) -> Self {
        Self { user_dbs, revoked }
    }

    /// The guest session `guest_did` holds for `user_id`, read from the
    /// person's database if the daemon already has it open; `None` otherwise —
    /// the same refusal shape as no session.
    pub(super) async fn find(
        &self,
        guest_did: &str,
        user_id: &UserId,
    ) -> io::Result<Option<EphemeralSession>> {
        let Some(user_db) = self.user_dbs.get(user_id) else {
            return Ok(None);
        };
        kotton_peer::daemon::db::find_ephemeral_session_by_guest_did(&user_db, guest_did, user_id.as_str())
            .await
    }

    /// Whether `session_id` was revoked since it was read.
    pub(super) fn revoked(&self, session_id: &str) -> bool {
        self.revoked.read().unwrap().contains(session_id)
    }
}

/// Where this node reserves, and the key it presents there: `NodeRelay`'s answer.
pub(super) struct NodeRelay {
    reachability: Arc<kotton_peer::Reachability>,
}

impl NodeRelay {
    pub(super) fn new(reachability: Arc<kotton_peer::Reachability>) -> Self {
        Self { reachability }
    }

    /// The relay this node reserves at, and — when `own_device` — the key it
    /// presents there for `user_id`.
    pub(super) fn answer(&self, user_id: &UserId, own_device: bool) -> UserResponse {
        let nat = self.reachability.nat();
        let relay_url = nat.relay_url;
        // The keys are held under what the relay *is*, its key, and the asker
        // is told that key beside the address.
        let relay_key = nat.relay_key;
        let admission = own_device
            .then(|| kotton_peer::relay_keys::relay_id(relay_key.as_deref()))
            .flatten()
            .and_then(|id| self.reachability.relay_keys().for_own_device(user_id.as_str(), &id));
        UserResponse::NodeRelayResult {
            relay_url: Some(relay_url).filter(|u| !u.is_empty()),
            relay_key,
            admission,
        }
    }
}

/// A person's recovery material as this node keeps it: the public chain and the
/// phrase-sealed copy, neither of which this node can open.
pub(super) struct Recovery {
    base: PathBuf,
    chains: Chains,
}

impl Recovery {
    pub(super) fn new(base: PathBuf, chains: Chains) -> Self {
        Self { base, chains }
    }

    /// The chain and the sealed copy, verbatim; empty when absent.
    pub(super) fn fetch(&self, user_id: &UserId) -> UserResponse {
        let kel = self.chains.chain(user_id.as_str());
        let bundle = kotton_identity::provisioning::read_recovery_bundle_raw(&self.base, user_id.as_str())
            .unwrap_or_default();
        UserResponse::RecoveryMaterial { kel, bundle }
    }

    /// Adopt the events that authorize a delivered copy, then keep the copy.
    pub(super) fn store(
        &self,
        peer_did: &str,
        user_id: &UserId,
        bundle: &str,
        kel: &[kotton_wire::kel::KelEvent],
    ) -> UserResponse {
        // The events that authorize the copy, before the copy. A chain this
        // node cannot extend is a copy it will refuse to serve, so the
        // failure belongs here rather than at the recovery six months later.
        if let Err(e) = self.chains.adopt(user_id.as_str(), kel) {
            return UserResponse::Error {
                message: format!("the key events offered with the recovery copy do not replay: {e}"),
            };
        }
        match kotton_identity::provisioning::write_recovery_bundle_raw(&self.base, user_id.as_str(), bundle) {
            Ok(()) => {
                tracing::info!(peer_did = %peer_did, user_id = %user_id, events = kel.len(), "kept a delivered recovery copy");
                UserResponse::Ok
            }
            Err(e) => UserResponse::Error {
                message: format!("keep recovery copy: {e}"),
            },
        }
    }
}

/// This node's part in a person's threshold signature: it reads its FROST share
/// for that person from the keychain, under the one label that names it, and
/// answers one round. The share never leaves this handle. It holds the whole
/// keychain; that no other secret is read through it is this method's
/// discipline, not its type's (kotton #256).
pub(super) struct FrostSigner {
    secrets: Arc<dyn SecretsStore + Send + Sync>,
    /// Holds a round-1's secret nonces until the matching round-2, a later and
    /// separate peer request.
    participant: Arc<kotton_org::frost_signing::FrostParticipant>,
}

impl FrostSigner {
    pub(super) fn new(
        secrets: Arc<dyn SecretsStore + Send + Sync>,
        participant: Arc<kotton_org::frost_signing::FrostParticipant>,
    ) -> Self {
        Self { secrets, participant }
    }

    /// Answer one round of `user_id`'s signing, `payload` a serialized
    /// `FrostRound`.
    pub(super) fn answer(&self, user_id: &UserId, payload: &str) -> UserResponse {
        use kotton_org::frost_signing::FrostRound;
        let round: FrostRound = match serde_json::from_str(payload) {
            Ok(r) => r,
            Err(e) => {
                return UserResponse::Error {
                    message: format!("invalid FrostSignRound payload: {e}"),
                };
            }
        };
        let share = match self
            .secrets
            .get_secret(&kotton_common::crypto::kdf_labels::frost_share(user_id.as_str()))
        {
            Ok(Some(s)) => s,
            Ok(None) => {
                return UserResponse::Error {
                    message: "no FROST share on this node — not enrolled in the threshold"
                        .to_string(),
                };
            }
            Err(e) => {
                return UserResponse::Error {
                    message: format!("keychain read failed: {e}"),
                };
            }
        };
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        match self.participant.handle(&share, round, now_secs) {
            Ok(reply) => match serde_json::to_string(&reply) {
                Ok(payload) => UserResponse::FrostSignReply { payload },
                Err(e) => UserResponse::Error {
                    message: format!("serialize FrostSignReply: {e}"),
                },
            },
            Err(e) => UserResponse::Error {
                message: format!("frost signing round failed: {e}"),
            },
        }
    }
}
