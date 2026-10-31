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
//! Two of these hold the whole keychain, `Arc<dyn SecretsStore>`, because what
//! they answer is kept there (a third, `file_host::PeerStoreHost`, holds it for
//! a mount's key domain): [`FrostSigner`] reads this node's FROST share for a
//! person and answers one signing round with it, and [`GuestSessions`] opens the
//! person's own database to find the guest session a stranger's key may hold.
//! Neither hands the keychain, a key or a database back, and each reads only
//! what its question needs — but that is true of their methods, not their
//! types. [`GuestSessions`] holds the keychain beside the base directory, which
//! is what a record store opens from; a method added here could open one.
//! Lending each only its labels, and no handle both, is kotton #256.
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
        user_id: &str,
    ) -> io::Result<PeerStanding> {
        kotton_device::users::admission::peer_standing_in(
            &self.chains,
            &self.db,
            &self.paired_keys,
            peer_did,
            peer_pubkey,
            Some(user_id),
        )
        .await
    }

    /// The identity `user_id` is registered as, which a recovery claim must name.
    pub(super) fn aid_of(&self, user_id: &str) -> Option<String> {
        self.chains.aid_of(user_id)
    }
}

/// The guest sessions a stranger's key may hold: found in the person's own
/// database, and checked against the ones revoked since they were read.
///
/// Holds what opening that database takes — the open map, the base directory,
/// the keychain its key is derived from, and the schema registry — and answers
/// one question with them. The pool is not handed out.
pub(super) struct GuestSessions {
    user_dbs: crate::db::user_db::UserDbMap,
    base: PathBuf,
    secrets: Arc<dyn SecretsStore + Send + Sync>,
    schema_registry: Arc<RwLock<kotton_record::registry::SchemaRegistry>>,
    revoked: Arc<RwLock<HashSet<String>>>,
}

impl GuestSessions {
    pub(super) fn new(
        user_dbs: crate::db::user_db::UserDbMap,
        base: PathBuf,
        secrets: Arc<dyn SecretsStore + Send + Sync>,
        schema_registry: Arc<RwLock<kotton_record::registry::SchemaRegistry>>,
        revoked: Arc<RwLock<HashSet<String>>>,
    ) -> Self {
        Self { user_dbs, base, secrets, schema_registry, revoked }
    }

    /// The guest session `guest_did` holds for `user_id`. An unopenable
    /// database reads as no session — the same refusal shape.
    pub(super) async fn find(
        &self,
        guest_did: &str,
        user_id: &str,
    ) -> io::Result<Option<EphemeralSession>> {
        match crate::db::user_db::user_agent_db(
            &self.user_dbs,
            &self.base,
            self.secrets.as_ref(),
            user_id,
            &self.schema_registry,
        )
        .await
        {
            Ok(user_db) => {
                kotton_peer::daemon::db::find_ephemeral_session_by_guest_did(
                    &user_db, guest_did, user_id,
                )
                .await
            }
            Err(e) => {
                tracing::warn!(user_id = %user_id, error = %e, "peer guest lookup: user db unavailable");
                Ok(None)
            }
        }
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
    pub(super) fn answer(&self, user_id: &str, own_device: bool) -> UserResponse {
        let nat = self.reachability.nat();
        let relay_url = nat.relay_url;
        // The keys are held under what the relay *is*, its key, and the asker
        // is told that key beside the address.
        let relay_key = nat.relay_key;
        let admission = own_device
            .then(|| kotton_peer::relay_keys::relay_id(relay_key.as_deref()))
            .flatten()
            .and_then(|id| self.reachability.relay_keys().for_own_device(user_id, &id));
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
    pub(super) fn fetch(&self, user_id: &str) -> UserResponse {
        let kel = self.chains.chain(user_id);
        let bundle = kotton_identity::provisioning::read_recovery_bundle_raw(&self.base, user_id)
            .unwrap_or_default();
        UserResponse::RecoveryMaterial { kel, bundle }
    }

    /// Adopt the events that authorize a delivered copy, then keep the copy.
    pub(super) fn store(
        &self,
        peer_did: &str,
        user_id: &str,
        bundle: &str,
        kel: &[kotton_wire::kel::KelEvent],
    ) -> UserResponse {
        // The events that authorize the copy, before the copy. A chain this
        // node cannot extend is a copy it will refuse to serve, so the
        // failure belongs here rather than at the recovery six months later.
        if let Err(e) = self.chains.adopt(user_id, kel) {
            return UserResponse::Error {
                message: format!("the key events offered with the recovery copy do not replay: {e}"),
            };
        }
        match kotton_identity::provisioning::write_recovery_bundle_raw(&self.base, user_id, bundle) {
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
    pub(super) fn answer(&self, user_id: &str, payload: &str) -> UserResponse {
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
            .get_secret(&kotton_common::crypto::kdf_labels::frost_share(user_id))
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
