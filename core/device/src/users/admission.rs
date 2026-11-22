// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a node does with a device its handshake admitted on proof.
//!
//! Admission is *decided* in the TLS handshake, by `PairedDeviceVerifier`, against
//! the identity tips and recovery authorities this node holds. It is *written down*
//! here, on the first request that device makes, because a verifier has no database
//! and rule 4 says membership is the truth the allowlist projects from — never the
//! other way round. The two meet in `Admission::admitted`, keyed by the TLS key the
//! handshake proved.

use crate::DeviceRuntime;
use kotton_crypto::kel_verify::{resolve_current_key, LocalArbiter};
use kotton_crypto::ed25519::VerifyingKey;
use kotton_identity::kel_store;
use kotton_net::transport::quic::tls::{Admission, Admitted};
use kotton_net::transport::Peer;
use kotton_wire::kel::KelEvent;
use sqlx::SqlitePool;
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Teach `admission` every chain this node holds for `user_ids` — at startup, and
/// whenever the set of hosted identities changes.
///
/// Per loaded user, never across all of them, for the reason `reproject_allowlist`
/// gives: a locked user's identity must not be admittable while its user is not.
pub fn reproject(base: &Path, user_ids: &[String], admission: &Admission) {
    for uid in user_ids {
        match kel_store::load_chain(base, uid) {
            Ok(chain) if !chain.is_empty() => admission.learn_chain(&chain),
            Ok(_) => {}
            Err(e) => tracing::warn!(user_id = %uid, error = %e, "admission: chain unreadable"),
        }
    }
}

/// Which local user an identity is registered as, if any.
pub fn user_for_aid(base: &Path, aid: &str) -> Option<String> {
    let registry = crate::registry::load_users(&base.join("system")).ok()?;
    registry
        .users
        .into_iter()
        .find(|u| u.did == aid)
        .map(|u| u.user_id)
}

/// Which identity a local user is registered as: the inverse of [`user_for_aid`].
pub fn aid_for_user(base: &Path, user_id: &str) -> Option<String> {
    let registry = crate::registry::load_users(&base.join("system")).ok()?;
    registry
        .users
        .into_iter()
        .find(|u| u.user_id == user_id)
        .map(|u| u.did)
}

/// What admitting a device reads and writes of the machine, and nothing else: the
/// hosted identities' chains and the users they are registered as, kept under the
/// base directory, and the handshake's [`Admission`] table.
///
/// The functions below that take a [`DeviceRuntime`] read these two things of it
/// and no other. A caller that must not hold the machine — a peer's request, served
/// on its own standing — is lent this instead ([`Chains::of`]): no keychain is here,
/// so no store keyed from one can be opened through it.
#[derive(Clone)]
pub struct Chains {
    base: PathBuf,
    admission: Admission,
}

impl Chains {
    /// The chains under `base`, projected into `admission`.
    pub fn new(base: PathBuf, admission: Admission) -> Self {
        Self { base, admission }
    }

    /// The runtime's own: its base directory and its live admission table (a
    /// clone of [`Admission`] shares the maps).
    pub fn of(runtime: &DeviceRuntime) -> Self {
        Self::new(runtime.base_dir().clone(), runtime.admission())
    }

    /// The identity `user_id` is registered as ([`aid_for_user`]).
    pub fn aid_of(&self, user_id: &str) -> Option<String> {
        aid_for_user(&self.base, user_id)
    }

    /// `user_id`'s stored chain, empty when there is none or it does not read.
    pub fn chain(&self, user_id: &str) -> Vec<KelEvent> {
        kel_store::load_chain(&self.base, user_id).unwrap_or_default()
    }

    /// [`adopt_chain_extension`], on the chains alone.
    pub fn adopt(&self, user_id: &str, events: &[KelEvent]) -> io::Result<()> {
        let base = &self.base;
        let mut chain = kel_store::load_chain(base, user_id).map_err(io::Error::other)?;
        let tip_seq = chain.last().map(|e| e.seq).unwrap_or(0);
        let mut extended = false;
        for e in events {
            if e.seq > tip_seq {
                chain.push(e.clone());
                extended = true;
            }
        }
        if extended {
            resolve_current_key(&chain, &LocalArbiter, false)
                .map_err(|e| io::Error::other(format!("offered events do not replay: {e}")))?;
            kel_store::save_chain(base, user_id, &chain).map_err(io::Error::other)?;
        }
        self.admission.learn_chain(&chain);
        Ok(())
    }
}

/// Take the events a peer offered past this node's tip, replay the whole chain,
/// and keep it — then project it into what this node will admit.
///
/// **A blind node's copy of an identity's chain has to track the identity's.**
/// It is the only thing the node can check a recovery claim against
/// (`Admission::learn_chain` indexes each set an inception, an add-recovery or a
/// recovery rotation carries, read through `kel_verify::committed_set`, which
/// returns a set only where it makes its event's commitment), so a chain that
/// stops at the moment of enrolment can only admit the authorities that existed
/// then.
///
/// That is not a corner case; it is the order the host guides (`docs/use/run-a-vault.md`,
/// then `docs/use/recover-and-start-over.md`) tell a person to work in: admit a node,
/// *then* `kotton id add-recovery`, and the phrase-derived authority is committed in
/// a key event the node never receives. Without this, the node keeps the sealed copy
/// — it is delivered in the same breath — and then refuses the one device that will
/// ever ask for it, with *"Device public key not in paired allowlist, and no key
/// events were offered that authorize it."* A test that sets the phrase **before**
/// enrolling the node never meets this, because the copy rides the pairing payload
/// beside a chain that already committed it.
///
/// **Nothing is taken on the peer's word.** Only events past the stored tip are
/// considered, and the result is replayed from the beginning: each event must be
/// authorized by the key state its predecessor established. And what the index
/// learns of an event is the set `kel_verify::committed_set` returns for it, the
/// set that makes the commitment the event's signature covers, never a set it
/// merely carries. A peer cannot insert an authority the identity did not sign
/// for — which is why the same helper is
/// safe for `persist_admitted`, where the offering device is not yet paired at
/// all, and narrower here, where it already is.
pub fn adopt_chain_extension(
    runtime: &DeviceRuntime,
    user_id: &str,
    events: &[KelEvent],
) -> io::Result<()> {
    Chains::of(runtime).adopt(user_id, events)
}

/// Rule 4: write the handshake's verdict down.
///
/// Extends the stored chain with the events the device offered past this node's
/// tip, replays the whole to be sure, records the device in `paired_nodes`, and
/// projects it into the live allowlist. Returns the user the device now belongs to.
///
/// The events were already verified by `admits_device` in the handshake; replaying
/// again here is cheap and is what keeps a stored chain something this node can
/// stand behind without trusting its own earlier self.
pub async fn persist_admitted(
    runtime: &DeviceRuntime,
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<VerifyingKey>>>,
    peer_key: VerifyingKey,
    aid: &str,
    events: &[KelEvent],
) -> io::Result<String> {
    persist_admitted_in(&Chains::of(runtime), db, paired_keys, peer_key, aid, events).await
}

/// [`persist_admitted`], on the chains alone ([`Chains`]).
async fn persist_admitted_in(
    chains: &Chains,
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<VerifyingKey>>>,
    key: VerifyingKey,
    aid: &str,
    events: &[KelEvent],
) -> io::Result<String> {
    let peer_pubkey = *key.as_bytes();
    let user_id = user_for_aid(&chains.base, aid).ok_or_else(|| {
        io::Error::other(format!("admitted identity {aid} is hosted under no local user"))
    })?;

    chains.adopt(&user_id, events)?;

    // Written by its key, under its derivation, where no row of the person's
    // holds the key; a row that does is left as it is, since this write brings
    // nothing it may lack: a made label, no address, no posture
    // (kottonllc/kotton#597, 27A, 69A).
    let now = kotton_common::time::now_secs();
    let id = format!("recovered-{}", &hex::encode(peer_pubkey)[..8]);
    kotton_peer::daemon::db::add_paired_node_if_absent(db, &id, &user_id, &key, "[]", now, None).await?;
    paired_keys.write().unwrap().insert(key);
    chains.admission.take_admitted(&peer_pubkey);
    tracing::info!(user_id = %user_id, peer = %kotton_crypto::DidKeyMethod::from_public_key(&key), "admitted a recovered device on proof");
    Ok(user_id)
}

/// What a connected peer is to a user this node keeps for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerStanding {
    /// On the allowlist for this user, or admitted on proof and now written down
    /// as paired (rule 4 of recovered-device admission).
    Paired,
    /// Admitted on a recovery claim for `aid`: it has proved only that it holds
    /// a recovery authority of an identity this node hosts, and may fetch that
    /// identity's chain and sealed copy and nothing else.
    Claim { aid: String },
    /// The vault's operator credential (`operator_key`): the key its landlord's
    /// desktop speaks under. It is nobody's device and no user's member, so it
    /// is decided before any user is asked about, and it stands to the node
    /// rather than to a pool. What it may say — the landlord's six verbs and
    /// nothing a tenant's standing reaches — is the vault's table
    /// (`kvaultd::peer::reaches`); a device enrols no operator, so on a device
    /// no connection is ever this.
    Operator,
    /// None of the above. What a stranger may do — a guest session, or nothing
    /// — is the caller's decision, not this function's.
    Stranger,
}

/// What a vault says to a key that is paired at it, but to another pool than
/// the one its request named: `held` is the pool the key is paired to, `asked`
/// the one it named. The sentence has one maker, the vault
/// (`kvaultd::peer::refusal`), and no reader of its words: it rides in
/// `UserResponse::NotPairedAs`, whose kind says which refusal it is, and every
/// reader prints it as data and decides nothing by it.
pub fn paired_as_another(held: &str, asked: &str) -> String {
    format!("{PAIRED_AS_ANOTHER} `{held}`, and asked as `{asked}`")
}

/// The words [`paired_as_another`] opens with. Made into a sentence, never
/// looked for in one.
pub const PAIRED_AS_ANOTHER: &str = "this device is paired here as tenant";

/// What a vault's refusal of a stranger says, between the peer's DID and the
/// pool it named. Made into the vault's sentence, never looked for in one:
/// whether a vault refused is the answer it sent (`UserResponse::NotPairedAs`).
pub const NOT_PAIRED_WITH: &str = "is not paired with user";

/// Classify a peer the handshake admitted, for one user.
///
/// `peer` is who the connection says it is from. A claim's standing is read
/// from the connection (#511): a peer admitted on a recovery claim stands as
/// that claim to a user, and is asked about no key, since it has none, so no
/// key check — paired, operator or proof — can give it another standing. A key
/// is the raw key behind its `did:key`; one whose DID does not parse is a
/// stranger, never an error. (The QUIC path still names a claimant by its
/// certificate's key, and its claim is read from the admission table under that
/// key, until step 12 of #496.) A proof-admitted
/// peer is persisted here, on its first request, so it is an ordinary paired
/// device from then on; a claim is not persisted, because a claim proves less.
///
/// `user_id` is the pool the request is addressed to, and `None` for a request
/// addressed to the node as a whole (a vault's `Tenants`): only the operator
/// stands to that, so every other peer is a stranger to it. The operator is
/// decided first, so a key that were both an operator and a user's device
/// would stand as the operator — the narrower of the two, by the vault's table.
pub async fn peer_standing(
    runtime: &DeviceRuntime,
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<VerifyingKey>>>,
    peer: &Peer,
    user_id: Option<&str>,
) -> io::Result<PeerStanding> {
    peer_standing_in(&Chains::of(runtime), db, paired_keys, peer, user_id).await
}

/// [`peer_standing`], on the chains alone ([`Chains`]): what a caller that holds
/// no machine classifies a peer with.
pub async fn peer_standing_in(
    chains: &Chains,
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<VerifyingKey>>>,
    peer: &Peer,
    user_id: Option<&str>,
) -> io::Result<PeerStanding> {
    let peer_did = match peer {
        // A claim stands to a user and to nothing addressed to the node as a whole.
        Peer::Claim { aid } => {
            return Ok(match user_id {
                Some(_) => PeerStanding::Claim { aid: aid.clone() },
                None => PeerStanding::Stranger,
            })
        }
        Peer::Key(did) => did.as_str(),
    };
    // The decode holds 4A: only the derivation's string for bytes the Ed25519
    // rule admits gives a key, and a DID that gives none stands as a stranger,
    // with nothing written.
    let peer_key: Option<VerifyingKey> = kotton_wire::did::Did::parse(peer_did)
        .ok()
        .and_then(|d| kotton_crypto::did::DidKeyMethod::to_public_key(&d).ok());
    let Some(peer_key) = peer_key else {
        return Ok(PeerStanding::Stranger);
    };
    let pk = *peer_key.as_bytes();
    if kotton_peer::daemon::db::is_operator_key(db, &pk).await? {
        return Ok(PeerStanding::Operator);
    }
    let Some(user_id) = user_id else {
        return Ok(PeerStanding::Stranger);
    };
    if kotton_peer::daemon::db::is_pubkey_paired_to_user(db, &pk, user_id)
        .await
        .map_err(io::Error::other)?
    {
        return Ok(PeerStanding::Paired);
    }
    match chains.admission.admitted(&pk) {
        Some(Admitted::ByProof { aid, events }) => {
            match persist_admitted_in(chains, db, paired_keys, peer_key, &aid, &events).await {
                Ok(admitted_user) if admitted_user == user_id => Ok(PeerStanding::Paired),
                Ok(_) => Ok(PeerStanding::Stranger),
                Err(e) => {
                    tracing::warn!(peer_did = %peer_did, error = %e, "could not persist an admission");
                    Ok(PeerStanding::Stranger)
                }
            }
        }
        Some(Admitted::ByClaim { aid }) => Ok(PeerStanding::Claim { aid }),
        None => Ok(PeerStanding::Stranger),
    }
}

/// **A device admitted on proof is written by its key** (kottonllc/kotton#624;
/// kottonllc/kotton#597, 27A, 28A, 69A), with keys from seeds.
#[cfg(test)]
mod named_by_key_tests {
    use super::*;

    const PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";

    async fn a_device_hosting_alice(temp: &tempfile::TempDir) -> (DeviceRuntime, Arc<SqlitePool>, String) {
        let rt = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            crate::config::RuntimeConfig::default(),
            Arc::new(kotton_secret::MemorySecrets::new()),
        )
        .await
        .unwrap();
        crate::users::commands::create_user(&rt, "alice", PASSPHRASE).await.unwrap();
        let db = Arc::new(crate::db::open_machine_db(temp.path().join("agent.db")).await.unwrap());
        let aid = aid_for_user(rt.base_dir(), "alice").expect("alice is registered");
        (rt, db, aid)
    }

    fn key(seed: u8) -> VerifyingKey {
        kotton_crypto::ed25519::verifying_key(&ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }

    /// Every row of alice's, column for column.
    async fn rows(db: &Arc<SqlitePool>) -> Vec<(String, String, Vec<u8>, String, i64, Option<String>)> {
        sqlx::query_as(
            "SELECT id, device_did, public_key, addresses, paired_at, posture FROM paired_nodes \
             WHERE user_id = 'alice' ORDER BY device_did",
        )
        .fetch_all(db.as_ref())
        .await
        .unwrap()
    }

    fn admitted_by_proof(rt: &DeviceRuntime, key: &VerifyingKey, aid: &str) {
        rt.admission()
            .admitted
            .write()
            .unwrap()
            .insert(*key.as_bytes(), Admitted::ByProof { aid: aid.to_string(), events: Vec::new() });
    }

    /// **A device admitted on proof is written under its key's derivation**, and
    /// its key admitted, through the door: the connection names it by that
    /// derivation, and it stands as paired.
    #[tokio::test]
    async fn a_device_admitted_on_proof_is_written_under_its_keys_derivation() {
        let temp = tempfile::tempdir().unwrap();
        let (rt, db, aid) = a_device_hosting_alice(&temp).await;
        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        let k = key(71);
        let did = kotton_crypto::DidKeyMethod::from_public_key(&k).to_string();
        admitted_by_proof(&rt, &k, &aid);

        let standing = peer_standing(&rt, &db, &paired_keys, &Peer::Key(did.clone()), Some("alice")).await.unwrap();
        assert_eq!(standing, PeerStanding::Paired);
        let all = rows(&db).await;
        assert_eq!(all.len(), 1, "{all:?}");
        assert_eq!((all[0].1.as_str(), all[0].2.as_slice()), (did.as_str(), k.as_bytes().as_slice()));
        assert!(paired_keys.read().unwrap().contains(&k));
    }

    /// **At the door, a DID that does not decode to a key stands as a stranger,
    /// and nothing is written** (4A's decode, said as that): another spelling of
    /// an admitted key's `did:key`, and a DID of another method.
    #[tokio::test]
    async fn a_door_did_that_does_not_decode_stands_as_a_stranger_and_nothing_is_written() {
        let temp = tempfile::tempdir().unwrap();
        let (rt, db, aid) = a_device_hosting_alice(&temp).await;
        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        let k = key(72);
        admitted_by_proof(&rt, &k, &aid);
        for did in [kotton_crypto::DidKeyMethod::spelled_otherwise(k.as_bytes()).to_string(), "did:web:laptop.example".to_string()] {
            let standing = peer_standing(&rt, &db, &paired_keys, &Peer::Key(did.clone()), Some("alice")).await.unwrap();
            assert_eq!(standing, PeerStanding::Stranger, "{did}");
            assert!(rows(&db).await.is_empty(), "{did}: a row was written");
            assert!(paired_keys.read().unwrap().is_empty(), "{did}: a key was admitted");
            assert!(rt.admission().admitted(k.as_bytes()).is_some(), "{did}: the admission was taken");
        }
    }

    /// **A device admitted on proof whose key has a row under another spelling
    /// leaves that row byte for byte as it was** (69A): the admission brings a
    /// made label, no address and no posture, which the row may not lack. The
    /// key is admitted.
    #[tokio::test]
    async fn a_device_admitted_on_proof_leaves_a_row_under_another_spelling_as_it_is() {
        let temp = tempfile::tempdir().unwrap();
        let (rt, db, aid) = a_device_hosting_alice(&temp).await;
        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        let k = key(73);
        let otherwise = kotton_crypto::DidKeyMethod::spelled_otherwise(k.as_bytes()).to_string();
        kotton_peer::daemon::db::seed_paired_node_as_stored(&db, "laptop", "alice", &otherwise, k.as_bytes(), r#"["127.0.0.1:7"]"#, 5, Some("full"))
            .await
            .unwrap();
        let before = rows(&db).await;
        admitted_by_proof(&rt, &k, &aid);

        let user = persist_admitted(&rt, &db, &paired_keys, k, &aid, &[]).await.unwrap();
        assert_eq!(user, "alice");
        assert_eq!(rows(&db).await, before, "the row was changed");
        assert!(paired_keys.read().unwrap().contains(&k));
    }
}
