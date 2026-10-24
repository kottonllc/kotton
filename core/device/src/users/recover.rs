// SPDX-License-Identifier: AGPL-3.0-or-later
//! `recover` — take the account back on a device that holds nothing but the phrase.
//!
//! Two verbs, not one: `login` is the ordinary sign-in and stays non-destructive; on a device
//! that has never held the identity it can only claim a locked slot, because there is
//! nothing local to verify the phrase against. This is the verb that makes the claim
//! good, in the order the constitution requires — **prove before install**:
//!
//! 1. Ask the user's paired nodes for the identity's public chain and phrase-sealed
//!    recovery copy. A node serves those only to a device that proved, in the TLS
//!    handshake, that it holds a recovery authority the chain committed
//!    ([`RecoveryClaim`]) — so a guessed phrase learns nothing, not even whether the
//!    node hosts the name it asked for.
//! 2. Replay the chain and check the phrase against its committed recovery set.
//!    Whatever handed the chain over cannot lie: the check is against the commitment.
//! 3. Open the recovery copy with the phrase; install the data roots.
//! 4. Rotate the identity onto **this device's own key**. The rotation
//!    event is the proof every node admits the device on, so it must name the key
//!    the device will present — the TLS key, not a fresh random one. A copy of the
//!    identity key this device kept sealed under the person's old passphrase seals
//!    the key just replaced, so it is removed ([`Recovered::sealed_copy_removed`])
//!    with that passphrase's record, and the roots are sealed under the passphrase
//!    the person chose for this device before the recovery began, with the lock
//!    policy set to it. A recovered device is never held without a sealed copy.
//! 5. Dial each node offering that one event. The node's verifier admits by proof
//!    and its handler persists membership, after which the device is an ordinary
//!    paired device there and the next sync pulls everything back.
//!
//! No node vouches for anything, issues anything, or learns a secret: the chain is
//! public by construction, the copy opens under the phrase alone, and the phrase never
//! leaves this device. Article XIII holds — a node reachable directly needs no third
//! party for any of this.
//!
//! **The vault the person's line names, and the drive.** The request carries the line
//! the recovery card printed under the words (`kotton-instance:vault:<key>@<ip>:<port>`),
//! and [`recover`] reads it here, in the daemon, for every door that recovers —
//! `kotton id recover` and the REPL's `id recover` send the same request:
//!
//! - **Before anything is written**, the words are read as a phrase, the passphrase is
//!   held to the bar, and the line is read as a vault's. A line whose key this device
//!   pairs for the person under a posture other than `blind-storage` (one of their own
//!   devices, a cosigner) is refused here: a drive is a vault, and nothing is relabelled.
//! - **The node to dial.** Unless the person pairs a node under the line's key already,
//!   the vault is added under `vault` (or `vault-` and eight hex of its key, when that
//!   label is taken) at the line's address. One paired under the key at another address
//!   is re-addressed as `peer add` does, keeping its posture and relay route: the line
//!   is where the person says the vault is now.
//! - **Steps 1 to 5**, against every node the person pairs, the vault among them.
//! - **Refused: the node added is taken back.** Everything the steps can fail on comes
//!   before the rotation is presented to any node, so a refused recovery has changed
//!   nothing anywhere but here, and here the node this request added is removed
//!   ([`kotton_peer::daemon::nodes::take_back_added`]). A node re-addressed is left at
//!   the line's address. The claim a door made is the door's to take back.
//! - **Proved: the vault is recorded as the person's drive**, through the one writer
//!   ([`kotton_peer::daemon::drives::record`]), with the row's posture `blind-storage`,
//!   the record enrolling the vault writes. Only after the proof, so words that prove
//!   nothing make no node a drive and there is no drive to take back. A record that
//!   cannot be written then is said beside the success ([`Recovered::drive_not_recorded`]),
//!   never as a refusal: the identity is already rotated, and recovering again would
//!   rotate it again.
//!
//! This is one of the three places a device records a drive, each naming a vault:
//! enrolment, this, and the membership projection (`kotton_peer::daemon::drives`).
//! Until #80 a door added the vault itself and then said "this is a drive" with
//! `PeerAdd { drive: true }`, a flag any local session could set on any key; the
//! REPL's door never said it (#76). Both are gone: the drive is recorded where the
//! proof is.

use crate::users::commands::{phrase_holds_authority, rotate_identity_to_key};
use crate::users::residency::Residency;
use crate::users::DeviceUsers as _;
use crate::DeviceRuntime;
use anyhow::{anyhow, Context, Result};
use kotton_crypto::kel_verify::{resolve_current_key, LocalArbiter};
use kotton_crypto::{try_mnemonic_to_seed32, OperationalRoots};
use kotton_identity::kel_store;
use kotton_identity::provisioning::{
    read_recovery_bundle, store_operational_roots, write_recovery_bundle,
    write_recovery_bundle_raw,
};
use kotton_net::transport::quic::tls::{CertOffer, RecoveryClaim};
use kotton_wire::ipc::{UserRequest, UserResponse};
use kotton_wire::kel::KelEvent;
use kotton_wire::peer::PairedNode;
use sqlx::SqlitePool;
use std::sync::Arc;

/// How many rungs of the phrase's ladder a fetch tries before giving up on a node.
///
/// A device with only the phrase cannot know which rung the chain is standing on —
/// that is in the chain it is trying to fetch. Rung 0 is committed by the event that
/// added the phrase and stays in the chain, so it is always enough for a node that
/// holds the whole chain; the rest cover a node that has collapsed to its tip after
/// that many recoveries, which is a bound on the ladder a person climbs in a lifetime.
const CLAIM_RUNGS: u64 = 4;

/// What `recover` leaves behind.
#[derive(Debug)]
pub struct Recovered {
    /// The `did:kel` AID, unchanged by recovery.
    pub did: String,
    /// The identity's new operational key — this device's own, hex.
    pub new_key_hex: String,
    /// How many of the user's paired nodes admitted this device on the rotation.
    pub nodes_admitted: usize,
    /// Whether this device kept a copy of the identity key sealed under the
    /// person's old passphrase, now replaced: it sealed the key the rotation
    /// replaced. Either way the roots are sealed under the new passphrase.
    pub sealed_copy_removed: bool,
    /// Why the vault the line names was not recorded as the person's drive, when
    /// the phrase proved and the record could not be written; `None` when it is
    /// recorded.
    pub drive_not_recorded: Option<String>,
}

/// Recover `user_id` onto this device from `recovery_key` and the vault `vault_line`
/// names, and seal it under `passphrase`, the one the person chose for this device:
/// add the vault, prove, rotate, be admitted, and record the vault as the person's
/// drive, or take the node back on a refusal. See the module doc.
///
/// The words, the passphrase and the line are read, and the passphrase held to the
/// bar, before anything is fetched or written, so a refusal of any of them changes
/// nothing.
///
/// **Not idempotent, deliberately.** A second run rotates again and climbs the
/// reserve ladder a rung; the first run's local state is complete on its own, so
/// a node that failed to admit is retried by dialling it, not by recovering again.
pub async fn recover(
    runtime: &DeviceRuntime,
    users: &dyn Residency,
    db: &Arc<SqlitePool>,
    user_id: &str,
    recovery_key: &str,
    passphrase: &str,
    vault_line: &str,
) -> Result<Recovered> {
    let asked = what_was_asked(runtime, user_id, recovery_key, passphrase)?;
    let (vault_key, vault_addr) =
        kotton_wire::line::InstanceLine::vault(vault_line).map_err(|why| anyhow!("{why}; nothing was changed"))?;

    let vault = point_at_the_vault(runtime, db, user_id, vault_key, vault_addr).await?;
    let mut done = match prove_and_rotate(runtime, users, db, user_id, recovery_key, passphrase, asked).await {
        Ok(done) => done,
        Err(refused) => {
            let Some(added) = vault.added.then_some(vault.label.as_str()) else {
                return Err(refused);
            };
            return Err(
                match kotton_peer::daemon::nodes::take_back_added(db, &runtime.paired_keys(), user_id, added).await {
                    Ok(()) => refused,
                    Err(e) => anyhow!(
                        "{refused:#}; and the node '{added}' this recovery added for the line is still paired \
                         here ({e}) — `kotton peer --user {user_id} revoke {added}` removes it"
                    ),
                },
            );
        }
    };
    // The phrase proved: the vault the person's line names is their drive.
    done.drive_not_recorded = kotton_peer::daemon::drives::record(db, user_id, &vault_key)
        .await
        .err()
        .map(|e| format!("the vault at '{}' was not recorded as your drive ({e})", vault.label));
    Ok(done)
}

/// What [`recover`] reads before anything is written: the words as a phrase's seed,
/// and whether attempts are limited here, with the passphrase held to the bar that
/// sets.
#[derive(Clone, Copy)]
struct Asked {
    seed32: [u8; 32],
    limiting: kotton_sys::secret::AttemptLimiting,
}

fn what_was_asked(runtime: &DeviceRuntime, user_id: &str, recovery_key: &str, passphrase: &str) -> Result<Asked> {
    let seed32 = try_mnemonic_to_seed32(recovery_key).map_err(|e| anyhow!(e))?;
    let limiting = kotton_identity::provisioning::attempt_limiting_for_user(runtime, user_id);
    kotton_crypto::daily_credential::assess(
        passphrase,
        kotton_crypto::daily_credential::required_entropy_bits_for(limiting),
    )
    .map_err(|weak| anyhow!("{weak}; nothing was changed"))?;
    Ok(Asked { seed32, limiting })
}

/// The node a recovery dials for the line's vault: its label, and whether this
/// recovery added it (and so takes it back on a refusal).
struct VaultNode {
    label: String,
    added: bool,
}

/// Make the line's vault a node `user_id` pairs here (module doc): kept where it is
/// paired at the line's address, re-addressed where it is paired at another, added
/// where it is not paired. Refused, with nothing written, where its key is paired
/// under a posture other than `blind-storage`.
async fn point_at_the_vault(
    runtime: &DeviceRuntime,
    db: &Arc<SqlitePool>,
    user_id: &str,
    key: [u8; 32],
    addr: std::net::SocketAddr,
) -> Result<VaultNode> {
    let nodes = kotton_peer::daemon::db::list_paired_nodes(db, user_id).await.context("list paired nodes")?;
    let paired = nodes.iter().find(|n| n.public_key == key);
    if let Some(n) = paired {
        if let Some(other) = n.posture.as_deref().filter(|p| *p != kotton_schemas::membership::Posture::BlindStorage.as_str()) {
            return Err(anyhow!(
                "the line's key is '{}' here, paired as {other} and not as a vault, so it is not the vault \
                 that keeps your things — check the line against what you wrote down; nothing was changed",
                n.id
            ));
        }
        if n.addresses.first() == Some(&addr) {
            return Ok(VaultNode { label: n.id.clone(), added: false });
        }
    }
    let (label, added) = match paired {
        Some(n) => (n.id.clone(), false),
        None => (label_for(&nodes, &key), true),
    };
    let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&key)
        .map_err(|e| anyhow!("the line's key is not a vault's key: {e}; nothing was changed"))?
        .to_string();
    match kotton_peer::daemon::nodes::peer_add(
        db,
        &runtime.paired_keys(),
        user_id.to_string(),
        label.clone(),
        did,
        hex::encode(key),
        addr,
    )
    .await?
    {
        UserResponse::NodePaired { .. } => Ok(VaultNode { label, added }),
        UserResponse::Error { message } => Err(anyhow!("{message}; nothing was changed")),
        other => Err(anyhow!("unexpected reply {other:?}")),
    }
}

/// The label a vault the line names is added under: `vault`, or, when the person
/// pairs a node under that label already, `vault-` and the first eight hex of its key.
fn label_for(taken: &[PairedNode], key: &[u8; 32]) -> String {
    if taken.iter().any(|n| n.id == "vault") {
        format!("vault-{}", &hex::encode(key)[..8])
    } else {
        "vault".to_string()
    }
}

/// Steps 1 to 5 of the module doc, against every node `user_id` pairs here.
async fn prove_and_rotate(
    runtime: &DeviceRuntime,
    users: &dyn Residency,
    db: &Arc<SqlitePool>,
    user_id: &str,
    recovery_key: &str,
    passphrase: &str,
    asked: Asked,
) -> Result<Recovered> {
    let Asked { seed32, limiting } = asked;
    let base = runtime.base_dir();

    let nodes = kotton_peer::daemon::db::list_paired_nodes(db, user_id)
        .await
        .context("list paired nodes")?;

    // 1–2. The chain: whatever this device already holds, else fetched and proven.
    let mut chain = kel_store::load_chain(base, user_id)?;
    if chain.is_empty() {
        if nodes.is_empty() {
            return Err(anyhow!(
                "'{user_id}' has no key history on this device and no paired node to fetch it \
                 from. Recover with the line of the vault that keeps your data."
            ));
        }
        let (fetched, bundle, from) = fetch_material(runtime, &nodes, user_id, &seed32).await?;
        resolve_current_key(&fetched, &LocalArbiter, false)
            .map_err(|e| anyhow!("the chain '{from}' served does not replay: {e}"))?;
        if !phrase_holds_authority(&fetched, &seed32) {
            return Err(anyhow!(
                "this recovery phrase is not an authority for the identity '{from}' serves as \
                 '{user_id}'"
            ));
        }
        kel_store::save_chain(base, user_id, &fetched)?;
        if let Some(bundle) = bundle.as_deref() {
            write_recovery_bundle_raw(base, user_id, bundle)?;
        }
        chain = fetched;
    } else if !phrase_holds_authority(&chain, &seed32) {
        return Err(anyhow!(
            "this recovery phrase is not an authority for '{user_id}'"
        ));
    }
    let did = chain[0].aid.to_string();

    // 3. The data roots, out of the copy the phrase opens. Only those: the copy
    // holds no signing key, and step 4 makes one by rotation.
    let data = read_recovery_bundle(base, user_id, &seed32)?.ok_or_else(|| {
        anyhow!(
            "'{user_id}' has no recovery copy on this device and none of its paired nodes \
             kept one, so the phrase can prove the identity but not open the data. A copy is \
             delivered to a blind node when it is enrolled after the phrase is set up."
        )
    })?;

    // 4. Rotate onto this device's key. From here the identity signs with the same
    // key the device presents to every peer.
    let device_sk = runtime.device_signing_key().clone();
    let rotation =
        rotate_identity_to_key(base, runtime.secrets(), user_id, recovery_key, &device_sk)
            .await?;
    let roots = OperationalRoots {
        master_secret: data.master_secret,
        identity_key: device_sk.to_bytes(),
        cek: data.cek,
    };
    store_operational_roots(runtime.secrets(), user_id, &roots);
    // Re-seal the copy this device keeps: the same two data roots, and — if the
    // fetched copy was an old one that carried a signing key — without it.
    write_recovery_bundle(base, user_id, &seed32, &roots.master_secret, &roots.cek)?;
    chain.push(rotation.clone());
    runtime.admission().learn_chain(&chain);
    // The copy this device sealed under the old passphrase holds the key just
    // replaced, and that passphrase would restore it, so it goes, and its record
    // with it; then the roots are sealed under the passphrase chosen for this
    // device, and the policy records it. All before the answer: a device whose
    // roots are held only in memory loses them to a restart or an auto-lock.
    // A step that fails here answers failure, never success, and says the key is
    // already rotated, because recovering again climbs a rung of the ladder.
    let rotated = |what: &str, e: anyhow::Error| {
        anyhow!(
            "'{user_id}' is rotated onto this device's key, and {what}: {e:#}. Recovering \
             again would rotate again, a rung further up the phrase's ladder; set a \
             passphrase with `kotton id set-passphrase {user_id}` instead."
        )
    };
    let sealed_copy_removed = kotton_identity::provisioning::remove_sealed_copy(runtime, user_id)
        .and_then(|removed| {
            kotton_session::lock_policy::forget_credential(base, user_id)?;
            Ok(removed)
        })
        .map_err(|e| rotated("the copy sealed under the old passphrase could not be removed", e))?;
    let auto_lock_minutes = kotton_session::lock_policy::load(base, user_id)
        .map(|p| p.auto_lock_minutes)
        .map_err(|e| rotated("its lock policy could not be read", e.into()))?;
    // Judged and hashed before the seal, recorded after it: the order every door
    // that sets a passphrase keeps, so the record never names one this device
    // holds nothing under.
    let policy = kotton_session::lock_policy::prepare_policy(
        kotton_wire::ipc::LockMode::Passphrase,
        auto_lock_minutes,
        Some(passphrase),
        limiting,
    )
    .map_err(|e| rotated("the new passphrase could not be hashed", e.into()))?;
    kotton_identity::provisioning::set_user_pin(runtime, user_id, passphrase)
        .await
        .map_err(|e| rotated("no sealed copy is held on this device", e))?;
    policy.record(base, user_id).map_err(|e| {
        rotated(
            "its keys are sealed under the new passphrase, which could not be recorded",
            e.into(),
        )
    })?;

    set_registry_did(base, user_id, &did)?;
    let store = runtime
        .reload_user_runtime(user_id)
        .await
        .context("reopen the user's store with its keys")?;
    users.insert(user_id.to_string(), store);

    // 5. Be admitted where the data is.
    let mut nodes_admitted = 0;
    for node in nodes {
        let label = node.id.clone();
        match admit_at(runtime, node, user_id, &rotation).await {
            Ok(()) => nodes_admitted += 1,
            Err(e) => tracing::warn!(user_id, node = %label, error = %e, "recover: node did not admit this device"),
        }
    }

    Ok(Recovered {
        did,
        new_key_hex: hex::encode(device_sk.verifying_key().to_bytes()),
        nodes_admitted,
        sealed_copy_removed,
        drive_not_recorded: None,
    })
}

/// Step 1: the chain and copy, from the first node that serves them.
///
/// Every refusal a node gives is the same string by design (`admit_by_proof`), so
/// this cannot tell "wrong rung" from "wrong node" — it tries the next and reports
/// the last. That opacity is the node's, not an inconvenience to route around.
async fn fetch_material(
    runtime: &DeviceRuntime,
    nodes: &[PairedNode],
    user_id: &str,
    seed32: &[u8; 32],
) -> Result<(Vec<KelEvent>, Option<String>, String)> {
    let device_pub = runtime.device_signing_key().verifying_key().to_bytes();
    let mut last_err: Option<anyhow::Error> = None;
    for node in nodes {
        for rung in 0..CLAIM_RUNGS {
            let reserve = ed25519_dalek::SigningKey::from_bytes(
                &kotton_crypto::kdf::derive_kel_recovery_key(seed32, rung),
            );
            let claim = RecoveryClaim::sign(&reserve, &device_pub);
            let dialer = runtime.dialer().with_offer(CertOffer::claim(claim));
            let client = match dialer.connect(node.clone(), user_id).await {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(anyhow!("{}: {e}", node.id));
                    continue;
                }
            };
            let req = UserRequest::RecoveryFetch {
                user_id: user_id.to_string(),
            };
            match client.send(&req).await {
                Ok(UserResponse::RecoveryMaterial { kel, bundle }) if !kel.is_empty() => {
                    return Ok((kel, bundle, node.id.clone()));
                }
                Ok(UserResponse::RecoveryMaterial { .. }) => {
                    last_err = Some(anyhow!("{}: holds no key history for '{user_id}'", node.id));
                }
                Ok(UserResponse::Error { message }) => {
                    last_err = Some(anyhow!("{}: {message}", node.id));
                }
                Ok(other) => {
                    last_err = Some(anyhow!("{}: unexpected reply {other:?}", node.id));
                }
                Err(e) => last_err = Some(anyhow!("{}: {e}", node.id)),
            }
            // The connection was admitted; a refusal now is the node's answer, not
            // the rung's. Move to the next node.
            break;
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no paired node served the recovery material")))
}

/// Step 5, at one node: present the rotation, and confirm the node now stands on it.
async fn admit_at(
    runtime: &DeviceRuntime,
    node: PairedNode,
    user_id: &str,
    rotation: &KelEvent,
) -> Result<()> {
    let dialer = runtime
        .dialer()
        .with_offer(CertOffer::events(vec![rotation.clone()]));
    let client = dialer.connect(node, user_id).await?;
    let req = UserRequest::RecoveryFetch {
        user_id: user_id.to_string(),
    };
    match client.send(&req).await? {
        UserResponse::RecoveryMaterial { kel, .. } => {
            if kel.last() != Some(rotation) {
                return Err(anyhow!(
                    "the node admitted this device but did not record the rotation"
                ));
            }
            Ok(())
        }
        UserResponse::Error { message } => Err(anyhow!(message)),
        other => Err(anyhow!("unexpected reply {other:?}")),
    }
}

/// A cold `login` registered the name with no identity behind it; the fetched chain
/// says which identity that is.
fn set_registry_did(base: &std::path::Path, user_id: &str, did: &str) -> Result<()> {
    let system_dir = base.join("system");
    let mut registry = crate::registry::load_users(&system_dir)?;
    let record = registry
        .users
        .iter_mut()
        .find(|u| u.user_id == user_id)
        .ok_or_else(|| anyhow!("'{user_id}' is not registered on this device"))?;
    if !record.did.is_empty() && record.did != did {
        return Err(anyhow!(
            "'{user_id}' on this device is a different identity than the one recovered"
        ));
    }
    record.did = did.to_string();
    crate::registry::save_users(&system_dir, &registry)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::commands::{add_recovery_phrase, create_user};
    use kotton_identity::provisioning::{
        open_vault_under, stage_rotated_vault, STAGED_VAULT_FILE, VAULT_FILE,
    };
    use kotton_session::lock_policy::{self, PinAttempt};
    use kotton_store::runtime::user::UserStore;
    use kotton_wire::ipc::OperatedService;
    use kotton_wire::line::InstanceLine;

    /// Five BIP-39 words, above the bar `create_user` holds a credential to.
    const OLD_PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";
    /// The passphrase chosen for this device at the recovery.
    const NEW_PASSPHRASE: &str = "abandon-ability-able-about-above";

    struct NobodyResident;
    impl Residency for NobodyResident {
        fn insert(&self, _: String, _: Arc<UserStore>) {}
        fn get(&self, _: &str) -> Option<Arc<UserStore>> {
            None
        }
    }

    async fn a_device_that_kept_its_sealed_copy(temp: &tempfile::TempDir) -> (DeviceRuntime, String) {
        let rt = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            crate::config::RuntimeConfig::default(),
            Arc::new(kotton_secret::MemorySecrets::new()),
        )
        .await
        .unwrap();
        create_user(&rt, "alice", OLD_PASSPHRASE).await.unwrap();
        let phrase = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice").await.unwrap();
        (rt, phrase)
    }

    async fn agent_db() -> Arc<SqlitePool> {
        let pool = Arc::new(SqlitePool::connect("sqlite::memory:").await.unwrap());
        crate::db::MIGRATOR.run(pool.as_ref()).await.unwrap();
        pool
    }

    /// **A device that kept its sealed copy is sealed again, in the same act, under
    /// the passphrase chosen for it.** The copy under the old passphrase, and a staged
    /// one beside it, seal the key the recovery replaced. When `recover` answers, the
    /// copy on disk opens under the new passphrase to this device's key and under the
    /// old one to nothing, no staged copy is left, the old passphrase is refused as
    /// wrong, and `Recovered` says a copy was replaced. A second recovery on the same
    /// device finds none of the old kind and says so.
    #[tokio::test]
    async fn recovering_where_a_sealed_copy_was_kept_reseals_under_the_new_passphrase() {
        let temp = tempfile::tempdir().unwrap();
        let (rt, phrase) = a_device_that_kept_its_sealed_copy(&temp).await;
        let dir = rt.base_dir().join("users").join("alice");
        let (sealed, staged) = (dir.join(VAULT_FILE), dir.join(STAGED_VAULT_FILE));
        stage_rotated_vault(&rt, "alice", OLD_PASSPHRASE, &[9u8; 32]).unwrap();
        assert!(sealed.exists() && staged.exists(), "the premise: this device kept sealed copies");
        let pool = agent_db().await;

        let done = proved(&rt, &pool, &phrase).await.unwrap();

        assert!(done.sealed_copy_removed, "the replacement is reported");
        assert!(!staged.exists(), "the staged copy is gone");
        let device_key = rt.device_signing_key().verifying_key().to_bytes();
        assert_eq!(done.new_key_hex, hex::encode(device_key), "the identity signs with this device's key");
        let opened = open_vault_under(&rt, "alice", NEW_PASSPHRASE).expect("the copy opens under the new passphrase");
        assert_eq!(
            ed25519_dalek::SigningKey::from_bytes(&opened.identity_key).verifying_key().to_bytes(),
            device_key,
            "the copy seals the recovered key"
        );
        assert!(open_vault_under(&rt, "alice", OLD_PASSPHRASE).is_err(), "the old passphrase opens a copy");
        let sessions: kotton_session::service::tokens::SessionMap = Default::default();
        assert!(
            matches!(
                lock_policy::try_unlock_with_pin(rt.base_dir(), "alice", OLD_PASSPHRASE, &sessions),
                Ok(PinAttempt::Wrong { .. })
            ),
            "the old passphrase is not refused as wrong"
        );
        assert!(sessions.read().unwrap().is_empty(), "the old passphrase opened a session");

        let again = proved(&rt, &pool, &phrase).await.unwrap();
        assert!(again.sealed_copy_removed, "the copy under the first recovery's passphrase is replaced too");
    }

    /// A passphrase below the bar, and a line that is not a vault's, are refused
    /// before anything happens: no node added, no rotation, and the sealed copy and
    /// the old passphrase are as they were.
    #[tokio::test]
    async fn a_weak_passphrase_or_a_line_that_is_no_vaults_is_refused_before_the_recovery_begins() {
        let temp = tempfile::tempdir().unwrap();
        let (rt, phrase) = a_device_that_kept_its_sealed_copy(&temp).await;
        let sealed = rt.base_dir().join("users").join("alice").join(VAULT_FILE);
        let (chain_before, copy_before) =
            (kel_store::load_chain(rt.base_dir(), "alice").unwrap().len(), std::fs::read(&sealed).unwrap());
        let pool = agent_db().await;

        let relay = InstanceLine { kind: OperatedService::Relay, hint: "http://127.0.0.1:7700".into(), key: key(9) }.to_text();
        for (passphrase, line) in [("hunter2", line_of(key(9), ADDR)), (NEW_PASSPHRASE, relay)] {
            let refused = recover(&rt, &NobodyResident, &pool, "alice", &phrase, passphrase, &line).await;
            let e = refused.expect_err("a weak passphrase or a relay's line recovered");
            assert!(e.to_string().contains("nothing was changed"), "{e}");
        }
        assert_eq!(kel_store::load_chain(rt.base_dir(), "alice").unwrap().len(), chain_before, "a rotation was appended");
        assert_eq!(std::fs::read(&sealed).unwrap(), copy_before, "the sealed copy changed");
        assert!(open_vault_under(&rt, "alice", OLD_PASSPHRASE).is_ok(), "the old passphrase no longer opens its copy");
        assert!(rows(&pool).await.is_empty(), "a refusal before the recovery added a node");
    }

    /// **Words that prove nothing take back the node the line added, and add no
    /// drive.** The device holds alice's log, so the words are checked against it
    /// and refused before any node is dialled. The node `Recover` added for the
    /// line is gone afterwards, its key off the live allowlist; a node the person
    /// already paired under the line's key at another address is left, at the
    /// line's address, and is no drive.
    #[tokio::test]
    async fn words_that_prove_nothing_take_back_the_node_the_line_added() {
        let temp = tempfile::tempdir().unwrap();
        let (rt, _phrase) = a_device_that_kept_its_sealed_copy(&temp).await;
        let pool = agent_db().await;
        let chain_before = kel_store::load_chain(rt.base_dir(), "alice").unwrap().len();

        let refused = recover(&rt, &NobodyResident, &pool, "alice", NOT_THEIRS, NEW_PASSPHRASE, &line_of(key(9), ADDR)).await;
        assert!(refused.expect_err("words that prove nothing").to_string().contains("not an authority"));
        assert!(rows(&pool).await.is_empty(), "the node the line added was left");
        assert!(!rt.paired_keys().read().unwrap().contains(&key(9)), "the line's key was left on the allowlist");

        kotton_peer::daemon::nodes::peer_add(
            &pool,
            &rt.paired_keys(),
            "alice".into(),
            "home".into(),
            did_of(&key(9)),
            hex::encode(key(9)),
            "127.0.0.1:7000".parse().unwrap(),
        )
        .await
        .unwrap();
        let refused = recover(&rt, &NobodyResident, &pool, "alice", NOT_THEIRS, NEW_PASSPHRASE, &line_of(key(9), ADDR)).await;
        assert!(refused.is_err(), "words that prove nothing recovered");
        let left = rows(&pool).await;
        assert_eq!(left.len(), 1, "{left:?}");
        assert_eq!((left[0].id.as_str(), left[0].addresses[0]), ("home", ADDR.parse().unwrap()), "{left:?}");
        assert!(kotton_peer::daemon::drives::list(&pool, "alice").await.unwrap().is_empty(), "a refusal recorded a drive");
        assert_eq!(kel_store::load_chain(rt.base_dir(), "alice").unwrap().len(), chain_before, "a rotation was appended");
    }

    /// **A line whose key is one of the person's own devices is refused before
    /// anything, and the device is not relabelled.** A drive is a vault; a row
    /// paired as `full` is the person's device, and recovery does not make it a
    /// sync target. The right words do not change that.
    #[tokio::test]
    async fn a_line_naming_a_device_of_the_persons_is_refused_and_the_row_kept() {
        let temp = tempfile::tempdir().unwrap();
        let (rt, phrase) = a_device_that_kept_its_sealed_copy(&temp).await;
        let pool = agent_db().await;
        kotton_peer::daemon::db::insert_paired_node(&pool, "laptop", "alice", &did_of(&key(6)), &key(6), "[]", 0, Some("full"))
            .await
            .unwrap();
        let chain_before = kel_store::load_chain(rt.base_dir(), "alice").unwrap().len();

        let refused = recover(&rt, &NobodyResident, &pool, "alice", &phrase, NEW_PASSPHRASE, &line_of(key(6), ADDR)).await;
        let e = refused.expect_err("a device's key recovered as a vault");
        assert!(e.to_string().contains("not as a vault") && e.to_string().contains("nothing was changed"), "{e}");
        let row = &rows(&pool).await[0];
        assert_eq!((row.id.as_str(), row.posture.as_deref()), ("laptop", Some("full")));
        assert!(row.addresses.is_empty(), "the device was re-addressed to the line's address");
        assert_eq!(kel_store::load_chain(rt.base_dir(), "alice").unwrap().len(), chain_before, "a rotation was appended");
    }

    /// The vault is added as `vault`, or beside a `vault` already there under its key.
    #[test]
    fn the_vault_is_added_as_vault_unless_that_label_is_taken() {
        assert_eq!(label_for(&[], &key(9)), "vault");
        let taken = PairedNode {
            id: "vault".to_string(),
            device_did: kotton_wire::did::Did::new("key", "z6MktGLn5v9bCrdxWgRojExample"),
            public_key: key(4),
            paired_at: 0,
            addresses: vec![],
            relay_url: None,
            posture: None,
        };
        assert_eq!(label_for(&[taken], &key(9)), format!("vault-{}", &hex::encode(key(9))[..8]));
    }

    /// Twenty-four words of the list, with the checksum right, that are no
    /// authority in alice's log.
    const NOT_THEIRS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon art";
    /// Where the test lines say their vault is: nothing listens there, and nothing
    /// here dials it.
    const ADDR: &str = "127.0.0.1:9";

    fn key(seed: u8) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes()
    }

    fn did_of(key: &[u8; 32]) -> String {
        kotton_crypto::DidKeyMethod::from_public_key_bytes(key).unwrap().to_string()
    }

    fn line_of(key: [u8; 32], addr: &str) -> String {
        InstanceLine { kind: OperatedService::Vault, hint: addr.into(), key }.to_text()
    }

    async fn rows(pool: &Arc<SqlitePool>) -> Vec<PairedNode> {
        kotton_peer::daemon::db::list_paired_nodes(pool, "alice").await.unwrap()
    }

    /// Steps 1 to 5 alone, for a device that holds the log and pairs no node: what
    /// the sealing tests are about, with no vault to add or record.
    async fn proved(rt: &DeviceRuntime, pool: &Arc<SqlitePool>, phrase: &str) -> Result<Recovered> {
        let asked = what_was_asked(rt, "alice", phrase, NEW_PASSPHRASE)?;
        prove_and_rotate(rt, &NobodyResident, pool, "alice", phrase, NEW_PASSPHRASE, asked).await
    }
}
