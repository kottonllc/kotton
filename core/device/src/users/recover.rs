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
}

/// Recover `user_id` onto this device from `recovery_key`, and seal it under
/// `passphrase`, the one the person chose for this device. See the module doc.
///
/// The passphrase is held to the bar before anything is fetched or written, so
/// a weak one changes nothing.
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
) -> Result<Recovered> {
    let seed32 = try_mnemonic_to_seed32(recovery_key).map_err(|e| anyhow!(e))?;
    let base = runtime.base_dir();
    let limiting = kotton_identity::provisioning::attempt_limiting_for_user(runtime, user_id);
    kotton_crypto::daily_credential::assess(
        passphrase,
        kotton_crypto::daily_credential::required_entropy_bits_for(limiting),
    )
    .map_err(|weak| anyhow!("{weak}; nothing was changed"))?;

    let nodes = kotton_peer::daemon::db::list_paired_nodes(db, user_id)
        .await
        .context("list paired nodes")?;

    // 1–2. The chain: whatever this device already holds, else fetched and proven.
    let mut chain = kel_store::load_chain(base, user_id)?;
    if chain.is_empty() {
        if nodes.is_empty() {
            return Err(anyhow!(
                "'{user_id}' has no key history on this device and no paired node to fetch it \
                 from. Add the node that keeps your data (`kotton peer add`) and run recover \
                 again."
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

        let done = recover(&rt, &NobodyResident, &pool, "alice", &phrase, NEW_PASSPHRASE).await.unwrap();

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

        let again = recover(&rt, &NobodyResident, &pool, "alice", &phrase, NEW_PASSPHRASE).await.unwrap();
        assert!(again.sealed_copy_removed, "the copy under the first recovery's passphrase is replaced too");
    }

    /// A passphrase below the bar is refused before anything happens: no rotation,
    /// and the sealed copy and the old passphrase are as they were.
    #[tokio::test]
    async fn a_weak_passphrase_is_refused_before_the_recovery_begins() {
        let temp = tempfile::tempdir().unwrap();
        let (rt, phrase) = a_device_that_kept_its_sealed_copy(&temp).await;
        let sealed = rt.base_dir().join("users").join("alice").join(VAULT_FILE);
        let (chain_before, copy_before) =
            (kel_store::load_chain(rt.base_dir(), "alice").unwrap().len(), std::fs::read(&sealed).unwrap());
        let pool = agent_db().await;

        let refused = recover(&rt, &NobodyResident, &pool, "alice", &phrase, "hunter2").await;

        let e = refused.expect_err("a weak passphrase recovered");
        assert!(e.to_string().contains("nothing was changed"), "{e}");
        assert_eq!(kel_store::load_chain(rt.base_dir(), "alice").unwrap().len(), chain_before, "a rotation was appended");
        assert_eq!(std::fs::read(&sealed).unwrap(), copy_before, "the sealed copy changed");
        assert!(open_vault_under(&rt, "alice", OLD_PASSPHRASE).is_ok(), "the old passphrase no longer opens its copy");
    }
}
