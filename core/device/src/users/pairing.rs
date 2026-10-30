// SPDX-License-Identifier: AGPL-3.0-or-later
//! Device-pairing **ceremony entry points**, and the tests for the verbs they run.
//!
//! Not in `peer`'s tier, for two different reasons.
//!
//! The three ceremony functions hold the daemon's `SessionMap`: they are the
//! ceremony's plumbing — a spawned task, an mpsc channel streaming progress to
//! the IPC client, and on join a minted session, because a joining device holds
//! no mnemonic to log in with afterward. The protocol they orchestrate lives in
//! [`kotton_peer::daemon::nodes`]. The asymmetry with `finalize_enrolled_node`,
//! which moved, is real: **joining an existing identity issues a session;
//! enrolling does not.**
//!
//! **Each entry point returns the ceremony's stream, and the type says so**
//! (`io::Result<mpsc::Receiver<UserResponse>>`, #120). Every client of these
//! verbs reads the answer with `send_streaming`, which ends only when the door
//! closes the connection, and the door closes it after a stream and not after
//! one frame. So a refusal before the ceremony starts is an `Err` (one error
//! frame, then the door closes), or a frame on the stream before it ends; it
//! cannot be a single frame left open, because there is no type to say one in.
//!
//! The tests stay for a blunter reason: they build a runtime to make a user
//! resident, and a crate that names the runtime crate cannot live in `peer` —
//! that is the cycle this whole move exists to escape. They exercise `peer`'s
//! functions from here, where naming it is legal.
//!
//! Both follow `peer` once `agent::sessions` moves to `core/session`.
//!
//! **A ceremony that admits a full device carries the drives both ways: the
//! drives learn the device, and the device learns the drives.** A device
//! syncs with its person's drives and never with another device, so a device
//! that joins has nothing to sync until it knows a drive, and a drive admits
//! nobody it was not told of.
//!
//! - *The device learns the drives.* The issuer hands the joiner the drives it
//!   records — each vault's key, the person's tenancy, the node it is reached
//!   through with its addresses and relay — inside the enrollment payload, over
//!   the ceremony's own encrypted, SAS-confirmed channel
//!   (`PairingPayload::FrostShare::drives`, [`drives_to_hand`]). The joiner
//!   records each through the one writer of the record — the node row, written
//!   with no posture so it keeps what this device already says of that key,
//!   then `drives::record`, which makes a row naming no posture a vault —
//!   before it answers `PairingComplete` ([`record_handed_drives`]), so its
//!   first `sync` has drives to reach. A handout it cannot keep refuses the
//!   join with the reason, before the joiner writes anything:
//!   one that does not hold together ([`check_handed_drives`]), and one whose
//!   rows would be written over a row this device holds — its key paired here
//!   as something other than a vault, or its DID paired here beside another
//!   key ([`check_handed_rows`]). A row is the person's and the node's DID's,
//!   and its label keys nothing (`kotton_peer::daemon::db`), so a drive's
//!   label that this device already shows on another row, the issuer's
//!   included, or that another person here uses, is no reason to refuse: the
//!   drive's row sits beside the other. The issuer's word replaces none of this
//!   device's rows under another key, reaches no other person's row, and
//!   writes no posture over any. A write that fails after that point also
//!   fails the join there, which the person runs again.
//!
//!   **A refusal reaches both sides, because the joiner's answer is the
//!   join's last step.** The issuer's ceremony returns only once the joiner
//!   has answered that it kept what it was handed
//!   ([`kotton_peer::pairing::JoinAnswer`], [`answer_the_issuer`]); a joiner
//!   that refuses the handout, fails to record it, or says nothing within
//!   [`kotton_peer::pairing::JOINER_KEEPS_WITHIN`] leaves the issuer with no
//!   row and no introduction, and the issuer's person is told so
//!   ([`kotton_peer::pairing::JoinNotKept`]). There is nothing to revoke.
//!   The joiner calls the join complete only on the issuer's sealed reply
//!   that it heard `kept`. Without it the joiner cannot tell an issuer that
//!   gave up from a reply that was lost, so its person is told the other
//!   device may not have kept this one and to check there — never that it
//!   is joined when the issuer may have kept nothing.
//! - *The drives learn the device.* When the joiner has answered that it kept
//!   what it was handed, the issuer — which holds the identity — records it
//!   and tells each drive about it, under the identity's signature, before it
//!   answers `PairingComplete` ([`crate::users::drive_devices`]); `device
//!   revoke` withdraws the device the same way. A joined device holds a key
//!   share and introduces nobody.
//!
//! **An admit by code records the vault only once the vault has said it keeps
//! for this device.** The vault wrote its half before it answered `kept`, so
//! when the ceremony returns its rule — which pool it holds this device's key
//! in — is already a fact this device can ask about. The admit asks
//! ([`refused_as`]) and then writes ([`keep_the_admitted`]): a refusal ends it
//! `PairFailed`, in the vault's words, with nothing recorded here. It never
//! writes and then withdraws (#157).
use kotton_session::service::tokens as sessions;
use kotton_peer::daemon::nodes::{
    PendingConfirms,
    StreamingConfirmer,
    WARM_KEY_TTL_SECONDS,
    ceremony_failure,
    finalize_enrolled_node,
    json_err,
    load_device_operational_key,
    load_signing_key,
    record_own_device_member,
    resolve_data_keys,
    wire_own_device_allowlist,
};
use kotton_wire::ipc::UserResponse;
use kotton_peer::daemon::db as network_db;
use ed25519_dalek::SigningKey;
use hex;
use kotton_peer::pairing::{
    encode_connection_code, open_pair_listener, parse_connection_code,
    run_enroll_issuer_committed, run_enroll_join_committed, Invite, JoinAnswer,
};
use kotton_peer::relay_keys::relay_id;
use crate::users::DeviceUsers as _;
use crate::DeviceRuntime;
use kotton_schemas::membership::Posture;
use kotton_common::crypto::kdf_labels;
use sqlx::SqlitePool;
use std::collections::HashSet;
use std::io;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use uuid::Uuid;
use kotton_common::time::now_secs;

/// Persist a joiner-side enrollment outcome (the `device join` completion): store
/// the delivered KEL + adopt the AID, persist the FROST share/warm/delegation/CEK,
/// record the issuer as a paired node, issue a session (the join cryptographically
/// authenticates this device), then live-refresh + record membership + wire sync.
///
/// The single joiner-completion path for the pairing ceremony. What it answers
/// is what the caller tells the issuer ([`answer_the_issuer`]): `PairFailed`
/// is a refusal, and the issuer keeps nothing of the join.
// Allowed: the daemon state a join's completion writes, as `handle_device_add` below takes it.
#[allow(clippy::too_many_arguments)]
pub async fn finalize_joined_node(
    runtime: &DeviceRuntime,
    users: &dyn crate::users::residency::Residency,
    db: &Arc<SqlitePool>,
    sessions: &sessions::SessionMap,
    paired_keys: &Arc<RwLock<HashSet<[u8; 32]>>>,
    user_id: &str,
    warm_key: &SigningKey,
    joined: kotton_peer::pairing::JoinedNode,
) -> io::Result<UserResponse> {
    // Adopt the did:kel AID as this device's user identity (the joiner
    // cannot reconstruct the AID itself). Blind / did:key-only enrollment carries
    // no KEL — fall back to the preserved root DID. Compute it from the delivered
    // KEL *in memory* — do NOT write yet.
    let user_did = match joined.kel.first() {
        Some(inception) => inception.aid.to_string(),
        None => joined.root_did.to_string(),
    };
    // The drives the issuer handed over, checked before anything is written:
    // a device that joins with a drive it cannot record has nothing to sync and
    // no way back, so such a join is refused here with the reason — which the
    // caller says to the issuer as well, and the issuer then keeps nothing.
    // So are the rows this device already holds: the issuer's word does not
    // write over them (`check_handed_rows`).
    let checked = match check_handed_drives(user_id, &joined.peer, &joined.drives) {
        Ok(()) => check_handed_rows(db, user_id, &joined.drives).await?,
        refused => refused,
    };
    if let Err(why) = checked {
        tracing::warn!(user_id, %why, "refused a join whose drives cannot be recorded");
        return Ok(UserResponse::PairFailed {
            reason: format!(
                "This device was not joined: {why}. Nothing was kept here, and the device that \
                 would have admitted you keeps nothing of it either; join again from the device \
                 that holds your identity once this is resolved."
            ),
        });
    }
    // Provision BEFORE writing anything: this validates that `user_id` is either
    // free or already this same identity (a name colliding with a *different*
    // local identity is rejected), and creates the user directory. Doing it first
    // means a collision fails clean — no half-written KEL over another user's.
    // `None` is the idempotent re-join: nothing new was provisioned, so there is
    // nothing new to make resident. The `reload_user_runtime` below swaps in a
    // CEK-refreshed handle either way.
    if let Some(user_rt) = runtime
        .provision_joined_user(user_id, &user_did)
        .map_err(|e| io::Error::other(format!("provision joined user: {e}")))?
    {
        users.insert(user_id.to_string(), user_rt);
    }
    // Now the identity + directory exist — store the delivered KEL.
    for event in &joined.kel {
        kotton_identity::kel_store::append_event(runtime.base_dir(), user_id, event)
            .map_err(|e| io::Error::other(format!("store delivered KEL: {e}")))?;
    }
    // This node can now admit a device that proves control of the identity's
    // root — the tip it will verify against, and the recovery authorities a
    // phrase-only device can claim. Learned here, at the moment the
    // chain arrives, so the listener that is already up sees it without a restart.
    runtime.admission().learn_chain(&joined.kel);
    if let Some(bundle) = joined.recovery_bundle.as_deref() {
        kotton_identity::provisioning::write_recovery_bundle_raw(
            runtime.base_dir(),
            user_id,
            bundle,
        )
        .map_err(|e| io::Error::other(format!("keep delivered recovery bundle: {e}")))?;
    }

    // Full/Cosigner deliver share + delegation + group key; only Full also delivers
    // the operational data keys. Blind delivers none.
    if let (Some(share), Some(delegation), Some(pubkey_package)) = (
        joined.frost_share.as_ref(),
        joined.warm_key_delegation.as_ref(),
        joined.pubkey_package.as_ref(),
    ) {
        let secrets = runtime.secrets();
        let warm_delegation_json = serde_json::to_string(delegation).map_err(json_err)?;
        secrets
            .set_secret(&kdf_labels::frost_share(user_id), &share.0)
            .map_err(|e| io::Error::other(format!("persist frost share: {e}")))?;
        secrets
            .set_secret(&kdf_labels::frost_pubkey_package(user_id), pubkey_package)
            .map_err(|e| io::Error::other(format!("persist group public-key package: {e}")))?;
        secrets
            .set_secret(
                &kdf_labels::warm_signing_key(user_id),
                &hex::encode(warm_key.to_bytes()),
            )
            .map_err(|e| io::Error::other(format!("persist warm key: {e}")))?;
        secrets
            .set_secret(
                &kdf_labels::warm_key_delegation(user_id),
                &warm_delegation_json,
            )
            .map_err(|e| io::Error::other(format!("persist warm delegation: {e}")))?;
        // The data capability, when this posture was granted one. Both domain
        // roots persist together: `master_secret` is what lets `resolve_user_keys`
        // build a mount whose `K_log` matches the rest of the fleet, so this
        // device can open the sealed record log it receives and encrypt its own
        // record database at rest.
        if let Some(keys) = joined.data_keys.as_ref() {
            secrets
                .set_secret(&kdf_labels::operational_cek(user_id), &hex::encode(keys.cek))
                .map_err(|e| io::Error::other(format!("persist operational cek: {e}")))?;
            secrets
                .set_secret(
                    &kdf_labels::operational_cek_epoch(user_id),
                    &keys.cek_epoch.to_string(),
                )
                .map_err(|e| io::Error::other(format!("persist cek epoch: {e}")))?;
            secrets
                .set_secret(
                    &kdf_labels::master_secret_keychain_key(user_id),
                    &hex::encode(keys.master_secret),
                )
                .map_err(|e| io::Error::other(format!("persist master secret: {e}")))?;
        }
    }

    // A node that was handed no data keys — a vault, a co-signer — cannot write
    // the membership set, which is sealed under them; the allowlist row below is
    // the whole of what it keeps about the issuer, and that is by design.
    let keyless = joined.data_keys.is_none();
    let node = joined.peer;
    let now = now_secs();
    let addresses_json = serde_json::to_string(&node.addresses).map_err(json_err)?;
    network_db::insert_paired_node(
        db,
        &node.id,
        user_id,
        &node.device_did.to_string(),
        &node.public_key,
        &addresses_json,
        now,
        None,
    )
    .await?;
    // The relay the issuer announced, when the ceremony learned one — see
    // `finalize_enrolled_node`.
    if let Some(relay) = node.relay_url.as_deref() {
        network_db::update_paired_node_relay(db, user_id, &node.device_did.to_string(), Some(relay)).await?;
    }
    paired_keys.write().unwrap().insert(node.public_key);

    // The person's drives, as the admitting device handed them: recorded here
    // through the one writer of the record (`record_handed_drives`), so this
    // device's first `sync` has drives to reach, before it answers
    // `PairingComplete`.
    if let Err(e) = record_handed_drives(db, paired_keys, user_id, &joined.drives).await {
        return Ok(UserResponse::PairFailed {
            reason: format!(
                "This device was not joined: recording your drives failed ({e}). The device that \
                 would have admitted you keeps nothing of it and told none of your drives of \
                 this one; join again from the device that holds your identity — a second join \
                 keeps what this one wrote."
            ),
        });
    }

    // Completing the join cryptographically authenticates this device (it proved
    // its operational key + ran the committed handshake). It holds no mnemonic to
    // log in with afterward, so issue a session now.
    let token = Uuid::new_v4().to_string();
    sessions::insert(sessions, token.clone(), user_id.to_string());

    // Live-refresh so the delivered CEK applies immediately; then record membership
    // + wire sync/allowlist. Best-effort (applies on next load on failure).
    match runtime.reload_user_runtime(user_id).await {
        Ok(user_rt) => {
            // The reload builds the refreshed runtime; swapping it in for the
            // stale one is the daemon's act. In-flight
            // requests holding the old handle finish against it.
            let store = std::sync::Arc::clone(&user_rt);
            users.insert(user_id.to_string(), user_rt);
            if keyless {
                tracing::info!(
                    user_id,
                    "joined blind: the membership set is sealed under keys this node does not hold, so only the allowlist row is kept"
                );
            } else if let Err(e) =
                record_own_device_member(store.as_ref(), &node, Posture::Full).await
            {
                tracing::warn!(
                    user_id,
                    "failed to record issuer membership after join: {e}"
                );
            } else {
                wire_own_device_allowlist(store.as_ref(), db, paired_keys, user_id, &node)
                    .await;
            }
            // A device paired later keeps its person's drives on demand until
            // told otherwise (the protocol's storage model): its default, kept
            // in its own database (`crate::users::pins`), and nothing of it
            // replicated. Best-effort: a device that could not write it keeps
            // what a device that stated nothing keeps, which is whole, and
            // says so by its claim at its first pass.
            if !keyless {
                let said = crate::users::pins::write(
                    db,
                    user_id,
                    &kotton_wire::ipc::PinScope::Default,
                    Some(crate::users::pins::JOINED),
                )
                .await
                .map_err(|e| e.to_string());
                if let Err(e) = said {
                    tracing::warn!(user_id, error = %e, "a joined device did not write that it keeps drives on demand");
                }
            }
        }
        Err(e) => tracing::warn!(
            user_id,
            "failed to refresh user runtime after join (CEK applies on next restart): {e}"
        ),
    }

    Ok(UserResponse::PairingComplete {
        node,
        session_token: Some(kotton_wire::ipc::SecretText::new(token)),
        relay_offer: None,
    })
}

/// The join's last step: tell the admitting device whether this one kept what
/// it was handed, and answer this device's person with what is then true.
///
/// `outcome` is what this device made of the payload — what
/// [`finalize_joined_node`] answered, or a refusal before it. A `PairFailed`
/// is said to the issuer in the same words, and stands whether or not the
/// issuer hears it: the issuer keeps nothing it was not told was kept. A
/// `PairingComplete` is said as `kept`, and stands only on the issuer's
/// sealed reply that it heard ([`JoinAnswer::kept`]). Without that reply the
/// issuer either stopped waiting
/// ([`kotton_peer::pairing::JOINER_KEEPS_WITHIN`]) and kept nothing, or kept
/// this device and the reply was lost; this side cannot tell which. So the
/// join is not reported complete: the session it minted is withdrawn, and
/// the person is told to check the other device and join again from it if it
/// does not list this one.
pub(crate) async fn answer_the_issuer(
    answer: JoinAnswer,
    sessions: &sessions::SessionMap,
    outcome: UserResponse,
) -> UserResponse {
    match outcome {
        UserResponse::PairFailed { reason } => {
            if let Err(e) = answer.refused(&reason).await {
                tracing::warn!(error = %e, "the admitting device did not hear this join refused; it keeps nothing unheard");
            }
            UserResponse::PairFailed { reason }
        }
        complete => match answer.kept().await {
            Ok(()) => complete,
            Err(e) => {
                if let UserResponse::PairingComplete { session_token: Some(token), .. } = &complete {
                    sessions.write().unwrap().remove(token.expose());
                }
                tracing::warn!(error = %e, "the admitting device did not hear this join kept");
                UserResponse::PairFailed {
                    reason: format!(
                        "This device kept what it was handed, but the device admitting it did not \
                         confirm it heard so ({e}), so it may not have kept this device. Check there: \
                         if it does not list this device, join again from it — a second join keeps \
                         what this one wrote."
                    ),
                }
            }
        },
    }
}

/// Issuer side of the streamed `device add` ceremony. Opens a bootstrap
/// listener, streams `PairAdvertising` (with the interim connection code) →
/// `PairShowCode` → `PairAwaitingPeer` → `PairTransferring` → `PairingComplete` |
/// `PairFailed`, and confirms the SAS via `PairConfirmCode`.
#[allow(clippy::too_many_arguments)]
pub async fn handle_device_add(
    runtime: Arc<DeviceRuntime>,
    users: Arc<dyn crate::users::residency::Residency>,
    db: Arc<SqlitePool>,
    device_db: Arc<SqlitePool>,
    paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    pending: PendingConfirms,
    user_id: String,
    as_name: Option<String>,
    ttl_seconds: u64,
    port: u16,
    posture: Posture,
) -> io::Result<mpsc::Receiver<UserResponse>> {
    let secrets = runtime.secrets();
    // This device announces its OWN name to the joiner; `--as`
    // overrides the persisted device name for this ceremony only.
    let self_name = match as_name {
        Some(n) => n,
        None => crate::config::ops::resolve_device_name(&device_db).await,
    };
    let identity_key = load_signing_key(&user_id, secrets)?;
    let op_key = load_device_operational_key(secrets)?;
    // A `Full` enrollment must hand over the whole data domain; enrolling one
    // with a partial capability would produce a device that reads files but is
    // silently absent from record sync. Fail the ceremony instead.
    let data_keys = resolve_data_keys(&user_id, secrets)?;
    if matches!(posture, Posture::Full) && data_keys.is_none() {
        return Err(io::Error::other(
            "cannot enroll a Full device: this device does not hold the complete \
             operational data capability (CEK + master_secret). Log in with the \
             recovery mnemonic on this device first, then retry.",
        ));
    }
    let issuer_kel = kotton_identity::kel_store::load_chain(runtime.base_dir(), &user_id)
        .unwrap_or_default();
    // The phrase-sealed recovery copy rides along to a blind node so a device
    // holding only the phrase can get it back from there. Only the
    // blind posture carries it — see `PairingPayload::BlindRelay`.
    let issuer_recovery_bundle = if matches!(posture, Posture::BlindStorage) {
        kotton_identity::provisioning::read_recovery_bundle_raw(runtime.base_dir(), &user_id)
            .unwrap_or_default()
    } else {
        None
    };
    let warm_key_expires_at = now_secs() + WARM_KEY_TTL_SECONDS;
    // The person's drives, handed to a `Full` joiner with its payload so its
    // first `sync` has drives to reach (`drives_to_hand`).
    let handed_drives = drives_to_hand(&db, &user_id).await;

    // Fresh offer id + bootstrap listener (its cert presents the operational key).
    let mut sid = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut sid);
    let (_unused_legacy_code, listen_addr, expires_at, endpoint) =
        open_pair_listener(&op_key, port, ttl_seconds)
            .await
            .map_err(|e| io::Error::other(format!("open device-add listener: {e}")))?;
    let code = encode_connection_code(&sid, listen_addr);

    // Advertise an anonymous mDNS offer so a joiner on the same LAN
    // can discover this by browsing — no code, no typed address. Best-effort: if
    // mDNS is unavailable/blocked, the hand-carried code still works (the fallback
    // ladder). The handle is held in the ceremony task and withdraws the offer when
    // the ceremony ends. Skipped in local-only mode (same-machine dev/CI): the
    // multicast socket would make the OS firewall prompt, and discovery is moot when
    // both daemons share a host — the joiner uses the connection code.
    let mdns_offer = if kotton_peer::local_only() {
        None
    } else {
        match kotton_net::advertise_pairing_offer(
            &hex::encode(sid),
            listen_addr.port(),
        ) {
            Ok(offer) => Some(offer),
            Err(e) => {
                tracing::warn!("mDNS pairing advertisement failed (code still works): {e}");
                None
            }
        }
    };

    let (tx, rx) = mpsc::channel::<UserResponse>(16);
    // Owned handle for the ceremony task: `Arc`-backed, so this is the same
    // residency map the daemon holds, not a snapshot of it.
    let users: Arc<dyn crate::users::residency::Residency> = Arc::clone(&users);
    tokio::spawn(async move {
        // Hold the mDNS offer for the ceremony's lifetime; dropping it withdraws.
        let _mdns_offer = mdns_offer;
        if tx
            .send(UserResponse::PairAdvertising { code: kotton_wire::ipc::SecretText::new(code), expires_at })
            .await
            .is_err()
        {
            return;
        }
        let confirmer = StreamingConfirmer {
            tx: tx.clone(),
            token: Uuid::new_v4().to_string(),
            pending,
            ttl: std::time::Duration::from_secs(ttl_seconds),
        };
        let result = run_enroll_issuer_committed(
            &identity_key,
            sid,
            data_keys,
            posture,
            &self_name,
            runtime.peer_listen_addr(),
            endpoint,
            ttl_seconds,
            warm_key_expires_at,
            issuer_kel,
            issuer_recovery_bundle,
            handed_drives,
            &confirmer,
        )
        .await;
        let frame = match result {
            Ok(enrolled) => {
                let _ = tx.send(UserResponse::PairTransferring).await;
                match finalize_enrolled_node(
                    runtime.secrets(),
                    match users.get(&user_id) {
                        Some(rt) => rt,
                        None => {
                            let _ = tx.send(UserResponse::Error {
                                message: format!("user runtime '{user_id}' is not loaded"),
                            }).await;
                            return;
                        }
                    }
                    .as_ref(),
                    &db,
                    &paired_keys,
                    &user_id,
                    posture,
                    enrolled,
                )
                .await
                {
                    Ok(node) => {
                        // The person's drives admit the device that enrolled
                        // them and nobody else until told: tell them of this
                        // one (`drive_devices`).
                        if posture == Posture::Full {
                            crate::users::drive_devices::introduce(&runtime, &db, &user_id, &node).await;
                        }
                        UserResponse::PairingComplete {
                            node,
                            session_token: None,
                            relay_offer: None,
                        }
                    }
                    Err(e) => UserResponse::PairFailed {
                        reason: format!("Added the device, but saving it failed: {e}"),
                    },
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "device-add ceremony failed");
                UserResponse::PairFailed {
                    reason: ceremony_failure(&e),
                }
            }
        };
        let _ = tx.send(frame).await;
    });
    Ok(rx)
}

/// The issuer half of the six-digit ceremony with the transport reversed, for a
/// gateway on a host this node can reach but that cannot reach this node. The
/// gateway printed a code — its address and the session id — and is listening;
/// this node dials it, shows the six digits it derives, and on the person's yes
/// admits it under `Posture::Gateway`. The gateway is handed whom it serves and
/// which relay to dial, and nothing that opens anything.
#[allow(clippy::too_many_arguments)]
pub async fn handle_gateway_enroll(
    runtime: Arc<DeviceRuntime>,
    users: Arc<dyn crate::users::residency::Residency>,
    db: Arc<SqlitePool>,
    device_db: Arc<SqlitePool>,
    paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    pending: PendingConfirms,
    user_id: String,
    code: String,
    ttl_seconds: u64,
) -> io::Result<mpsc::Receiver<UserResponse>> {
    use kotton_peer::pairing::{parse_connection_code, run_enroll_issuer_dialing};

    let (sid, addr) = parse_connection_code(code.trim())
        .map_err(|e| io::Error::other(format!("gateway code: {e}")))?;
    let secrets = runtime.secrets();
    let self_name = crate::config::ops::resolve_device_name(&device_db).await;
    let identity_key = load_signing_key(&user_id, secrets)?;
    let op_key = load_device_operational_key(secrets)?;
    let relay_url = runtime.reachability().nat().relay_url;
    if relay_url.is_empty() {
        return Err(io::Error::other(
            "this node has no relay set, so a gateway would have nothing to dial — \
             `kotton config relay set <url>` first",
        ));
    }
    let handout = kotton_wire::peer::GatewayHandout {
        user_id: user_id.clone(),
        relay_url,
        node_label: self_name.clone(),
    };

    let (tx, rx) = mpsc::channel::<UserResponse>(16);
    tokio::spawn(async move {
        if tx.send(UserResponse::PairConnecting).await.is_err() {
            return;
        }
        let confirmer = StreamingConfirmer {
            tx: tx.clone(),
            token: Uuid::new_v4().to_string(),
            pending,
            ttl: std::time::Duration::from_secs(ttl_seconds),
        };
        let result = run_enroll_issuer_dialing(
            &identity_key,
            &op_key,
            sid,
            addr,
            &self_name,
            runtime.peer_listen_addr(),
            Posture::Gateway,
            Vec::new(),
            None,
            Vec::new(),
            Some(handout),
            &confirmer,
        )
        .await;
        let frame = match result {
            Ok(enrolled) => {
                let _ = tx.send(UserResponse::PairTransferring).await;
                let store = match users.get(&user_id) {
                    Some(rt) => rt,
                    None => {
                        let _ = tx
                            .send(UserResponse::Error {
                                message: format!("user runtime '{user_id}' is not loaded"),
                            })
                            .await;
                        return;
                    }
                };
                match finalize_enrolled_node(
                    runtime.secrets(),
                    store.as_ref(),
                    &db,
                    &paired_keys,
                    &user_id,
                    Posture::Gateway,
                    enrolled,
                )
                .await
                {
                    Ok(node) => UserResponse::PairingComplete {
                        node,
                        session_token: None,
                        relay_offer: None,
                    },
                    Err(e) => UserResponse::PairFailed {
                        reason: format!("Admitted the gateway, but saving it failed: {e}"),
                    },
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "gateway-enrol ceremony failed");
                UserResponse::PairFailed {
                    reason: ceremony_failure(&e),
                }
            }
        };
        let _ = tx.send(frame).await;
    });
    Ok(rx)
}

/// Joiner side of the streamed `device join` ceremony. Dials the issuer
/// using the interim connection `code` (sid + addr) and streams `PairConnecting` →
/// `PairShowCode` → `PairAwaitingPeer` → `PairTransferring` → `PairingComplete`
/// (with a session token) | `PairFailed`.
/// What a joiner will accept from the issuer's payload.
///
/// The issuer decides what it hands over (a `Posture`); the joiner decides what
/// it will keep. A vault holds no key and can be given none, so
/// it joins under `BlindOnly`: a payload carrying data keys or a signing share
/// is refused before anything is written, and the keys the ceremony delivered
/// are dropped with the frame that carried them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinPolicy {
    /// Keep whatever the issuer's posture delivers — a device.
    Any,
    /// Keep only what a blind enrolment carries: the chain and the sealed
    /// recovery copy. Refuse a payload with keys in it.
    BlindOnly,
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_device_join(
    runtime: Arc<DeviceRuntime>,
    users: Arc<dyn crate::users::residency::Residency>,
    db: Arc<SqlitePool>,
    device_db: Arc<SqlitePool>,
    sessions: sessions::SessionMap,
    paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    pending: PendingConfirms,
    user_id: String,
    code: String,
    as_name: Option<String>,
    policy: JoinPolicy,
) -> io::Result<mpsc::Receiver<UserResponse>> {
    let node_key = load_device_operational_key(runtime.secrets())?;
    let warm_key = SigningKey::generate(&mut rand::rngs::OsRng);
    // This device announces its OWN name to the issuer; `--as` overrides the
    // persisted device name for this ceremony only.
    let self_name = match as_name {
        Some(n) => n,
        None => crate::config::ops::resolve_device_name(&device_db).await,
    };

    // An empty code means "discover on the LAN" (an mDNS browse); a
    // non-empty code carries (sid, addr) directly (the interim/off-LAN fallback).
    let (sid, candidates): ([u8; 16], Vec<std::net::SocketAddr>) = if code.trim().is_empty() {
        if kotton_peer::local_only() {
            // No LAN in local-only mode — the multicast browse would prompt the
            // firewall and find nothing. Require the connection code instead.
            return Err(io::Error::other(
                "local-only pairing (KOTTON_PAIR_LOCAL_ONLY) has no LAN discovery — \
                 pass the connection code shown by `device add`",
            ));
        }
        let offers =
            kotton_net::browse_pairing_offers(std::time::Duration::from_secs(5))
                .map_err(|e| io::Error::other(format!("mDNS browse failed: {e}")))?;
        match offers.as_slice() {
            [] => {
                return Err(io::Error::other(
                    "no device is offering to pair on this network — run `device add` on your \
                     other device, or pass a connection code",
                ))
            }
            [offer] => {
                // The label is not on the wire; the joiner learns it over the
                // encrypted channel (PairInfo) after connecting. One offer → preselect.
                let raw = hex::decode(&offer.sid_hex)
                    .map_err(|e| io::Error::other(format!("bad offer sid hex: {e}")))?;
                let sid: [u8; 16] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| io::Error::other("offer sid must be 16 bytes"))?;
                // The peer advertises every interface address (Wi-Fi, VPN, IPv6,
                // link-local). Keep only the ones we can actually dial, IPv4 first —
                // picking one blindly is what made discovery a coin toss.
                let candidates =
                    kotton_peer::pairing::rank_dial_candidates(&offer.addresses);
                if candidates.is_empty() {
                    return Err(io::Error::other(
                        "the pairing offer advertised no address reachable from here — \
                         make sure both devices are on the same network",
                    ));
                }
                (sid, candidates)
            }
            offers => {
                return Err(io::Error::other(format!(
                    "{} devices are offering to pair; pick one by passing its connection code \
                     (name-based disambiguation is not wired yet)",
                    offers.len()
                )))
            }
        }
    } else {
        let (sid, mut addr) = parse_connection_code(&code)
            .map_err(|e| io::Error::other(format!("invalid connection code: {e}")))?;
        // A code minted from a `0.0.0.0` bind advertises an unspecified IP; treat it
        // as loopback (same-host). mDNS addresses are already concrete, so this only
        // affects the code path.
        if addr.ip().is_unspecified() {
            addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        }
        (sid, vec![addr])
    };
    // The dial + handshake + human-comparison window.
    let ttl_seconds = 120u64;
    // Where this node answers the protocol, announced during the ceremony so the
    // issuer records that rather than the bootstrap socket (`announce_bytes`).
    let peer_listen_addr = runtime.peer_listen_addr();

    let (tx, rx) = mpsc::channel::<UserResponse>(16);
    // Owned handle for the ceremony task: `Arc`-backed, so this is the same
    // residency map the daemon holds, not a snapshot of it.
    let users: Arc<dyn crate::users::residency::Residency> = Arc::clone(&users);
    tokio::spawn(async move {
        if tx.send(UserResponse::PairConnecting).await.is_err() {
            return;
        }
        let confirmer = StreamingConfirmer {
            tx: tx.clone(),
            token: Uuid::new_v4().to_string(),
            pending,
            ttl: std::time::Duration::from_secs(ttl_seconds),
        };
        // Rung 1 (mDNS/code + human SAS): the SAS comparison authenticates, so no
        // out-of-band key is pinned. Rungs 2/4 will pass the pinned issuer key.
        let result = run_enroll_join_committed(
            &node_key,
            &warm_key,
            sid,
            &candidates,
            &self_name,
            peer_listen_addr,
            &confirmer,
            None,
        )
        .await;
        let frame = match result {
            Ok((joined, answer))
                if policy == JoinPolicy::BlindOnly
                    && (joined.data_keys.is_some()
                        || joined.frost_share.is_some()
                        || joined.warm_key_delegation.is_some()) =>
            {
                // Dropped here, unwritten: the vault never holds what it was
                // handed, and the issuer is told why in its answer.
                tracing::warn!(user_id = %user_id, "a vault refused a payload carrying keys");
                let refused = UserResponse::PairFailed {
                    reason: "this node is a vault: it keeps sealed bytes and holds no key, so \
                             enrol it blind (`device add --blind`)"
                        .to_string(),
                };
                answer_the_issuer(answer, &sessions, refused).await
            }
            Ok((joined, answer)) => {
                let _ = tx.send(UserResponse::PairTransferring).await;
                let outcome = match finalize_joined_node(
                    &runtime, &*users,
                    &db,
                    &sessions,
                    &paired_keys,
                    &user_id,
                    &warm_key,
                    joined,
                )
                .await
                {
                    Ok(resp) => resp,
                    Err(e) => UserResponse::PairFailed {
                        reason: format!("This device was not joined: saving your keys failed ({e})"),
                    },
                };
                answer_the_issuer(answer, &sessions, outcome).await
            }
            Err(e) => {
                tracing::warn!(error = %e, "device-join ceremony failed");
                UserResponse::PairFailed {
                    reason: ceremony_failure(&e),
                }
            }
        };
        let _ = tx.send(frame).await;
    });
    Ok(rx)
}


/// The vault an admit is held to, and why: the vault whose operator credential
/// this person keeps pins its vault's key (`OperatorCredential.vault`).
#[derive(Debug, Clone)]
pub struct PinnedVault {
    /// The vault, as its operator credential names it — for the refusal's sentence.
    pub vault: String,
    /// The vault's operational key the credential pins.
    pub key: [u8; 32],
}

/// The six digits, confirmed by the key instead of by a person.
///
/// Only ever handed to a ceremony that holds the other end to a pinned key
/// ([`kotton_peer::pairing::Transport::pinned_to`]): the vault signs its key
/// over the channel's transcript, and the ceremony is refused before anything
/// is handed over if that key is not the pinned one, so a node between the two
/// cannot pass however the digits are answered. Emits no frame — there is
/// nothing for a person to read, and never a code to fall back to.
struct TheKeyConfirms;

#[async_trait::async_trait]
impl kotton_peer::pair_channel::SasConfirmer for TheKeyConfirms {
    async fn confirm(&self, _sas: u32, _peer_label: Option<&str>) -> bool {
        true
    }
}

/// What the person is told when the vault that answered is not the one the
/// credential pins: both keys, and that nothing left this device.
fn not_the_pinned_vault(vault: &str, refused: &kotton_peer::pairing::NotThePinnedKey) -> String {
    format!(
        "the vault that answered is not the vault your operator credential for '{vault}' pins: \
         it proved key {}, and the credential pins {} — nothing was handed over. The vault that \
         answered is not the vault the credential was enrolled with, and no six digits stand in \
         for its key.",
        hex::encode(refused.answered),
        hex::encode(refused.pinned),
    )
}

/// Why an invite refuses a posture other than blind, and the command that adds
/// such a device instead — carrying the posture asked for, so a person who typed
/// `--cosigner` is not sent to a bare `device add`, which hands over more, and a
/// gateway is not sent to `device join`, since it prints the code and this node
/// admits it. Every arm is written out, so a new posture fails to compile here
/// rather than inheriting a sentence; the one posture an invite admits never
/// reaches this function, because [`admits_by_code`] is its only caller and
/// admits blind before asking for a sentence — the guard and its explanation are
/// two functions on purpose, so the refusal names a command for every posture
/// it refuses.
fn not_blind_refusal(posture: Posture) -> String {
    let add = adds_instead(posture);
    let instead = match posture {
        Posture::BlindStorage => {
            unreachable!("admits_by_code admits the blind posture before asking for a refusal")
        }
        Posture::Full | Posture::Cosigner => format!(
            "A device that would hold keys joins the other way round: run `{add}` here and \
             `device join <code>` on it"
        ),
        Posture::Gateway => format!(
            "A gateway is admitted by its own code: the gateway prints the code, and this \
             node admits it with `{add}`"
        ),
    };
    format!(
        "an invite admits a vault, and a vault keeps what it cannot read — so this \
         door takes the blind posture only. {instead}"
    )
}

/// The one `device add` that adds a device of `posture`, as data the refusal
/// interpolates and the test holds — so no test has to pick a command out of
/// prose, and a sentence that named a second `device add` would fail the test
/// that counts them. Exhaustive for the same reason as [`not_blind_refusal`].
///
/// A posture `device add` names with a flag takes the flag from
/// `DEVICE_ADD_POSTURE_FLAGS`, the table the shell's `parse_add` reads, looked up
/// by posture: the hint has no spelling of its own to drift. The default posture
/// is the bare line, and a gateway is `--gateway <code>`, a word with a value the
/// table does not carry; `cargo xtask device-add-check` holds that this arm is the
/// only `"device add --` literal outside tests under `core/`.
fn adds_instead(posture: Posture) -> String {
    use kotton_schemas::membership::DEVICE_ADD_POSTURE_FLAGS;
    let flagged = |posture: Posture| {
        let (flag, _) = DEVICE_ADD_POSTURE_FLAGS
            .iter()
            .find(|(_, p)| *p == posture)
            .expect("`device add` names this posture with a flag of DEVICE_ADD_POSTURE_FLAGS");
        format!("device add {flag}")
    };
    match posture {
        Posture::Full => "device add".to_owned(),
        Posture::Cosigner => flagged(posture),
        Posture::Gateway => "device add --gateway <code>".to_owned(),
        Posture::BlindStorage => {
            unreachable!("admits_by_code admits the blind posture before asking for a refusal")
        }
    }
}

/// A vault's invite as its code names it: where the ceremony
/// meets and under which words, the key the meeting relay must prove before it
/// is dialled, the key the vault must prove inside the channel, and the relay's
/// *invited* admission key when the code carries one — what the dial presents
/// at a relay whose rule is *the people I invite*, which refuses a stranger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Invited {
    pub(crate) invite: Invite,
    pub(crate) relay_key: [u8; 32],
    pub(crate) vault_key: [u8; 32],
    pub(crate) admission: Option<kotton_net::rendezvous::AdmissionKey>,
}

/// What an admit is handed, read: a vault's invite, or a listening vault's
/// connection code.
#[derive(Debug)]
enum AdmitCode {
    Invite(Invited),
    Dial([u8; 16], std::net::SocketAddr),
}

/// What an admit says of an invite in the form that named no key.
pub(crate) const KEYLESS_INVITE: &str = "this invite is in the form that names no key (`relay#words`), so \
     neither its relay nor its vault could be held to anything — ask for the invite again: an invite \
     now begins `kotton-invite:`";

/// Read the code an admit is handed. A code in the one grammar is read by its
/// one parser (`kotton_wire::line::Code`): a vault's invite is admitted, and a
/// relay's invite or an instance's line is refused naming what takes it. A
/// `relay#words` invite named no key, and is refused. Anything else is a
/// listening vault's connection code.
fn read_admit_code(code: &str) -> io::Result<AdmitCode> {
    use kotton_wire::line::{Code, InviteCode, INVITE_PREFIX, LINE_PREFIX};
    let code = code.trim();
    if code.starts_with(INVITE_PREFIX) || code.starts_with(LINE_PREFIX) {
        return match Code::parse(code).map_err(io::Error::other)? {
            Code::Invite(read @ InviteCode::Vault { key, relay_key, invited, .. }) => Ok(AdmitCode::Invite(Invited {
                invite: Invite::of(&read).expect("a vault's invite meets at its relay"),
                relay_key,
                vault_key: key,
                admission: invited.map(kotton_net::rendezvous::AdmissionKey::from_bytes),
            })),
            Code::Invite(InviteCode::Relay { .. }) => Err(io::Error::other(
                "this is a relay's invite: it is stood at, not admitted — paste it at Settings' door, or \
                 `relay set <invite>` on this device",
            )),
            Code::Line(_) => Err(io::Error::other(
                "this is a vault's or a relay's line, which names an instance and makes nobody a member — an \
                 admit takes a vault's invite (`kotton-invite:vault:…`)",
            )),
        };
    }
    if code.contains('#') {
        return Err(io::Error::other(KEYLESS_INVITE));
    }
    let (sid, addr) = kotton_peer::pairing::parse_connection_code(code)
        .map_err(|e| io::Error::other(format!("connection code: {e}")))?;
    Ok(AdmitCode::Dial(sid, addr))
}

/// The relay an invite met at, as the line the ceremony's last frame offers it
/// in: its key, and the address it was met at as the hint.
pub(crate) fn relay_offered(url: &str, key: [u8; 32]) -> String {
    kotton_wire::line::InstanceLine { kind: kotton_wire::ipc::OperatedService::Relay, hint: url.to_string(), key }.to_text()
}

/// What the person is told when the vault that answered is not the one the
/// invite names: both keys, and that nothing left this device.
fn not_the_invited_vault(refused: &kotton_peer::pairing::NotThePinnedKey) -> String {
    format!(
        "the vault that answered is not the vault the invite names: it proved key {}, and the invite names {} \
         — nothing was handed over. Whoever answered holds the invite's words and not the vault's key; ask \
         for the invite again.",
        hex::encode(refused.answered),
        hex::encode(refused.pinned),
    )
}

/// What the person is told when the relay an invite meets at is not the one
/// it names.
fn not_the_invited_relay(refused: &kotton_peer::pairing::NotTheInvitedRelay) -> String {
    format!(
        "the relay at {} did not prove the key the invite names, so it was not dialled and nothing was handed \
         over ({}). Check that the invite was pasted whole, or ask for it again.",
        refused.url, refused.why
    )
}

/// Admit a vault by its invite, or a node **listening** for this one by its
/// code, under `posture`. Only `BlindStorage` is
/// admitted this way today — a vault. A Full or co-signing device joins the
/// other way round, dialling this node, because what those receive is not
/// something to send to whoever printed a code.
///
/// **An invite is held to the two keys its code names**: the meeting relay must prove its key before it is dialled
/// ([`kotton_peer::pairing::NotTheInvitedRelay`]), and the vault must prove its
/// key inside the channel before this side says anything about itself
/// ([`kotton_peer::pairing::NotThePinnedKey`]). A stand-in at either is refused
/// and nothing is handed over. The six digits stay the standing check: an
/// invite is a bearer at member level, and the person compares them.
///
/// `pinned`, when given, is the vault the person's operator credential names
/// (`vault invite <v> --me`): the invite must be one and name the
/// same key, the six digits are confirmed by the key ([`TheKeyConfirms`]) and
/// never shown, and a vault that proves another key is refused before anything
/// is handed over.
#[allow(clippy::too_many_arguments)]
pub async fn handle_device_admit(
    runtime: Arc<DeviceRuntime>,
    users: Arc<dyn crate::users::residency::Residency>,
    db: Arc<SqlitePool>,
    device_db: Arc<SqlitePool>,
    paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    pending: PendingConfirms,
    user_id: String,
    code: String,
    ttl_seconds: u64,
    posture: Posture,
    pinned: Option<PinnedVault>,
) -> io::Result<mpsc::Receiver<UserResponse>> {
    use kotton_peer::pairing::{run_enroll_issuer_dialing, run_enroll_issuer_relayed};

    admits_by_code(posture)?;
    let (invite, dial) = match read_admit_code(&code)? {
        AdmitCode::Invite(invited) => (Some(invited), None),
        AdmitCode::Dial(sid, addr) => (None, Some((sid, addr))),
    };
    match (&pinned, &invite) {
        (Some(_), None) => {
            return Err(io::Error::other(
                "an admit held to an operated vault takes the invite its operator minted (`kotton-invite:vault:…`); \
                 a connection code dials a port, and is not one",
            ))
        }
        // The credential and the code must name one vault, or the admit is
        // refused before anything is dialled.
        (Some(p), Some(inv)) if p.key != inv.vault_key => {
            return Err(io::Error::other(format!(
                "the vault this invite names is not the vault your operator credential for '{}' pins: the invite \
                 names key {}, and the credential pins {} — nothing was dialled, and nothing was handed over",
                p.vault,
                hex::encode(inv.vault_key),
                hex::encode(p.key)
            )))
        }
        _ => {}
    }
    let secrets = runtime.secrets();
    let self_name = crate::config::ops::resolve_device_name(&device_db).await;
    let identity_key = load_signing_key(&user_id, secrets)?;
    let op_key = load_device_operational_key(secrets)?;
    let issuer_kel = kotton_identity::kel_store::load_chain(runtime.base_dir(), &user_id)
        .unwrap_or_default();
    let issuer_recovery_bundle =
        kotton_identity::provisioning::read_recovery_bundle_raw(runtime.base_dir(), &user_id)
            .unwrap_or_default();
    // Admitting an invite never sets this device's relay: a device that has
    // none is offered the relay the vault was met at, by its key, in the
    // ceremony's last frame, and stands there only on the person's yes. A
    // device that has one keeps it; the vault reserves at its own and the
    // pair resolves the difference.
    let own_relay_url = runtime.reachability().nat().relay_url;
    let handed_drives = drives_to_hand(&db, &user_id).await;
    let relay_offer = invite
        .as_ref()
        .filter(|_| own_relay_url.is_empty())
        .map(|inv| relay_offered(&inv.invite.relay_url, inv.relay_key));

    let (tx, rx) = mpsc::channel::<UserResponse>(16);
    tokio::spawn(async move {
        if tx.send(UserResponse::PairConnecting).await.is_err() {
            return;
        }
        let streaming = StreamingConfirmer {
            tx: tx.clone(),
            token: Uuid::new_v4().to_string(),
            pending,
            ttl: std::time::Duration::from_secs(ttl_seconds),
        };
        let confirmer: &dyn kotton_peer::pair_channel::SasConfirmer = match &pinned {
            Some(_) => &TheKeyConfirms,
            None => &streaming,
        };
        let result = match (&invite, dial) {
            (Some(inv), _) => {
                // What the ceremony's one dial presents: at this device's own
                // relay by its own records — the relay it stands at, or a
                // relay its person operates at the address their credential
                // names — the key this machine holds there; anywhere else,
                // the invited key the code carried and nothing of this
                // device's — the one choice every dial to an address another
                // party supplied makes (`RelayKeyring`). An operator taking
                // their own vault's offer meets it at the relay they operate,
                // and presents *mine*, which *only my devices* reads.
                let nat = runtime.reachability().nat();
                let admission = runtime.reachability().relay_keys().presenting_on_a_dial(
                    &inv.invite.relay_url,
                    inv.admission.clone(),
                    &nat.relay_url,
                    relay_id(nat.relay_key.as_deref()).as_ref(),
                );
                run_enroll_issuer_relayed(
                    &inv.invite,
                    inv.relay_key,
                    &admission,
                    &identity_key,
                    &op_key,
                    &self_name,
                    runtime.peer_listen_addr(),
                    &own_relay_url,
                    posture,
                    issuer_kel,
                    issuer_recovery_bundle,
                    handed_drives,
                    confirmer,
                    Some(inv.vault_key),
                )
                .await
            }
            (None, Some((sid, addr))) => {
                run_enroll_issuer_dialing(
                    &identity_key,
                    &op_key,
                    sid,
                    addr,
                    &self_name,
                    runtime.peer_listen_addr(),
                    posture,
                    issuer_kel,
                    issuer_recovery_bundle,
                    handed_drives,
                    None,
                    confirmer,
                )
                .await
            }
            (None, None) => unreachable!("a code is an invite or a connection code"),
        };
        let frame = match result {
            Ok(enrolled) => {
                let _ = tx.send(UserResponse::PairTransferring).await;
                let store = match users.get(&user_id) {
                    Some(rt) => rt,
                    None => {
                        let _ = tx
                            .send(UserResponse::Error {
                                message: format!("user runtime '{user_id}' is not loaded"),
                            })
                            .await;
                        return;
                    }
                };
                let the_vaults_rule = refused_as(&runtime, enrolled.node.clone(), &user_id);
                match keep_the_admitted(
                    the_vaults_rule,
                    runtime.secrets(),
                    store.as_ref(),
                    &db,
                    &paired_keys,
                    &user_id,
                    posture,
                    enrolled,
                )
                .await
                {
                    Ok(node) => {
                        if posture == Posture::Full {
                            crate::users::drive_devices::introduce(&runtime, &db, &user_id, &node).await;
                        }
                        UserResponse::PairingComplete {
                            node,
                            session_token: None,
                            relay_offer,
                        }
                    }
                    Err(reason) => UserResponse::PairFailed { reason },
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "admit-by-code ceremony failed");
                let reason = match (
                    &pinned,
                    e.downcast_ref::<kotton_peer::pairing::NotThePinnedKey>(),
                    e.downcast_ref::<kotton_peer::pairing::NotTheInvitedRelay>(),
                ) {
                    (Some(p), Some(refused), _) => not_the_pinned_vault(&p.vault, refused),
                    (None, Some(refused), _) => not_the_invited_vault(refused),
                    (_, _, Some(refused)) => not_the_invited_relay(refused),
                    _ => ceremony_failure(&e),
                };
                UserResponse::PairFailed { reason }
            }
        };
        let _ = tx.send(frame).await;
    });
    Ok(rx)
}

/// Keep the vault an admit's ceremony enrolled — **after** its rule is read,
/// and only if it keeps for this device: `the_vaults_rule` is [`refused_as`]
/// for the admit, and is awaited before anything is written. A refusal ends
/// the admit with the vault's words ([`not_kept_as`]) and nothing recorded
/// here: no row, no drive, no key on the allowlist, no member. There is
/// nothing to withdraw, so there is no withdrawal path (#157).
///
/// Why the rule can be read first: what it asks is the vault's own record,
/// which the vault wrote before it answered that it kept the join
/// ([`answer_the_issuer`] follows [`finalize_joined_node`] on its side), and
/// the ceremony returned only on that answer. The question is a dial to the
/// node the ceremony learned ([`kotton_peer::pairing::EnrolledNode::node`],
/// the value [`finalize_enrolled_node`] records and returns unchanged), and a
/// dial reads no row: [`kotton_peer::dialer::Dialer::connect`] takes the node
/// it is handed.
///
/// `Err` is the `PairFailed` reason. A write that fails part-way through
/// [`finalize_enrolled_node`] is said as such; that function is not one
/// transaction, which is its own work.
#[allow(clippy::too_many_arguments)]
async fn keep_the_admitted(
    the_vaults_rule: impl std::future::Future<Output = Option<String>>,
    secrets: &dyn kotton_sys::secret::SecretsStore,
    member_store: &dyn kotton_peer::membership::MemberStore,
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<[u8; 32]>>>,
    user_id: &str,
    posture: Posture,
    enrolled: kotton_peer::pairing::EnrolledNode,
) -> Result<kotton_wire::peer::PairedNode, String> {
    if let Some(message) = the_vaults_rule.await {
        return Err(not_kept_as(user_id, &message));
    }
    finalize_enrolled_node(secrets, member_store, db, paired_keys, user_id, posture, enrolled)
        .await
        .map_err(|e| format!("Admitted, but recording the node failed: {e}"))
}

/// The one posture an admit by code takes, refused before anything else runs.
/// It is also why [`refused_as`] says a vault's verb only to a vault: the admit
/// is its one caller, and a Full or Cosigner admit never reaches the ceremony,
/// so it never reaches the check after it. That check holds no posture test of its
/// own, since this one is what makes it unnecessary.
fn admits_by_code(posture: Posture) -> io::Result<()> {
    match posture {
        Posture::BlindStorage => Ok(()),
        refused => Err(io::Error::other(not_blind_refusal(refused))),
    }
}

/// How long the admit waits to hear whether the vault keeps for this device.
/// A relayed vault reserves for the new pair on its registrar's next pass, a
/// second or so, and a dial in that gap is answered by nobody; past this, the
/// admit completes unchecked and the first sync is where a refusal shows.
const STANDING_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

/// How long a refusal must hold before the admit reports it. The vault records
/// its half of the pairing *after* the channel closes, and this device's half
/// completes when the channel does, so the first answer can predate the
/// vault's record: a re-admit under the right name is refused as the old
/// tenant until the vault has written the new one. A refusal that is still the
/// answer this long after it was first heard is the vault's standing, not its
/// lag; an answer in between clears it.
const REFUSAL_HOLDS: std::time::Duration = std::time::Duration::from_secs(5);

/// Ask the vault an admit's ceremony just enrolled — before this device
/// records it ([`keep_the_admitted`]) — under this device's own user, whether
/// it keeps for this device — `VaultCapacity`, a tenant's verb, which the vault answers
/// only to a key paired to the pool the request names. The vault's refusal,
/// when it holds for [`REFUSAL_HOLDS`]; `None` when it answers anything else,
/// or cannot be reached within [`STANDING_WAIT`].
///
/// This is the whole of the check that the name the vault was given
/// (`kvaultd invite <name>`) is the name this device syncs as: the pairing says
/// which pool the device's key is in, and every later request names the
/// device's user, so the one question that compares them is a request. It adds
/// nothing to the enrolment and nothing to the wire — a verb the device would
/// say at its first sync anyway, said before the person has anything to sync.
async fn refused_as(runtime: &DeviceRuntime, node: kotton_wire::peer::PairedNode, user_id: &str) -> Option<String> {
    let started = tokio::time::Instant::now();
    let mut refused: Option<(tokio::time::Instant, String)> = None;
    loop {
        // One attempt, bounded: a dial down the whole NAT ladder can outlast
        // the wait on its own.
        let attempt = async {
            let client = runtime.open_peer_client(node.clone(), user_id, None).await.ok()?;
            client
                .send(&kotton_wire::ipc::UserRequest::VaultCapacity {
                    user_id: user_id.to_string(),
                })
                .await
                .ok()
        };
        let answer = tokio::time::timeout(REFUSAL_HOLDS, attempt).await.ok().flatten();
        match answer {
            // The vault's refusal of a stranger, and nothing else: a node that
            // is not a vault answers a vault's verb with an error that says
            // nothing about this device's standing there.
            Some(UserResponse::Error { message }) if message.contains(crate::users::admission::NOT_PAIRED_WITH) => {
                let since = refused.as_ref().map_or_else(tokio::time::Instant::now, |(t, _)| *t);
                if since.elapsed() >= REFUSAL_HOLDS {
                    return Some(message);
                }
                refused = Some((since, message));
            }
            Some(_) => return None,
            None => {}
        }
        if started.elapsed() >= STANDING_WAIT + REFUSAL_HOLDS {
            if refused.is_none() {
                tracing::warn!(node = %node.id, "the admitted vault did not answer in time; its standing is unchecked");
            }
            return refused.map(|(_, message)| message);
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// What the admit prints when the vault its ceremony reached refuses this
/// device: the vault's own sentence, that this device kept nothing of it
/// ([`keep_the_admitted`] reads the refusal before it writes), and what to
/// type. When the vault holds this device's key under another pool, it has
/// said which ([`crate::users::admission::paired_as_another`]), and the way out
/// is the operator's: invite again under this device's user. Dropping the
/// tenant the key was paired to is not a way out — `tenancy::drop_tenant`
/// sweeps the key's row, which leaves the device paired nowhere and still
/// refused — so it is named only as the cleanup after the new invite is
/// admitted.
fn not_kept_as(user_id: &str, message: &str) -> String {
    let what_to_do = if message.contains(crate::users::admission::PAIRED_AS_ANOTHER) {
        format!(
            "The vault was given another name for this device than it syncs as. On the host, invite again \
             under this device's user — `kvaultd invite {user_id}` (or `vault invite [<v>] {user_id}` \
             from the desktop that holds its credential) — and admit that invite here first. Once \
             it is admitted, the other tenant can be dropped on the host, if it was only ever this \
             device's."
        )
    } else {
        format!(
            "On the host, `kvaultd invite {user_id}` (or `vault invite [<v>] {user_id}` from the desktop \
             that holds its credential), and admit that invite here."
        )
    };
    format!(
        "Not admitted: the vault will not keep for this device as `{user_id}`: {message}. Nothing of it was \
         recorded here, so there is nothing to revoke. {what_to_do}"
    )
}

/// Why no invite is minted at a relay that shows no key: a code names its
/// relay by its key, and the admitting device holds the relay to it.
const RELAY_SHOWS_NO_KEY: &str = "the relay this invite would meet at shows no key of its own, so an \
     invite could not name it — nothing was minted. A relay of today proves its key; upgrade it";

/// Why no invite is minted by a node that presents a key at its relay and may
/// hand on none — an invitee there, or a person beside the relay's operator on
/// one machine: the relay reads a key, and the invite could carry none.
const CANNOT_CARRY_A_KEY: &str = "this node presents a key at its relay, and holds no key there it may \
     hand on — so an invite minted here would carry no key the relay reads, and its holder would be refused \
     there. Nothing was minted. An invite to a relay that reads a key is minted where that relay's invited \
     key is kept: by its operator, or by a vault its operator told it to";

/// Why no invite is minted when its handle could not be reserved, in the
/// words of the cause: a relay that answered and refused this node by its rule
/// would refuse whoever was handed the invite too; a relay that was not reached
/// says nothing about its rule, and is named with what went wrong.
fn not_minted(relay_url: &str, why: &kotton_peer::pairing::InviteNotReserved) -> String {
    use kotton_peer::pairing::InviteNotReserved;
    match why {
        InviteNotReserved::Refused(answer) => format!(
            "the relay at {relay_url} refused this node's reservation for the invite ({answer}), so it would \
             refuse whoever was handed the invite too — nothing was minted. Its rule reads a key this node \
             does not hold; the relay's operator tells a vault its keys (`vault stand <the vault>` on their \
             desktop)"
        ),
        InviteNotReserved::Unreachable(error) => format!(
            "could not reach the relay at {relay_url} to reserve the invite ({error}) — nothing was minted. \
             Check that the relay is up and reachable from here, then ask for the invite again"
        ),
    }
}

/// Mint an invite and wait to be admitted through the relay: reserve under
/// the invite's handle at this node's relay, stream the invite
/// (`PairAdvertising`), and run the joiner half when a device dials —
/// `PairShowCode` → `PairTransferring` → `PairingComplete` | `PairFailed`, the
/// frames every joiner half streams, so whatever drives one drives them all.
/// Nothing listens on a public port; the node needs a relay, which it needs to
/// be reachable after pairing anyway — no second public port, and no code
/// carrying an address.
///
/// `relay_url` is the relay the invite meets at, handed in by the caller that
/// just refused its absence in its own words — a vault names its settings
/// file (`kvaultd`'s `NO_RELAY`), a device its `kotton config relay set`
/// (`kuserd`'s `NO_RELAY_FOR_AN_INVITE`). This function does not read the URL
/// itself, so there is no path into it that skipped that check, and it keeps
/// no refusal of its own to backstop one.
///
/// `offered` is the relay's *invited* key the caller may hand on with this
/// invite — a vault's, told it by its operator with its reach set; a person's
/// own, held as that relay's operator — read by the caller, which knows whose
/// keys are whose: another person's on the same machine are never carried. It
/// rides in the code so the invite also admits its holder's first contact at a
/// relay whose rule is *the people I invite*.
/// The invite's handle is reserved before the code is handed out, so a relay
/// that refuses this node refuses the mint, never the person handed it.
#[allow(clippy::too_many_arguments)]
pub async fn handle_device_invite(
    runtime: Arc<DeviceRuntime>,
    relay_url: String,
    offered: Option<kotton_net::rendezvous::AdmissionKey>,
    users: Arc<dyn crate::users::residency::Residency>,
    db: Arc<SqlitePool>,
    device_db: Arc<SqlitePool>,
    sessions: sessions::SessionMap,
    paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    pending: PendingConfirms,
    user_id: String,
    ttl_seconds: u64,
    as_name: Option<String>,
    policy: JoinPolicy,
) -> io::Result<mpsc::Receiver<UserResponse>> {
    use kotton_peer::pairing::run_enroll_join_relayed;

    let node_key = load_device_operational_key(runtime.secrets())?;
    let warm_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let self_name = match as_name {
        Some(n) => n,
        None => crate::config::ops::resolve_device_name(&device_db).await,
    };
    let invite = Invite::new(&relay_url);
    // The code names the relay by its key and this node by its own: the
    // key recorded for this node's relay, or — none
    // recorded — the key it proves now. A relay that shows none cannot be
    // named, and nothing is minted.
    let relay_key = match relay_id(runtime.reachability().nat().relay_key.as_deref()) {
        Some(k) => k,
        None => kotton_peer::relay_key::prove_relay(&invite.relay_url, None)
            .await
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::other(RELAY_SHOWS_NO_KEY))?,
    };
    // The relay's *invited* key rides in the code when the caller may hand it
    // on (`offered`). A node that presents a key at its relay and may hand on
    // none (`CANNOT_CARRY_A_KEY`) would mint a code carrying no key the relay
    // reads, so nothing is minted.
    let invited = offered;
    if invited.is_none() && runtime.reachability().present_at_own_relay().is_some() {
        return Err(io::Error::other(CANNOT_CARRY_A_KEY));
    }
    // The vault reserves the invite's handle at its own relay, presenting the
    // key its operator told it with its reach set (`StandAt`) — and does so
    // before the code is handed to anyone, so a relay that refuses this node
    // refuses the mint rather than the person handed the code.
    let admission = runtime.reachability().present_at_own_relay();
    let reserved = kotton_peer::pairing::reserve_invite(&invite, admission.as_ref())
        .await
        .map_err(|e| io::Error::other(not_minted(&invite.relay_url, &e)))?;
    let code = invite.code_for(node_key.verifying_key().to_bytes(), relay_key, invited.as_ref()).to_text();
    let expires_at = (now_secs() as u64).checked_add(ttl_seconds).ok_or_else(|| {
        io::Error::other(format!("an invite of {ttl_seconds}s expires past any timestamp"))
    })?;
    // Announced, not merely bound: a relayed circuit observes no address for
    // the other side to complete a bare port with, so a host that has a public
    // address says it here: a host has one public address.
    let peer_listen_addr = runtime.announced_peer_addr();

    let (tx, rx) = mpsc::channel::<UserResponse>(16);
    tokio::spawn(async move {
        if tx
            .send(UserResponse::PairAdvertising { code: kotton_wire::ipc::SecretText::new(code), expires_at })
            .await
            .is_err()
        {
            return;
        }
        let confirmer = StreamingConfirmer {
            tx: tx.clone(),
            token: Uuid::new_v4().to_string(),
            pending,
            ttl: std::time::Duration::from_secs(ttl_seconds),
        };
        let result = run_enroll_join_relayed(
            &invite,
            reserved,
            &warm_key,
            &node_key,
            ttl_seconds,
            &self_name,
            peer_listen_addr,
            &confirmer,
        )
        .await;
        let frame = match result {
            Ok((joined, answer))
                if policy == JoinPolicy::BlindOnly
                    && (joined.data_keys.is_some()
                        || joined.frost_share.is_some()
                        || joined.warm_key_delegation.is_some()) =>
            {
                tracing::warn!(user_id = %user_id, "a vault refused a payload carrying keys");
                let refused = UserResponse::PairFailed {
                    reason: "this node is a vault: it keeps sealed bytes and holds no key, so \
                             admit it blind"
                        .to_string(),
                };
                answer_the_issuer(answer, &sessions, refused).await
            }
            Ok((joined, answer)) => {
                let _ = tx.send(UserResponse::PairTransferring).await;
                let outcome = match finalize_joined_node(
                    &runtime, &*users, &db, &sessions, &paired_keys, &user_id, &warm_key, joined,
                )
                .await
                {
                    Ok(resp) => resp,
                    Err(e) => UserResponse::PairFailed {
                        reason: format!("Not admitted: saving failed ({e})"),
                    },
                };
                answer_the_issuer(answer, &sessions, outcome).await
            }
            Err(e) => {
                tracing::warn!(error = %e, "invite ceremony failed");
                UserResponse::PairFailed {
                    reason: ceremony_failure(&e),
                }
            }
        };
        let _ = tx.send(frame).await;
    });
    Ok(rx)
}


/// The person's drives this device records — the first drive on each vault,
/// one per vault ([`kotton_peer::daemon::drives::list`]) — as the handout a
/// joiner is given at the join (`PairingPayload::FrostShare::drives`). The
/// drives made beside them the joiner learns from the vaults themselves at its
/// first pass (`drive_verbs::follow`), so the payload is unchanged. Whether a join is handed
/// them is the ceremony's to decide (`kotton_peer::pairing::issuer_over`
/// hands them to a `Full` joiner only); this says what they are. A record that
/// does not read is a join that hands no drive, and is logged, never a failed
/// join.
pub async fn drives_to_hand(db: &Arc<SqlitePool>, user_id: &str) -> Vec<kotton_wire::peer::DriveHandout> {
    match kotton_peer::daemon::drives::list(db, user_id).await {
        Ok(drives) => drives
            .into_iter()
            .map(|d| kotton_wire::peer::DriveHandout { vault_key: d.vault_key, tenancy: d.tenancy, node: d.node })
            .collect(),
        Err(e) => {
            tracing::warn!(user_id, error = %e, "the drive record does not read; the join hands no drive");
            Vec::new()
        }
    }
}

/// Whether this device can record every drive `issuer` handed it at the join,
/// as the name `user_id` it joins under: each drive's tenancy is that name, its
/// node's key is the vault's key and its DID names that key, and its node is
/// not the issuer's — neither the issuer's key nor the issuer's DID, which is
/// the key of the row the join writes for the issuer, so a drive under it
/// would be written over that row. `Err` says which drive and why. The rows
/// this device already holds are [`check_handed_rows`]'s.
///
/// What the drive's node is *called* is not checked: a label keys no row
/// (`kotton_peer::daemon::db`), so a drive shown under the issuer's name, or
/// two drives under one label, are each written to their own row and replace
/// nothing.
///
/// Checked before the join writes anything, so a handout this device cannot
/// keep refuses the ceremony cleanly: a device that joins with a drive it
/// cannot reach has nothing to sync and no way back — the projection runs only
/// in a pass on a drive it already reaches.
pub fn check_handed_drives(
    user_id: &str,
    issuer: &kotton_wire::peer::PairedNode,
    drives: &[kotton_wire::peer::DriveHandout],
) -> Result<(), String> {
    for drive in drives {
        let node = &drive.node;
        let named = kotton_crypto::DidKeyMethod::to_public_key(&node.device_did).map(|k| k.to_bytes()).ok();
        let why = if drive.tenancy != user_id {
            Some(format!("it is kept under '{}', and this device joins as '{user_id}'", drive.tenancy))
        } else if node.public_key != drive.vault_key {
            Some("the node it is reached through is not the vault's key".to_string())
        } else if named != Some(node.public_key) {
            Some("its node's DID does not name its key".to_string())
        } else if node.device_did == issuer.device_did || node.public_key == issuer.public_key {
            Some(format!("its node is the device this one joins ('{}')", issuer.id))
        } else {
            None
        };
        if let Some(why) = why {
            return Err(format!("the drive at '{}' cannot be recorded here: {why}", node.id));
        }
    }
    Ok(())
}

/// Whether this device can record every drive handed at the join without
/// writing over a row it holds. A row is keyed by the person and the node's
/// DID (`kotton_peer::daemon::db`), so the join's write (`insert_paired_node`)
/// can take only this person's row under the drive's DID, and `drives::record`
/// reads this person's row under the vault's key; those are the rows read
/// here, and no other person's, which no write of this person's reaches. The
/// one the join may take is a row for the vault's key under no posture or
/// `blind-storage`. `Ok(Err)` says which drive and why.
///
/// - **The vault's key, paired here as something else** — one of the person's
///   devices, a cosigner — is not made a vault on the issuer's word: the row
///   keeps its posture, and the join is refused. `drives::record` refuses the
///   same row; checking here refuses before anything is written.
/// - **The drive's DID, paired here beside another key**, is not rewritten to
///   the vault's key: that row, and the drive it may be, stay as they are, and
///   the join is refused.
///
/// A label is not read: one the person's rows already carry is shown on the
/// drive's row too, and keys neither.
///
/// Read before the join writes anything, beside [`check_handed_drives`].
pub async fn check_handed_rows(
    db: &Arc<SqlitePool>,
    user_id: &str,
    drives: &[kotton_wire::peer::DriveHandout],
) -> io::Result<Result<(), String>> {
    for drive in drives {
        let node = &drive.node;
        let rows: Vec<(String, Vec<u8>, Option<String>)> = sqlx::query_as(
            "SELECT id, public_key, posture FROM paired_nodes \
             WHERE user_id = ? AND (device_did = ? OR public_key = ?) ORDER BY device_did",
        )
        .bind(user_id)
        .bind(node.device_did.to_string())
        .bind(drive.vault_key.as_slice())
        .fetch_all(db.as_ref())
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
        for (id, key, posture) in rows {
            let why = if key.as_slice() == drive.vault_key.as_slice() {
                match posture.filter(|p| p != Posture::BlindStorage.as_str()) {
                    Some(other) => format!(
                        "this device pairs '{id}' under the vault's key as {other}, not as a vault, and \
                         keeps it as that"
                    ),
                    None => continue,
                }
            } else {
                format!("this device pairs the vault's DID as '{id}' under another key, and keeps it as that")
            };
            return Ok(Err(format!("the drive at '{}' cannot be recorded here: {why}", node.id)));
        }
    }
    Ok(Ok(()))
}

/// Record the drives an admitting device handed this one at the join, through
/// the one writer of the record: the node it is reached through, with its
/// addresses and relay, admitted at the handshake, then the drive itself
/// through `drives::record`, which sets `blind-storage` on a row naming no
/// posture and refuses one naming another. The row is written with no posture
/// of its own, so a row this device holds for the vault's key keeps what it
/// says, as `peer add` keeps it: the issuer's word makes nothing a vault here.
///
/// The caller has checked them ([`check_handed_drives`],
/// [`check_handed_rows`]), so no row is written over and `record` refuses
/// none; a write that fails anyway is the join's error, so the person is told
/// and joins again — a re-join is idempotent — rather than ending with a
/// device that has nothing to sync.
pub async fn record_handed_drives(
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<[u8; 32]>>>,
    user_id: &str,
    drives: &[kotton_wire::peer::DriveHandout],
) -> io::Result<()> {
    for drive in drives {
        let node = &drive.node;
        let did = node.device_did.to_string();
        let addresses = serde_json::to_string(&node.addresses).map_err(json_err)?;
        network_db::insert_paired_node(
            db,
            &node.id,
            user_id,
            &did,
            &node.public_key,
            &addresses,
            now_secs(),
            None,
        )
        .await?;
        if let Some(relay) = node.relay_url.as_deref() {
            network_db::update_paired_node_relay(db, user_id, &did, Some(relay)).await?;
        }
        kotton_peer::daemon::drives::record(db, user_id, &drive.vault_key).await?;
        paired_keys.write().unwrap().insert(node.public_key);
        tracing::info!(user_id, drive = %node.id, "recorded a drive handed at the join");
    }
    Ok(())
}

#[cfg(test)]
mod handed_drive_tests {
    use super::{check_handed_drives, check_handed_rows, record_handed_drives};
    use kotton_peer::daemon::db as network_db;
    use kotton_store::runtime::user::UserStore;
    use kotton_wire::ipc::UserResponse;
    use kotton_wire::peer::{DriveHandout, PairedNode};
    use sqlx::SqlitePool;
    use std::collections::HashSet;
    use std::sync::{Arc, RwLock};

    fn a_node(id: &str, seed: u8) -> PairedNode {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
        PairedNode {
            id: id.into(),
            device_did: kotton_crypto::DidKeyMethod::from_public_key(&key),
            public_key: key.to_bytes(),
            paired_at: 0,
            addresses: vec![],
            relay_url: None,
            posture: Some("blind-storage".into()),
        }
    }

    fn a_drive(id: &str, seed: u8, tenancy: &str) -> DriveHandout {
        let node = a_node(id, seed);
        DriveHandout { vault_key: node.public_key, tenancy: tenancy.into(), node }
    }

    /// **A handout the joiner cannot keep refuses the join**, by name and with
    /// the reason: another tenancy, a node that is not the vault's key, a DID
    /// that names another key, and a node that is the issuer's own row. A
    /// drive it can keep, and no drive at all, are taken.
    #[test]
    fn a_handout_the_joiner_cannot_keep_is_refused_with_the_reason() {
        let issuer = a_node("laptop", 1);
        assert!(check_handed_drives("alice", &issuer, &[]).is_ok());
        assert!(check_handed_drives("alice", &issuer, &[a_drive("vault", 2, "alice")]).is_ok());

        let why = check_handed_drives("alice", &issuer, &[a_drive("vault", 2, "bob")]).unwrap_err();
        assert!(why.contains("'vault'") && why.contains("kept under 'bob'"), "{why}");

        let mut not_the_vault = a_drive("vault", 2, "alice");
        not_the_vault.vault_key = [9; 32];
        let why = check_handed_drives("alice", &issuer, &[not_the_vault]).unwrap_err();
        assert!(why.contains("not the vault's key"), "{why}");

        let mut misnamed = a_drive("vault", 2, "alice");
        misnamed.node.device_did = a_node("other", 3).device_did;
        let why = check_handed_drives("alice", &issuer, &[misnamed]).unwrap_err();
        assert!(why.contains("DID does not name its key"), "{why}");

        // The issuer's name on a drive is a label, and keys no row: taken.
        assert!(check_handed_drives("alice", &issuer, &[a_drive("laptop", 2, "alice")]).is_ok());
        let mut issuers_key = a_drive("vault", 1, "alice");
        issuers_key.node.id = "vault".into();
        let why = check_handed_drives("alice", &issuer, &[issuers_key]).unwrap_err();
        assert!(why.contains("the device this one joins"), "{why}");

        // Two drives under one label are two rows: taken, as an issuer that
        // enrolled two vaults under the default `vault` holds them.
        assert!(check_handed_drives("alice", &issuer, &[a_drive("vault", 2, "alice"), a_drive("vault", 3, "alice")])
            .is_ok());

        // The issuer's DID is the key of the row written for it: a drive under
        // it would be written over that row. Its DID here names another key
        // than the one it presents, as a device's identity DID beside its
        // operational key does.
        let mut issuer_by_identity = a_node("laptop", 1);
        issuer_by_identity.device_did = a_node("identity", 8).device_did;
        let why = check_handed_drives("alice", &issuer_by_identity, &[a_drive("vault", 8, "alice")]).unwrap_err();
        assert!(why.contains("the device this one joins"), "{why}");
    }

    /// A machine database at the current schema, on disk so every connection
    /// of the pool sees the same one.
    async fn machine_db() -> (tempfile::TempDir, Arc<SqlitePool>) {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::db::open_machine_db(dir.path().join("agent.db")).await.unwrap();
        (dir, Arc::new(pool))
    }

    async fn pair(db: &Arc<SqlitePool>, user_id: &str, id: &str, seed: u8, posture: Option<&str>) {
        let node = a_node(id, seed);
        network_db::insert_paired_node(db, id, user_id, &node.device_did.to_string(), &node.public_key, "[]", 0, posture)
            .await
            .unwrap();
    }

    async fn drive_records(db: &Arc<SqlitePool>) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM drives").fetch_one(db.as_ref()).await.unwrap()
    }

    struct NobodyResident;
    impl crate::users::residency::Residency for NobodyResident {
        fn insert(&self, _: String, _: Arc<UserStore>) {}
        fn get(&self, _: &str) -> Option<Arc<UserStore>> {
            None
        }
    }

    /// Run the joiner's side of a join that hands `drives`, from the issuer
    /// `laptop`, on `db`, and say what it answered.
    async fn join_handing(db: &Arc<SqlitePool>, drives: Vec<DriveHandout>) -> UserResponse {
        let temp = tempfile::tempdir().unwrap();
        let runtime = crate::runtime::DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            crate::config::RuntimeConfig::default(),
            Arc::new(kotton_secret::MemorySecrets::new()),
        )
        .await
        .unwrap();
        let issuer = a_node("issuer", 1);
        let joined = kotton_peer::pairing::JoinedNode {
            root_did: issuer.device_did.clone(),
            peer: issuer,
            frost_share: None,
            warm_key_delegation: None,
            data_keys: None,
            pubkey_package: None,
            kel: Vec::new(),
            recovery_bundle: None,
            gateway: None,
            drives,
        };
        super::finalize_joined_node(
            &runtime,
            &NobodyResident,
            db,
            &Default::default(),
            &Arc::new(RwLock::new(HashSet::new())),
            "alice",
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            joined,
        )
        .await
        .unwrap()
    }

    fn refusal(answer: UserResponse) -> String {
        match answer {
            UserResponse::PairFailed { reason } => reason,
            other => panic!("the join was not refused: {other:?}"),
        }
    }

    /// **The issuer's word does not make one of the joiner's devices a
    /// vault.** The joiner pairs `laptop` as `full` under the key the issuer
    /// hands as a vault's: the join is refused with the reason, before it
    /// writes anything, and `laptop` is still `full` and no drive.
    #[tokio::test]
    async fn a_joiner_holding_the_handed_key_as_a_device_keeps_that_row_and_the_join_is_refused() {
        let (_dir, db) = machine_db().await;
        pair(&db, "alice", "laptop", 2, Some("full")).await;

        let why = refusal(join_handing(&db, vec![a_drive("vault", 2, "alice")]).await);
        assert!(why.contains("'laptop'") && why.contains("as full, not as a vault"), "{why}");
        assert!(why.contains("This device was not joined"), "{why}");

        let laptop = network_db::paired_node_named(&db, "alice", "laptop").await.unwrap().unwrap();
        assert_eq!(laptop.posture.as_deref(), Some("full"), "the join relabelled the device");
        assert!(network_db::paired_node_named(&db, "alice", "vault").await.unwrap().is_none());
        assert!(network_db::paired_node_named(&db, "alice", "issuer").await.unwrap().is_none(), "a refused join wrote");
        assert_eq!(drive_records(&db).await, 0, "the device was recorded as a drive");
    }

    /// **The issuer's word does not replace a row the joiner holds under
    /// another key, nor drop its drive.** The joiner's own `vault`, another
    /// key and recorded as its drive: a join handing a drive labelled `vault`
    /// writes the handed drive's row beside it (a label keys no row), and that
    /// row and its drive are as they were.
    #[tokio::test]
    async fn a_joiner_holding_another_key_under_the_handed_label_keeps_that_rows_drive() {
        let (_dir, db) = machine_db().await;
        pair(&db, "alice", "vault", 3, None).await;
        kotton_peer::daemon::drives::record(&db, "alice", &a_node("vault", 3).public_key).await.unwrap();

        let answer = join_handing(&db, vec![a_drive("vault", 2, "alice")]).await;
        assert!(!matches!(answer, UserResponse::PairFailed { .. }), "the join was refused: {answer:?}");

        let mut drives: Vec<_> = kotton_peer::daemon::drives::list(&db, "alice")
            .await
            .unwrap()
            .into_iter()
            .map(|d| (d.node.id, d.vault_key))
            .collect();
        drives.sort();
        let mut want = vec![("vault".to_string(), a_node("vault", 3).public_key), ("vault".to_string(), a_node("vault", 2).public_key)];
        want.sort();
        assert_eq!(drives, want, "the join replaced the joiner's vault or dropped its drive");
    }

    /// **A drive shown under the issuer's own name is recorded beside the
    /// issuer** (kotton #99). The person's device is named `laptop` and so is
    /// one of their drives: the join writes both rows, under their own DIDs,
    /// and is not refused for the name.
    #[tokio::test]
    async fn a_drive_under_the_issuers_name_is_recorded_beside_the_issuer() {
        let (_dir, db) = machine_db().await;
        let answer = join_handing(&db, vec![a_drive("issuer", 2, "alice")]).await;
        assert!(!matches!(answer, UserResponse::PairFailed { .. }), "the join was refused: {answer:?}");
        let rows = network_db::list_paired_nodes(&db, "alice").await.unwrap();
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(rows.iter().all(|n| n.id == "issuer"), "{rows:?}");
        let drives = kotton_peer::daemon::drives::list(&db, "alice").await.unwrap();
        assert_eq!(drives.len(), 1, "{drives:?}");
        assert_eq!(drives[0].node.public_key, a_node("issuer", 2).public_key, "the drive names the issuer");
    }

    /// **Two people's rows under one label are both kept** (kotton #99). Bob
    /// pairs a vault as `vault` and another under the key alice's drive is
    /// handed under; alice's join writes her own rows beside them, under her
    /// name, and bob's rows and drives are as they were.
    #[tokio::test]
    async fn a_row_of_another_person_here_under_the_handed_label_or_key_is_kept() {
        let (_dir, db) = machine_db().await;
        pair(&db, "bob", "vault", 3, None).await;
        kotton_peer::daemon::drives::record(&db, "bob", &a_node("vault", 3).public_key).await.unwrap();
        pair(&db, "bob", "household", 2, Some("blind-storage")).await;
        let handed = [a_drive("vault", 4, "alice"), a_drive("shared", 2, "alice")];
        assert_eq!(check_handed_rows(&db, "alice", &handed).await.unwrap(), Ok(()));

        let answer = join_handing(&db, handed.to_vec()).await;
        assert!(!matches!(answer, UserResponse::PairFailed { .. }), "the join was refused: {answer:?}");

        let bobs = network_db::list_paired_nodes(&db, "bob").await.unwrap();
        assert_eq!(bobs.len(), 2, "{bobs:?}");
        let vault = network_db::paired_node_named(&db, "bob", "vault").await.unwrap().unwrap();
        assert_eq!(vault.public_key, a_node("vault", 3).public_key, "alice's join took bob's row");
        let bobs_drives = kotton_peer::daemon::drives::list(&db, "bob").await.unwrap();
        assert_eq!(bobs_drives.len(), 1, "{bobs_drives:?}");
        assert_eq!(bobs_drives[0].node.public_key, a_node("vault", 3).public_key, "bob's drive names a node not his");

        let alices = kotton_peer::daemon::drives::list(&db, "alice").await.unwrap();
        let mut named: Vec<_> = alices.iter().map(|d| d.node.id.as_str()).collect();
        named.sort();
        assert_eq!(named, ["shared", "vault"], "{alices:?}");
    }

    /// **What the join may write over, it records through the one writer.** A
    /// fresh drive, and a row the joiner holds for the vault's key with no
    /// posture, are taken: each is recorded as a drive and its row made
    /// `blind-storage` by `drives::record`, and the joiner's own label for
    /// the key it already pairs as a vault is kept as its drive.
    #[tokio::test]
    async fn a_handed_drive_the_joiner_can_keep_is_recorded_by_the_one_writer() {
        let (_dir, db) = machine_db().await;
        pair(&db, "alice", "vault", 3, None).await;
        pair(&db, "alice", "home-vault", 5, Some("blind-storage")).await;
        let handed = [a_drive("vault", 3, "alice"), a_drive("office", 4, "alice"), a_drive("home-vault", 5, "alice")];
        assert_eq!(check_handed_rows(&db, "alice", &handed).await.unwrap(), Ok(()));

        record_handed_drives(&db, &Arc::new(RwLock::new(HashSet::new())), "alice", &handed).await.unwrap();
        let drives = kotton_peer::daemon::drives::list(&db, "alice").await.unwrap();
        let mut named: Vec<_> = drives.iter().map(|d| d.node.id.as_str()).collect();
        named.sort();
        assert_eq!(named, ["home-vault", "office", "vault"]);
        assert!(drives.iter().all(|d| d.node.posture.as_deref() == Some("blind-storage")), "{drives:?}");
    }
}

#[cfg(test)]
mod admit_tests {
    use super::{admits_by_code, not_kept_as, adds_instead, not_minted};
    use crate::users::admission::{paired_as_another, NOT_PAIRED_WITH};
    use kotton_schemas::membership::Posture;

    /// **An invite that was not minted says which cause stopped it**:
    /// only a relay that answered and refused names its rule; one that was not
    /// reached is named with its address and the error, and says nothing of a
    /// rule or a key it could not have learned.
    #[test]
    fn a_relay_not_reached_is_not_said_to_have_refused_by_its_rule() {
        use kotton_peer::pairing::InviteNotReserved;
        const AT: &str = "http://relay.example:7700";
        let refused = not_minted(AT, &InviteNotReserved::Refused("the relay refused: HTTP error: 403 Forbidden".into()));
        assert!(refused.contains("refused this node's reservation") && refused.contains("rule reads a key"), "{refused}");
        assert!(refused.contains("nothing was minted"), "{refused}");
        let unreached = not_minted(AT, &InviteNotReserved::Unreachable("Connection refused (os error 111)".into()));
        assert!(unreached.contains("could not reach the relay at http://relay.example:7700"), "{unreached}");
        assert!(unreached.contains("Connection refused (os error 111)"), "the error is named: {unreached}");
        assert!(unreached.contains("nothing was minted"), "{unreached}");
        assert!(
            !unreached.contains("rule") && !unreached.contains("refused this node") && !unreached.contains("key"),
            "a relay never reached was said to have refused by its rule: {unreached}"
        );
    }

    /// What the admit prints when the vault holds this device under another
    /// tenant: both names, the invite to type first, and dropping the other
    /// tenant only after it — a drop alone leaves the device paired nowhere.
    #[test]
    fn a_device_paired_as_another_tenant_is_told_to_invite_first_and_drop_after() {
        let vault = format!("peer did:key:zD {NOT_PAIRED_WITH} 'alice': {}", paired_as_another("sam", "alice"));
        let said = not_kept_as("alice", &vault);
        assert!(said.contains("tenant `sam`, and asked as `alice`"), "{said}");
        let invite = said.find("kvaultd invite alice").expect(&said);
        let drop = said.find("dropped").expect(&said);
        assert!(invite < drop, "the invite comes before the drop: {said}");
        assert!(said.contains("Once it is admitted, the other tenant can be dropped"), "{said}");
        assert!(!said.contains("; or drop"), "dropping is not offered as an alternative: {said}");
    }

    /// The tenant check after an admit says a vault's verb, so only a blind
    /// admit may reach it: every other posture is refused before the ceremony,
    /// and so before the check.
    #[test]
    fn only_a_blind_admit_reaches_the_vaults_tenant_check() {
        assert!(admits_by_code(Posture::BlindStorage).is_ok());
        for posture in [Posture::Full, Posture::Cosigner, Posture::Gateway] {
            let refused = admits_by_code(posture).expect_err("only blind is admitted by code");
            assert!(refused.to_string().contains("blind posture only"), "{refused}");
        }
    }

    /// The posture a hint's `device add` words give, by the shape this crate owns: `device
    /// add` and then nothing (the default posture), exactly one flag of
    /// `DEVICE_ADD_POSTURE_FLAGS` (the shell's table, read from `kotton-schemas`, not copied), or
    /// `--gateway <value>` (a gateway). Anything else, including two posture flags, which the
    /// shell's `parse_add` refuses, is `None`. This holds the shape of the hints, not the
    /// shell's full grammar (`--as`, `--browser`, ordering): this crate cannot reach the shell
    /// and a second copy of that grammar would be a second reader to drift.
    fn device_add_parses(command: &str) -> Option<Posture> {
        use kotton_schemas::membership::{DEVICE_ADD_DEFAULT_POSTURE, DEVICE_ADD_POSTURE_FLAGS};
        let words: Vec<&str> = command.split_whitespace().collect();
        match words.strip_prefix(&["device", "add"])? {
            [] => Some(DEVICE_ADD_DEFAULT_POSTURE),
            ["--gateway", _code] => Some(Posture::Gateway),
            [flag] => DEVICE_ADD_POSTURE_FLAGS.iter().find(|(f, _)| f == flag).map(|(_, p)| *p),
            _ => None,
        }
    }

    /// The hints' reader refuses what the shell's refuses: two posture flags are no posture.
    #[test]
    fn two_posture_flags_are_no_posture_to_the_hint_reader() {
        assert_eq!(device_add_parses("device add --blind --cosigner"), None);
        assert_eq!(device_add_parses("device add --cosigner --blind"), None);
        assert_eq!(device_add_parses("device add --blind --blind"), None);
        assert_eq!(device_add_parses("device add --browser"), None);
        assert_eq!(device_add_parses("device add --cosigner"), Some(Posture::Cosigner));
    }

    /// Every posture the admit refuses is handed a `device add` that adds a
    /// device *of that posture* — never a bare one, which is a Full join code, and
    /// a gateway is never sent to `device join`, since it prints the code and this
    /// node admits it.
    #[test]
    fn every_refused_posture_is_named_the_device_add_that_adds_it() {
        for posture in [Posture::Full, Posture::Cosigner, Posture::Gateway, Posture::BlindStorage] {
            let Err(refused) = admits_by_code(posture) else { continue };
            let said = refused.to_string();
            // The command is data, held directly: it adds a device of this posture.
            let add = adds_instead(posture);
            assert_eq!(device_add_parses(&add), Some(posture), "{posture:?} adds by `{add}`");
            // And the sentence carries that command, backticked, and no other
            // `device add` — a second one would be a wider hint slipped in after
            // the right one, which is what this test exists to refuse.
            let adds: Vec<&str> = said
                .split('`')
                .skip(1)
                .step_by(2)
                .filter(|quoted| quoted.starts_with("device add"))
                .collect();
            assert_eq!(adds, vec![add.as_str()], "{posture:?} names exactly one `device add`: {said}");
            if posture == Posture::Gateway {
                assert!(!said.contains("device join"), "a gateway does not join: {said}");
                assert!(said.contains("prints the code"), "{said}");
            }
        }
    }

    /// The posture guard is the daemon's, and it is the only one: the shell sends
    /// whatever posture it was asked for, so a device that would hold keys is
    /// turned away here, before anything is dialled or read, with the sentence
    /// that says how such a device joins instead, with no flag that has one
    /// legal value.
    #[tokio::test]
    async fn admit_refuses_every_posture_that_could_hold_keys() {
        use kotton_schemas::membership::Posture;
        use kotton_store::runtime::user::UserStore;
        use std::collections::{HashMap, HashSet};
        use std::sync::{Arc, RwLock};

        struct NobodyResident;
        impl crate::users::residency::Residency for NobodyResident {
            fn insert(&self, _: String, _: Arc<UserStore>) {}
            fn get(&self, _: &str) -> Option<Arc<UserStore>> {
                None
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let runtime = Arc::new(
            crate::runtime::DeviceRuntime::new_with_secrets(
                temp.path().to_path_buf(),
                crate::config::RuntimeConfig::default(),
                Arc::new(kotton_secret::MemorySecrets::new()),
            )
            .await
            .unwrap(),
        );
        let pool = Arc::new(sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap());
        for posture in [Posture::Full, Posture::Cosigner] {
            let refused = super::handle_device_admit(
                runtime.clone(),
                Arc::new(NobodyResident),
                pool.clone(),
                pool.clone(),
                Arc::new(RwLock::new(HashSet::new())),
                Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                "alice".into(),
                "https://relay.example#amber-otter-kite".into(),
                120,
                posture,
                None,
            )
            .await;
            let Err(e) = refused else { panic!("{posture:?} was admitted by invite") };
            let said = e.to_string();
            assert!(said.contains("keeps what it cannot read"), "{posture:?}: {said}");
            assert!(said.contains("`device join <code>` on it"), "{posture:?}: {said}");
            // The fix it names carries the posture asked for: a bare `device add`
            // is Full, and would hand a co-signer more than was asked.
            let add = if posture == Posture::Cosigner { "`device add --cosigner`" } else { "`device add`" };
            assert!(said.contains(add), "{posture:?}: {said}");
        }
    }

    /// A key the vault holds under no tenant is told to be invited, and not
    /// told of a tenant to drop, since the vault named none.
    #[test]
    fn a_device_paired_nowhere_is_told_to_be_invited_and_of_no_tenant() {
        let said = not_kept_as("alice", &format!("peer did:key:zD {NOT_PAIRED_WITH} 'alice'"));
        assert!(said.contains("kvaultd invite alice"), "{said}");
        // From the desktop, the vault is named only where it operates several.
        assert!(said.contains("`vault invite [<v>] alice`"), "{said}");
        assert!(!said.contains("drop"), "{said}");
    }

    /// A member store that keeps what it is told, so a test sees whether the
    /// admit wrote a member.
    #[derive(Default)]
    struct Members(std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>);

    #[async_trait::async_trait]
    impl kotton_peer::membership::MemberStore for Members {
        async fn member_write(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
            self.0.lock().unwrap().insert(path.to_string(), data.to_vec());
            Ok(())
        }
        async fn member_read(&self, path: &str) -> anyhow::Result<Vec<u8>> {
            self.0.lock().unwrap().get(path).cloned().ok_or_else(|| anyhow::anyhow!("nothing at {path}"))
        }
        async fn member_delete(&self, path: &str) -> anyhow::Result<()> {
            self.0.lock().unwrap().remove(path);
            Ok(())
        }
        async fn member_list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
            Ok(self.0.lock().unwrap().keys().filter(|k| k.starts_with(prefix)).cloned().collect())
        }
    }

    /// What an admit's ceremony hands back for a vault: its node, blind, and
    /// no share.
    fn an_enrolled_vault() -> kotton_peer::pairing::EnrolledNode {
        let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]).verifying_key();
        kotton_peer::pairing::EnrolledNode {
            issuer_share: None,
            pubkey_package: None,
            node: kotton_wire::peer::PairedNode {
                id: "vault".into(),
                device_did: kotton_crypto::DidKeyMethod::from_public_key(&key),
                public_key: key.to_bytes(),
                paired_at: 0,
                addresses: vec![],
                relay_url: Some("http://relay.test:7700".into()),
                posture: Some("blind-storage".into()),
            },
        }
    }

    /// What an admit records of a vault: its row, its drive, its key on the
    /// allowlist, and its member — all four, so a test can say none is there.
    struct Recorded {
        row: bool,
        drives: i64,
        allowed: bool,
        members: usize,
    }

    async fn recorded(
        db: &std::sync::Arc<sqlx::SqlitePool>,
        paired_keys: &std::sync::Arc<std::sync::RwLock<std::collections::HashSet<[u8; 32]>>>,
        members: &Members,
    ) -> Recorded {
        let key = an_enrolled_vault().node.public_key;
        Recorded {
            row: kotton_peer::daemon::db::paired_node_named(db, "alice", "vault").await.unwrap().is_some(),
            drives: sqlx::query_scalar("SELECT COUNT(*) FROM drives").fetch_one(db.as_ref()).await.unwrap(),
            allowed: paired_keys.read().unwrap().contains(&key),
            members: members.0.lock().unwrap().len(),
        }
    }

    /// **An admit the vault's rule refuses records nothing, and says the
    /// vault's words** (#157). The rule is read before anything is written —
    /// the test's rule looks, and finds no row — and its refusal ends the
    /// admit there: no row, no drive, no key on the allowlist, no member, so
    /// a `PairFailed` never stands beside a row it denies.
    #[tokio::test]
    async fn an_admit_the_vaults_rule_refuses_records_nothing_and_says_the_vaults_words() {
        use std::collections::HashSet;
        use std::sync::{Arc, RwLock};

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(crate::db::open_machine_db(dir.path().join("agent.db")).await.unwrap());
        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        let members = Members::default();
        let secrets = kotton_secret::MemorySecrets::new();
        let refusal = format!("peer did:key:zD {NOT_PAIRED_WITH} 'alice': {}", paired_as_another("sam", "alice"));

        let the_vaults_rule = async {
            let at_the_read = recorded(&db, &paired_keys, &members).await;
            assert!(!at_the_read.row && at_the_read.drives == 0, "the admit wrote before it read the vault's rule");
            Some(refusal.clone())
        };
        let said = super::keep_the_admitted(
            the_vaults_rule,
            &secrets,
            &members,
            &db,
            &paired_keys,
            "alice",
            Posture::BlindStorage,
            an_enrolled_vault(),
        )
        .await
        .expect_err("a vault that refuses this device was kept");

        assert!(said.starts_with("Not admitted"), "{said}");
        assert!(said.contains(&refusal), "the admit does not say the vault's words: {said}");
        assert!(said.contains("Nothing of it was recorded here"), "{said}");
        assert!(said.contains("kvaultd invite alice"), "{said}");
        let after = recorded(&db, &paired_keys, &members).await;
        assert!(!after.row, "a refused admit left the vault's row");
        assert_eq!(after.drives, 0, "a refused admit left a drive");
        assert!(!after.allowed, "a refused admit left the vault's key on the allowlist");
        assert_eq!(after.members, 0, "a refused admit left a member");
    }

    /// The other half: a vault whose rule keeps for this device is recorded
    /// through `finalize_enrolled_node`, after the rule is read — its row, its
    /// drive, its key and its member.
    #[tokio::test]
    async fn an_admit_the_vaults_rule_keeps_is_recorded_after_the_rule_is_read() {
        use std::collections::HashSet;
        use std::sync::{Arc, RwLock};

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(crate::db::open_machine_db(dir.path().join("agent.db")).await.unwrap());
        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        let members = Members::default();
        let secrets = kotton_secret::MemorySecrets::new();

        let the_vaults_rule = async {
            let at_the_read = recorded(&db, &paired_keys, &members).await;
            assert!(!at_the_read.row && at_the_read.drives == 0, "the admit wrote before it read the vault's rule");
            None
        };
        let node = super::keep_the_admitted(
            the_vaults_rule,
            &secrets,
            &members,
            &db,
            &paired_keys,
            "alice",
            Posture::BlindStorage,
            an_enrolled_vault(),
        )
        .await
        .expect("a vault that keeps for this device is recorded");

        assert_eq!(node.public_key, an_enrolled_vault().node.public_key);
        let after = recorded(&db, &paired_keys, &members).await;
        assert!(after.row && after.allowed && after.members > 0, "the vault was not recorded");
        assert_eq!(after.drives, 1, "the vault was not recorded as a drive");
    }
}
