// SPDX-License-Identifier: AGPL-3.0-or-later
//! Contact pairing **ceremony entry points**, the person-to-person
//! counterpart of [`super::pairing`].
//!
//! Both verbs stream, and their type is the stream (see [`super::pairing`]
//! for why a refusal here cannot be one frame left open). Each builds this
//! user's identity as the other side will see it, runs
//! [`kotton_peer::contact_pairing`] over the node's relay, and on the human's
//! yes writes what came back: one `contact` member (a key that may be
//! messaged, and nothing else) and the contact's key log beside it. A delivery from them reaches the pair's own door, which the
//! mailbox registry opens from that member; the device allowlist is not theirs
//! to be on.

use crate::users::DeviceUsers as _;
use crate::DeviceRuntime;
use kotton_common::time::now_secs;
use kotton_peer::contact_pairing::{self, ContactIdentity, PairedContact};
use kotton_peer::daemon::nodes::{ceremony_failure, load_signing_key, PendingConfirms, StreamingConfirmer};
use kotton_peer::membership::Membership as _;
use kotton_schemas::membership::{Ceremony, Member, Role};
use kotton_wire::ipc::UserResponse;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;

/// The two ends of the ceremony share everything but who waits.
#[derive(Clone, Copy)]
enum Side {
    Start,
    Join,
}

/// Which relay this node meets strangers at. A node with no relay cannot be
/// found by one, and says so rather than waiting for nothing.
fn relay_url_of(runtime: &DeviceRuntime) -> io::Result<String> {
    let url = runtime.reachability().nat().relay_url;
    if url.trim().is_empty() {
        return Err(io::Error::other(
            "no relay is configured, so there is nowhere for the other person to find this \
             node — set one (`relay set`) and try again",
        ));
    }
    Ok(url)
}

/// This user, as the other side will see them — with the reach note their
/// card will start from, signed now if the one held no longer says it.
async fn own_identity(
    runtime: &DeviceRuntime,
    users: &dyn crate::users::residency::Residency,
    user_id: &str,
    as_name: Option<String>,
) -> io::Result<(ContactIdentity, ed25519_dalek::SigningKey)> {
    let aid = runtime
        .user_aid(user_id)
        .ok_or_else(|| io::Error::other(format!("no identity for '{user_id}' on this device")))?;
    let key = load_signing_key(user_id, runtime.secrets())?;
    let public_key = key.verifying_key().to_bytes();
    let kel = kotton_identity::kel_store::load_chain(runtime.base_dir(), user_id).unwrap_or_default();
    if let Some(current) = runtime.user_current_key(user_id) {
        if current != public_key {
            return Err(io::Error::other(
                "this device's identity key is not the one the key log resolves to — rotate or \
                 recover before pairing",
            ));
        }
    }
    // Nowhere to be found is refused before a note is signed that says so.
    relay_url_of(runtime)?;
    let store = users
        .get(user_id)
        .ok_or_else(|| io::Error::other(format!("user runtime '{user_id}' is not loaded")))?;
    let (reach, signed_now) =
        crate::users::reach::current_note(runtime, store.as_ref(), user_id, now_secs() as u64).await?;
    if signed_now {
        // Everyone else this person knows is owed it too; the reach keeper
        // sends it to each contact that has not acknowledged it.
        runtime.reach_changed().notify_one();
    }
    Ok((
        ContactIdentity {
            aid,
            public_key,
            display_name: as_name.unwrap_or_else(|| user_id.to_string()),
            reach,
            kel,
        },
        key,
    ))
}

/// Write what the ceremony authenticated: the member and their key log.
///
/// **Not** their key into this device's peer allowlist. A contact reaches this
/// node at their own door, one per pair, whose verifier admits the pair's key and
/// nothing else; the allowlist is the device door, and on it a
/// contact would stand as a stranger at a door they have no business at. The
/// projection that rebuilds the allowlist at start admits own devices only
/// (`Member::in_paired_key_allowlist`), and nothing here puts the key back.
/// Holding it would also make the relay listener keep two device reservations
/// for the contact beside their two doors, so a test's "two reservations are up"
/// would mean "a door may not be", and a reply sent at once could find no door
/// open for it.
async fn admit(
    runtime: &DeviceRuntime,
    users: &dyn crate::users::residency::Residency,
    user_id: &str,
    contact: &PairedContact,
) -> io::Result<()> {
    let user_rt = users
        .get(user_id)
        .ok_or_else(|| io::Error::other(format!("user runtime '{user_id}' is not loaded")))?;
    let member = Member {
        did: contact.did.clone(),
        public_key: contact.public_key,
        role: Role::Contact,
        admitted_by: Ceremony::Pairing,
        added_at: chrono::Utc::now().to_rfc3339(),
        posture: None,
        label: Some(contact.label.clone()),
        // The ceremony held it to their key already; the card starts here.
        reach: Some(contact.reach.clone()),
    };
    user_rt.write_member(&member).await.map_err(io::Error::other)?;
    if !contact.kel.is_empty() {
        kotton_identity::kel_store::save_contact_chain(runtime.base_dir(), user_id, &contact.did, &contact.kel)
            .map_err(io::Error::other)?;
    }
    // The mailbox this pair will use is opened by whoever keeps the registry;
    // membership is what it reads, so it only needs telling that
    // membership moved.
    // `notify_one`, not `notify_waiters`: the latter wakes whoever is waiting
    // *now* and is otherwise dropped, so a pairing that finished while the
    // registry was mid-rebuild would open no mailbox until the next one. This
    // leaves a permit, and the rebuild is whole-set anyway.
    runtime.contacts_changed().notify_one();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run(
    side: Side,
    runtime: Arc<DeviceRuntime>,
    users: Arc<dyn crate::users::residency::Residency>,
    pending: PendingConfirms,
    user_id: String,
    as_name: Option<String>,
    code: Option<String>,
    ttl_seconds: u64,
) -> io::Result<mpsc::Receiver<UserResponse>> {
    let (ours, key) = own_identity(&runtime, users.as_ref(), &user_id, as_name).await?;
    // The ceremony meets at this node's relay; the note is what the other
    // side's card keeps.
    let relay_url = relay_url_of(&runtime)?;
    // The key this device presents at its own relay, if it holds one, and
    // what it is — said when the relay refuses it.
    let admission = runtime.reachability().presenting_at_own_relay();
    let code = match (side, code) {
        (Side::Start, _) => contact_pairing::generate_code(),
        (Side::Join, Some(c)) => contact_pairing::normalize_code(&c),
        (Side::Join, None) => return Err(io::Error::other("a code is needed to join")),
    };
    let (tx, rx) = mpsc::channel::<UserResponse>(16);
    tokio::spawn(async move {
        let opening = match side {
            Side::Start => UserResponse::PairAdvertising {
                code: kotton_wire::ipc::SecretText::new(code.clone()),
                expires_at: (now_secs() as u64).saturating_add(ttl_seconds),
            },
            Side::Join => UserResponse::PairConnecting,
        };
        if tx.send(opening).await.is_err() {
            return;
        }
        let confirmer = StreamingConfirmer {
            tx: tx.clone(),
            token: Uuid::new_v4().to_string(),
            pending,
            ttl: Duration::from_secs(ttl_seconds),
        };
        // The ceremony has its own windows (the wait for a joiner, the dial, the
        // human's verdict); this is the hard ceiling over all of them, so a peer
        // that stalls mid-handshake cannot hold a ceremony task open forever.
        let ceiling = Duration::from_secs(ttl_seconds.saturating_add(30));
        let result = match side {
            Side::Start => {
                tokio::time::timeout(
                    ceiling,
                    contact_pairing::run_issuer(
                        &relay_url,
                        &code,
                        &ours,
                        &key,
                        &confirmer,
                        Duration::from_secs(ttl_seconds),
                        &admission,
                    ),
                )
                .await
            }
            Side::Join => {
                tokio::time::timeout(
                    ceiling,
                    contact_pairing::run_joiner(&relay_url, &code, &ours, &key, &confirmer, &admission),
                )
                .await
            }
        }
        .unwrap_or_else(|_| Err(anyhow::anyhow!("the ceremony did not finish in time")));
        let frame = match result {
            Ok(contact) => match admit(&runtime, users.as_ref(), &user_id, &contact).await {
                Ok(()) => UserResponse::ContactPaired {
                    did: contact.did,
                    label: contact.label,
                },
                Err(e) => UserResponse::PairFailed {
                    reason: format!("Paired, but saving the contact failed: {e}"),
                },
            },
            Err(e) => {
                tracing::warn!(error = %e, "contact pairing failed");
                UserResponse::PairFailed {
                    reason: ceremony_failure(&e),
                }
            }
        };
        let _ = tx.send(frame).await;
    });
    Ok(rx)
}

/// `ContactPairStart`: print a code and wait for the other person.
pub async fn handle_contact_pair_start(
    runtime: Arc<DeviceRuntime>,
    users: Arc<dyn crate::users::residency::Residency>,
    pending: PendingConfirms,
    user_id: String,
    as_name: Option<String>,
    ttl_seconds: u64,
) -> io::Result<mpsc::Receiver<UserResponse>> {
    run(Side::Start, runtime, users, pending, user_id, as_name, None, ttl_seconds).await
}

/// `ContactPairJoin`: reach the other person by their code.
pub async fn handle_contact_pair_join(
    runtime: Arc<DeviceRuntime>,
    users: Arc<dyn crate::users::residency::Residency>,
    pending: PendingConfirms,
    user_id: String,
    code: String,
    as_name: Option<String>,
) -> io::Result<mpsc::Receiver<UserResponse>> {
    // The joiner's wait is the SAS dialog; the dial itself has its own window.
    run(Side::Join, runtime, users, pending, user_id, as_name, Some(code), 180).await
}
