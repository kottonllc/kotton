// SPDX-License-Identifier: AGPL-3.0-or-later
//! Network IPC handlers — peer pairing, sync rules, mounts, ephemeral sessions.
//!
//! Each function maps to one `DeviceRequest` variant of the network layer. All
//! mutations hit the daemon's SQLite DB (tables created by
//! `migrations/0002_v0_3_network.sql`).

use crate::membership::Membership as _;
use kotton_wire::ipc::UserResponse;
use super::db as network_db;
use aes_kw::KekAes256;
use ed25519_dalek::{Signer, SigningKey};
use hex;
use hkdf::Hkdf;
use kotton_sys::secret::SecretsStore;
use kotton_wire::did::Did;
use kotton_wire::peer::{
    EphemeralSession, GuestAccess, MountConfig, PairedNode, SessionPermissions,
};
use kotton_wire::GrantEnvelope;

use kotton_wire::peer::DataKeys;

use kotton_crypto::{derive_cek, derive_master_secret};
use crate::pair_channel::SasConfirmer;
use crate::relay_keys::{FirstContact, Presented, RefusedAtTheRelay, Tier};
use crate::pairing::ed25519_to_x25519_private;
use kotton_schemas::membership::{Ceremony, Member, Posture, Role};
use kotton_schemas::{CapabilityGrant, CapabilityKind};
use kotton_common::crypto::kdf_labels;
use sha2::Sha256;
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::sync::{mpsc, oneshot, Mutex};
use uuid::Uuid;
use x25519_dalek::PublicKey as X25519PublicKey;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

use kotton_common::time::now_secs;

pub fn json_err(e: serde_json::Error) -> io::Error {
    io::Error::other(e.to_string())
}

// ---------------------------------------------------------------------------
// Peer pairing
// ---------------------------------------------------------------------------

/// Insert a peer node by explicit DID, public key, and address.
///
/// Mirrors [`DeviceDaemon::insert_paired_node`] but is accessible over IPC,
/// enabling the demo recipe and the `two_node_transfer` integration test to
/// set up pairing without the full QUIC ceremony.
///
/// `peer_pubkey_hex` must be 64 lowercase hex characters (32 bytes raw Ed25519).
/// The key is inserted into both the `paired_nodes` DB table and the live
/// `paired_keys` mTLS allowlist, so the peer can connect immediately.
///
/// `drive` says the node is a vault the person keeps a drive on — `kotton id
/// recover` says it of the vault its line names — and records the drive, with
/// the row's posture `blind-storage`, through the one writer enrolment uses
/// ([`super::drives::record`]). Without it nothing is recorded but the row:
/// an address and a key say nothing of what a node keeps.
///
/// **What bounds `drive`.** `PeerAdd` is a local verb (`ConnTrustOrigin::Local`),
/// sent on this device's own socket under the person's session, and the same
/// call without `drive` already gives the key a device's standing here
/// (`peer_standing` answers `Paired`, which serves the person's files and
/// sealed objects). Being a drive adds that the device pushes to it what it
/// pushes to a vault — the phrase-sealed recovery copy, the doors it holds for
/// the person, introductions of their other devices — each of which a vault
/// holds without the keys to open, and narrows the node's posture to
/// `blind-storage`. The CLI says it of one key only: the one the recovery line
/// names, after the phrase has proved.
// Allowed: the request's fields plus the two stores it writes, one argument each.
#[allow(clippy::too_many_arguments)]
pub async fn peer_add(
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<[u8; 32]>>>,
    user_id: String,
    label: String,
    peer_did: String,
    peer_pubkey_hex: String,
    peer_addr: SocketAddr,
    drive: bool,
) -> io::Result<UserResponse> {
    let pubkey_bytes = hex::decode(&peer_pubkey_hex)
        .map_err(|e| io::Error::other(format!("peer_pubkey_hex is not valid hex: {e}")))?;
    if pubkey_bytes.len() != 32 {
        return Err(io::Error::other(format!(
            "peer_pubkey_hex must encode exactly 32 bytes, got {}",
            pubkey_bytes.len()
        )));
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&pubkey_bytes);

    let now = now_secs();
    // The label IS the paired_nodes primary key — it must be stable and
    // human-readable so that mount configs (which FK-reference it) and CLI
    // commands that take a node label all resolve to the same row.
    let id = label.clone();
    let addresses_json = serde_json::to_string(&[peer_addr]).map_err(json_err)?;

    // Parse DID for the PairedNode response.
    let device_did_parsed = Did::parse(&peer_did)
        .map_err(|e| io::Error::other(format!("invalid peer_did '{}': {e}", peer_did)))?;

    super::db::insert_paired_node(
        db,
        &id,
        &user_id,
        &peer_did,
        &pubkey,
        &addresses_json,
        now,
        None,
    )
    .await?;
    if drive {
        super::drives::record(db, &user_id, &pubkey).await?;
    }

    // Update live mTLS allowlist.
    paired_keys.write().unwrap().insert(pubkey);

    // The row as it now stands: a posture an earlier pairing projected is kept
    // (`insert_paired_node`), and a drive's is `blind-storage`.
    let node = super::db::get_paired_node_by_id(db, &user_id, &id).await?.unwrap_or(PairedNode {
        id,
        device_did: device_did_parsed,
        public_key: pubkey,
        paired_at: now,
        addresses: vec![peer_addr],
        relay_url: None,
        posture: None,
    });
    Ok(UserResponse::NodePaired { node })
}
///
/// Constructs a `GuestAccessToken` with:
/// - Per-path `GrantEnvelope` grants from `paths` + `permissions`
/// - An `issuer_signature` covering all token fields, signed with the user's
///   Ed25519 identity key (loaded from the OS keychain)
/// - When `guest_ephemeral_pubkey` is `Some(x25519_pubkey)`, `wrapped_deks`
///   is populated with per-path DEKs re-wrapped to the ECDH-derived session
///   key.  When `None`, `wrapped_deks` is empty (backwards-compatible).
// Allowed: the token's fields plus the stores it reads, as `run_enroll_join_relayed` takes them.
#[allow(clippy::too_many_arguments)]
pub async fn pair_node_ephemeral(
    db: &Arc<SqlitePool>,
    sealed_read: &dyn crate::pairing::SealedLocalRead,
    user_id: String,
    _label: String,
    paths: Vec<String>,
    permissions: SessionPermissions,
    ttl_seconds: u64,
    guest_ephemeral_pubkey: Option<[u8; 32]>,
    secrets: &dyn SecretsStore,
) -> io::Result<UserResponse> {
    let now = now_secs();
    let session_id = Uuid::new_v4().to_string();
    let expires_at = now + ttl_seconds as i64;
    let guest_did = Did::new("peer", "pending");
    let guest_did_str = guest_did.to_string();

    // The guest_ephemeral_pubkey stored in GuestAccessToken is the raw X25519
    // public key supplied by the guest (or zeros if not provided).
    let guest_pubkey: [u8; 32] = guest_ephemeral_pubkey.unwrap_or([0u8; 32]);
    let guest_pubkey_blob: Vec<u8> = guest_pubkey.to_vec();

    // Build VFS capability grants from the caller-supplied paths + permissions.
    let grants: Vec<CapabilityGrant> = paths
        .iter()
        .flat_map(|path| {
            let read = CapabilityGrant::vfs(CapabilityKind::Read, path.clone());
            if permissions == SessionPermissions::ReadWrite {
                vec![
                    read,
                    CapabilityGrant::vfs(CapabilityKind::Write, path.clone()),
                ]
            } else {
                vec![read]
            }
        })
        .collect();

    let issuer_did = Did::parse(&user_id).unwrap_or_else(|_| Did::new("key", &user_id));

    // Build the GuestAccessToken and sign it.
    let access = match permissions {
        SessionPermissions::Read => GuestAccess::Read,
        SessionPermissions::ReadWrite => GuestAccess::ReadWrite,
    };

    // Populate wrapped_deks when the guest supplies an X25519 ephemeral pubkey.
    //
    // Protocol:
    //   1. Derive the CEK from the user's seed32.
    //   2. For each requested path, read the raw encrypted blob from "local"
    //      storage and extract the 40-byte AES-KW-wrapped DEK from the header.
    //   3. Unwrap the DEK using the CEK → 32-byte plaintext DEK.
    //   4. Derive a per-session wrapping key:
    //        ECDH(issuer_x25519_private, guest_x25519_public) → shared_secret
    //        HKDF-SHA256(shared_secret, info="kotton:guest-session:v1") → 32B
    //   5. Re-wrap the DEK with the session wrapping key → 40 bytes.
    //   6. Store in wrapped_deks[path].
    //
    // Paths that do not exist in storage are silently skipped.
    let wrapped_deks: HashMap<String, Vec<u8>> =
        if let Some(guest_x25519_bytes) = guest_ephemeral_pubkey {
            // Steps 1+4: resolve the operational CEK, load the signing key,
            // derive the session key.
            match (
                resolve_cek(&user_id, secrets),
                load_signing_key(&user_id, secrets),
            ) {
                (Ok(Some(cek)), Ok(signing_key)) => {
                    let cek_kek = KekAes256::from(cek);

                    // Derive ECDH session wrapping key.
                    let issuer_x25519 = ed25519_to_x25519_private(&signing_key);
                    let guest_x25519 = X25519PublicKey::from(guest_x25519_bytes);
                    let shared_secret = issuer_x25519.diffie_hellman(&guest_x25519);
                    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
                    let mut session_key = [0u8; 32];
                    hk.expand(b"kotton:guest-session:v1", &mut session_key)
                        .expect("HKDF expand is infallible for 32B output");
                    let session_kek = KekAes256::from(session_key);

                    // Step 2+3+5: for each path, read raw blob, extract DEK, re-wrap.
                    let mut deks: HashMap<String, Vec<u8>> = HashMap::new();

                    {
                        for path in &paths {
                            // Read the RAW on-disk blob. The "local" remote is an
                            // EncryptedObjectStorage whose get() would *decrypt* and return
                            // plaintext; we need the raw [wrapped_dek][nonce][ciphertext] to
                            // lift the per-object wrapped-DEK header. (Reading the decrypting
                            // remote is the bug that left wrapped_deks empty.)
                            let raw = match sealed_read.read_sealed_local(path).await {
                                Some(bytes) => bytes,
                                None => continue, // path not found / unreadable — skip
                            };

                            // Blob format: [wrapped_dek: 40B][nonce: 12B][ciphertext+tag]
                            const WRAPPED_DEK_LEN: usize = 40;
                            if raw.len() < WRAPPED_DEK_LEN {
                                continue; // too short — not our format
                            }
                            let wrapped_dek_bytes: [u8; WRAPPED_DEK_LEN] =
                                raw[..WRAPPED_DEK_LEN].try_into().unwrap();

                            // Unwrap the DEK with the CEK.
                            let mut dek = [0u8; 32];
                            if cek_kek.unwrap(&wrapped_dek_bytes, &mut dek).is_err() {
                                continue; // wrong CEK or corrupt blob — skip
                            }

                            // Re-wrap the DEK with the session wrapping key.
                            let mut rewrapped = [0u8; WRAPPED_DEK_LEN];
                            if session_kek.wrap(&dek, &mut rewrapped).is_err() {
                                continue; // shouldn't happen
                            }

                            deks.insert(path.clone(), rewrapped.to_vec());
                        }
                    }
                    deks
                }
                _ => HashMap::new(), // no seed32 / signing key (blind relay or locked) — skip
            }
        } else {
            HashMap::new()
        };

    // Signable bytes: canonical JSON of all fields except issuer_signature.
    // We build a temporary serde_json::Value to get a stable byte sequence.
    let signable = serde_json::json!({
        "paths": paths,
        "access": access,
        "expires_at": expires_at,
        "wrapped_deks": {},
        "guest_ephemeral_pubkey": guest_pubkey,
        "issuer_did": issuer_did.to_string(),
    });
    let signable_bytes = serde_json::to_vec(&signable).map_err(json_err)?;

    // Sign with the user's identity key if available; fall back to empty sig
    // when the identity key is not in the OS keychain (e.g. test environments
    // that don't persist the signing key).
    let issuer_signature: Vec<u8> = match load_signing_key(&user_id, secrets) {
        Ok(signing_key) => signing_key.sign(&signable_bytes).to_bytes().to_vec(),
        Err(_) => Vec::new(),
    };

    let grant = GrantEnvelope {
        id: session_id.clone(),
        issuer_did: issuer_did.clone(),
        subject_did: guest_did.clone(),
        node_did: None,
        grants,
        issued_at: now,
        expires_at: Some(expires_at),
        // Not an app grant: this envelope authorises a paired guest node, and the
        // app binding does not apply.
        app_id: None,
        issuer_signature: hex::encode(&issuer_signature),
    };

    let grant_json = serde_json::to_string(&grant).map_err(json_err)?;

    network_db::insert_ephemeral_session(
        db,
        &session_id,
        &user_id,
        &guest_did_str,
        &guest_pubkey_blob,
        &grant_json,
        now,
    )
    .await?;

    Ok(UserResponse::SessionList {
        sessions: vec![EphemeralSession {
            id: session_id,
            guest_did,
            guest_public_key: guest_pubkey,
            grant,
            issued_at: now,
            revoked: false,
            wrapped_deks,
        }],
    })
}

// ---------------------------------------------------------------------------
// Node list / revoke
// ---------------------------------------------------------------------------

pub async fn node_list(db: &Arc<SqlitePool>, user_id: String) -> io::Result<UserResponse> {
    let nodes = network_db::list_paired_nodes(db, &user_id).await?;
    Ok(UserResponse::NodeList { nodes })
}

pub async fn node_revoke(
    member_store: &dyn crate::membership::MemberStore,
    db: &Arc<SqlitePool>,
    user_id: String,
    node_id: String,
    paired_keys: &Arc<RwLock<HashSet<[u8; 32]>>>,
) -> io::Result<UserResponse> {
    // Fetch the node *before* deleting so we have its DID (to drop the membership
    // record) and public key (to drop the live TLS allowlist entry).
    let node = match network_db::get_paired_node_by_id(db, &user_id, &node_id).await? {
        Some(n) => n,
        None => {
            return Ok(UserResponse::Error {
                message: format!("node '{}' not found for user '{}'", node_id, user_id),
            })
        }
    };

    // Remove the membership record (the source of truth) so every computed
    // view closes — "revoke once, closed everywhere". Best-effort: the live
    // allowlist removal below is what actually blocks connections today, so a
    // membership-cleanup failure is logged, not fatal.
    {
        if let Err(e) = member_store.remove_member(&node.device_did.to_string()).await {
            tracing::warn!(
                user_id = %user_id,
                node_id = %node_id,
                "revoked node but failed to remove its membership record: {e}"
            );
        }
    }

    network_db::delete_paired_node(db, &user_id, &node_id).await?;
    paired_keys.write().unwrap().remove(&node.public_key);
    Ok(UserResponse::NodeRevoked)
}

// ---------------------------------------------------------------------------
// Distributed FROST signing — coordinator side
// ---------------------------------------------------------------------------

/// Coordinate a threshold signature over `message` across this node's own
/// network. This node contributes its own FROST share locally and co-signs with
/// every **Full** own-device member reached over the authenticated peer channel
/// — each runs the `FrostSignRound` responder, so their shares never leave their
/// nodes. Returns the aggregate 64-byte Ed25519 signature, which verifies under
/// the group (identity) DID.
///
/// Co-signers are resolved from the membership set (the source of truth):
/// a paired node is included iff it holds a share — a `Full` or `Cosigner`
/// membership record — which is precisely what excludes a `BlindStorage` (no
/// share) from the quorum.
/// Best-effort refresh of a paired node's stored address after a successful
/// operational connect.
///
/// When the connection came up over a direct/hole-punched path, `observed` is
/// the peer's directly-dialable address; if it differs from the previously
/// stored first address (typically the stale enrollment-bootstrap address), it
/// is persisted so the *next* dial tries the live address first rather than
/// re-timing-out on the dead one. Never fails the caller — the connection has
/// Record the relay a peer said it reserves at, when it differs from what the
/// row holds. Best-effort like the address refresh beside it.
pub async fn refresh_peer_relay(
    db: &Arc<SqlitePool>,
    user_id: &str,
    device_did: &str,
    prev: Option<&str>,
    learned: Option<&str>,
) {
    let Some(relay) = learned else {
        return;
    };
    if Some(relay) == prev {
        return;
    }
    if let Err(e) = network_db::update_paired_node_relay(db, user_id, device_did, Some(relay)).await {
        tracing::warn!(peer = %device_did, error = %e, "failed to record the peer's relay after connect");
    }
}

/// already succeeded, so a write error is logged and swallowed.
pub async fn refresh_observed_peer_address(
    db: &Arc<SqlitePool>,
    user_id: &str,
    device_did: &str,
    prev: Option<SocketAddr>,
    observed: Option<SocketAddr>,
) {
    let Some(addr) = observed else {
        return;
    };
    if Some(addr) == prev {
        return;
    }
    if let Err(e) = network_db::update_paired_node_address(db, user_id, device_did, addr).await {
        tracing::warn!(
            peer = %device_did,
            error = %e,
            "failed to refresh paired-node address after connect",
        );
    }
}

pub async fn threshold_sign(
    // Not the machine handle: this wants a way to dial co-signers and the key
    // domain to declare, not the whole machine. Naming those two is what lets
    // this file live in `peer` at all — a handler that names the runtime type
    // could not, because `peer -> runtime -> device -> peer` is a cycle.
    //
    // The type is deliberately not spelled in this comment: the criterion is
    // checked with `grep -c`, and a mention here would be a false positive.
    dialer: &crate::dialer::Dialer,
    domain_id: Option<String>,
    member_store: &dyn crate::membership::MemberStore,
    db: &Arc<SqlitePool>,
    user_id: String,
    message: Vec<u8>,
    secrets: &dyn SecretsStore,
) -> io::Result<UserResponse> {
    use kotton_org::frost_signing::{
        coordinate_threshold_sign, FrostRound, FrostRoundReply, FrostRoundTrip, FrostSigner,
        LocalFrostSigner, PeerFrostSigner,
    };

    // Resolve Full own-device co-signers from membership, then map each to its
    // paired-node record (for its address) to dial.
    //
    // **First, and refused rather than emptied.** A node restarted and not yet
    // unlocked holds a store with no key, and its membership set cannot be listed.
    // Read with `unwrap_or_default()`, that refusal would become *no
    // co-signers*: nothing dialled, the round failed for want of a quorum, and
    // the person told their other devices were missing when the truth is that
    // this one is locked — the one answer with a remedy they can perform. The
    // store's own refusal says so, and it is passed on whole.
    //
    // It comes before the share is read so that a locked node's answer is the lock
    // and nothing else: it touches no signing material to say it, and says the
    // same whether or not it is enrolled.
    let members = match member_store.list_members().await {
        Ok(members) => members,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: format!("cannot choose who signs with this node: {e:#}"),
            })
        }
    };
    let full_dids: HashSet<String> = members
        .into_iter()
        // Any share-holding member can co-sign: `Full` and `Cosigner` both
        // hold a FROST share. Only `BlindStorage` is excluded.
        .filter(|m| matches!(m.posture, Some(Posture::Full | Posture::Cosigner)))
        .map(|m| m.did)
        .collect();

    // This node's own share + the group public-key package (both persisted at
    // enrollment). Absence means this node is not enrolled in the threshold.
    let local_share = match secrets.get_secret(&kdf_labels::frost_share(&user_id)) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Ok(UserResponse::Error {
                message: "no FROST share on this node — not enrolled in the threshold".to_string(),
            })
        }
        Err(e) => return Err(io::Error::other(format!("keychain read failed: {e}"))),
    };
    let pubkey_package = match secrets.get_secret(&kdf_labels::frost_pubkey_package(&user_id)) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Ok(UserResponse::Error {
                message: "no group public-key package on this node".to_string(),
            })
        }
        Err(e) => return Err(io::Error::other(format!("keychain read failed: {e}"))),
    };

    let mut cosigner_nodes: Vec<PairedNode> = Vec::new();
    for node in network_db::list_paired_nodes(db, &user_id).await? {
        if full_dids.contains(&node.device_did.to_string()) {
            cosigner_nodes.push(node);
        }
    }

    // Open a peer client per co-signer and build a request/response FrostSigner
    // over it. The session id correlates this co-signer's two rounds.
    let mut clients = Vec::new();
    for node in cosigner_nodes {
        let label = node.device_did.to_string();
        let prev_addr = node.addresses.first().copied();
        let prev_relay = node.relay_url.clone();
        match dialer.connect(node, &user_id).await.map(|c| match domain_id.clone() {
            Some(d) => c.with_domain_id(d),
            None => c,
        }) {
            Ok(c) => {
                refresh_observed_peer_address(
                    db,
                    &user_id,
                    &label,
                    prev_addr,
                    c.observed_direct_addr(),
                )
                .await;
                refresh_peer_relay(db, &user_id, &label, prev_relay.as_deref(), c.learned_relay()).await;
                clients.push(Arc::new(c));
            }
            Err(e) => {
                return Ok(UserResponse::Error {
                    message: format!("could not reach co-signer {label}: {e}"),
                })
            }
        }
    }

    let mut peer_signers: Vec<PeerFrostSigner> = Vec::with_capacity(clients.len());
    for (i, client) in clients.iter().enumerate() {
        let client = Arc::clone(client);
        let uid = user_id.clone();
        let round_trip: FrostRoundTrip = Box::new(move |round: FrostRound| {
            let client = Arc::clone(&client);
            let uid = uid.clone();
            Box::pin(async move {
                let payload = serde_json::to_string(&round)
                    .map_err(|e| anyhow::anyhow!("serialize round: {e}"))?;
                let resp = client
                    .send(&kotton_wire::ipc::UserRequest::FrostSignRound {
                        user_id: uid,
                        payload,
                    })
                    .await?;
                match resp {
                    UserResponse::FrostSignReply { payload } => {
                        serde_json::from_str::<FrostRoundReply>(&payload)
                            .map_err(|e| anyhow::anyhow!("parse round reply: {e}"))
                    }
                    UserResponse::Error { message } => {
                        Err(anyhow::anyhow!("co-signer error: {message}"))
                    }
                    other => Err(anyhow::anyhow!("unexpected co-signer response: {other:?}")),
                }
            })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = anyhow::Result<FrostRoundReply>> + Send>,
                >
        });
        peer_signers.push(PeerFrostSigner::new(format!("sign-{i}"), round_trip));
    }

    let local = LocalFrostSigner::new(local_share);
    let mut signers: Vec<&dyn FrostSigner> = vec![&local];
    for ps in &peer_signers {
        signers.push(ps);
    }

    match coordinate_threshold_sign(&signers, &pubkey_package, &message).await {
        Ok(sig) => Ok(UserResponse::ThresholdSigned {
            signature_hex: hex::encode(sig),
        }),
        Err(e) => Ok(UserResponse::Error {
            message: format!("threshold signing failed: {e}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Mounts
// ---------------------------------------------------------------------------

pub async fn mount_path(
    db: &Arc<SqlitePool>,
    user_id: String,
    node_id: String,
    remote_path: String,
    local_path: String,
    cache_budget_bytes: Option<u64>,
    pins: Vec<String>,
) -> io::Result<UserResponse> {
    let now = now_secs();
    let pins_json = serde_json::to_string(&pins).map_err(json_err)?;
    network_db::upsert_mount(
        db,
        &user_id,
        &node_id,
        &remote_path,
        &local_path,
        cache_budget_bytes,
        &pins_json,
        now,
    )
    .await?;
    Ok(UserResponse::Mounted {
        config: MountConfig {
            node_id,
            remote_path,
            local_path,
            cache_budget_bytes,
            pins,
            mounted_at: now,
        },
    })
}

pub async fn mount_list(db: &Arc<SqlitePool>, user_id: String) -> io::Result<UserResponse> {
    let mounts = network_db::list_mounts(db, &user_id).await?;
    Ok(UserResponse::MountList { mounts })
}

pub async fn mount_evict(
    db: &Arc<SqlitePool>,
    user_id: String,
    node_id: String,
    local_path: String,
) -> io::Result<UserResponse> {
    let found = network_db::delete_mount(db, &user_id, &node_id, &local_path).await?;
    if !found {
        return Ok(UserResponse::Error {
            message: format!(
                "mount '{}' (node '{}') not found for user '{}'",
                local_path, node_id, user_id
            ),
        });
    }
    // Cache-eviction byte count is not tracked — always 0.
    Ok(UserResponse::MountEvicted { freed_bytes: 0 })
}

// ---------------------------------------------------------------------------
// Ephemeral sessions
// ---------------------------------------------------------------------------

pub async fn session_list(
    db: &Arc<SqlitePool>,
    user_id: String,
) -> io::Result<UserResponse> {
    let sessions = network_db::list_ephemeral_sessions(db, &user_id).await?;
    Ok(UserResponse::SessionList { sessions })
}

pub async fn session_end(
    db: &Arc<SqlitePool>,
    user_id: String,
    session_id: String,
    revoked_sessions: &Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
) -> io::Result<UserResponse> {
    let found = network_db::revoke_session(db, &user_id, &session_id).await?;
    if !found {
        return Ok(UserResponse::Error {
            message: format!("session '{}' not found for user '{}'", session_id, user_id),
        });
    }
    revoked_sessions.write().unwrap().insert(session_id);
    Ok(UserResponse::SessionEnded)
}

// ---------------------------------------------------------------------------
// NAT / coord handlers
// ---------------------------------------------------------------------------





// ---------------------------------------------------------------------------
// QUIC gateway config
// ---------------------------------------------------------------------------





// ---------------------------------------------------------------------------
// HTTP gateway
// ---------------------------------------------------------------------------








// ---------------------------------------------------------------------------
// Runtime inspection
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// Network status
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// Pairing ceremony
// ---------------------------------------------------------------------------

/// Load the user's Ed25519 identity signing key from the OS keychain.
pub fn load_signing_key(
    user_id: &str,
    secrets: &dyn SecretsStore,
) -> io::Result<SigningKey> {
    let hex_key = secrets
        .get_secret(&kdf_labels::identity_signing_key(user_id))
        .map_err(|e| io::Error::other(format!("keychain read failed: {e}")))?
        .ok_or_else(|| {
            io::Error::other(format!(
                "identity signing key not found for user '{}' — session may be locked",
                user_id
            ))
        })?;
    let key_bytes: [u8; 32] = hex::decode(&hex_key)
        .map_err(|e| io::Error::other(format!("invalid signing key hex: {e}")))?
        .try_into()
        .map_err(|_| io::Error::other("signing key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Load this **device's** operational signing key from the keychain.
///
/// Device-level (not per-user): the same key `DeviceRuntime` resolves at startup
/// and the operational peer listener presents. Using it as the enrollment
/// bootstrap identity makes the pubkey recorded in `paired_nodes` match what the
/// peer's operational listener presents — so an enrolled node is dialable
/// operationally. Persisted at daemon startup, so it is expected to be
/// present.
pub fn load_device_operational_key(secrets: &dyn SecretsStore) -> io::Result<SigningKey> {
    let hex_key = secrets
        .get_secret(&kdf_labels::device_operational_key())
        .map_err(|e| io::Error::other(format!("keychain read failed: {e}")))?
        .ok_or_else(|| io::Error::other("device operational key not found"))?;
    let key_bytes: [u8; 32] = hex::decode(&hex_key)
        .map_err(|e| io::Error::other(format!("invalid operational key hex: {e}")))?
        .try_into()
        .map_err(|_| io::Error::other("operational key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Load the raw `seed32` bytes from the OS keychain for `user_id`.
///
/// Returns `None` if the secret is absent (blind relay or locked session).
pub fn load_seed32_opt(
    user_id: &str,
    secrets: &dyn SecretsStore,
) -> io::Result<Option<[u8; 32]>> {
    let hex_seed = match secrets
        .get_secret(&kdf_labels::seed32_keychain_key(user_id))
        .map_err(|e| io::Error::other(format!("keychain read failed: {e}")))?
    {
        Some(s) => s,
        None => return Ok(None),
    };
    let seed_bytes =
        hex::decode(&hex_seed).map_err(|e| io::Error::other(format!("invalid seed32 hex: {e}")))?;
    if seed_bytes.len() < 32 {
        return Err(io::Error::other("seed32 too short"));
    }
    let mut seed32 = [0u8; 32];
    seed32.copy_from_slice(&seed_bytes[..32]);
    Ok(Some(seed32))
}

/// Whether this node can decrypt `user_id`'s data — i.e. holds a content
/// encryption key. True for the bootstrap device (has `seed32`, from which the CEK
/// derives) **and** for a `Full`-enrolled device (which holds a delivered
/// operational CEK but no seed32). False for blind storage nodes and cosigners, which
/// hold no data keys. Used by the dispatch NoCek guard —
/// keying it on seed32 alone wrongly blocks a Full-joined device from its own data.
pub fn user_has_cek(user_id: &str, secrets: &dyn SecretsStore) -> bool {
    load_seed32_opt(user_id, secrets).unwrap_or(None).is_some()
        || secrets
            .get_secret(&kdf_labels::operational_cek(user_id))
            .unwrap_or(None)
            .is_some()
}

/// Resolve the operational CEK for `user_id`: prefer the stored random
/// `operational_cek`; fall back to the legacy `seed32`-derived CEK.
///
/// A store that could not be read is an error, and the fallback is taken only
/// when the store answered that it holds no operational CEK: taken for absent,
/// an unreadable read fell through to the derivation and answered with a key
/// derived from another root — which a `Full` enrollment then delivered, and the
/// joiner kept.
pub fn resolve_cek(user_id: &str, secrets: &dyn SecretsStore) -> io::Result<Option<[u8; 32]>> {
    resolve_root(user_id, secrets, &kdf_labels::operational_cek(user_id), derive_cek)
}

/// Resolve `master_secret` for `user_id`: prefer the stored random operational
/// root; fall back to deriving it from the legacy `seed32`. Mirrors
/// [`resolve_cek`] — the two roots are stored and recovered the same way, and an
/// unreadable store is an error in both.
fn resolve_master_secret(user_id: &str, secrets: &dyn SecretsStore) -> io::Result<Option<[u8; 32]>> {
    resolve_root(user_id, secrets, &kdf_labels::master_secret_keychain_key(user_id), derive_master_secret)
}

/// One stored root, or its `seed32` derivation when the store holds no copy.
fn resolve_root(
    user_id: &str,
    secrets: &dyn SecretsStore,
    label: &str,
    derive: fn(&[u8; 32]) -> [u8; 32],
) -> io::Result<Option<[u8; 32]>> {
    fn decode32(h: String) -> Option<[u8; 32]> {
        hex::decode(h).ok().and_then(|b| b.try_into().ok())
    }
    if let Some(root) = read_secret(secrets, label)?.and_then(decode32) {
        return Ok(Some(root));
    }
    Ok(read_secret(secrets, &kdf_labels::seed32_keychain_key(user_id))?
        .and_then(decode32)
        .map(|seed| derive(&seed)))
}

/// A label's stored text: `Ok(None)` only when the store answered that it holds
/// none, and the store's error, naming the label, when it could not answer.
fn read_secret(secrets: &dyn SecretsStore, label: &str) -> io::Result<Option<String>> {
    secrets
        .get_secret(label)
        .map_err(|e| io::Error::other(format!("could not read {label} from the secrets store: {e}")))
}

/// Resolve the full **data capability** (the `data` axis) this device can
/// hand to a `Full` joiner: both domain roots plus the CEK epoch.
///
/// `Ok(None)` when *either* root is missing, because half of it is not a posture —
/// a device holding the CEK without `master_secret` reads objects but derives a
/// different `K_log` and cannot open the fleet's record log. Callers enrolling a
/// `Full` device must therefore treat `None` as an error, not as "enroll a
/// cosigner instead" (see [`handle_device_add`]). A store that could not be read
/// is an error, never a capability built from fallbacks.
pub fn resolve_data_keys(user_id: &str, secrets: &dyn SecretsStore) -> io::Result<Option<DataKeys>> {
    let Some(cek) = resolve_cek(user_id, secrets)? else {
        return Ok(None);
    };
    let Some(master_secret) = resolve_master_secret(user_id, secrets)? else {
        return Ok(None);
    };
    // The epoch is metadata about the CEK copy; absent (pre-rotation) it is 0 —
    // absent, not unreadable.
    let cek_epoch = read_secret(secrets, &kdf_labels::operational_cek_epoch(user_id))?
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    Ok(Some(DataKeys {
        cek,
        cek_epoch,
        master_secret,
    }))
}

/// Default warm-key delegation lifetime: 30 days (a TTL-bounded warm key).
pub const WARM_KEY_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Build an `own-device` membership record for a newly enrolled node.
///
/// The posture is the caller's — the one the enrollment ran under, which
/// [`finalize_enrolled_node`] passes through. The label carries the human name
/// the issuer gave the device.
pub fn own_device_member(node: &PairedNode, posture: Posture, added_at: &str) -> Member {
    Member {
        did: node.device_did.to_string(),
        public_key: node.public_key,
        role: Role::OwnDevice,
        admitted_by: Ceremony::DeviceEnroll,
        added_at: added_at.to_string(),
        posture: Some(posture),
        label: Some(node.id.clone()),
        reach: None,
    }
}

/// Record `node` as an `own-device` member of `user_id`'s network — the
/// source of truth the paired-key allowlist, device list, and relay allowlist are
/// computed from.
///
/// Both sides of an enrollment call this so each node's local membership set
/// reflects the relationship immediately (they converge fully once the set
/// syncs). The store handed in must already hold the correct VFS CEK — on the
/// issuer that's true at startup; on the joiner it requires the post-join
/// `reload_user_runtime` refresh first.
///
/// Takes no `user_id`: it existed to resolve the registry and to name the user in
/// an error, and the caller now does the resolving. Which user's store this is,
/// is the store's own business.
pub async fn record_own_device_member(
    member_store: &dyn crate::membership::MemberStore,
    node: &PairedNode,
    posture: Posture,
) -> io::Result<()> {
    let member = own_device_member(node, posture, &chrono::Utc::now().to_rfc3339());

    member_store.write_member(&member).await.map_err(|e| {
        // `{e:#}`, not `{e}`. An `anyhow` error prints only its outermost
        // context by default, so this said "write member did:key:…" and dropped
        // every reason underneath it — which is the half an operator needs and
        // the half that made this failure take three scenario runs to place.
        io::Error::other(format!(
            "node enrolled at the transport layer, but writing its membership record failed: {e:#}"
        ))
    })
}

/// Project the user's membership set into the live mTLS allowlist
/// (`paired_keys`) and the `paired_nodes` cache — **additively**.
///
/// Membership is the source of truth; the paired-key allowlist and `paired_nodes`
/// are computed views, not independently edited. This adds every
/// **own-device** member's key to the live allowlist and ensures a `paired_nodes`
/// cache row exists for it (so it is dialable; an address-less row is filled later
/// by presence/connect). It **never removes a key** — revocation is an explicit
/// act ([`node_revoke`](node_revoke) drops the member and the key together), and a
/// reproject-*with-removal* against a not-yet-synced (incomplete) membership set
/// would wrongly drop legitimately-paired keys (the "revoke-wins /
/// completeness" hazard).
///
/// The one thing it does remove is a `paired_nodes` row for a member who is not an
/// own device — a repair, not a revocation, and safe against an incomplete set
/// because it acts only on members the store actually returned. Best-effort: reading the CEK-encrypted
/// set needs the user's operational CEK, so a locked/CEK-less user is a no-op and
/// the `paired_nodes`-seeded allowlist still stands. Returns the count of keys
/// newly added to the live allowlist.
///
/// An own-device member admitted under `Posture::BlindStorage` — a vault — is
/// also recorded as the person's drive ([`super::drives::record`]), so a device
/// that joined after the vault was enrolled knows the drive.
pub async fn project_membership_into_allowlist(
    member_store: &dyn crate::membership::MemberStore,
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<[u8; 32]>>>,
    user_id: &str,
) -> usize {
    let members = match member_store.list_members().await {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(user_id, error = %e, "membership not readable; allowlist projection skipped");
            return 0;
        }
    };
    let existing_dids: HashSet<String> = network_db::list_paired_nodes(db, user_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|n| n.device_did.to_string())
        .collect();
    let now = chrono::Utc::now().timestamp();
    let mut added = 0usize;
    // Every member, not only the ones the allowlist admits.
    //
    // Not `filter(|m| m.in_paired_key_allowlist())`: that predicate means
    // own-device — a contact has their own door, and the device allowlist gates
    // peer mTLS — so filtering the loop by it would keep contacts out of the
    // repair below. The filter belongs on the allowlist insert, which is the one
    // thing it is about.
    for m in members {
        if m.in_paired_key_allowlist() && paired_keys.write().unwrap().insert(m.public_key) {
            added += 1;
        }
        // Ensure a paired_nodes cache row exists without clobbering learned
        // addresses (keyed by the unique DID; address-less until reachability
        // fills it). Skip members already cached.
        //
        // **Own devices only.** `paired_nodes` is what `peer_standing` reads to
        // answer `PeerStanding::Paired`, and that standing serves `ReadFile`,
        // `ReadSealed`, `ListSealed`, `ApplyRecordChangeset` and `RecoveryFetch`.
        // Caching a contact here hands another person's node a device's reach over
        // the user's data, which contact pairing forbids in as many words:
        // *pairing exchanges authenticated public keys and nothing else.*
        //
        // A contact cached by an earlier build is *removed* here rather than
        // merely not re-added: a fix that only stops writing the row leaves
        // every node that already paired a contact holed after the upgrade.
        if !m.is_own_device() && existing_dids.contains(&m.did) {
            match network_db::delete_paired_node(db, user_id, &m.did).await {
                Ok(true) => tracing::warn!(
                    did = %m.did,
                    "removed a contact from paired_nodes: a contact is admitted to the \
                     handshake, never to a device's standing"
                ),
                Ok(false) => {}
                Err(e) => tracing::warn!(did = %m.did, error = %e, "could not un-cache a contact"),
            }
        }
        if m.is_own_device() && !existing_dids.contains(&m.did) {
            if let Err(e) = network_db::insert_paired_node(
                db,
                &m.did,
                user_id,
                &m.did,
                &m.public_key,
                "[]",
                now,
                m.posture.map(|p| p.as_str()),
            )
            .await
            {
                tracing::warn!(did = %m.did, error = %e, "failed to cache member in paired_nodes");
            }
        }
        // A vault of the person's, as the device that enrolled it wrote it into
        // the membership set: its tenancy is their drive here too. This is how
        // a device that joined after the enrolment — or any device the set
        // reaches before the person tells it where the vault is — comes to know
        // the drive, through the one writer (`super::drives`). Idempotent, so
        // a row this device already holds for the vault is recorded as well.
        if m.is_own_device() && m.posture == Some(Posture::BlindStorage) {
            if let Err(e) = super::drives::record(db, user_id, &m.public_key).await {
                tracing::warn!(did = %m.did, error = %e, "a vault in the membership set was not recorded as a drive");
            }
        }
    }
    added
}

/// Rebuild the live allowlist as the union of the loaded users' contributions.
///
/// The allowlist is the union of per-user contributions, present while the
/// contributing daemon runs. Each loaded user contributes their own
/// `paired_nodes` keys plus whatever their membership set projects; a user who is
/// not loaded contributes nothing, so a peer paired only with a locked user fails
/// the TLS handshake exactly as a never-paired device does.
///
/// **Why this may clear and rebuild when `project_membership_into_allowlist` may
/// not.** That function's no-removal rule guards the completeness hazard:
/// membership *syncs*, so diffing against a set that has not finished syncing
/// would drop legitimately-paired keys. This rebuild does not diff membership. It
/// unions each loaded user's durable local `paired_nodes` rows — which do not
/// depend on a sync having completed — and then lets membership projection add on
/// top, additively, exactly as before. The result is never smaller than the
/// durable pairing record for a loaded user, so the hazard is not reachable here.
///
/// Removal comes from a user ceasing to be loaded, not from a set comparison.
/// That is what makes it safe: the question "is this contribution still live?" is
/// answered by the principal's presence, which is always known accurately, rather
/// than by a view that may still be catching up.
pub async fn reproject_allowlist(
    // The caller enumerates: this rebuilds every loaded user's allowlist, so it
    // needs the set, and `peer` must not learn how residency is tracked.
    users: &[(String, std::sync::Arc<dyn crate::membership::MemberStore>)],
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<[u8; 32]>>>,
) {
    let user_ids: Vec<String> = users.iter().map(|(id, _)| id.clone()).collect();

    // Built aside and swapped in, so the live set is never transiently empty —
    // a handshake landing mid-rebuild must not be refused for a peer that both
    // the old and the new allowlist admit.
    let mut rebuilt: HashSet<[u8; 32]> = HashSet::new();
    // The vault's operator credential, which is no user's row and is admitted at
    // the handshake all the same; what it may say once admitted is its standing
    // (`PeerStanding::Operator`). Empty on a device.
    match network_db::operator_keys(db).await {
        Ok(keys) => rebuilt.extend(keys),
        Err(e) => {
            tracing::warn!(error = %e, "operator_key unreadable; keeping the live keys");
            rebuilt.extend(paired_keys.read().unwrap().iter().copied());
        }
    }
    for uid in &user_ids {
        match network_db::list_paired_nodes(db, uid).await {
            Ok(nodes) => rebuilt.extend(nodes.into_iter().map(|n| n.public_key)),
            Err(e) => {
                // Losing one user's rows would silently unadmit their peers, so
                // keep whatever is live for them rather than narrowing on error.
                tracing::warn!(user_id = %uid, error = %e, "paired_nodes unreadable; keeping the live keys for this user");
                rebuilt.extend(paired_keys.read().unwrap().iter().copied());
            }
        }
    }
    // A row is evidence of a pairing only if its key is one somebody holds the
    // secret half of. A stored row can name a key nobody holds, and the TLS
    // stack accepts a signature under a small-order key that anyone can make,
    // so on the allowlist such a key would admit whoever tried, not nobody.
    rebuilt.retain(a_key_someone_holds);
    *paired_keys.write().unwrap() = rebuilt;

    for (uid, store) in users {
        project_membership_into_allowlist(store.as_ref(), db, paired_keys, uid).await;
    }
}

/// Whether `key` is an Ed25519 key a peer can hold the secret half of: a curve
/// point, and not one of small order (the all-zero encoding is one).
fn a_key_someone_holds(key: &[u8; 32]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(key).is_ok_and(|k| !k.is_weak())
}

/// Project a freshly-enrolled own-device node into the user's live mTLS allowlist
/// (additive) so the two devices can reach each other.
///
/// It does **not** register a data-sync rule. Enrollment is not "copy everything
/// now" — the user's data moves on demand (`kotton sync` / an explicit mount),
/// keeping the user in control of where their data lives (the sovereignty thesis).
/// Membership is recorded directly on both sides at pairing
/// ([`record_own_device_member`]); ongoing membership convergence across a 3+
/// device fleet is on-demand for now (see SYNC-ON-DEMAND idea doc).
///
/// Best-effort: a failure here does not unwind the already-completed enrollment.
pub async fn wire_own_device_allowlist(
    member_store: &dyn crate::membership::MemberStore,
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<[u8; 32]>>>,
    user_id: &str,
    _node: &PairedNode,
) {
    project_membership_into_allowlist(member_store, db, paired_keys, user_id).await;
}

// ---------------------------------------------------------------------------
// Streamed committed-handshake ceremony (device add / device join)
// ---------------------------------------------------------------------------
//
// The user-facing `device add` (issuer) / `device join` (joiner) verbs **stream**
// ceremony state as `UserResponse` frames and run the forward-secret
// committed handshake (`run_enroll_{issuer,join}_committed`). The six-digit SAS is
// surfaced as a `PairShowCode` frame and confirmed via a separate `PairConfirmCode`
// request, which fires a oneshot parked in `PendingConfirms`. Completion goes
// through the shared `finalize_enrolled_node` / `finalize_joined_node` helpers
// below (one source of truth for the membership/allowlist/sync/session wiring).

/// Parked SAS confirmations: `token` → the sender a `PairConfirmCode` request
/// fires with the human's verdict.
pub type PendingConfirms = Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>;

/// Bridges the tier-05 [`SasConfirmer`] seam to the IPC stream: emits a
/// `PairShowCode` frame and blocks on the human's verdict, delivered out-of-band
/// by a `PairConfirmCode` request via [`PendingConfirms`]. A timeout or a dropped
/// stream is treated as a decline — fail safe.
pub struct StreamingConfirmer {
    pub tx: mpsc::Sender<UserResponse>,
    pub token: String,
    pub pending: PendingConfirms,
    pub ttl: std::time::Duration,
}

#[async_trait::async_trait]
impl SasConfirmer for StreamingConfirmer {
    async fn confirm(&self, sas: u32, peer_label: Option<&str>) -> bool {
        let (verdict_tx, verdict_rx) = oneshot::channel::<bool>();
        self.pending
            .lock()
            .await
            .insert(self.token.clone(), verdict_tx);

        if self
            .tx
            .send(UserResponse::PairShowCode {
                token: kotton_wire::ipc::SecretText::new(self.token.clone()),
                sas,
                peer_label: peer_label.map(str::to_string),
            })
            .await
            .is_err()
        {
            self.pending.lock().await.remove(&self.token);
            return false;
        }

        let verdict = matches!(
            tokio::time::timeout(self.ttl, verdict_rx).await,
            Ok(Ok(true))
        );
        self.pending.lock().await.remove(&self.token);
        if verdict {
            let _ = self.tx.send(UserResponse::PairAwaitingPeer).await;
        }
        verdict
    }
}

/// Deliver a human's SAS verdict to a parked ceremony (the `PairConfirmCode`
/// handler). A late/duplicate/unknown token is a no-op, not an error.
pub async fn confirm_code(
    pending: &PendingConfirms,
    token: String,
    matches: bool,
) -> io::Result<UserResponse> {
    if let Some(sender) = pending.lock().await.remove(&token) {
        let _ = sender.send(matches);
    }
    Ok(UserResponse::PairConfirmAck)
}

/// What a person is told when a ceremony fails: a relay's refusal at its door
/// ([`RefusedAtTheRelay`]) as what this device presented there, and every other
/// failure as [`ceremony_failure_copy`] reads it.
pub fn ceremony_failure(err: &anyhow::Error) -> String {
    match err.downcast_ref::<RefusedAtTheRelay>() {
        Some(refused) => refused_at_the_relay_copy(refused),
        None => ceremony_failure_copy(&err.to_string()),
    }
}

/// What a person is told when a relay refused, at its door, what this device
/// presented on a first contact: which relay, what this device presented there
/// (from its own knowledge — the relay says nothing past its `403`), and which
/// invite admits it there. Never what the relay's rule is: a `403` is an
/// unsigned HTTP answer that anything in front of the relay could give as well
/// (decision 0006). Never *try again*, which the same code would meet the same
/// way.
pub fn refused_at_the_relay_copy(refused: &RefusedAtTheRelay) -> String {
    let url = &refused.url;
    let presented = match (refused.presented, refused.meeting) {
        (Presented::Nothing, FirstContact::VaultInvite) => format!(
            "The relay at {url} refused this device: it presented no key there — the invite carried none, and this \
             device presents none of its own at an address the invite supplied."
        ),
        (Presented::Nothing, FirstContact::SpokenCode) => format!(
            "The relay at {url}, where this device stands, refused it: this device presented no key there."
        ),
        (Presented::Handed, _) => format!("The relay at {url} refused the key the invite carries for it."),
        (Presented::Held(Tier::Invited), _) => format!(
            "The relay at {url} refused the key this device presented there as one of the people its operator \
             invites."
        ),
        (Presented::Held(Tier::LearnedMine), _) => format!(
            "The relay at {url} refused the key of its operator's own devices, which this device learned from \
             another of yours."
        ),
        (Presented::Held(Tier::KeptMine), _) => format!(
            "The relay at {url} refused the key this device presented there as its operator, the one your \
             operator credential for it names."
        ),
    };
    let admits = match (refused.presented, refused.meeting) {
        (Presented::Nothing, FirstContact::VaultInvite) => {
            "The invite that admits its holder there is the vault's invite as it was minted, which carries the \
             relay's key: ask for it again, whole."
        }
        (Presented::Nothing, FirstContact::SpokenCode) => {
            "The invite that admits this device there is the relay's own, from whoever operates it: stand there \
             with it (`relay set <invite>`), then pair."
        }
        (Presented::Handed, _) => {
            "That key may no longer be the relay's: ask the vault's landlord for a new invite."
        }
        (Presented::Held(Tier::Invited), _) => {
            "That key may no longer be the relay's: ask whoever operates it for a new relay invite, and stand there \
             with it (`relay set <invite>`)."
        }
        (Presented::Held(Tier::LearnedMine), _) => {
            "That key may no longer be the relay's: this device learns the current one from your device that \
             operates the relay, at its next connect to it."
        }
        (Presented::Held(Tier::KeptMine), _) => {
            "That happens when the relay was started over without this credential, or when something in front of \
             the relay answers for it: check the host before doing anything here."
        }
    };
    format!("{presented} Nothing was shared. {admits}")
}

/// Map a ceremony error to calm, specific failure copy for `PairFailed`.
pub fn ceremony_failure_copy(err: &str) -> String {
    let e = err.to_lowercase();
    if e.contains("codes did not match") || e.contains("cancelled") {
        // The one genuinely dangerous branch earns serious wording.
        "The codes don't match. Nothing was shared. This can mean someone on this \
         network interfered — try again on a network you trust."
            .to_string()
    } else if e.contains("commitment mismatch") {
        "The handshake was tampered with. Nothing was shared. Try again on a network \
         you trust."
            .to_string()
    } else if e.contains("attestation") {
        "Couldn't verify the other device's identity. Nothing was shared. Try again \
         on a network you trust."
            .to_string()
    } else if e.contains("timed out") || e.contains("timeout") {
        "The pairing window closed. Run add-device again when both machines are ready.".to_string()
    } else {
        "Lost the connection before anything was shared. Try again.".to_string()
    }
}

/// Persist an issuer-side enrollment outcome (the `device add` completion): the
/// retained FROST share + group key, the paired-node record + live allowlist, and
/// the own-device membership + sync wiring.
///
/// The single issuer-completion path for the pairing ceremony.
pub async fn finalize_enrolled_node(
    secrets: &dyn SecretsStore,
    member_store: &dyn crate::membership::MemberStore,
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<[u8; 32]>>>,
    user_id: &str,
    posture: Posture,
    enrolled: crate::pairing::EnrolledNode,
) -> io::Result<PairedNode> {
    // Full/Cosigner: persist the issuer's retained 2-of-2 share + group key. Blind
    // retains nothing.
    if let Some((issuer_share, _root_did)) = &enrolled.issuer_share {
        secrets
            .set_secret(&kdf_labels::frost_share(user_id), &issuer_share.0)
            .map_err(|e| io::Error::other(format!("persist issuer FROST share: {e}")))?;
    }
    if let Some(pkg) = &enrolled.pubkey_package {
        secrets
            .set_secret(&kdf_labels::frost_pubkey_package(user_id), pkg)
            .map_err(|e| io::Error::other(format!("persist group public-key package: {e}")))?;
    }

    let node = enrolled.node;
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
        Some(posture.as_str()),
    )
    .await?;
    // The relay the peer said it reserves at, when the ceremony learned one
    // (the relayed transport does; a peer reached on a socket said nothing
    // and is asked at the first connect). Without this a vault
    // admitted through its relay has no address *and* no relay on the row —
    // paired, and unreachable.
    if let Some(relay) = node.relay_url.as_deref() {
        network_db::update_paired_node_relay(db, user_id, &node.device_did.to_string(), Some(relay)).await?;
    }
    // A vault admitted blind keeps the person's things: its tenancy is a drive,
    // recorded as one here, as `recover` records the vault it is pointed at
    // (`super::drives`).
    if posture == Posture::BlindStorage {
        super::drives::record(db, user_id, &node.public_key).await?;
    }
    paired_keys.write().unwrap().insert(node.public_key);

    // The issuer's VFS CEK is correct at startup, so membership is written under
    // the right key with no reload (unlike the joiner).
    record_own_device_member(member_store, &node, posture).await?;
    wire_own_device_allowlist(member_store, db, paired_keys, user_id, &node).await;
    Ok(node)
}




#[cfg(test)]
mod refusal_copy {
    use super::*;

    fn refused(presented: Presented, meeting: FirstContact) -> anyhow::Error {
        RefusedAtTheRelay { url: "http://relay.test:7700".into(), presented, meeting }.into()
    }

    /// **A relay's refusal is said as what this device presented, and which
    /// invite admits it** — never as a lost connection, which sends a person to
    /// try the same code again, and never as the relay's rule, which a `403`
    /// does not prove.
    #[test]
    fn a_refusal_at_the_relay_is_said_as_what_was_presented_and_which_invite_admits_it() {
        let said = ceremony_failure(&refused(Presented::Nothing, FirstContact::VaultInvite));
        assert!(said.starts_with("The relay at http://relay.test:7700 refused this device"), "{said}");
        assert!(said.contains("presented no key there"), "{said}");
        assert!(said.contains("the vault's invite as it was minted"), "{said}");

        let said = ceremony_failure(&refused(Presented::Nothing, FirstContact::SpokenCode));
        assert!(said.contains("presented no key there") && said.contains("`relay set <invite>`"), "{said}");

        let said = ceremony_failure(&refused(Presented::Handed, FirstContact::VaultInvite));
        assert!(said.contains("refused the key the invite carries") && said.contains("new invite"), "{said}");

        let said = ceremony_failure(&refused(Presented::Held(Tier::Invited), FirstContact::SpokenCode));
        assert!(said.contains("people its operator invites") && said.contains("new relay invite"), "{said}");

        for presented in [
            Presented::Nothing,
            Presented::Handed,
            Presented::Held(Tier::Invited),
            Presented::Held(Tier::LearnedMine),
            Presented::Held(Tier::KeptMine),
        ] {
            for meeting in [FirstContact::VaultInvite, FirstContact::SpokenCode] {
                let said = ceremony_failure(&refused(presented, meeting));
                assert!(said.contains("refused") && said.contains("Nothing was shared."), "{said}");
                assert!(!said.contains("Lost the connection") && !said.contains("Try again"), "{said}");
                assert!(!said.contains("rule"), "a 403 was said as the relay's rule: {said}");
                assert!(!said.contains("holds"), "a refusal said what this device holds, not what it presented: {said}");
                assert!(!said.contains("forget"), "a refusal sent the person to drop a credential: {said}");
            }
        }
    }

    /// Every other failure reads as it did.
    #[test]
    fn any_other_failure_reads_as_before() {
        let lost = anyhow::anyhow!("nobody is waiting on that code at this relay (Connection failed: 404)");
        assert_eq!(ceremony_failure(&lost), "Lost the connection before anything was shared. Try again.");
    }
}

#[cfg(test)]
mod allowlist_rebuild {
    use super::*;
    use crate::membership::MemberStore;

    /// Holds no members: the rebuild under test reads `paired_nodes`, and
    /// membership projection is not what this asserts.
    struct NoMembers;

    #[async_trait::async_trait]
    impl MemberStore for NoMembers {
        async fn member_write(&self, _: &str, _: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        async fn member_read(&self, path: &str) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("no member at {path}")
        }
        async fn member_delete(&self, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn member_list(&self, _: &str) -> anyhow::Result<Vec<String>> {
            Ok(Vec::new())
        }
    }

    /// **The allowlist a daemon rebuilds from its store holds no key nobody
    /// holds.** A store can still carry an all-zero row: one written by the
    /// placeholder pairing verb this crate no longer has, which an existing
    /// database keeps, or one `peer_add` was handed. The rebuild admits the
    /// real peer beside it and not the zero key.
    #[tokio::test]
    async fn the_rebuilt_allowlist_holds_no_all_zero_key() {
        let dir = tempfile::tempdir().unwrap();
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("agent.db"))
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::migrate!("../device/migrations").run(&pool).await.unwrap();
        let db = Arc::new(pool);

        let real = SigningKey::from_bytes(&[11u8; 32]).verifying_key().to_bytes();
        for (id, did, key) in [
            ("laptop", "did:peer:laptop", real),
            ("my-vps", "did:peer:my-vps", [0u8; 32]),
        ] {
            network_db::insert_paired_node(&db, id, "alice", did, &key, "[]", 0, None)
                .await
                .unwrap();
        }

        // The live set starts with the zero key in it, as a daemon that loaded
        // such a row before this rebuild would hold it.
        let paired_keys = Arc::new(RwLock::new(HashSet::from([[0u8; 32]])));
        let users: Vec<(String, Arc<dyn MemberStore>)> =
            vec![("alice".to_string(), Arc::new(NoMembers))];
        reproject_allowlist(&users, &db, &paired_keys).await;

        let live = paired_keys.read().unwrap().clone();
        assert!(live.contains(&real), "the real peer's row must still be admitted");
        assert!(
            !live.contains(&[0u8; 32]),
            "the rebuilt allowlist admitted the all-zero key"
        );
    }
}
