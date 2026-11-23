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
use crate::pairing::{JoinNotKept, NotHanded, RefusedBeforeHanding};
use kotton_crypto::x25519::ed25519_priv_to_x25519;
use kotton_crypto::ed25519::VerifyingKey;
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
/// `peer_pubkey_hex` must be 64 lowercase hex characters (32 bytes raw Ed25519),
/// and `peer_did` the `did:key` of that key, as
/// [`kotton_crypto::DidKeyMethod::from_public_key`] makes it; any other string,
/// another spelling of the key's `did:key` included, is refused, and nothing
/// is written. The row is the store's to name ([`super::db::insert_paired_node`]):
/// where the person already has a row for the key, that row is rewritten with
/// this label and address under its DID as stored, and no second row is added.
/// The key is inserted into both the `paired_nodes` DB table and the live
/// `paired_keys` mTLS allowlist, so the peer can connect immediately.
///
/// **It records a row, never a drive.** An address and a key say nothing of
/// what a node keeps, so a node added here is no drive until something that
/// names a vault records it ([`super::drives`]): enrolment, the daemon's
/// `Recover` after the proof, the membership projection, or the join
/// (`record_handed_drives` in `kotton_device::users::pairing`). The `drive` flag
/// that let a local session record any key as a drive went with #80.
pub async fn peer_add(
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<VerifyingKey>>>,
    user_id: String,
    label: String,
    peer_did: String,
    peer_pubkey_hex: String,
    peer_addr: SocketAddr,
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
    let key = VerifyingKey::from_bytes(&pubkey)
        .map_err(|e| io::Error::other(format!("peer_pubkey_hex is not an Ed25519 key: {e}")))?;

    let now = now_secs();
    // The label is what the person reads and names the node by; the row is
    // keyed by the person and the DID (`super::db`), so a label another row of
    // theirs already carries is shown on both, and replaces neither.
    let id = label.clone();
    let addresses_json = serde_json::to_string(&[peer_addr]).map_err(json_err)?;

    // A typed DID that is not the key's derivation is refused, and nothing is
    // written: the person said two things of one node that do not agree, and
    // neither is taken (kottonllc/kotton#597, 28A). The writer takes the key
    // alone, so the string is checked here and stored nowhere.
    let device_did_parsed = kotton_crypto::DidKeyMethod::from_public_key(&key);
    if peer_did != device_did_parsed.to_string() {
        return Err(io::Error::other(format!(
            "<did> '{peer_did}' is not the did:key of <pubkey-hex>; that key's is \
             '{device_did_parsed}', and nothing was added"
        )));
    }

    // The writer names the row: a row the person has for the key is rewritten
    // under its DID as stored, and a new one is written under the key's
    // derivation, which is the DID checked above (kottonllc/kotton#597, 27A,
    // 30A). A posture an earlier pairing projected is kept.
    let node = super::db::insert_paired_node(db, &id, &user_id, &key, &addresses_json, now, None).await?;

    // Update live mTLS allowlist.
    paired_keys.write().unwrap().insert(key);
    Ok(UserResponse::NodePaired { node })
}

/// Point the row `user_id` already pairs for `public_key` at `peer_addr`: what the
/// daemon's `Recover` runs for a line whose vault the person pairs at another
/// address (`kotton_device::users::recover`). `Ok(None)`, with nothing written,
/// when no row of theirs holds the key.
///
/// **A row that stands is re-addressed by its bytes, whatever DID is stored
/// beside them** (kottonllc/kotton#597, 5B). Unlike [`peer_add`], which adds a
/// row and so holds the DID it is given to the key's derivation, this adds no
/// row and reads no DID: the row keeps its DID as stored, its label, its posture
/// and its relay, and only its address and the time it was paired change
/// ([`super::db::readdress_paired_node_for_key`]). The key goes on the live
/// allowlist, as `peer add` puts it there. Bytes the Ed25519 rule refuses are no
/// key, so no row under them is re-addressed or admitted.
pub async fn peer_readdress(
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<VerifyingKey>>>,
    user_id: &str,
    public_key: &[u8; 32],
    peer_addr: SocketAddr,
) -> io::Result<Option<PairedNode>> {
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| io::Error::other(format!("the key is not an Ed25519 key: {e}")))?;
    let addresses_json = serde_json::to_string(&[peer_addr]).map_err(json_err)?;
    let Some(node) =
        network_db::readdress_paired_node_for_key(db, user_id, public_key, &addresses_json, now_secs()).await?
    else {
        return Ok(None);
    };
    paired_keys.write().unwrap().insert(key);
    Ok(Some(node))
}

/// Take back a node row that a request added and nothing has used since: the
/// row, and its key from the live allowlist unless another row on this
/// machine (another person's, say, who keeps a drive on the same vault) still
/// pairs it. What the daemon's `Recover` runs when the words are refused, for
/// the node it added for the line (`kotton_device::users::recover`).
///
/// Unlike a revoke ([`revoke_named`]) it touches no membership record: a node added by
/// address was never a member, and the person's set may not be open here.
/// The node is named by its DID, the row's key: the label it was added under
/// may be another row's too.
pub async fn take_back_added(
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<VerifyingKey>>>,
    user_id: &str,
    device_did: &str,
) -> io::Result<()> {
    let Some(node) = network_db::get_paired_node(db, user_id, device_did).await? else {
        return Ok(());
    };
    network_db::delete_paired_node(db, user_id, device_did).await?;
    if !still_paired(db, &node.public_key).await? {
        unadmit(paired_keys, &node.public_key);
    }
    Ok(())
}

/// Take `key` off the live allowlist. Bytes the Ed25519 rule refuses are no key, so they
/// were never on it.
fn unadmit(paired_keys: &RwLock<HashSet<VerifyingKey>>, key: &[u8; 32]) {
    if let Ok(key) = VerifyingKey::from_bytes(key) {
        paired_keys.write().unwrap().remove(&key);
    }
}

/// Whether any row on this machine, any person's, still pairs `key`: the live
/// allowlist is the machine's, so a key leaves it with its last row.
async fn still_paired(db: &Arc<SqlitePool>, key: &[u8; 32]) -> io::Result<bool> {
    let row: Option<i64> = sqlx::query_scalar("SELECT 1 FROM paired_nodes WHERE public_key = ? LIMIT 1")
        .bind(key.as_slice())
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(row.is_some())
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
                    let issuer_x25519 = ed25519_priv_to_x25519(&signing_key);
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

/// Every node `user_id` has paired, and beside them a note for each row that
/// names no key or stands by its bytes under another spelling
/// ([`network_db::notes_of`]).
///
/// `members` is the person's set, handed in only for an answer given at the
/// machine: kottonllc/kotton#610 has such a note "carried only in an answer to
/// the person whose set it is, on their own device".
/// With it, the answer also carries a note for each DID as stored that
/// own-device members of the set carry whose bytes are no key and that no row
/// stands for ([`member_notes`]): the one thing such a member is reached by is
/// `device revoke`, which resolves it for a local asker only ([`node_named`]). Without
/// it, as for every remote asker, each note says only what its row in the
/// answer already does. A set that cannot be read adds no note, and the rows are
/// listed as ever.
pub async fn node_list(
    db: &Arc<SqlitePool>,
    user_id: String,
    members: Option<&dyn crate::membership::MemberStore>,
) -> io::Result<UserResponse> {
    let nodes = network_db::list_paired_nodes(db, &user_id).await?;
    let mut notes = network_db::notes_of(&nodes);
    if let Some(store) = members {
        match store.list_found().await {
            Ok(found) => notes.extend(member_notes(&nodes, &found)),
            Err(e) => tracing::debug!(user_id, error = %e, "membership not readable; no member is noted"),
        }
    }
    Ok(UserResponse::NodeList { nodes, notes })
}

/// The own-device members of `found`, the set's own listing, that no row of
/// `rows`, the person's, holds the key of: a row is its bytes' and stands for
/// the member that holds them (kottonllc/kotton#597, 5B), so these are the
/// members no row stands for. Contacts and relays are never among them.
pub fn members_with_no_row(rows: &[PairedNode], found: Vec<crate::membership::Found>) -> Vec<crate::membership::Found> {
    found
        .into_iter()
        .filter(|f| f.member.is_own_device())
        .filter(|f| !rows.iter().any(|r| r.public_key == f.member.public_key))
        .collect()
}

/// A note for each DID as stored that own-device members of `found` carry whose
/// bytes the Ed25519 rule refuses and that no row of `rows` stands for
/// ([`members_with_no_row`]), named by that DID: the name `device revoke` takes
/// to them ([`node_named`]). The name is noted once however many members carry
/// it, since the one revoke by it removes every one of them
/// (kottonllc/kotton#597, 35A). A member whose DID as stored a row also
/// carries, as its DID or its label, is not noted: the resolver takes that name
/// to the row first, so a command printed with it would reach the row and not
/// the member (20A; 36A).
pub fn member_notes(rows: &[PairedNode], found: &[crate::membership::Found]) -> Vec<kotton_wire::note::RowNote> {
    let mut named: Vec<String> = Vec::new();
    for f in members_with_no_row(rows, found.to_vec())
        .into_iter()
        .filter(|f| VerifyingKey::from_bytes(&f.member.public_key).is_err())
        .filter(|f| !rows.iter().any(|r| r.id == f.member.did || r.device_did.to_string() == f.member.did))
    {
        if !named.contains(&f.member.did) {
            named.push(f.member.did);
        }
    }
    named.into_iter().map(kotton_wire::note::RowNote::names_no_key).collect()
}

/// What a name a person typed may reach ([`node_named`]).
pub enum Reach<'a> {
    /// The person's `paired_nodes` rows, and nothing else: what a remote asker
    /// reaches with `device revoke`.
    Rows,
    /// The rows, and where no row carries the name, an own-device member of this
    /// set that no row stands for ([`members_with_no_row`]), by its DID as stored.
    RowsAndMembers(&'a dyn crate::membership::MemberStore),
    /// The person's rows that the drive record names, one per node
    /// ([`super::drives::nodes`]), and nothing else: what a verb whose noun is a
    /// drive reaches, `remote add` and `sync` (kottonllc/kotton#597, 37A). A
    /// device is not in reach, so a drive is named by its label whatever a
    /// device carries.
    Drives,
}

/// Who asked for a revoke, for what it may reach ([`Asked::reach`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    /// At the machine, on the person's own device (`ConnTrustOrigin::Local`):
    /// a row, or an own-device member of their set with no row.
    Locally,
    /// By anyone else: a row of the person's and that row's members, as before
    /// (kottonllc/kotton#610).
    Remotely,
}

impl Asked {
    /// What a revoke so asked may reach, over `members`, the person's set: the
    /// one place an asker becomes a [`Reach`]. `device revoke` resolves through
    /// it ([`node_named`]) and removes what it resolved ([`revoke_named`]), in
    /// `kotton_device::users::drive_devices::revoke`, the one body a revoke runs.
    pub fn reach(self, members: &dyn crate::membership::MemberStore) -> Reach<'_> {
        match self {
            Asked::Locally => Reach::RowsAndMembers(members),
            Asked::Remotely => Reach::Rows,
        }
    }
}

/// What [`node_named`] resolved a name to.
#[derive(Debug, Clone)]
pub enum Named {
    /// One of the person's rows.
    Row(PairedNode),
    /// The own-device members of the person's set that carry the name as their
    /// DID as stored and that no row stands for, as the set's own listing
    /// returned them. Never empty.
    Members(Vec<crate::membership::Found>),
}

/// **The one resolver of a node a person names** (kottonllc/kotton#610). A
/// name is taken whole and compared by equality with what is stored, and held
/// to no rule of characters: the rule a sentence prints a command by
/// ([`kotton_wire::note::one_plain_word`]) bounds what is printed, never what is
/// taken (kottonllc/kotton#597, 26A).
///
/// In order: a row of the person's under the name as its DID as stored, then a
/// row carrying it as its label, refused where two rows carry it
/// ([`network_db::paired_node_named`]); then, with [`Reach::RowsAndMembers`] and
/// only where no row carries the name, an own-device member of the person's set
/// under it as its DID as stored that no row stands for, found in the set's own
/// listing ([`crate::membership::Membership::list_found`]). With
/// [`Reach::Drives`], the same order over the rows the drive record names only:
/// one by its DID as stored, then one by its label, refused where two of those
/// rows carry it; it never reaches a member. A contact or a relay is never
/// resolved, and the name is never joined into a store path. `Ok(None)` when it
/// names nothing in reach; `Err` for a label two rows in reach carry, or a set
/// or a drive record that could not be read.
///
/// Conceded (kottonllc/kotton#597, 36A): a member under bytes that are no key is
/// neither reached nor noted ([`member_notes`]) while a row of the person's
/// carries its DID as stored as a DID or a label, and is both once no row does.
/// The seam is the member arm, one branch here: a form of the request that says
/// the member is meant, taken at the machine only, would reach it by its listing
/// key with no change to a store, a row or a note.
pub async fn node_named(
    db: &Arc<SqlitePool>,
    user_id: &str,
    name: &str,
    reach: Reach<'_>,
) -> io::Result<Option<Named>> {
    if let Reach::Drives = reach {
        return Ok(drive_node_named(db, user_id, name).await?.map(Named::Row));
    }
    if let Some(row) = network_db::paired_node_named(db, user_id, name).await? {
        return Ok(Some(Named::Row(row)));
    }
    let Reach::RowsAndMembers(store) = reach else {
        return Ok(None);
    };
    let found = store
        .list_found()
        .await
        .map_err(|e| io::Error::other(format!("could not read your membership set to look for '{name}': {e:#}")))?;
    let rows = network_db::list_paired_nodes(db, user_id).await?;
    let named: Vec<_> = members_with_no_row(&rows, found).into_iter().filter(|f| f.member.did == name).collect();
    Ok((!named.is_empty()).then_some(Named::Members(named)))
}

/// [`node_named`] over [`Reach::Drives`]: the row among the drive record's that
/// `name` names, by its DID as stored, then by its label where one of those rows
/// carries it.
async fn drive_node_named(db: &Arc<SqlitePool>, user_id: &str, name: &str) -> io::Result<Option<PairedNode>> {
    let rows = super::drives::nodes(db, user_id)
        .await
        .map_err(|e| io::Error::other(format!("failed to list your drives: {e}")))?;
    if let Some(row) = rows.iter().find(|r| r.device_did.to_string() == name) {
        return Ok(Some(row.clone()));
    }
    let mut labelled: Vec<PairedNode> = rows.into_iter().filter(|r| r.id == name).collect();
    match labelled.len() {
        0 | 1 => Ok(labelled.pop()),
        n => {
            let mut dids: Vec<String> = labelled.iter().map(|r| r.device_did.to_string()).collect();
            dids.sort();
            Err(io::Error::other(format!(
                "'{name}' is the label of {n} of your drives ({}); name the one you mean by its DID",
                dids.join(", ")
            )))
        }
    }
}

/// Revoke what [`node_named`] resolved, and its key on the live allowlist
/// unless a row still pairs it: another person's here, who may pair the same
/// node (two tenants of one vault).
///
/// - **A row:** the row goes, and with it every own-device member of the set that
///   holds the row's key, by its bytes: a row is its bytes', and the DID beside
///   them is not read as the member's name (kottonllc/kotton#597, 5B). The
///   members go first, as the source of truth ("revoke once, closed
///   everywhere"), best-effort: the row and the live allowlist entry are what
///   block a connection here today, so a set that cannot be read or written is
///   logged, not fatal.
/// - **Members with no row:** each is removed from the set by the key the set's
///   own listing gave for it, and a failure is the answer.
///
/// **A row's revoke is not a success while another row of the person's holds
/// its key** (kottonllc/kotton#597, 34A). Such a row, which only an earlier
/// build can have stored, still pairs the key here, so the answer is an error
/// that names each, by the name `device revoke` takes to it
/// ([`network_db::name_of`]), printed as data ([`kotton_wire::note::quoted`]).
/// Only the person's own rows are named: another person's row under the key is
/// theirs ([`still_paired_as`]).
pub async fn revoke_named(
    member_store: &dyn crate::membership::MemberStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    named: &Named,
    paired_keys: &Arc<RwLock<HashSet<VerifyingKey>>>,
) -> io::Result<UserResponse> {
    let mut still: Option<(String, Vec<String>)> = None;
    let keys: Vec<[u8; 32]> = match named {
        Named::Row(node) => {
            match member_store.list_found().await {
                Ok(found) => {
                    let holding = found
                        .iter()
                        .filter(|f| f.member.is_own_device() && f.member.public_key == node.public_key);
                    for f in holding {
                        if let Err(e) = member_store.remove_found(f).await {
                            tracing::warn!(user_id, member = %f.member.did, "revoked node but failed to remove its membership record: {e:#}");
                        }
                    }
                }
                Err(e) => tracing::warn!(user_id, node = %node.device_did, "revoked node but could not read the membership set to remove its member: {e:#}"),
            }
            let name = network_db::name_of(&network_db::list_paired_nodes(db, user_id).await?, node);
            network_db::delete_paired_node(db, user_id, &node.device_did.to_string()).await?;
            let others = still_paired_as(&network_db::list_paired_nodes(db, user_id).await?, &node.public_key);
            if !others.is_empty() {
                still = Some((name, others));
            }
            vec![node.public_key]
        }
        Named::Members(found) => {
            for f in found {
                member_store.remove_found(f).await.map_err(|e| io::Error::other(format!("{e:#}")))?;
            }
            found.iter().map(|f| f.member.public_key).collect()
        }
    };
    for key in keys {
        if !still_paired(db, &key).await? {
            unadmit(paired_keys, &key);
        }
    }
    Ok(match still {
        None => UserResponse::NodeRevoked,
        Some((name, others)) => UserResponse::Error {
            message: format!(
                "{} is revoked on this device, but this device still pairs its key for you as {}, so a \
                 connection under that key is still admitted here. `device revoke` takes {} by that name.",
                kotton_wire::note::quoted(&name),
                others.iter().map(|n| kotton_wire::note::quoted(n)).collect::<Vec<_>>().join(", "),
                if others.len() == 1 { "it" } else { "each" },
            ),
        },
    })
}

/// The name `device revoke` takes to each of `rows`, one person's, that holds
/// `key` ([`network_db::name_of`]), in the one order
/// ([`network_db::listed_before`]). `rows` are the person's alone, so no other
/// person's row is named.
pub fn still_paired_as(rows: &[PairedNode], key: &[u8; 32]) -> Vec<String> {
    let mut holding: Vec<&PairedNode> = rows.iter().filter(|r| r.public_key == *key).collect();
    holding.sort_by(|a, b| network_db::listed_before(a, b));
    holding.into_iter().map(|r| network_db::name_of(rows, r)).collect()
}

// ---------------------------------------------------------------------------
// Distributed FROST signing — coordinator side
// ---------------------------------------------------------------------------

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

/// The person's `paired_nodes` rows a threshold round dials: each row whose key
/// is the key of a member that holds a share (`Full` or `Cosigner`).
///
/// **A co-signer is chosen by its key.** A `paired_nodes` row is its bytes',
/// and the DID stored beside them is never read as the key's name
/// (kottonllc/kotton#597, 5B): a row under another spelling of a member's
/// `did:key` is that member's row, and a row whose stored DID is a member's
/// beside a different key is not. This is how the membership projection reads
/// an own device ([`project_membership_into_allowlist`]).
///
/// A member whose bytes the Ed25519 rule refuses chooses no row: nothing is
/// dialled for a signature under bytes that are no key. A key held by more than
/// one row is dialled once, through the row the key is reached through
/// ([`network_db::reached_through`], kottonllc/kotton#622), so no share is
/// asked for twice in one round. The rows come back in the order `rows` lists
/// them, one per key.
#[cfg(any(test, feature = "test-support"))]
fn cosigner_nodes(members: &[Member], rows: Vec<PairedNode>) -> Vec<PairedNode> {
    let keys: HashSet<[u8; 32]> = members
        .iter()
        // Any share-holding member can co-sign: `Full` and `Cosigner` both
        // hold a FROST share. Only `BlindStorage` is excluded.
        .filter(|m| matches!(m.posture, Some(Posture::Full | Posture::Cosigner)))
        .filter(|m| VerifyingKey::from_bytes(&m.public_key).is_ok())
        .map(|m| m.public_key)
        .collect();
    let chosen: Vec<String> = keys
        .iter()
        .filter_map(|k| network_db::reached_through(&rows, k))
        .map(|n| n.device_did.to_string())
        .collect();
    rows.into_iter().filter(|n| chosen.contains(&n.device_did.to_string())).collect()
}

/// A co-signer's answer to a signing round: its reply, or why not. The
/// co-signer's `Error`, and what its reply did not read as, are printed as data
/// to a bounded length ([`kotton_wire::note::quoted_cut`]; how another node's
/// text is printed); an answer not asked for by its name and no field of it
/// ([`kotton_wire::ipc::unasked`]).
#[cfg(any(test, feature = "test-support"))]
fn round_reply_in(resp: UserResponse) -> anyhow::Result<kotton_org::frost_signing::FrostRoundReply> {
    match resp {
        UserResponse::FrostSignReply { payload } => serde_json::from_str(&payload).map_err(|e| {
            anyhow::anyhow!("the co-signer's round reply did not read: {}", kotton_wire::note::quoted_cut(&e.to_string()))
        }),
        UserResponse::Error { message } => {
            Err(anyhow::anyhow!("the co-signer answered: {}", kotton_wire::note::quoted_cut(&message)))
        }
        other => Err(anyhow::anyhow!("the co-signer answered {}", kotton_wire::ipc::unasked(&other))),
    }
}

/// Coordinate a threshold signature over `message` across this node's own
/// network. This node contributes its own FROST share locally and co-signs with
/// every **Full** own-device member reached over the authenticated peer channel
/// — each runs the `FrostSignRound` responder, so their shares never leave their
/// nodes. Returns the aggregate 64-byte Ed25519 signature, which verifies under
/// the group (identity) DID.
///
/// Co-signers are resolved from the membership set (the source of truth):
/// a paired node is included iff its key is the key of a member that holds a
/// share — a `Full` or `Cosigner` membership record — which is precisely what
/// excludes a `BlindStorage` (no share) from the quorum. The match is by the
/// key's bytes ([`cosigner_nodes`]).
///
/// **Compiled only under `test-support`: this is the test-only round.** No request on
/// any door of a daemon's build asks the person's group key to sign bytes the caller
/// supplies: this coordinator is not in a daemon's build, and neither is the
/// `FrostSignRound` responder that answers it (kuserd's `test-support`). The
/// integration suite turns both features on, to drive a distributed round between two
/// enrolled daemons in process, over the peer channel and the responder each
/// co-signer serves. Each error says why no signature came: the store is locked, this
/// node holds no share, a co-signer could not be reached, or the round failed.
#[cfg(feature = "test-support")]
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
    message: &[u8],
    secrets: &dyn SecretsStore,
) -> anyhow::Result<Vec<u8>> {
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
    let members = member_store
        .list_members()
        .await
        .map_err(|e| anyhow::anyhow!("cannot choose who signs with this node: {e:#}"))?;

    // This node's own share + the group public-key package (both persisted at
    // enrollment). Absence means this node is not enrolled in the threshold.
    let local_share = match secrets.get_secret(&kdf_labels::frost_share(&user_id)) {
        Ok(Some(s)) => s,
        Ok(None) => anyhow::bail!("no FROST share on this node — not enrolled in the threshold"),
        Err(e) => anyhow::bail!("keychain read failed: {e}"),
    };
    let pubkey_package = match secrets.get_secret(&kdf_labels::frost_pubkey_package(&user_id)) {
        Ok(Some(s)) => s,
        Ok(None) => anyhow::bail!("no group public-key package on this node"),
        Err(e) => anyhow::bail!("keychain read failed: {e}"),
    };

    let cosigner_nodes = cosigner_nodes(&members, network_db::list_paired_nodes(db, &user_id).await?);

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
            Err(e) => anyhow::bail!("could not reach co-signer {label}: {e}"),
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
                round_reply_in(resp)
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

    coordinate_threshold_sign(&signers, &pubkey_package, message)
        .await
        .map_err(|e| anyhow::anyhow!("threshold signing failed: {e}"))
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
///
/// **Its DID is its key's derivation**, made here from the node's key and not
/// read from the node: an own device's DID is a name for its key
/// (kottonllc/kotton#597, 27A), and [`crate::membership::Membership::write_member`]
/// writes no own-device member under any other. Bytes the Ed25519 rule refuses
/// have no derivation; the member keeps the node's DID, and `write_member`
/// refuses it by its key.
pub fn own_device_member(node: &PairedNode, posture: Posture, added_at: &str) -> Member {
    let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&node.public_key)
        .map_or_else(|_| node.device_did.to_string(), |d| d.to_string());
    Member {
        did,
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
/// act (`device revoke`, whose [`revoke_named`] drops the member and the key
/// together), and a reproject-*with-removal* against a not-yet-synced (incomplete) membership set
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
    paired_keys: &Arc<RwLock<HashSet<VerifyingKey>>>,
    user_id: &str,
) -> usize {
    let members = match member_store.list_members().await {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(user_id, error = %e, "membership not readable; allowlist projection skipped");
            return 0;
        }
    };
    let existing = network_db::list_paired_nodes(db, user_id).await.unwrap_or_default();
    // A contact cached as a device is found by the DID it was cached under: the
    // repair below removes the row an earlier build wrote for the member, by
    // the name it wrote it under, and no row of the person's own that happens
    // to hold the same bytes.
    let existing_dids: HashSet<String> = existing.iter().map(|n| n.device_did.to_string()).collect();
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
        // A member is recorded here as a key or not at all: for bytes the Ed25519
        // rule refuses, nothing is written below — no allowlist entry, no
        // `paired_nodes` row, no drive.
        let key = VerifyingKey::from_bytes(&m.public_key).ok();
        if let Some(key) = key.filter(|_| m.in_paired_key_allowlist()) {
            if paired_keys.write().unwrap().insert(key) {
                added += 1;
            }
        }
        // Ensure a paired_nodes cache row exists without clobbering learned
        // addresses (address-less until reachability fills it). A member whose key
        // a row of the person's already holds is already cached.
        //
        // **Own devices only.** `paired_nodes` is what `peer_standing` reads to
        // answer `PeerStanding::Paired`, and that standing serves `ReadFile`,
        // `ReadSealed`, `ListSealed` and `RecoveryFetch`.
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
        // The row is written by the member's key, under its derivation, with the
        // member's label where it has one (kottonllc/kotton#597, 27A, 28A): a
        // member an earlier build wrote under another spelling stands by its
        // bytes (5B), and its row is named as every row is. Where a row of the
        // person's already holds the key, nothing is written or changed (69A).
        // A derivation that is already a row's DID beside another key is
        // refused by the writer: the member is then a member with no row.
        if let Some(key) = key.as_ref().filter(|_| m.is_own_device()) {
            let label = m.label.clone().unwrap_or_else(|| kotton_crypto::DidKeyMethod::from_public_key(key).to_string());
            if let Err(e) = network_db::add_paired_node_if_absent(
                db,
                &label,
                user_id,
                key,
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
        if key.is_some() && m.is_own_device() && m.posture == Some(Posture::BlindStorage) {
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
    paired_keys: &Arc<RwLock<HashSet<VerifyingKey>>>,
) {
    let user_ids: Vec<String> = users.iter().map(|(id, _)| id.clone()).collect();

    // Built aside and swapped in, so the live set is never transiently empty —
    // a handshake landing mid-rebuild must not be refused for a peer that both
    // the old and the new allowlist admit.
    //
    // A key the rule refuses is not put on the allowlist. The set's element is the
    // key type, so nothing enters it but through `VerifyingKey::from_bytes`: the
    // operator keys and the stored rows read below, the keys carried over from the
    // live set (keys already), and the own-device members' keys the membership
    // projection adds after the swap. Bytes that do not decode, are not their
    // point's canonical encoding, are the identity, or are outside the prime-order
    // subgroup are left out.
    let mut rebuilt: HashSet<VerifyingKey> = HashSet::new();
    // The vault's operator credential, which is no user's row and is admitted at
    // the handshake all the same; what it may say once admitted is its standing
    // (`PeerStanding::Operator`). Empty on a device.
    match network_db::operator_keys(db).await {
        Ok(keys) => rebuilt.extend(keys.iter().filter_map(|k| VerifyingKey::from_bytes(k).ok())),
        Err(e) => {
            tracing::warn!(error = %e, "operator_key unreadable; keeping the live keys");
            rebuilt.extend(paired_keys.read().unwrap().iter().copied());
        }
    }
    for uid in &user_ids {
        match network_db::list_paired_nodes(db, uid).await {
            Ok(nodes) => rebuilt.extend(nodes.iter().filter_map(|n| VerifyingKey::from_bytes(&n.public_key).ok())),
            Err(e) => {
                // Losing one user's rows would silently unadmit their peers, so
                // keep whatever is live for them rather than narrowing on error.
                tracing::warn!(user_id = %uid, error = %e, "paired_nodes unreadable; keeping the live keys for this user");
                rebuilt.extend(paired_keys.read().unwrap().iter().copied());
            }
        }
    }
    *paired_keys.write().unwrap() = rebuilt;

    for (uid, store) in users {
        project_membership_into_allowlist(store.as_ref(), db, paired_keys, uid).await;
    }
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
    paired_keys: &Arc<RwLock<HashSet<VerifyingKey>>>,
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
/// by a `PairConfirmCode` request via [`PendingConfirms`]. A timeout, a dropped
/// stream, or the stream closing while the verdict is awaited is treated as a
/// decline — fail safe.
///
/// **A ceremony ends with the stream that started it (#436).** The stream's
/// sender is the one thing that closes whatever ended the stream: a revoked or
/// expired session (`while_live` drops the verb's receiver), or a client that
/// went away. So the confirmer races its wait against [`mpsc::Sender::closed`],
/// and [`Self::unless_abandoned`] is what each ceremony runner drives its
/// ceremony through, so the same signal ends it in every other step too. The
/// confirmer's parked entry goes with it, on every ending, so a later
/// `PairConfirmCode` for its token finds nothing.
pub struct StreamingConfirmer {
    tx: mpsc::Sender<UserResponse>,
    token: String,
    pending: PendingConfirms,
    ttl: std::time::Duration,
    /// Set once the human's yes has been taken, before anything is handed
    /// over: the point after which the ceremony is not abandoned (see
    /// [`Self::unless_abandoned`]).
    said_yes: std::sync::atomic::AtomicBool,
}

/// A confirmation parked in [`PendingConfirms`], removed when it is dropped:
/// the verdict was taken, the wait timed out, the stream closed, or the
/// ceremony holding it was dropped mid-wait. One home for the removal, so no
/// ending leaves a token a later `PairConfirmCode` could find.
struct Parked {
    pending: PendingConfirms,
    token: String,
}

impl Drop for Parked {
    fn drop(&mut self) {
        // Uncontended in practice: the table is held only for an insert or a
        // remove. If it is held now, the removal is handed to the runtime; the
        // verdict's receiver is dropped with the ceremony either way, so an
        // entry not yet removed can fire nothing.
        if let Ok(mut parked) = self.pending.try_lock() {
            parked.remove(&self.token);
            return;
        }
        let (pending, token) = (Arc::clone(&self.pending), std::mem::take(&mut self.token));
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                pending.lock().await.remove(&token);
            });
        }
    }
}

/// `work`, unless `tx`'s stream closes first: `None` then, and `work` is
/// dropped where it stood. Whatever ended the stream — a revoked or expired
/// session, or a client gone away — this is the one signal (#436).
pub async fn until_closed<M, T>(tx: &mpsc::Sender<M>, work: impl std::future::Future<Output = T>) -> Option<T> {
    tokio::select! {
        biased;
        () = tx.closed() => None,
        out = work => Some(out),
    }
}

impl StreamingConfirmer {
    /// A confirmer for the stream `tx` feeds, parking its verdict under a
    /// fresh token in `pending` for up to `ttl`.
    pub fn new(tx: mpsc::Sender<UserResponse>, pending: PendingConfirms, ttl: std::time::Duration) -> Self {
        Self {
            tx,
            token: Uuid::new_v4().to_string(),
            pending,
            ttl,
            said_yes: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Mark the comparison as answered yes by something other than a person
    /// — a pinned key ([`SasConfirmer`] implementations that confirm by key)
    /// — so the ceremony past this point is held to the same rule as one a
    /// person confirmed.
    pub fn confirmed_by_key(&self) {
        self.said_yes.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// `ceremony`, ended if its stream closes before the comparison is
    /// answered yes (#436).
    ///
    /// Before the yes, nothing has been handed over: the issuer is waiting
    /// for a joiner (and is advertised at the relay or on the LAN), dialling,
    /// or waiting on the verdict. Dropping the ceremony there drops its
    /// listener, its relay reservation and its parked confirmation, and admits
    /// nothing. After the yes, the payload crosses and each side records what
    /// it kept; dropping it there could leave this side without a record of a
    /// device that holds what it was handed. So the stream closing after the
    /// yes does not end the ceremony: it runs to its own end, bounded by its
    /// own windows, and records what it was told to.
    pub async fn unless_abandoned<T>(&self, ceremony: impl std::future::Future<Output = T>) -> Option<T> {
        let abandoned = async {
            self.tx.closed().await;
            if self.said_yes.load(std::sync::atomic::Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            biased;
            () = abandoned => None,
            out = ceremony => Some(out),
        }
    }
}

#[async_trait::async_trait]
impl SasConfirmer for StreamingConfirmer {
    async fn confirm(&self, sas: u32, peer_label: Option<&str>) -> bool {
        let (verdict_tx, verdict_rx) = oneshot::channel::<bool>();
        self.pending
            .lock()
            .await
            .insert(self.token.clone(), verdict_tx);
        let parked = Parked {
            pending: Arc::clone(&self.pending),
            token: self.token.clone(),
        };

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
            return false;
        }

        // The verdict, the ttl, or the stream closing, whichever is first: a
        // stream that closed has nobody behind it to have answered.
        let verdict = matches!(
            until_closed(&self.tx, tokio::time::timeout(self.ttl, verdict_rx)).await,
            Some(Ok(Ok(true)))
        );
        drop(parked);
        if verdict {
            self.said_yes.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = self.tx.send(UserResponse::PairAwaitingPeer).await;
        }
        verdict
    }
}

/// Deliver a human's SAS verdict to a parked ceremony (the `PairConfirmCode`
/// handler). A late/duplicate/unknown token is a no-op, not an error — and so
/// is the token of a ceremony that ended with its stream (#436): its entry
/// went with it, so the verdict reaches nothing and admits nothing. The
/// answer is the same `PairConfirmAck` either way: it says the request was
/// read, never that a ceremony took it.
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
/// ([`RefusedAtTheRelay`]) as what this device presented there, a join the
/// other device did not keep ([`JoinNotKept`]) as what is kept here — nothing —
/// a ceremony one side refused before anything was handed
/// ([`RefusedBeforeHanding`], [`NotHanded`]) as that refusal, and every other
/// failure as [`ceremony_failure_copy`] reads it.
pub fn ceremony_failure(err: &anyhow::Error) -> String {
    if let Some(not_kept) = err.downcast_ref::<JoinNotKept>() {
        return join_not_kept_copy(not_kept);
    }
    if let Some(RefusedBeforeHanding(why)) = err.downcast_ref::<RefusedBeforeHanding>() {
        return refused_before_handing_copy(why);
    }
    if let Some(not_handed) = err.downcast_ref::<NotHanded>() {
        return not_handed_copy(not_handed);
    }
    match err.downcast_ref::<RefusedAtTheRelay>() {
        Some(refused) => refused_at_the_relay_copy(refused),
        None => ceremony_failure_copy(&err.to_string()),
    }
}

/// What the admitting device's person is told when the other device did not
/// keep what it was handed: that this device kept nothing either — no row for
/// it, and no drive told of it — so there is nothing here to revoke, and, for
/// a refusal, the other device's own reason, printed as data and to a
/// bounded length ([`kotton_wire::note::quoted_cut`]; how another node's text
/// is printed). The sentence is this device's own: every reader of the
/// `PairFailed` it becomes prints it as written, so that reason is quoted
/// once. Not
/// [`ceremony_failure_copy`]'s *nothing was shared*: the payload crossed, and
/// the other device threw it away.
pub fn join_not_kept_copy(not_kept: &JoinNotKept) -> String {
    const NOTHING_KEPT: &str = "Nothing is kept here: this device did not add it, and none of your drives \
                                was told of it, so there is nothing to revoke.";
    match not_kept {
        JoinNotKept::Refused(why) => {
            format!("The other device refused the join. {NOTHING_KEPT} It said: {}", kotton_wire::note::quoted_cut(why))
        }
        JoinNotKept::Unanswered(how) => format!(
            "The other device did not say it kept what it was handed ({how}). {NOTHING_KEPT} Pair again when \
             both devices are ready."
        ),
    }
}

/// What the admitting device's person is told when it would not record the
/// other device and so handed it nothing ([`RefusedBeforeHanding`]): `why`,
/// this device's own sentence, and that nothing is kept on either side. The
/// other device was sent this device's refusal in the payload's place.
pub fn refused_before_handing_copy(why: &str) -> String {
    format!(
        "This device did not add the other device: {why}. Nothing was handed over, so nothing is kept on either \
         device; pair again once that is resolved."
    )
}

/// What the joining device's person is told when the admitting device refused
/// it before handing anything ([`NotHanded`]): this device's own sentence, and
/// the admitting device's reason printed as data and to a bounded length
/// ([`kotton_wire::note::quoted_cut`]; how another node's text is printed).
pub fn not_handed_copy(not_handed: &NotHanded) -> String {
    format!(
        "This device was not joined: the device that would have admitted it refused it before handing anything \
         over. Nothing was kept here, and that device keeps nothing of it either. It said: {}",
        kotton_wire::note::quoted_cut(&not_handed.0)
    )
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

/// The person's rows on this device, as an issuing ceremony asks of the
/// joiner's row before it hands anything
/// ([`crate::pairing::JoinerRow`]): the store's own rule,
/// [`network_db::row_refused_for`], which reads and writes nothing.
pub struct PersonsRows<'a> {
    pub db: &'a SqlitePool,
    pub user_id: &'a str,
}

#[async_trait::async_trait]
impl crate::pairing::JoinerRow for PersonsRows<'_> {
    async fn refused_for(&self, key: &VerifyingKey) -> io::Result<Option<String>> {
        network_db::row_refused_for(self.db, self.user_id, key).await
    }
}

/// Why [`finalize_enrolled_node`] did not record a node the ceremony enrolled.
#[derive(Debug)]
pub enum NotRecorded {
    /// The store refuses the node's row, or its key, read before the first
    /// write: nothing was kept. The store's sentence.
    Refused(String),
    /// A write failed. What was kept before it stays: the finalizer is not
    /// one transaction.
    Failed(io::Error),
}

impl From<io::Error> for NotRecorded {
    fn from(e: io::Error) -> Self {
        NotRecorded::Failed(e)
    }
}

impl std::fmt::Display for NotRecorded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotRecorded::Refused(why) => f.write_str(why),
            NotRecorded::Failed(e) => write!(f, "{e}"),
        }
    }
}

/// Persist an issuer-side enrollment outcome (the `device add` completion): the
/// retained FROST share + group key, the paired-node record + live allowlist, and
/// the own-device membership + sync wiring.
///
/// The single issuer-completion path for the pairing ceremony.
///
/// It returns the ceremony's node unchanged, and the store names the row
/// (kottonllc/kotton#597, 27A, 30A): where the person's row for the key is
/// stored under another spelling, the node returned carries the key's
/// derivation and the row keeps its DID as stored. The label names the row
/// either way.
///
/// **The ceremony has read the row for its node before it handed anything**
/// ([`PersonsRows`]), so a row the store would refuse ended the ceremony
/// before the payload, with both sides told and nothing kept on either.
///
/// **It reads that row again before it keeps anything**
/// ([`network_db::row_refused_for`]). Where the store refuses it — its key's
/// derivation is already a row's DID beside another key — it answers
/// [`NotRecorded::Refused`] with nothing kept: no FROST share or group key, no
/// row, no drive, no key on the allowlist, no member. Its callers say that as
/// a refusal, never as a write that failed. It is not one transaction: a
/// write that fails for another reason after the first is
/// [`NotRecorded::Failed`], and leaves what was kept before it. No writer of
/// this build stores the refused shape — every writer names a new row by its
/// own key's derivation or keeps the key's row — so between the ceremony's
/// read and this one, and between this read and the write, the offending row
/// can only be removed.
pub async fn finalize_enrolled_node(
    secrets: &dyn SecretsStore,
    member_store: &dyn crate::membership::MemberStore,
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<RwLock<HashSet<VerifyingKey>>>,
    user_id: &str,
    posture: Posture,
    enrolled: crate::pairing::EnrolledNode,
) -> Result<PairedNode, NotRecorded> {
    // The node's key enters the allowlist below; bytes the Ed25519 rule refuses are
    // refused here, before anything is recorded.
    let key = VerifyingKey::from_bytes(&enrolled.node.public_key)
        .map_err(|e| NotRecorded::Refused(format!("the enrolled node's key is not an Ed25519 key: {e}")))?;
    // The row the store would refuse is refused here, before the first write:
    // a ceremony the store refuses keeps nothing.
    if let Some(why) = network_db::row_refused_for(db, user_id, &key).await? {
        return Err(NotRecorded::Refused(why));
    }
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
    // The row is written by its key, and the store names it: the row the person
    // has for the key, under its DID as stored, or a new one under the key's
    // derivation (kottonllc/kotton#597, 27A, 30A). The node's own DID is not
    // handed to the store.
    let row = network_db::insert_paired_node(db, &node.id, user_id, &key, &addresses_json, now, Some(posture.as_str()))
        .await?;
    // The relay the peer said it reserves at, when the ceremony learned one
    // (the relayed transport does; a peer reached on a socket said nothing
    // and is asked at the first connect). Without this a vault
    // admitted through its relay has no address *and* no relay on the row —
    // paired, and unreachable. Written to the row just written, by its DID.
    if let Some(relay) = node.relay_url.as_deref() {
        network_db::update_paired_node_relay(db, user_id, &row.device_did.to_string(), Some(relay)).await?;
    }
    // A vault admitted blind keeps the person's things: its tenancy is a drive,
    // recorded as one here, as `recover` records the vault it is pointed at
    // (`super::drives`).
    if posture == Posture::BlindStorage {
        super::drives::record(db, user_id, &node.public_key).await?;
    }
    paired_keys.write().unwrap().insert(key);

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

    /// **A join the other device did not keep is said as what is kept here —
    /// nothing, and nothing to revoke** — with the other device's reason when
    /// it refused, and never as *nothing was shared* or a lost connection: the
    /// payload crossed, and the other device threw it away.
    #[test]
    fn a_join_the_other_device_did_not_keep_says_nothing_is_kept_here() {
        let refused: anyhow::Error = JoinNotKept::Refused("the drive at 'vault' cannot be recorded here".into()).into();
        let said = ceremony_failure(&refused);
        assert!(said.starts_with("The other device refused the join."), "{said}");
        assert!(said.contains("Nothing is kept here") && said.contains("nothing to revoke"), "{said}");
        assert!(said.ends_with("It said: `the drive at 'vault' cannot be recorded here`"), "{said}");

        let silent: anyhow::Error = JoinNotKept::Unanswered("no answer within 120s".into()).into();
        let said = ceremony_failure(&silent);
        assert!(said.contains("did not say it kept what it was handed (no answer within 120s)"), "{said}");
        assert!(said.contains("Nothing is kept here"), "{said}");

        for said in [ceremony_failure(&refused), ceremony_failure(&silent)] {
            assert!(!said.contains("Nothing was shared") && !said.contains("Lost the connection"), "{said}");
            assert!(!said.contains("device revoke"), "a join nobody kept sent the person to revoke it: {said}");
        }
    }

    /// **A joining device's reason is printed as data and to the bound** (how
    /// another node's text is printed): a backtick and a line break escaped,
    /// and one past `MAX_SAID_CHARS` cut, inside this device's own sentence.
    #[test]
    fn a_joining_devices_reason_is_printed_as_data_and_to_the_bound() {
        use kotton_wire::note::{quoted_cut, MAX_SAID_CHARS};
        let long = "j".repeat(MAX_SAID_CHARS + 3);
        for why in ["no `room`\nhere", long.as_str()] {
            let said = join_not_kept_copy(&JoinNotKept::Refused(why.to_string()));
            assert!(said.starts_with("The other device refused the join."), "{said}");
            assert!(said.ends_with(&format!("It said: {}", quoted_cut(why))), "{said}");
            assert!(!said.contains('\n') && !said.contains(why), "{said}");
        }
        let said = join_not_kept_copy(&JoinNotKept::Refused("no `room`\nhere".into()));
        assert!(said.ends_with("It said: `no \\u{60}room\\u{60}\\nhere`"), "{said}");
        let said = join_not_kept_copy(&JoinNotKept::Refused(long.clone()));
        assert!(said.ends_with(" (cut: 3 more characters)"), "{said}");
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

    /// A member store that keeps what it is told.
    #[derive(Default)]
    struct Members(std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>);

    #[async_trait::async_trait]
    impl MemberStore for Members {
        async fn member_write(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
            self.0.lock().unwrap().insert(path.to_string(), data.to_vec());
            Ok(())
        }
        async fn member_read(&self, path: &str) -> anyhow::Result<Vec<u8>> {
            self.0.lock().unwrap().get(path).cloned().ok_or_else(|| anyhow::anyhow!("no member at {path}"))
        }
        async fn member_delete(&self, path: &str) -> anyhow::Result<()> {
            self.0.lock().unwrap().remove(path);
            Ok(())
        }
        async fn member_list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
            Ok(self.0.lock().unwrap().keys().filter(|k| k.starts_with(prefix)).cloned().collect())
        }
    }

    /// An own-device member under `public_key`, named `did`, admitted blind: a vault, which
    /// the projection also records as a drive.
    fn own_device(did: &str, public_key: [u8; 32]) -> Member {
        Member {
            did: did.to_string(),
            public_key,
            role: Role::OwnDevice,
            admitted_by: Ceremony::DeviceEnroll,
            added_at: "2026-11-16T00:00:00Z".to_string(),
            posture: Some(Posture::BlindStorage),
            label: None,
            reach: None,
        }
    }

    /// **A row and a member stand by their bytes** (kottonllc/kotton#597): a
    /// `paired_nodes` row and an own-device member whose bytes are a key, each
    /// stored under another spelling of the key's `did:key`, are admitted as
    /// before: the rebuilt allowlist holds both keys and the row's key is paired
    /// to its person.
    #[tokio::test]
    async fn a_row_and_a_member_under_another_spelling_are_admitted_by_their_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("agent.db"))
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::migrate!("../device/migrations").run(&pool).await.unwrap();
        let db = Arc::new(pool);

        let row = *kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[21u8; 32])).as_bytes();
        let member = *kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[22u8; 32])).as_bytes();
        let row_did = kotton_crypto::DidKeyMethod::spelled_otherwise(&row).to_string();
        network_db::seed_paired_node_as_stored(&db, "laptop", "alice", &row_did, &row, "[]", 0, None).await.unwrap();
        let members = Members::default();
        // As an earlier build wrote it: `write_member` writes no own-device
        // member under another spelling of its key.
        let m = own_device(&kotton_crypto::DidKeyMethod::spelled_otherwise(&member).to_string(), member);
        members.member_write(&m.vfs_path(), &serde_json::to_vec(&m).unwrap()).await.unwrap();

        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        let users: Vec<(String, Arc<dyn MemberStore>)> = vec![("alice".to_string(), Arc::new(members))];
        reproject_allowlist(&users, &db, &paired_keys).await;
        let live = paired_keys.read().unwrap().clone();
        let key = |b: &[u8; 32]| VerifyingKey::from_bytes(b).unwrap();
        assert!(live.contains(&key(&row)), "the row under another spelling is not admitted");
        assert!(live.contains(&key(&member)), "the member under another spelling is not admitted");
        assert!(network_db::is_pubkey_paired_to_user(&db, &row, "alice").await.unwrap());
    }

    /// **The allowlist a daemon rebuilds from its store holds only keys the
    /// rule admits**, from every source it is built from. A store can carry a
    /// row whose bytes are not a key: an all-zero row written by the placeholder
    /// pairing verb this crate no longer has, which an existing database keeps,
    /// or bytes `peer_add` was handed. A membership set can carry such a member
    /// too. One row per key the rule refuses sits beside one honest row, and the
    /// rebuild runs twice: with no members, and with one own-device member per
    /// refused key beside one honest member, each a vault. Each time only the
    /// honest keys are on the allowlist, and nothing is recorded for a member the
    /// rule refuses: no `paired_nodes` row and no drive.
    #[tokio::test]
    async fn the_rebuilt_allowlist_holds_only_keys_the_rule_admits() {
        use kotton_crypto::ed25519::refused;

        let honest_row = SigningKey::from_bytes(&[11u8; 32]).verifying_key().to_bytes();
        let honest_member = SigningKey::from_bytes(&[13u8; 32]).verifying_key().to_bytes();
        let refused_keys: Vec<[u8; 32]> = refused::SMALL_ORDER_KEYS
            .into_iter()
            .chain(refused::IDENTITY_OTHER_ENCODINGS)
            .chain([refused::mixed_order_key(), refused::NON_CANONICAL_KEY, refused::NOT_A_POINT])
            .collect();
        assert_eq!(refused_keys.len(), 14, "one row and one member per refused key vector");

        let members = Members::default();
        // As an earlier build wrote them: `write_member` refuses a member under such
        // bytes, and an own-device member under a DID of another method.
        let m = own_device("did:peer:honest-member", honest_member);
        members.member_write(&m.vfs_path(), &serde_json::to_vec(&m).unwrap()).await.unwrap();
        for (i, key) in refused_keys.iter().enumerate() {
            let m = own_device(&format!("did:peer:refused-member-{i}"), *key);
            members.member_write(&m.vfs_path(), &serde_json::to_vec(&m).unwrap()).await.unwrap();
        }
        assert_eq!(members.list_members().await.unwrap().len(), 15);

        let key = |b: &[u8; 32]| VerifyingKey::from_bytes(b).expect("an honest key");
        let runs: [(Arc<dyn MemberStore>, HashSet<VerifyingKey>, bool); 2] = [
            (Arc::new(NoMembers), HashSet::from([key(&honest_row)]), false),
            (Arc::new(members), HashSet::from([key(&honest_row), key(&honest_member)]), true),
        ];
        for (store, honest, with_members) in runs {
            let dir = tempfile::tempdir().unwrap();
            let options = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(dir.path().join("agent.db"))
                .create_if_missing(true);
            let pool = SqlitePool::connect_with(options).await.unwrap();
            sqlx::migrate!("../device/migrations").run(&pool).await.unwrap();
            let db = Arc::new(pool);

            network_db::seed_paired_node_as_stored(&db, "laptop", "alice", "did:peer:laptop", &honest_row, "[]", 0, None)
                .await
                .unwrap();
            for (i, key) in refused_keys.iter().enumerate() {
                let (id, did) = (format!("refused-{i}"), format!("did:peer:refused-{i}"));
                network_db::seed_paired_node_as_stored(&db, &id, "alice", &did, key, "[]", 0, None)
                    .await
                    .unwrap();
            }
            assert_eq!(network_db::list_paired_nodes(&db, "alice").await.unwrap().len(), 15);

            let paired_keys = Arc::new(RwLock::new(HashSet::new()));
            let users: Vec<(String, Arc<dyn MemberStore>)> = vec![("alice".to_string(), store)];
            reproject_allowlist(&users, &db, &paired_keys).await;

            let live = paired_keys.read().unwrap().clone();
            for (i, key) in refused_keys.iter().enumerate() {
                assert!(
                    !live.iter().any(|k| k.as_bytes() == key),
                    "the rebuilt allowlist admitted refused key vector {i}"
                );
            }
            assert_eq!(live, honest, "only the honest keys are on the allowlist");

            let drives_under = |key: [u8; 32]| {
                let db = Arc::clone(&db);
                async move {
                    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM drives WHERE vault_key = ?")
                        .bind(key.as_slice())
                        .fetch_one(db.as_ref())
                        .await
                        .unwrap()
                }
            };
            for (i, key) in refused_keys.iter().enumerate() {
                let did = format!("did:peer:refused-member-{i}");
                assert!(
                    network_db::get_paired_node(&db, "alice", &did).await.unwrap().is_none(),
                    "a row was written for refused member {i}"
                );
                assert_eq!(drives_under(*key).await, 0, "a drive was recorded for refused key vector {i}");
            }
            let honest_drives = drives_under(honest_member).await;
            assert_eq!(honest_drives, i64::from(with_members), "the honest vault member's drive");
        }
    }

    /// **A key revoked for one person stays in the live allowlist while
    /// another person's row still pairs it, and leaves with the last row**
    /// (kotton #99). Rows are each person's, so two tenants of one vault on a
    /// shared device each pair its key; a revoke for one of them must
    /// not shut the other's door at the handshake.
    #[tokio::test]
    async fn a_revoked_key_leaves_the_allowlist_with_its_last_row() {
        let dir = tempfile::tempdir().unwrap();
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("agent.db"))
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::migrate!("../device/migrations").run(&pool).await.unwrap();
        let db = Arc::new(pool);

        let key = SigningKey::from_bytes(&[12u8; 32]).verifying_key().to_bytes();
        let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&key).unwrap().to_string();
        let admitted = VerifyingKey::from_bytes(&key).unwrap();
        for user in ["alice", "bob"] {
            network_db::insert_paired_node(&db, "household", user, &admitted, "[]", 0, None).await.unwrap();
        }
        let paired_keys = Arc::new(RwLock::new(HashSet::from([admitted])));

        let said = revoke(&NoMembers, &db, "alice", "household", &paired_keys, Asked::Locally).await;
        assert!(matches!(said, UserResponse::NodeRevoked), "{said:?}");
        assert!(network_db::list_paired_nodes(&db, "alice").await.unwrap().is_empty());
        assert!(paired_keys.read().unwrap().contains(&admitted), "alice's revoke shut bob's door at the handshake");

        let said = revoke(&NoMembers, &db, "bob", &did, &paired_keys, Asked::Locally).await;
        assert!(matches!(said, UserResponse::NodeRevoked), "{said:?}");
        assert!(!paired_keys.read().unwrap().contains(&admitted), "a key no row pairs is still admitted");
    }

    /// **A row an earlier build stored under bytes the rule refuses is removed by
    /// the verb that revokes any node**, named by its DID as stored and matched
    /// by what is stored, not through the decode: for every key vector the rule
    /// refuses, the row goes, the honest row beside it stays, and the allowlist
    /// is untouched.
    #[tokio::test]
    async fn a_row_under_bytes_the_rule_refuses_is_revoked_by_what_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("agent.db"))
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::migrate!("../device/migrations").run(&pool).await.unwrap();
        let db = Arc::new(pool);

        let honest = kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[12u8; 32]));
        let honest_did = kotton_crypto::DidKeyMethod::from_public_key(&honest).to_string();
        network_db::insert_paired_node(&db, "laptop", "alice", &honest, "[]", 0, None).await.unwrap();
        let paired_keys = Arc::new(RwLock::new(HashSet::from([honest])));

        for (name, bytes) in kotton_crypto::ed25519::refused_keys() {
            let did = kotton_crypto::DidKeyMethod::spelled_over(&bytes).to_string();
            network_db::seed_paired_node_as_stored(&db, "old", "alice", &did, &bytes, "[]", 0, None).await.unwrap();
            let said = revoke(&NoMembers, &db, "alice", &did, &paired_keys, Asked::Locally).await;
            assert!(matches!(said, UserResponse::NodeRevoked), "{name}: {said:?}");
            let left: Vec<String> =
                network_db::list_paired_nodes(&db, "alice").await.unwrap().iter().map(|n| n.device_did.to_string()).collect();
            assert_eq!(left, vec![honest_did.clone()], "{name}: the row was not removed, or the honest one went with it");
            assert_eq!(*paired_keys.read().unwrap(), HashSet::from([honest]), "{name}: the allowlist changed");
        }
    }

    async fn agent_db(dir: &tempfile::TempDir) -> Arc<SqlitePool> {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("agent.db"))
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::migrate!("../device/migrations").run(&pool).await.unwrap();
        Arc::new(pool)
    }

    /// `device revoke` as its one body runs it here, with no drive to tell
    /// (`kotton_device::users::drive_devices::revoke`): the name resolved within
    /// what `asked` reaches, then what it resolved revoked.
    async fn revoke(
        store: &dyn MemberStore,
        db: &Arc<SqlitePool>,
        user: &str,
        name: &str,
        keys: &Arc<RwLock<HashSet<VerifyingKey>>>,
        asked: Asked,
    ) -> UserResponse {
        match node_named(db, user, name, asked.reach(store)).await.unwrap() {
            Some(named) => revoke_named(store, db, user, &named, keys).await.unwrap(),
            None => UserResponse::Error { message: format!("node '{name}' not found for user '{user}'") },
        }
    }

    /// A member as an earlier build could have written it, past `write_member`'s rule.
    async fn stored(members: &Members, m: &Member) {
        members.member_write(&m.vfs_path(), &serde_json::to_vec(m).unwrap()).await.unwrap();
    }

    fn dids(members: &[Member]) -> Vec<String> {
        let mut dids: Vec<String> = members.iter().map(|m| m.did.clone()).collect();
        dids.sort();
        dids
    }

    /// **`device revoke` of a row removes the member that holds the row's key**
    /// (kottonllc/kotton#610; kottonllc/kotton#597, 5B): the row stands under its
    /// key's `did:key` and the own-device member under another spelling of it, and
    /// both go. A member under another key, and a contact under the row's key, stay.
    #[tokio::test]
    async fn a_rows_revoke_removes_the_member_that_holds_the_rows_key() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let key = kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[31u8; 32]));
        let other = kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[32u8; 32]));
        network_db::insert_paired_node(&db, "laptop", "alice", &key, "[]", 0, None).await.unwrap();
        let members = Members::default();
        let spelled = kotton_crypto::DidKeyMethod::spelled_otherwise(key.as_bytes()).to_string();
        stored(&members, &own_device(&spelled, *key.as_bytes())).await;
        let stays = own_device(&kotton_crypto::DidKeyMethod::from_public_key(&other).to_string(), *other.as_bytes());
        members.write_member(&stays).await.unwrap();
        let mut contact = own_device("did:kel:Ecarol", *key.as_bytes());
        contact.role = Role::Contact;
        members.write_member(&contact).await.unwrap();
        let paired_keys = Arc::new(RwLock::new(HashSet::from([key])));

        let said = revoke(&members, &db, "alice", "laptop", &paired_keys, Asked::Remotely).await;
        assert!(matches!(said, UserResponse::NodeRevoked), "{said:?}");
        assert!(network_db::list_paired_nodes(&db, "alice").await.unwrap().is_empty(), "the row stayed");
        let mut want = vec![stays.did.clone(), contact.did.clone()];
        want.sort();
        assert_eq!(dids(&members.list_members().await.unwrap()), want, "the member under the row's key stayed");
        assert!(paired_keys.read().unwrap().is_empty(), "the key stayed on the allowlist");
    }

    /// **A member of the set with no row is resolved by its DID as stored and
    /// removed from the set** (kottonllc/kotton#610), for every key vector the
    /// Ed25519 rule refuses: the listing at the machine notes it by that DID, the
    /// note's sentence names `device revoke` with it, and the revoke by the note's
    /// name, asked locally, removes it. Asked remotely, the same name is not found
    /// and the member stays; the listing without the set notes it not at all.
    #[tokio::test]
    async fn a_member_with_no_row_is_noted_and_removed_for_a_local_asker_only() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let honest = kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[33u8; 32]));
        let honest_did = kotton_crypto::DidKeyMethod::from_public_key(&honest).to_string();
        network_db::insert_paired_node(&db, "laptop", "alice", &honest, "[]", 0, None).await.unwrap();
        let members = Members::default();
        let kept = own_device(&honest_did, *honest.as_bytes());
        members.write_member(&kept).await.unwrap();
        let paired_keys = Arc::new(RwLock::new(HashSet::from([honest])));

        for (name, bytes) in kotton_crypto::ed25519::refused_keys() {
            let did = kotton_crypto::DidKeyMethod::spelled_over(&bytes).to_string();
            stored(&members, &own_device(&did, bytes)).await;

            let (_, remote) = listed(node_list(&db, "alice".into(), None).await.unwrap());
            assert!(remote.is_empty(), "{name}: a member was noted without the set: {remote:?}");
            let said = revoke(&members, &db, "alice", &did, &paired_keys, Asked::Remotely).await;
            assert!(matches!(&said, UserResponse::Error { message } if message.contains("not found")), "{name}: {said:?}");
            assert_eq!(members.list_members().await.unwrap().len(), 2, "{name}: a remote asker removed a member with no row");

            let (nodes, notes) = listed(node_list(&db, "alice".into(), Some(&members)).await.unwrap());
            assert_eq!(nodes.len(), 1, "{name}");
            assert_eq!(notes, vec![kotton_wire::note::RowNote::names_no_key(did.clone())], "{name}");
            assert!(
                kotton_wire::note::sentence(&notes[0], "device revoke").contains(&format!("`device revoke {did}`")),
                "{name}: the sentence names no revoke"
            );
            let said = revoke(&members, &db, "alice", &notes[0].name, &paired_keys, Asked::Locally).await;
            assert!(matches!(said, UserResponse::NodeRevoked), "{name}: {said:?}");
            assert_eq!(members.list_members().await.unwrap(), vec![kept.clone()], "{name}: the member stayed, or another went");
            let (nodes, notes) = listed(node_list(&db, "alice".into(), Some(&members)).await.unwrap());
            assert_eq!((nodes.len(), notes.len()), (1, 0), "{name}: {notes:?}");
            assert_eq!(*paired_keys.read().unwrap(), HashSet::from([honest]), "{name}: the allowlist changed");
        }
    }

    /// **A member with no row whose bytes pass is resolved too, and its key leaves
    /// the live allowlist**, where the projection put it without a row; it carries
    /// no note, since it names a key.
    #[tokio::test]
    async fn a_member_with_no_row_whose_bytes_pass_is_removed_and_unadmitted() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let key = kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[34u8; 32]));
        let did = kotton_crypto::DidKeyMethod::from_public_key(&key).to_string();
        let members = Members::default();
        members.write_member(&own_device(&did, *key.as_bytes())).await.unwrap();
        let paired_keys = Arc::new(RwLock::new(HashSet::from([key])));

        let (_, notes) = listed(node_list(&db, "alice".into(), Some(&members)).await.unwrap());
        assert!(notes.is_empty(), "{notes:?}");
        let said = revoke(&members, &db, "alice", &did, &paired_keys, Asked::Locally).await;
        assert!(matches!(said, UserResponse::NodeRevoked), "{said:?}");
        assert!(members.list_members().await.unwrap().is_empty());
        assert!(paired_keys.read().unwrap().is_empty(), "the key stayed on the allowlist");
    }

    /// **A contact or a relay is never resolved** (kottonllc/kotton#610), whatever
    /// its bytes: asked locally by its DID as stored, it is not found, it stays in
    /// the set, and the listing notes neither.
    #[tokio::test]
    async fn a_contact_or_a_relay_is_never_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let members = Members::default();
        let (_, refused) = kotton_crypto::ed25519::refused_keys().remove(0);
        for (role, did) in [(Role::Contact, "did:kel:Ecarol"), (Role::Relay, "did:key:zRelay")] {
            let mut m = own_device(did, refused);
            m.role = role;
            stored(&members, &m).await;
        }
        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        for did in ["did:kel:Ecarol", "did:key:zRelay"] {
            let said = revoke(&members, &db, "alice", did, &paired_keys, Asked::Locally).await;
            assert!(matches!(&said, UserResponse::Error { message } if message.contains("not found")), "{did}: {said:?}");
        }
        assert_eq!(members.list_members().await.unwrap().len(), 2, "a contact or a relay was removed");
        let (_, notes) = listed(node_list(&db, "alice".into(), Some(&members)).await.unwrap());
        assert!(notes.is_empty(), "{notes:?}");
    }

    /// **A member is removed by the key the set's own listing gave for it, and
    /// the typed name is joined into no store path** (kottonllc/kotton#610): an
    /// object listed under one key that holds a member under another DID is
    /// resolved by the DID it holds and removed at the key it was listed under;
    /// the path that DID would make holds an honest member, which stays.
    #[tokio::test]
    async fn a_member_is_removed_at_the_key_it_was_listed_under() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let members = Members::default();
        let (_, refused) = kotton_crypto::ed25519::refused_keys().remove(0);
        let earlier = own_device("did:key:zEarlier", refused);
        members
            .member_write("/network/members/did:key:zListedElsewhere", &serde_json::to_vec(&earlier).unwrap())
            .await
            .unwrap();
        let honest = kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[35u8; 32]));
        let at_its_path = own_device("did:key:zHonest", *honest.as_bytes());
        members.member_write(&kotton_schemas::membership::member_path("did:key:zEarlier"), &serde_json::to_vec(&at_its_path).unwrap()).await.unwrap();

        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        let said = revoke(&members, &db, "alice", "did:key:zEarlier", &paired_keys, Asked::Locally).await;
        assert!(matches!(said, UserResponse::NodeRevoked), "{said:?}");
        assert_eq!(members.list_members().await.unwrap(), vec![at_its_path], "the wrong object was removed");
    }

    /// **The one resolver takes a label and a DID as stored whole, by equality,
    /// and holds neither to a rule of characters** (kottonllc/kotton#597, 26A): a
    /// row whose label and whose DID as stored are neither one plain word is
    /// resolved by each and removed.
    #[tokio::test]
    async fn a_row_with_no_plain_name_is_resolved_by_each_name_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let key = kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[36u8; 32]));
        let (label, did) = ("my phone; it's \"old\"", "did:key:z an earlier spelling");
        assert!(!kotton_wire::note::one_plain_word(label) && !kotton_wire::note::one_plain_word(did));
        let paired_keys = Arc::new(RwLock::new(HashSet::from([key])));
        for name in [label, did] {
            network_db::seed_paired_node_as_stored(&db, label, "alice", did, key.as_bytes(), "[]", 0, None).await.unwrap();
            match node_named(&db, "alice", name, Reach::Rows).await.unwrap() {
                Some(Named::Row(row)) => assert_eq!(row.device_did.to_string(), did, "{name}"),
                other => panic!("{name:?} resolved to {other:?}"),
            }
            let said = revoke(&NoMembers, &db, "alice", name, &paired_keys, Asked::Remotely).await;
            assert!(matches!(said, UserResponse::NodeRevoked), "{name:?}: {said:?}");
            assert!(network_db::list_paired_nodes(&db, "alice").await.unwrap().is_empty(), "{name:?}");
        }
    }

    /// **A member whose DID as stored a row carries as its name is not noted**:
    /// `device revoke` given that name takes it to the row, so a sentence naming
    /// it would remove the row and not the member (20A).
    #[tokio::test]
    async fn a_member_whose_did_a_row_carries_is_not_noted() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let (_, refused) = kotton_crypto::ed25519::refused_keys().remove(0);
        let did = kotton_crypto::DidKeyMethod::spelled_over(&refused).to_string();
        let honest = kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[37u8; 32]));
        network_db::insert_paired_node(&db, &did, "alice", &honest, "[]", 0, None).await.unwrap();
        let members = Members::default();
        stored(&members, &own_device(&did, refused)).await;
        let (_, notes) = listed(node_list(&db, "alice".into(), Some(&members)).await.unwrap());
        assert!(notes.is_empty(), "{notes:?}");
    }

    /// **One name removes every member with no row under it, and the listing says
    /// the name once** (kottonllc/kotton#597, 35A): two own-device members carry one
    /// DID as stored under two listing keys, each under bytes the rule refuses. The
    /// listing at the machine notes that DID once; the local revoke by it removes
    /// both; the listing then notes nothing; an honest member beside them stays.
    #[tokio::test]
    async fn several_members_under_one_did_are_noted_once_and_all_removed() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let members = Members::default();
        let refused = kotton_crypto::ed25519::refused_keys();
        let did = "did:peer:twice-stored";
        for (i, (_, bytes)) in refused.iter().take(2).enumerate() {
            let m = own_device(did, *bytes);
            members.member_write(&format!("/network/members/listed-{i}"), &serde_json::to_vec(&m).unwrap()).await.unwrap();
        }
        let honest = kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[38u8; 32]));
        let stays = own_device(&kotton_crypto::DidKeyMethod::from_public_key(&honest).to_string(), *honest.as_bytes());
        members.write_member(&stays).await.unwrap();
        assert_eq!(members.list_members().await.unwrap().len(), 3);
        let paired_keys = Arc::new(RwLock::new(HashSet::from([honest])));

        let (_, notes) = listed(node_list(&db, "alice".into(), Some(&members)).await.unwrap());
        assert_eq!(notes, vec![kotton_wire::note::RowNote::names_no_key(did)], "the name is not noted once");
        let said = revoke(&members, &db, "alice", &notes[0].name, &paired_keys, Asked::Locally).await;
        assert!(matches!(said, UserResponse::NodeRevoked), "{said:?}");
        assert_eq!(members.list_members().await.unwrap(), vec![stays], "a member under the name stayed, or the honest one went");
        let (_, notes) = listed(node_list(&db, "alice".into(), Some(&members)).await.unwrap());
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(*paired_keys.read().unwrap(), HashSet::from([honest]), "the allowlist changed");
    }

    /// **A row's revoke removes the members that hold its key and leaves a second
    /// row of the person's under that key** (kottonllc/kotton#597, 34A's removal): two
    /// rows under one key, by its `did:key` and by another spelling of it, and an
    /// own-device member holding the key. Revoking the first removes it and the
    /// member, and answers an error that names the second (34A's answer); the
    /// second row stays, and the key stays on the allowlist while it pairs it.
    /// Revoking the second removes it and takes the key off.
    #[tokio::test]
    async fn a_rows_revoke_removes_its_members_and_leaves_a_second_row_under_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let key = kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[39u8; 32]));
        let did = kotton_crypto::DidKeyMethod::from_public_key(&key).to_string();
        let spelled = kotton_crypto::DidKeyMethod::spelled_otherwise(key.as_bytes()).to_string();
        network_db::insert_paired_node(&db, "laptop", "alice", &key, "[]", 0, None).await.unwrap();
        network_db::seed_paired_node_as_stored(&db, "laptop-before", "alice", &spelled, key.as_bytes(), "[]", 0, None).await.unwrap();
        let members = Members::default();
        members.write_member(&own_device(&did, *key.as_bytes())).await.unwrap();
        let paired_keys = Arc::new(RwLock::new(HashSet::from([key])));

        let said = revoke(&members, &db, "alice", "laptop", &paired_keys, Asked::Locally).await;
        assert!(matches!(&said, UserResponse::Error { message } if message.contains("`laptop-before`")), "{said:?}");
        assert!(members.list_members().await.unwrap().is_empty(), "the member that holds the key stayed");
        let left: Vec<String> = network_db::list_paired_nodes(&db, "alice").await.unwrap().iter().map(|n| n.device_did.to_string()).collect();
        assert_eq!(left, vec![spelled.clone()], "the second row went, or the first stayed");
        assert!(paired_keys.read().unwrap().contains(&key), "the key left the allowlist while a row pairs it");

        let said = revoke(&members, &db, "alice", "laptop-before", &paired_keys, Asked::Locally).await;
        assert!(matches!(said, UserResponse::NodeRevoked), "{said:?}");
        assert!(network_db::list_paired_nodes(&db, "alice").await.unwrap().is_empty(), "the second row stayed");
        assert!(paired_keys.read().unwrap().is_empty(), "the key stayed on the allowlist with no row");
    }

    /// **A member whose DID as stored a row carries is reached once that row is
    /// gone** (kottonllc/kotton#597, 36A), for a row that carries it as its DID as
    /// stored beside a key from a seed, and for one that carries it as its label:
    /// the listing at the machine notes nothing; `device revoke` of that name
    /// removes the row and leaves the member; the next listing notes the member by
    /// that DID; the local revoke by the note's name removes it.
    #[tokio::test]
    async fn a_member_whose_did_a_row_carries_is_reached_once_the_row_is_gone() {
        let (_, refused) = kotton_crypto::ed25519::refused_keys().remove(0);
        let name = "did:peer:carried-by-a-row";
        let honest = kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[40u8; 32]));
        let honest_did = kotton_crypto::DidKeyMethod::from_public_key(&honest).to_string();
        for (label, row_did) in [("laptop", name), (name, honest_did.as_str())] {
            let dir = tempfile::tempdir().unwrap();
            let db = agent_db(&dir).await;
            if row_did == honest_did {
                network_db::insert_paired_node(&db, label, "alice", &honest, "[]", 0, None).await.unwrap();
            } else {
                network_db::seed_paired_node_as_stored(&db, label, "alice", row_did, honest.as_bytes(), "[]", 0, None).await.unwrap();
            }
            let members = Members::default();
            let member = own_device(name, refused);
            stored(&members, &member).await;
            let paired_keys = Arc::new(RwLock::new(HashSet::from([honest])));

            let (nodes, notes) = listed(node_list(&db, "alice".into(), Some(&members)).await.unwrap());
            assert_eq!(nodes.len(), 1, "{label}");
            assert!(notes.is_empty(), "{label}: {notes:?}");
            let said = revoke(&members, &db, "alice", name, &paired_keys, Asked::Locally).await;
            assert!(matches!(said, UserResponse::NodeRevoked), "{label}: {said:?}");
            assert!(network_db::list_paired_nodes(&db, "alice").await.unwrap().is_empty(), "{label}: the row stayed");
            assert_eq!(members.list_members().await.unwrap(), vec![member.clone()], "{label}: the member went with the row");

            let (_, notes) = listed(node_list(&db, "alice".into(), Some(&members)).await.unwrap());
            assert_eq!(notes, vec![kotton_wire::note::RowNote::names_no_key(name)], "{label}");
            let said = revoke(&members, &db, "alice", &notes[0].name, &paired_keys, Asked::Locally).await;
            assert!(matches!(said, UserResponse::NodeRevoked), "{label}: {said:?}");
            assert!(members.list_members().await.unwrap().is_empty(), "{label}: the member stayed");
        }
    }

    /// **"No row" is read by bytes** (kottonllc/kotton#597, 5B): a row under its
    /// key's `did:key`, and an own-device member holding the same key under another
    /// spelling of it. `device revoke` of the member's DID, asked at the machine, is
    /// not found, and the row and the member stay: the row stands for the member,
    /// and is reached by its own names.
    #[tokio::test]
    async fn a_members_did_whose_key_a_row_holds_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let key = kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[41u8; 32]));
        let spelled = kotton_crypto::DidKeyMethod::spelled_otherwise(key.as_bytes()).to_string();
        network_db::insert_paired_node(&db, "laptop", "alice", &key, "[]", 0, None).await.unwrap();
        let members = Members::default();
        let member = own_device(&spelled, *key.as_bytes());
        stored(&members, &member).await;
        let paired_keys = Arc::new(RwLock::new(HashSet::from([key])));

        let said = revoke(&members, &db, "alice", &spelled, &paired_keys, Asked::Locally).await;
        assert!(matches!(&said, UserResponse::Error { message } if message.contains("not found")), "{said:?}");
        assert_eq!(network_db::list_paired_nodes(&db, "alice").await.unwrap().len(), 1, "the row went");
        assert_eq!(members.list_members().await.unwrap(), vec![member], "the member went");
        assert!(paired_keys.read().unwrap().contains(&key), "the key left the allowlist");
    }

    fn listed(said: UserResponse) -> (Vec<PairedNode>, Vec<kotton_wire::note::RowNote>) {
        match said {
            UserResponse::NodeList { nodes, notes } => (nodes, notes),
            other => panic!("the listing answered {other:?}"),
        }
    }

    /// **The node listing notes a row under bytes the rule refuses, by the
    /// name `device revoke` takes, and the revoke by that name removes it**
    /// (kottonllc/kotton#605), for every key vector the rule refuses. The
    /// honest row beside it carries no note, and after the revoke the listing
    /// carries none.
    #[tokio::test]
    async fn the_node_listing_notes_a_row_that_names_no_key_and_its_revoke_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let honest = kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[12u8; 32]));
        let honest_did = kotton_crypto::DidKeyMethod::from_public_key(&honest).to_string();
        network_db::insert_paired_node(&db, "laptop", "alice", &honest, "[]", 0, None).await.unwrap();
        let paired_keys = Arc::new(RwLock::new(HashSet::from([honest])));

        for (name, bytes) in kotton_crypto::ed25519::refused_keys() {
            let did = kotton_crypto::DidKeyMethod::spelled_over(&bytes).to_string();
            network_db::seed_paired_node_as_stored(&db, "old", "alice", &did, &bytes, "[]", 0, None).await.unwrap();
            let (nodes, notes) = listed(node_list(&db, "alice".into(), None).await.unwrap());
            assert_eq!(nodes.len(), 2, "{name}: the row is listed as any other");
            assert_eq!(notes, vec![kotton_wire::note::RowNote::names_no_key("old")], "{name}");

            let said = revoke(&NoMembers, &db, "alice", &notes[0].name, &paired_keys, Asked::Locally).await;
            assert!(matches!(said, UserResponse::NodeRevoked), "{name}: {said:?}");
            let (nodes, notes) = listed(node_list(&db, "alice".into(), None).await.unwrap());
            assert_eq!(nodes.iter().map(|n| n.device_did.to_string()).collect::<Vec<_>>(), vec![honest_did.clone()], "{name}");
            assert!(notes.is_empty(), "{name}: {notes:?}");
        }
    }

    /// **A note's name is one `device revoke` takes to its row**: the label
    /// where the resolver takes the label to this row, the DID as stored
    /// where the label is two rows' or is another row's DID. Every note's
    /// name resolves, through [`network_db::paired_node_named`], to the row it
    /// notes.
    #[tokio::test]
    async fn every_notes_name_resolves_to_its_row() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let refused = kotton_crypto::ed25519::refused_keys();
        let row = |i: usize| (refused[i].1, kotton_crypto::DidKeyMethod::spelled_over(&refused[i].1).to_string());
        let (one, one_did) = row(0);
        let (two, two_did) = row(1);
        let (three, three_did) = row(2);
        let (four, four_did) = row(3);
        // A label only this row carries.
        network_db::seed_paired_node_as_stored(&db, "attic", "alice", &one_did, &one, "[]", 0, None).await.unwrap();
        // A label two rows carry.
        network_db::seed_paired_node_as_stored(&db, "twin", "alice", &two_did, &two, "[]", 0, None).await.unwrap();
        network_db::seed_paired_node_as_stored(&db, "twin", "alice", &three_did, &three, "[]", 0, None).await.unwrap();
        // A label that is another row's DID.
        network_db::seed_paired_node_as_stored(&db, &one_did, "alice", &four_did, &four, "[]", 0, None).await.unwrap();

        let (nodes, notes) = listed(node_list(&db, "alice".into(), None).await.unwrap());
        assert_eq!(notes.len(), 4, "{notes:?}");
        let name_of = |did: &str| notes.iter().zip(nodes.iter()).find(|(_, n)| n.device_did.to_string() == did).map(|(note, _)| note.name.clone()).unwrap();
        assert_eq!(name_of(&one_did), "attic");
        assert_eq!(name_of(&two_did), two_did);
        assert_eq!(name_of(&three_did), three_did);
        assert_eq!(name_of(&four_did), four_did, "a label that is another row's DID finds that row");
        for (note, node) in notes.iter().zip(&nodes) {
            let found = network_db::paired_node_named(&db, "alice", &note.name).await.unwrap().expect("the name finds a row");
            assert_eq!(found.device_did.to_string(), node.device_did.to_string(), "{} finds another row", note.name);
        }
    }

    /// The labels a note's name is held over where the shell reads a typed line
    /// in words: each is not one plain word.
    const LABELS_NOT_ONE_WORD: &[&str] =
        &["my phone", "a;b", "a|b", "a&&b", "it's", "say\"x", "a`b", "--old", "--browser", "bell\u{7}"];

    /// **A note's name is one word the shell takes to its row** (20A): a label
    /// that is not one plain word is not a note's name, and the note names the
    /// row by its DID as stored, which is one and which
    /// [`network_db::paired_node_named`] takes to the noted row. A label that is
    /// one plain word is the note's name and resolves to its row.
    #[tokio::test]
    async fn a_notes_name_is_one_word_the_shell_takes_to_its_row() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let (_, bytes) = kotton_crypto::ed25519::refused_keys()[0];
        let did = kotton_crypto::DidKeyMethod::spelled_over(&bytes).to_string();
        assert!(kotton_wire::note::one_plain_word(&did), "the DID as stored is not one plain word: {did}");
        for (i, label) in LABELS_NOT_ONE_WORD.iter().copied().chain(["attic"]).enumerate() {
            let user = format!("person-{i}");
            network_db::seed_paired_node_as_stored(&db, label, &user, &did, &bytes, "[]", 0, None).await.unwrap();
            let (nodes, notes) = listed(node_list(&db, user.clone(), None).await.unwrap());
            assert_eq!((nodes.len(), notes.len()), (1, 1), "{label:?}");
            let name = &notes[0].name;
            let want = if label == "attic" { label } else { did.as_str() };
            assert_eq!(name, want, "{label:?}");
            assert!(kotton_wire::note::one_plain_word(name), "{label:?}: {name:?}");
            let found = network_db::paired_node_named(&db, &user, name).await.unwrap().expect("the name finds a row");
            assert_eq!(found.device_did.to_string(), did, "{label:?}");
            assert_eq!(found.id, label, "{label:?}");
        }

        // A DID as stored whose identifier is not one plain word, under a label
        // that is not one either: the note is carried, under the DID as stored,
        // and its sentence names its verb and composes no command (23A).
        let odd = "did:key:RD/T4NHD S5UEFOU51W*VRLU7R";
        network_db::seed_paired_node_as_stored(&db, "my phone", "person-odd", odd, &bytes, "[]", 0, None).await.unwrap();
        let (_, notes) = listed(node_list(&db, "person-odd".into(), None).await.unwrap());
        assert_eq!(notes, vec![kotton_wire::note::RowNote::names_no_key(odd)]);
        let said = kotton_wire::note::sentence(&notes[0], "device revoke");
        assert!(said.contains("names no Ed25519 key") && said.contains("`device revoke` is the verb that removes it, by this name, as recorded"), "{said}");
        assert!(!said.contains("device revoke "), "{said}");
    }

    /// **The second kind's name is one word too**: a row under another spelling
    /// whose label is not one plain word is named by its DID as stored, and its
    /// sentence says a command takes that recorded name, which resolves to it.
    #[tokio::test]
    async fn the_second_kinds_name_is_one_word_the_shell_takes_to_its_row() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let spellings = include_str!("../../../wire/src/did/did-key-spellings.txt");
        let mut lines = spellings.lines().filter(|l| !l.starts_with('#')).map(|l| l.split_once(' ').unwrap().1);
        let did_key = lines.next().unwrap().to_string();
        let other = lines.next().unwrap().to_string();
        let key = kotton_crypto::DidKeyMethod::to_public_key(&did_key.parse().unwrap()).unwrap();
        assert!(kotton_wire::note::one_plain_word(&other), "{other}");
        for (i, label) in LABELS_NOT_ONE_WORD.iter().enumerate() {
            let user = format!("person-{i}");
            network_db::seed_paired_node_as_stored(&db, label, &user, &other, key.as_bytes(), "[]", 0, None).await.unwrap();
            let (_, notes) = listed(node_list(&db, user.clone(), None).await.unwrap());
            assert_eq!(
                notes,
                vec![kotton_wire::note::RowNote {
                    name: other.clone(),
                    is: kotton_wire::note::NoteKind::StandsByBytes { did_key: did_key.clone(), stored: other.clone() },
                }],
                "{label:?}"
            );
            let said = kotton_wire::note::sentence(&notes[0], "device revoke");
            assert!(said.ends_with("takes that recorded name, not the key's") && !said.contains(label), "{said}");
            let found = network_db::paired_node_named(&db, &user, &other).await.unwrap().expect("the name finds a row");
            assert_eq!(found.id, *label);
        }
    }

    /// **A row whose bytes pass under a `did:key` spelled another way is
    /// noted with its key's `did:key` and the DID as stored, and is admitted
    /// after the listing as before it** (5B, 18B).
    #[tokio::test]
    async fn a_row_under_another_spelling_is_noted_as_standing_by_its_bytes_and_still_admitted() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let spellings = include_str!("../../../wire/src/did/did-key-spellings.txt");
        let mut lines = spellings.lines().filter(|l| !l.starts_with('#')).map(|l| l.split_once(' ').unwrap().1);
        let did_key = lines.next().unwrap().to_string();
        let other = lines.next().unwrap().to_string();
        let key = kotton_crypto::DidKeyMethod::to_public_key(&did_key.parse().unwrap()).unwrap();
        network_db::seed_paired_node_as_stored(&db, "phone", "alice", &other, key.as_bytes(), "[]", 0, None).await.unwrap();
        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        let none: Vec<(String, Arc<dyn crate::membership::MemberStore>)> = vec![("alice".into(), Arc::new(NoMembers))];

        reproject_allowlist(&none, &db, &paired_keys).await;
        assert!(paired_keys.read().unwrap().contains(&key), "the row is not admitted before the listing");
        let (_, notes) = listed(node_list(&db, "alice".into(), None).await.unwrap());
        assert_eq!(
            notes,
            vec![kotton_wire::note::RowNote {
                name: "phone".into(),
                is: kotton_wire::note::NoteKind::StandsByBytes { did_key: did_key.clone(), stored: other.clone() },
            }]
        );
        let said = kotton_wire::note::sentence(&notes[0], "device revoke");
        assert!(!said.contains("device revoke"), "{said}");
        reproject_allowlist(&none, &db, &paired_keys).await;
        assert!(paired_keys.read().unwrap().contains(&key), "the row is not admitted after the listing");
    }
}

#[cfg(test)]
mod streaming_confirmer {
    use super::*;
    use std::time::Duration;

    fn a_confirmer() -> (StreamingConfirmer, mpsc::Receiver<UserResponse>, PendingConfirms) {
        let (tx, rx) = mpsc::channel(16);
        let pending = PendingConfirms::default();
        (StreamingConfirmer::new(tx, Arc::clone(&pending), Duration::from_secs(60)), rx, pending)
    }

    async fn token_shown(rx: &mut mpsc::Receiver<UserResponse>) -> String {
        match rx.recv().await {
            Some(UserResponse::PairShowCode { token, .. }) => token.expose().to_string(),
            other => panic!("expected the digits, got {other:?}"),
        }
    }

    /// **A confirmer whose stream closes while it waits declines, and parks
    /// nothing (#436).** The digits are shown, the stream's receiver is
    /// dropped, and the wait ends at once — not at the 60 s ttl — as a no;
    /// the token is gone, so a later yes for it reaches nothing.
    #[tokio::test]
    async fn a_closed_stream_declines_the_wait_and_unparks_its_token() {
        let (confirmer, mut rx, pending) = a_confirmer();
        let waiting = tokio::spawn(async move { confirmer.confirm(123_456, None).await });
        let token = token_shown(&mut rx).await;
        assert!(pending.lock().await.contains_key(&token), "the shown token is parked");

        drop(rx);
        let said = tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .expect("the wait outlived its stream")
            .unwrap();
        assert!(!said, "a closed stream was taken as a yes");
        assert!(pending.lock().await.is_empty(), "the token is still parked");
        let ack = confirm_code(&pending, token, true).await.unwrap();
        assert!(matches!(ack, UserResponse::PairConfirmAck), "{ack:?}");
    }

    /// **A ceremony is abandoned with its stream before the yes, and run to
    /// its end after it.** Before the yes nothing has crossed, so the stream
    /// closing ends it there; after the yes the payload crosses and each side
    /// records what it kept, so it is not dropped part-way.
    #[tokio::test]
    async fn a_ceremony_is_abandoned_before_the_yes_and_not_after() {
        let (confirmer, rx, _) = a_confirmer();
        drop(rx);
        let ended = tokio::time::timeout(
            Duration::from_secs(10),
            confirmer.unless_abandoned(std::future::pending::<()>()),
        )
        .await
        .expect("a ceremony before its yes outlived its stream");
        assert!(ended.is_none(), "an abandoned ceremony said it finished");

        let (confirmer, mut rx, pending) = a_confirmer();
        let confirmer = Arc::new(confirmer);
        let asked = Arc::clone(&confirmer);
        let ceremony = tokio::spawn(async move {
            asked
                .unless_abandoned(async {
                    assert!(asked.confirm(123_456, None).await, "the yes was not taken");
                    // The stream closes past the yes, while the payload would cross.
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    "recorded"
                })
                .await
        });
        let token = token_shown(&mut rx).await;
        confirm_code(&pending, token, true).await.unwrap();
        assert!(matches!(rx.recv().await, Some(UserResponse::PairAwaitingPeer)));
        drop(rx);
        let finished = tokio::time::timeout(Duration::from_secs(10), ceremony).await.expect("ran").unwrap();
        assert_eq!(finished, Some("recorded"), "a ceremony past its yes was dropped part-way");
    }
}

/// Who a threshold round dials, and what `peer add` stores beside a key
/// (kottonllc/kotton#609): a co-signer is chosen by its key's bytes, and the DID
/// a row is added under is the derivation's string for those bytes.
#[cfg(test)]
mod chosen_by_key {
    use super::*;
    use kotton_crypto::DidKeyMethod;

    fn key(seed: u8) -> VerifyingKey {
        kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[seed; 32]))
    }

    fn member(did: &Did, public_key: [u8; 32], posture: Posture) -> Member {
        Member {
            did: did.to_string(),
            public_key,
            role: Role::OwnDevice,
            admitted_by: Ceremony::DeviceEnroll,
            added_at: "2026-11-17T00:00:00Z".to_string(),
            posture: Some(posture),
            label: None,
            reach: None,
        }
    }

    fn row(id: &str, did: Did, public_key: [u8; 32]) -> PairedNode {
        PairedNode {
            id: id.to_string(),
            device_did: did,
            public_key,
            paired_at: 0,
            addresses: Vec::new(),
            relay_url: None,
            posture: None,
        }
    }

    fn ids(nodes: &[PairedNode]) -> Vec<&str> {
        nodes.iter().map(|n| n.id.as_str()).collect()
    }

    /// **A row stored under another spelling of a member's key is that member's
    /// co-signer.** The member is named by its key's `did:key`; the row holds
    /// the same key's bytes beside another spelling of it. A `Cosigner` member
    /// is chosen the same way; a `BlindStorage` member holds no share and is not.
    #[test]
    fn a_row_under_another_spelling_of_a_members_key_is_chosen() {
        let (full, cosigner, blind) = (key(31), key(32), key(33));
        let members = vec![
            member(&DidKeyMethod::from_public_key(&full), *full.as_bytes(), Posture::Full),
            member(&DidKeyMethod::from_public_key(&cosigner), *cosigner.as_bytes(), Posture::Cosigner),
            member(&DidKeyMethod::from_public_key(&blind), *blind.as_bytes(), Posture::BlindStorage),
        ];
        let rows = vec![
            row("laptop", DidKeyMethod::spelled_otherwise(full.as_bytes()), *full.as_bytes()),
            row("phone", DidKeyMethod::spelled_otherwise(cosigner.as_bytes()), *cosigner.as_bytes()),
            row("vault", DidKeyMethod::from_public_key(&blind), *blind.as_bytes()),
        ];
        assert_eq!(ids(&cosigner_nodes(&members, rows)), vec!["laptop", "phone"]);
    }

    /// **A row whose stored DID names a member, beside a different key, is not
    /// chosen.** The DID beside a row's bytes is not read as a key's name, so
    /// the member's own DID on a row holding another key dials no one.
    #[test]
    fn a_row_under_a_members_did_beside_another_key_is_not_chosen() {
        let (signer, other) = (key(34), key(35));
        let signer_did = DidKeyMethod::from_public_key(&signer);
        let members = vec![member(&signer_did, *signer.as_bytes(), Posture::Full)];
        let rows = vec![row("not-the-signer", signer_did, *other.as_bytes())];
        assert!(cosigner_nodes(&members, rows).is_empty());
    }

    /// **A member under bytes the Ed25519 rule refuses chooses no row**, for
    /// every vector in `kotton_ed25519::refused`, even a row stored under the
    /// same bytes and the same string: nothing is dialled for a signature under
    /// bytes that are no key.
    #[test]
    fn a_member_under_bytes_the_rule_refuses_chooses_no_row() {
        for (name, bytes) in kotton_crypto::ed25519::refused_keys() {
            let did = DidKeyMethod::spelled_over(&bytes);
            let members = vec![member(&did, bytes, Posture::Full)];
            let rows = vec![row("old", did, bytes)];
            assert!(cosigner_nodes(&members, rows).is_empty(), "{name}: a row was chosen");
        }
    }

    /// **A key held by two rows is dialled once**, through the row the key is
    /// reached through ([`network_db::reached_through`], kottonllc/kotton#622),
    /// in whichever order the rows are handed: one co-signer is one share in
    /// the round. Paired at one time, that is the row under the lower DID.
    #[test]
    fn a_key_held_by_two_rows_is_dialled_once() {
        let signer = key(36);
        let members = vec![member(&DidKeyMethod::from_public_key(&signer), *signer.as_bytes(), Posture::Full)];
        let (derived, spelled) = (DidKeyMethod::from_public_key(&signer), DidKeyMethod::spelled_otherwise(signer.as_bytes()));
        let want = if derived.to_string() < spelled.to_string() { "derived" } else { "spelled" };
        let rows = vec![row("derived", derived, *signer.as_bytes()), row("spelled", spelled, *signer.as_bytes())];
        assert_eq!(ids(&cosigner_nodes(&members, rows.clone())), vec![want]);
        assert_eq!(ids(&cosigner_nodes(&members, rows.into_iter().rev().collect())), vec![want]);
    }

    /// **The first row the store lists is the one dialled**, against the store's
    /// own order rather than a list put in order by hand: two rows for one key
    /// written through the store, the more recently paired written first, and
    /// the round dials the one `list_paired_nodes` lists first, the more
    /// recently paired, once.
    #[tokio::test]
    async fn a_key_held_by_two_stored_rows_is_dialled_through_the_one_the_store_lists_first() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let signer = key(40);
        let members = vec![member(&DidKeyMethod::from_public_key(&signer), *signer.as_bytes(), Posture::Full)];
        let (newer, older) = (
            DidKeyMethod::spelled_otherwise(signer.as_bytes()).to_string(),
            DidKeyMethod::from_public_key(&signer).to_string(),
        );
        network_db::seed_paired_node_as_stored(&db, "newer", "alice", &newer, signer.as_bytes(), "[]", 200, None).await.unwrap();
        network_db::seed_paired_node_as_stored(&db, "older", "alice", &older, signer.as_bytes(), "[]", 100, None).await.unwrap();

        let listed = network_db::list_paired_nodes(&db, "alice").await.unwrap();
        assert_eq!(ids(&listed), vec!["newer", "older"], "the premise: the store lists the more recently paired first");
        assert_eq!(ids(&cosigner_nodes(&members, listed)), vec!["newer"]);
    }

    /// **A row under bytes the Ed25519 rule refuses is not re-addressed**, for
    /// every vector in `kotton_ed25519::refused`: the address is as it was and
    /// nothing is admitted.
    #[tokio::test]
    async fn peer_readdress_leaves_a_row_under_bytes_the_rule_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        for (name, bytes) in kotton_crypto::ed25519::refused_keys() {
            let did = DidKeyMethod::spelled_over(&bytes).to_string();
            network_db::seed_paired_node_as_stored(&db, &name, "alice", &did, &bytes, "[]", 0, None).await.unwrap();
            let said = peer_readdress(&db, &paired_keys, "alice", &bytes, "127.0.0.1:7".parse().unwrap()).await;
            assert!(said.is_err(), "{name}: re-addressed: {said:?}");
            let row = network_db::get_paired_node(&db, "alice", &did).await.unwrap().expect("the row stands");
            assert!(row.addresses.is_empty(), "{name}: the row was re-addressed");
            assert!(paired_keys.read().unwrap().is_empty(), "{name}: something was admitted");
        }
    }

    async fn agent_db(dir: &tempfile::TempDir) -> Arc<SqlitePool> {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("agent.db"))
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::migrate!("../device/migrations").run(&pool).await.unwrap();
        Arc::new(pool)
    }

    /// **`peer add` stores the derivation's string for the key it stores.**
    #[tokio::test]
    async fn peer_add_stores_the_did_key_of_the_key_it_stores() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        let added = key(37);
        let did = DidKeyMethod::from_public_key(&added).to_string();

        let said = peer_add(&db, &paired_keys, "alice".into(), "laptop".into(), did.clone(), hex::encode(added.as_bytes()), "127.0.0.1:7".parse().unwrap())
            .await
            .expect("the key's own did:key is added");
        let UserResponse::NodePaired { node } = said else { panic!("{said:?}") };
        assert_eq!(node.device_did.to_string(), did);
        let rows = network_db::list_paired_nodes(&db, "alice").await.unwrap();
        assert_eq!(rows.iter().map(|n| (n.device_did.to_string(), n.public_key)).collect::<Vec<_>>(), vec![(did, *added.as_bytes())]);
        assert!(paired_keys.read().unwrap().contains(&added));
    }

    /// **`peer add` refuses a DID that is not the derivation's string for the
    /// key beside it**: another spelling of that key's `did:key`, another key's
    /// `did:key`, and a DID of another method. Nothing is stored and nothing is
    /// admitted.
    #[tokio::test]
    async fn peer_add_refuses_a_did_that_is_not_its_keys() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        let added = key(38);
        let refused = [
            ("another spelling", DidKeyMethod::spelled_otherwise(added.as_bytes()).to_string()),
            ("another key's did:key", DidKeyMethod::from_public_key(&key(39)).to_string()),
            ("another method", "did:web:example.com".to_string()),
        ];
        for (name, did) in refused {
            let said = peer_add(&db, &paired_keys, "alice".into(), "laptop".into(), did, hex::encode(added.as_bytes()), "127.0.0.1:7".parse().unwrap()).await;
            let e = said.expect_err(&format!("{name}: added"));
            assert!(
                e.to_string().contains("<did>")
                    && e.to_string().contains("<pubkey-hex>")
                    && e.to_string().contains(&DidKeyMethod::from_public_key(&added).to_string()),
                "{name}: the refusal does not name the usage's arguments and the key's did:key: {e}"
            );
            assert!(network_db::list_paired_nodes(&db, "alice").await.unwrap().is_empty(), "{name}: a row was stored");
            assert!(paired_keys.read().unwrap().is_empty(), "{name}: the key was admitted");
        }
    }
}

/// **A row is named by its key, and no writer hands the store a second name**
/// (kottonllc/kotton#624; kottonllc/kotton#597, 27A, 28A, 30A, 65A, 69A): the
/// store's writer, the membership projection and `peer add`, each with keys
/// from seeds.
#[cfg(test)]
mod named_by_key {
    use super::*;
    use crate::membership::MemberStore;
    use kotton_crypto::DidKeyMethod;

    fn key(seed: u8) -> VerifyingKey {
        kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[seed; 32]))
    }

    fn derived(key: &VerifyingKey) -> String {
        DidKeyMethod::from_public_key(key).to_string()
    }

    fn spelled(key: &VerifyingKey) -> String {
        DidKeyMethod::spelled_otherwise(key.as_bytes()).to_string()
    }

    async fn agent_db(dir: &tempfile::TempDir) -> Arc<SqlitePool> {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("agent.db"))
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::migrate!("../device/migrations").run(&pool).await.unwrap();
        Arc::new(pool)
    }

    /// One row as the store holds it: label, DID, key, addresses, time, posture, relay.
    type Stored = (String, String, Vec<u8>, String, i64, Option<String>, Option<String>);

    /// Every row of `user`'s, column for column, in DID order.
    async fn rows(db: &Arc<SqlitePool>, user: &str) -> Vec<Stored> {
        sqlx::query_as(
            "SELECT id, device_did, public_key, addresses, paired_at, posture, relay_url FROM paired_nodes \
             WHERE user_id = ? ORDER BY device_did",
        )
        .bind(user)
        .fetch_all(db.as_ref())
        .await
        .unwrap()
    }

    /// A member store that keeps what it is told.
    #[derive(Default)]
    struct Members(std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>);

    #[async_trait::async_trait]
    impl MemberStore for Members {
        async fn member_write(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
            self.0.lock().unwrap().insert(path.to_string(), data.to_vec());
            Ok(())
        }
        async fn member_read(&self, path: &str) -> anyhow::Result<Vec<u8>> {
            self.0.lock().unwrap().get(path).cloned().ok_or_else(|| anyhow::anyhow!("no member at {path}"))
        }
        async fn member_delete(&self, path: &str) -> anyhow::Result<()> {
            self.0.lock().unwrap().remove(path);
            Ok(())
        }
        async fn member_list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
            Ok(self.0.lock().unwrap().keys().filter(|k| k.starts_with(prefix)).cloned().collect())
        }
    }

    fn own_device(did: &str, key: &VerifyingKey, label: Option<&str>) -> Member {
        Member {
            did: did.to_string(),
            public_key: *key.as_bytes(),
            role: Role::OwnDevice,
            admitted_by: Ceremony::DeviceEnroll,
            added_at: "2026-11-21T00:00:00Z".to_string(),
            posture: Some(Posture::Full),
            label: label.map(str::to_string),
            reach: None,
        }
    }

    const AT: &str = r#"["127.0.0.1:7"]"#;

    /// **A new row is written under its key's derivation**, and the writer
    /// returns it as stored.
    #[tokio::test]
    async fn the_writer_names_a_new_row_by_its_keys_derivation() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        for (seed, label) in [(51u8, "laptop"), (52, "phone")] {
            let k = key(seed);
            let node = network_db::insert_paired_node(&db, label, "alice", &k, AT, 10, Some("full")).await.unwrap();
            assert_eq!(node.device_did.to_string(), derived(&k), "{label}");
            assert_eq!((node.id.as_str(), node.public_key), (label, *k.as_bytes()), "{label}");
        }
        let stored: Vec<(String, Vec<u8>)> = rows(&db, "alice").await.into_iter().map(|r| (r.1, r.2)).collect();
        let mut want = vec![(derived(&key(51)), key(51).as_bytes().to_vec()), (derived(&key(52)), key(52).as_bytes().to_vec())];
        want.sort();
        assert_eq!(stored, want);
    }

    /// **A key with a row under another spelling rewrites that row in place**,
    /// under its DID as stored: the label, address and time the write brings,
    /// the posture where it brings one, and the relay the row was last known
    /// at; no second row. The writer returns the row under that DID.
    #[tokio::test]
    async fn a_key_with_a_row_under_another_spelling_is_rewritten_under_its_did_as_stored() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let k = key(53);
        let stored = spelled(&k);
        network_db::seed_paired_node_as_stored(&db, "old-laptop", "alice", &stored, k.as_bytes(), "[]", 5, Some("full")).await.unwrap();
        network_db::update_paired_node_relay(&db, "alice", &stored, Some("https://relay.test")).await.unwrap();

        let node = network_db::insert_paired_node(&db, "laptop", "alice", &k, AT, 10, None).await.unwrap();
        assert_eq!(node.device_did.to_string(), stored, "the writer did not return the row as stored");
        let relay = Some("https://relay.test".to_string());
        assert_eq!(
            rows(&db, "alice").await,
            vec![("laptop".into(), stored.clone(), k.as_bytes().to_vec(), AT.into(), 10, Some("full".into()), relay.clone())]
        );

        network_db::insert_paired_node(&db, "laptop", "alice", &k, AT, 11, Some("cosigner")).await.unwrap();
        assert_eq!(
            rows(&db, "alice").await,
            vec![("laptop".into(), stored, k.as_bytes().to_vec(), AT.into(), 11, Some("cosigner".into()), relay)]
        );
    }

    /// **The derivation's string as a row's DID beside another key refuses the
    /// write, which names the row and writes nothing**, in both of the writer's
    /// forms.
    #[tokio::test]
    async fn the_derivation_as_a_rows_did_beside_another_key_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let (k, other) = (key(54), key(55));
        let did = derived(&k);
        network_db::seed_paired_node_as_stored(&db, "attic", "alice", &did, other.as_bytes(), "[]", 5, Some("full")).await.unwrap();
        let before = rows(&db, "alice").await;

        let refused = [
            network_db::insert_paired_node(&db, "laptop", "alice", &k, AT, 10, None).await.map(|_| ()),
            network_db::add_paired_node_if_absent(&db, "laptop", "alice", &k, AT, 10, None).await.map(|_| ()),
        ];
        for said in refused {
            let why = said.expect_err("written over a row beside another key").to_string();
            assert!(
                why.contains(&kotton_wire::note::quoted("attic")) && why.contains(&did) && why.contains("nothing was written") && why.contains("device revoke"),
                "{why}"
            );
            assert_eq!(rows(&db, "alice").await, before, "the store changed");
        }
        // Another person's row under the same string is theirs, and refuses nothing.
        let node = network_db::insert_paired_node(&db, "laptop", "bob", &k, AT, 10, None).await.unwrap();
        assert_eq!(node.device_did.to_string(), did);
    }

    /// **Two rows for one key, written at different times, one of them
    /// `gateway`** (65A): a write rewrites the one `list_paired_nodes` lists
    /// first, the more recently paired; the other is byte for byte as it was;
    /// no third row is written; and the key is still read as a gateway's.
    #[tokio::test]
    async fn two_rows_for_one_key_one_a_gateway_the_first_listed_is_rewritten() {
        let k = key(56);
        for (gateway_at, full_at) in [(200, 100), (100, 200)] {
            let dir = tempfile::tempdir().unwrap();
            let db = agent_db(&dir).await;
            let (gateway_did, full_did) = (derived(&k), spelled(&k));
            network_db::seed_paired_node_as_stored(&db, "front-door", "alice", &gateway_did, k.as_bytes(), "[]", gateway_at, Some("gateway"))
                .await
                .unwrap();
            network_db::seed_paired_node_as_stored(&db, "laptop", "alice", &full_did, k.as_bytes(), "[]", full_at, Some("full"))
                .await
                .unwrap();
            let before = rows(&db, "alice").await;
            let first = network_db::list_paired_nodes(&db, "alice").await.unwrap()[0].device_did.to_string();
            let want_first = if gateway_at > full_at { &gateway_did } else { &full_did };
            assert_eq!(&first, want_first, "the premise: the more recently paired is listed first");

            let node = network_db::insert_paired_node(&db, "renamed", "alice", &k, AT, 300, None).await.unwrap();
            assert_eq!(node.device_did.to_string(), first, "{gateway_at}: another row was rewritten");
            let after = rows(&db, "alice").await;
            assert_eq!(after.len(), 2, "{gateway_at}: a row was added or removed: {after:?}");
            for (was, now) in before.iter().zip(&after) {
                if was.1 == first {
                    assert_eq!((now.0.as_str(), now.3.as_str(), now.4, &now.5), ("renamed", AT, 300, &was.5), "{gateway_at}");
                } else {
                    assert_eq!(now, was, "{gateway_at}: the other row changed");
                }
            }
            assert_eq!(
                network_db::paired_posture_for_user(&db, k.as_bytes(), "alice").await.unwrap(),
                Some(Some("gateway".to_string())),
                "{gateway_at}: the key is no longer read as a gateway's"
            );
        }
    }

    /// **The add-only form writes no row and changes none where a row holds the
    /// key** (69A), and writes under the derivation where none does.
    #[tokio::test]
    async fn the_add_only_form_changes_no_row_that_holds_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let (held, free) = (key(57), key(58));
        network_db::seed_paired_node_as_stored(&db, "laptop", "alice", &spelled(&held), held.as_bytes(), AT, 5, Some("full")).await.unwrap();
        let before = rows(&db, "alice").await;
        assert!(network_db::add_paired_node_if_absent(&db, "recovered", "alice", &held, "[]", 10, None).await.unwrap().is_none());
        assert_eq!(rows(&db, "alice").await, before, "a row that holds the key was changed");

        let node = network_db::add_paired_node_if_absent(&db, "recovered", "alice", &free, "[]", 10, None).await.unwrap();
        assert_eq!(node.map(|n| n.device_did.to_string()), Some(derived(&free)));
        assert_eq!(rows(&db, "alice").await.len(), 2);
    }

    /// **The projection writes a member's row under its key's derivation, with
    /// the member's label where it has one**, and the derivation where it has none.
    #[tokio::test]
    async fn the_projection_writes_a_members_row_under_its_keys_derivation_with_its_label() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let (named, unnamed) = (key(59), key(60));
        let members = Members::default();
        members.write_member(&own_device(&derived(&named), &named, Some("phone"))).await.unwrap();
        members.write_member(&own_device(&derived(&unnamed), &unnamed, None)).await.unwrap();
        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        project_membership_into_allowlist(&members, &db, &paired_keys, "alice").await;

        let mut got: Vec<(String, String)> = rows(&db, "alice").await.into_iter().map(|r| (r.0, r.1)).collect();
        got.sort();
        let mut want = vec![("phone".to_string(), derived(&named)), (derived(&unnamed), derived(&unnamed))];
        want.sort();
        assert_eq!(got, want);
    }

    /// **An own-device member under another spelling has one row, under its
    /// key's derivation, and is admitted; the member is unchanged in the set**
    /// (28A, 5B).
    #[tokio::test]
    async fn an_own_device_member_under_another_spelling_has_one_row_under_its_keys_derivation() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let k = key(61);
        let members = Members::default();
        // As an earlier build wrote it: `write_member` writes no such member.
        let m = own_device(&spelled(&k), &k, Some("laptop"));
        members.member_write(&m.vfs_path(), &serde_json::to_vec(&m).unwrap()).await.unwrap();
        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        for _ in 0..2 {
            project_membership_into_allowlist(&members, &db, &paired_keys, "alice").await;
        }
        let stored: Vec<(String, String, Vec<u8>)> = rows(&db, "alice").await.into_iter().map(|r| (r.0, r.1, r.2)).collect();
        assert_eq!(stored, vec![("laptop".to_string(), derived(&k), k.as_bytes().to_vec())]);
        assert!(paired_keys.read().unwrap().contains(&k), "the member's key is not admitted");
        assert_eq!(members.list_members().await.unwrap(), vec![m], "the member changed in the set");
    }

    /// **The projection leaves a row that holds a member's key byte for byte as
    /// it was** (69A), whatever DID the row is stored under, and admits the key.
    #[tokio::test]
    async fn the_projection_leaves_a_row_under_another_spelling_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let k = key(62);
        network_db::seed_paired_node_as_stored(&db, "old-laptop", "alice", &spelled(&k), k.as_bytes(), AT, 5, Some("cosigner")).await.unwrap();
        let before = rows(&db, "alice").await;
        let members = Members::default();
        members.write_member(&own_device(&derived(&k), &k, Some("laptop"))).await.unwrap();
        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        project_membership_into_allowlist(&members, &db, &paired_keys, "alice").await;
        assert_eq!(rows(&db, "alice").await, before);
        assert!(paired_keys.read().unwrap().contains(&k));
    }

    /// **`peer add` of a key that has a row under another spelling rewrites that
    /// row**, under its DID as stored, with the label and address it brings and
    /// the posture the row had; it answers with that row, and adds none.
    #[tokio::test]
    async fn peer_add_of_a_key_with_a_row_under_another_spelling_rewrites_that_row() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let paired_keys = Arc::new(RwLock::new(HashSet::new()));
        let k = key(63);
        let stored = spelled(&k);
        network_db::seed_paired_node_as_stored(&db, "old", "alice", &stored, k.as_bytes(), "[]", 5, Some("full")).await.unwrap();
        let addr: SocketAddr = "127.0.0.1:7".parse().unwrap();

        let said = peer_add(&db, &paired_keys, "alice".into(), "laptop".into(), derived(&k), hex::encode(k.as_bytes()), addr).await.unwrap();
        let UserResponse::NodePaired { node } = said else { panic!("{said:?}") };
        assert_eq!((node.id.as_str(), node.device_did.to_string(), node.addresses.clone()), ("laptop", stored.clone(), vec![addr]));
        let all = rows(&db, "alice").await;
        assert_eq!(all.len(), 1, "{all:?}");
        let (label, did, bytes, addresses, _, posture, relay) = all[0].clone();
        assert_eq!(
            (label.as_str(), did, bytes, addresses, posture.as_deref(), relay),
            ("laptop", stored, k.as_bytes().to_vec(), AT.to_string(), Some("full"), None)
        );
        assert!(paired_keys.read().unwrap().contains(&k));
    }
}

/// **One function and one order for the row a key is reached through**
/// (kottonllc/kotton#622): two rows of a person's for one key, as only an
/// earlier build can have stored them, read by every reader that takes one row
/// for a key.
#[cfg(test)]
mod one_row_for_a_key {
    use super::*;
    use kotton_crypto::DidKeyMethod;

    fn key(seed: u8) -> VerifyingKey {
        kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[seed; 32]))
    }

    async fn agent_db(dir: &tempfile::TempDir) -> Arc<SqlitePool> {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("agent.db"))
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::migrate!("../device/migrations").run(&pool).await.unwrap();
        Arc::new(pool)
    }

    /// Two names for `k`, its `did:key` and another spelling of it, as (lower,
    /// higher) by their bytes: the order `ORDER BY device_did` would read them in.
    fn two_names(k: &VerifyingKey) -> (String, String) {
        let (a, b) = (
            DidKeyMethod::from_public_key(k).to_string(),
            DidKeyMethod::spelled_otherwise(k.as_bytes()).to_string(),
        );
        if a < b { (a, b) } else { (b, a) }
    }

    fn node(id: &str, did: &str, k: &VerifyingKey, paired_at: i64, addresses: Vec<SocketAddr>) -> PairedNode {
        PairedNode {
            id: id.to_string(),
            device_did: Did::parse(did).unwrap(),
            public_key: *k.as_bytes(),
            paired_at,
            addresses,
            relay_url: None,
            posture: None,
        }
    }

    /// **The one function gives one row whatever order the rows come in**: the
    /// more recently paired, then the lower DID by its bytes where two were
    /// paired at one time; a row under another key is never it, and a key no
    /// row holds has none. Over a pure function, so both orders of listing are
    /// held and not only the one the store happens to give.
    #[test]
    fn the_row_a_key_is_reached_through_is_one_row_in_either_order() {
        let (k, other) = (key(81), key(82));
        let (low, high) = two_names(&k);
        let at: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        // The newer row has no address and the higher DID; the older has both.
        let newer = node("newer", &high, &k, 200, vec![]);
        let older = node("older", &low, &k, 100, vec![at]);
        let elsewhere = node("elsewhere", &DidKeyMethod::from_public_key(&other).to_string(), &other, 300, vec![]);
        for rows in [
            vec![newer.clone(), older.clone(), elsewhere.clone()],
            vec![elsewhere.clone(), older.clone(), newer.clone()],
        ] {
            assert_eq!(network_db::reached_through(&rows, k.as_bytes()).map(|n| n.id.as_str()), Some("newer"), "{rows:?}");
        }
        // Paired at one time: the lower DID.
        let tied = node("tied", &high, &k, 100, vec![]);
        for rows in [vec![tied.clone(), older.clone()], vec![older.clone(), tied.clone()]] {
            assert_eq!(network_db::reached_through(&rows, k.as_bytes()).map(|n| n.id.as_str()), Some("older"), "{rows:?}");
        }
        assert!(network_db::reached_through(&[elsewhere], k.as_bytes()).is_none());
        // The listing's order is the one order.
        let mut listed = [older.clone(), newer.clone()];
        listed.sort_by(network_db::listed_before);
        assert_eq!(listed.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(), vec!["newer", "older"]);
    }

    /// **Every reader that takes one row for a key takes the same row, at the
    /// store** (kottonllc/kotton#622): two rows of alice's for one key, the
    /// more recently paired with no address and the higher DID, the other with
    /// an address and the lower DID, written to the store in both orders. The
    /// row `paired_node_for_key` gives, the first `list_paired_nodes` lists for
    /// the key, the co-signer dialled, the drive's node and the row whose
    /// posture the drive record reads and sets, the row a write rewrites and
    /// the row a re-address re-addresses are one row, the newer.
    #[tokio::test]
    async fn every_reader_of_a_keys_row_reads_the_same_row_of_two() {
        let k = key(83);
        let (low, high) = two_names(&k);
        let at = serde_json::to_string(&["127.0.0.1:7000".parse::<SocketAddr>().unwrap()]).unwrap();
        for newer_first in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let db = agent_db(&dir).await;
            // The newer row was added by address (no posture); the older says
            // it is a co-signer, so a drive recorded through it is refused.
            let seeds = [("newer", high.as_str(), "[]", 200, None), ("older", low.as_str(), at.as_str(), 100, Some("cosigner"))];
            let order: Vec<_> = if newer_first { seeds.iter().collect() } else { seeds.iter().rev().collect() };
            for (id, did, addresses, paired_at, posture) in order {
                network_db::seed_paired_node_as_stored(&db, id, "alice", did, k.as_bytes(), addresses, *paired_at, *posture)
                    .await
                    .unwrap();
            }
            let case = if newer_first { "newer written first" } else { "older written first" };

            let for_key = network_db::paired_node_for_key(&db, "alice", k.as_bytes()).await.unwrap().unwrap();
            assert_eq!((for_key.id.as_str(), for_key.device_did.to_string()), ("newer", high.clone()), "{case}: paired_node_for_key");
            assert!(for_key.addresses.is_empty(), "{case}: the premise: the row reached has no address");
            let listed = network_db::list_paired_nodes(&db, "alice").await.unwrap();
            assert_eq!(listed[0].id, "newer", "{case}: list_paired_nodes");

            let members = vec![Member {
                did: DidKeyMethod::from_public_key(&k).to_string(),
                public_key: *k.as_bytes(),
                role: Role::OwnDevice,
                admitted_by: Ceremony::DeviceEnroll,
                added_at: "2026-11-21T00:00:00Z".to_string(),
                posture: Some(Posture::Full),
                label: None,
                reach: None,
            }];
            let dialled = cosigner_nodes(&members, listed.clone());
            assert_eq!(dialled.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(), vec!["newer"], "{case}: co-signer");
            // Over the rows in the other order too: selection does not lean on the listing.
            let dialled = cosigner_nodes(&members, listed.into_iter().rev().collect());
            assert_eq!(dialled.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(), vec!["newer"], "{case}: co-signer, reversed");

            super::super::drives::record(&db, "alice", k.as_bytes()).await.unwrap();
            let drives = super::super::drives::list(&db, "alice").await.unwrap();
            assert_eq!(drives[0].node.id, "newer", "{case}: the drive's node");
            let postures: Vec<(String, Option<String>)> =
                sqlx::query_as("SELECT id, posture FROM paired_nodes WHERE user_id = 'alice' ORDER BY id").fetch_all(db.as_ref()).await.unwrap();
            assert_eq!(
                postures,
                vec![("newer".to_string(), Some("blind-storage".to_string())), ("older".to_string(), Some("cosigner".to_string()))],
                "{case}: the drive record read or set another row's posture"
            );

            let readdressed = network_db::readdress_paired_node_for_key(&db, "alice", k.as_bytes(), &at, 300).await.unwrap().unwrap();
            assert_eq!(readdressed.id, "newer", "{case}: the re-address");
            let written = network_db::insert_paired_node(&db, "renamed", "alice", &k, &at, 400, None).await.unwrap();
            assert_eq!(written.device_did.to_string(), high, "{case}: the write");
            let left = network_db::get_paired_node(&db, "alice", &low).await.unwrap().unwrap();
            assert_eq!((left.id.as_str(), left.paired_at), ("older", 100), "{case}: the other row changed");
        }
    }

    /// **The re-address points the drive at the row it re-addressed**
    /// (kottonllc/kotton#622): a drive recorded while one row held its key,
    /// then a second, more recently paired row for the key, stored as an
    /// earlier build could have (no drive touched). The re-address reaches the
    /// newer row, and the drive's record shows that row's label: the drive is
    /// reached through the row re-addressed. A write that follows names the
    /// same row and keeps the record on its label.
    #[tokio::test]
    async fn the_drive_shows_the_label_of_the_row_re_addressed() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let k = key(84);
        let (low, high) = two_names(&k);
        network_db::seed_paired_node_as_stored(&db, "older", "alice", &low, k.as_bytes(), "[]", 100, Some("blind-storage")).await.unwrap();
        super::super::drives::record(&db, "alice", k.as_bytes()).await.unwrap();
        network_db::seed_paired_node_as_stored(&db, "newer", "alice", &high, k.as_bytes(), "[]", 200, Some("blind-storage")).await.unwrap();
        let node_id = || async {
            sqlx::query_scalar::<_, String>("SELECT node_id FROM drives WHERE user_id = 'alice'").fetch_all(db.as_ref()).await.unwrap()
        };
        assert_eq!(node_id().await, vec!["older"], "the premise: the record names the row it was recorded through");

        let at = serde_json::to_string(&["127.0.0.1:7000".parse::<SocketAddr>().unwrap()]).unwrap();
        let readdressed = network_db::readdress_paired_node_for_key(&db, "alice", k.as_bytes(), &at, 300).await.unwrap().unwrap();
        assert_eq!(readdressed.id, "newer");
        assert_eq!(node_id().await, vec!["newer"], "the drive's record does not show the row re-addressed");
        let drives = super::super::drives::list(&db, "alice").await.unwrap();
        assert_eq!(drives[0].node.device_did.to_string(), high, "the drive is not reached through the row re-addressed");

        network_db::insert_paired_node(&db, "vault", "alice", &k, &at, 400, None).await.unwrap();
        assert_eq!(node_id().await, vec!["vault"], "a write left the record on another label");
        assert_eq!(super::super::drives::list(&db, "alice").await.unwrap()[0].node.id, "vault");
    }

    /// A store a test fills, holding what it is told.
    #[derive(Default)]
    struct Members(std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>);

    #[async_trait::async_trait]
    impl crate::membership::MemberStore for Members {
        async fn member_write(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
            self.0.lock().unwrap().insert(path.to_string(), data.to_vec());
            Ok(())
        }
        async fn member_read(&self, path: &str) -> anyhow::Result<Vec<u8>> {
            self.0.lock().unwrap().get(path).cloned().ok_or_else(|| anyhow::anyhow!("no member at {path}"))
        }
        async fn member_delete(&self, path: &str) -> anyhow::Result<()> {
            self.0.lock().unwrap().remove(path);
            Ok(())
        }
        async fn member_list(&self, dir: &str) -> anyhow::Result<Vec<String>> {
            Ok(self.0.lock().unwrap().keys().filter(|p| p.starts_with(dir)).cloned().collect())
        }
    }

    async fn revoke(db: &Arc<SqlitePool>, user: &str, name: &str, keys: &Arc<RwLock<HashSet<VerifyingKey>>>) -> UserResponse {
        let members = Members::default();
        let named = node_named(db, user, name, Asked::Remotely.reach(&members)).await.unwrap().expect("the name names a row");
        revoke_named(&members, db, user, &named, keys).await.unwrap()
    }

    /// **A row's revoke names each other row of the person's under its key, by
    /// the name `device revoke` takes to it, and no other person's**
    /// (kottonllc/kotton#597, 34A): alice pairs one key under two rows, one
    /// labelled with a plain word and one labelled with words that are not one,
    /// so it is named by its DID as stored; bob pairs the key too. Revoking
    /// alice's first row answers an error naming her other row and nothing of
    /// bob's; revoking by the name the answer gave removes it, and the answer
    /// is a success. The key stays admitted while bob pairs it.
    #[tokio::test]
    async fn a_rows_revoke_names_the_persons_other_rows_under_its_key_and_no_one_elses() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let k = key(85);
        let (low, high) = two_names(&k);
        network_db::insert_paired_node(&db, "laptop", "alice", &k, "[]", 100, None).await.unwrap();
        let other = if DidKeyMethod::from_public_key(&k).to_string() == low { &high } else { &low };
        network_db::seed_paired_node_as_stored(&db, "old laptop", "alice", other, k.as_bytes(), "[]", 50, None).await.unwrap();
        network_db::insert_paired_node(&db, "alices-laptop", "bob", &k, "[]", 10, None).await.unwrap();
        let keys = Arc::new(RwLock::new(HashSet::from([k])));

        let said = revoke(&db, "alice", "laptop", &keys).await;
        let UserResponse::Error { message } = said else { panic!("a revoke that left a row under its key answered {said:?}") };
        let rows = network_db::list_paired_nodes(&db, "alice").await.unwrap();
        let names = still_paired_as(&rows, k.as_bytes());
        assert_eq!(names, vec![other.clone()], "a label that is not one plain word is not the name: {names:?}");
        assert!(message.contains(&kotton_wire::note::quoted(other)), "{message}");
        assert!(message.contains("`laptop` is revoked"), "{message}");
        assert!(!message.contains("alices-laptop"), "another person's row was named: {message}");

        let said = revoke(&db, "alice", &names[0], &keys).await;
        assert!(matches!(said, UserResponse::NodeRevoked), "{said:?}");
        assert!(network_db::list_paired_nodes(&db, "alice").await.unwrap().is_empty());
        assert!(keys.read().unwrap().contains(&k), "the key left the allowlist while bob pairs it");
    }

    /// **Revoking by the name the answer gave takes the key off the allowlist**
    /// (34A): with only alice's two rows under the key, revoking the first
    /// leaves the key admitted and names the second; revoking that name removes
    /// it and takes the key off.
    #[tokio::test]
    async fn revoking_by_the_name_the_answer_gave_takes_the_key_off_the_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let k = key(86);
        let (low, high) = two_names(&k);
        network_db::seed_paired_node_as_stored(&db, "phone", "alice", &low, k.as_bytes(), "[]", 100, None).await.unwrap();
        network_db::seed_paired_node_as_stored(&db, "phone-before", "alice", &high, k.as_bytes(), "[]", 50, None).await.unwrap();
        let keys = Arc::new(RwLock::new(HashSet::from([k])));

        let said = revoke(&db, "alice", "phone", &keys).await;
        let UserResponse::Error { message } = said else { panic!("{said:?}") };
        assert!(message.contains("`phone-before`"), "{message}");
        assert!(keys.read().unwrap().contains(&k), "the key left the allowlist while a row pairs it");

        let said = revoke(&db, "alice", "phone-before", &keys).await;
        assert!(matches!(said, UserResponse::NodeRevoked), "{said:?}");
        assert!(keys.read().unwrap().is_empty(), "the key stayed on the allowlist with no row");
    }
}

/// **The narrowest of a key's rows answers what the key may ask**
/// (kottonllc/kotton#597): where two rows of a person's hold one key, as only
/// an earlier build can have stored them, `paired_posture_for_user` answers
/// with the narrowest of what they say, whichever row holds which DID and
/// whichever was paired first.
#[cfg(test)]
mod narrowest_of_a_keys_rows {
    use super::*;
    use kotton_crypto::DidKeyMethod;

    /// Text no build of this one's recognises as a posture.
    const UNRECOGNISED: &str = "posture-of-a-later-build";

    /// The six things a row can say, narrowest first, as the addendum orders
    /// them; stated here apart from the function under test.
    const NARROWEST_FIRST: [Option<&str>; 6] =
        [Some("gateway"), Some("blind-storage"), Some("cosigner"), Some(UNRECOGNISED), Some("full"), None];

    fn key(seed: u8) -> VerifyingKey {
        kotton_crypto::ed25519::verifying_key(&SigningKey::from_bytes(&[seed; 32]))
    }

    async fn agent_db(dir: &tempfile::TempDir) -> Arc<SqlitePool> {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("agent.db"))
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::migrate!("../device/migrations").run(&pool).await.unwrap();
        Arc::new(pool)
    }

    /// Two names for `k`, as (lower, higher) by their bytes.
    fn two_names(k: &VerifyingKey) -> (String, String) {
        let (a, b) = (
            DidKeyMethod::from_public_key(k).to_string(),
            DidKeyMethod::spelled_otherwise(k.as_bytes()).to_string(),
        );
        if a < b { (a, b) } else { (b, a) }
    }

    /// **Every pair of the six, in all four arrangements of DID and time.**
    /// Rows `a` and `b` of alice's under one key: `a` under the lower DID or
    /// the higher, paired before `b` or after. The answer is whichever of the
    /// two comes first in [`NARROWEST_FIRST`], in every arrangement. Each case
    /// is its own key, so no case reads another's rows; bob's row under each
    /// key says `full` and changes nothing of alice's answer.
    #[tokio::test]
    async fn the_narrowest_of_two_rows_answers_in_every_arrangement() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let mut seed = 0u8;
        for a in NARROWEST_FIRST {
            for b in NARROWEST_FIRST {
                let want = NARROWEST_FIRST.iter().copied().find(|p| *p == a || *p == b).unwrap().map(str::to_string);
                for a_lower in [true, false] {
                    for a_first in [true, false] {
                        seed += 1;
                        let k = key(seed);
                        let (lower, higher) = two_names(&k);
                        let (a_did, b_did) = if a_lower { (&lower, &higher) } else { (&higher, &lower) };
                        let (a_at, b_at) = if a_first { (100, 200) } else { (200, 100) };
                        network_db::seed_paired_node_as_stored(&db, "a", "alice", a_did, k.as_bytes(), "[]", a_at, a).await.unwrap();
                        network_db::seed_paired_node_as_stored(&db, "b", "alice", b_did, k.as_bytes(), "[]", b_at, b).await.unwrap();
                        network_db::seed_paired_node_as_stored(&db, "b", "bob", &lower, k.as_bytes(), "[]", 300, Some("full"))
                            .await
                            .unwrap();
                        assert_eq!(
                            network_db::paired_posture_for_user(&db, k.as_bytes(), "alice").await.unwrap(),
                            Some(want.clone()),
                            "rows {a:?} and {b:?}, the first under the lower DID: {a_lower}, paired first: {a_first}"
                        );
                        sqlx::query("DELETE FROM paired_nodes").execute(db.as_ref()).await.unwrap();
                    }
                }
            }
        }
        assert_eq!(network_db::paired_posture_for_user(&db, key(1).as_bytes(), "alice").await.unwrap(), None, "no row: no posture");
    }

    /// **Two texts this build does not recognise: the least by its bytes
    /// answers**, whichever row holds it.
    #[tokio::test]
    async fn of_two_unrecognised_texts_the_least_by_its_bytes_answers() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let k = key(7);
        let (lower, higher) = two_names(&k);
        for (lower_says, higher_says) in [("zz-later", "aa-later"), ("aa-later", "zz-later")] {
            network_db::seed_paired_node_as_stored(&db, "a", "alice", &lower, k.as_bytes(), "[]", 200, Some(lower_says)).await.unwrap();
            network_db::seed_paired_node_as_stored(&db, "b", "alice", &higher, k.as_bytes(), "[]", 100, Some(higher_says)).await.unwrap();
            assert_eq!(
                network_db::paired_posture_for_user(&db, k.as_bytes(), "alice").await.unwrap(),
                Some(Some("aa-later".to_string())),
                "the lower DID says {lower_says}"
            );
            sqlx::query("DELETE FROM paired_nodes").execute(db.as_ref()).await.unwrap();
        }
    }
}

#[cfg(test)]
mod a_cosigners_answer {
    use super::*;
    use kotton_wire::note::{quoted_cut, MAX_SAID_CHARS};

    fn said(resp: UserResponse) -> String {
        match round_reply_in(resp) {
            Ok(_) => panic!("a refusal was read as a round reply"),
            Err(e) => e.to_string(),
        }
    }

    /// **A co-signer's `Error`, and a reply that does not read, are printed as
    /// data and to the bound; an answer not asked for by its name and no
    /// field** (how another node's text is printed; how an answer not asked
    /// for is said).
    #[test]
    fn a_cosigners_refusal_is_printed_as_data_and_to_the_bound() {
        let long = "c".repeat(MAX_SAID_CHARS + 4);
        for text in ["no `round`\nhere", long.as_str()] {
            let refused = said(UserResponse::Error { message: text.to_string() });
            assert_eq!(refused, format!("the co-signer answered: {}", quoted_cut(text)));
            assert!(!refused.contains('\n') && !refused.contains(text), "{refused}");
        }
        assert_eq!(
            said(UserResponse::Error { message: "no `round`\nhere".into() }),
            "the co-signer answered: `no \\u{60}round\\u{60}\\nhere`"
        );
        let unread = said(UserResponse::FrostSignReply { payload: "\"no `round`\\nhere\"".into() });
        assert!(unread.starts_with("the co-signer's round reply did not read: `"), "{unread}");
        assert!(!unread.contains('\n') && !unread.contains("no `round`"), "{unread}");
        assert_eq!(said(UserResponse::VaultFull { held: 17, quota: 9 }), "the co-signer answered `VaultFull`");
    }
}
