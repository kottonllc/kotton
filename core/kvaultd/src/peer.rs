// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a vault answers on the authenticated peer transport.
//!
//! Twenty-one verbs, and nothing else exists here to be reached. Fifteen are a
//! tenant's: sealed read, write and list; the recovery packet, kept and
//! returned; where this vault reserves; how much it keeps; the doors held
//! for a person, what arrived at them, and what the vault carries for them;
//! the person's other devices, admitted and withdrawn under their
//! identity's signature (`TenantDevice`, `crate::devices`); and the person's
//! drives here, made, listed, named and retired (`TenantDriveMake`,
//! `TenantDrives`, `TenantDriveName`, `TenantDriveRetire`, `crate::drives`).
//! Six are the
//! landlord's — an invite and its digits, the tenants, one pool's quota,
//! dropping one pool, and where the vault stands — and are reached by one
//! connection only, the one whose key is the vault's operator credential
//! (`crate::operator`). The full daemon admits a blind node to a wider set and
//! relies on the node's having no key to make the rest fail. This file is the
//! shape in which that reliance is unnecessary — the plaintext verbs are not
//! refused, they are absent.
//!
//! **Absent at the decoder, not refused by an arm.** The acceptor
//! (`crate::Vault::peer_handler`) decodes a peer's bytes as
//! [`VaultPeerRequest`], which holds the twenty-one and nothing else, so
//! `ReadFile`, `RecordInsert` and every other verb of a device's door is an
//! unknown variant there and never reaches [`handle`]. Until kotton #239 it
//! decoded the device's whole `UserRequest` and [`handle`] refused by arm what
//! was "not a vault's verb"; that arm was evidence a device's verbs were
//! reachable here, and it is gone because they are not. The vault's peer wire
//! is its own type, not a device's `PeerRequest`: the two share six verbs, and
//! one type for both would put each acceptor's other verbs on the other's
//! wire. What is left to decide here is *who* says each verb, which no type
//! can decide, because the same key is a tenant to one pool and a stranger to
//! the next.
//!
//! **Who reaches which verb is one table, [`reaches`], and it is the whole of
//! the decision.** A standing is what `peer_standing` says the connection is to
//! the pool it names; the table says what each standing may say:
//!
//! | standing | the fifteen a tenant says | the landlord's six |
//! |---|---|---|
//! | `Paired` — a tenant's device, to its own pool | yes | no |
//! | `Claim` — a phrase-only device | `RecoveryFetch` of its own identity only | no |
//! | `Operator` — the vault's operator credential | **no** | yes |
//! | `Stranger` | no | no |
//!
//! The operator's row is the one the design turns on: it reads no pack,
//! fetches no recovery copy, writes nothing and holds no door, because a
//! credential that sets numbers and mints invites has no use for any of them
//! (Article VII). And the invite it mints admits blind, as at the door.

use crate::control::ControlContext;
use crate::host::VaultHost;
use crate::meter::Meter;
use crate::residency::Pools;
use kotton_device::users::admission::{paired_as_another, peer_standing, PeerStanding, NOT_PAIRED_WITH};
use kotton_device::users::files::SealedReassembly;
use kotton_device::users::residency::Residency as _;
use kotton_device::users::DeviceUsers as _;
use kotton_device::DeviceRuntime;
use kotton_sys::store::SyncableStore;
use kotton_wire::ipc::{UserResponse, VaultPeerRequest};
use sqlx::SqlitePool;
use std::sync::Arc;

/// What the peer handler holds for the listener's lifetime.
pub struct PeerContext {
    pub runtime: Arc<DeviceRuntime>,
    pub pools: Pools,
    pub db: Arc<SqlitePool>,
    pub meter: Arc<Meter>,
    /// Chunks of a large sealed object arrive as separate requests and
    /// accumulate here until complete.
    pub reassembly: SealedReassembly,
    /// Held for reading by every request that touches a pool, and for writing
    /// by the landlord's drop of a tenant while it takes their standing away
    /// (`tenancy::drop_tenant`, step 1), so no write lands in a pool after its
    /// tenant is dropped, and a request that waited finds them gone.
    /// Serialises; decides nothing.
    pub tenancy: tokio::sync::RwLock<()>,
    /// One landlord's drop at a time, held for the whole of it — the shelf
    /// walk included, which `tenancy` is not.
    pub drops: tokio::sync::Mutex<()>,
    /// One lock per made drive a tenant keeps here: held for reading by every
    /// sealed write into the drive's tree, for the whole of the request, and
    /// for writing by its retire (`crate::drives::retire`), so a write either
    /// lands before the retire begins or finds the tree gone and is refused.
    pub trees: crate::drives::Trees,
}

/// The fifteen verbs a tenant's device says to its own pool.
pub fn is_tenant_verb(request: &VaultPeerRequest) -> bool {
    matches!(
        request,
        VaultPeerRequest::ReadSealed { .. }
            | VaultPeerRequest::WriteSealed { .. }
            | VaultPeerRequest::ListSealed { .. }
            | VaultPeerRequest::RecoveryFetch { .. }
            | VaultPeerRequest::RecoveryStore { .. }
            | VaultPeerRequest::NodeRelay { .. }
            | VaultPeerRequest::VaultCapacity { .. }
            | VaultPeerRequest::HoldDoors { .. }
            | VaultPeerRequest::TakeDeliveries { .. }
            | VaultPeerRequest::CarryFrame { .. }
            | VaultPeerRequest::TenantDevice { .. }
            | VaultPeerRequest::TenantDriveMake { .. }
            | VaultPeerRequest::TenantDrives { .. }
            | VaultPeerRequest::TenantDriveName { .. }
            | VaultPeerRequest::TenantDriveRetire { .. }
    )
}

/// The landlord's six, which only the operator's key reaches here: the four
/// verbs over pools; reading the six digits a ceremony an invite of theirs
/// started is waiting on (`InviteDigits`), which the vault's own terminal
/// prints at the host and nothing else shows the desktop that minted it; and
/// telling the vault where to stand (`StandAt`, RFC-0084 V11). That last is on
/// this row and no other because the operator is the one party that
/// introduces the vault to its relays and minted the keys that ride with them;
/// no tenant can reach it, so no tenant can move the vault or set the key
/// another tenant is handed.
pub fn is_landlord_verb(request: &VaultPeerRequest) -> bool {
    matches!(
        request,
        VaultPeerRequest::DeviceInvite { .. }
            | VaultPeerRequest::InviteDigits { .. }
            | VaultPeerRequest::Tenants
            | VaultPeerRequest::SetQuota { .. }
            | VaultPeerRequest::DropTenant { .. }
            | VaultPeerRequest::StandAt { .. }
    )
}

/// Whether a connection of `standing` may say `request` — the table in the
/// module note, and the only place the vault decides it. A claim's further
/// condition, that the identity fetched is the one claimed, is `handle`'s,
/// because it needs the vault's own records to check.
pub fn reaches(standing: &PeerStanding, request: &VaultPeerRequest) -> bool {
    match standing {
        PeerStanding::Paired => is_tenant_verb(request),
        PeerStanding::Claim { .. } => matches!(request, VaultPeerRequest::RecoveryFetch { .. }),
        PeerStanding::Operator => is_landlord_verb(request),
        PeerStanding::Stranger => false,
    }
}

pub async fn handle(control: &ControlContext, peer_did: &str, request: VaultPeerRequest) -> UserResponse {
    use kotton_crypto::did::DidKeyMethod;
    use kotton_wire::did::Did;
    let ctx: &PeerContext = &control.peer;

    // Which pool the request names — `None` for one addressed to the vault as
    // a whole, the operator's `Tenants` and `StandAt`. Every verb that decodes
    // here is a vault's (`VaultPeerRequest`), so there is nothing else to name.
    let pool: Option<String> = match &request {
        VaultPeerRequest::ReadSealed { user_id, .. }
        | VaultPeerRequest::ListSealed { user_id, .. }
        | VaultPeerRequest::WriteSealed { user_id, .. }
        | VaultPeerRequest::RecoveryFetch { user_id }
        | VaultPeerRequest::RecoveryStore { user_id, .. }
        | VaultPeerRequest::NodeRelay { user_id }
        | VaultPeerRequest::VaultCapacity { user_id }
        | VaultPeerRequest::HoldDoors { user_id, .. }
        | VaultPeerRequest::TakeDeliveries { user_id, .. }
        | VaultPeerRequest::CarryFrame { user_id, .. }
        | VaultPeerRequest::TenantDevice { user_id, .. }
        | VaultPeerRequest::TenantDriveMake { user_id, .. }
        | VaultPeerRequest::TenantDrives { user_id }
        | VaultPeerRequest::TenantDriveName { user_id, .. }
        | VaultPeerRequest::TenantDriveRetire { user_id, .. }
        | VaultPeerRequest::DeviceInvite { user_id, .. }
        | VaultPeerRequest::InviteDigits { user_id }
        | VaultPeerRequest::SetQuota { user_id, .. }
        | VaultPeerRequest::DropTenant { user_id } => Some(user_id.clone()),
        VaultPeerRequest::Tenants | VaultPeerRequest::StandAt { .. } => None,
    };

    // Standing is decided under this, so a drop in progress is waited out and
    // then its tenant's devices are strangers (`PeerContext::tenancy`).
    let steady = ctx.tenancy.read().await;

    let peer_pubkey: Option<[u8; 32]> = Did::parse(peer_did)
        .ok()
        .and_then(|d| DidKeyMethod::to_public_key(&d).ok())
        .map(|vk| vk.to_bytes());

    // Who is asking, to this pool. A vault grants no guest session, so a
    // stranger is refused here and there is no second door.
    let standing = match peer_standing(
        &ctx.runtime,
        &ctx.db,
        &ctx.runtime.paired_keys(),
        peer_did,
        peer_pubkey,
        pool.as_deref(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            return UserResponse::Error {
                message: format!("authorization check failed: {e}"),
            }
        }
    };
    if !reaches(&standing, &request) {
        let held = held_by(&ctx.db, &standing, peer_pubkey, pool.as_deref()).await;
        return refusal(&standing, peer_did, pool.as_deref(), held.as_deref(), &request);
    }
    if let PeerStanding::Claim { aid } = &standing {
        let own = pool.as_deref().and_then(|p| ctx.runtime.user_aid(p));
        if own.as_deref() != Some(aid) {
            return refusal(&standing, peer_did, pool.as_deref(), None, &request);
        }
    }

    // The landlord's verbs take their own locks — a drop takes `tenancy` for
    // writing — so standing's read is let go before they run.
    //
    // **Each is kept under the key that said it** (`operator_acts`,
    // `TASK-a-device-has-operators-not-an-operator`). A vault admits a set of
    // operator keys, so "the operator did it" names nobody; the key the
    // connection authenticated as at the handshake does. It is known here —
    // `Operator` standing is decided from it — and the act is kept *before* it
    // runs: a record that cannot be written refuses the act, so nothing an
    // operator does goes unkept. Its outcome is marked after.
    if matches!(standing, PeerStanding::Operator) {
        drop(steady);
        let Some(key) = peer_pubkey else {
            return refusal(&standing, peer_did, pool.as_deref(), None, &request);
        };
        let verb = request.variant_name();
        let pool = pool.unwrap_or_default();
        let id = match kotton_peer::daemon::db::record_operator_act(&ctx.db, &key, verb, &pool).await {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(error = %e, verb, "an operator's act could not be kept, so it did not run");
                return UserResponse::Error {
                    message: format!("{verb} was not run: it could not be kept under the key that said it: {e}"),
                };
            }
        };
        let answer = crate::control::landlord(control, &key, request).await;
        if !matches!(answer, UserResponse::Error { .. }) {
            if let Err(e) = kotton_peer::daemon::db::operator_act_done(&ctx.db, id).await {
                // The act is kept, under its key; only its outcome is not.
                tracing::error!(error = %e, verb, "an operator's act ran but its outcome was not kept");
            }
        }
        return answer;
    }

    let host = VaultHost {
        runtime: &ctx.runtime,
        pools: &ctx.pools,
    };
    let result: std::io::Result<UserResponse> = match request {
        VaultPeerRequest::ReadSealed {
            user_id,
            mount,
            path,
            offset,
            length,
        } => kotton_device::users::files::read_sealed(&host, user_id, mount, path, offset, length).await,
        VaultPeerRequest::ListSealed {
            user_id,
            mount,
            prefix,
        } => kotton_device::users::files::list_sealed(&host, user_id, mount, prefix).await,
        VaultPeerRequest::WriteSealed {
            user_id,
            mount,
            path,
            blob,
            domain_id,
            offset,
            total_size,
            content_hash,
        } => {
            // A write into a made drive holds the drive here for the whole of
            // the request, and a drive being retired, or retired, takes none:
            // it is refused by name rather than landing in a tree on its way
            // out (`crate::drives::retire`).
            let _tree = match crate::drives::write_into(ctx, &user_id, &mount).await {
                Ok(held) => held,
                Err(message) => return UserResponse::Error { message },
            };
            // The meter's one decision, made before any byte is buffered: does
            // the whole object fit? Checked on the first chunk, so a large
            // object is refused once rather than after occupying a buffer.
            if offset == 0 {
                if let Some(store) = ctx.pools.get(&user_id) {
                    let shelves = pool_shelves(&store);
                    let shelves: Vec<&dyn SyncableStore> = shelves.iter().map(|s| s.as_ref()).collect();
                    if let Err(full) = ctx.meter.admits(&user_id, &shelves, total_size).await {
                        return UserResponse::VaultFull {
                            held: full.held,
                            quota: full.quota,
                        };
                    }
                }
            }
            let written = blob.len() as u64;
            let resp = kotton_device::users::files::write_sealed(
                &host,
                user_id.clone(),
                mount,
                path,
                blob,
                domain_id,
                offset,
                total_size,
                content_hash,
                Some(&ctx.reassembly),
            )
            .await;
            if matches!(resp, Ok(UserResponse::Ok)) {
                ctx.meter.add(&user_id, written);
            }
            resp
        }
        VaultPeerRequest::RecoveryFetch { user_id } => {
            let base = ctx.runtime.base_dir();
            let kel = kotton_identity::kel_store::load_chain(base, &user_id).unwrap_or_default();
            let bundle =
                kotton_identity::provisioning::read_recovery_bundle_raw(base, &user_id).unwrap_or_default();
            Ok(UserResponse::RecoveryMaterial { kel, bundle })
        }
        VaultPeerRequest::RecoveryStore { user_id, bundle, kel } => {
            // The events that authorize the copy, before the copy. A vault that
            // cannot extend its chain is a vault that will refuse to serve what
            // it just accepted, so the failure belongs here.
            if let Err(e) = kotton_device::users::admission::adopt_chain_extension(
                &ctx.runtime,
                &user_id,
                &kel,
            ) {
                return UserResponse::Error {
                    message: format!(
                        "the key events offered with the recovery copy do not replay: {e}"
                    ),
                };
            }
            match kotton_identity::provisioning::write_recovery_bundle_raw(
                ctx.runtime.base_dir(),
                &user_id,
                &bundle,
            ) {
                Ok(()) => {
                    tracing::info!(peer_did = %peer_did, user_id = %user_id, "kept a delivered recovery copy");
                    Ok(UserResponse::Ok)
                }
                Err(e) => Ok(UserResponse::Error {
                    message: format!("could not keep the recovery copy: {e}"),
                }),
            }
        }
        VaultPeerRequest::NodeRelay { .. } => {
            // The first relay of the reach set, by its key and address. A
            // tenant is one of *the people I invite*: handed the invited key for
            // it, and never *mine*.
            let (relay_url, relay_key, admission) = crate::reach::for_tenant(&ctx.runtime);
            Ok(UserResponse::NodeRelayResult {
                relay_url,
                relay_key,
                admission,
            })
        }
        VaultPeerRequest::VaultCapacity { user_id } => Ok(capacity(ctx, &user_id).await),
        // The doors held for a person (`DEC-0056`): a device of theirs hands
        // them over and takes what arrived. Paired standing was checked above.
        VaultPeerRequest::HoldDoors { user_id, doors } => {
            Ok(crate::doors::hold(&ctx.runtime, &ctx.db, &user_id, doors).await)
        }
        VaultPeerRequest::TakeDeliveries { user_id, ack } => {
            Ok(crate::doors::take(&ctx.db, &user_id, ack).await)
        }
        // What the person's outbox holds, carried while no device of theirs
        // is awake (`carry`). Paired standing was checked above.
        VaultPeerRequest::CarryFrame { user_id, messages, drop } => {
            Ok(crate::carry::carry(&ctx.db, &user_id, messages, drop).await)
        }
        // Another device of the person's, admitted or withdrawn under their
        // identity's signature (`devices`). Paired standing was checked above;
        // the signature is what decides.
        VaultPeerRequest::TenantDevice { user_id, change, signature } => {
            Ok(crate::devices::change(ctx, &user_id, change, &signature).await)
        }
        // The person's drives here (`crate::drives`): made, listed and retired
        // by a device of theirs. Paired standing was checked above; a made
        // drive is named by its id, so the tenancy's own tree is beyond reach.
        VaultPeerRequest::TenantDriveMake { user_id, drive, sealed_name } => {
            crate::drives::make(ctx, &user_id, drive, sealed_name).await
        }
        VaultPeerRequest::TenantDrives { user_id } => crate::drives::list(ctx, &user_id).await,
        VaultPeerRequest::TenantDriveName { user_id, drive, sealed_name } => {
            crate::drives::name(ctx, &user_id, drive, sealed_name).await
        }
        VaultPeerRequest::TenantDriveRetire { user_id, drive } => crate::drives::retire(ctx, &user_id, drive).await,
        // The landlord's six: only the operator's standing reaches them, and
        // it went to `control::landlord` above, so none arrives here, which
        // `each_standing_reaches_exactly_its_row_of_the_table` holds. Should
        // the table ever widen past this match, the verb is refused — never a
        // panic in the handler — and a new verb here is a deliberate diff.
        other => Ok(UserResponse::Error {
            message: format!("{} is reached by no body at this vault", other.variant_name()),
        }),
    };
    result.unwrap_or_else(|e| UserResponse::Error {
        message: e.to_string(),
    })
}

/// What a refused caller reads: the sentence for its standing.
/// The pool a stranger's key is paired to here, when it is paired to one —
/// read only for a `Stranger` refused a request that names a pool.
///
/// **Only a key already paired at this vault learns a name, and the name is
/// its own pool's.** A key paired nowhere gets `None`, and so today's sentence,
/// which names nothing it did not send. Nor does the sentence say whether the
/// pool the request named exists: it reads the same either way. So the one
/// thing disclosed is what the operator already told that device's person by
/// inviting it — the name its pairing is under — and it is what they need to
/// see when their device asks under another
/// (`TASK-a-vault-invite-names-a-tenant-the-device-does-not-sync-as`).
async fn held_by(
    db: &Arc<SqlitePool>,
    standing: &PeerStanding,
    peer_pubkey: Option<[u8; 32]>,
    pool: Option<&str>,
) -> Option<String> {
    let (PeerStanding::Stranger, Some(key), Some(_)) = (standing, peer_pubkey, pool) else {
        return None;
    };
    // Every pool the key is paired to, not the first by name: a vault keeps a
    // key to one tenant (`crate::devices`), so this is one pool or none, and a
    // key two pools pair is not a state this sentence names — it reads as
    // none, today's sentence, rather than picking one of them.
    match kotton_peer::daemon::db::paired_users_for_pubkey(db, &key).await {
        Ok(mut pools) if pools.len() == 1 => pools.pop(),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(error = %e, "could not read which pool a refused key is paired to");
            None
        }
    }
}

/// The sentence a refused caller reads. `held` is the pool a stranger's key
/// is paired to at this vault ([`held_by`]), `None` for a key paired nowhere.
fn refusal(
    standing: &PeerStanding,
    peer_did: &str,
    pool: Option<&str>,
    held: Option<&str>,
    request: &VaultPeerRequest,
) -> UserResponse {
    let message = match standing {
        PeerStanding::Paired => format!(
            "{} is the landlord's, said under the vault's operator credential; a tenant's device does \
             not say it",
            request.variant_name()
        ),
        PeerStanding::Claim { .. } => "a device admitted on a recovery claim may only fetch the identity \
                                       it claimed"
            .to_string(),
        PeerStanding::Operator => format!(
            "the operator credential says the landlord's four verbs and nothing else; {} is a \
             tenant's",
            request.variant_name()
        ),
        PeerStanding::Stranger => match (pool, held) {
            (Some(user_id), Some(held)) => format!(
                "peer {peer_did} {NOT_PAIRED_WITH} '{user_id}': {}",
                paired_as_another(held, user_id)
            ),
            (Some(user_id), None) => format!("peer {peer_did} {NOT_PAIRED_WITH} '{user_id}'"),
            (None, _) => format!("peer {peer_did} is not this vault's operator"),
        },
    };
    UserResponse::Error { message }
}

/// The shelves a pool rests on: one per drive the tenant keeps here — the
/// tenancy's own tree, `local`, and each made beside it (`crate::drives`) —
/// each the sealed-only stack straight over its shelf on a vault, so a
/// listing is the shelf's. What the meter measures, so every drive is charged.
pub fn pool_shelves(store: &kotton_store::runtime::user::UserStore) -> Vec<Arc<dyn SyncableStore>> {
    store
        .shelf_mounts()
        .into_iter()
        .filter_map(|(mount, _)| store.get_remote(&mount))
        .collect()
}

/// What a pool holds over every drive it keeps, walked now.
pub async fn measure_pool(store: &kotton_store::runtime::user::UserStore) -> u64 {
    let shelves = pool_shelves(store);
    let shelves: Vec<&dyn SyncableStore> = shelves.iter().map(|s| s.as_ref()).collect();
    Meter::measure_all(&shelves).await
}

/// The meter's readout for a pool: measured now if never measured, and the
/// pool's own quota (the default when the landlord set it none).
pub async fn capacity(ctx: &PeerContext, user_id: &str) -> UserResponse {
    let held = match ctx.meter.held(user_id) {
        Some(h) => h,
        None => {
            let measured = match ctx.pools.get(user_id) {
                Some(store) => measure_pool(&store).await,
                None => 0,
            };
            ctx.meter.set(user_id, measured);
            measured
        }
    };
    UserResponse::VaultCapacityResult {
        held,
        quota: ctx.meter.quota(user_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One of each verb a tenant's device says to its pool — the fifteen.
    fn tenant_verbs() -> Vec<VaultPeerRequest> {
        let u = || "alice".to_string();
        vec![
            VaultPeerRequest::ReadSealed {
                user_id: u(),
                mount: "local".into(),
                path: "p".into(),
                offset: 0,
                length: 0,
            },
            VaultPeerRequest::WriteSealed {
                user_id: u(),
                mount: "local".into(),
                path: "p".into(),
                blob: vec![1],
                domain_id: "d".into(),
                offset: 0,
                total_size: 1,
                content_hash: "h".into(),
            },
            VaultPeerRequest::ListSealed {
                user_id: u(),
                mount: "local".into(),
                prefix: String::new(),
            },
            VaultPeerRequest::RecoveryFetch { user_id: u() },
            VaultPeerRequest::RecoveryStore {
                user_id: u(),
                bundle: String::new(),
                kel: vec![],
            },
            VaultPeerRequest::NodeRelay { user_id: u() },
            VaultPeerRequest::VaultCapacity { user_id: u() },
            VaultPeerRequest::HoldDoors {
                user_id: u(),
                doors: vec![],
            },
            VaultPeerRequest::TakeDeliveries {
                user_id: u(),
                ack: vec![],
            },
            VaultPeerRequest::CarryFrame {
                user_id: u(),
                messages: vec![],
                drop: vec![],
            },
            VaultPeerRequest::TenantDevice {
                user_id: u(),
                change: kotton_wire::ipc::TenantDeviceChange {
                    act: kotton_wire::ipc::TenantDeviceAct::Admit,
                    device_did: "did:key:z".into(),
                    public_key: [0; 32],
                    said_at_ms: 0,
                },
                signature: vec![],
            },
            VaultPeerRequest::TenantDriveMake {
                user_id: u(),
                drive: kotton_wire::ipc::MadeDrive([1; 16]),
                sealed_name: vec![],
            },
            VaultPeerRequest::TenantDrives { user_id: u() },
            VaultPeerRequest::TenantDriveName {
                user_id: u(),
                drive: kotton_wire::ipc::MadeDrive([1; 16]),
                sealed_name: vec![],
            },
            VaultPeerRequest::TenantDriveRetire {
                user_id: u(),
                drive: kotton_wire::ipc::MadeDrive([1; 16]),
            },
        ]
    }

    /// The landlord's six.
    fn landlord_verbs() -> Vec<VaultPeerRequest> {
        vec![
            VaultPeerRequest::DeviceInvite {
                user_id: "sam".into(),
                ttl_seconds: 60,
                as_name: None,
            },
            VaultPeerRequest::InviteDigits {
                user_id: "sam".into(),
            },
            VaultPeerRequest::Tenants,
            VaultPeerRequest::SetQuota {
                user_id: "sam".into(),
                quota: 1 << 30,
            },
            VaultPeerRequest::DropTenant {
                user_id: "sam".into(),
            },
            VaultPeerRequest::StandAt { relays: vec![] },
        ]
    }

    /// The standing table, row by row (the module note's): the operator
    /// reaches the landlord's six and not one verb a tenant's standing
    /// reaches — no sealed read, no write, no recovery packet; a tenant's
    /// device reaches its fifteen and none of the six; a claim reaches the
    /// recovery fetch alone; a stranger reaches nothing. The sets are the
    /// module's own predicates, and they are checked disjoint here too, so a
    /// verb added to both is caught by this test rather than by review; and
    /// together they are the whole of the vault's peer wire.
    #[test]
    fn each_standing_reaches_exactly_its_row_of_the_table() {
        let claim = PeerStanding::Claim { aid: "did:kel:x".into() };
        for verb in landlord_verbs() {
            let name = verb.variant_name();
            assert!(reaches(&PeerStanding::Operator, &verb), "the operator says {name}");
            assert!(!reaches(&PeerStanding::Paired, &verb), "a tenant's device does not say {name}");
            assert!(!reaches(&claim, &verb), "a claim does not say {name}");
            assert!(!reaches(&PeerStanding::Stranger, &verb), "a stranger does not say {name}");
            assert!(!is_tenant_verb(&verb), "{name} is not a tenant's verb as well");
        }
        for verb in tenant_verbs() {
            let name = verb.variant_name();
            assert!(reaches(&PeerStanding::Paired, &verb), "a tenant's device says {name}");
            assert!(
                !reaches(&PeerStanding::Operator, &verb),
                "the operator credential does not say {name}"
            );
            assert_eq!(
                reaches(&claim, &verb),
                matches!(verb, VaultPeerRequest::RecoveryFetch { .. }),
                "a claim says the recovery fetch and nothing else: {name}"
            );
            assert!(!reaches(&PeerStanding::Stranger, &verb), "a stranger does not say {name}");
            assert!(!is_landlord_verb(&verb), "{name} is not the landlord's as well");
        }
        // The twenty-one are every verb the vault's peer wire has: each is a
        // tenant's or the landlord's, never both and never neither.
        let named: Vec<&str> = tenant_verbs().iter().chain(&landlord_verbs()).map(|v| v.variant_name()).collect();
        assert_eq!(named.len(), 21, "a tenant's fifteen and the landlord's six: {named:?}");
    }

    /// A verb that is neither — a plaintext read, a record insert — is not
    /// refused by a standing here: it is not on the vault's peer wire, and the
    /// acceptor's decoder answers it before any standing is read.
    #[test]
    fn a_plaintext_verb_is_not_a_request_on_the_vaults_peer_wire() {
        for bytes in [
            r#"{"ReadFile":{"user_id":"alice","path":"notes.txt","offset":0,"length":0}}"#,
            r#"{"RecordInsert":{"user_id":"alice","schema_nsid":"sh.kotton.notes","record":{},"root":null,"app_id":null}}"#,
        ] {
            let err = serde_json::from_str::<VaultPeerRequest>(bytes).expect_err("decoded on the vault's peer wire");
            assert!(err.to_string().contains("unknown variant"), "{err}");
        }
    }

    /// A vault's peer database with `sam`'s device paired, by its key.
    async fn a_vault_with_sams_device(sams: [u8; 32]) -> Arc<SqlitePool> {
        let db = Arc::new(SqlitePool::connect("sqlite::memory:").await.expect("db"));
        kotton_device::db::MIGRATOR.run(db.as_ref()).await.expect("migrations");
        kotton_peer::daemon::db::insert_paired_node(&db, "sams-laptop", "sam", "did:key:zSam", &sams, "[]", 0, Some("full"))
            .await
            .expect("sam's device paired");
        db
    }

    /// The refusal a key reads when its request names a pool it is not paired
    /// to (`TASK-a-vault-invite-names-a-tenant-the-device-does-not-sync-as`).
    /// A key paired here, to another pool, reads its own pool's name and the
    /// one it asked as; a key paired nowhere reads today's sentence, which
    /// names no pool it did not send — and the same whether the pool it named
    /// exists or not.
    #[tokio::test]
    async fn a_refused_key_learns_its_own_pool_and_a_key_paired_nowhere_learns_none() {
        let sams = [7u8; 32];
        let db = a_vault_with_sams_device(sams).await;
        let asked = VaultPeerRequest::VaultCapacity { user_id: "alice".into() };
        let said = |held: Option<String>| match refusal(&PeerStanding::Stranger, "did:key:zPeer", Some("alice"), held.as_deref(), &asked) {
            UserResponse::Error { message } => message,
            other => panic!("a stranger is refused: {other:?}"),
        };

        // Sam's device, asking as alice: both names, its own pool first.
        let held = held_by(&db, &PeerStanding::Stranger, Some(sams), Some("alice")).await;
        assert_eq!(held.as_deref(), Some("sam"));
        let message = said(held);
        assert!(
            message.contains("this device is paired here as tenant `sam`, and asked as `alice`"),
            "{message}"
        );

        // A key paired nowhere: today's sentence, and no pool it did not name.
        let nowhere = held_by(&db, &PeerStanding::Stranger, Some([9u8; 32]), Some("alice")).await;
        assert_eq!(nowhere, None);
        let message = said(nowhere);
        assert_eq!(message, "peer did:key:zPeer is not paired with user 'alice'");
        assert!(!message.contains("sam"), "a key paired nowhere learned a pool: {message}");

        // Only a stranger's refusal is looked up; and one naming no pool —
        // the operator's `Tenants` — is not.
        assert_eq!(held_by(&db, &PeerStanding::Paired, Some(sams), Some("alice")).await, None);
        assert_eq!(held_by(&db, &PeerStanding::Stranger, Some(sams), None).await, None);
        assert_eq!(held_by(&db, &PeerStanding::Stranger, None, Some("alice")).await, None);

        // A key two pools pair — a state `crate::devices` does not make on a
        // vault — names neither, rather than the first by name.
        kotton_peer::daemon::db::insert_paired_node(&db, "sams-laptop", "pat", "did:key:zSam", &sams, "[]", 0, Some("full"))
            .await
            .expect("a second pool's row for sam's key");
        assert_eq!(held_by(&db, &PeerStanding::Stranger, Some(sams), Some("alice")).await, None);
    }
}
