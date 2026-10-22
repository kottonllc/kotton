// SPDX-License-Identifier: AGPL-3.0-or-later
//! User lifecycle commands
//!
//! Free functions that implement user-level operations against a
//! [`kotton_identity::ProvisioningHost`] — nine named capabilities, not a
//! machine handle. **This file does not reference `DeviceRuntime` in
//! production**, which is what frees it to reach `core/identity`.
//!
//! Two of the nine are narrow on purpose: `principal()` is the one field of a
//! `RuntimeConfig` that is read, and `adopt_root()` is one operation, not the
//! entire sealed-custody handle. That is the difference between a trait that
//! *relocates* a reach and one that *shrinks* it, which is the test for these.
//! The runtime is passed by reference; all writes go through its interior-mutable fields.

use kotton_identity::provisioning::{delete_all_user_secrets, read_recovery_bundle, resolve_master_secret, resolve_operational_cek, store_operational_roots, write_recovery_bundle};
use kotton_identity::ProvisioningHost;
use crate::registry as storage;
use kotton_peer::devices::DeviceInfo;
use crate::registry::{ComponentVersions, UserRecord};
use kotton_identity::kel_store;
use kotton_store::runtime::UserKeys;
use kotton_store::runtime::user::UserStore;
use kotton_crypto::kel_verify::build_mnemonic_rotation;
use anyhow::{anyhow, Context, Result};
use kotton_sys::crypto::MnemonicProvider;
use kotton_sys::secret::SecretsStore;
use std::path::PathBuf;
use kotton_crypto::{
    generate_cek,
    try_mnemonic_to_seed32, Bip39MnemonicProvider,
    OperationalRoots,
};
use kotton_common::crypto::kdf_labels;
use kotton_crypto::daily_credential;
use kotton_session::lock_policy::{self, required_entropy_bits};
use kotton_wire::ipc::LockMode;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

// -- Operational roots & mnemonic-sealed recovery -------------------------------

// -- Public commands -----------------------------------------------------------

/// Create a new user on this machine (first device).
///
/// Generates a new DID, recovery key, and user directory structure.
/// The caller MUST save the recovery key — it's the only way to add devices later.
///
/// ## Returns the runtime; does not make it resident
///
/// Registering the runtime here would make **creating a user and deciding a
/// user is live on this machine the same act** — and the second of those is
/// the daemon's, since the daemon is what owns and ends those lifetimes.
///
/// So creation yields two things and the caller decides what to do with each:
/// the [`kotton_identity::provisioning::UserCreationResult`], which is facts a human must keep, and the
/// runtime, which is a lifetime the machine must decide about. A caller that
/// wants the user resident registers it and says so in a line, rather than the
/// work being hidden inside here.
/// Build a brand-new user's store.
///
/// It lays down no app directory: that would mean calling into the app domain,
/// and so making a *vault* link the app domain. An app directory is the app
/// domain's, and the daemon that has apps lays it down when it makes a user
/// resident (`kuserd`'s residency); a vault has no apps and lays down none.
///
/// The shelves arrive from the host rather than being named here, so a vault
/// can put the same store over a bucket. The daemon that knows it runs on an OS says so once, when it builds
/// its runtime, and nothing below it names a backend.
pub(crate) fn create_user_store(
    shelves: &dyn kotton_sys::store::Shelves,
    user_id: &str,
    did: &str,
    user_dir: PathBuf,
    keys: UserKeys,
) -> Result<kotton_store::runtime::user::UserStore> {
    kotton_store::runtime::user::UserStore::create(user_id, did, user_dir, keys, shelves)
}

/// Reopen an existing user's store. Replaces `UserStore::load`; see the note
/// on [`create_user_store`] about the shelves.
pub(crate) async fn load_user_store(
    shelves: &dyn kotton_sys::store::Shelves,
    user_id: &str,
    did: &str,
    user_dir: PathBuf,
    keys: UserKeys,
) -> Result<kotton_store::runtime::user::UserStore> {
    kotton_store::runtime::user::UserStore::load(user_id, did, user_dir, keys, shelves).await
}

pub async fn create_user(
    rt: &dyn ProvisioningHost,
    user_id: &str,
    passphrase: &str,
) -> Result<(kotton_identity::provisioning::UserCreationResult, Arc<UserStore>)> {
    if user_id.is_empty() {
        return Err(anyhow!("user_id cannot be empty"));
    }
    if user_id.contains('/') || user_id.contains('\\') {
        return Err(anyhow!("user_id cannot contain path separators"));
    }
    // A process spawned for one principal does not mint others.
    // Creating a user is device authority — it belongs to the supervisor's
    // topology, not to some other user's daemon.
    if let Some(principal) = rt.principal() {
        if principal != user_id {
            return Err(anyhow!(
                "this daemon serves '{principal}' and cannot create user '{user_id}' — \
                 user creation on a supervised device goes through kdeviced"
            ));
        }
    }

    // **The credential is assessed here, and here is the only place it can be.**
    //
    // This check used to live in `occupant_host::create_identity`, one layer up,
    // which meant it guarded the guest shell and nothing else: `kotton id create`
    // and `kctl` call this function directly and minted identities with no
    // credential at all — and, since creation stopped minting a recovery phrase,
    // with no way back in either. Two of the three doors were open.
    //
    // The fix was not a third check. `create_user` is what all three doors pass
    // through, so the requirement belongs where the identity is actually made and
    // the guard above it can be deleted. What made the check necessary was that
    // this function was reachable without one.
    //
    // Assessed *before* the registry is touched, so "too weak" is a refusal with
    // nothing created rather than an account that exists and cannot be sealed.
    daily_credential::assess(passphrase, required_entropy_bits())
        .map_err(anyhow::Error::new)?;

    let system_dir = rt.base_dir().join("system");
    let mut registry = storage::load_users(&system_dir)?;

    if registry.users.iter().any(|u| u.user_id == user_id) {
        return Err(anyhow!("User '{}' already exists", user_id));
    }

    // A new identity is a `did:kel` AID whose inception installs a **random**
    // operational key and commits **no recovery authority**. The AID is the
    // self-addressing digest of that inception — the user's DID.
    //
    // All three operational roots are random and independent of the mnemonic,
    // the identity key included.
    //
    // **No mnemonic is minted.** First run asks for nothing at the moment a person
    // has least to lose; recovery is set up afterwards with `add_recovery_phrase`,
    // which grows the committed set. An account with none says so —
    // `empty_recovery_root()` is distinguishable, so the product can tell a person
    // they have no way back in yet rather than implying they do.
    let roots = OperationalRoots {
        master_secret: generate_cek()?, // cryptographically-random 32 bytes
        identity_key: generate_cek()?,  // cryptographically-random 32 bytes
        cek: generate_cek()?,           // cryptographically-random 32 bytes
    };
    let inception = kotton_crypto::kel_verify::build_fresh_inception(
        &ed25519_dalek::SigningKey::from_bytes(&roots.identity_key),
    );
    let did = inception.aid.to_string();
    store_operational_roots(rt.secrets(), user_id, &roots);
    // Use the stable device-level fingerprint (not per-user).
    let device_fingerprint = rt.device_fingerprint().to_string();

    storage::create_user_directory(rt.base_dir(), user_id)
        .with_context(|| format!("Failed to create directory for user '{}'", user_id))?;

    // Persist the head of the user's KEL. Own-identity resolution
    // (grant issuance/verification via `KelResolver`) replays this locally — no
    // network — honoring the machine-count invariant.
    kel_store::append_event(rt.base_dir(), user_id, &inception)?;

    // No recovery bundle here: there is no phrase yet to seal one under.
    // `add_recovery_phrase` writes it when a person sets recovery up.

    let now = SystemTime::now();
    registry.users.push(UserRecord {
        user_id: user_id.to_string(),
        did: did.clone(),
        did_method: "kel".to_string(),
        aliases: vec![],
        created_at: now,
        last_active: now,
        versions: ComponentVersions::default(),
    });
    storage::save_users(&system_dir, &registry)?;

    let mut routing = storage::load_device_routing(&system_dir)?;
    routing
        .routes
        .insert(device_fingerprint.clone(), user_id.to_string());
    storage::save_device_routing(&system_dir, &routing)?;

    rt.register_device(device_fingerprint.clone(), user_id.to_string());

    let user_dir = rt.base_dir().join("users").join(user_id);
    let user_runtime = create_user_store(
        rt.shelves(),
        user_id,
        &did,
        user_dir.clone(),
        // The canonical key assembly, exactly as the load/unlock path does it,
        // so a freshly created user's mount carries the history log from the
        // start rather than only after its first reload. Hand-
        // rolling `UserKeys::new(Some(cek))` here dropped the log key — the very
        // "a call site builds a runtime with a key missing" slip that
        // `resolve_user_keys` exists to prevent.
        resolve_user_keys(rt.secrets(), user_id, rt.device_did())?,
    )?;

    let device_info = DeviceInfo {
        device_id: format!("device_{}", user_id),
        device_name: hostname::get()
            .ok()
            .and_then(|h| h.to_str().map(String::from))
            .unwrap_or_else(|| "Unknown Device".to_string()),
        fingerprint: device_fingerprint.clone(),
        added_at: now,
        last_seen: now,
    };

    // The device list is `peer`'s and the config is the store's: two files,
    // no shared state, so two calls. `UserStore` bundled them behind one
    // `save()`, which is what made a device list look like store business.
    let mut devices = kotton_peer::devices::DeviceList::load(&user_dir)?;
    devices.add(device_info)?;
    devices.save(&user_dir)?;
    user_runtime.save_config()?;

    // Record the lock mode and seal the vault under the credential, so a cold
    // start can reopen it. Both used to live in `occupant_host`, which is why an
    // identity made from the CLI had a keychain copy of its roots and no sealed
    // one — working until the keychain was cleared, and then gone.
    //
    // Ordering: after the roots are stored, because sealing reads them back.
    // The passphrase is judged before the seal and recorded after it, the order
    // every door that sets one keeps: the record never names a passphrase this
    // device holds nothing under. No binding exists at creation, so nothing
    // counts: the passphrase bar.
    let policy = lock_policy::prepare_policy(
        LockMode::Passphrase,
        0,
        Some(passphrase),
        kotton_sys::secret::AttemptLimiting::None,
    )
    .map_err(|e| anyhow!("{e}"))?;
    // Seals *and* purges the platform's plaintext copies. An
    // account is locked from the moment it exists, so a restart needs the
    // credential and the OS keychain is defence-in-depth rather than the trust
    // boundary, which is what `os.rs` has always claimed it was.
    //
    // It rests on two things: the unlock screen, and `records.db` and `agent.db`
    // refusing when the master is unresolvable rather than opening *unencrypted*,
    // which would make a locked account read as a corrupt one.
    kotton_identity::provisioning::set_user_pin(rt, user_id, passphrase).await?;
    policy.record(rt.base_dir(), user_id).map_err(|e| anyhow!("{e}"))?;

    Ok((
        kotton_identity::provisioning::UserCreationResult {
            user_id: user_id.to_string(),
            did,
            device_fingerprint,
        },
        Arc::new(user_runtime),
    ))
}

/// Login with a recovery key (BIP39 mnemonic) on a new or existing device.
///
/// **A phrase is checked against a key log, never taken on a name's word.** The
/// DID is not derived from the phrase, which cannot compute it. What a phrase can
/// do is reveal the reserve key a log commits, and [`phrase_holds_authority`] asks
/// exactly that of a log: the question `recover` asks before it installs anything,
/// and the one a node asks before it serves a chain. Which log is asked is what
/// `user_id_hint` says:
///
/// - **A name** names the log. If this device holds anything under that name (a
///   record, a resident store, a key log, a copy of a root), the phrase must be an
///   authority in that name's log, or the login is refused and nothing is written.
///   A name this device holds nothing under has no log here to check the phrase
///   against: it is claimed locked, with no DID and no key, and only `recover`
///   proves the phrase, against a chain fetched from a paired node, before
///   installing anything.
/// - **No name** asks every local log, and the user whose log commits the phrase
///   is the one logged in.
///
/// A phrase that proves opens the user with the data roots from the copy sealed
/// under it and the signing key this device already holds. It makes no root: a
/// login that made new data roots would write them over the ones the user's data
/// is keyed from.
///
/// Returns `(user_id, device_fingerprint, runtime)` on success.
///
/// Like [`create_user`], it hands back the runtime rather than making it
/// resident, so the daemon has the handle it needs to read the DID rather than
/// re-resolving the user from the registry. `resident` is the caller's answer to
/// "is the user the name names already live here?": the registry of live users is
/// the daemon's, so only the caller can know.
pub async fn login_with_recovery_key(
    rt: &dyn ProvisioningHost,
    recovery_key: &str,
    user_id_hint: Option<&str>,
    device_name: Option<String>,
    resident: Option<Arc<UserStore>>,
) -> Result<(String, String, Arc<UserStore>)> {
    let seed32 = try_mnemonic_to_seed32(recovery_key).map_err(|e| anyhow!(e))?;

    let system_dir = rt.base_dir().join("system");
    let mut registry = storage::load_users(&system_dir)?;

    // Which log the phrase is checked against: the one the name names, or, with
    // no name, the local log that commits it.
    let user_id = match user_id_hint {
        Some(name) => name.to_string(),
        None => registry
            .users
            .iter()
            .find(|u| {
                kel_store::load_chain(rt.base_dir(), &u.user_id)
                    .is_ok_and(|chain| phrase_holds_authority(&chain, &seed32))
            })
            .map(|u| u.user_id.clone())
            .ok_or_else(|| {
                anyhow!(
                    "No identity on this device has this recovery phrase as an authority. \
                     If this device has never held the identity, its key history is not here \
                     to check the phrase against yet."
                )
            })?,
    };
    let user_id = &user_id;
    let chain = kel_store::load_chain(rt.base_dir(), user_id)?;

    if !phrase_holds_authority(&chain, &seed32) {
        // The phrase is no authority in this name's log, and an empty log commits
        // nothing. That refuses the login whenever this device holds anything under
        // the name: what it holds is someone's, and a phrase that does not prove
        // gets none of it.
        let held = registry.users.iter().any(|u| &u.user_id == user_id)
            || resident.is_some()
            || user_dir_for(rt, user_id).exists()
            || stored_identity_key(rt, user_id)?.is_some()
            || resolve_master_secret(rt.secrets(), user_id)?.is_some();
        if held {
            return Err(anyhow!(
                "this recovery phrase is not an authority in '{user_id}'s key log on this \
                 device, so nothing was opened or written"
            ));
        }
        return claim_locked(rt, &system_dir, &mut registry, user_id, device_name);
    }

    if let Some(existing) = resident {
        // Resident is not the same as unlocked. A user loaded at daemon start has a
        // `UserStore` and may hold no roots, which is the state a locked account
        // boots into; so the roots are put back from the copy the phrase opens when
        // they are not held, and the device, already registered, is not registered
        // again. "Not held" is the store answering that it holds none: a store
        // that could not answer refuses here, since the restore writes all three
        // roots and would write them over the ones it could not read.
        if resolve_master_secret(rt.secrets(), user_id)
            .with_context(|| format!("'{user_id}'s roots could not be read on this device, so nothing was restored over them"))?
            .is_none()
        {
            let data = read_recovery_bundle(rt.base_dir(), user_id, &seed32)?.ok_or_else(|| {
                anyhow!(
                    "'{user_id}' is locked on this device and has no recovery bundle, so \
                     this phrase cannot reopen it. Unlock with the device credential \
                     instead."
                )
            })?;
            // The data roots open under the phrase; the signing key is only ever
            // this device's own. Without one, the device must rotate.
            let identity_key = stored_identity_key(rt, user_id)?.ok_or_else(|| {
                anyhow!(
                    "'{user_id}' is locked on this device and its signing key is gone. The \
                     phrase opens the data but never re-installs a key silently — run \
                     `kotton id recover`, which rotates the identity onto this device."
                )
            })?;
            store_operational_roots(
                rt.secrets(),
                user_id,
                &OperationalRoots { master_secret: data.master_secret, identity_key, cek: data.cek },
            );
        }
        // A re-authentication, after a session lock or expiry. The daemon handler
        // issues a fresh session token.
        return Ok((user_id.clone(), rt.device_fingerprint().to_string(), existing));
    }

    let did = registry
        .users
        .iter()
        .find(|u| &u.user_id == user_id)
        .map(|u| u.did.clone())
        .ok_or_else(|| {
            anyhow!(
                "'{user_id}'s key log on this device commits this phrase, but the device holds \
                 no record of '{user_id}'; `kotton id recover` brings the identity onto it"
            )
        })?;

    // The two data roots come from the copy sealed under this phrase, and the
    // signing key is the one this device holds: a phrase opens the copy, it derives
    // nothing, and it never re-installs a signing key (`recover` rotates onto a new
    // one, visibly).
    let data = read_recovery_bundle(rt.base_dir(), user_id, &seed32)?.ok_or_else(|| {
        anyhow!(
            "this phrase is an authority for '{user_id}', but no copy of its data sealed \
             under the phrase is on this device, and a phrase login makes no data root"
        )
    })?;
    let identity_key = stored_identity_key(rt, user_id)?.ok_or_else(|| {
        anyhow!(
            "the phrase opens '{user_id}'s data on this device, but the signing key is gone \
             and a phrase never re-installs one silently. Run `kotton id recover`, which \
             rotates the identity onto this device and installs the data roots."
        )
    })?;
    let roots = OperationalRoots { master_secret: data.master_secret, identity_key, cek: data.cek };

    let user_runtime = load_user_store(
        rt.shelves(),
        user_id,
        &did,
        user_dir_for(rt, user_id),
        UserKeys::new(Some(roots.cek)),
    )
    .await
    .with_context(|| format!("Failed to load user runtime for '{}'", user_id))?;

    let device_fingerprint = register_this_device(rt, user_id, device_name)?;
    user_runtime.save_config()?;
    store_operational_roots(rt.secrets(), user_id, &roots);

    Ok((user_id.clone(), device_fingerprint, Arc::new(user_runtime)))
}

/// Claim `user_id` **locked** on a device that holds nothing under that name: a
/// registered user with no DID and no roots, the state a locked account boots
/// into. There is no log here to check a phrase against, so nothing is installed;
/// `recover` fetches the chain and the sealed copy from a paired node, proves the
/// phrase against the chain, and only then installs anything. Until it runs, this
/// device holds a name and no key.
fn claim_locked(
    rt: &dyn ProvisioningHost,
    system_dir: &Path,
    registry: &mut storage::UsersRegistry,
    user_id: &str,
    device_name: Option<String>,
) -> Result<(String, String, Arc<UserStore>)> {
    let now = SystemTime::now();
    registry.users.push(UserRecord {
        user_id: user_id.to_string(),
        did: String::new(),
        did_method: "kel".to_string(),
        aliases: vec![],
        created_at: now,
        last_active: now,
        versions: ComponentVersions::default(),
    });
    storage::save_users(system_dir, registry)?;
    storage::create_user_directory(rt.base_dir(), user_id)
        .with_context(|| format!("Failed to create directory for '{}'", user_id))?;

    tracing::info!(
        user_id = %user_id,
        "identity claimed on a device that has never held it; locked until `recover`"
    );
    let user_runtime =
        create_user_store(rt.shelves(), user_id, "", user_dir_for(rt, user_id), UserKeys::new(None))
            .with_context(|| format!("Failed to initialise user runtime for '{}'", user_id))?;
    let device_fingerprint = register_this_device(rt, user_id, device_name)?;
    user_runtime.save_config()?;
    Ok((user_id.to_string(), device_fingerprint, Arc::new(user_runtime)))
}

/// The identity signing key this device already holds for `user_id`, if any.
/// The only place a signing key ever comes from on a phrase login.
///
/// `Ok(None)` only when the store answered that it holds none; a store that
/// could not be read is its error, so a phrase login says what went wrong
/// instead of "the signing key is gone".
fn stored_identity_key(rt: &dyn ProvisioningHost, user_id: &str) -> Result<Option<[u8; 32]>> {
    let label = kdf_labels::identity_signing_key(user_id);
    Ok(rt
        .secrets()
        .get_secret(&label)
        .map_err(|e| anyhow!("could not read {label} from the secrets store: {e}"))?
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok()))
}

fn user_dir_for(rt: &dyn ProvisioningHost, user_id: &str) -> PathBuf {
    rt.base_dir().join("users").join(user_id)
}

/// Record this machine as one of `user_id`'s devices: the device list in the
/// user directory, the fingerprint → user route, and the runtime's routing table.
/// Returns the fingerprint. Shared by every path that brings an identity onto a
/// device, including the locked claim a cold `login` makes.
fn register_this_device(
    rt: &dyn ProvisioningHost,
    user_id: &str,
    device_name: Option<String>,
) -> Result<String> {
    let user_dir = user_dir_for(rt, user_id);
    let system_dir = rt.base_dir().join("system");
    let device_fingerprint = rt.device_fingerprint().to_string();
    let now = SystemTime::now();

    let mut devices = kotton_peer::devices::DeviceList::load(&user_dir)?;
    devices.add(DeviceInfo {
        device_id: format!("device_{}_{}", user_id, device_fingerprint),
        device_name: device_name.unwrap_or_else(|| {
            hostname::get()
                .ok()
                .and_then(|h| h.to_str().map(String::from))
                .unwrap_or_else(|| "Unknown Device".to_string())
        }),
        fingerprint: device_fingerprint.clone(),
        added_at: now,
        last_seen: now,
    })?;
    devices.save(&user_dir)?;

    let mut routing = storage::load_device_routing(&system_dir)?;
    routing
        .routes
        .insert(device_fingerprint.clone(), user_id.to_string());
    storage::save_device_routing(&system_dir, &routing)?;

    rt.register_device(device_fingerprint.clone(), user_id.to_string());
    Ok(device_fingerprint)
}

/// Does this phrase hold recovery authority over `chain`?
///
/// Derives the rung of the phrase's ladder the chain is standing on and asks
/// whether the tip's committed set contains it — the same check a recovery
/// event is held to by `validate`, so a phrase that passes here produces an
/// event that is accepted rather than one that looks right and is rejected.
/// Verifies rather than derives: the AID is random and the phrase cannot compute
/// it, and this is the stronger question anyway ("may this phrase act for it?").
pub fn phrase_holds_authority(chain: &[kotton_wire::kel::KelEvent], seed32: &[u8; 32]) -> bool {
    // One implementation, `kel_verify`'s: a node serving a chain to a recovering
    // device asks the identical question, and two copies of a test that gates the
    // same authority is the shape that produced the `next_recovery_index` bug. It
    // also reads past a `RotationCooperative` tip, which carries no set of its own.
    let index = kotton_crypto::kel_verify::next_recovery_index(chain);
    let member = kotton_crypto::kel_verify::kel_recovery_pubkey(
        &kotton_crypto::kdf::derive_kel_recovery_key(seed32, index),
    );
    kotton_crypto::kel_verify::tip_commits_recovery_key(chain, &member)
}

// ── Key health and migration — `core/crypto`'s ────────────────────────────────
//
// The wrappers resolve what the domain deliberately does not know: whether a PIN
// is set (the runtime owns the vault filename — see `pin_is_set`) and which DID
// this user has (reading the registry would make `crypto` depend on the
// runtime's storage module).

pub use kotton_crypto::key_health::{KeyHealthResult, RecoveryLayerStatusResult};

// ── Recovery status and mnemonic confirmation — moved to `core/identity` ──────
//
// The wrappers supply the one thing the domain deliberately does not know:
// whether a PIN vault exists. The runtime owns that filename (see `pin_is_set`),
// and duplicating the probe is how it was wrong before.

pub use kotton_identity::recovery::RecoveryStatus;

/// Load existing users from disk into the runtime.
///
/// Called once at startup when the machine is built. When the config names a
/// [`principal`](crate::config::RuntimeConfig::principal) (this process was
/// spawned for one user), only that user is loaded and only that user's keys
/// are resolved; everyone else on the device stays out of this process's
/// memory. With no principal (unsupervised dev/compat mode) every user loads,
/// as one daemon always has.
/// Load every user this process is permitted to serve, and **return** them.
///
/// Returns rather than registers: which users a process loads is a question
/// about principal scoping, answered here from the on-disk registry and
/// `config.principal`; which loaded users are
/// *resident* is the daemon's bookkeeping. Splitting them also makes the
/// principal-scoping tests assert on a returned set rather than on hidden state,
/// which is the stronger assertion — a load that silently registered nobody used
/// to look identical to one that registered everybody until something else
/// asked.
pub(crate) async fn load_users_on_startup(
    rt: &dyn ProvisioningHost,
) -> Result<Vec<(String, Arc<UserStore>)>> {
    let system_dir = rt.base_dir().join("system");

    let registry = storage::load_users(&system_dir).context("Failed to load users registry")?;

    let routing_data =
        storage::load_device_routing(&system_dir).context("Failed to load device routing")?;

    rt.restore_device_routes(routing_data.routes);

    let principal = rt.principal();
    let serving = |record: &UserRecord| match principal {
        // Matched by DID (what kdeviced spawns with) or user id (dev launches).
        Some(p) => record.did == p || record.user_id == p,
        None => true,
    };
    if let Some(p) = principal {
        let others = registry.users.iter().filter(|u| !serving(u)).count();
        if !registry.users.iter().any(&serving) {
            // Not fatal: a joining device starts with no record for its user
            // (DeviceJoin creates it), and the strict fail-without-it form is
            // not built. Nothing loads meanwhile.
            tracing::warn!(principal = %p, "no user record matches this daemon's principal yet");
        } else if others > 0 {
            tracing::info!(
                principal = %p,
                skipped = others,
                "serving one principal; other users on this device are not loaded into this process"
            );
        }
    }

    let mut loaded = Vec::new();
    for user_record in registry.users.iter().filter(|u| serving(u)) {
        let user_dir = rt.base_dir().join("users").join(&user_record.user_id);
        // Keys the store could not read load the user **keyless** — the state a
        // locked account boots into, and nothing in it writes or
        // mints: a keyless store migrates nothing and opens no database, and the
        // resolvers no longer fall back to a key derived from another root, so
        // keyless means no keys, never wrong ones. A locked keychain is
        // transient; the next unlock's `rekey_resident_store` rebuilds this
        // store with the roots it restores. Skipping the user instead left no
        // resident store for any unlock to rekey until the daemon restarted.
        let keys = match resolve_user_keys(rt.secrets(), &user_record.user_id, rt.device_did()) {
            Ok(keys) => keys,
            Err(e) => {
                tracing::warn!(
                    user_id = %user_record.user_id,
                    "the secrets store could not be read; loaded keyless until the next unlock: {e:#}"
                );
                UserKeys::new(None)
            }
        };
        match load_user_store(
            rt.shelves(),
            &user_record.user_id,
            &user_record.did,
            user_dir,
            keys,
        )
        .await
        {
            Ok(user_runtime) => {
                // Bring a pre-blinding store up to blinded keys before it
                // serves anything. Best-effort — a failure leaves the mount Plain
                // with plaintext fallback (still readable), and the resumable pass
                // retries next startup.
                if let Err(e) = user_runtime.migrate_pending_mounts().await {
                    tracing::warn!(
                        user_id = %user_record.user_id,
                        "RFC-0044 mount migration deferred: {e}"
                    );
                }
                loaded.push((user_record.user_id.clone(), user_runtime));
            }
            Err(e) => {
                eprintln!(
                    "Warning: Failed to load user '{}': {}",
                    user_record.user_id, e
                );
            }
        }
    }

    Ok(loaded
        .into_iter()
        .map(|(user_id, runtime)| (user_id, Arc::new(runtime)))
        .collect())
}

// -- Recovery status ----------------------------------------------------------

// -- Key health ---------------------------------------------------------------

// -- Post-quantum migration ---------------------------------------------------

// -- Private helpers -----------------------------------------------------------

/// The minimum contest window carried on a mnemonic recovery rotation.
/// For a lone factor it is moot — the recovery finalizes immediately — but it is
/// committed (signed) now so it becomes load-bearing the moment the witnessed
/// multi-factor arbiter lands (`RECOVERY-ARBITER.md`), with no schema change.
const RECOVERY_CONTEST_MIN_SECONDS: u64 = 7 * 24 * 60 * 60;

// -- Tests ---------------------------------------------------------------------

/// Resolve every leaf key a [`UserKeys`] carries, from the secrets store.
///
/// The single place a runtime's keys are assembled, so a new key (the pack
/// key, the log key) is added here rather than at each call site —
/// and so no call site can accidentally build a runtime with one key missing.
///
/// A root the store could not read is an error, not a key the user lacks: a
/// runtime built keyless over it would read as locked, and one created over it
/// would carry no CEK for data that has one.
pub(crate) fn resolve_user_keys(
    secrets: &(dyn SecretsStore + Send + Sync),
    user_id: &str,
    device_did: &str,
) -> Result<UserKeys> {
    let keys = UserKeys::new(resolve_operational_cek(secrets, user_id)?);
    // History is db-domain, so it needs `master_secret` rather than the CEK. A
    // node that holds the CEK but not `master_secret` — a blind storage node, a
    // FROST-joined device — therefore packs and reads objects but appends no
    // history, which is the correct behaviour rather than a degradation: it
    // could not open a segment it wrote.
    Ok(match resolve_master_secret(secrets, user_id)? {
        Some(ms) => keys.with_log(device_did, &ms),
        None => keys,
    })
}

/// Give this identity a recovery phrase — the "set up recovery" action.
///
/// Generates a BIP-39 mnemonic, commits its first reserve key
/// (`pub(K_rec[0])`) by **growing** the identity's recovery set, and seals
/// mnemonic-recoverable copies of the random operational roots. Returns the
/// mnemonic, which is shown once and never stored.
///
/// # Why this exists as its own action
///
/// A fresh identity is minted with **no** recovery authority
/// (`build_fresh_inception`), so first run asks for nothing at the moment a person
/// has least to lose. Recovery is set up afterwards, when they add a device, buy
/// storage, or ask for it — and this is that step.
///
/// The event is `RotationAddRecovery`, authorized by the operational key already on
/// this device. That is safe because the growth rule forbids subtraction: this can
/// add a way in and can never remove one, so it cannot be used to evict an existing
/// authority even by someone holding the device.
///
/// Adding a *second* authority later goes through this same path and costs no more
/// than the first, which is the point — adding devices and storage are ordinary
/// repeated actions, not ceremonies.
pub async fn add_recovery_phrase(
    base_dir: &Path,
    secrets: &(dyn SecretsStore + Send + Sync),
    user_id: &str,
) -> Result<String> {
    let chain = kotton_identity::kel_store::load_chain(base_dir, user_id)?;
    let prev = chain
        .last()
        .ok_or_else(|| anyhow!("user '{user_id}' has no KEL (legacy did:key account)"))?;

    let mnemonic = Bip39MnemonicProvider
        .generate()
        .map_err(|e| anyhow!("Failed to generate mnemonic: {}", e))?;
    let seed32 = try_mnemonic_to_seed32(&mnemonic).map_err(|e| anyhow!(e))?;
    let krec0 = kotton_crypto::kel_verify::kel_recovery_pubkey(
        &kotton_crypto::kdf::derive_kel_recovery_key(&seed32, 0),
    );

    // Grow, never replace. The prior set is carried on the event that committed it,
    // which is why `recovery_set` travels in the clear — containment is not a
    // property a Merkle root can prove.
    let mut set = prev.recovery_set.clone();
    // Not a user-facing refusal: the phrase was generated three lines up, so a
    // collision here means the RNG repeated itself. It is kept as the assertion it
    // actually is, because the failure it catches is one a person could not see —
    // an "added" authority that silently was not.
    if set.contains(&krec0) {
        return Err(anyhow!(
            "generated a recovery phrase already committed for this identity — refusing \
             rather than reporting an authority that was not added"
        ));
    }
    set.push(krec0);

    let signing_hex = secrets
        .get_secret(&kdf_labels::identity_signing_key(user_id))
        .context("reading the operational key")?
        .ok_or_else(|| anyhow!("no operational key for '{user_id}' — cannot authorize"))?;
    let signing_bytes: [u8; 32] = hex::decode(signing_hex)
        .context("identity signing key is not hex")?
        .try_into()
        .map_err(|_| anyhow!("identity signing key is not 32 bytes"))?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&signing_bytes);

    let event = kotton_crypto::kel_verify::build_add_recovery(prev, &set, &sk);
    kotton_identity::kel_store::append_event(base_dir, user_id, &event)?;

    // Seal recovery copies of the random roots under the new phrase. Until this
    // point the identity had no phrase, so there was nothing to seal them to.
    let master_secret = resolve_master_secret(secrets, user_id)?
        .ok_or_else(|| anyhow!("no master_secret for '{user_id}'"))?;
    let cek = resolve_operational_cek(secrets, user_id)?
        .ok_or_else(|| anyhow!("no CEK for '{user_id}'"))?;
    write_recovery_bundle(base_dir, user_id, &seed32, &master_secret, &cek)?;

    Ok(mnemonic)
}

/// Rotate the user's operational identity key via a **mnemonic recovery rotation**
/// (the headline "survive key compromise" move).
///
/// Reveals the pre-committed reserve key `K_rec[i]` (mnemonic-derived — an attacker
/// holding the *current* key cannot open it), installs a fresh **random**
/// operational key as the new authoritative key-state, pre-commits the next reserve,
/// and appends the rotation to the user's KEL. The `did:kel` AID is **unchanged** —
/// the identity survives the key change; every future signature uses the new key and
/// signatures by the old (compromised) key stop verifying.
///
/// Single-device (lone factor) today: the rotation finalizes immediately. Returns
/// the new operational verifying key (hex). Errors if the mnemonic does not match
/// this identity or the user has no KEL (a legacy `did:key` account cannot rotate).
///
/// **The vault follows the key.** A person with a vault keeps the durable copy of
/// their roots there, and every unlock restores what it seals; a rotation that
/// left it sealing the retired key would be undone by the next restart. So the
/// vault is re-sealed under `credential` once the new key is stored. Custody
/// holds the roots and never the credential, nor the key derived from it, so the
/// credential is asked for — the same reason `bind_device` asks — and proved by
/// opening the vault **before** anything irreversible. The new vault is sealed
/// before the key log is appended and renamed into place after, so a rotation
/// either lands with its vault or leaves nothing changed; a crash between the two
/// is finished by the next unlock. Two refusals, both with
/// nothing changed: a person with a vault and no credential, and a person with a
/// vault who is locked, whose retiring key reads as absent and would otherwise be
/// kept by nobody.
pub async fn rotate_identity_via_mnemonic(
    rt: &dyn ProvisioningHost,
    user_id: &str,
    recovery_key: &str,
    credential: Option<&str>,
) -> Result<String> {
    let has_vault =
        kotton_identity::provisioning::pin_is_set(&rt.base_dir().join("users").join(user_id));
    let reseal_under = if has_vault {
        let credential = credential.ok_or_else(|| {
            anyhow!(
                "'{user_id}' keeps their keys in a vault sealed under their passphrase, and a \
                 rotation re-seals it around the new key — give the passphrase with the rotation"
            )
        })?;
        let live = kotton_identity::provisioning::open_vault_under(rt, user_id, credential)
            .context("the rotation was refused and nothing changed")?;
        // A staged vault left by an earlier rotation is settled first — it may
        // be the only sealed copy of the key the log installs, and staging this
        // rotation would overwrite it. What cannot be settled refuses. So does
        // one that was just promoted: custody still holds the key the live vault
        // restored, not the one the log installs, and a rotation from here would
        // retire the wrong key and leave the installed one held nowhere. The
        // unlock is what moves the promoted roots into custody.
        if kotton_identity::provisioning::settle_staged_vault(rt, user_id, credential, &live)
            .is_some()
        {
            return Err(anyhow!(
                "an earlier rotation's vault for '{user_id}' was completed just now; unlock \
                 again so this device holds the key it installed, then rotate — nothing else \
                 changed"
            ));
        }
        if rt
            .base_dir()
            .join("users")
            .join(user_id)
            .join(kotton_identity::provisioning::STAGED_VAULT_FILE)
            .exists()
        {
            return Err(anyhow!(
                "an earlier rotation's vault for '{user_id}' could not be settled; the rotation \
                 was refused and nothing changed"
            ));
        }
        if rt
            .secrets()
            .get_secret(&kdf_labels::identity_signing_key(user_id))
            .map_err(|e| anyhow!("read the identity key being retired: {e}"))?
            .is_none()
        {
            return Err(anyhow!(
                "'{user_id}' is locked on this device; unlock first — a rotation from here \
                 would keep no retired key and seal the vault without one"
            ));
        }
        Some(credential)
    } else {
        None
    };

    // A fresh random operational key (operational material is random, not
    // mnemonic-derived — only the reserve lineage is).
    let new_sk = ed25519_dalek::SigningKey::from_bytes(&generate_cek()?);

    // The vault is sealed around the new key **before** the append, because the
    // append cannot be taken back: a re-seal that fails after it has landed the
    // rotation with the vault sealing the retired key, and the next unlock
    // restores that one.
    // Staged beside the vault, under the same credential and against the same
    // binding; the live vault is not touched until the key log names the new key.
    if let Some(credential) = reseal_under {
        kotton_identity::provisioning::stage_rotated_vault(
            rt,
            user_id,
            credential,
            &new_sk.to_bytes(),
        )
        .context("the rotation was refused and nothing changed: the vault could not be sealed around the new key")?;
    }

    let rotated =
        rotate_identity_to_key(rt.base_dir(), rt.secrets(), user_id, recovery_key, &new_sk).await;

    // Whatever `rotate_identity_to_key` returned, the key log decides: once it
    // installs the new key, the staged vault is the vault — even when a later
    // step failed, since the next unlock must restore the key the log names.
    // Until then it seals a key nothing installed, and goes.
    if reseal_under.is_some() {
        match kotton_identity::provisioning::key_log_installs(
            rt.base_dir(),
            user_id,
            &new_sk.to_bytes(),
        ) {
            Ok(true) => {
                if let Err(e) = kotton_identity::provisioning::commit_staged_vault(rt, user_id) {
                    // The key is rotated and stored; the sealed copy of it is
                    // whole beside the vault, and the next unlock renames it in.
                    tracing::warn!(
                        user_id = %user_id,
                        "the key was rotated and its vault is staged; the next unlock \
                         finishes it: {e:#}"
                    );
                }
            }
            Ok(false) => kotton_identity::provisioning::discard_staged_vault(rt, user_id),
            // Kept for the unlock to decide: it may be the only sealed copy of
            // the key the log installs.
            Err(e) => tracing::warn!(
                user_id = %user_id,
                "the key log could not be read after a rotation; its staged vault is \
                 kept for the next unlock to decide: {e:#}"
            ),
        }
    }
    rotated?;
    Ok(hex::encode(new_sk.verifying_key().to_bytes()))
}

/// The recovery rotation itself: reveal the reserve rung, install `new_sk` as the
/// identity's operational key, append the event, and replace the stored key.
///
/// Two callers, one rule. `rotate_identity_via_mnemonic` passes a random key;
/// `recover` passes **this device's own** key, because a node admits a recovered
/// device by comparing its TLS key to the chain's group key
/// (`admits_device`) — the rotation is what turns the device into the identity's
/// signer. Returns the event, which is what the recovering device then offers.
pub async fn rotate_identity_to_key(
    base_dir: &Path,
    secrets: &dyn SecretsStore,
    user_id: &str,
    recovery_key: &str,
    new_sk: &ed25519_dalek::SigningKey,
) -> Result<kotton_wire::kel::KelEvent> {
    Bip39MnemonicProvider
        .validate(recovery_key)
        .map_err(|e| anyhow!("Invalid mnemonic: {}", e))?;
    let seed32 = try_mnemonic_to_seed32(recovery_key).map_err(|e| anyhow!(e))?;

    let chain = kotton_identity::kel_store::load_chain(base_dir, user_id)?;
    let prev = chain
        .last()
        .ok_or_else(|| anyhow!("user '{user_id}' has no KEL to rotate (legacy did:key account)"))?;

    // The reserve index is the number of recovery rotations already applied (0 for
    // the first — the inception committed `pub(K_rec[0])`). Counted by the shared
    // helper rather than inline: a second copy of this rule is easy to get
    // wrong by omitting guardian recoveries, which builds an event against the
    // wrong rung.
    let recovery_index = kotton_crypto::kel_verify::next_recovery_index(&chain);

    // The phrase must hold recovery authority over *this* identity. It used to be
    // checked by reconstructing the AID from the mnemonic and comparing — which
    // only worked while the identity derived from the phrase, and asked the weaker
    // question anyway ("did this phrase mint this identity?" rather than "may this
    // phrase act for it?").
    //
    // Checked against the committed set instead: derive the reserve key for the
    // rung this chain is standing on, and require it to be a member. That is the
    // same verification a recovery event will be held to by `validate`, so a phrase
    // that passes here produces an event that is accepted rather than one that
    // looks right and is rejected downstream.
    let reserve = kotton_crypto::kel_verify::kel_recovery_pubkey(
        &kotton_crypto::kdf::derive_kel_recovery_key(&seed32, recovery_index),
    );
    let holds_authority = kotton_crypto::kel_verify::recovery_proof(&prev.recovery_set, &reserve)
        .is_some_and(|proof| {
            kotton_crypto::kel_verify::verify_recovery_inclusion(
                &prev.recovery_commitment,
                &reserve,
                &proof,
            )
        });
    if !holds_authority {
        return Err(anyhow!(
            "this recovery phrase is not an authority for this identity"
        ));
    }

    let new_identity_key = new_sk.to_bytes();
    // The prior commitment is a *set*, so building the event needs
    // the set it commits to, not just the key being revealed. Today every identity
    // commits a one-member set holding the mnemonic reserve, so that is what is
    // passed; when an identity can hold several authorities this is where the rest
    // of them have to come from, and `build_mnemonic_rotation`'s doc says why that
    // is an open question rather than an oversight.
    let prior_set = [kotton_crypto::kel_verify::kel_recovery_pubkey(
        &kotton_crypto::kdf::derive_kel_recovery_key(&seed32, recovery_index),
    )];
    let rotation = build_mnemonic_rotation(
        prev,
        &seed32,
        recovery_index,
        new_sk,
        RECOVERY_CONTEST_MIN_SECONDS,
        &prior_set,
    );

    // Keep the key being replaced — sealed to its successor, beside the key log —
    // so that what was sealed to it still opens for the person: every message they
    // received, and their own copy of every one they sent.
    // Before anything irreversible, and refusing the rotation if it cannot be kept:
    // a rotation that costs the person their history is not one to finish quietly.
    // "Could not read the key" is a refusal, not "there is no key": only a label
    // the store answers as empty — a node that never held the old key, such as a
    // recovery onto a new device — has nothing to keep.
    let retiring = match secrets.get_secret(&kdf_labels::identity_signing_key(user_id)) {
        Ok(None) => None,
        Ok(Some(hex_key)) => Some(
            hex::decode(&hex_key)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .map(|b| ed25519_dalek::SigningKey::from_bytes(&b))
                .ok_or_else(|| anyhow!("the identity key being retired is not 32 hex bytes"))?,
        ),
        Err(e) => return Err(anyhow!("read the identity key being retired: {e}")),
    };
    if let Some(retiring) = retiring.filter(|k| k.to_bytes() != new_sk.to_bytes()) {
        kotton_identity::retired_keys::retire(
            base_dir,
            user_id,
            &retiring,
            &new_sk.verifying_key().to_bytes(),
        )
        .map_err(|e| anyhow!("keep the retiring identity key: {e}"))?;
    }

    kotton_identity::kel_store::append_event(base_dir, user_id, &rotation)?;

    // Replace the operational identity key so all future signing uses the new key.
    // The AID (UserRecord.did) is unchanged — the identity is continuous.
    secrets
        .set_secret(
            &kdf_labels::identity_signing_key(user_id),
            &hex::encode(new_identity_key),
        )
        .map_err(|e| anyhow!("persist rotated identity key: {e}"))?;

    // The new key is stored: drop any set of retired keys it does not open, so
    // nothing left on disk opens on a retired key. Best-effort — a set left
    // behind is one no current key reads, and the next rotation drops it.
    if let Err(e) = kotton_identity::retired_keys::settle(base_dir, user_id, new_sk) {
        tracing::warn!(user_id = %user_id, "could not settle retired identity keys: {e}");
    }

    // The rotation makes the identity a fresh 1-of-1 under the new key. Any prior
    // FROST material (shares of the RETIRED key) is now stale — clear it so a
    // stale threshold-sign cannot run against the old key-state. Devices rejoin
    // the quorum by re-enrolling under the new key (fleet re-establishment).
    let _ = secrets
        .delete_secret(&kdf_labels::frost_share(user_id));
    let _ = secrets
        .delete_secret(&kdf_labels::frost_pubkey_package(user_id));

    Ok(rotation)
}

/// Remove a user from this device (local only).
///
/// Deletes the user's directory and removes them from the on-disk registry.
/// The in-memory `UserStore` is evicted AFTER on-disk work completes so that
/// a failed mid-removal can be retried without leaving the runtime in a stale state.
///
/// WARNING: This permanently deletes all local user data.
pub async fn logout_user(rt: &dyn ProvisioningHost, user_id: &str) -> Result<()> {
    let system_dir = rt.base_dir().join("system");
    let mut registry = storage::load_users(&system_dir)?;

    let pos = registry
        .users
        .iter()
        .position(|u| u.user_id == user_id)
        .ok_or_else(|| anyhow!("User '{}' not found", user_id))?;
    registry.users.remove(pos);
    storage::save_users(&system_dir, &registry)?;

    let mut routing = storage::load_device_routing(&system_dir)?;
    routing.routes.retain(|_device, uid| uid != user_id);
    storage::save_device_routing(&system_dir, &routing)?;

    rt.unregister_user_devices(user_id);

    // Dropping the cached record store BEFORE deleting the directory is
    // load-bearing: an open per-user file handle makes Windows refuse the
    // delete. It is the daemon's call, made in `dispatch` immediately before
    // this one, because the cache of open stores is the daemon's with the rest
    // of residency and this crate cannot reach it. Making the user non-resident is the caller's for the same reason.

    let user_dir = rt.base_dir().join("users").join(user_id);
    // The bounded retry and the naming of what still holds the directory are
    // `kotton_common::fs::remove_dir_all_retrying`'s, shared with the whole-device
    // form (`kotton device reset`) rather than written out twice.
    kotton_common::fs::remove_dir_all_retrying(&user_dir).map_err(|e| {
        // `Error::new` rather than `anyhow!(e.to_string())`: `HeldOpen` is an
        // `Error` whose `source` is the io error and whose `Display` names the
        // files still open, so the chain keeps both instead of flattening them
        // into one string.
        anyhow::Error::new(e).context(format!("Failed to delete user directory {user_dir:?}"))
    })?;

    // Purge EVERY per-user secret from the keychain, so removing a user leaves no
    // trace (the PIN vault + recovery bundle are files in the user dir, removed
    // above). Best-effort per label — a missing entry is not an error. The
    // device-level operational key is intentionally kept (it is not user-scoped;
    // other users share it, and the whole-device wipe that does take it is
    // `kotton device reset`).
    delete_all_user_secrets(rt.secrets(), user_id);

    Ok(())
}


#[cfg(test)]
mod tests {
    /// The unlock credential these tests create identities with — five BIP-39
    /// words, 55.00 bits by the wordlist path, so it clears the bar
    /// `create_user` now enforces.
    const TEST_PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";

    use super::*;
    use crate::registry as storage;
    use tempfile::TempDir;
    use crate::users::DeviceUsers as _;
    use crate::DeviceRuntime;
    use kotton_crypto::derive_cek;

    async fn make_runtime(temp: &TempDir) -> DeviceRuntime {
        let config = crate::config::RuntimeConfig::default();
        // MemorySecrets avoids touching the OS keychain (macOS Keychain requires
        // interactive auth in CI, causing indefinite hangs).
        let secrets = std::sync::Arc::new(kotton_secret::MemorySecrets::new());
        DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, secrets)
            .await
            .unwrap()
    }

    /// A runtime built for one principal loads that user and
    /// nobody else — the other user on the device is simply not resident in
    /// this process, by user id or by DID.
    #[tokio::test]
    async fn a_principal_scoped_runtime_loads_only_its_user() {
        let temp = TempDir::new().unwrap();
        let secrets: std::sync::Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> =
            std::sync::Arc::new(kotton_secret::MemorySecrets::new());

        // Unsupervised boot: two users exist on this device.
        let alice_did = {
            let rt = DeviceRuntime::new_with_secrets(
                temp.path().to_path_buf(),
                crate::config::RuntimeConfig::default(),
                std::sync::Arc::clone(&secrets),
            )
            .await
            .unwrap();
            let (creation, _user_rt) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
            create_user(&rt, "bob", TEST_PASSPHRASE).await.unwrap();
            // Ask the runtime, not a map the test filled in itself: "loads
            // everyone" is the unsupervised runtime's property, and the old
            // assertion could only restate the line above it.
            let loaded = rt.load_users().await.unwrap();
            assert!(
                loaded.iter().any(|(id, _)| id == "bob"),
                "unsupervised loads everyone"
            );
            creation.did
        };

        // Supervised for alice, named by user id.
        let rt = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            crate::config::RuntimeConfig {
                principal: Some("alice".into()),
                ..Default::default()
            },
            std::sync::Arc::clone(&secrets),
        )
        .await
        .unwrap();
        // Loading is the daemon's startup step now, so the test performs it too —
        // which is the point: the principal filter must apply where the daemon
        // applies it, not as a side effect of construction.
        // Asserts on the set `load_users` *returns*, not on what happens to be
        // resident afterwards. That is the stronger claim and the reason loading
        // returns now: an equality against the whole set cannot pass vacuously,
        // where the old `is_some()`/`is_none()` pair could both hold for a load
        // that silently did nothing at all.
        let loaded = rt.load_users().await.unwrap();
        let ids: Vec<&str> = loaded.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["alice"], "the principal loads, and nobody else");

        // Supervised for alice, named by DID — what kdeviced actually spawns with.
        let rt = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            crate::config::RuntimeConfig {
                principal: Some(alice_did),
                ..Default::default()
            },
            secrets,
        )
        .await
        .unwrap();
        let loaded = rt.load_users().await.unwrap();
        let ids: Vec<&str> = loaded.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["alice"], "matching by DID works, and scopes just as tightly");
    }

    /// A principal-scoped process does not mint other users.
    /// Creating its own (first boot of a supervised daemon) still works.
    #[tokio::test]
    async fn a_principal_scoped_runtime_refuses_to_create_another_user() {
        let temp = TempDir::new().unwrap();
        let secrets = std::sync::Arc::new(kotton_secret::MemorySecrets::new());
        let rt = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            crate::config::RuntimeConfig {
                principal: Some("alice".into()),
                ..Default::default()
            },
            secrets,
        )
        .await
        .unwrap();

        create_user(&rt, "alice", TEST_PASSPHRASE)
            .await
            .expect("a supervised daemon may create its own principal");
        // `.map(|_| ())` because the Ok half now carries an `Arc<UserStore>`,
        // which has no `Debug` — deliberately, so a runtime holding key material
        // cannot be logged by accident. Absence over a redacting impl, as
        // everywhere else here.
        let err = create_user(&rt, "mallory", TEST_PASSPHRASE)
            .await
            .map(|_| ())
            .expect_err("and nobody else");
        assert!(
            err.to_string().contains("cannot create"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn resolve_cek_prefers_operational_over_legacy_seed32() {
        use kotton_secret::MemorySecrets;
        let s = MemorySecrets::new();

        // Neither present → None (blind relay / locked).
        assert!(resolve_operational_cek(&s, "u").unwrap().is_none());

        // Legacy seed-node: only seed32 → derive_cek(seed32).
        let seed = [7u8; 32];
        s.set_secret(&kdf_labels::seed32_keychain_key("u"), &hex::encode(seed))
            .unwrap();
        assert_eq!(resolve_operational_cek(&s, "u").unwrap(), Some(derive_cek(&seed)));

        // Once a random operational_cek is present it takes precedence (the CEK
        // is random and stored, not seed-derived).
        let random_cek = [5u8; 32];
        s.set_secret(&kdf_labels::operational_cek("u"), &hex::encode(random_cek))
            .unwrap();
        assert_eq!(resolve_operational_cek(&s, "u").unwrap(), Some(random_cek));
    }

    /// The sealed-replication domain gate is only truthful if the advertised domain derives
    /// from the key the stores actually seal with. OS keychain entries are
    /// keyed by user_id alone and machine-global, so a second daemon on the
    /// same machine re-creating the same user_id rewrites them under a live
    /// runtime. If the domain id followed the keychain, this node would
    /// advertise one domain while sealing in another — its blobs would pass a
    /// receiver's domain gate and land unopenable, the exact failure
    /// `two_node_transfer` surfaced.
    #[tokio::test]
    async fn domain_id_follows_the_live_runtime_not_the_keychain() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let (_, alice_rt) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        let alice = Some(alice_rt);
        let before = rt
            .user_cek_domain_id("alice", alice.as_deref())
            .expect("a live user with keys has a domain");

        // Another daemon's create_user("alice") rewrites the shared entry.
        rt.secrets()
            .set_secret(
                &kdf_labels::operational_cek("alice"),
                &hex::encode([0x99u8; 32]),
            )
            .unwrap();

        assert_eq!(
            rt.user_cek_domain_id("alice", alice.as_deref()),
            Some(before.clone()),
            "the advertised domain must derive from the runtime's own CEK, \
             not from whatever the shared keychain currently says"
        );

        // The other half of the same rule, asserted so the precedence is pinned
        // in both directions rather than only the one that broke: with nothing
        // loaded there is no authoritative CEK, so the keychain *is* consulted —
        // and now yields the rewritten value. This is what makes passing `None`
        // while a runtime is live a silent lie rather than a harmless shortcut,
        // which is why the parameter is the runtime and not a bool.
        assert_ne!(
            rt.user_cek_domain_id("alice", None),
            Some(before),
            "with no runtime loaded the keychain is the only source, so a \
             rewritten entry must change the answer"
        );
    }

    /// **Two recovery phrases both open the data, not only the last.** The "set up
    /// recovery" action, driven twice the way a person would: `create_user` mints an
    /// identity with no recovery authority, the first phrase is its first and the
    /// second its second. Each phrase's sealed copy of the data roots is kept beside
    /// the other's, not written over it, so the first phrase — still a committed KEL
    /// authority — both rotates the identity and opens the files. Were the second
    /// copy to replace the first, the first phrase would keep its authority over the
    /// identity and lose the files, and nothing would say so.
    #[tokio::test]
    async fn both_recovery_phrases_open_the_data_not_only_the_last() {
        use kotton_identity::provisioning::read_recovery_bundle;
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();

        let phrase1 = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("first phrase");
        let phrase2 = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("second phrase");
        assert_ne!(phrase1, phrase2);

        let seed1 = try_mnemonic_to_seed32(&phrase1).unwrap();
        let seed2 = try_mnemonic_to_seed32(&phrase2).unwrap();

        // Both phrases open the same data roots — the sealed set grew with the
        // KEL set instead of being replaced.
        let d1 = read_recovery_bundle(rt.base_dir(), "alice", &seed1)
            .unwrap()
            .expect("the FIRST phrase must still open the data");
        let d2 = read_recovery_bundle(rt.base_dir(), "alice", &seed2)
            .unwrap()
            .expect("the second phrase opens the data");
        assert_eq!(d1.master_secret, d2.master_secret, "same roots for both phrases");
        assert_eq!(d1.cek, d2.cek);

        // And both are committed KEL authorities, so the two halves agree: every
        // phrase in the recovery set can unseal the roots.
        let tip = kotton_identity::kel_store::load_chain(rt.base_dir(), "alice")
            .unwrap()
            .last()
            .unwrap()
            .clone();
        assert_eq!(tip.recovery_set.len(), 2, "two committed authorities");
    }

    #[tokio::test]
    async fn adding_a_recovery_phrase_grows_the_set_and_keeps_the_identity() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let (_creation, _user_rt) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();

        let before = kotton_identity::kel_store::load_chain(rt.base_dir(), "alice").unwrap();
        let tip_before = before.last().unwrap().clone();

        let phrase = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("adding a recovery phrase");
        assert!(!phrase.is_empty());

        let after = kotton_identity::kel_store::load_chain(rt.base_dir(), "alice").unwrap();
        let tip = after.last().unwrap();

        // The identity is the same — this adds a way in, it does not mint a new one.
        assert_eq!(tip.aid, tip_before.aid);
        assert_eq!(tip.key_state, tip_before.key_state, "no key change");
        assert_eq!(after.len(), before.len() + 1);

        // The set grew rather than being replaced.
        assert!(tip.recovery_set.len() > tip_before.recovery_set.len());
        for old in &tip_before.recovery_set {
            assert!(
                tip.recovery_set.contains(old),
                "an existing authority was dropped"
            );
        }

        // And the chain still validates, which is the real assertion — the growth
        // rule is enforced in `validate`, not here.
        assert_eq!(
            kotton_crypto::kel_verify::validate(&tip_before, tip),
            kotton_crypto::kel_verify::Verdict::Valid
        );
    }

    /// **No door reaches a created identity without a credential.**
    ///
    /// This is the regression test for the defect that moved the check here:
    /// `assess` and the vault seal lived in `occupant_host::create_identity`, so
    /// they guarded the guest shell and neither CLI path. Asserting it at
    /// `create_user` is what makes it true for all three, because this is the
    /// function all three call.
    #[tokio::test]
    async fn a_weak_credential_creates_nothing() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;

        for weak in ["", "123456", "hunter2", "aaaaaaaaaaaaaaaaaaaa"] {
            assert!(
                create_user(&rt, "alice", weak).await.is_err(),
                "{weak:?} should be refused"
            );
            // Refused *before* anything was written — a rejected credential must
            // not leave a half-made account behind, which is why the assessment
            // runs ahead of the registry.
            assert!(
                kotton_identity::kel_store::load_chain(rt.base_dir(), "alice")
                    .map(|c| c.is_empty())
                    .unwrap_or(true),
                "{weak:?} was refused but left a key history behind"
            );
        }

        // And the same identity is creatable once the credential clears.
        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
    }

    /// **The full cold-start cycle.** Create with a credential, lose every
    /// plaintext root, unlock with the credential, and read the data back.
    ///
    /// Written to settle whether `create_user` may purge the platform's
    /// plaintext copies the way `set_user_pin` does. The worry was that purging
    /// makes a restart need an unlock that nothing can perform — so this drives
    /// the mechanism directly rather than reasoning about it.
    #[tokio::test]
    async fn a_purged_account_comes_back_with_its_credential() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();

        let before = kel_store::resolve_current_key_for(rt.base_dir(), "alice", false)
            .unwrap()
            .expect("an inception key");

        // Everything the platform held, gone — the state `adopt_roots_into_memory`
        // produces, and the state a fresh boot of a purged account is in.
        for label in [
            kdf_labels::master_secret_keychain_key("alice"),
            kdf_labels::identity_signing_key("alice"),
            kdf_labels::operational_cek("alice"),
        ] {
            let _ = rt.secrets().delete_secret(&label);
        }
        assert!(
            rt.secrets()
                .get_secret(&kdf_labels::identity_signing_key("alice"))
                .ok()
                .flatten()
                .is_none(),
            "the roots must actually be gone for this to test anything"
        );

        // The credential opens the vault and puts them back.
        kotton_identity::provisioning::unlock_with_pin(&rt, "alice", TEST_PASSPHRASE)
            .await
            .expect("the credential must reopen a purged account");

        let after = kel_store::resolve_current_key_for(rt.base_dir(), "alice", false)
            .unwrap()
            .expect("a key after unlock");
        assert_eq!(before, after, "the same identity came back, not a new one");

        // And a wrong credential does not.
        for label in [
            kdf_labels::master_secret_keychain_key("alice"),
            kdf_labels::identity_signing_key("alice"),
            kdf_labels::operational_cek("alice"),
        ] {
            let _ = rt.secrets().delete_secret(&label);
        }
        assert!(
            kotton_identity::provisioning::unlock_with_pin(&rt, "alice", "canyon-orbit-velvet-fish-orbit")
                .await
                .is_err(),
            "a wrong credential must not open the vault"
        );
    }

    /// Creation seals the vault, so a cold start can reopen the account.
    ///
    /// The seal used to be the occupant host's, which is why an identity made
    /// with `kotton id create` had its roots in the keychain and nowhere else —
    /// working until the keychain was cleared, and then gone.
    #[tokio::test]
    async fn creation_seals_the_vault_under_the_credential() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();

        let vault = rt.base_dir().join("users").join("alice").join("vault.json");
        assert!(vault.exists(), "creation must leave a sealed vault at {vault:?}");
    }

    /// A fresh identity has no recovery authority, and says so in the chain.
    ///
    /// This is the state a person is in after first run: an account that works and
    /// has no way back in. It is recorded rather than implied, which is what makes
    /// it something the product can tell them.
    #[tokio::test]
    async fn a_fresh_user_has_no_recovery_authority() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let (_creation, _user_rt) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();

        let chain = kotton_identity::kel_store::load_chain(rt.base_dir(), "alice").unwrap();
        let tip = chain.last().unwrap();
        assert_eq!(
            tip.recovery_commitment,
            kotton_crypto::kel_verify::empty_recovery_root(),
            "creation must not commit a recovery authority"
        );
        assert!(tip.recovery_set.is_empty());

        // And no recovery bundle was written, because there is no phrase to seal
        // one under. A bundle here would be sealed to nothing.
        assert!(
            !kotton_identity::provisioning::recovery_bundle_path(rt.base_dir(), "alice").exists(),
            "a fresh user has no recovery bundle"
        );
    }

    #[tokio::test]
    async fn create_user_mints_a_did_kel_identity() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;

        let (creation, _user_rt) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();

        // The DID is a did:kel AID and the registry records the "kel" method.
        assert!(
            creation.did.starts_with("did:kel:"),
            "new identities are did:kel, got {}",
            creation.did
        );
        let registry = storage::load_users(&temp.path().join("system")).unwrap();
        let record = registry
            .users
            .iter()
            .find(|u| u.user_id == "alice")
            .expect("alice is registered");
        assert_eq!(record.did, creation.did);
        assert_eq!(record.did_method, "kel");

        // The KEL is stored locally (inception is the whole chain at creation) and
        // replays to the mnemonic-derived identity key — no network.
        let chain = kel_store::load_chain(rt.base_dir(), "alice").unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].aid.to_string(), creation.did);
        // The key-state replays to the *random* key stored for this user. It used to
        // replay to one derived from the mnemonic, and the assertion below used to
        // be that the AID was reconstructible from the phrase alone — both of which
        // were the deviation this change closed. The identity is now a public
        // identifier that does not derive from any secret.
        let stored = rt
            .secrets()
            .get_secret(&kdf_labels::identity_signing_key("alice"))
            .unwrap()
            .unwrap();
        let stored_bytes: [u8; 32] = hex::decode(&stored).unwrap().try_into().unwrap();
        let identity_pubkey = ed25519_dalek::SigningKey::from_bytes(&stored_bytes)
            .verifying_key()
            .to_bytes();
        assert_eq!(
            kel_store::resolve_current_key_for(rt.base_dir(), "alice", false).unwrap(),
            Some(identity_pubkey),
        );
        assert_eq!(
            chain[0].aid.to_string(),
            creation.did
        );
    }

    /// Recovery rotation (the headline "survive key compromise" property):
    /// a mnemonic rotation changes the authoritative key while the `did:kel` AID —
    /// the identity itself — is unchanged, and the old key stops speaking.
    #[tokio::test]
    async fn mnemonic_rotation_changes_the_key_but_not_the_aid() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let (creation, _user_rt) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();

        // Creation mints no phrase, so the identity is given one first. This is the
        // real sequence a person follows — set up an account, then set up recovery —
        // and a rotation test that skipped it would be testing a state the product
        // no longer produces.
        let phrase = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("adding a recovery phrase");

        // Pre-rotation: the authoritative key is the random inception key.
        let old_key = kel_store::resolve_current_key_for(rt.base_dir(), "alice", false)
            .unwrap()
            .expect("an inception key");

        let new_key_hex =
            rotate_identity_via_mnemonic(&rt, "alice", &phrase, Some(TEST_PASSPHRASE))
                .await
                .unwrap();
        let new_key: [u8; 32] = hex::decode(&new_key_hex).unwrap().try_into().unwrap();

        // The AID (identity) survives; the authoritative key is now the new one.
        let registry = storage::load_users(&temp.path().join("system")).unwrap();
        let record = registry.users.iter().find(|u| u.user_id == "alice").unwrap();
        assert_eq!(record.did, creation.did, "the did:kel AID survives the rotation");
        let current = kel_store::resolve_current_key_for(rt.base_dir(), "alice", false)
            .unwrap()
            .unwrap();
        assert_eq!(current, new_key, "the new key now speaks for the identity");
        assert_ne!(current, old_key, "the old (compromised) key no longer speaks");

        // The stored operational signing key (the private scalar) was replaced, and
        // its public half is the new authoritative key.
        let stored = rt
            .secrets()
            .get_secret(&kdf_labels::identity_signing_key("alice"))
            .unwrap()
            .unwrap();
        let stored_bytes: [u8; 32] = hex::decode(&stored).unwrap().try_into().unwrap();
        assert_eq!(
            ed25519_dalek::SigningKey::from_bytes(&stored_bytes)
                .verifying_key()
                .to_bytes(),
            new_key,
        );

        // A different identity's mnemonic cannot rotate alice.
        let (_bob, _bob_rt) = create_user(&rt, "bob", TEST_PASSPHRASE).await.unwrap();
        let bob_phrase = add_recovery_phrase(rt.base_dir(), rt.secrets(), "bob")
            .await
            .expect("bob's recovery phrase");
        assert!(
            rotate_identity_via_mnemonic(&rt, "alice", &bob_phrase, Some(TEST_PASSPHRASE))
                .await
                .is_err(),
            "a foreign mnemonic must not rotate this identity"
        );
    }

    /// Everything a phrase login for `user` could write, as bytes, each under
    /// its name: the three roots, the users registry, the device routing, the
    /// copy sealed under a phrase, the device list and the key log.
    fn what_a_phrase_login_could_write(
        rt: &DeviceRuntime,
        user: &str,
    ) -> Vec<(&'static str, Option<Vec<u8>>)> {
        use kotton_identity::provisioning::{recovery_bundle_path, resolve_operational_cek};
        let read = |p: PathBuf| std::fs::read(p).ok();
        let user_dir = rt.base_dir().join("users").join(user);
        vec![
            ("master secret", resolve_master_secret(rt.secrets(), user).unwrap().map(|k| k.to_vec())),
            ("cek", resolve_operational_cek(rt.secrets(), user).unwrap().map(|k| k.to_vec())),
            ("identity key", stored_identity_key(rt, user).unwrap().map(|k| k.to_vec())),
            ("users.json", read(rt.base_dir().join("system").join("users.json"))),
            ("device_routing.json", read(rt.base_dir().join("system").join("device_routing.json"))),
            ("recovery.json", read(recovery_bundle_path(rt.base_dir(), user))),
            ("devices.json", read(user_dir.join("devices.json"))),
            ("kel.json", read(user_dir.join("identity").join("kel.json"))),
        ]
    }

    /// Panics naming each thing `after` holds differently from `before`.
    fn assert_nothing_written(
        before: &[(&'static str, Option<Vec<u8>>)],
        after: &[(&'static str, Option<Vec<u8>>)],
    ) {
        let changed: Vec<&str> = before
            .iter()
            .zip(after)
            .filter(|(b, a)| b.1 != a.1)
            .map(|(b, _)| b.0)
            .collect();
        assert!(changed.is_empty(), "a refused phrase login wrote: {changed:?}");
    }

    /// **A phrase no log commits, with a resident user's name, opens nothing.**
    /// The name says which log to check; it is not the answer. The phrase here
    /// is a valid one and nobody's authority, and alice is resident and
    /// unlocked, so a login that took the name for the answer would hand back
    /// her live store.
    #[tokio::test]
    async fn a_phrase_alices_log_does_not_commit_does_not_open_resident_alice() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let (_, alice) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("alice's own phrase");
        let wrong = Bip39MnemonicProvider.generate().unwrap();
        let before = what_a_phrase_login_could_write(&rt, "alice");
        assert!(before[0].1.is_some(), "alice is unlocked: her master secret is held");

        let refused = login_with_recovery_key(&rt, &wrong, Some("alice"), None, Some(alice)).await;
        assert_nothing_written(&before, &what_a_phrase_login_could_write(&rt, "alice"));
        let err = match refused {
            Ok(_) => panic!("a phrase alice's log does not commit opened her session"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("not an authority in 'alice's key log"), "one sentence says why: {err}");
    }

    /// **A phrase no log commits, with the name of a user this device holds the
    /// key of, writes no root and no sealed copy.** alice is not resident, set
    /// up no phrase, and this device is not in her device list, as a device
    /// that joined her is not: so it holds her key and no copy sealed under any
    /// phrase, the state in which a login that skipped the check made new data
    /// roots over hers and sealed them under the unrelated phrase.
    #[tokio::test]
    async fn a_phrase_alices_log_does_not_commit_writes_nothing_over_her_roots() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let (_, alice) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        drop(alice);
        std::fs::remove_file(rt.base_dir().join("users").join("alice").join("devices.json"))
            .unwrap();
        let wrong = Bip39MnemonicProvider.generate().unwrap();
        let before = what_a_phrase_login_could_write(&rt, "alice");
        assert!(before[0].1.is_some(), "this device holds alice's master secret");
        assert!(before[2].1.is_some(), "this device holds alice's identity key");
        assert!(before[5].1.is_none(), "alice has no copy sealed under a phrase");

        let refused = login_with_recovery_key(&rt, &wrong, Some("alice"), None, None).await;
        assert_nothing_written(&before, &what_a_phrase_login_could_write(&rt, "alice"));
        let err = match refused {
            Ok(_) => panic!("a phrase alice's log does not commit logged her in"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("not an authority in 'alice's key log"), "one sentence says why: {err}");
    }

    /// **A phrase another local user's log commits does not open alice.** The
    /// name says which log is checked, so bob's phrase with alice's name is
    /// checked against alice's log, and refused, rather than opening bob.
    #[tokio::test]
    async fn bobs_phrase_with_alices_name_opens_neither() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let (_, alice) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        let (_, _bob) = create_user(&rt, "bob", TEST_PASSPHRASE).await.unwrap();
        let bobs = add_recovery_phrase(rt.base_dir(), rt.secrets(), "bob")
            .await
            .expect("bob's phrase");
        let alice_before = what_a_phrase_login_could_write(&rt, "alice");
        let bob_before = what_a_phrase_login_could_write(&rt, "bob");

        let refused = login_with_recovery_key(&rt, &bobs, Some("alice"), None, Some(alice)).await;
        assert!(refused.is_err(), "bob's phrase opened alice");
        assert_nothing_written(&alice_before, &what_a_phrase_login_could_write(&rt, "alice"));
        assert_nothing_written(&bob_before, &what_a_phrase_login_could_write(&rt, "bob"));
    }

    /// **The phrase alice's log commits opens her resident session by name**, and
    /// leaves the roots the device holds as they were.
    #[tokio::test]
    async fn the_phrase_alices_log_commits_opens_her_by_name() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let (creation, alice) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        let phrase = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("alice's phrase");
        let before = what_a_phrase_login_could_write(&rt, "alice");

        let (uid, _, store) =
            login_with_recovery_key(&rt, &phrase, Some("alice"), None, Some(alice))
                .await
                .expect("alice's own phrase opens her resident session");
        assert_eq!(uid, "alice");
        assert_eq!(store.did(), creation.did);
        assert_nothing_written(&before, &what_a_phrase_login_could_write(&rt, "alice"));
    }

    /// **A phrase login for a resident user whose master secret the store cannot
    /// read refuses, and writes no root over it.** Taking the unreadable read
    /// for "locked" sent this branch to the recovery bundle and
    /// `store_operational_roots`, which writes all three labels — a write under
    /// the label it could not read.
    #[tokio::test]
    async fn a_resident_phrase_login_that_cannot_read_the_master_secret_writes_no_root() {
        use kotton_sys::secret::{SecretsError, SecretsResult, SecretsStore};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Mutex;

        /// A platform store whose master-secret read fails once `broken` is set,
        /// and which records every root label written after that.
        #[derive(Default)]
        struct MasterUnreadable {
            inner: kotton_secret::MemorySecrets,
            broken: AtomicBool,
            written: Mutex<Vec<String>>,
        }
        impl SecretsStore for MasterUnreadable {
            fn get_secret(&self, key: &str) -> SecretsResult<Option<String>> {
                if self.broken.load(Ordering::SeqCst) && key == kdf_labels::master_secret_keychain_key("alice") {
                    return Err(SecretsError::Storage("the keychain did not answer".into()));
                }
                self.inner.get_secret(key)
            }
            fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
                if self.broken.load(Ordering::SeqCst) {
                    self.written.lock().unwrap().push(key.to_string());
                }
                self.inner.set_secret(key, value)
            }
            fn delete_secret(&self, key: &str) -> SecretsResult<()> {
                self.inner.delete_secret(key)
            }
        }

        let temp = TempDir::new().unwrap();
        let platform = std::sync::Arc::new(MasterUnreadable::default());
        let rt = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            crate::config::RuntimeConfig::default(),
            platform.clone(),
        )
        .await
        .unwrap();
        let (_, alice) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        let phrase = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("adding a recovery phrase");
        let identity_key = rt
            .secrets()
            .get_secret(&kdf_labels::identity_signing_key("alice"))
            .unwrap()
            .expect("the identity key is held");
        // Out of memory custody, so every read reaches the platform; the identity
        // key kept there, as a keychain holds it, and the master secret's read
        // failing — a keychain that answers for one entry and not another.
        assert!(rt.custody().lock_identity("alice"));
        platform.inner.set_secret(&kdf_labels::identity_signing_key("alice"), &identity_key).unwrap();
        platform.broken.store(true, Ordering::SeqCst);

        let refused = login_with_recovery_key(&rt, &phrase, None, None, Some(alice)).await;
        let err = match refused {
            Ok(_) => panic!("a master secret the store cannot read must refuse the login"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("the keychain did not answer"), "the read's error is named: {err}");
        assert_eq!(
            *platform.written.lock().unwrap(),
            Vec::<String>::new(),
            "a root was written over a master secret the store could not read"
        );
    }

    /// A rotation whose retiring key cannot be read is refused, with nothing
    /// changed: an unreadable key is not a key the node never held, and a
    /// rotation that went on would cost the person every message sealed to it.
    #[tokio::test]
    async fn a_rotation_that_cannot_read_the_key_it_retires_changes_nothing() {
        use kotton_sys::secret::{SecretsError, SecretsResult, SecretsStore};

        /// Every label passes through except the identity key, whose read fails.
        struct UnreadableIdentityKey<'a>(&'a (dyn SecretsStore + Send + Sync));
        impl SecretsStore for UnreadableIdentityKey<'_> {
            fn get_secret(&self, key: &str) -> SecretsResult<Option<String>> {
                if key == kdf_labels::identity_signing_key("alice") {
                    return Err(SecretsError::Storage("the keychain did not answer".into()));
                }
                self.0.get_secret(key)
            }
            fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
                self.0.set_secret(key, value)
            }
            fn delete_secret(&self, key: &str) -> SecretsResult<()> {
                self.0.delete_secret(key)
            }
        }

        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        let phrase = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("adding a recovery phrase");
        let key_before = rt
            .secrets()
            .get_secret(&kdf_labels::identity_signing_key("alice"))
            .unwrap();
        let chain_before = kel_store::load_chain(rt.base_dir(), "alice").unwrap().len();

        let refused = rotate_identity_to_key(
            rt.base_dir(),
            &UnreadableIdentityKey(rt.secrets()),
            "alice",
            &phrase,
            &ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]),
        )
        .await;
        assert!(refused.is_err(), "an unreadable retiring key must refuse: {refused:?}");
        assert_eq!(
            rt.secrets()
                .get_secret(&kdf_labels::identity_signing_key("alice"))
                .unwrap(),
            key_before,
            "the stored key is untouched"
        );
        assert_eq!(
            kel_store::load_chain(rt.base_dir(), "alice").unwrap().len(),
            chain_before,
            "no rotation event was appended"
        );
    }

    /// The vault follows the key: after a rotation, what the vault seals is the new
    /// key, so the unlock that follows a restart restores it rather than the key
    /// the rotation retired.
    #[tokio::test]
    async fn a_rotation_reseals_the_vault_around_the_new_key() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        let phrase = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("adding a recovery phrase");
        let sealed_before =
            kotton_identity::provisioning::open_vault_under(&rt, "alice", TEST_PASSPHRASE)
                .unwrap();

        let new_key_hex =
            rotate_identity_via_mnemonic(&rt, "alice", &phrase, Some(TEST_PASSPHRASE))
                .await
                .unwrap();

        let sealed =
            kotton_identity::provisioning::open_vault_under(&rt, "alice", TEST_PASSPHRASE)
                .expect("the vault still opens under the passphrase the person already has");
        assert_eq!(
            hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&sealed.identity_key)
                    .verifying_key()
                    .to_bytes()
            ),
            new_key_hex,
            "the vault seals the rotated key"
        );
        assert_eq!(sealed.master_secret, sealed_before.master_secret, "the other roots are unchanged");
        assert_eq!(sealed.cek, sealed_before.cek);
    }

    /// A person with a vault is refused a rotation that cannot re-seal it — no
    /// credential, the wrong one, or a locked account — and every refusal comes
    /// before anything irreversible: the key, the key log and the vault are as
    /// they were.
    #[tokio::test]
    async fn a_rotation_that_cannot_reseal_the_vault_changes_nothing() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        let phrase = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("adding a recovery phrase");
        let label = kdf_labels::identity_signing_key("alice");
        let vault_path = rt.base_dir().join("users").join("alice").join("vault.json");
        let key_before = rt.secrets().get_secret(&label).unwrap();
        let chain_before = kel_store::load_chain(rt.base_dir(), "alice").unwrap().len();
        let vault_before = std::fs::read(&vault_path).unwrap();
        let unchanged = |why: &str| {
            assert_eq!(rt.secrets().get_secret(&label).unwrap(), key_before, "{why}: the key");
            assert_eq!(
                kel_store::load_chain(rt.base_dir(), "alice").unwrap().len(),
                chain_before,
                "{why}: no rotation event"
            );
            assert_eq!(std::fs::read(&vault_path).unwrap(), vault_before, "{why}: the vault");
        };

        let refused = rotate_identity_via_mnemonic(&rt, "alice", &phrase, None).await;
        assert!(refused.is_err(), "no credential: {refused:?}");
        unchanged("no credential");

        let refused =
            rotate_identity_via_mnemonic(&rt, "alice", &phrase, Some("not the passphrase")).await;
        assert!(refused.is_err(), "the wrong credential: {refused:?}");
        unchanged("the wrong credential");

        // Locked, as a restart leaves a person: the roots are in no store at all.
        assert!(rt.custody().lock_identity("alice"), "alice's roots were in custody");
        let refused =
            rotate_identity_via_mnemonic(&rt, "alice", &phrase, Some(TEST_PASSPHRASE)).await;
        let err = refused.expect_err("a locked person keeps no retired key");
        assert!(err.to_string().contains("locked"), "the refusal names the lock: {err}");
        assert_eq!(rt.secrets().get_secret(&label).unwrap(), None, "locked: nothing was written");
        assert_eq!(
            kel_store::load_chain(rt.base_dir(), "alice").unwrap().len(),
            chain_before,
            "locked: no rotation event"
        );
        assert_eq!(std::fs::read(&vault_path).unwrap(), vault_before, "locked: the vault");
    }

    /// The identity key a fresh process restores for `user` from the vault under
    /// `credential` — a restart: memory custody is gone, and the unlock is what
    /// brings the roots back.
    async fn key_after_restart_and_unlock(base: &Path, user: &str, credential: &str) -> String {
        held_key(&restart_and_unlock(base, user, credential).await, user)
    }

    /// A fresh process over `base`, unlocked with `credential`.
    async fn restart_and_unlock(base: &Path, user: &str, credential: &str) -> DeviceRuntime {
        let fresh = DeviceRuntime::new_with_secrets(
            base.to_path_buf(),
            crate::config::RuntimeConfig::default(),
            std::sync::Arc::new(kotton_secret::MemorySecrets::new()),
        )
        .await
        .unwrap();
        kotton_identity::provisioning::unlock_with_pin(&fresh, user, credential)
            .await
            .expect("the unlock after a restart");
        fresh
    }

    /// The identity key custody holds for `user`.
    fn held_key(rt: &DeviceRuntime, user: &str) -> String {
        rt.secrets()
            .get_secret(&kdf_labels::identity_signing_key(user))
            .unwrap()
            .expect("custody holds the identity key")
    }

    /// A rotation whose vault cannot be sealed around the new key is refused
    /// **before** the key log is appended: the key, the key log and the vault are
    /// as they were, no temporary or staged sealed copy is left, and a restart
    /// and unlock restores the key the log still names.
    ///
    /// The write is made to fail by occupying the staged vault's path with a
    /// directory, so the rename onto it is refused after the sealed bytes were
    /// written to the temporary file.
    #[tokio::test]
    async fn a_rotation_whose_vault_write_fails_changes_nothing() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        let phrase = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("adding a recovery phrase");
        let label = kdf_labels::identity_signing_key("alice");
        let user_dir = rt.base_dir().join("users").join("alice");
        let vault_path = user_dir.join(kotton_identity::provisioning::VAULT_FILE);
        let staged = user_dir.join(kotton_identity::provisioning::STAGED_VAULT_FILE);
        let key_before = rt.secrets().get_secret(&label).unwrap();
        let chain_before = kel_store::load_chain(rt.base_dir(), "alice").unwrap().len();
        let vault_before = std::fs::read(&vault_path).unwrap();

        std::fs::create_dir_all(staged.join("occupied")).unwrap();
        let refused =
            rotate_identity_via_mnemonic(&rt, "alice", &phrase, Some(TEST_PASSPHRASE)).await;

        assert!(refused.is_err(), "a vault that cannot be written refuses the rotation");
        assert_eq!(rt.secrets().get_secret(&label).unwrap(), key_before, "the key");
        assert_eq!(
            kel_store::load_chain(rt.base_dir(), "alice").unwrap().len(),
            chain_before,
            "no rotation event"
        );
        assert_eq!(std::fs::read(&vault_path).unwrap(), vault_before, "the vault");
        assert!(
            !staged.with_extension("json.tmp").exists(),
            "no temporary sealed copy is left behind"
        );
        std::fs::remove_dir_all(&staged).unwrap();
        assert_eq!(
            Some(key_after_restart_and_unlock(rt.base_dir(), "alice", TEST_PASSPHRASE).await),
            key_before,
            "a restart and unlock restores the key the key log still names"
        );
    }

    /// The crash window: the rotated vault was staged and the key log appended,
    /// and the process died before the rename. The next unlock finishes it — it
    /// restores the key the log installs, not the one it retired, the vault now
    /// seals that key, and the staged copy is gone.
    #[tokio::test]
    async fn a_rotation_that_dies_before_its_vault_rename_is_finished_by_the_next_unlock() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        let phrase = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("adding a recovery phrase");
        let user_dir = rt.base_dir().join("users").join("alice");
        let staged = user_dir.join(kotton_identity::provisioning::STAGED_VAULT_FILE);

        // `rotate_identity_via_mnemonic`'s steps up to the rename, and no further.
        let new_sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        kotton_identity::provisioning::stage_rotated_vault(
            &rt,
            "alice",
            TEST_PASSPHRASE,
            &new_sk.to_bytes(),
        )
        .unwrap();
        rotate_identity_to_key(rt.base_dir(), rt.secrets(), "alice", &phrase, &new_sk)
            .await
            .unwrap();
        assert!(staged.exists(), "the crash left the staged vault");

        assert_eq!(
            key_after_restart_and_unlock(rt.base_dir(), "alice", TEST_PASSPHRASE).await,
            hex::encode(new_sk.to_bytes()),
            "the unlock restores the key the key log installs"
        );
        let sealed =
            kotton_identity::provisioning::open_vault_under(&rt, "alice", TEST_PASSPHRASE).unwrap();
        assert_eq!(sealed.identity_key, new_sk.to_bytes(), "the vault seals the rotated key");
        assert!(!staged.exists(), "the staged vault became the vault");
    }

    /// A staged vault that will not open while the key log has moved past the live
    /// vault is **kept**, not dropped: it may be the only sealed copy of the key
    /// the log installs. The unlock after the crash cannot restore that key while
    /// the file will not open, and a later unlock, once it opens again, does. A
    /// rotation meanwhile is refused with nothing changed rather than staging
    /// over it.
    #[tokio::test]
    async fn a_staged_vault_that_will_not_open_after_a_landed_rotation_is_kept() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        let phrase = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("adding a recovery phrase");
        let staged = rt
            .base_dir()
            .join("users")
            .join("alice")
            .join(kotton_identity::provisioning::STAGED_VAULT_FILE);
        let new_sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        kotton_identity::provisioning::stage_rotated_vault(
            &rt,
            "alice",
            TEST_PASSPHRASE,
            &new_sk.to_bytes(),
        )
        .unwrap();
        rotate_identity_to_key(rt.base_dir(), rt.secrets(), "alice", &phrase, &new_sk)
            .await
            .unwrap();
        let sealed = std::fs::read(&staged).unwrap();
        std::fs::write(&staged, b"not yet readable").unwrap();

        key_after_restart_and_unlock(rt.base_dir(), "alice", TEST_PASSPHRASE).await;
        assert!(staged.exists(), "an unopenable staged vault the log may need is kept");

        let chain_before = kel_store::load_chain(rt.base_dir(), "alice").unwrap().len();
        let refused =
            rotate_identity_via_mnemonic(&rt, "alice", &phrase, Some(TEST_PASSPHRASE)).await;
        assert!(refused.is_err(), "a rotation does not stage over it: {refused:?}");
        assert_eq!(std::fs::read(&staged).unwrap(), b"not yet readable", "untouched");
        assert_eq!(
            kel_store::load_chain(rt.base_dir(), "alice").unwrap().len(),
            chain_before,
            "no rotation event"
        );

        std::fs::write(&staged, &sealed).unwrap();
        assert_eq!(
            key_after_restart_and_unlock(rt.base_dir(), "alice", TEST_PASSPHRASE).await,
            hex::encode(new_sk.to_bytes()),
            "once it opens, the unlock restores the key the log installs"
        );
        assert!(!staged.exists());
    }

    /// The state the keep leaves behind: the log installs the rotated key, custody
    /// holds the one the live vault restored, and the staged vault opens again. A
    /// rotation from there finishes the vault and is **refused**: rotating would
    /// retire the key custody holds rather than the one the log installs, and
    /// leave that one held nowhere. The next unlock brings it into custody, and a
    /// rotation after that retires it.
    #[tokio::test]
    async fn a_rotation_that_finds_a_staged_vault_to_promote_is_refused_until_the_unlock() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        let phrase = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("adding a recovery phrase");
        let old_key = held_key(&rt, "alice");
        let staged = rt
            .base_dir()
            .join("users")
            .join("alice")
            .join(kotton_identity::provisioning::STAGED_VAULT_FILE);
        let installed = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        kotton_identity::provisioning::stage_rotated_vault(
            &rt,
            "alice",
            TEST_PASSPHRASE,
            &installed.to_bytes(),
        )
        .unwrap();
        rotate_identity_to_key(rt.base_dir(), rt.secrets(), "alice", &phrase, &installed)
            .await
            .unwrap();
        let sealed = std::fs::read(&staged).unwrap();
        std::fs::write(&staged, b"not yet readable").unwrap();
        let restarted = restart_and_unlock(rt.base_dir(), "alice", TEST_PASSPHRASE).await;
        assert_eq!(held_key(&restarted, "alice"), old_key, "the keep path restores the live vault");
        std::fs::write(&staged, &sealed).unwrap();
        let chain_before = kel_store::load_chain(rt.base_dir(), "alice").unwrap().len();

        let refused =
            rotate_identity_via_mnemonic(&restarted, "alice", &phrase, Some(TEST_PASSPHRASE)).await;
        assert!(refused.is_err(), "a rotation from the wrong key is refused: {refused:?}");
        assert_eq!(
            kel_store::load_chain(rt.base_dir(), "alice").unwrap().len(),
            chain_before,
            "no rotation event"
        );
        assert!(!staged.exists(), "the staged vault was finished");
        assert_eq!(
            kotton_identity::provisioning::open_vault_under(&restarted, "alice", TEST_PASSPHRASE)
                .unwrap()
                .identity_key,
            installed.to_bytes(),
            "the vault seals the key the log installs"
        );

        kotton_identity::provisioning::unlock_with_pin(&restarted, "alice", TEST_PASSPHRASE)
            .await
            .unwrap();
        assert_eq!(held_key(&restarted, "alice"), hex::encode(installed.to_bytes()));
        let next =
            rotate_identity_via_mnemonic(&restarted, "alice", &phrase, Some(TEST_PASSPHRASE))
                .await
                .expect("the rotation after the unlock");
        let current = ed25519_dalek::SigningKey::from_bytes(
            &<[u8; 32]>::try_from(hex::decode(held_key(&restarted, "alice")).unwrap()).unwrap(),
        );
        assert_eq!(hex::encode(current.verifying_key().to_bytes()), next);
        let kept = kotton_identity::retired_keys::open(rt.base_dir(), "alice", &current).unwrap();
        assert!(
            kept.iter().any(|k| k.to_bytes() == installed.to_bytes()),
            "the key the log installed is the one retired and kept"
        );
    }

    /// The other side of the crash window: the vault was staged and the process
    /// died before the append. Nothing installed the staged key, so the unlock
    /// restores the key the log names and removes the staged copy.
    #[tokio::test]
    async fn a_staged_vault_the_key_log_never_installed_is_dropped_by_the_next_unlock() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        let label = kdf_labels::identity_signing_key("alice");
        let key_before = rt.secrets().get_secret(&label).unwrap();
        let vault_path = rt.base_dir().join("users").join("alice").join("vault.json");
        let vault_before = std::fs::read(&vault_path).unwrap();
        let staged = rt
            .base_dir()
            .join("users")
            .join("alice")
            .join(kotton_identity::provisioning::STAGED_VAULT_FILE);

        kotton_identity::provisioning::stage_rotated_vault(
            &rt,
            "alice",
            TEST_PASSPHRASE,
            &[9u8; 32],
        )
        .unwrap();

        assert_eq!(
            Some(key_after_restart_and_unlock(rt.base_dir(), "alice", TEST_PASSPHRASE).await),
            key_before,
            "the unlock restores the key the key log names"
        );
        assert_eq!(std::fs::read(&vault_path).unwrap(), vault_before, "the vault is untouched");
        assert!(!staged.exists(), "a staged vault nothing installed is removed");
    }

    /// An enrolled node — holding only the delivered `operational_cek`, no
    /// `seed32` — reads data the issuer wrote under `derive_cek(seed32)`.
    #[tokio::test]
    async fn enrolled_node_decrypts_issuer_data_via_resolved_cek() {
        use kotton_sys::store::ObjectStorage;
        use kotton_fs::OsFilesystem;
        use kotton_store::{EncryptedObjectStorage, LocalObjectStorage};
        use kotton_secret::MemorySecrets;
        use std::path::Path;

        let dir = TempDir::new().unwrap();
        let issuer_seed = [7u8; 32];
        let issuer_cek = derive_cek(&issuer_seed);
        let key = Path::new("hello.bin");
        let plaintext = b"sovereign data";

        // Issuer writes an encrypted object under its seed-derived CEK.
        {
            let store = EncryptedObjectStorage::new(
                LocalObjectStorage::new(dir.path().to_path_buf(), OsFilesystem),
                issuer_cek,
            );
            store.put(key, plaintext).await.unwrap();
        }

        // Enrolled node: only operational_cek in the keychain (no seed32), set to
        // the CEK the enrollment ceremony delivered.
        let secrets = MemorySecrets::new();
        secrets
            .set_secret(&kdf_labels::operational_cek("alice"), &hex::encode(issuer_cek))
            .unwrap();
        assert!(secrets
            .get_secret(&kdf_labels::seed32_keychain_key("alice"))
            .unwrap()
            .is_none());

        let resolved =
            resolve_operational_cek(&secrets, "alice").unwrap().expect("CEK resolves from operational_cek");

        // Reading with the resolved CEK yields the issuer's plaintext.
        let store = EncryptedObjectStorage::new(
            LocalObjectStorage::new(dir.path().to_path_buf(), OsFilesystem),
            resolved,
        );
        let got = store.get(key).await.unwrap();
        assert_eq!(got.as_ref(), plaintext);

        // Sanity: encryption is real — a wrong CEK cannot read the object.
        let wrong = EncryptedObjectStorage::new(
            LocalObjectStorage::new(dir.path().to_path_buf(), OsFilesystem),
            [0u8; 32],
        );
        assert!(
            wrong.get(key).await.is_err(),
            "a wrong CEK must not decrypt the issuer's object"
        );
    }

    /// Setting a PIN must make `pin_set` report `true`.
    ///
    /// Regression: `set_user_pin` writes `vault.json`, but the two reporters
    /// probed `wrapped_seed.json` — the older name — so `pin_set` was
    /// `false` for every user who had a PIN. Nothing caught it because writer and
    /// readers named the file independently; they now share [`VAULT_FILE`].
    #[tokio::test]
    async fn setting_a_pin_is_visible_to_recovery_status() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();

        // Sealing is `create_user`'s, so a fresh user has a PIN vault by
        // construction: there is no window in which an identity exists
        // unsealed.
        assert!(
            rt.get_recovery_status("alice").unwrap().pin_set,
            "creation seals the vault, so a fresh user reports pin_set"
        );

        // Changing it keeps it reported — the regression this test exists for is
        // that the writer and the two readers named the vault file
        // independently, so a re-seal is the case that would catch it again.
        rt.set_user_pin("alice", "correct horse battery staple")
            .await
            .unwrap();

        assert!(
            rt.get_recovery_status("alice").unwrap().pin_set,
            "pin_set must report true once a PIN vault exists"
        );
        assert!(
            rt.get_key_health("alice")
                .unwrap()
                .recovery_layers
                .iter()
                .any(|l| l.layer == "pin_wrap" && l.active),
            "key health must agree with recovery status about the PIN layer"
        );
    }

    /// After create, the CEK is the random `operational_cek` and **no `seed32` is
    /// persisted**. A reload rebuilds the runtime against that resolved
    /// CEK and still decrypts existing data.
    #[tokio::test]
    async fn reload_user_runtime_picks_up_operational_cek() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let (_, urt) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();

        // Invariant: seed32 is never persisted; a random operational CEK is stored.
        assert!(
            rt.secrets()
                .get_secret(&kdf_labels::seed32_keychain_key("alice"))
                .unwrap()
                .is_none(),
            "seed32 must never be persisted (RFC-0039)"
        );
        assert!(
            rt.secrets()
                .get_secret(&kdf_labels::operational_cek("alice"))
                .unwrap()
                .is_some(),
            "a random operational CEK is stored at create"
        );

        // Write a file under the operational CEK.
        urt.write_file("/note.txt", b"hello").await.unwrap();

        // Reload — CEK resolves via operational_cek — and still reads the file.
        // The refreshed handle is what `reload` returns, so read through it
        // directly — the registry still holds the stale one until a caller swaps
        // it in, and reading that would test the opposite of this test's point.
        let urt2 = rt.reload_user_runtime("alice").await.unwrap();
        let got = urt2.read_file("/note.txt").await.unwrap();
        assert_eq!(got, b"hello");
    }

    #[tokio::test]
    async fn test_create_user() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;

        let (result, _user_rt) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();

        assert_eq!(result.user_id, "alice");
        assert!(result.did.starts_with("did:kel:")); // new identities are did:kel
        assert!(!result.device_fingerprint.is_empty());

        let user_dir = temp.path().join("users").join("alice");
        assert!(user_dir.exists());
        assert!(user_dir.join("keys").exists());
        assert!(user_dir.join("data").exists());

        let system_dir = temp.path().join("system");
        let registry = storage::load_users(&system_dir).unwrap();
        assert_eq!(registry.users.len(), 1);
        assert_eq!(registry.users[0].user_id, "alice");

        let routing = storage::load_device_routing(&system_dir).unwrap();
        assert_eq!(routing.routes.len(), 1);
        assert_eq!(
            routing.routes.get(&result.device_fingerprint),
            Some(&"alice".to_string())
        );
    }

    #[tokio::test]
    async fn test_create_duplicate_user() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;

        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        // `.map(|_| ())` for the same reason as above: the Ok half carries an
        // `Arc<UserStore>`, which has no `Debug` by design.
        let result = create_user(&rt, "alice", TEST_PASSPHRASE).await.map(|_| ());

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn provision_joined_user_is_idempotent_but_rejects_a_name_collision() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let did_a = "did:kel:identity_a";
        let did_b = "did:kel:identity_b";

        // First provision under identity A succeeds; re-provisioning the SAME
        // identity under the SAME name is idempotent (a re-join).
        rt.provision_joined_user("laptop", did_a).unwrap();
        rt.provision_joined_user("laptop", did_a).unwrap();

        // The same local name mapping to a DIFFERENT identity is rejected — not
        // silently skipped — so one identity's keys are never installed under
        // another identity's name.
        let err = rt.provision_joined_user("laptop", did_b).map(|_| ()).unwrap_err();
        assert!(
            err.to_string().contains("different identity"),
            "expected a name-collision error, got: {err}"
        );

        // The registry still holds exactly one 'laptop', bound to identity A.
        let registry = storage::load_users(&temp.path().join("system")).unwrap();
        let laptops: Vec<_> = registry
            .users
            .iter()
            .filter(|u| u.user_id == "laptop")
            .collect();
        assert_eq!(laptops.len(), 1, "no duplicate registry entry");
        assert_eq!(laptops[0].did, did_a, "still bound to the first identity");
    }

    #[tokio::test]
    async fn test_logout_user() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;

        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        logout_user(&rt, "alice").await.unwrap();

        let user_dir = temp.path().join("users").join("alice");
        assert!(!user_dir.exists());

        let system_dir = temp.path().join("system");
        let registry = storage::load_users(&system_dir).unwrap();
        assert_eq!(registry.users.len(), 0);

        let routing = storage::load_device_routing(&system_dir).unwrap();
        assert_eq!(routing.routes.len(), 0);
    }

    /// Removing a user leaves NO trace in the keychain — every per-user label is
    /// purged, not just the four the old code handled.
    #[tokio::test]
    async fn logout_user_purges_every_per_user_secret() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();

        // Seed the labels enrollment/join/pin would set beyond what create_user does.
        let labels = [
            kdf_labels::seed32_keychain_key("alice"),
            kdf_labels::identity_signing_key("alice"),
            kdf_labels::master_secret_keychain_key("alice"),
            kdf_labels::operational_cek("alice"),
            kdf_labels::operational_cek_epoch("alice"),
            kdf_labels::frost_share("alice"),
            kdf_labels::frost_pubkey_package("alice"),
            kdf_labels::warm_signing_key("alice"),
            kdf_labels::warm_key_delegation("alice"),
            kdf_labels::user_records_db("alice"),
        ];
        for l in &labels {
            rt.secrets().set_secret(l, "sensitive").unwrap();
        }

        logout_user(&rt, "alice").await.unwrap();

        for l in &labels {
            assert_eq!(
                rt.secrets().get_secret(l).unwrap(),
                None,
                "secret '{l}' survived user removal"
            );
        }
    }

    #[tokio::test]
    async fn test_logout_nonexistent_user() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;

        let result = logout_user(&rt, "alice").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_invalid_user_id() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;

        assert!(create_user(&rt, "", TEST_PASSPHRASE).await.is_err());
        assert!(create_user(&rt, "alice/bob", TEST_PASSPHRASE).await.is_err());
    }

    #[tokio::test]
    async fn test_userruntime_spawned_on_create() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;

        let (_, user_runtime) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        assert_eq!(user_runtime.user_id(), "alice");
        assert!(user_runtime.did().starts_with("did:kel:")); // a new identity is did:kel
        // Read back from disk rather than from a field: the device list is
        // `peer`'s and persisted separately now, so this asserts the write
        // happened rather than that a struct was populated.
        let devices =
            kotton_peer::devices::DeviceList::load(user_runtime.base_dir()).unwrap();
        assert_eq!(devices.len(), 1);
    }

    #[tokio::test]
    async fn test_userruntime_removed_on_logout() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;

        let (_, alice_rt) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();

        // The daemon's logout is two acts, in this order: stop being resident,
        // then do the disk work (`dispatch` evicts before calling this, because
        // background services enumerate loaded users). `logout_user` cannot
        // reach the daemon's bookkeeping any more, so the caller evicts — this
        // test performs the same sequence, and here evicting is dropping the
        // last handle.
        drop(alice_rt);
        logout_user(&rt, "alice").await.unwrap();

        // The load-bearing assertion is the *on-disk* removal, which is the half
        // this function still owns. Asserting the eviction alone would only be
        // asserting the line above it.
        let on_disk = storage::load_users(&temp.path().join("system")).unwrap();
        assert!(
            !on_disk.users.iter().any(|u| u.user_id == "alice"),
            "logout must remove the user from the on-disk registry"
        );
    }

    #[tokio::test]
    async fn test_users_loaded_on_startup() {
        let temp = TempDir::new().unwrap();

        // First process: create two users on this device.
        {
            let rt = make_runtime(&temp).await;
            create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
            create_user(&rt, "bob", TEST_PASSPHRASE).await.unwrap();
        }

        // Second process: a **fresh** map, because residency does not survive a
        // process — that is the whole claim being tested. Carrying one across
        // both blocks would have asserted the opposite while still passing,
        // which is how this test failed when the field moved. A plain map, not
        // the daemon's type: what is under test is what `load_users` returns.
        let mut resident: std::collections::HashMap<String, std::sync::Arc<UserStore>> =
            std::collections::HashMap::new();
        let rt = make_runtime(&temp).await;
        assert!(
            !resident.contains_key("alice"),
            "nothing is resident before loading"
        );
        for (user_id, user_rt) in rt.load_users().await.unwrap() {
            resident.insert(user_id, user_rt);
        }
        assert!(resident.contains_key("alice"));
        assert!(resident.contains_key("bob"));

        let alice = resident.get("alice").unwrap();
        let devices = kotton_peer::devices::DeviceList::load(alice.base_dir()).unwrap();
        assert_eq!(devices.len(), 1);
    }

    #[tokio::test]
    async fn test_device_routing() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;

        let (result, _user_rt) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        let fp = result.device_fingerprint;

        assert_eq!(rt.route_device(&fp).as_deref(), Some("alice"));

        assert!(rt.route_device("unknown_fingerprint").is_none());
    }

    /// Ignored because it **fails**, and written down rather than adjusted so that
    /// "can a wiped device recover" has a mechanical answer: remove the `ignore`
    /// and it must go green.
    ///
    /// It logs out — which does `remove_dir_all` on the user directory, taking the
    /// KEL with it — and then logs in with the phrase. That worked while the AID
    /// was reconstructible from the mnemonic. It cannot now: verification needs a
    /// chain to check the phrase against, and this device no longer has one.
    /// Keeping the chain around to make it pass would test a path the product does
    /// not take: fetching a chain for a wiped device is not built.
    #[ignore = "needs the chain-fetch path: a wiped device has nothing to verify the phrase against"]
    #[tokio::test]
    async fn test_login_with_recovery_key() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;

        let (creation, alice_rt) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        // Recovery is set up after creation now, so a login-by-phrase test has to
        // set one up before there is a phrase to log in with.
        let recovery_key = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("adding a recovery phrase");

        logout_user(&rt, "alice").await.unwrap();
        // Eviction is the caller's now — `logout_user` closes the record store
        // but cannot reach the daemon's bookkeeping. The
        // daemon does both, in this order, in `dispatch`; so does this test.
        // With no map to remove from, evicting is dropping the last handle.
        drop(alice_rt);

        // Simulate data sync from another device: minimal on-disk state
        let user_dir = temp.path().join("users").join("alice");
        std::fs::create_dir_all(user_dir.join("keys")).unwrap();
        std::fs::create_dir_all(user_dir.join("data")).unwrap();

        let config_content = format!(
            "user_id = \"alice\"\ndid = \"{}\"\n\n[remotes.local.backend]\ntype = \"local\"\npath = \"{}\"\n",
            creation.did,
            user_dir.join("data").to_string_lossy().replace('\\', "\\\\")
        );
        std::fs::write(user_dir.join("config.toml"), config_content).unwrap();
        std::fs::write(user_dir.join("devices.json"), r#"{"devices":[]}"#).unwrap();

        // Re-register the user in the system registry
        let system_dir = temp.path().join("system");
        let mut registry = storage::load_users(&system_dir).unwrap();
        registry.users.push(UserRecord {
            user_id: "alice".to_string(),
            did: creation.did.clone(),
            did_method: "kel".to_string(),
            aliases: vec![],
            created_at: SystemTime::now(),
            last_active: SystemTime::now(),
            versions: ComponentVersions::default(),
        });
        storage::save_users(&system_dir, &registry).unwrap();

        let (uid, new_fp, user_runtime) = login_with_recovery_key(
            &rt,
            &recovery_key,
            None,
            Some("New Laptop".into()),
            // Nothing is resident: the eviction above dropped the only handle.
            // The daemon arrives at this call with the same `None`.
            None,
        )
        .await
        .unwrap();

        assert_eq!(uid, "alice");
        assert!(!new_fp.is_empty());
        // Both create and login use the stable device fingerprint -- they must match.
        assert_eq!(new_fp, creation.device_fingerprint);

        // Asserts on the runtime login *returned* — which is the one the daemon
        // will make resident. The registry is deliberately not consulted here:
        // `logout_user` above evicted alice, so a lookup would be asking whether
        // login re-registered her, and it no longer does that by design.
        assert_eq!(user_runtime.user_id(), "alice");
        assert_eq!(user_runtime.did(), creation.did);
        let devices =
            kotton_peer::devices::DeviceList::load(user_runtime.base_dir()).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_name, "New Laptop");

        assert_eq!(rt.route_device(&new_fp).as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn test_login_with_invalid_recovery_key() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;

        let result = login_with_recovery_key(&rt, "invalid mnemonic phrase", None, None, None).await;
        assert!(result.is_err());
        let msg = result.map(|_| ()).unwrap_err().to_string();
        // Wording moved with the identity change — a phrase is no longer turned into
        // an AID, so "failed to derive" is not what happens. It is still rejected
        // before anything is looked up, which is the property.
        assert!(
            msg.to_lowercase().contains("mnemonic") || msg.to_lowercase().contains("phrase"),
            "an invalid phrase should be rejected as such, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_login_with_unknown_recovery_key() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;

        let mnemonic = Bip39MnemonicProvider.generate().unwrap();
        let result = login_with_recovery_key(&rt, &mnemonic, None, None, None).await;
        assert!(result.is_err());
        // A well-formed phrase that is nobody's authority. It used to fail as "no
        // user found" after reconstructing an AID; it now fails because no local
        // chain commits this phrase's reserve key — same refusal, checked rather
        // than derived.
        let msg = result.map(|_| ()).unwrap_err().to_string();
        assert!(
            msg.contains("recovery phrase as an authority") || msg.contains("key history"),
            "an unknown phrase should be refused, got: {msg}"
        );
    }

    /// The right phrase, with no name, re-opens a resident user: the log that
    /// commits it is found among the local ones.
    #[tokio::test]
    async fn test_reauth_with_correct_mnemonic_succeeds() {
        // After a session lock the UserStore stays loaded but the session token
        // is removed.  Re-authenticating with the correct mnemonic must succeed
        // so the UI can issue a fresh session token.
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;

        let (_result, alice_rt) = create_user(&rt, "alice", TEST_PASSPHRASE).await.unwrap();
        let phrase = add_recovery_phrase(rt.base_dir(), rt.secrets(), "alice")
            .await
            .expect("adding a recovery phrase");
        // Still resident — "the UserStore stays loaded" is the premise here.
        let login_result =
            login_with_recovery_key(&rt, &phrase, None, None, Some(alice_rt)).await;
        assert!(
            login_result.is_ok(),
            "re-auth with correct mnemonic should succeed: {:?}",
            login_result.err()
        );
    }
}
