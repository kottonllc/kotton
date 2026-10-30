// SPDX-License-Identifier: AGPL-3.0-or-later
//! `DeviceRuntime` — the machine, running.
//!
//! It holds what a node *is while switched on*: its identity and
//! configuration, the transports and discovery it started, the fingerprint →
//! user_id routing table, the mount locks, and the lifecycle that starts and
//! stops all of it.
//!
//! **It reaches no user's data, and that is checkable rather than asserted:**
//! this crate does not depend on `kotton-store` and names no `UserStore`
//! anywhere. Three things are not on this struct — the user-runtime registry,
//! the record-store cache, and the user-lifecycle methods — because each would
//! be a path from the machine to a user's contents, and the invariant in this
//! crate's `lib.rs` admits none.
//!
//! The user-lifecycle methods are `crate::users::DeviceUsers`, a trait
//! implemented for this struct. An inherent impl must live with its type; a
//! trait impl need not.

pub use crate::config;
/// Re-exported from [`kotton_device`], where the machine's own identity now lives.
pub(crate) use crate::identity;
pub(crate) mod lifecycle;
mod provisioning;
#[cfg(test)]
mod multi_transport_tests;
#[cfg(test)]
mod boot_announces_nothing_tests;
pub(crate) mod network;
pub(crate) mod routing;
use crate::config::RuntimeConfig;
use kotton_peer::Reachability;
use kotton_record::SchemaRegistry;
use anyhow::Result;
use kotton_sys::net::{Connection, Discovery, Transport};
use kotton_sys::secret::SecretsStore;
use kotton_secret::SealedCustody;
use kotton_diag::{Event, EventBus, EventCategory, EventLevel};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;

/// System-level runtime (one per machine)
///
/// Manages system-wide services and routes connections to appropriate UserRuntimes.
/// One mutex per `(user_id, mount)`. Named because the shape is load-bearing:
/// the key is the *mount*, not whoever is touching it, which is what makes the
/// lock outlive any single writer. See [`DeviceRuntime::lock_mount`].
pub type MountLocks = Arc<RwLock<HashMap<(String, String), Arc<Mutex<()>>>>>;

pub struct DeviceRuntime {
    pub(crate) base_dir: PathBuf,
    pub(crate) config: RuntimeConfig,
    pub(crate) event_bus: Arc<EventBus>,

    /// Poked when a user's contact set changes — see [`Self::contacts_changed`].
    contacts_changed: Arc<tokio::sync::Notify>,

    /// Poked when the relays this device holds at change — see
    /// [`Self::reach_changed`].
    reach_changed: Arc<tokio::sync::Notify>,

    // Stable per-machine identity -- generated once, persisted to device/identity.json
    pub(crate) device_fingerprint: String,

    /// The device's operational Ed25519 signing key.
    ///
    /// Used to derive the TLS certificate for the QUIC peer-listener (and for
    /// presence, NAT coordination, and outbound dialing). Loaded from — or
    /// created and persisted to — the secrets store on startup
    /// ([`load_or_create_device_signing_key`]), so the operational identity is
    /// **stable across restarts**. Binding it to the user's root via a
    /// `WarmKeyDelegation` is not built.
    pub(crate) device_signing_key: ed25519_dalek::SigningKey,

    // Network infrastructure
    pub(crate) transports: Arc<RwLock<Vec<Box<dyn Transport>>>>, // All configured transports
    pub(crate) discoveries: Arc<RwLock<Vec<Box<dyn Discovery>>>>, // All configured discovery mechanisms
    pub(crate) active_connections: Arc<Mutex<HashMap<String, Box<dyn Connection>>>>, // peer_id â†’ connection
    pub(crate) accept_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>, // Accept loop tasks

    /// How this device is reached by the other devices its user owns: the live
    /// reachability config, the STUN-learned reflexive address, the presence
    /// registration and the relay reservation.
    ///
    /// One handle rather than four fields — reachability
    /// is peer authority, and the state has one lifetime and three readers.
    pub(crate) reachability: Arc<Reachability>,

    /// The local-network door (`network::local_door`): closed unless the person
    /// opened it, and holding its socket only while it is open.
    pub(crate) local_door: network::local_door::DoorKeeper,

    /// The listeners introductions opened (`network::introduction`): one per
    /// session one of the person's devices asked for, none otherwise.
    pub(crate) introductions: network::introduction::Introductions,

    // Multi-user support
    pub(crate) device_routing: Arc<RwLock<HashMap<String, String>>>, // device_fingerprint → user_id
    /// One lock per mount, keyed `(user_id, mount)` — see [`DeviceRuntime::lock_mount`].
    ///
    /// A mount is one manifest and one superblock, and its writers are not
    /// idempotent against each other: a compaction that retires a pack a sync is
    /// mid-write on loses what was in it. Everything that writes a mount takes
    /// this for the whole operation.
    ///
    /// It lives on the runtime, beside the mounts themselves, because the lock
    /// belongs to the *mount* rather than to whoever happens to be touching it.
    /// The sync engine's `running` set is not this: it is a coalescing set that
    /// dedupes work the engine itself dispatched, and is blind to a sync the
    /// user started — the gap that lost a record (STATUS, later¹⁰).
    ///
    /// Entries are created on first use and kept; the map is bounded by users ×
    /// mounts, and a stale entry is an idle mutex.
    pub(crate) mount_locks: MountLocks,

    // Schema Layer
    /// In-memory registry of all known schema definitions (core + app).
    pub schema_registry: Arc<RwLock<SchemaRegistry>>,

    // Window Registry

    // Lifecycle state
    pub(crate) started: Arc<RwLock<bool>>,

    /// Secrets store — OS keychain in production, in-memory in tests.
    pub(crate) secrets: Arc<dyn SecretsStore + Send + Sync>,

    /// The shelves this node's mounts rest on: the host
    /// filesystem unless the process that built this runtime said otherwise —
    /// a vault does, when its landlord has a bucket. Decided once, here, and
    /// never named below this type.
    pub(crate) shelves: Arc<dyn kotton_sys::store::Shelves>,

    /// The same object as [`Self::secrets`], typed, so the credential-gated
    /// operations can reach `adopt_root` / `lock`.
    ///
    /// Two handles to one store rather than two stores: every read still goes
    /// through `secrets`, and this only exposes the custody decisions that a
    /// bare `SecretsStore` cannot express.
    pub(crate) custody: Arc<SealedCustody>,
}

/// The device's operational signing key as `secrets` holds it — read, never
/// made. `Ok(None)` only when the store answered that it holds none. A store
/// that could not be read is an error, and so is a value that reads but does
/// not decode as a key: neither is a store with no key, and a caller that took
/// either for one would mint over the key the node's chain admits.
/// What a vault's `create` asks of a state it would adopt, so it never mints a
/// key over existing state.
pub fn stored_device_signing_key(
    secrets: &(dyn SecretsStore + Send + Sync),
) -> Result<Option<ed25519_dalek::SigningKey>> {
    use kotton_common::crypto::kdf_labels;
    let label = kdf_labels::device_operational_key();
    let Some(hex_seed) = secrets
        .get_secret(&label)
        .map_err(|e| anyhow::anyhow!("could not read the device operational key ({label}) from the secrets store: {e}"))?
    else {
        return Ok(None);
    };
    // Refused, not replaced: a value that is there and is not a key is the
    // record's open half, answered with its default — the file store's open
    // refuses a file it cannot parse in the same words. The value is not echoed.
    let seed = hex::decode(&hex_seed)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the device operational key ({label}) in the secrets store does not read as a key, \
                 so nothing was made over it"
            )
        })?;
    Ok(Some(ed25519_dalek::SigningKey::from_bytes(&seed)))
}

/// Make a fresh operational signing key and keep it in `secrets`, under
/// [`kdf_labels::device_operational_key`] as a lowercase-hex 32-byte Ed25519
/// seed — the one form [`stored_device_signing_key`] reads.
///
/// [`kdf_labels::device_operational_key`]: kotton_common::crypto::kdf_labels::device_operational_key
pub fn make_device_signing_key(secrets: &(dyn SecretsStore + Send + Sync)) -> Result<ed25519_dalek::SigningKey> {
    use kotton_common::crypto::kdf_labels;
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    secrets
        .set_secret(&kdf_labels::device_operational_key(), &hex::encode(key.to_bytes()))
        .map_err(|e| match e {
            // The keyring already names itself and the remedy (`SecretsError`'s
            // own message) — wrapping it in "persist device operational key: …"
            // buries the one line a person can act on inside jargon about a
            // function they never called, where the kernel keyring is refused.
            kotton_sys::secret::SecretsError::KeyringRefused => anyhow::anyhow!("{e}"),
            e => anyhow::anyhow!("persist device operational key: {e}"),
        })?;
    tracing::info!("generated and persisted a new device operational signing key");
    Ok(key)
}

/// Load the device's persistent operational signing key from `secrets`, or
/// generate and persist a fresh one on first start.
///
/// Stored as a lowercase-hex 32-byte Ed25519 seed under
/// `kdf_labels::device_operational_key`. This makes the device's operational
/// identity stable across restarts (a per-process random key would break the
/// mTLS allowlist and presence on every restart).
///
/// A key is made only when the store answered that it holds none. One it could
/// not read, or one that does not decode, stops the start
/// ([`stored_device_signing_key`]); neither is replaced, the first by reading
/// `get_secret(..).ok()` nor the second with a warning.
fn load_or_create_device_signing_key(
    secrets: &(dyn SecretsStore + Send + Sync),
) -> Result<ed25519_dalek::SigningKey> {
    match stored_device_signing_key(secrets)? {
        Some(key) => Ok(key),
        None => make_device_signing_key(secrets),
    }
}

impl DeviceRuntime {
    /// Create a new DeviceRuntime with the given configuration
    ///
    /// Does not start services - call `start()` to begin operation.
    pub async fn new(base_dir: PathBuf, config: RuntimeConfig) -> Result<Self> {
        // Keychain entries scope to this install's base dir (legacy unscoped
        // names for the default install) — a dev daemon must not read or write
        // production secrets, least of all the device operational key.
        // Not `OsSecrets` directly: a runtime rooted under the system temp dir
        // gets an in-process store, so a throwaway root leaves nothing permanent
        // in the machine's keychain. See `secrets_for_base_dir`.
        let secrets = kotton_secret::secrets_for_base_dir(&base_dir)?;
        Self::new_with_secrets(base_dir, config, secrets).await
    }

    /// The shelves a device has unless told otherwise: directories, through
    /// the host filesystem. Named here, in the layer that knows there is one.
    fn local_shelves() -> Arc<dyn kotton_sys::store::Shelves> {
        Arc::new(kotton_store::LocalShelves(kotton_fs::OsFilesystem))
    }

    async fn build(
        base_dir: PathBuf,
        config: RuntimeConfig,
        secrets: Arc<dyn SecretsStore + Send + Sync>,
        shelves: Arc<dyn kotton_sys::store::Shelves>,
    ) -> Result<Self> {
        // Validate config
        config
            .validate()
            .map_err(|e| anyhow::anyhow!("Invalid configuration: {}", e))?;

        // Every secrets read in this process goes through custody: operational
        // roots the user has a sealed vault for are held
        // in memory here and nowhere else, and everything else passes through
        // to the platform. Wrapping at construction rather than at call sites
        // is what makes it impossible to bypass — there is one store, and it
        // is this one.
        let custody = Arc::new(SealedCustody::new(secrets));
        let secrets: Arc<dyn SecretsStore + Send + Sync> = custody.clone();

        // Create event bus
        let event_bus = Arc::new(EventBus::default());


        // Load or generate stable device identity (device/identity.json)
        let device_identity = identity::ensure_device_identity(&base_dir)
            .map_err(|e| anyhow::anyhow!("Device identity error: {}", e))?;

        // Load (or create + persist) the device's operational signing key. This
        // is the stable, device-level identity that authenticates operational
        // peer connections — stable across restarts, unlike a per-process
        // ephemeral key.
        let device_signing_key = load_or_create_device_signing_key(secrets.as_ref())?;

        // Seed reachability from the boot config before `config` is moved. A
        // runtime `relay set` moves it on from there without a restart.
        let reachability = Arc::new(Reachability::new(
            config.nat.clone(),
            device_signing_key.clone(),
        ));

        let runtime = Self {
            base_dir,
            config,
            event_bus: event_bus.clone(),
            contacts_changed: Arc::new(tokio::sync::Notify::new()),
            reach_changed: Arc::new(tokio::sync::Notify::new()),
            device_fingerprint: device_identity.fingerprint,
            device_signing_key,
            transports: Arc::new(RwLock::new(Vec::new())),
            discoveries: Arc::new(RwLock::new(Vec::new())),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            accept_tasks: Arc::new(Mutex::new(Vec::new())),
            reachability,
            local_door: Default::default(),
            introductions: Default::default(),
            device_routing: Arc::new(RwLock::new(HashMap::new())),
            mount_locks: Arc::new(RwLock::new(HashMap::new())),
            schema_registry: Arc::new(RwLock::new(SchemaRegistry::new())),
            started: Arc::new(RwLock::new(false)),
            secrets,
            shelves,
            custody,
        };

        Ok(runtime)
    }



    // ── The machine half, not `DeviceUsers`'s ──────────────────────────────────
    //
    // These nine are not in the user-lifecycle trait, because by authority they
    // are the machine's: a routing table, mount locks, a dialer, and the
    // machine's own paths and fingerprint. None reaches a user's data, so
    // they are inherent and travel with the struct to `core/device`.
    //
    // A test of them that had to import `DeviceUsers` would be a file asking
    // why its own state needs someone else's trait.

    /// Whether this machine can bind a vault to hardware at all.
    pub fn hardware_binding_available(&self) -> bool {
        kotton_secret::PlatformBinding::is_available()
    }

    /// Which user owns the device with this fingerprint, if any.
    ///
    /// **Returns an id, not a runtime.** The routing table
    /// answers a question about *the machine* — which of the users on this machine a
    /// paired device belongs to — and that answer is a user id. Resolving that id
    /// to a live runtime and acting on it is the daemon's hop, not this one
    /// ("who is asking?" versus "what is running?").
    ///
    /// It is the one method that answers it: two methods doing the same thing,
    /// neither with a production caller, is how a boundary stays undecided,
    /// with no single place to change.
    pub fn route_device(&self, device_fingerprint: &str) -> Option<String> {
        self.device_routing
            .read()
            .unwrap()
            .get(device_fingerprint)
            .cloned()
    }

    /// Claim a mount for writing, waiting for whoever holds it.
    ///
    /// **Every writer of a mount must hold this for the whole operation** — both
    /// sync directions and maintenance alike. A mount is one manifest and one
    /// superblock; two writers interleaving on it is how a compaction retires a
    /// pack a sync has written but not yet committed.
    ///
    /// The guard is owned, so it can be held across the awaits of a long sync.
    pub async fn lock_mount(&self, user_id: &str, mount: &str) -> tokio::sync::OwnedMutexGuard<()> {
        self.mount_lock(user_id, mount).lock_owned().await
    }

    /// Claim a mount only if it is free, for work that is never urgent.
    ///
    /// Maintenance uses this: packing and compaction can always happen on the
    /// next pass, so they yield to real work rather than queueing ahead of it.
    pub fn try_lock_mount(
        &self,
        user_id: &str,
        mount: &str,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        self.mount_lock(user_id, mount).try_lock_owned().ok()
    }

    pub fn base_dir(&self) -> &std::path::PathBuf {
        &self.base_dir
    }

    /// The stable per-machine device fingerprint (a `did:key:…` DID).
    ///
    /// This is generated once on first daemon startup and persisted to
    /// `device/identity.json`. All users on the same device share this fingerprint.
    pub fn device_fingerprint(&self) -> &str {
        &self.device_fingerprint
    }


    /// Connect to a peer and return the non-erased [`KottonPeerObjectStorage`].
    ///
    /// Use this when the caller needs to send IPC-level notifications
    /// (e.g. `SyncAvailable`, `RecordSyncAvailable`) in addition to
    /// regular object-storage operations.
    /// What this machine needs in order to dial a peer, as one value.
    ///
    /// Built on demand: the three parts are cheap (`Arc` clones and a key copy),
    /// and naming them is what lets dialing live in `peer`, where its return
    /// type lives.
    pub fn dialer(&self) -> kotton_peer::dialer::Dialer {
        kotton_peer::dialer::Dialer::new(
            self.device_signing_key.clone(),
            Arc::clone(&self.reachability),
            Arc::clone(&self.event_bus),
        )
    }


    /// The lock protecting one mount, created on first use.
    ///
    /// The registry lock is released before the returned handle is awaited on,
    /// so a caller waiting for a mount never blocks another user's lookup.
    fn mount_lock(&self, user_id: &str, mount: &str) -> Arc<tokio::sync::Mutex<()>> {
        let key = (user_id.to_string(), mount.to_string());
        let mut locks = self.mount_locks.write().unwrap();
        locks.entry(key).or_default().clone()
    }

    // ── Accessors ────────────────────────────────────────────────────────────
    //
    // These fields are `pub(crate)`, so without an accessor every one of their
    // readers would have to live in this crate. Naming them here is what lets those readers sit
    // outside it — and it narrows what they can reach: a caller asks for the
    // mount locks, not for the machine.
    /// The device's operational Ed25519 signing key.
    pub fn device_signing_key(&self) -> &ed25519_dalek::SigningKey {
        &self.device_signing_key
    }

    /// How this device is reached by the other devices its user owns.
    /// The live admission state the peer listener verifies against — identity
    /// tips, committed recovery authorities, and handshake verdicts awaiting
    /// persistence. Shared with the listener; cloning shares.
    pub fn admission(&self) -> kotton_net::transport::quic::tls::Admission {
        self.reachability.admission()
    }

    /// Poked when a user's contact set changes, so whoever keeps the contact
    /// mailboxes rebuilds them from membership rather than polling
    /// it. The ceremony that admits a contact is here; the registry it feeds is
    /// the daemon's, and this is the whole of what passes between them.
    pub fn contacts_changed(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.contacts_changed)
    }

    /// Poked whenever the relays this device holds reservations at change, so
    /// whoever keeps each person's reach note re-signs it and sends it to their
    /// contacts at once rather than on its next timer.
    /// Its own signal, not the reservation listener's: that one is taken by one
    /// waiter, and sharing it would starve one of the two.
    pub fn reach_changed(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.reach_changed)
    }

    pub fn reachability(&self) -> &Arc<Reachability> {
        &self.reachability
    }

    /// One lock per mount, keyed `(user_id, mount)`. See [`Self::lock_mount`].
    pub fn mount_locks(&self) -> &MountLocks {
        &self.mount_locks
    }

    /// The fingerprint → user_id routing table.
    pub fn device_routing(&self) -> &Arc<RwLock<HashMap<String, String>>> {
        &self.device_routing
    }

    /// Live accept-loop tasks, so a listener can register the one it spawned.
    pub fn accept_tasks(&self) -> &Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> {
        &self.accept_tasks
    }

    /// The typed custody handle, for the credential-gated operations a bare
    /// `SecretsStore` cannot express.
    pub fn custody(&self) -> &Arc<SealedCustody> {
        &self.custody
    }

    /// Get the event bus for subscribing to events
    pub fn event_bus(&self) -> &Arc<EventBus> {
        &self.event_bus
    }

    /// Get the runtime configuration
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Get the secrets store (OS keychain in production, in-memory in tests).
    pub fn secrets(&self) -> &(dyn SecretsStore + Send + Sync) {
        self.secrets.as_ref()
    }

    /// Get an owned, cloneable handle to the secrets store.
    ///
    /// Use when a `'static` background task must outlive the borrow from
    /// [`secrets`](Self::secrets) — e.g. the node-enrollment ceremony task that
    /// persists the issuer's retained FROST share after the joiner connects.
    pub fn secrets_arc(&self) -> Arc<dyn SecretsStore + Send + Sync> {
        self.secrets.clone()
    }

    /// Create a runtime with a custom secrets store (used in integration tests).
    pub async fn new_with_secrets(
        base_dir: PathBuf,
        config: RuntimeConfig,
        secrets: Arc<dyn SecretsStore + Send + Sync>,
    ) -> Result<Self> {
        Self::build(base_dir, config, secrets, Self::local_shelves()).await
    }

    /// Create a runtime whose mounts rest on `shelves` rather than on the host
    /// filesystem — what a vault does when its landlord has a bucket.
    pub async fn new_with_secrets_and_shelves(
        base_dir: PathBuf,
        config: RuntimeConfig,
        secrets: Arc<dyn SecretsStore + Send + Sync>,
        shelves: Arc<dyn kotton_sys::store::Shelves>,
    ) -> Result<Self> {
        Self::build(base_dir, config, secrets, shelves).await
    }

    /// Where this node's mounts rest.
    pub fn shelves(&self) -> &dyn kotton_sys::store::Shelves {
        self.shelves.as_ref()
    }

    /// Bytes of the device's ephemeral Ed25519 verifying key.
    ///
    /// This is the public key the remote peer must store in `PairedNode.public_key`
    /// so that our mTLS TLS certificate can be verified during QUIC handshakes.
    pub fn device_signing_pubkey_bytes(&self) -> [u8; 32] {
        self.device_signing_key.verifying_key().to_bytes()
    }

    /// The routing fingerprint from `device/identity.json`, as a DID — **the
    /// scope of this device's key labels**, and nothing else.
    ///
    /// It is not `PairedNode.device_did` on the remote peer, nor the argument to
    /// `remote_add`, in the sense that matters: the key behind it was generated
    /// once and its private half discarded, so the DID names a key nobody can present, and a peer that
    /// records it cannot check it against anything. What *is* checked is the
    /// operational key, and the DID of that key is [`Self::operational_did`].
    /// This one survives because `resolve_user_keys` derives a label from it;
    /// changing it re-keys every existing install. A node identity that is two
    /// keys is a debt, named here.
    pub fn device_did(&self) -> &str {
        &self.device_fingerprint
    }

    /// The DID of the key this node presents: `did:key:` over the operational
    /// signing key, the same string a peer derives from this node's TLS
    /// certificate on connect. This is what `GetNodeIdentity` answers, what
    /// the pairing ceremony records, and what a person writes down.
    pub fn operational_did(&self) -> String {
        kotton_crypto::DidKeyMethod::from_public_key(&self.device_signing_key.verifying_key())
            .to_string()
    }

    /// Check if runtime is started
    pub fn is_started(&self) -> bool {
        *self.started.read().unwrap()
    }


    // ====================
    // Runtime Methods (business logic that composes platform traits)
    // ====================

    /// Connect to a peer using the first available compatible transport
    ///
    /// Selects a transport based on address type and capability.
    // TODO: refactor transports to Arc<dyn Transport> so the read guard
    // can be dropped before the connect() await.  Safe for now: the guard is
    // read-only, no writer runs concurrently during connect.
    #[allow(clippy::await_holding_lock)]
    pub async fn connect_to_peer(
        &self,
        peer_id: String,
        address: &kotton_sys::net::Address,
    ) -> Result<()> {
        self.event_bus
            .publish(Event::with_payload(
                EventCategory::Network,
                EventLevel::Info,
                format!("Connecting to peer {} at {:?}", peer_id, address),
                serde_json::json!({
                    "peer_id": peer_id,
                }),
            ))
            .ok();

        // Find compatible transport
        let transports = self.transports.read().unwrap();
        let compatible_transport = transports.iter().find(|t| {
            t.supported_address_types()
                .contains(&address.address_type())
        });

        let transport = compatible_transport.ok_or_else(|| {
            anyhow::anyhow!(
                "No compatible transport for address type: {:?}",
                address.address_type()
            )
        })?;

        // Establish connection
        let connection = transport
            .connect(address)
            .await
            .map_err(|e| anyhow::anyhow!("Connection failed: {}", e))?;

        // Store active connection
        self.active_connections
            .lock()
            .await
            .insert(peer_id.clone(), connection);

        self.event_bus
            .publish(Event::new(
                EventCategory::Network,
                EventLevel::Info,
                format!("Connected to peer {}", peer_id),
            ))
            .ok();

        Ok(())
    }

    /// Send message to a peer
    ///
    /// Uses existing connection or fails if not connected.
    pub async fn send_message(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        let connections = self.active_connections.lock().await;
        let connection = connections
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Not connected to peer: {}", peer_id))?;

        connection
            .send(data)
            .await
            .map_err(|e| anyhow::anyhow!("Send failed: {}", e))?;

        self.event_bus
            .publish(Event::with_payload(
                EventCategory::Network,
                EventLevel::Debug,
                format!("Sent {} bytes to {}", data.len(), peer_id),
                serde_json::json!({
                    "peer_id": peer_id,
                    "bytes": data.len(),
                }),
            ))
            .ok();

        Ok(())
    }

    /// Get count of active transports
    pub fn transport_count(&self) -> usize {
        self.transports.read().unwrap().len()
    }

    /// Get count of active connections
    pub async fn connection_count(&self) -> usize {
        self.active_connections.lock().await.len()
    }

    /// Get count of active discovery mechanisms
    pub fn discovery_count(&self) -> usize {
        self.discoveries.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn runtime_for_locks(temp: &tempfile::TempDir) -> DeviceRuntime {
        DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            RuntimeConfig::default(),
            Arc::new(kotton_secret::MemorySecrets::new()),
        )
        .await
        .unwrap()
    }

    /// The property the mount lock exists for: two writers of one mount cannot
    /// hold it at once. A sync and a compaction overlapping here is how a pack
    /// that one has written but not committed gets reclaimed by the other.
    #[tokio::test]
    async fn one_mount_admits_one_writer() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime_for_locks(&temp).await;

        let held = rt.lock_mount("alice", "local").await;
        assert!(
            rt.try_lock_mount("alice", "local").is_none(),
            "a second writer must not get the mount while the first holds it"
        );

        // Releasing hands it to the next writer — the lock defers work, it does
        // not drop it.
        drop(held);
        assert!(
            rt.try_lock_mount("alice", "local").is_some(),
            "the mount must be claimable again once released"
        );
    }

    /// And it locks a *mount*, not the world: unrelated mounts stay concurrent,
    /// which is why this is not simply a global sync lock.
    #[tokio::test]
    async fn different_mounts_do_not_contend() {
        let temp = tempfile::tempdir().unwrap();
        let rt = runtime_for_locks(&temp).await;

        let _alice_local = rt.lock_mount("alice", "local").await;
        assert!(
            rt.try_lock_mount("alice", "backup").is_some(),
            "another mount of the same user must stay independent"
        );
        assert!(
            rt.try_lock_mount("bob", "local").is_some(),
            "another user's mount must stay independent"
        );
    }

    #[tokio::test]
    async fn test_system_runtime_creation() {
        let config = RuntimeConfig::default();
        let temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, std::sync::Arc::new(kotton_secret::MemorySecrets::new())).await;
        assert!(runtime.is_ok());
    }

    #[tokio::test]
    async fn device_operational_key_is_stable_across_restarts() {
        use kotton_secret::MemorySecrets;
        // A persistent secrets store stands in for the OS keychain surviving a
        // process restart; the base dir is fresh each "restart" to prove the
        // key comes from the keychain, not disk.
        let secrets = Arc::new(MemorySecrets::new());

        let temp1 = tempfile::tempdir().unwrap();
        let rt1 = DeviceRuntime::new_with_secrets(
            temp1.path().to_path_buf(),
            RuntimeConfig::default(),
            secrets.clone(),
        )
        .await
        .unwrap();
        let key1 = rt1.device_signing_pubkey_bytes();

        let temp2 = tempfile::tempdir().unwrap();
        let rt2 = DeviceRuntime::new_with_secrets(
            temp2.path().to_path_buf(),
            RuntimeConfig::default(),
            secrets.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            key1,
            rt2.device_signing_pubkey_bytes(),
            "operational key persists across restarts (loaded from the keychain)"
        );

        // A node with its own (empty) keychain generates a different key.
        let temp3 = tempfile::tempdir().unwrap();
        let rt3 = DeviceRuntime::new_with_secrets(
            temp3.path().to_path_buf(),
            RuntimeConfig::default(),
            Arc::new(MemorySecrets::new()),
        )
        .await
        .unwrap();
        assert_ne!(
            key1,
            rt3.device_signing_pubkey_bytes(),
            "a distinct device (separate keychain) has a distinct operational key"
        );
    }

    /// Stands in for the Linux kernel keyring refusing `add_key` — the shape
    /// a container's default seccomp profile produces.
    /// `set_secret` is the only call `load_or_create_device_signing_key`
    /// reaches on a fresh install, so it is the only one that needs to refuse.
    struct RefusingKeyring;

    impl SecretsStore for RefusingKeyring {
        fn get_secret(&self, _key: &str) -> kotton_sys::secret::SecretsResult<Option<String>> {
            Ok(None)
        }
        fn set_secret(&self, _key: &str, _value: &str) -> kotton_sys::secret::SecretsResult<()> {
            Err(kotton_sys::secret::SecretsError::KeyringRefused)
        }
        fn delete_secret(&self, _key: &str) -> kotton_sys::secret::SecretsResult<()> {
            Ok(())
        }
    }

    /// The line a friend actually sees when the kernel keyring refuses
    /// `add_key`, replacing `persist device operational key: Storage error:
    /// Platform secure storage failure: PermissionDenied`, which is what a
    /// container's default seccomp profile produces: one line, naming the keyring as
    /// what failed and what would let it run, nothing sealed.
    #[tokio::test]
    async fn a_refused_kernel_keyring_names_itself_and_the_remedy() {
        let temp = tempfile::tempdir().unwrap();
        // `DeviceRuntime` derives no `Debug`, so `expect_err`/`unwrap_err`
        // (both bounded on `T: Debug`) are not available here.
        let err = match DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            RuntimeConfig::default(),
            Arc::new(RefusingKeyring),
        )
        .await
        {
            Ok(_) => panic!("a refused keyring must fail startup rather than continue silently"),
            Err(e) => e,
        };

        let line = err.to_string();
        assert!(
            !line.contains('\n'),
            "the exit message must be one line: {line}"
        );
        assert!(
            line.contains("keyring"),
            "must name the keyring as what failed: {line}"
        );
        assert!(
            line.contains("seccomp") || line.contains("without"),
            "must say what would let it run: {line}"
        );
        assert!(
            !line.contains("Storage error")
                && !line.contains("PermissionDenied")
                && !line.contains("persist device operational key"),
            "must not be the old opaque nested error: {line}"
        );

        // This is `DeviceRuntime::new`'s error, not yet what a friend sees:
        // `kuserd`'s startup (`core/kuserd/src/agent/mod.rs`) wraps it with
        // `io::Error::other(e.to_string())` and the process exits printing
        // that `io::Error`'s `Debug` form. Reproduce the same wrap here so
        // the assertions above are checked against the actual printed line,
        // not an intermediate one.
        let printed = format!("{:?}", std::io::Error::other(line.clone()));
        // `{:?}` on an `io::Error` always escapes a literal newline, so a
        // `!printed.contains('\n')` assertion here would hold for any input
        // and prove nothing; the meaningful property is that the wrap
        // carries the payload through unmangled — checked directly, rather
        // than re-deriving "one line" from a guarantee `Debug` already gives.
        assert!(
            printed.contains(&line),
            "wrapping must not lose or mangle the payload: {printed}"
        );
    }

    /// A store whose every read fails — a locked or unreachable keychain — and
    /// which counts the writes it is asked for, refusing none of them, so a
    /// caller that went on to mint would be seen doing it.
    #[derive(Default)]
    struct UnreadableStore {
        writes: std::sync::atomic::AtomicUsize,
    }

    impl SecretsStore for UnreadableStore {
        fn get_secret(&self, _key: &str) -> kotton_sys::secret::SecretsResult<Option<String>> {
            Err(kotton_sys::secret::SecretsError::Storage("the keychain did not answer".into()))
        }
        fn set_secret(&self, _key: &str, _value: &str) -> kotton_sys::secret::SecretsResult<()> {
            self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        fn delete_secret(&self, _key: &str) -> kotton_sys::secret::SecretsResult<()> {
            Ok(())
        }
    }

    /// **A runtime over a store it cannot read does not start, and writes no
    /// key.** An unreadable store is not one that holds nothing: minting here
    /// would put a new operational key over the one the node's chain admits.
    #[tokio::test]
    async fn a_store_that_cannot_be_read_does_not_start_and_no_key_is_minted() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(UnreadableStore::default());
        let started = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            RuntimeConfig::default(),
            store.clone(),
        )
        .await;
        let err = match started {
            Ok(_) => panic!("a runtime over an unreadable store must not start"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("the keychain did not answer"), "the read's own error is named: {err}");
        assert_eq!(
            store.writes.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "set_secret was called: a key was minted over one the store could not read"
        );
    }

    /// **A stored key that does not read as a key is refused, naming the label,
    /// and never replaced** — the open half of the record, answered with its
    /// default, as the file store's open answers a file it cannot read.
    #[tokio::test]
    async fn a_stored_key_that_does_not_read_as_a_key_is_refused_not_replaced() {
        use kotton_common::crypto::kdf_labels;
        let temp = tempfile::tempdir().unwrap();
        let secrets = Arc::new(kotton_secret::MemorySecrets::new());
        secrets.set_secret(&kdf_labels::device_operational_key(), "not a key").unwrap();
        let started = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            RuntimeConfig::default(),
            secrets.clone(),
        )
        .await;
        let err = match started {
            Ok(_) => panic!("a runtime whose stored key does not decode must not start"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains(&kdf_labels::device_operational_key()), "the label is named: {err}");
        assert_eq!(
            secrets.get_secret(&kdf_labels::device_operational_key()).unwrap().as_deref(),
            Some("not a key"),
            "the stored value is as it was"
        );
    }

    #[tokio::test]
    async fn test_system_runtime_rejects_invalid_config() {
        let mut config = RuntimeConfig::default();
        config.stores = vec![crate::config::StorageConfig::S3 {
            bucket: "".to_string(), // Invalid: empty bucket
            region: "us-east-1".to_string(),
            credentials: None,
        }];

        let temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, std::sync::Arc::new(kotton_secret::MemorySecrets::new())).await;
        assert!(runtime.is_err());
    }

    #[tokio::test]
    async fn test_event_bus_access() {
        let config = RuntimeConfig::default();
        let temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, std::sync::Arc::new(kotton_secret::MemorySecrets::new()))
            .await
            .unwrap();

        let event_bus = runtime.event_bus();
        assert_eq!(event_bus.subscriber_count(), 0);

        // Subscribe and verify it works
        let _receiver = event_bus.subscribe();
        assert_eq!(event_bus.subscriber_count(), 1);
    }

    #[tokio::test]
    async fn test_config_access() {
        let config = RuntimeConfig::full_node(std::path::PathBuf::from("/data"));
        let temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config.clone(), std::sync::Arc::new(kotton_secret::MemorySecrets::new()))
            .await
            .unwrap();

        let runtime_config = runtime.config();
        assert_eq!(runtime_config.transports.len(), 1);
        assert_eq!(runtime_config.stores.len(), 1);
        assert!(runtime_config.relay.is_some());
    }

    /// A `file` node (`KOTTON_SECRETS=file`) whose `secrets.json` does not parse
    /// does not start, and the file that holds its key is left as it was.
    ///
    /// The provider is named rather than chosen by `new`: a root under the system
    /// temp directory is given an in-process store whatever `KOTTON_SECRETS` says.
    /// What follows the choice is `new`'s own line, `open` then the runtime.
    #[tokio::test]
    async fn a_node_whose_secrets_file_does_not_parse_does_not_start_with_a_new_key() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("system").join("secrets.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // A store cut short mid-write by something other than `persist`: the key is there, half of it.
        let original = br#"{"kotton:device_operational_key": "9f86d081884c7d659a2feaa0c55ad0"#.to_vec();
        std::fs::write(&path, &original).unwrap();

        let started = async {
            let secrets = kotton_secret::SecretsProvider::File.open(temp.path())?;
            DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), RuntimeConfig::default(), secrets).await
        }
        .await;

        assert!(started.is_err(), "a node whose secrets file does not parse started with a new key");
        assert_eq!(std::fs::read(&path).unwrap(), original, "the file that held the node's key was written over");
    }
}
