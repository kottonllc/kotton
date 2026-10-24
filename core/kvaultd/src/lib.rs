// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kvaultd` — the vault: the node a person rents to keep their data (RFC-0084).
//!
//! It keeps sealed packs it cannot open, admits the person's devices — the one
//! that enrolled it, and each other one the identity introduces under its
//! signature (`devices`) — holds the
//! sealed recovery copy a phrase-only device needs, and reserves at the person's
//! relay so they are reachable when nothing of theirs is awake. It is paid by
//! the byte and it has one meter. Many people's pools live in one process, and
//! each pool holds that person's drives here: the tenancy's own tree, and each
//! drive made beside it (`drives`).
//!
//! What is *not* here is the point: no apps, no sandbox, no display, no
//! plaintext verb. The full daemon enrolled blind is correct because a node
//! with no key cannot answer a plaintext verb; this binary is the shape in which
//! that reliance is unnecessary, and `cargo xtask vault-check` keeps it so.

pub mod carry;
pub mod control;
pub mod devices;
pub mod doors;
pub mod drives;
pub mod host;
pub mod instance;
pub mod meter;
pub mod operator;
pub mod peer;
pub mod reach;
pub mod residency;
pub mod settings;
pub mod shelf;
pub mod tenancy;

use kotton_device::users::residency::Residency as _;
use kotton_device::users::DeviceUsers as _;
use kotton_device::{DeviceRuntime, RuntimeConfig};
use kotton_sys::ipc::IpcEndpoint;
use kotton_sys::secret::SecretsStore;
use meter::Meter;
use peer::PeerContext;
use residency::Pools;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

pub struct Vault {
    peer: Arc<PeerContext>,
    control: Arc<control::ControlContext>,
    endpoint: IpcEndpoint,
    device_db: Arc<SqlitePool>,
    /// The state directory's exclusive lock, held from before the machine db
    /// is opened until [`Self::shutdown`], so `kvaultd create` cannot write
    /// the operator set under a serving vault (`instance::StateLock`).
    held: std::sync::Mutex<Option<instance::StateLock>>,
}

impl Vault {
    /// A vault at the base directory the environment names, with the OS
    /// keychain, on the shelves the environment names (`KVAULTD_SHELF`).
    pub async fn new(endpoint: IpcEndpoint) -> io::Result<Self> {
        let base = kotton_common::base_dir().map_err(|e| io::Error::other(e.to_string()))?;
        // The state directory checked before the provider opens anything in it:
        // under `KOTTON_SECRETS=file` the open reads `system/secrets.json`, and
        // its error would otherwise be what a refused directory prints.
        instance::check_state_dir(&base)?;
        // Keychain entries scoped to this install's base dir, an in-process store
        // under a temp root — the runtime's own rule for where secrets live.
        let provider = kotton_secret::SecretsProvider::for_base_dir(&base);
        let secrets: Arc<dyn SecretsStore + Send + Sync> = provider.open(&base).map_err(io::Error::other)?;
        let shelves = shelf::from_env()?;
        Self::open(base, endpoint, secrets, shelves, Some(provider)).await
    }

    /// A vault at an explicit `base`, with an injected secrets store, on the
    /// local disk — what a test constructs, one per temporary directory.
    pub async fn new_with_base_and_secrets(
        base: PathBuf,
        endpoint: IpcEndpoint,
        secrets: Arc<dyn SecretsStore + Send + Sync>,
    ) -> io::Result<Self> {
        Self::new_with_shelves(base, endpoint, secrets, shelf::local()).await
    }

    /// A vault whose pools rest on `shelves` — a bucket, when the landlord has
    /// one (RFC-0084 V5). Everything the vault keeps beside the pools (its own
    /// key, each person's chain and sealed recovery copy, the paired-nodes
    /// table) stays under `base` on its disk: small, and the vault's own.
    pub async fn new_with_shelves(
        base: PathBuf,
        endpoint: IpcEndpoint,
        secrets: Arc<dyn SecretsStore + Send + Sync>,
        shelves: Arc<dyn kotton_sys::store::Shelves>,
    ) -> io::Result<Self> {
        Self::open(base, endpoint, secrets, shelves, None).await
    }

    /// The vault, its store opened by `provider` when this process chose it
    /// ([`Self::new`]) — compared with the provider `kvaultd create` recorded —
    /// or handed in by a caller that holds it (`None`).
    async fn open(
        base: PathBuf,
        endpoint: IpcEndpoint,
        secrets: Arc<dyn SecretsStore + Send + Sync>,
        shelves: Arc<dyn kotton_sys::store::Shelves>,
        provider: Option<kotton_secret::SecretsProvider>,
    ) -> io::Result<Self> {
        // No vault exists unowned (RFC-0084 V19): before anything is opened,
        // bound or made, the state must be this process's alone and name an
        // operator. A state directory that is not there names none, and is not
        // made here — `kvaultd create` makes it.
        // Held first, before the machine db is opened: a `create` mid-run is
        // never read half-written. Before the lock, the state directory is
        // checked and never made: one that is not there was never created, and
        // one that is not this user's and closed is refused unchanged
        // (`instance::check_state_dir`). Nothing under it is checked.
        instance::check_state_dir(&base)?;
        let held = instance::StateLock::take(&base)?;
        instance::refuse_unless_operated(&base).await?;
        // Started under the provider it was created under, named when not.
        if let Some(provider) = provider {
            instance::refuse_unless_started_as_created(&base, provider)?;
        }
        // And its own key is where the provider keeps it: the runtime below
        // would make one where it is not, which a device may and a vault may
        // not (`instance::refuse_unless_keyed`).
        instance::refuse_unless_keyed(&base, secrets.as_ref())?;
        // A vault operated before the record existed has none, and `create`
        // refuses operated state, so it would never get one: the start that
        // found the key under its own provider has proved that provider, and
        // writes it, under the lock. Every later start compares.
        if let Some(provider) = provider {
            if instance::recorded_provider(&base)?.is_none() {
                instance::record_provider(&base, provider)?;
                tracing::info!(provider = provider.name(), "recorded which secrets provider holds this vault's key");
            }
        }
        let db = kotton_device::db::open_machine_db(instance::machine_db(&base))
            .await
            .map_err(|e| io::Error::other(format!("failed to open machine db: {e}")))?;
        let device_db = kotton_device::db::open_device_db(&base, &db).await?;
        // The device's own rows — the forwarding relay and its window — and
        // nothing that names a relay: where this vault stands is its reach set,
        // stood at below (`reach::restore`).
        let nat = kotton_device::config::db::load_nat_config(&device_db).await?;
        let nat_at_start = nat.clone();
        let peer_listen_port = kotton_device::config::db::load_peer_listen_port(&device_db)
            .await?
            .or_else(|| {
                std::env::var("KOTTON_PEER_LISTEN_PORT")
                    .ok()
                    .and_then(|s| s.parse::<u16>().ok())
            });
        // The host's one address (`TASK-a-box-has-one-public-address`), resolved
        // once, here: a name a person mistyped is an error at startup rather
        // than a silent nothing announced in a ceremony a day later — the
        // failure `resolve_advertise` exists to refuse.
        let public_ip = match std::env::var("KOTTON_PUBLIC_ADDR") {
            Ok(v) if !v.trim().is_empty() => {
                Some(kotton_net::resolve_advertise(&format!("{}:0", v.trim())).await?.ip())
            }
            _ => None,
        };
        let config = RuntimeConfig {
            nat,
            peer_listen_port,
            public_ip,
            principal: None,
            ..RuntimeConfig::default()
        };
        let runtime = DeviceRuntime::new_with_secrets_and_shelves(base.clone(), config, secrets, shelves)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        // Every pool this vault keeps, made resident. A keeper serves all of
        // them at once (RFC-0084 V6); there is no principal to scope to.
        let pools = Pools::new();
        for (user_id, store) in runtime
            .load_users()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?
        {
            pools.insert(user_id, store);
        }
        let ids = pools.ids();

        // What each pool's chain lets this vault admit (a recovered device on
        // proof, a phrase-only one on a claim), learned before the listener is up.
        kotton_device::users::admission::reproject(&base, &ids, &runtime.admission());

        let db = Arc::new(db);
        let paired_keys = runtime.paired_keys();
        {
            let resolved: Vec<(String, Arc<dyn kotton_peer::membership::MemberStore>)> = pools
                .all()
                .into_iter()
                .map(|(id, s)| (id, s as Arc<dyn kotton_peer::membership::MemberStore>))
                .collect();
            kotton_peer::daemon::nodes::reproject_allowlist(&resolved, &db, &paired_keys).await;
        }

        // The meter, seeded by measuring what is already on the shelf, with
        // each pool's own quota read back from beside the doors (`pool_quotas`).
        let meter = Arc::new(Meter::from_env());
        meter::init(&db).await?;
        meter.load(&db).await?;
        for (id, store) in pools.all() {
            meter.set(&id, peer::measure_pool(&store).await);
        }

        let runtime = Arc::new(runtime);
        // Where this vault stands, as its operator's desktop last told it, so a
        // restart reserves where it reserved before with the keys it presented.
        reach::init(&db).await?;
        reach::restore(&runtime, &db, nat_at_start).await?;
        // The doors held for the people this vault keeps for (`DEC-0056`),
        // reloaded so a restart answers the same doors it did before.
        doors::init(&db).await?;
        doors::refresh(&runtime, &db).await;
        carry::init(&db).await?;
        devices::init(&db).await?;
        drives::init(&db).await?;
        let peer = Arc::new(PeerContext {
            runtime: Arc::clone(&runtime),
            pools,
            db,
            meter,
            reassembly: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            tenancy: tokio::sync::RwLock::new(()),
            drops: tokio::sync::Mutex::new(()),
        });
        let device_db = Arc::new(device_db);
        let control = Arc::new(control::ControlContext {
            peer: Arc::clone(&peer),
            device_db: Arc::clone(&device_db),
            sessions: Arc::new(std::sync::RwLock::new(HashMap::new())),
            pending_confirms: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            shown: control::Shown::default(),
        });
        Ok(Self {
            peer,
            control,
            endpoint,
            device_db,
            held: std::sync::Mutex::new(Some(held)),
        })
    }

    /// This vault's line (RFC-0084 V20): its kind, the address it announces
    /// and its key. Printed at every start; it carries no secret, so the
    /// journal may keep it.
    pub fn line(&self) -> kotton_wire::line::InstanceLine {
        let config = self.peer.runtime.config();
        instance::line(
            instance::hint(config.public_ip, config.peer_listen_port),
            self.peer.runtime.device_signing_pubkey_bytes(),
        )
    }

    /// Take `set` as this vault's reach set — what its operator's `StandAt`
    /// reaches (`reach::stand_at`), for a caller that holds the vault in
    /// process and so already holds every authority over it: the suite.
    pub async fn stand_at(&self, set: Vec<kotton_wire::rendezvous::Stand>) -> Result<(), String> {
        reach::stand_at(&self.peer.runtime, &self.peer.db, &self.device_db, set).await
    }

    pub fn runtime(&self) -> &Arc<DeviceRuntime> {
        &self.peer.runtime
    }

    pub fn pools(&self) -> &Pools {
        &self.peer.pools
    }

    pub fn meter(&self) -> &Arc<Meter> {
        &self.peer.meter
    }

    /// Every act an operator key said over the wire, oldest first, each under
    /// the key that said it (`TASK-a-device-has-operators-not-an-operator`) —
    /// a readout, as `doors_held` is.
    pub async fn operator_acts(&self) -> io::Result<Vec<kotton_peer::daemon::db::OperatorAct>> {
        kotton_peer::daemon::db::operator_acts(&self.peer.db).await
    }

    /// How many doors this vault holds for `user_id` right now — a readout,
    /// for the landlord's door and for a test that must not race the device
    /// handing them over.
    pub async fn doors_held(&self, user_id: &str) -> u32 {
        use sqlx::Row as _;
        sqlx::query("SELECT COUNT(*) AS n FROM held_doors WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(self.peer.db.as_ref())
            .await
            .map(|r| r.get::<i64, _>("n") as u32)
            .unwrap_or(0)
    }

    /// How many messages this vault carries for `user_id` right now — a
    /// readout, as `doors_held` is.
    pub async fn carried(&self, user_id: &str) -> u32 {
        carry::count(&self.peer.db, user_id).await
    }

    /// How many sealed deliveries this vault holds for `user_id` right now,
    /// waiting for a device of theirs to take them — a readout.
    pub async fn deliveries_held(&self, user_id: &str) -> u32 {
        use sqlx::Row as _;
        sqlx::query("SELECT COUNT(*) AS n FROM held_deliveries WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(self.peer.db.as_ref())
            .await
            .map(|r| r.get::<i64, _>("n") as u32)
            .unwrap_or(0)
    }

    /// Start the authenticated peer listener on `port`, and the relay-side
    /// listener beside it, both serving the vault's verbs and nothing else.
    pub async fn start_peer_listener_background(self: &Arc<Self>, port: u16) -> anyhow::Result<()> {
        self.peer.runtime.start_peer_listener(port, self.peer_handler()).await
    }

    /// The vault's verbs, as the handler every door serves. It holds the
    /// landlord's door's context because the operator's key reaches the
    /// door's four landlord verbs (`control::landlord`); what reaches what is
    /// `peer::reaches`.
    fn peer_handler(&self) -> kotton_peer::PeerHandler {
        let ctx = Arc::clone(&self.control);
        Arc::new(move |peer_did: String, req_bytes: Vec<u8>| {
            let ctx = Arc::clone(&ctx);
            Box::pin(async move {
                let request = match serde_json::from_slice::<kotton_wire::ipc::UserRequest>(&req_bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        return serde_json::to_vec(&kotton_wire::ipc::UserResponse::Error {
                            message: format!("invalid peer request: {e}"),
                        })
                        .unwrap_or_default();
                    }
                };
                let response = peer::handle(&ctx, &peer_did, request).await;
                serde_json::to_vec(&response).unwrap_or_default()
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send>>
        })
    }

    /// Start, serve the door until it fails, then close what is held.
    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let outcome = Arc::clone(&self).serve().await;
        self.shutdown().await;
        outcome
    }

    async fn serve(self: Arc<Self>) -> io::Result<()> {
        self.peer.runtime.start().await.map_err(io::Error::other)?;
        // Reserve at the relay: one handle per paired device, and every door
        // held for a person (`DEC-0056`). This is what makes a vault reachable
        // when every device of theirs is asleep (RFC-0084, "the vault holds a
        // reservation"); the device-side handler answers its verbs there too.
        self.peer.runtime.start_relay_reservations(self.peer_handler());
        // Carry what each person's outbox handed here, while no device of
        // theirs is awake to try it.
        let _carrying = carry::spawn(Arc::clone(&self.peer.runtime), Arc::clone(&self.peer.db));
        if let Some(port) = self.peer.runtime.config().peer_listen_port {
            self.start_peer_listener_background(port)
                .await
                .map_err(io::Error::other)?;
        }
        tracing::info!(
            pools = self.peer.pools.count(),
            default_quota = ?self.peer.meter.default_quota(),
            "vault serving"
        );
        control::serve(self.endpoint.clone(), Arc::clone(&self.control)).await
    }

    pub async fn shutdown(&self) {
        if let Err(e) = self.peer.runtime.shutdown().await {
            tracing::debug!("runtime shutdown: {e}");
        }
        for (id, _) in self.peer.pools.all() {
            self.peer.pools.remove(&id);
        }
        self.peer.db.close().await;
        self.device_db.close().await;
        // The state is free for another vault, or for `create`, only now.
        self.held.lock().unwrap().take();
        tracing::info!("vault shutdown complete");
    }
}
