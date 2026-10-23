// SPDX-License-Identifier: AGPL-3.0-or-later
//! `DeviceRuntime`'s user lifecycle API.
//!
//! Most of these methods delegate to [`crate::users::commands`],
//! where the logic lives. **They are the API, not scaffolding for it**: most
//! are one-line delegates, and they carry dozens of production and test call
//! sites on a `DeviceRuntime`. A delegation layer with that many callers is a
//! crate's public surface.
//!
//! Counting those callers by a bare search for a method name (`.create_user(`)
//! counts every method with that name — the SDK client, the CLI and the shell
//! each have their own. Intersecting with the files that actually name
//! `DeviceRuntime` is what makes the number mean something.
//!
//! Three methods hold real logic rather than delegating: `add_contact`,
//! `user_cek_domain_id`, and `open_peer_client`. The record-store cache is the
//! daemon's, and so is opening a record store.
//!
//! One method, `device_fingerprint`, has no caller — but it is **not** dead. It
//! wraps a `pub(crate)` field that every caller reaches directly today because
//! they are all in this crate; a caller outside it needs the accessor.
//!
//! It lives beside `DeviceRuntime` in `core/device` because `device` may name a
//! `UserStore`, so the methods need no other home.
//!
//! The trait is kept rather than flattened into an inherent impl: it carries the
//! rationale for all 44 methods, and the impl carries only bodies, so deleting it
//! would discard the documentation to save one `use` at each call site. Flattening
//! it is a separate, mechanical change if anyone wants it.
//!
//! The constraint that replaces the old one is narrower and holds: **`device` may
//! name a user's store; it may not enumerate or resolve one.** Residency — the
//! `user_id -> Arc<UserStore>` map — stays in the daemon.

pub mod admission;
pub mod commands;
pub mod contacts;
pub mod drive_devices;
pub mod pairing;
pub mod reach;
pub mod recover;
pub mod residency;
pub mod files;
/// Installing a model: the manifest as a record, the weights as the sealed
/// object it names.
pub mod models;
#[cfg(test)]
mod record_tests;

use std::time::SystemTime;
use crate::registry::{ComponentVersions, UserRecord};
use self::commands::{resolve_user_keys, create_user_store, load_user_store};
use kotton_store::runtime::user::UserStore;
use kotton_peer::membership::Membership as _;
use crate::registry as storage;
use crate::DeviceRuntime;
use kotton_identity::kel_store;
use anyhow::{anyhow, Context, Result};
use std::sync::Arc;

/// `DeviceRuntime`'s user-lifecycle API, as a trait.
///
/// **A trait rather than an inherent impl, so the struct is not pinned.** An
/// inherent `impl` must live in the crate that defines the type,
/// which pinned `DeviceRuntime` here: these methods could not follow it to
/// `core/device` either, because `create_user` returns a `UserStore` and that
/// crate may hold no path to a user's data. The two constraints pointed in
/// opposite directions and a local trait is the way between them — the same
/// shape as `impl MemberStore for UserStore` in `peer`.
///
/// Call sites keep their method syntax and add `use crate::users::DeviceUsers`.
/// That is the whole cost, which is why this was worth measuring before
/// rewriting 83 call sites into free-function calls instead.
#[async_trait::async_trait]
pub trait DeviceUsers {
    /// Register a joining device's identity in this device's users registry and
    /// build its [`UserStore`].
    ///
    /// `Ok(None)` is the idempotent re-join of the *same* identity under the same
    /// local name. The same name mapping to a **different** DID is a collision and
    /// is refused, rather than installing one identity's keys under another's name.
    fn provision_joined_user(
        &self,
        user_id: &str,
        did: &str,
    ) -> Result<Option<Arc<UserStore>>>;

    /// Rebuild a single user's [`UserStore`] from disk with the **currently
    /// resolved** operational CEK, and **return** it.
    ///
    /// It does not install what it builds. Residency is the daemon's, so every
    /// caller follows this with its own `users.insert` — see `users::pairing` and
    /// the `UnlockWithPin` arm of `kuserd`'s dispatch. It does not replace the
    /// live handle in any runtime map: a test that reloaded and dropped the result
    /// would pass against the stale store it meant to replace.
    ///
    /// Loading a user binds its VFS object storage to whatever CEK was resolvable at
    /// load time ([`resolve_operational_cek`]). Two states arrive that way. A node
    /// enrolled into an existing identity receives its CEK *after* startup, so the
    /// already-loaded store is bound to the wrong key. And a daemon that started
    /// before its user was unlocked — every restart — holds one bound to **no** key
    /// until the unlock rebuilds it, and a login gives it its key back. Re-resolving here
    /// and swapping at the call site is what lets either take effect **without a
    /// daemon restart**.
    ///
    /// In-flight requests holding a clone of the old `Arc<UserStore>` finish
    /// against it; subsequent lookups get the refreshed one.
    async fn reload_user_runtime(&self, user_id: &str) -> Result<Arc<UserStore>>;

    /// Open a peer link for one user, declaring the key domain it replicates in.
    ///
    /// In the trait, not the machine: the *bodies* name no store, but the **signatures** take
    /// `Option<&UserStore>`, so these are a path to a user's data and cannot
    /// be the machine's. Classifying by body alone would miss it; the compiler
    /// does not.
    /// Connect to a paired peer and return its storage as an [`ObjectStorage`].
    ///
    /// The `node` record must already be resolved from the paired-nodes DB by the
    /// caller (the daemon IPC handler).
    ///
    /// Internally calls [`nat_connect`] → [`QuicPeerChannel`] → [`KottonPeerObjectStorage`].
    async fn open_peer_storage(
        &self,
        node: kotton_wire::peer::PairedNode,
        user_id: &str,
        loaded: Option<&kotton_store::runtime::user::UserStore>,
    ) -> Result<Arc<dyn kotton_sys::store::SyncableStore>>;
    async fn open_peer_client(
        &self,
        node: kotton_wire::peer::PairedNode,
        user_id: &str,
        loaded: Option<&kotton_store::runtime::user::UserStore>,
    ) -> Result<kotton_peer::KottonPeerObjectStorage>;

    /// Load every user this process may serve.
    ///
    /// In the trait, not an inherent impl: it returns `Arc<UserStore>`.
    /// Returning the users is deliberate — registering them is residency,
    /// and residency is the daemon's.
    async fn load_users(&self) -> Result<Vec<(String, Arc<UserStore>)>>;

    /// The user's canonical DID — the `did:kel` AID recorded at creation.
    ///
    /// This is the identity a person shares and that contacts are stored under.
    /// Read from the users registry rather than derived, so it stays correct
    /// across key rotation: rotation changes the authoritative key, never the
    /// AID.
    fn user_aid(&self, user_id: &str) -> Option<String>;

    /// The user's current authoritative Ed25519 key, by replaying their KEL.
    ///
    /// The same resolution grant verification performs, so a rotation is
    /// observed immediately rather than after a cache expires.
    fn user_current_key(&self, user_id: &str) -> Option<[u8; 32]>;

    /// Admit another identity on this device as a **contact** of `user_rt`.
    ///
    /// A contact is the missing first domino in "contacts → admission → channel
    /// key grant". Channel key-granting already re-wraps the channel key for a
    /// member and writes it into their store — but it resolves the member's
    /// public key through the membership registry, and until now the only thing
    /// that ever wrote to that registry was **device pairing**. So the registry
    /// could contain your own laptop and nothing else, and a household
    /// conversation was unreachable: not because admission was missing, but
    /// because another person could not exist as a known key.
    ///
    /// ## Where the key comes from, and the limit of it
    ///
    /// The contact's Ed25519 key is resolved from **their KEL on this device** —
    /// the key the identity system issues, not a string someone pasted. That is
    /// trustworthy here for exactly one reason: both identities live on this
    /// daemon, so reading one is not trusting a stranger.
    ///
    /// It therefore admits **local identities only**. A contact on another
    /// machine needs their key to arrive over a ceremony that authenticates it
    /// (contact pairing), and this deliberately refuses rather than inventing a
    /// weaker path — accepting a DID plus a pasted key would let anyone who can
    /// reach the IPC socket install themselves as anyone.
    ///
    /// ## Why this one keeps `&self` when its two neighbours did not
    ///
    /// It takes the admitting user's runtime rather than their id, because
    /// resolving an id to a runtime is the caller's hop. But unlike [`UserStore::member_public_key`] and
    /// [`UserStore::list_contacts`], which moved to `UserStore` outright,
    /// this genuinely needs both principals: the **machine** knows which local
    /// identity holds `contact_did` and can replay their KEL, and the **user's
    /// runtime** is what the resulting member record is written into. A method
    /// that needs a fact about the machine is a device method, and this is the one
    /// of the three that actually was.
    async fn add_contact(&self, user_rt: &UserStore, contact_did: &str) -> Result<()>;

    /// The local account holding `did`, if any identity on this device does.
    ///
    /// The inverse of [`Self::user_aid`]. Answers "is this party someone I can
    /// hand a record to directly, or does their copy have to travel?" — which is
    /// the question local delivery turns on.
    fn local_user_for_did(&self, did: &str) -> Option<String>;

    /// See [`commands::create_user`] — returns the runtime rather than making
    /// it resident, so that creating a user and deciding a user is live on this
    /// machine are two acts with two callers.
    ///
    /// `passphrase` is not optional, and that is the point: it is assessed and
    /// sealed inside `create_user`, so no caller can reach a created identity
    /// without one.
    async fn create_user(
        &self,
        user_id: &str,
        passphrase: &str,
    ) -> Result<(kotton_identity::provisioning::UserCreationResult, Arc<UserStore>)>;

    async fn logout_user(&self, user_id: &str) -> Result<()>;

    async fn login_with_recovery_key(
        &self,
        recovery_key: &str,
        user_id_hint: Option<&str>,
        device_name: Option<String>,
        resident: Option<Arc<UserStore>>,
    ) -> Result<(String, String, Arc<UserStore>)>;

    /// Rotate the user's operational identity key via a mnemonic recovery rotation.
    /// Returns the new operational verifying key (hex); the AID is
    /// unchanged.
    async fn rotate_identity_via_mnemonic(
        &self,
        user_id: &str,
        recovery_key: &str,
        credential: Option<&str>,
    ) -> Result<String>;

    /// Seal the operational roots under `pin` into the user's at-rest vault.
    ///
    /// The user must already be logged in (a secrets-store entry exists).  Call
    /// this once after `create_user` to enable PIN-based cold-start unlock.
    async fn set_user_pin(&self, user_id: &str, pin: &str) -> Result<()>;

    /// Open that vault with `pin` and restore the operational roots to the
    /// secrets store.  After this, `get_or_create_record_store` works normally.
    async fn unlock_with_pin(&self, user_id: &str, pin: &str) -> Result<()>;

    /// Bind this user's vault to this device's hardware.
    ///
    /// Opt-in: it changes the recovery story, so it is never inferred from the
    /// hardware merely being present.
    async fn bind_device(&self, user_id: &str, credential: &str) -> Result<()>;


    /// Mark that the user has read and confirmed their BIP-39 recovery mnemonic.
    async fn confirm_mnemonic(&self, user_id: &str) -> Result<()>;

    /// Return the recovery layer coverage for a user.
    fn get_recovery_status(&self, user_id: &str) -> Result<commands::RecoveryStatus>;

    /// Return the cryptographic health summary for a user.
    fn get_key_health(&self, user_id: &str) -> Result<commands::KeyHealthResult>;






    /// The hex **key-domain id** this node's sealed objects belong to, or `None`
    /// if it holds no data keys at all (`BlindStorage`).
    ///
    /// Sealed replication carries this so a receiver can answer the only question
    /// that matters — *can I open this blob?* — which is exactly *is this the same
    /// CEK?* A node without a CEK returns `None`: it has no domain of
    /// its own, only material sealed elsewhere and handed to it.
    ///
    /// Derived from the key rather than tracked as a counter, because a counter
    /// cannot see the failure that matters. Two nodes that were never in the same
    /// fleet both start at epoch 0 and compare equal while holding entirely
    /// different keys — a check that passes exactly when it must fail. The epoch
    /// remains a local concept for diagnostics and rotation ordering.
    ///
    /// ## `loaded` must be the registry's answer, never a convenient `None`
    ///
    /// The runtime is passed in rather than looked up here, because the
    /// registry is the daemon's. That moves only
    /// the lookup — the precedence below stays in one body deliberately, since
    /// it is a security rule and not a convenience.
    ///
    /// It does mean `None` is now something a caller can get wrong, and a caller
    /// that passes `None` while a runtime *is* loaded silently re-creates exactly
    /// the failure the rule exists to prevent: this node advertises one key
    /// domain while sealing in another. So `loaded` must always be what the
    /// registry says, and it is typed as the runtime itself rather than a bool so
    /// that producing one requires having looked.
    ///
    /// Splitting this into an authoritative half and a keychain-only half would
    /// read more cleanly and be worse — it would hand every call site a way to
    /// pick the wrong one.
    fn user_cek_domain_id(
        &self,
        user_id: &str,
        // The store, not the runtime: this reads one thing from it, the key its
        // objects seal under, and the doc below already says "the key the user's
        // stores actually seal with".
        loaded: Option<&kotton_store::runtime::user::UserStore>,
    ) -> Option<String>;




    /// Rebuild the `UserStorageRouter` for `user_id` from `storage-mounts.toml`.
    ///
    /// New app sandbox instances started after this call will pick up the
    /// updated mount table.  Long-lived instances that already have a router
    /// reference are not affected — they must be restarted.
    async fn rebuild_storage_mounts(&self, user_rt: &UserStore) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
impl DeviceUsers for DeviceRuntime {
    /// Provision a user that this device **joined** rather than created:
    /// register it (registry + directory) and stand up its `UserStore` from the
    /// delivered operational CEK — building the encrypted local backend and writing
    /// `config.toml` (via `new` + `save`, the same path `create_user` uses), so the
    /// runtime is live and future `load`s succeed. Idempotent: a no-op if already
    /// present. The join delivers key material; this turns it into a usable identity.
    ///
    /// Returns the new runtime for the caller to make resident, or `None` on the
    /// idempotent re-join — where there is nothing new to register, and saying so
    /// with `None` is more honest than handing back a runtime this call did not
    /// create.
    fn provision_joined_user(
        &self,
        user_id: &str,
        did: &str,
    ) -> Result<Option<Arc<UserStore>>> {
        let system_dir = self.base_dir().join("system");
        let mut registry =
            storage::load_users(&system_dir).context("failed to load users registry")?;
        // The local `user_id` is a nickname; the identity is the DID. If a record
        // already holds this name, only treat it as idempotent when it is the SAME
        // identity (re-joining). A name that already maps to a DIFFERENT identity is
        // a genuine collision — reject it rather than silently skip provisioning (or
        // worse, install this identity's keys under another identity's name).
        if let Some(existing) = registry.users.iter().find(|u| u.user_id == user_id) {
            if existing.did == did {
                return Ok(None); // idempotent re-join of the same identity
            }
            return Err(anyhow!(
                "the name '{user_id}' already belongs to a different identity on this device \
                 ({} ≠ {}); choose a different name for the joining device",
                existing.did,
                did
            ));
        }
        let now = SystemTime::now();
        // Dispatch the method from the DID itself: a did:kel AID (delivered
        // via the enrollment KEL) records "kel"; a legacy did:key records "key".
        let did_method = kotton_wire::did::Did::parse(did)
            .map(|d| d.method().to_string())
            .unwrap_or_else(|_| "key".to_string());
        registry.users.push(UserRecord {
            user_id: user_id.to_string(),
            did: did.to_string(),
            did_method,
            aliases: vec![],
            created_at: now,
            last_active: now,
            versions: ComponentVersions::default(),
        });
        storage::save_users(&system_dir, &registry).context("failed to save users registry")?;
        storage::create_user_directory(self.base_dir(), user_id)
            .with_context(|| format!("failed to create directory for '{user_id}'"))?;

        // Stand up the runtime with the delivered operational CEK: `new` builds the
        // encrypted local backend, `save` persists config.toml so later loads work.
        let user_dir = self.base_dir().join("users").join(user_id);
        let keys = resolve_user_keys(self.secrets(), user_id, self.device_did())?;
        let user_runtime = create_user_store(self.shelves(), user_id, did, user_dir, keys)
            .context("build joined user runtime")?;
        user_runtime.save_config().context("persist joined user config")?;
        Ok(Some(Arc::new(user_runtime)))
    }

    /// See [`Self::provision_joined_user`] — returns the refreshed runtime for
    /// the caller to swap in, rather than replacing the live handle itself.
    async fn reload_user_runtime(&self, user_id: &str) -> Result<Arc<UserStore>> {
        let system_dir = self.base_dir().join("system");
        let registry =
            storage::load_users(&system_dir).context("failed to load users registry")?;
        let user_record = registry
            .users
            .iter()
            .find(|u| u.user_id == user_id)
            .ok_or_else(|| anyhow!("user '{user_id}' not found in registry"))?;

        let user_dir = self.base_dir().join("users").join(user_id);
        let keys = resolve_user_keys(self.secrets(), user_id, self.device_did())?;
        let user_runtime =
            load_user_store(self.shelves(), user_id, &user_record.did, user_dir, keys)
                .await
                .with_context(|| format!("reload user runtime '{user_id}'"))?;

        Ok(Arc::new(user_runtime))
    }

    /// Connect to a paired peer and return its storage as an [`ObjectStorage`].
    ///
    /// The `node` record must already be resolved from the paired-nodes DB by the
    /// caller (the daemon IPC handler).
    ///
    /// Internally calls [`nat_connect`] → [`QuicPeerChannel`] → [`KottonPeerObjectStorage`].
    async fn open_peer_storage(
        &self,
        node: kotton_wire::peer::PairedNode,
        user_id: &str,
        loaded: Option<&kotton_store::runtime::user::UserStore>,
    ) -> Result<Arc<dyn kotton_sys::store::SyncableStore>> {
        let storage = self.open_peer_client(node, user_id, loaded).await?;
        Ok(Arc::new(storage))
    }

    async fn open_peer_client(
        &self,
        node: kotton_wire::peer::PairedNode,
        user_id: &str,
        loaded: Option<&kotton_store::runtime::user::UserStore>,
    ) -> Result<kotton_peer::KottonPeerObjectStorage> {
        let client = self.dialer().connect(node, user_id).await?;
        // Declare the key domain this link replicates in. Without it sealed
        // transfers fail closed rather than moving blobs whose domain is unstated.
        // A node with no CEK declares nothing — it never initiates
        // replication, it only serves it.
        Ok(match self.user_cek_domain_id(user_id, loaded) {
            Some(domain_id) => client.with_domain_id(domain_id),
            None => client,
        })
    }

    /// Load the users already on disk into this process.
    ///
    /// **Called explicitly, not inside the constructor.** Building the machine
    /// and deciding which users are resident in this process are different acts
    /// by different owners: the first is a fact about the machine, the second is
    /// the daemon starting up. In `new`, "a user's runtime exists" would be a
    /// consequence of "the machine was built", which would keep the registry
    /// attached to `DeviceRuntime`.
    ///
    /// Honours [`RuntimeConfig::principal`]: a process spawned for one user loads
    /// only that user, and everyone else on the device stays out of its memory.
    /// That is a security property, not an optimisation, so callers
    /// that skip this call get an empty process rather than a permissive one.
    ///
    /// **Returns the loaded users; registering them is the caller's.** The same split as the constructor above, one level down:
    /// loading answers *which users may this process serve*, and residency is the
    /// daemon's bookkeeping over lifetimes it owns.
    async fn load_users(&self) -> Result<Vec<(String, Arc<UserStore>)>> {
        crate::users::commands::load_users_on_startup(self).await
    }

    // ── Identity resolution ───────────────────────────────────────────────────
    //
    // Answering "who is this user, and what key encrypts to them" — needed by
    // anything that addresses a person rather than a device. Messaging
    // resolves the `did:kel` AID like every other subsystem; a `did:key` derived
    // from the keychain would disagree with them and silently break channel key
    // grants.

    /// The user's canonical DID — the `did:kel` AID recorded at creation.
    ///
    /// This is the identity a person shares and that contacts are stored under.
    /// Read from the users registry rather than derived, so it stays correct
    /// across key rotation: rotation changes the authoritative key, never the
    /// AID.
    fn user_aid(&self, user_id: &str) -> Option<String> {
        let registry = storage::load_users(&self.base_dir().join("system")).ok()?;
        registry
            .users
            .iter()
            .find(|u| u.user_id == user_id)
            .map(|u| u.did.clone())
    }

    /// The user's current authoritative Ed25519 key, by replaying their KEL.
    ///
    /// The same resolution grant verification performs, so a rotation is
    /// observed immediately rather than after a cache expires.
    fn user_current_key(&self, user_id: &str) -> Option<[u8; 32]> {
        kel_store::resolve_current_key_for(self.base_dir(), user_id, false)
            .ok()
            .flatten()
    }

    /// Admit another identity on this device as a **contact** of `user_rt`.
    ///
    /// A contact is the missing first domino in "contacts → admission → channel
    /// key grant". Channel key-granting already re-wraps the channel key for a
    /// member and writes it into their store — but it resolves the member's
    /// public key through the membership registry, and until now the only thing
    /// that ever wrote to that registry was **device pairing**. So the registry
    /// could contain your own laptop and nothing else, and a household
    /// conversation was unreachable: not because admission was missing, but
    /// because another person could not exist as a known key.
    ///
    /// ## Where the key comes from, and the limit of it
    ///
    /// The contact's Ed25519 key is resolved from **their KEL on this device** —
    /// the key the identity system issues, not a string someone pasted. That is
    /// trustworthy here for exactly one reason: both identities live on this
    /// daemon, so reading one is not trusting a stranger.
    ///
    /// It therefore admits **local identities only**. A contact on another
    /// machine needs their key to arrive over a ceremony that authenticates it
    /// (contact pairing), and this deliberately refuses rather than inventing a
    /// weaker path — accepting a DID plus a pasted key would let anyone who can
    /// reach the IPC socket install themselves as anyone.
    ///
    /// ## Why this one keeps `&self` when its two neighbours did not
    ///
    /// It takes the admitting user's runtime rather than their id, because
    /// resolving an id to a runtime is the caller's hop. But unlike [`UserStore::member_public_key`] and
    /// [`UserStore::list_contacts`], which moved to `UserStore` outright,
    /// this genuinely needs both principals: the **machine** knows which local
    /// identity holds `contact_did` and can replay their KEL, and the **user's
    /// runtime** is what the resulting member record is written into. A method
    /// that needs a fact about the machine is a device method, and this is the one
    /// of the three that actually was.
    async fn add_contact(&self, user_rt: &UserStore, contact_did: &str) -> Result<()> {
        use kotton_schemas::membership::{Ceremony, Member, Role};

        let user_id = user_rt.user_id();
        if self.user_aid(user_id).as_deref() == Some(contact_did) {
            anyhow::bail!("'{user_id}' cannot be their own contact");
        }

        // Find the local identity that owns this AID. Scanning is fine: the
        // registry is the handful of identities on one machine.
        let registry = storage::load_users(&self.base_dir().join("system"))
            .context("failed to load the user registry")?;
        let owner = registry
            .users
            .iter()
            .find(|u| u.did == contact_did)
            .ok_or_else(|| {
                anyhow!(
                    "no identity on this device has the DID {contact_did} — a contact on \
                     another machine has to be paired, so their key arrives authenticated \
                     rather than asserted"
                )
            })?;

        let public_key = self.user_current_key(&owner.user_id).ok_or_else(|| {
            anyhow!("could not resolve the current key for {contact_did} from their KEL")
        })?;

        let member = Member {
            did: contact_did.to_string(),
            public_key,
            role: Role::Contact,
            admitted_by: Ceremony::Pairing,
            added_at: chrono::Utc::now().to_rfc3339(),
            // `posture` is `Some` only for own devices — a contact holds no data
            // capability, and saying otherwise here would widen a gate that is
            // projected from this field.
            posture: None,
            label: Some(owner.user_id.clone()),
            reach: None,
        };

        user_rt.write_member(&member).await
    }

    /// The local account holding `did`, if any identity on this device does.
    ///
    /// The inverse of [`Self::user_aid`]. Answers "is this party someone I can
    /// hand a record to directly, or does their copy have to travel?" — which is
    /// the question local delivery turns on.
    fn local_user_for_did(&self, did: &str) -> Option<String> {
        storage::load_users(&self.base_dir().join("system"))
            .ok()?
            .users
            .into_iter()
            .find(|u| u.did == did)
            .map(|u| u.user_id)
    }

    // ── User lifecycle ────────────────────────────────────────────────────────

    /// See [`commands::create_user`] — returns the runtime rather than making
    /// it resident, so that creating a user and deciding a user is live on this
    /// machine are two acts with two callers.
    async fn create_user(
        &self,
        user_id: &str,
        passphrase: &str,
    ) -> Result<(kotton_identity::provisioning::UserCreationResult, Arc<UserStore>)> {
        commands::create_user(self, user_id, passphrase).await
    }

    async fn logout_user(&self, user_id: &str) -> Result<()> {
        commands::logout_user(self, user_id).await
    }

    async fn login_with_recovery_key(
        &self,
        recovery_key: &str,
        user_id_hint: Option<&str>,
        device_name: Option<String>,
        resident: Option<Arc<UserStore>>,
    ) -> Result<(String, String, Arc<UserStore>)> {
        commands::login_with_recovery_key(self, recovery_key, user_id_hint, device_name, resident)
            .await
    }

    /// Rotate the user's operational identity key via a mnemonic recovery rotation.
    /// Returns the new operational verifying key (hex); the AID is
    /// unchanged.
    async fn rotate_identity_via_mnemonic(
        &self,
        user_id: &str,
        recovery_key: &str,
        credential: Option<&str>,
    ) -> Result<String> {
        commands::rotate_identity_via_mnemonic(self, user_id, recovery_key, credential).await
    }

    /// Seal the operational roots under `pin` into the user's at-rest vault.
    ///
    /// The user must already be logged in (a secrets-store entry exists).  Call
    /// this once after `create_user` to enable PIN-based cold-start unlock.
    async fn set_user_pin(&self, user_id: &str, pin: &str) -> Result<()> {
        kotton_identity::provisioning::set_user_pin(self, user_id, pin).await
    }

    /// Open that vault with `pin` and restore the operational roots to the
    /// secrets store.  After this, `get_or_create_record_store` works normally.
    async fn unlock_with_pin(&self, user_id: &str, pin: &str) -> Result<()> {
        kotton_identity::provisioning::unlock_with_pin(self, user_id, pin).await
    }

    /// Bind this user's vault to this device's hardware.
    ///
    /// Opt-in: it changes the recovery story, so it is never inferred from the
    /// hardware merely being present.
    async fn bind_device(&self, user_id: &str, credential: &str) -> Result<()> {
        kotton_identity::provisioning::bind_device(self, user_id, credential).await
    }


    // -- Recovery status ------------------------------------------------------

    /// Mark that the user has read and confirmed their BIP-39 recovery mnemonic.
    async fn confirm_mnemonic(&self, user_id: &str) -> Result<()> {
        kotton_identity::recovery::confirm_mnemonic(self.base_dir(), user_id).await
    }

    /// Return the recovery layer coverage for a user.
    fn get_recovery_status(&self, user_id: &str) -> Result<commands::RecoveryStatus> {
        let user_dir = self.base_dir().join("users").join(user_id);
        kotton_identity::recovery::get_recovery_status(
            self.base_dir(),
            kotton_identity::provisioning::pin_is_set(&user_dir),
            user_id,
        )
    }

    // -- Key health -----------------------------------------------------------

    /// Return the cryptographic health summary for a user.
    fn get_key_health(&self, user_id: &str) -> Result<commands::KeyHealthResult> {
        let user_dir = self.base_dir().join("users").join(user_id);
        kotton_crypto::key_health::get_key_health(
            self.base_dir(),
            user_id,
            kotton_identity::provisioning::pin_is_set(&user_dir),
        )
    }

    // -- Post-quantum migration ----------------------------------------------

    //  User runtime accessors



    //  Mount locking






    /// The hex **key-domain id** this node's sealed objects belong to, or `None`
    /// if it holds no data keys at all (`BlindStorage`).
    ///
    /// Sealed replication carries this so a receiver can answer the only question
    /// that matters — *can I open this blob?* — which is exactly *is this the same
    /// CEK?* A node without a CEK returns `None`: it has no domain of
    /// its own, only material sealed elsewhere and handed to it.
    ///
    /// Derived from the key rather than tracked as a counter, because a counter
    /// cannot see the failure that matters. Two nodes that were never in the same
    /// fleet both start at epoch 0 and compare equal while holding entirely
    /// different keys — a check that passes exactly when it must fail. The epoch
    /// remains a local concept for diagnostics and rotation ordering.
    ///
    /// ## `loaded` must be the registry's answer, never a convenient `None`
    ///
    /// The runtime is passed in rather than looked up here, because the
    /// registry is the daemon's. That moves only
    /// the lookup — the precedence below stays in one body deliberately, since
    /// it is a security rule and not a convenience.
    ///
    /// It does mean `None` is now something a caller can get wrong, and a caller
    /// that passes `None` while a runtime *is* loaded silently re-creates exactly
    /// the failure the rule exists to prevent: this node advertises one key
    /// domain while sealing in another. So `loaded` must always be what the
    /// registry says, and it is typed as the runtime itself rather than a bool so
    /// that producing one requires having looked.
    ///
    /// Splitting this into an authoritative half and a keychain-only half would
    /// read more cleanly and be worse — it would hand every call site a way to
    /// pick the wrong one.
    fn user_cek_domain_id(
        &self,
        user_id: &str,
        // The store, not the runtime: this reads one thing from it, the key its
        // objects seal under, and the doc below already says "the key the user's
        // stores actually seal with".
        loaded: Option<&kotton_store::runtime::user::UserStore>,
    ) -> Option<String> {
        // The domain must be derived from the key the user's stores actually
        // seal with — the live runtime's CEK — never re-resolved from the OS
        // keychain while a runtime is up. Keychain entries are keyed by
        // user_id alone and machine-global, so a second daemon (or any future
        // rotation flow) rewriting `kotton:*:{user_id}` under a live runtime
        // would otherwise make this node *advertise* one domain while
        // *sealing* in another — blobs then pass the receiver's sealed-replication
        // domain gate and land unopenable, which is precisely the failure the
        // gate exists to refuse. A live runtime with no CEK (a blind posture)
        // is likewise authoritative: it has no domain, whatever a stale
        // keychain entry claims. The keychain is consulted only when no
        // runtime is loaded at all.
        let cek = match loaded {
            Some(store) => store.sealing_keys().map(|k| *k.cek),
            // A CEK the store could not read advertises no domain, the same
            // answer as none: this only names a domain to a peer, and writes
            // nothing. Logged so the unreadable store is not silent.
            None => match kotton_identity::provisioning::resolve_operational_cek(self.secrets(), user_id) {
                Ok(cek) => cek,
                Err(e) => {
                    tracing::warn!(%user_id, "no CEK domain advertised: {e:#}");
                    None
                }
            },
        }?;
        Some(hex::encode(
            kotton_crypto::kdf::derive_cek_domain_id(&cek),
        ))
    }




    //  Schema record stores



    // -- Storage mount hot-reload ---------------------------------------------

    /// Rebuild the `UserStorageRouter` for `user_id` from `storage-mounts.toml`.
    ///
    /// New app sandbox instances started after this call will pick up the
    /// updated mount table.  Long-lived instances that already have a router
    /// reference are not affected — they must be restarted.
    async fn rebuild_storage_mounts(&self, user_rt: &UserStore) -> anyhow::Result<()> {
        // Drop the cached router; the next path resolve re-reads the file.
        user_rt.invalidate_mount_router();
        tracing::info!(
            user_id = user_rt.user_id(),
            "storage-mounts.toml reloaded; mount router invalidated"
        );
        Ok(())
    }
}


