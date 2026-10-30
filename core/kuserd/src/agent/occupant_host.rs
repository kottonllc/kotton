// SPDX-License-Identifier: AGPL-3.0-or-later
//! The daemon's implementation of [`OccupantHost`] — the pre-auth verbs.
//!
//! This is the only place in the tree where a *guest* can cause an identity to
//! be minted, and it is reachable exactly when the caller hands it to
//! `apps::app_launch`/`app_input_event`, which they do only for the app the
//! user designated `shell`.
//!
//! ## The interface and the implementation did not agree
//!
//! `interface auth` declares `create-identity(passphrase) -> (did, mnemonic)`
//! and `unlock(passphrase) -> token`. The identity subsystem has neither shape:
//! [`create_user`] takes a **user id** and no passphrase, and there is no
//! `unlock(passphrase)` verb at all. The credential is established *after* the
//! identity exists, by `set_user_pin`, which seals the operational roots into
//! the at-rest vault; `unlock_with_pin` is what opens them on a cold start.
//!
//! So the WIT was not a stub of the real model — it was a different model,
//! written at the interface without a backing implementation, which is why all
//! three verbs had been erroring since they were declared. This module composes
//! the real verbs into the declared ones rather than changing either:
//!
//! | WIT verb                 | What actually happens                                    |
//! |--------------------------|----------------------------------------------------------|
//! | `create-identity(pass)`  | `create_user(id)` → `prepare_policy(Passphrase)` → `set_user_pin(pass)` → `record` |
//! | `unlock(pass)`           | `unlock_with_pin(the one registered user, pass)`         |
//! | `unlock-with-pin(id,pin)`| `unlock_with_pin(id, pin)`                               |
//!
//! `set_user_pin`'s parameter is named `pin` but is documented as the
//! credential — `bind_device` passes a passphrase to it — so the collapse of
//! "PIN" and "passphrase" is one this layer inherits rather than one it
//! introduces. The PIN is the passphrase today; separating them is the
//! identity subsystem's to do, or nobody's.
//!
//! [`create_user`]: kotton_device::users::commands::create_user
//! [`OccupantHost`]: kotton_app::daemon::apps::OccupantHost

use std::path::Path;
use std::sync::Arc;

use sqlx::SqlitePool;

use kotton_app::daemon::apps::OccupantHost;
use kotton_wire::ipc::{OperatorVerb, UserResponse};
use kotton_wire::runner::{
    RunnerAdmittedBrowser, RunnerAuthError, RunnerContact, RunnerIdentity, RunnerOperator, RunnerOperatorBox,
    RunnerPairedDevice, RunnerPerson, RunnerRelay, RunnerSealedMessage, RunnerTenant,
    RunnerThisDevice, RunnerVault,
};

use crate::agent::device_operator;
use crate::agent::handlers;
use crate::agent::sessions::SessionMap;
use crate::device_users;
use crate::residency::UserRegistry;
use kotton_device::DeviceRuntime;
use kotton_peer::membership::Membership;
use kotton_session::lock_policy;

/// How long an invite minted from Settings › Networking stays open: a day, as
/// `vault invite` and `kvaultd invite` wait by default, and the most the vault
/// takes over the wire (`kvaultd::control::invite_window`).
const LANDLORD_INVITE_TTL_SECS: u64 = 24 * 60 * 60;

/// How long the platform's prompt waits for the person before it is taken down
/// and the verb that raised it is refused.
///
/// Long enough to read the question and type a name; short enough that a desk
/// left with a question up is not holding a guest's call — and, while it does,
/// the app stack's input, since the call is serviced inside the click that made
/// it — for the rest of the day.
const PROMPT_WAIT: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// **A question only the platform asks, put to the person on the compositor's
/// prompt layer** — over the whole desk, dimmed, which no guest can produce.
///
/// A trait over [`crate::surface_proxy::SurfaceProxy::ask`] so that the door's
/// rule — [`dropped_once_typed_back`] — can be held by a test with no compositor.
/// `Err` is *there is no desk to ask on*; `Ok(None)` is *asked, and not answered*.
#[async_trait::async_trait]
pub trait AsksTheDesk: Send + Sync {
    async fn ask(&self, prompt: kotton_wire::PlatformPrompt) -> Result<Option<String>, String>;
}

#[async_trait::async_trait]
impl AsksTheDesk for crate::surface_proxy::SurfaceProxy {
    async fn ask(&self, prompt: kotton_wire::PlatformPrompt) -> Result<Option<String>, String> {
        crate::surface_proxy::SurfaceProxy::ask(self, prompt, PROMPT_WAIT).await
    }
}

/// **The drop's door: the pool's name typed back on the platform's own prompt,
/// then the drop — and nothing unless it was.** The platform's prompts are a
/// compositor layer over a dimmed desk.
///
/// The shell sends the verb and draws no confirmation; this is where the verb
/// learns it needs a typed name, and the compositor is what asks for it and
/// carries it back. The comparison is the terminal's (`vault drop <v> <name>
/// --confirm <name>`): exact, so *Sam* is not *sam*, and an empty pool is
/// never dropped by typing nothing.
///
/// **A guard this host holds now**, which it could not while the shell drew the
/// sheet: a name the shell typed back was the asking guest vouching for itself.
/// The name comes from the desk, which the guest cannot reach — so there is no
/// check here on *who* is asking, because the asker is not the one who answers.
///
/// **Nothing is asked until the question is a real one.** `kept` is the vault's own answer — under this desktop's operator credential
/// for it — to *do you keep `pool`?*, and it runs first: a vault this person holds no
/// credential for is refused by `operator::speak` in words, and a pool the vault does not
/// keep is refused here, both before the desk is touched. So the guest verb that leads here
/// can raise the platform's dim only for a drop the platform itself would perform — a vault
/// the person runs, a person that vault keeps — and never with a vault or a name of its own
/// invention. That is the reach the platform's prompt needs: the dim is the daemon's
/// question about facts the daemon checked, not something a guest can say.
///
/// `drop` runs only after a whole answer, and its own refusal is the verb's.
pub(crate) async fn dropped_once_typed_back<K, KFut, F, Fut>(
    desk: &dyn AsksTheDesk,
    vault: &str,
    pool: &str,
    kept: K,
    drop: F,
) -> Result<(), String>
where
    K: FnOnce() -> KFut,
    KFut: std::future::Future<Output = Result<bool, String>>,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    if pool.is_empty() || !kept().await? {
        return Err(format!("{vault} keeps no pool named {pool} — nothing to drop"));
    }
    let asked = kotton_wire::PlatformPrompt::DropTenant {
        vault: vault.to_owned(),
        pool: pool.to_owned(),
    };
    match desk.ask(asked).await? {
        Some(typed) if !pool.is_empty() && typed == pool => drop().await,
        Some(_) => Err(format!(
            "{pool} was not dropped from {vault}: the name typed back was not {pool}"
        )),
        None => Err(format!("{pool} was not dropped from {vault}: not confirmed")),
    }
}

/// **An operator's removal: their name typed back on the platform's own prompt,
/// then the removal — and nothing unless it was.** This device's operators
/// speak to `kdeviced` under the person's own key.
///
/// The drop's door ([`dropped_once_typed_back`]) with a person's name: exact, so
/// *ana* is not *Ana*, and an empty name is never confirmed by typing nothing.
/// The caller asks only once it has checked the question is a real one — the
/// person is one of this machine's operators, and not its last — so a guest's
/// verb dims the desk only for a removal the platform itself would perform.
pub(crate) async fn stepped_down_once_typed_back<F, Fut>(
    desk: &dyn AsksTheDesk,
    name: &str,
    step_down: F,
) -> Result<(), String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    if name.is_empty() {
        return Err("an operator with no name cannot be confirmed by typing it".to_owned());
    }
    let asked = kotton_wire::PlatformPrompt::RemoveOperator { name: name.to_owned() };
    match desk.ask(asked).await? {
        Some(typed) if typed == name => step_down().await,
        Some(_) => Err(format!("{name} is still an operator: the name typed back was not {name}")),
        None => Err(format!("{name} is still an operator: not confirmed")),
    }
}

pub struct DaemonOccupantHost<'a> {
    pub runtime: &'a DeviceRuntime,
    pub users: &'a UserRegistry,
    pub sessions: &'a SessionMap,
    pub base: &'a Path,
    /// The per-user database handles, so a created identity can be handed its apps.
    /// Carried rather than reopened, for the same reason `db` is.
    pub user_dbs: &'a crate::db::user_db::UserDbMap,
    /// The live per-account event-log tasks, because an unlock at this door
    /// starts the account's log again (`custody_window::rekey_resident_store`).
    pub event_log_tasks: &'a crate::event_log::EventLogTasks,
    /// The long-lived ceremony registry.
    ///
    /// Not built from this host's borrows: a ceremony outlives the call that
    /// starts it, and this struct is a bundle of borrows dropped at the end of
    /// one. See `agent::ceremony`.
    pub ceremonies: &'a super::ceremony::Ceremonies,
    /// The machine database, where the paired-node roster lives.
    ///
    /// Carried rather than reopened: a second pool over the same file is a
    /// second writer, and the roster is the one thing a revoke must not race.
    pub db: &'a Arc<SqlitePool>,
    /// The per-user record stores, because messaging needs the same host the
    /// IPC arms build (`msg_host`) — the surface and the CLI must not disagree
    /// about what a send does.
    pub record_stores: &'a crate::residency::RecordStores,
    /// **Who this host let in, if anyone** — the one thing a caller must learn
    /// from an exchange rather than from the world afterwards.
    ///
    /// The ceremony's trigger is a registry that answered nobody before an
    /// input event and somebody after; the daemon can read that from its own
    /// record of who exists. An unlock changes no such record: the person was
    /// registered and loaded before they typed, and loaded is not unlocked.
    /// The only new fact is that *this* call opened a session for
    /// *that* user, and it exists for the length of this call.
    ///
    /// So it is written here, where the session is opened, and read by the
    /// caller that built this host once the exchange it lent it to has
    /// returned — `DeviceDaemon::compositor_input`. It is **not** the session
    /// map: a process-scoped sidecar token names its user too
    /// (`mint_gateway_bootstrap_token`), so *somebody holds a token for this
    /// user* is not *this person just came in at this screen*.
    ///
    /// Private, and scoped to one host: this struct is a bundle of borrows
    /// built per call (`occupant_host`), so nothing here outlives the exchange
    /// that produced it and no second caller can read another's answer.
    unlocked: std::sync::Mutex<Option<String>>,
    /// The **read-only** projection of this machine's own configuration, and
    /// deliberately not the pool behind it (`interface network`).
    ///
    /// `interface devices` says why `set-device-name` is absent: the key is in
    /// `system/device.db`, which is kdeviced's file, and handing this
    /// guest-facing host that pool is the twenty-line fix and the wrong one.
    /// Read is not write, so the readout arrives as a thing with two questions
    /// and no setters — see [`crate::agent::network_readout::MachineReadout`].
    machine: super::network_readout::MachineReadout,
    /// **The desk, for the questions only the platform asks** —
    /// the compositor's prompt layer, reached on the pair `kuid` already holds.
    /// Borrowed as the trait so a door's rule can be tested with no compositor.
    desk: &'a dyn AsksTheDesk,
    /// **The browser admissions, as the one verb that ends one** — not the
    /// principal-session map or the channel registry behind it. The screen
    /// revokes a browser through [`super::browser_channel::revoke`], the function
    /// `BrowserDeviceRevoke` calls, and this is the whole of what it is handed
    /// to do that: a host that held the maps could read every browser's live
    /// token to answer a verb that needs none of them.
    browsers: super::browser_channel::BrowserAdmissions,
}

impl DaemonOccupantHost<'_> {
    /// The single identity on this device, if there is exactly one.
    ///
    /// `unlock(passphrase)` names no user, so one has to be resolved. With one
    /// identity that is unambiguous and is the case first run produces. With
    /// several it is not, and guessing would unlock *an* identity rather than
    /// the one the person meant — so it refuses, and the surface must use
    /// `unlock-with-pin`, which names its user.
    fn the_only_user(&self) -> Result<String, RunnerAuthError> {
        let mut ids: Vec<String> = device_users::load(self.base)
            .unwrap_or_default()
            .keys()
            .cloned()
            .collect();
        match ids.len() {
            0 => Err(RunnerAuthError::NoIdentity),
            1 => Ok(ids.remove(0)),
            // Typed rather than a `Daemon` message. A surface that wants to
            // offer a picker was matching on the prose this used to carry,
            // which is what a spelled-out error enum exists to make
            // unnecessary. The count is not on the variant because no caller
            // has a use for it: the answer is "ask which one" whether it is
            // two or five.
            _ => Err(RunnerAuthError::SeveralIdentities),
        }
    }

    /// Verify a credential and open a session, restoring the operational roots
    /// from the vault if this is a cold start.
    ///
    /// The same two steps the `UnlockWithPin` request arm performs, for the
    /// same reason: `try_unlock_with_pin` decides whether the credential opens
    /// a session (it reads the hash), and the vault is what a successful unlock
    /// then uses to restore the roots.
    async fn open_session(
        &self,
        user_id: &str,
        credential: &str,
    ) -> Result<String, RunnerAuthError> {
        let token =
            match lock_policy::try_unlock_with_pin(self.base, user_id, credential, self.sessions) {
                Ok(lock_policy::PinAttempt::Unlocked(token)) => token,
                Ok(lock_policy::PinAttempt::Wrong { .. }) => {
                    return Err(RunnerAuthError::WrongPassphrase)
                }
                Ok(lock_policy::PinAttempt::RateLimited { retry_after_secs }) => {
                    return Err(RunnerAuthError::Daemon {
                        message: format!(
                            "too many attempts — try again in {retry_after_secs} seconds"
                        ),
                    })
                }
                Err(e) => {
                    return Err(RunnerAuthError::Daemon {
                        message: format!("{e}"),
                    })
                }
            };

        // The roots back from the vault when the store does not hold them — the
        // one check both doors make (`custody_window::restore_roots_if_absent`).
        // A store that could not say whether it holds them, or a sealed copy
        // that does not open under the passphrase the record accepted, refuses
        // the unlock, and the session just opened is closed again: nothing past
        // here can read a key the store cannot.
        if let Err(e) = super::custody_window::restore_roots_if_absent(self.runtime, user_id, credential).await {
            self.sessions.write().unwrap().remove(&token);
            return Err(RunnerAuthError::Daemon { message: e.to_string() });
        }
        // **And the resident store is rebuilt with the key the unlock restored.**
        // The IPC arm does this, and so must this door: the daemon loaded this
        // person keyless at boot, the passphrase was right, the relaunch that
        // follows is for a named person, and without the rebuild it lands on a
        // desk over a store that refuses every read — no roots, and a
        // Networking notice saying the node holds no key. One function for both
        // doors, so neither can be fixed alone.
        super::custody_window::rekey_resident_store(
            self.runtime,
            self.users,
            self.user_dbs,
            self.event_log_tasks,
            self.base,
            user_id,
        )
        .await;
        // The credential opened a session for this user, which is the whole of
        // what [`Self::unlocked_as`] reports. Recorded here rather than in each
        // verb because both doors — `unlock`, which resolves the one registered
        // user, and `unlock-with-pin`, which is handed one — are the same act:
        // the person at this screen typed their credential and it was right.
        if let Ok(mut unlocked) = self.unlocked.lock() {
            *unlocked = Some(user_id.to_string());
        }
        // **This person's own operator key, made known to this machine.**
        // Minted into their sealed store if they have none, and proved to
        // `kdeviced`, which keeps it as theirs and grants it nothing — so that an
        // operator can make them one by naming them, never a key. Off the unlock's
        // path: a machine with no `kdeviced` running (a desktop nobody supervises)
        // costs a line in the log, never the unlock.
        //
        // **Only a daemon that was told its supervisor does this unasked.** One
        // `kdeviced` spawned (a principal) or one handed a `kdeviced` socket knows
        // there is a machine to speak to; a daemon told neither — a desktop nobody
        // supervises, a test harness — would be reaching for the machine's default
        // socket on its own, and on a machine whose `kdeviced` runs with nobody
        // enrolled its key would become the first operator. Such a daemon speaks
        // to `kdeviced` only when the person opens *This device* and asks.
        let supervised = self.runtime.config().principal.is_some() || self.runtime.config().kdeviced.is_some();
        let known = device_users::load(self.base)
            .ok()
            .and_then(|u| u.get(user_id).map(|r| r.did.clone()))
            .filter(|_| supervised);
        if let (Some(store), Some(did), Ok(at)) = (self.users.get(user_id), known, self.kdeviced()) {
            tokio::spawn(async move {
                if let Err(e) = device_operator::keep(&at, &store, &did).await {
                    tracing::debug!(error = %e, "this person's own operator key is not yet known to kdeviced");
                }
            });
        }
        Ok(token)
    }

    /// Whom this host let in during the call it was built for, if anyone.
    ///
    /// `None` is the answer for every exchange that did not open a session,
    /// including one whose credential was wrong — `open_session` writes only on
    /// the path that returns a token.
    pub fn unlocked_as(&self) -> Option<String> {
        self.unlocked.lock().ok().and_then(|u| u.clone())
    }
}

#[async_trait::async_trait]
impl OccupantHost for DaemonOccupantHost<'_> {
    async fn list_devices(&self) -> Result<Vec<RunnerPairedDevice>, String> {
        let user_id = self.the_only_user().map_err(|e| format!("{e:?}"))?;
        // The same call the `NodeList` IPC arm makes, so the surface and the CLI
        // cannot disagree about what is paired.
        let nodes = match kotton_peer::daemon::nodes::node_list(self.db, user_id.clone())
            .await
            .map_err(|e| format!("reading the device roster: {e}"))?
        {
            UserResponse::NodeList { nodes } => nodes,
            other => return Err(format!("unexpected reply reading devices: {other:?}")),
        };

        // This device's own DID, so the surface can mark the row the person is
        // holding. Resolved here because the guest has no other way to
        // recognise it, and offering to revoke your own device without saying
        // so is the kind of surprise Article IV exists to prevent.
        //
        // The operational key's DID: it is what the ceremony recorded on the
        // other device, so it is the string a row in `nodes` can equal.
        let this_did = self.runtime.operational_did();

        // The name comes from the membership record, which is the only store
        // holding one a person chose. Not from `paired_nodes.id`, which four
        // write paths fill with a UUID, a DID or a label depending on which one
        // ran — so the surface would show a person their laptop's UUID under the
        // heading "Your devices". A row with no
        // label reports `None` and the surface says so, rather than the roster
        // dressing an internal identifier up as a name.
        let user_rt = self
            .users
            .get(&user_id)
            .ok_or_else(|| format!("user runtime '{user_id}' is not loaded"))?;

        let mut devices = Vec::with_capacity(nodes.len());
        for n in nodes {
            let did = n.device_did.to_string();
            // Best-effort: a member record that cannot be read costs the row its
            // name, never the row. A roster that hides a device because its
            // label is unreadable is the failure mode Article IV is about.
            let member = user_rt.read_member(&did).await.ok().flatten();
            // Whether it opens the person's files is the member record's
            // posture and nothing else: a vault, a cosigner and the gateway are
            // paired, so they are rows here, and none of them holds a root a
            // person reads. The share sheet lists only the rows this is true
            // of: *a device of your own*. A record that cannot
            // be read, or names no posture, answers `false` — the side that
            // offers nothing.
            let opens_your_files = member.as_ref().is_some_and(|m| {
                m.role == kotton_schemas::membership::Role::OwnDevice
                    && m.posture == Some(kotton_schemas::membership::Posture::Full)
            });
            devices.push(RunnerPairedDevice {
                is_this_device: did == this_did,
                name: member.and_then(|m| m.label),
                did,
                paired_at: n.paired_at,
                opens_your_files,
            });
        }
        Ok(devices)
    }

    /// The relay this device is paired with (`interface network`).
    ///
    /// Read from [`kotton_peer::reachability::Reachability`] rather than from
    /// `device_config`, and that is the better source rather than a way around
    /// the pool: `nat()` is the config the dial side actually uses, so a
    /// runtime `relay set` is already in it, and `relay_readout()` is what the
    /// reservation listener knows — a live control socket on the relay, which
    /// is the only thing that can honestly answer *did it answer*.
    async fn paired_relay(&self) -> Result<Option<RunnerRelay>, String> {
        let relay_url = self.runtime.reachability().nat().relay_url;
        if relay_url.trim().is_empty() {
            return Ok(None);
        }
        let user_id = self.user()?;
        let nodes = self.paired_nodes(&user_id).await?;
        let handles = self.enrolled_handles(&user_id).await?;
        Ok(super::network_readout::relay_row(
            &relay_url,
            self.runtime.reachability().relay_readout(),
            &nodes,
            &handles,
        ))
    }

    /// Every vault this person has enrolled.
    ///
    /// The vault **set** is [`admitted_vaults`] — the membership set's blind
    /// own devices, which is what admission writes and revocation removes —
    /// and not a root's targets: a root's `target` carries
    /// a handle and a label and nothing else, a vault targeted by three roots
    /// would appear three times, and a vault enrolled and targeted by nothing
    /// would not appear at all. The roots are read anyway — they are what says
    /// *what it holds*.
    ///
    /// Not the person's `RemoteBackend::Kotton` remotes, which nothing in
    /// admission writes: a vault admitted a second ago would not be there.
    async fn enrolled_vaults(&self) -> Result<Vec<RunnerVault>, String> {
        let user_id = self.user()?;
        let store = self
            .users
            .get(&user_id)
            .ok_or_else(|| format!("user runtime '{user_id}' is not loaded"))?;
        let enrolled = admitted_vaults(&store).await?;
        let nodes = self.paired_nodes(&user_id).await?;
        // A roots index that will not open costs the rows their *holds*, never
        // the rows: a vault the person enrolled is a fact about their network
        // whether or not this device can name what is kept there today.
        let roots =
            super::app_host::user_runner_roots(self.users, self.base, &user_id).unwrap_or_default();
        // The vaults and relays this person operates. A credential that will
        // not open costs the rows their *yours*, never the rows.
        let held = super::operator::held(&store)
            .inspect_err(|e| tracing::warn!(error = %e, "the operator credentials kept here do not open"))
            .unwrap_or_default();
        let mut operated = Vec::new();
        let mut relays = Vec::new();
        for c in held {
            match c.operates {
                kotton_peer::operator::Operates::Vault { vault, .. } => {
                    // Where it stands is what this desktop told it, first relay first.
                    let told = super::operator::stands_of(&store, &vault);
                    let told_at = told.as_ref().map(|t| t.told_at);
                    let stood = told.and_then(|t| t.relays.into_iter().next());
                    operated.push(super::network_readout::Operated {
                        vault,
                        name: c.name,
                        relay_key: stood.as_ref().and_then(|r| kotton_peer::relay_keys::relay_id(Some(&r.key))),
                        relay: stood.map(|r| r.hint),
                        told_at,
                    })
                }
                kotton_peer::operator::Operates::Relay { key, .. } => {
                    relays.push(super::network_readout::OperatedRelay { name: c.name, key })
                }
            }
        }
        Ok(super::network_readout::vault_rows(
            &enrolled,
            &nodes,
            &roots,
            &|did| self.machine.is_connected(did),
            &operated,
            &relays,
        ))
    }

    /// Every relay this person runs, as its card reads it: read
    /// from their sealed credentials and this desktop's dated *stands-at*
    /// record, and this device's own relay by the key it recorded. Nothing is
    /// dialled.
    async fn operated_relays(&self) -> Result<Vec<kotton_wire::runner::RunnerOperatedRelay>, String> {
        let user_id = self.user()?;
        let store = self
            .users
            .get(&user_id)
            .ok_or_else(|| format!("user runtime '{user_id}' is not loaded"))?;
        let held = super::operator::held(&store).map_err(|e| format!("your operator keys here do not open: {e:#}"))?;
        let stands = super::operator::stands(&store).unwrap_or_default();
        let mut relays = Vec::new();
        let mut vaults = Vec::new();
        for c in held {
            match c.operates {
                kotton_peer::operator::Operates::Relay { url, key, .. } => relays.push((c.name, key, url)),
                kotton_peer::operator::Operates::Vault { vault, .. } => vaults.push(super::network_readout::Operated {
                    vault,
                    name: c.name,
                    relay: None,
                    relay_key: None,
                    told_at: None,
                }),
            }
        }
        let told = |v: &[u8; 32]| -> Vec<[u8; 32]> {
            let want = hex::encode(v);
            stands
                .iter()
                .filter(|s| s.vault == want)
                .flat_map(|s| s.relays.iter().filter_map(|r| kotton_peer::relay_keys::relay_id(Some(&r.key))))
                .collect()
        };
        let device = self.machine.device_name().await;
        let own = kotton_peer::relay_keys::relay_id(self.runtime.reachability().nat().relay_key.as_deref());
        Ok(super::network_readout::operated_relay_rows(
            &relays,
            &vaults,
            &told,
            own.map(|k| (device.as_str(), k)),
        ))
    }

    /// This device's own name and local reachability.
    async fn this_device(&self) -> Result<RunnerThisDevice, String> {
        Ok(RunnerThisDevice {
            name: self.machine.device_name().await,
            local_reach: super::network_readout::local_reach(
                self.runtime.reachability().peer_listen_addr(),
            ),
        })
    }

    /// Admit an invite under the blind posture — an invite pasted at the door.
    async fn join_admit(&self, invite: String) -> Result<(), String> {
        let user_id = self.user()?;
        self.ceremonies.admit(user_id, invite).await
    }

    async fn join_confirm(&self, typed: String) -> Result<(), String> {
        let user_id = self.user()?;
        self.ceremonies.join_confirm(&user_id, &typed).await
    }

    async fn join_cancel(&self) -> Result<(), String> {
        let user_id = self.user()?;
        self.ceremonies.join_cancel(&user_id).await;
        Ok(())
    }

    async fn join_take_relay(&self) -> Result<(), String> {
        let user_id = self.user()?;
        self.ceremonies.take_relay(&user_id).await
    }

    /// Who the vault keeps for (`interface landlord`), under the operator
    /// credential this person keeps for it — `vault people <v>`.
    ///
    /// The guest names the vault and nothing else; the credential is found
    /// here, in the person's own sealed object, and a vault they hold none for
    /// is refused in words by `operator::speak` before anything is dialled.
    async fn landlord_people(&self, vault: String) -> Result<Vec<RunnerTenant>, String> {
        let user_id = self.user()?;
        tenants_answered(
            super::operator::speak(self.runtime, self.users, self.record_stores, &user_id, &vault, OperatorVerb::Pools)
                .await,
        )
    }

    /// Mint `name`'s invite, then set their space aside —
    /// `vault invite <v> <name> --space <bytes>`, the invite first, so one the
    /// vault refuses sets nothing (`operator::requests_for`).
    ///
    /// The window is a day, as `vault invite` and `kvaultd invite` wait by
    /// default, and not the guest's to name: an invite is a door left open,
    /// and how long is the landlord's terminal's decision, not the shell's.
    async fn landlord_invite(
        &self,
        vault: String,
        name: String,
        space_bytes: u64,
    ) -> Result<String, String> {
        let user_id = self.user()?;
        let verb = OperatorVerb::Invite {
            pool: name,
            quota: Some(space_bytes),
            ttl_seconds: LANDLORD_INVITE_TTL_SECS,
        };
        invite_answered(super::operator::speak(self.runtime, self.users, self.record_stores, &user_id, &vault, verb).await)
    }

    /// Drop one person's pool — `vault drop <v> <name>`, once the person has
    /// typed the name back on the platform's own prompt
    /// ([`dropped_once_typed_back`]). The shell asks for nothing and draws
    /// nothing; see `interface landlord`.
    ///
    /// Who is asking is read first: a caller with no person behind it is refused
    /// before a question is put to the desk on nobody's behalf.
    async fn landlord_drop(&self, vault: String, name: String) -> Result<(), String> {
        let user_id = self.user()?;
        let kept = || async {
            Ok(self.landlord_people(vault.clone()).await?.iter().any(|t| t.name == name))
        };
        dropped_once_typed_back(self.desk, &vault, &name, kept, || async {
            dropped_answered(
                super::operator::speak(
                    self.runtime,
                    self.users,
                    self.record_stores,
                    &user_id,
                    &vault,
                    OperatorVerb::Drop { pool: name.clone() },
                )
                .await,
            )
        })
        .await
    }

    /// Who may use the relay — `OperatorVerb::ReadRule`, asked of the relay
    /// under the credential this person keeps for it.
    async fn landlord_rule(&self, relay: String) -> Result<kotton_wire::rendezvous::AdmissionRule, String> {
        let user_id = self.user()?;
        rule_answered(
            super::operator::speak(self.runtime, self.users, self.record_stores, &user_id, &relay, OperatorVerb::ReadRule)
                .await,
        )
    }

    /// Set who may use the relay — `OperatorVerb::SetRule`. The keys it
    /// takes are minted, kept and handed on in `operator::set_rule`; the guest
    /// named a rule, and is answered with the rule the relay then holds.
    async fn landlord_set_rule(
        &self,
        relay: String,
        rule: kotton_wire::rendezvous::AdmissionRule,
    ) -> Result<kotton_wire::rendezvous::AdmissionRule, String> {
        let user_id = self.user()?;
        rule_answered(
            super::operator::speak(self.runtime, self.users, self.record_stores, &user_id, &relay, OperatorVerb::SetRule { rule })
                .await,
        )
    }

    /// Settings' one door: what a pasted code names, before anything is
    /// written (`agent::door::resolve`). The code is not logged.
    async fn landlord_resolve(&self, code: String) -> Result<kotton_wire::runner::RunnerResolved, String> {
        let user_id = self.user()?;
        let store = self.users.get(&user_id).ok_or_else(|| format!("user runtime '{user_id}' is not loaded"))?;
        let kept = super::operator::held(&store).map_err(|e| format!("Your operator keys here do not open: {e:#}"))?;
        let minted = super::operator::minted(&store).map_err(|e| format!("The keys minted here do not open: {e:#}"))?;
        super::door::resolve(&kept, &minted, &code)
    }

    /// Paste a vault's or a relay's line — the terminal's `enrol`, its own
    /// completion, told no name: it finds the key the line
    /// completes as the resolve did. Nothing here reads more of the code than
    /// that it is a line.
    async fn landlord_enrol(&self, code: String) -> Result<kotton_wire::runner::RunnerEnrolled, String> {
        let user_id = self.user()?;
        let line = super::door::line_of(&code)?;
        super::door::enrolled(
            super::operator::complete(self.runtime, self.users, self.record_stores, &user_id, &line).await,
        )
    }

    /// The vault's *Move…*, and the answer to the desktop asking where a
    /// vault stands — `vault move <v> <r>` (`OperatorVerb::Move`).
    async fn landlord_move_vault(&self, vault: String, relay: String) -> Result<(), String> {
        let user_id = self.user()?;
        moved_answered(
            super::operator::speak(self.runtime, self.users, self.record_stores, &user_id, &vault, OperatorVerb::Move { relay })
                .await,
        )
    }

    /// *This device › Operators*: whether the person at this desk operates this
    /// machine and, when they do, who does and who else has an account here —
    /// read from `kdeviced` under the person's own key, which is minted into
    /// their sealed store the first time it is wanted (`device_operator`).
    ///
    /// Only an operator reads who operates the machine; anyone else is told
    /// they are not one, and nothing more.
    async fn operators(&self) -> Result<RunnerOperatorBox, String> {
        let me = self.operator_person()?;
        let store = self.store_of(&me.user_id)?;
        let accounts = self.accounts();
        let Some((own, rows)) = device_operator::read(&self.kdeviced()?, &store, &me.did).await? else {
            return Ok(RunnerOperatorBox { operates: false, operators: Vec::new(), others: Vec::new() });
        };
        // One row per person, oldest first. A key that answers for nobody (a
        // first-run key never bound) is a key, not a person, and is not drawn.
        let mut operators: Vec<RunnerOperator> = Vec::new();
        let mut seen: Vec<&str> = Vec::new();
        for row in &rows {
            let Some(person) = &row.person else { continue };
            if seen.contains(&person.as_str()) {
                continue;
            }
            seen.push(person);
            let (handle, name) = accounts.by_did(person);
            operators.push(RunnerOperator {
                person: handle,
                name,
                you: *person == me.did || row.did == own,
            });
        }
        let operating: Vec<&str> = rows.iter().filter_map(|r| r.person.as_deref()).collect();
        let others = accounts
            .people
            .iter()
            .filter(|p| !operating.contains(&p.did.as_str()))
            .map(|p| RunnerPerson { person: p.user_id.clone(), name: p.name.clone() })
            .collect();
        Ok(RunnerOperatorBox { operates: true, operators, others })
    }

    /// *Make Ana an operator* — by Ana, never by a key: `kdeviced` binds the key
    /// Ana's own daemon proved and kept for her, and keeps the act under this
    /// person's key.
    async fn operator_add(&self, person: String) -> Result<(), String> {
        let me = self.operator_person()?;
        let store = self.store_of(&me.user_id)?;
        let accounts = self.accounts();
        let other = accounts.person(&person)?;
        device_operator::make_operator(&self.kdeviced()?, &store, &me.did, &other.did).await
    }

    /// Step `person` down — once their name has been typed back on the
    /// platform's own prompt ([`stepped_down_once_typed_back`]).
    ///
    /// **Nothing is asked until the question is a real one**, as the drop's
    /// door: the person asking must operate this machine, the person named must
    /// be one of its operators, and not its last. Each is read from `kdeviced`
    /// first, so a guest's verb raises the platform's dim only over a removal
    /// the platform would perform — and `kdeviced` refuses the last again on
    /// its own side, in the one `DELETE`, whatever was read here.
    async fn operator_remove(&self, person: String) -> Result<(), String> {
        let me = self.operator_person()?;
        let store = self.store_of(&me.user_id)?;
        let accounts = self.accounts();
        let other = accounts.person(&person)?;
        let at = self.kdeviced()?;
        let Some((_, rows)) = device_operator::read(&at, &store, &me.did).await? else {
            return Err("you are not one of this PC's operators".to_owned());
        };
        let mut people: Vec<&str> = rows.iter().filter_map(|r| r.person.as_deref()).collect();
        people.sort_unstable();
        people.dedup();
        if !people.contains(&other.did.as_str()) {
            return Err(format!("{} is not one of this PC's operators", other.name));
        }
        if people.len() < 2 {
            return Err(format!(
                "{} is this PC's last operator, and the last is never removed — add another operator first",
                other.name
            ));
        }
        stepped_down_once_typed_back(self.desk, &other.name, || {
            device_operator::step_down(&at, &store, &me.did, &other.did)
        })
        .await
    }

    async fn pair_start(&self, label: Option<String>, ttl_seconds: u64) -> Result<(), String> {
        let user_id = self.user()?;
        self.ceremonies
            .start(user_id, super::ceremony::Side::Start { label, ttl_seconds })
            .await
    }

    async fn pair_join(&self, code: String, label: Option<String>) -> Result<(), String> {
        let user_id = self.user()?;
        self.ceremonies
            .start(user_id, super::ceremony::Side::Join { code, label })
            .await
    }

    async fn pair_confirm(&self, matched: bool) -> Result<(), String> {
        let user_id = self.user()?;
        self.ceremonies.confirm(&user_id, matched).await
    }

    async fn pair_cancel(&self) -> Result<(), String> {
        let user_id = self.user()?;
        self.ceremonies.cancel(&user_id).await;
        Ok(())
    }

    async fn list_contacts(&self) -> Result<Vec<RunnerContact>, String> {
        let user_id = self.user()?;
        // The same `list_contacts` the `ContactList` IPC arm calls, through the
        // same user runtime — so the shell, the phone and the CLI cannot
        // disagree about who a person knows. It is a *view* over membership
        // records filtered to `Role::Contact`, which is why there is no store
        // here to keep in step with anything.
        let user_rt = self
            .users
            .get(&user_id)
            .ok_or_else(|| format!("user runtime '{user_id}' is not loaded"))?;
        use kotton_peer::membership::Membership as _;
        let contacts = user_rt
            .list_contacts()
            .await
            .map_err(|e| format!("reading the contact list: {e}"))?;
        Ok(contacts
            .into_iter()
            .map(|(did, label)| RunnerContact { did, label })
            .collect())
    }

    async fn message_send(
        &self,
        to_did: &str,
        body: &str,
    ) -> Result<(String, Option<String>), String> {
        let user = self.user()?;
        let resp = kotton_msg::daemon::messages::message_send(
            &self.msg(),
            user,
            to_did.to_string(),
            body.to_string(),
            None,
        )
        .await
        .map_err(|e| format!("sending: {e}"))?;
        match resp {
            UserResponse::MessageSent {
                message_id,
                delivery,
            } => Ok((
                message_id,
                // The one word, as a word. `Delivery` is the wire's enum and
                // the guest is owed the vocabulary rather than the type. The
                // mapping lives on the enum (`Delivery::word`, pinned there)
                // rather than here, so the four delivery words have one copy
                // and the CLI reads the same one.
                delivery.map(|d| d.word().to_string()),
            )),
            UserResponse::Error { message } => Err(message),
            other => Err(format!("messages.send: unexpected reply {other:?}")),
        }
    }

    /// `kotton_msg`'s `message_share`, answered as [`Self::message_send`] is:
    /// the record id and the one word. Whom it may go to is a
    /// message's answer, unchanged: the domain resolves the recipient's key
    /// from membership, as `message_send` does.
    async fn message_share(
        &self,
        to_did: &str,
        name: &str,
        data: &[u8],
        origin: Option<&str>,
    ) -> Result<(String, Option<String>), String> {
        let user = self.user()?;
        let resp = kotton_msg::daemon::messages::message_share(
            &self.msg(),
            user,
            to_did.to_string(),
            name.to_string(),
            data.to_vec(),
            origin.map(str::to_string),
            None,
        )
        .await
        .map_err(|e| format!("sharing: {e}"))?;
        match resp {
            UserResponse::MessageSent { message_id, delivery } => {
                Ok((message_id, delivery.map(|d| d.word().to_string())))
            }
            UserResponse::Error { message } => Err(message),
            other => Err(format!("messages.share: unexpected reply {other:?}")),
        }
    }

    async fn message_channel_send(&self, channel_did: &str, body: &str) -> Result<String, String> {
        let user = self.user()?;
        let resp = kotton_msg::daemon::messages::message_channel_send(
            &self.msg(),
            user,
            channel_did.to_string(),
            body.to_string(),
        )
        .await
        .map_err(|e| format!("sending to the channel: {e}"))?;
        match resp {
            // The occupant is handed the message id and not the fan-out. Where
            // each member's copy went is a readout of who in a group had
            // something awake, and a confined app has no business holding one —
            // that is refused even to the person's own surfaces for a
            // direct message's *route*, and this is the same fact about N people
            // at once. The person's own client gets it; a guest does not.
            UserResponse::ChannelSent { message_id, .. } => Ok(message_id),
            UserResponse::Error { message } => Err(message),
            other => Err(format!("messages.channel-send: unexpected reply {other:?}")),
        }
    }

    /// `kotton_msg`'s `message_channel_share`, answered as
    /// [`Self::message_channel_send`] is: the record id, and not the fan-out,
    /// for the reason given there. Who it reaches is the channel's current
    /// membership as this person's own newest grant reads it.
    async fn message_channel_share(
        &self,
        channel_did: &str,
        name: &str,
        data: &[u8],
        origin: Option<&str>,
    ) -> Result<String, String> {
        let user = self.user()?;
        let resp = kotton_msg::daemon::messages::message_channel_share(
            &self.msg(),
            user,
            channel_did.to_string(),
            name.to_string(),
            data.to_vec(),
            origin.map(str::to_string),
        )
        .await
        .map_err(|e| format!("sharing with the group: {e}"))?;
        match resp {
            UserResponse::ChannelSent { message_id, .. } => Ok(message_id),
            UserResponse::Error { message } => Err(message),
            other => Err(format!("messages.channel-share: unexpected reply {other:?}")),
        }
    }

    /// `kotton_msg`'s `message_groups`: the channels this person holds a key
    /// for, by DID and count, from their own grants.
    async fn message_groups(&self) -> Result<Vec<kotton_wire::runner::RunnerGroup>, String> {
        let user = self.user()?;
        let groups = kotton_msg::daemon::messages::message_groups(&self.msg(), &user).await?;
        Ok(groups
            .into_iter()
            .map(|g| kotton_wire::runner::RunnerGroup {
                channel_did: g.channel_did,
                members: u32::try_from(g.members).unwrap_or(u32::MAX),
            })
            .collect())
    }

    async fn message_channel_history(
        &self,
        channel_did: &str,
        before_id: Option<String>,
        limit: u32,
    ) -> Result<Vec<RunnerSealedMessage>, String> {
        let user = self.user()?;
        let resp = kotton_msg::daemon::messages::message_channel_history(
            &self.msg(),
            user,
            channel_did.to_string(),
            before_id,
            limit,
        )
        .await
        .map_err(|e| format!("reading the channel: {e}"))?;
        message_list(resp, "channel-history")
    }

    async fn message_poll_inbox(&self) -> Result<Vec<RunnerSealedMessage>, String> {
        let user = self.user()?;
        let resp = kotton_msg::daemon::messages::message_poll_inbox(&self.msg(), user)
            .await
            .map_err(|e| format!("reading the inbox: {e}"))?;
        message_list(resp, "poll-inbox")
    }

    /// The same join the `MessageUnreadCount` IPC arm makes, through the same
    /// two halves — so the shell, the phone and the CLI cannot disagree about
    /// how many messages are waiting.
    async fn message_unread_count(&self) -> Result<u64, String> {
        let user = self.user()?;
        let marks = super::read_mark_host::read_marks(self.users, &user)?;
        let resp = kotton_msg::daemon::messages::message_poll_inbox(&self.msg(), user)
            .await
            .map_err(|e| format!("reading the inbox: {e}"))?;
        let inbox = match resp {
            UserResponse::MessageHistory { messages } => messages,
            UserResponse::Error { message } => return Err(message),
            other => return Err(format!("messages.unread-count: unexpected reply {other:?}")),
        };
        kotton_msg::read_marks::unread_count(&marks, &inbox)
            .await
            .map_err(|e| format!("counting what is unread: {e}"))
    }

    /// The conversation window's read, through the same verb a browser's
    /// conversation would use, so the two cannot draw different halves.
    async fn message_conversation(&self, peer_did: &str) -> Result<Vec<RunnerSealedMessage>, String> {
        let user = self.user()?;
        let resp = kotton_msg::daemon::messages::message_conversation(
            &self.msg(),
            user,
            peer_did.to_string(),
        )
        .await
        .map_err(|e| format!("reading the conversation: {e}"))?;
        message_list(resp, "conversation")
    }

    /// The readings `MessageDeliveries` answers a browser with — one function
    /// behind both, so the shell and the phone say the same word.
    async fn message_deliveries(
        &self,
        peer_did: &str,
    ) -> Result<Vec<kotton_wire::ipc::DeliveryReading>, String> {
        let user = self.user()?;
        kotton_msg::daemon::outbox::readings(&self.msg(), &user, peer_did).await
    }

    /// [`Self::message_unread_count`]'s join, narrowed to one conversation:
    /// the same marks and the same inbox, counted only where `peer_did` sent it.
    async fn message_unread_from(&self, peer_did: &str) -> Result<u64, String> {
        let user = self.user()?;
        let marks = super::read_mark_host::read_marks(self.users, &user)?;
        let resp = kotton_msg::daemon::messages::message_poll_inbox(&self.msg(), user)
            .await
            .map_err(|e| format!("reading the inbox: {e}"))?;
        let inbox = match resp {
            UserResponse::MessageHistory { messages } => messages,
            UserResponse::Error { message } => return Err(message),
            other => return Err(format!("messages.unread-from: unexpected reply {other:?}")),
        };
        kotton_msg::read_marks::unread_count_from(&marks, &inbox, peer_did)
            .await
            .map_err(|e| format!("counting what is unread: {e}"))
    }

    async fn message_mark_read(
        &self,
        peer_did: &str,
        filed_at: u64,
        message_id: &str,
    ) -> Result<bool, String> {
        let user = self.user()?;
        let marks = super::read_mark_host::read_marks(self.users, &user)?;
        use kotton_msg::read_marks::ReadMarks as _;
        marks
            .mark_read(peer_did, filed_at, message_id)
            .await
            .map_err(|e| format!("recording what you have read: {e}"))
    }

    async fn root_records(
        &self,
        root: &str,
        nsid: &str,
    ) -> Result<Vec<kotton_wire::runner::RunnerRecord>, String> {
        let user = self.user()?;
        let store = self
            .record_stores
            .get_or_open(self.runtime.base_dir(), &user, self.runtime.secrets())
            .map_err(|e| e.to_string())?;
        // The person's membership, read now and asked before any row is: the
        // root id is one this daemon handed the occupant, and a name the guest
        // holds is not the authority.
        let access = super::record_access::record_access(self.users, self.base, &user);
        let rows = kotton_record::record_cmds::Record::new(&self.runtime.schema_registry, &store)
            .within(&access, Some(root))
            .map_err(|e| e.to_string())?
            .query(nsid, vec![], None, None, None)
            .await
            .map_err(|e| e.to_string())?;
        Ok(rows.into_iter().map(runner_record).collect())
    }

    async fn root_add_record(&self, root: &str, nsid: &str, data: &str) -> Result<String, String> {
        let user = self.user()?;
        let body: serde_json::Value =
            serde_json::from_str(data).map_err(|e| format!("a record is a JSON object: {e}"))?;
        let store = self
            .record_stores
            .get_or_open(self.runtime.base_dir(), &user, self.runtime.secrets())
            .map_err(|e| e.to_string())?;
        let access = super::record_access::record_access(self.users, self.base, &user);
        kotton_record::record_cmds::Record::new(&self.runtime.schema_registry, &store)
            .within(&access, Some(root))
            .map_err(|e| e.to_string())?
            .insert(nsid, body)
            .await
            .map_err(|e| e.to_string())
    }

    async fn app_holdings(
        &self,
        app_id: &str,
    ) -> Result<Vec<kotton_app::daemon::apps::HeldShape>, String> {
        let user = self.user()?;
        // The person's own database, where the grants the host signed for
        // their apps are — the same pool a launch reads its envelopes from, so
        // the occupant and the sandbox cannot disagree about what was granted.
        let user_db = crate::db::user_db::user_agent_db(
            self.user_dbs,
            self.base,
            self.runtime.secrets(),
            &user,
            &self.runtime.schema_registry,
        )
        .await
        .map_err(|e| format!("reading what your apps were granted: {e}"))?;
        kotton_app::daemon::apps::app_holdings(&user_db, self.base, app_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn file_openers(&self) -> Result<Vec<kotton_wire::runner::RunnerOpener>, String> {
        let user = self.user()?;
        // The person's own database: their registry, and which app they
        // designated `shell` — the same pool `app_holdings` reads, so the
        // apps the sheet offers are the apps this person installed.
        let user_db = crate::db::user_db::user_agent_db(
            self.user_dbs,
            self.base,
            self.runtime.secrets(),
            &user,
            &self.runtime.schema_registry,
        )
        .await
        .map_err(|e| format!("reading the apps you installed: {e}"))?;
        kotton_app::daemon::apps::app_file_openers(&user_db, self.base)
            .await
            .map_err(|e| e.to_string())
    }

    async fn message_open(&self, message: RunnerSealedMessage) -> Result<String, String> {
        let user = self.user()?;
        // Which key opens it is read off the record by the one opener every
        // filed shape goes through: the channel's grants for a record naming a
        // channel — whichever door it came through — and this person's
        // identity key for a direct message (`messages::message_open`).
        let resp = kotton_msg::daemon::messages::message_open(&self.msg(), user, message.into())
            .await
        .map_err(|e| format!("opening: {e}"))?;
        match resp {
            UserResponse::Decrypted { plaintext } => Ok(plaintext),
            UserResponse::Error { message } => Err(message),
            other => Err(format!("messages.open: unexpected reply {other:?}")),
        }
    }

    async fn revoke_device(&self, did: &str) -> Result<(), String> {
        let user_id = self.the_only_user().map_err(|e| format!("{e:?}"))?;
        let user_rt = self
            .users
            .get(&user_id)
            .ok_or_else(|| format!("user runtime '{user_id}' is not loaded"))?;

        // The same call the `NodeRevoke` IPC arm makes, with the same arguments,
        // so the surface and the CLI cannot drift about what revoking means: the
        // membership record goes and the live TLS allowlist entry goes with it.
        // The membership record goes, the live TLS allowlist entry with it, and
        // the person's drives are told to admit the device no longer.
        // The answer is read, not discarded: a revoke a drive did not take, or
        // one refused on a device without the identity, is an error to the
        // person, never a success.
        match kotton_device::users::drive_devices::revoke(self.runtime, user_rt.as_ref(), self.db, user_id, did.to_owned())
            .await
            .map_err(|e| format!("revoking the device: {e}"))?
        {
            UserResponse::NodeRevoked => Ok(()),
            UserResponse::Error { message } => Err(message),
            other => Err(format!("revoking the device: unexpected reply {other:?}")),
        }
    }

    /// The browsers admitted for this person — the read `BrowserDeviceList`
    /// makes, from the same person's own database, projected to a name and two
    /// dates.
    ///
    /// Whose is the host's answer, not the guest's: the verb names nobody, and
    /// the person is resolved the way `list_devices` resolves them.
    async fn list_browsers(&self) -> Result<Vec<RunnerAdmittedBrowser>, String> {
        let user_id = self.user()?;
        let db = self.user_db(&user_id).await?;
        let browsers = kotton_device::config::ops::list_browser_devices(&db, &user_id)
            .await
            .map_err(|e| format!("reading the admitted browsers: {e}"))?;
        Ok(browsers
            .into_iter()
            .map(|b| RunnerAdmittedBrowser {
                name: b.name,
                admitted_at: b.created_at,
                last_visit: b.last_used_at,
            })
            .collect())
    }

    /// Revoke one of this person's admitted browsers, by name.
    ///
    /// **The same function `BrowserDeviceRevoke` calls, with the same
    /// arguments** — so the screen and the terminal cannot drift about what
    /// revoking a browser means: the row, the sessions its admission minted,
    /// and every channel admitted as it, now. The guest names a row it was
    /// shown; the daemon decides whose row that is and does the revoking.
    async fn revoke_browser(&self, name: &str) -> Result<(), String> {
        let user_id = self.user()?;
        let db = self.user_db(&user_id).await?;
        match super::browser_channel::revoke(&self.browsers, &db, &user_id, name).await {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(format!("no browser named '{name}' is admitted")),
            Err(e) => Err(format!("revoking the browser: {e}")),
        }
    }

    /// Mint the first identity on this device, called `display_name`.
    ///
    /// **The id is minted and the name is stored beside it.** A guest may not
    /// name users. That holds, and is not what this does:
    /// the guest still chooses no id — `device_users::mint_user_id` draws one at
    /// random, from neither the name nor the DID — and what the person typed is
    /// a display name, which is theirs to say the way a phone's is. A device
    /// enrolled with the literal `owner` as its id keeps it; nothing draws it.
    async fn create_identity(
        &self,
        passphrase: &str,
        display_name: &str,
    ) -> Result<String, RunnerAuthError> {
        if !device_users::load(self.base).unwrap_or_default().is_empty() {
            return Err(RunnerAuthError::Daemon {
                message: "this device already has an identity; create another with \
                          `kotton id create`, which lets you name it"
                    .to_string(),
            });
        }
        // Assessed before anything is made, so a name that does not fit is a
        // refusal with nothing created — the same order the credential gets.
        // The registry's write normalises again; this is the early refusal,
        // not the rule's only home.
        let display_name = device_users::normalize_display_name(display_name)
            .map_err(|e| RunnerAuthError::Daemon {
                message: e.to_string(),
            })?;

        // Mint the identity. Reused rather than reimplemented so residency,
        // device registration, the session and the audit event all happen the
        // one way they already happen.
        //
        // **The credential goes with it, and nothing here checks it.** This
        // function used to assess the passphrase and then seal the vault after,
        // which read as thoroughness and was in fact the bug: both steps were
        // this wrapper's, so the two CLI paths that call `create_user` directly
        // did neither. `create_user` assesses before it creates and seals before
        // it returns, so there is nothing left for this layer to add — and no
        // door that reaches a created identity without passing through it.
        let created = handlers::user::create_user(
            self.runtime,
            self.users,
            self.user_dbs,
            self.event_log_tasks,
            self.base,
            handlers::user::NewIdentity {
                user_id: device_users::mint_user_id(),
                passphrase: passphrase.to_string(),
                display_name,
            },
            self.sessions,
        )
        .await
        .map_err(|e| RunnerAuthError::Daemon {
            message: e.to_string(),
        })?;

        match created {
            UserResponse::UserCreated { did, .. } => Ok(did),
            UserResponse::WeakCredential { message } => {
                Err(RunnerAuthError::WeakCredential { message })
            }
            UserResponse::Error { message } => Err(RunnerAuthError::Daemon { message }),
            other => Err(RunnerAuthError::Daemon {
                message: format!("unexpected response from user creation: {other:?}"),
            }),
        }
    }

    async fn suggest_credential(&self) -> String {
        kotton_crypto::daily_credential::generate()
    }

    /// Read the identity out of `device/users.json` — the same file
    /// [`Self::the_only_user`] resolves against, and the reason this verb needed
    /// no authority the host did not already hold.
    ///
    /// `registered_at` is stored as an ISO 8601 string and crosses the wire as
    /// unix seconds, because a surface should not be parsing timestamps to
    /// render a date. An unparseable one yields `0`, which the surface renders
    /// as no date at all — the same best-effort rule the device roster uses for
    /// a name: a field that will not load costs its field, never the reading.
    async fn read_identity(&self) -> Result<RunnerIdentity, RunnerAuthError> {
        let user_id = self.the_only_user()?;
        let users = device_users::load(self.base).map_err(|e| RunnerAuthError::Daemon {
            message: format!("cannot read the device's identity registry: {e}"),
        })?;
        let record = users.get(&user_id).ok_or(RunnerAuthError::NoIdentity)?;
        Ok(RunnerIdentity {
            user_id: user_id.clone(),
            display_name: record.display_name.clone(),
            did: record.did.clone(),
            registered_at: chrono::DateTime::parse_from_rfc3339(&record.registered_at)
                .map(|t| t.timestamp())
                .unwrap_or(0),
        })
    }

    /// Change what the person is called: the name record in their own store,
    /// which every device of theirs follows, and then this device's copy in the
    /// registry `read_identity` reads.
    ///
    /// **Refused unless they are unlocked.** This host is the locked shell's as
    /// much as the desktop's, so the verb is reachable from the lock screen; a
    /// live session for the one identity is what says the person it names is
    /// the one asking. That is the check, and what makes it necessary is that
    /// `world occupant` is one world before and after unlock — the honest
    /// place for it is here, at the one write, rather than a second world.
    async fn set_display_name(&self, name: &str) -> Result<(), RunnerAuthError> {
        let user_id = self.the_only_user()?;
        if !kotton_session::service::tokens::has_live_session_for(self.sessions, &user_id) {
            return Err(RunnerAuthError::Daemon {
                message: "unlock first: a name is changed by the person it names".to_string(),
            });
        }
        // **The record first, the copy second**: a person's name travels with
        // their identity. The name is kept
        // in the person's own store, sealed, and their other devices follow it
        // when it arrives by sync; this device's registry entry is a copy of it.
        // Both writes normalise, so a name that does not fit is refused at the
        // first with nothing written, and a record that cannot be written leaves
        // the copy as it was rather than ahead of the source.
        let store = self.users.get(&user_id).ok_or_else(|| RunnerAuthError::Daemon {
            message: "unlock first: a name is changed by the person it names".to_string(),
        })?;
        let kept = crate::own_name::write(&store, name)
            .await
            .map_err(|e| RunnerAuthError::Daemon {
                message: e.to_string(),
            })?;
        device_users::set_display_name(self.base, &user_id, kept.as_deref().unwrap_or(""))
            .map(|_| ())
            .map_err(|e| RunnerAuthError::Daemon {
                message: e.to_string(),
            })
    }

    async fn unlock(&self, passphrase: &str) -> Result<String, RunnerAuthError> {
        let user_id = self.the_only_user()?;
        self.open_session(&user_id, passphrase).await
    }

    async fn unlock_with_pin(&self, user_id: &str, pin: &str) -> Result<String, RunnerAuthError> {
        self.open_session(user_id, pin).await
    }
}

// ── Messages ──────────────────────────────────────────────────────────────────
//
// Every one of these calls the same `kotton_msg::daemon::messages` function the
// IPC arm calls, through the same `msg_host`. That is the point: the shell, the
// phone and the CLI must not be able to disagree about what a send does, and
// the way to guarantee it is one implementation with three callers rather than
// three that were written to match.

/// The person a daemon acts for at the desk, for *Operators*: their account id
/// here and the DID `kdeviced` knows their account by.
struct Acting {
    user_id: String,
    did: String,
}

/// One person with an account on this machine, as *Operators* names them.
struct Account {
    user_id: String,
    did: String,
    name: String,
}

/// The accounts on this machine (`device/users.json`), by what each is called.
struct Accounts {
    people: Vec<Account>,
}

impl Accounts {
    /// Who `handle` — an account id a guest was handed — is, or a refusal.
    fn person(&self, handle: &str) -> Result<&Account, String> {
        self.people
            .iter()
            .find(|p| p.user_id == handle)
            .ok_or_else(|| "nobody with that account is on this PC".to_owned())
    }

    /// The handle and name of the account `did` is, or — for an operator whose
    /// account is no longer here — a name that says so and a handle naming
    /// nobody, so no verb can reach them through it but `kctl`.
    fn by_did(&self, did: &str) -> (String, String) {
        match self.people.iter().find(|p| p.did == did) {
            Some(p) => (p.user_id.clone(), p.name.clone()),
            None => (String::new(), "Someone no longer on this PC".to_owned()),
        }
    }
}

impl DaemonOccupantHost<'_> {
    /// **Whom this daemon acts for, for *Operators*** — the person `kdeviced`
    /// spawned it for (its principal: one daemon per person, on the machine a
    /// household shares), else the one identity here. Never a
    /// name the guest gave: the guest cannot say who is asking.
    fn operator_person(&self) -> Result<Acting, String> {
        let users = device_users::load(self.base)
            .map_err(|e| format!("cannot read who has an account on this PC: {e}"))?;
        let user_id = match self.runtime.config().principal.as_deref() {
            Some(principal) => users
                .iter()
                .find(|(id, r)| r.did == principal || id.as_str() == principal)
                .map(|(id, _)| id.clone())
                .ok_or_else(|| format!("this daemon serves {principal}, who has no account on this PC"))?,
            None => self.user()?,
        };
        let did = users
            .get(&user_id)
            .map(|r| r.did.clone())
            .ok_or_else(|| format!("{user_id} has no account on this PC"))?;
        Ok(Acting { user_id, did })
    }

    /// The person's own store, which holds their operator key — present only
    /// once they have unlocked.
    fn store_of(&self, user_id: &str) -> Result<Arc<kotton_store::runtime::user::UserStore>, String> {
        self.users
            .get(user_id)
            .ok_or_else(|| "unlock first: an operator acts with a key only they can open".to_owned())
    }

    /// Everyone with an account here, each by the name they go by — or, for an
    /// account made at a terminal with no name, its account id.
    fn accounts(&self) -> Accounts {
        let mut people: Vec<Account> = device_users::load(self.base)
            .unwrap_or_default()
            .into_iter()
            .map(|(user_id, r)| Account {
                name: r.display_name.clone().unwrap_or_else(|| user_id.clone()),
                did: r.did,
                user_id,
            })
            .collect();
        people.sort_by(|a, b| a.name.cmp(&b.name).then(a.user_id.cmp(&b.user_id)));
        Accounts { people }
    }

    /// Where this machine's `kdeviced` listens.
    fn kdeviced(&self) -> Result<kotton_sys::ipc::IpcEndpoint, String> {
        device_operator::endpoint(self.runtime.config().kdeviced.as_ref())
    }

    /// This person's own database, where their admitted browsers are — the
    /// one `BrowserDeviceList` reads.
    async fn user_db(&self, user_id: &str) -> Result<Arc<SqlitePool>, String> {
        super::dispatch::user_db_for(self.runtime, self.users, self.user_dbs, self.base, Some(user_id))
            .await
            .map_err(|e| format!("opening {user_id}'s database: {e}"))
    }

    /// The messaging host, built as `dispatch` builds it.
    fn msg(&self) -> crate::agent::message_host::DaemonMessageHost<'_> {
        crate::agent::message_host::msg_host(self.runtime, self.users, self.record_stores)
    }

    /// Whose messages these are.
    ///
    /// The occupant surface names no user — it is the one person at this
    /// machine — so it resolves the same way `unlock` does, and refuses for the
    /// same reason where there are several.
    fn user(&self) -> Result<String, String> {
        self.the_only_user().map_err(|e| format!("{e:?}"))
    }

    /// This person's paired-node roster, the same read `list_devices` makes.
    async fn paired_nodes(
        &self,
        user_id: &str,
    ) -> Result<Vec<kotton_wire::peer::PairedNode>, String> {
        match kotton_peer::daemon::nodes::node_list(self.db, user_id.to_string())
            .await
            .map_err(|e| format!("reading the device roster: {e}"))?
        {
            UserResponse::NodeList { nodes } => Ok(nodes),
            other => Err(format!("unexpected reply reading the roster: {other:?}")),
        }
    }

    /// The DIDs of the vaults this person has enrolled.
    ///
    /// A vault is a paired node too, so the relay's device count has to know
    /// which rows are vaults — a person's *devices* is what that row says.
    ///
    /// An error, not an empty set, when the vaults cannot be read: an empty set
    /// here counts every vault as a device, which is the miscount this exists
    /// to prevent. A store that is not loaded has no vaults this device can
    /// name, and answers empty as it always did.
    async fn enrolled_handles(
        &self,
        user_id: &str,
    ) -> Result<std::collections::HashSet<String>, String> {
        let Some(store) = self.users.get(user_id) else {
            return Ok(std::collections::HashSet::new());
        };
        Ok(admitted_vaults(&store)
            .await?
            .into_iter()
            .map(|t| t.handle)
            .collect())
    }
}

/// The vaults this person has admitted, as the network readout lists them.
///
/// **The readout's source, and nothing else's.** A vault admitted by
/// `kotton drive enrol <invite> --blind` or by an invite pasted at Settings' door
/// runs `handle_device_admit`, whose completion records it as an own-device
/// member under the blind posture, and revoking it removes that member. So the
/// list is [`Membership::list_vaults`] — a view over the membership set, which
/// is the source every list of principals is projected from — and
/// nothing here keeps a copy of it.
///
/// Not `config.toml`'s `RemoteBackend::Kotton` entries. Admission writes none —
/// a remote is the peer storage opened to a node, registered the first time
/// something syncs to it — so read from there, a vault admitted a second ago
/// would be in no list, and the relay's row would count it as a device.
///
/// **It never decides where anything is kept.** The roots take no target from
/// this set: an admitted vault holds nothing until a root names it (the joining
/// record's ruling), so neither a first run nor a rebuilt routing half may
/// read it as a target. That is why this lives beside the readout rather than
/// beside the roots.
///
/// An error when the membership set cannot be read, because *could not look*
/// is not *no vaults*.
///
/// [`Membership::list_vaults`]: kotton_peer::membership::Membership::list_vaults
pub(crate) async fn admitted_vaults(
    store: &kotton_store::runtime::user::UserStore,
) -> Result<Vec<kotton_store::runtime::roots::Target>, String> {
    store
        .list_vaults()
        .await
        .map(|vaults| {
            vaults
                .into_iter()
                .map(|(did, label)| kotton_store::runtime::roots::Target::new(did, label))
                .collect()
        })
        .map_err(|e| format!("{e:#}"))
}

/// One row of a root, as the occupant is handed it.
///
/// The keys the query verb added are the host's, not the record's: the guest
/// asked for one root and knows which, and when the store filed a row is not a
/// fact about the row: a conversation is not ordered by a clock it does not
/// hold.
fn runner_record(mut body: serde_json::Value) -> kotton_wire::runner::RunnerRecord {
    let id = body["_id"].as_str().unwrap_or_default().to_owned();
    if let Some(obj) = body.as_object_mut() {
        obj.remove("_id");
        obj.remove("_root");
        obj.remove("_filed_at");
    }
    kotton_wire::runner::RunnerRecord {
        id,
        data: body.to_string(),
    }
}

/// One record out of the store, as the occupant sees it.
///
/// A record that will not parse costs itself and not the list: an inbox that
/// hides everything because one row is malformed is worse than an inbox with a
/// gap, and the gap is visible.
///
/// `filed_at` is required where `sent_at` is not: it is the key the surface
/// orders by and marks with, and a row with no place in the filing order cannot
/// be put anywhere honestly. Every row the message verbs return has one.
fn sealed_from_record(v: &serde_json::Value) -> Option<RunnerSealedMessage> {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|x| x.to_string());
    Some(RunnerSealedMessage {
        id: s("id")?,
        thread_id: s("thread_id").unwrap_or_default(),
        from_did: s("from_did")?,
        to_did: s("to_did"),
        channel_did: s("channel_did"),
        body: s("body")?,
        nonce: s("nonce")?,
        ephemeral_pub: s("ephemeral_pub"),
        sent_at: v.get("sent_at").and_then(|x| x.as_u64()).unwrap_or(0),
        filed_at: v.get("filed_at").and_then(|x| x.as_u64())?,
        message_type: s("type").unwrap_or_else(|| "text".to_string()),
    })
}

fn message_list(resp: UserResponse, verb: &str) -> Result<Vec<RunnerSealedMessage>, String> {
    match resp {
        UserResponse::MessageHistory { messages } => {
            Ok(messages.iter().filter_map(sealed_from_record).collect())
        }
        UserResponse::Error { message } => Err(message),
        other => Err(format!("messages.{verb}: unexpected reply {other:?}")),
    }
}

// Recording the lock policy and `set_user_pin`, the two halves of recording a
// credential, are `create_user`'s, which is what makes them reachable from every
// door rather than from this one.

/// Build an occupant host for one dispatch arm.
///
/// Callers hand the result only where the app being driven is the designated
/// shell; everywhere else they pass `None`.
#[allow(clippy::too_many_arguments)]
pub fn occupant_host<'a>(
    runtime: &'a DeviceRuntime,
    users: &'a UserRegistry,
    sessions: &'a SessionMap,
    base: &'a Path,
    db: &'a Arc<SqlitePool>,
    record_stores: &'a crate::residency::RecordStores,
    ceremonies: &'a super::ceremony::Ceremonies,
    user_dbs: &'a crate::db::user_db::UserDbMap,
    event_log_tasks: &'a crate::event_log::EventLogTasks,
    // kdeviced's configuration pool and the live connected-peer set — **taken
    // here and never stored**, because what the host holds is the projection
    // built from them and not the two of them. One place knows the shape.
    device_db: &Arc<SqlitePool>,
    connected_peers: &Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
    // The compositor's end of the pair, for the platform's own prompts. Every
    // caller already holds it; none of them gives a guest anything of it.
    desk: &'a crate::surface_proxy::SurfaceProxy,
    // What a browser revoke reaches, and nothing else.
    browsers: super::browser_channel::BrowserAdmissions,
) -> DaemonOccupantHost<'a> {
    DaemonOccupantHost {
        runtime,
        users,
        sessions,
        base,
        user_dbs,
        event_log_tasks,
        db,
        record_stores,
        ceremonies,
        // Nobody yet: one host, one exchange, one answer.
        unlocked: std::sync::Mutex::new(None),
        machine: super::network_readout::MachineReadout::new(
            Arc::clone(device_db),
            Arc::clone(connected_peers),
        ),
        desk,
        browsers,
    }
}

#[cfg(test)]
mod message_tests {
    use super::*;

    fn record(extra: serde_json::Value) -> serde_json::Value {
        let mut v = serde_json::json!({
            "id": "m1",
            "from_did": "did:key:zFrom",
            "body": "Y2lwaGVy",
            "nonce": "bm9uY2U=",
            "sent_at": 1_700_000_000u64,
            "filed_at": 1_700_000_000_123u64,
        });
        for (k, val) in extra.as_object().unwrap() {
            v[k] = val.clone();
        }
        v
    }

    #[test]
    fn a_dm_record_carries_its_ephemeral_key_across() {
        let m = sealed_from_record(&record(serde_json::json!({
            "to_did": "did:key:zTo",
            "thread_id": "t1",
            "ephemeral_pub": "ZXBo",
            "type": "text",
        })))
        .expect("a DM record parses");
        assert_eq!(m.id, "m1");
        assert_eq!(m.ephemeral_pub.as_deref(), Some("ZXBo"));
        assert_eq!(m.channel_did, None);
        assert_eq!(m.message_type, "text");
    }

    /// The store writes `type`; the wire calls it `message_type`. A record with
    /// neither is still a message, and calling it text is the right default —
    /// but the rename is exactly the kind of thing that silently produces empty
    /// strings, so it is pinned.
    #[test]
    fn a_record_without_a_type_is_text() {
        let m = sealed_from_record(&record(serde_json::json!({}))).expect("parses");
        assert_eq!(m.message_type, "text");
        assert_eq!(
            m.thread_id, "",
            "a record with no thread says so rather than guessing"
        );
    }

    /// The **join**, which is where the defect was: what the message verbs emit
    /// must be what this parser reads.
    ///
    /// `record_cmds::query` writes the row id to `_id` on every row it returns
    /// ("Every row carries `_id` because there is one branch producing rows"),
    /// and the message verbs rename it to `id` on the way out. Only one of them
    /// did. So a record reaching this parser through the inbox had `_id`, no
    /// `id`, and `sealed_from_record` returned `None` — and `filter_map`
    /// dropped the lot in silence: the shell's inbox was **unconditionally
    /// empty**, and an empty inbox reads exactly like a real one.
    ///
    /// Neither side was wrong on its own, which is why neither side's tests
    /// caught it: the fixture above is written with `id`, because that is what
    /// the parser reads, and a fixture shaped like the parser tests the parser
    /// against itself. This one starts from the store's shape and runs it
    /// through both halves.
    #[test]
    fn what_the_message_verbs_emit_is_what_this_parser_reads() {
        let from_the_store = serde_json::json!({
            "_id": "0192f7c1-0000-7000-8000-000000000001",
            "from_did": "did:key:zFrom",
            "to_did": "did:key:zTo",
            "thread_id": "t1",
            "body": "Y2lwaGVy",
            "nonce": "bm9uY2U=",
            "sent_at": 1_700_000_000u64,
            "_filed_at": 1_700_000_000_123u64,
            "type": "text",
        });
        let on_the_wire = kotton_msg::daemon::messages::expose_row_id(from_the_store);
        let got = message_list(
            UserResponse::MessageHistory {
                messages: vec![on_the_wire],
            },
            "poll_inbox",
        )
        .expect("the reply is a history");
        assert_eq!(
            got.len(),
            1,
            "the store's own row shape must survive both halves"
        );
        assert_eq!(got[0].id, "0192f7c1-0000-7000-8000-000000000001");
        assert_eq!(
            got[0].filed_at, 1_700_000_000_123,
            "the filing position survives both halves too — it is what the shell orders by"
        );
    }

    /// **A channel copy that came over a member's door reaches `messages.open`
    /// naming its channel and carrying the envelope's key**, so an app can open
    /// a channel message that arrived from another member.
    /// Built by the door's own filing (`messages::filed_record`) and run
    /// through the store's row shape and this parser, so the message handed
    /// back to `message_open` is the one the door filed: both fields survive,
    /// and the opener — not this parser — decides by `channel_did` which key
    /// opens it. Dropping either field here is what would send a received
    /// channel copy down the direct-message path again.
    #[test]
    fn a_channel_copy_from_a_members_door_reaches_the_opener_naming_its_channel() {
        use kotton_msg::envelope::{ChannelCopy, DmInner};
        let inner = DmInner {
            from_did: "did:kel:sam".into(),
            to_did: "did:kel:avery".into(),
            thread_id: "t".into(),
            sent_at: 1,
            kind: "text".into(),
            text: String::new(),
            channel: Some(ChannelCopy {
                channel_did: "did:key:zHousehold".into(),
                epoch: 4,
                body: b"channel".to_vec(),
                nonce: "Y2hhbm5vbmNl".into(),
            }),
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: None,
            range: None,
        };
        let envelope = kotton_wire::ipc::SealedDm {
            ephemeral_pub: "ZW52ZWxvcGU=".into(),
            nonce: "ZW52bm9uY2U=".into(),
            body: "ZW52Ym9keQ==".into(),
        };
        let mut row = kotton_msg::daemon::messages::filed_record(&inner, &envelope);
        row["_id"] = serde_json::json!("m1");
        row["_filed_at"] = serde_json::json!(1_700_000_000_123u64);
        let got = message_list(
            UserResponse::MessageHistory { messages: vec![kotton_msg::daemon::messages::expose_row_id(row)] },
            "channel_history",
        )
        .expect("the reply is a history");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].channel_did.as_deref(), Some("did:key:zHousehold"));
        assert_eq!(got[0].ephemeral_pub.as_deref(), Some("ZW52ZWxvcGU="), "the envelope's key, kept to deduplicate");
        assert_eq!((got[0].body.as_str(), got[0].nonce.as_str()), ("Y2hhbm5lbA==", "Y2hhbm5vbmNl"), "the channel's ciphertext");
    }

    /// A root's row reaches the occupant as the record and its id, and none of
    /// the keys the query verb added — the root, and when the store filed it.
    #[test]
    fn a_root_row_reaches_the_guest_without_the_hosts_keys() {
        let r = runner_record(serde_json::json!({
            "_id": "r1", "_root": "fam", "_filed_at": 1_757_000_000_123i64, "title": "dentist",
        }));
        assert_eq!(r.id, "r1");
        let body: serde_json::Value = serde_json::from_str(&r.data).unwrap();
        assert_eq!(body, serde_json::json!({ "title": "dentist" }));
    }

    /// A record with no place in the filing order is not given one. Ordering it
    /// by its sender's `sent_at` instead would order a conversation by a clock
    /// it does not hold, which the stamp exists to prevent.
    #[test]
    fn a_record_with_no_filing_position_is_dropped_not_placed_by_its_senders_clock() {
        let mut v = record(serde_json::json!({}));
        v.as_object_mut().unwrap().remove("filed_at");
        assert!(sealed_from_record(&v).is_none());
    }

    /// A row that will not parse costs itself and not the list. An inbox that
    /// hides everything because one record is malformed is worse than one with
    /// a visible gap.
    #[test]
    fn a_record_missing_what_opens_it_is_dropped_not_guessed() {
        assert!(
            sealed_from_record(&serde_json::json!({ "id": "m1" })).is_none(),
            "no from_did, no body, no nonce — there is nothing here to open"
        );
    }
}

/// The answer a landlord reader asked for, read; any other, refused in
/// [`kotton_wire::ipc::answer_said`]'s words — the vault's own where the
/// answer carries them (`Error`, `VaultKeepsAlready`), and otherwise its name,
/// never its fields.
///
/// **One expectation per reader, and no list** (#114, #121). Each reader
/// names the one answer its verb asks the vault for, and nothing else: there
/// is no arm for `Error`, no arm for any refusal, and no catch-all of its own.
/// An answer a release adds is not the one asked for, so it is refused and
/// said, never misread and never printed. The five other landlord readers
/// had one shape — the answer asked for, then `Error`, then a debug print of
/// anything else — and the invite's had the form this is (#122): written once
/// here, rather than five times more, so each reader below states only what it
/// asked for. It is a macro because what a reader asked for is a pattern,
/// which a function cannot take.
macro_rules! answered {
    ($answer:expr, $asked:pat => $read:expr) => {
        match $answer {
            $asked => Ok($read),
            unread => Err(kotton_wire::ipc::answer_said(&unread)),
        }
    };
}

/// `landlord.invite`: the invite's text. A name the vault keeps is refused
/// here, as everywhere but `vault invite --me` (#108): a guest's invite
/// admits someone new.
fn invite_answered(answer: UserResponse) -> Result<String, String> {
    answered!(answer, UserResponse::PairAdvertising { code, .. } => code.expose().to_string())
}

/// `landlord.people` (and the drop's check of who is kept): who the vault
/// keeps for.
fn tenants_answered(answer: UserResponse) -> Result<Vec<RunnerTenant>, String> {
    answered!(answer, UserResponse::VaultTenants { tenants } => tenants
        .into_iter()
        .map(|t| RunnerTenant {
            name: t.user_id,
            held_bytes: t.held,
            space_bytes: t.quota,
            devices: t.devices,
        })
        .collect())
}

/// `landlord.drop-pool`: the pool dropped.
fn dropped_answered(answer: UserResponse) -> Result<(), String> {
    answered!(answer, UserResponse::TenantDropped { .. } => ())
}

/// `landlord.rule` and `landlord.set-rule`: the rule the relay holds — read,
/// or as it holds it once set. Both verbs ask the relay for the same answer.
fn rule_answered(answer: UserResponse) -> Result<kotton_wire::rendezvous::AdmissionRule, String> {
    answered!(answer, UserResponse::RelayRule { rule } => rule)
}

/// `landlord.move-vault`: the vault took the relay it was told of.
fn moved_answered(answer: UserResponse) -> Result<(), String> {
    answered!(answer, UserResponse::Ok => ())
}

#[cfg(test)]
mod a_guests_invite {
    use super::*;

    /// **A name the vault keeps is refused to the guest in the vault's
    /// sentence** (#108): the vault answers `VaultKeepsAlready`, and the guest's
    /// `vault invite <v> <name> --space` is told the vault already keeps for
    /// that name — never a debug print of the variant. `landlord_invite` hands
    /// the vault's answer to [`invite_answered`] and nothing else; the method
    /// itself needs a kept credential and a live vault to reach this.
    #[test]
    fn a_name_the_vault_keeps_is_refused_to_the_guest_in_the_vaults_sentence() {
        let said = invite_answered(UserResponse::VaultKeepsAlready { user_id: "sam".into() })
            .expect_err("an invite for a kept name was answered as minted");
        assert!(said.starts_with("this vault already keeps for 'sam'"), "{said}");
        assert!(!said.contains("VaultKeepsAlready") && !said.contains("does not read"), "{said}");
        let minted = UserResponse::PairAdvertising {
            code: kotton_wire::ipc::SecretText::new("kotton-invite:vault:the-words"),
            expires_at: 1,
        };
        assert_eq!(invite_answered(minted).as_deref(), Ok("kotton-invite:vault:the-words"));
        assert_eq!(invite_answered(UserResponse::Error { message: "no relay".into() }), Err("no relay".to_string()));
    }

    /// **A refusal no reader names is refused to the guest and said, not
    /// printed** (#114). `VaultFull` stands in for a typed refusal a later
    /// release adds: the guest is told no invite, in `answer_said`'s words,
    /// with none of the answer's fields. Nothing follows it at the vault
    /// either: `landlord_invite` speaks through `operator::in_order`, which
    /// sends the number only on the invite
    /// (`an_invite_answered_with_a_refusal_nobody_names_sends_no_number`).
    #[test]
    fn a_refusal_nobody_names_is_refused_to_the_guest_and_said() {
        let unnamed = UserResponse::VaultFull { held: 3, quota: 2 };
        let said = invite_answered(unnamed.clone()).expect_err("an answer other than the invite was taken as one");
        assert_eq!(said, kotton_wire::ipc::answer_said(&unnamed));
        assert!(said.starts_with("the answer was `VaultFull`"), "{said}");
        assert!(!said.contains('{') && !said.contains("does not read"), "{said}");
    }
}

#[cfg(test)]
mod a_landlords_answer {
    use super::*;
    use kotton_wire::rendezvous::AdmissionRule;

    /// A typed refusal no landlord reader names, standing in for one a later
    /// release adds — as `a_refusal_nobody_names_is_refused_to_the_guest_and_said`.
    fn unnamed() -> UserResponse {
        UserResponse::VaultFull { held: 3, quota: 2 }
    }

    /// What every reader says of [`unnamed`]: `answer_said`'s words, with no
    /// field of the answer and no debug print.
    fn said_by_name<T: std::fmt::Debug>(read: Result<T, String>) {
        let said = read.expect_err("an answer other than the one asked for was taken as it");
        assert_eq!(said, kotton_wire::ipc::answer_said(&unnamed()));
        assert!(said.starts_with("the answer was `VaultFull`"), "{said}");
        assert!(!said.contains('{') && !said.contains("does not read"), "{said}");
    }

    /// The vault's own words, where its refusal is an `Error`.
    fn refused() -> UserResponse {
        UserResponse::Error { message: "no operator credential is kept for 'home'".into() }
    }

    /// **`landlord.people` reads the tenants and says any other answer**
    /// (#121): `VaultTenants` is the list, an `Error` its message, and an
    /// answer it does not name is said by its name.
    #[test]
    fn landlord_people_reads_the_tenants_and_says_any_other_answer() {
        let tenant = kotton_wire::ipc::VaultTenant { user_id: "sam".into(), held: 7, quota: Some(9), devices: 1 };
        let people = tenants_answered(UserResponse::VaultTenants { tenants: vec![tenant] }).expect("the tenants");
        assert_eq!(people.len(), 1);
        assert_eq!((people[0].name.as_str(), people[0].held_bytes, people[0].space_bytes), ("sam", 7, Some(9)));
        assert_eq!(tenants_answered(refused()).err().as_deref(), Some("no operator credential is kept for 'home'"));
        said_by_name(tenants_answered(unnamed()));
    }

    /// **`landlord.drop-pool` reads the drop and says any other answer**
    /// (#121). A pool's readout (`VaultCapacityResult`) is not a drop either:
    /// an answer meant for another verb is said, never taken as done.
    #[test]
    fn landlord_drop_reads_the_drop_and_says_any_other_answer() {
        let tenant = kotton_wire::ipc::VaultTenant { user_id: "sam".into(), held: 7, quota: None, devices: 1 };
        assert_eq!(dropped_answered(UserResponse::TenantDropped { tenant }), Ok(()));
        assert_eq!(dropped_answered(refused()).err().as_deref(), Some("no operator credential is kept for 'home'"));
        said_by_name(dropped_answered(unnamed()));
        let readout = dropped_answered(UserResponse::VaultCapacityResult { held: 7, quota: None });
        assert!(readout.is_err_and(|s| s.starts_with("the answer was `VaultCapacityResult`")));
    }

    /// **`landlord.rule` reads the relay's rule and says any other answer**
    /// (#121).
    #[test]
    fn landlord_rule_reads_the_rule_and_says_any_other_answer() {
        assert_eq!(rule_answered(UserResponse::RelayRule { rule: AdmissionRule::Anyone }), Ok(AdmissionRule::Anyone));
        assert_eq!(rule_answered(refused()).err().as_deref(), Some("no operator credential is kept for 'home'"));
        said_by_name(rule_answered(unnamed()));
    }

    /// **`landlord.set-rule` is answered with the rule the relay then holds,
    /// and says any other answer** (#121): a bare `Ok` is not the rule held,
    /// so it is said, not taken as set.
    #[test]
    fn landlord_set_rule_reads_the_rule_held_and_says_any_other_answer() {
        let held = rule_answered(UserResponse::RelayRule { rule: AdmissionRule::PeopleIInvite });
        assert_eq!(held, Ok(AdmissionRule::PeopleIInvite));
        said_by_name(rule_answered(unnamed()));
        assert!(rule_answered(UserResponse::Ok).is_err_and(|s| s.starts_with("the answer was `Ok`")));
    }

    /// **`landlord.move-vault` reads the vault taking the relay and says any
    /// other answer** (#121).
    #[test]
    fn landlord_move_vault_reads_the_move_and_says_any_other_answer() {
        assert_eq!(moved_answered(UserResponse::Ok), Ok(()));
        assert_eq!(moved_answered(refused()).err().as_deref(), Some("no operator credential is kept for 'home'"));
        said_by_name(moved_answered(unnamed()));
    }
}

#[cfg(test)]
mod the_drops_door {
    use super::*;

    /// A desk whose person types `typed` — or declines (`Ok(None)`), or is not
    /// there at all (`Err`) — and which remembers what it was asked.
    struct Desk {
        answer: Result<Option<&'static str>, &'static str>,
        asked: std::sync::Mutex<Vec<kotton_wire::PlatformPrompt>>,
    }

    #[async_trait::async_trait]
    impl AsksTheDesk for Desk {
        async fn ask(&self, prompt: kotton_wire::PlatformPrompt) -> Result<Option<String>, String> {
            self.asked.lock().unwrap().push(prompt);
            self.answer.map(|t| t.map(str::to_owned)).map_err(str::to_owned)
        }
    }

    /// **The verb's door asks for the name, and drops only on the name.**
    ///
    /// Every drop is asked on the desk first, for exactly the pool and vault the
    /// verb names; the drop runs on the name typed back exactly and on nothing
    /// else — a near miss, a declined prompt, and a machine with no desk each
    /// leave the pool where it is and say why. Deleting the comparison in
    /// [`dropped_once_typed_back`] turns this red at `Sam`.
    #[tokio::test]
    async fn a_drop_is_asked_on_the_desk_and_goes_only_on_the_name_typed_back() {
        let cases: [(Result<Option<&'static str>, &'static str>, bool); 7] = [
            (Ok(Some("sam")), true),
            (Ok(Some("Sam")), false),
            (Ok(Some("sa")), false),
            (Ok(Some("sam ")), false),
            (Ok(Some("")), false),
            (Ok(None), false),
            (Err("no desk"), false),
        ];
        for (answer, drops) in cases {
            let desk = Desk { answer, asked: Default::default() };
            let dropped = std::sync::atomic::AtomicBool::new(false);
            let outcome = dropped_once_typed_back(&desk, "kotton", "sam", || async { Ok(true) }, || async {
                dropped.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .await;
            assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), drops, "{answer:?}");
            assert_eq!(outcome.is_ok(), drops, "{answer:?}: {outcome:?}");
            assert_eq!(
                *desk.asked.lock().unwrap(),
                vec![kotton_wire::PlatformPrompt::DropTenant {
                    vault: "kotton".into(),
                    pool: "sam".into()
                }],
                "{answer:?}"
            );
        }
        // An empty pool is never dropped by typing nothing.
        let desk = Desk { answer: Ok(Some("")), asked: Default::default() };
        let outcome = dropped_once_typed_back(&desk, "kotton", "", || async { Ok(true) }, || async { Ok(()) }).await;
        assert!(outcome.is_err(), "{outcome:?}");
    }

    /// **A guest's verb raises the desk's dim only for a drop the platform would perform.**
    /// A vault this desktop
    /// holds no credential for (the vault is never reached: `kept` is refused in words), and a
    /// pool the vault does not keep, are refused **before the desk is asked anything** — so
    /// the shell cannot dim the desk over a vault it has no standing on or a name it made up.
    /// Taking the `kept` check out turns this red.
    #[tokio::test]
    async fn the_desk_is_asked_only_about_a_pool_the_vault_keeps() {
        for kept in [Ok(false), Err("this desktop holds no operator credential for 'attic'".to_owned())] {
            let desk = Desk { answer: Ok(Some("sam")), asked: Default::default() };
            let outcome = dropped_once_typed_back(&desk, "kotton", "sam", || async { kept.clone() }, || async {
                panic!("dropped without a kept pool")
            })
            .await;
            assert!(outcome.is_err(), "{kept:?}: {outcome:?}");
            assert!(desk.asked.lock().unwrap().is_empty(), "{kept:?}: the desk was asked about a pool nobody keeps");
        }
    }

    /// **An operator is stepped down only on their name typed back**: the desk is asked, for exactly that person, and the removal runs on the
    /// name typed back exactly and on nothing else. Deleting the comparison in
    /// [`stepped_down_once_typed_back`] turns this red at `ana`.
    #[tokio::test]
    async fn an_operator_is_removed_only_on_their_name_typed_back() {
        let cases: [(Result<Option<&'static str>, &'static str>, bool); 6] = [
            (Ok(Some("Ana")), true),
            (Ok(Some("ana")), false),
            (Ok(Some("An")), false),
            (Ok(Some("")), false),
            (Ok(None), false),
            (Err("no desk"), false),
        ];
        for (answer, removes) in cases {
            let desk = Desk { answer, asked: Default::default() };
            let removed = std::sync::atomic::AtomicBool::new(false);
            let outcome = stepped_down_once_typed_back(&desk, "Ana", || async {
                removed.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .await;
            assert_eq!(removed.load(std::sync::atomic::Ordering::SeqCst), removes, "{answer:?}");
            assert_eq!(outcome.is_ok(), removes, "{answer:?}: {outcome:?}");
            assert_eq!(
                *desk.asked.lock().unwrap(),
                vec![kotton_wire::PlatformPrompt::RemoveOperator { name: "Ana".into() }],
                "{answer:?}"
            );
        }
        // A person with no name is never confirmed by typing nothing, and the desk is not asked.
        let desk = Desk { answer: Ok(Some("")), asked: Default::default() };
        let outcome = stepped_down_once_typed_back(&desk, "", || async { panic!("removed with no name") }).await;
        assert!(outcome.is_err());
        assert!(desk.asked.lock().unwrap().is_empty());
    }
}
