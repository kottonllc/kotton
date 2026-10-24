// SPDX-License-Identifier: AGPL-3.0-or-later
//! Running a contact ceremony for the shell, and telling it what happened.
//!
//! ## Why this is a module and not a method
//!
//! Every other occupant verb answers from state the daemon already holds:
//! ask, read, reply. A ceremony is not like that. It is a **conversation between
//! two people at two screens**, lasting as long as they take, and the surface's
//! job is to show where it has got to. So something has to outlive a single host
//! call, and [`DaemonOccupantHost`](super::occupant_host::DaemonOccupantHost) is
//! a bundle of borrows built per call and dropped at the end of it.
//!
//! [`Ceremonies`] is that something: one per daemon, cloneable, holding what a
//! ceremony task needs to run and to reach the app that asked for it.
//!
//! ## Pushed, never polled
//!
//! Each frame reaches the app at `on-message` the moment the daemon learns it.
//! The alternative — a `pair-poll` verb the guest calls on a timer — was
//! rejected, and not only on taste. The frame that matters is *the other person
//! is here, compare these digits*, and two humans are about to read those digits
//! to each other. A polled surface is stale for the length of its timer in the
//! one step of the ceremony whose entire purpose is confirming that nothing in
//! between altered the meeting. Polling also puts the ceremony's state in the
//! host, buffered until the guest asks; pushing leaves the state where the thing
//! that draws it lives, which is less machinery rather than more.
//!
//! ## The token stays here
//!
//! The stream parks on a confirmation token, and answering the digits means
//! firing it. That token is never sent to the guest: `pair_confirm(matched)`
//! looks up the ceremony *this app* started. A guest that could name a token
//! could answer a ceremony it did not start, which is the one thing standing
//! between the six digits and a stranger's key.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use kotton_device::DeviceRuntime;
use kotton_wire::runner::{HostFrame, RunnerContact, RunnerPairingState, PAIRING_FRAME_KIND};
use kotton_wire::UserResponse;
use sqlx::SqlitePool;
use tokio::sync::Mutex;

use crate::residency::{RecordStores, UserRegistry};
use crate::surface_proxy::SurfaceProxy;

/// One ceremony in flight, as the daemon tracks it.
struct Running {
    /// The token the digits are answered with, once both sides have met. `None`
    /// before that: there is nothing to confirm until there are digits.
    token: Option<String>,
    /// Cancels the driving task, which is what abandons the ceremony — dropping
    /// the stream is how the other side learns it is over.
    task: tokio::task::AbortHandle,
}

/// Everything a ceremony needs to run and to reach the app that asked for it.
///
/// Cloneable and long-lived, unlike the per-call host that borrows it.
#[derive(Clone)]
pub struct Ceremonies {
    pub runtime: Arc<DeviceRuntime>,
    pub users: UserRegistry,
    pub sessions: crate::agent::sessions::SessionMap,
    pub base: PathBuf,
    pub db: Arc<SqlitePool>,
    pub record_stores: RecordStores,
    /// So a guest that calls `infer` while a ceremony is running gets the same
    /// answer it would from any other frame.
    pub infer_proxy: Arc<crate::infer_proxy::InferProxy>,
    pub paired_keys: Arc<std::sync::RwLock<std::collections::HashSet<[u8; 32]>>>,
    pub pending_confirms: kotton_peer::daemon::nodes::PendingConfirms,
    pub live_instances: Arc<Mutex<HashMap<String, kotton_app::daemon::apps::LongLivedInstance>>>,
    pub events: Arc<kotton_diag::service::EventBus>,
    pub surface: Arc<SurfaceProxy>,
    pub runner: PathBuf,
    pub secrets: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync>,
    /// The per-user databases, for the two things a push needs to read: which
    /// app holds the `shell` designation, and the store `app_message` opens.
    pub user_dbs: crate::db::user_db::UserDbMap,
    /// The live per-account event-log tasks, carried for the one reason
    /// `device_db` below is: an occupant host built here can take an unlock,
    /// and an unlock starts the account's log again. Not used here.
    pub event_log_tasks: crate::event_log::EventLogTasks,
    /// kdeviced's configuration pool and the live connected-peer set, carried
    /// for one reason: a pairing frame builds an occupant host to push to, and
    /// that host needs the read-only machine projection like every other one.
    /// Neither is read here.
    pub device_db: Arc<SqlitePool>,
    pub connected_peers: Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
    /// The revoke-only handle on browser admissions, carried for the same one
    /// reason as the two above: a host built here needs it. Not used here.
    pub browsers: crate::agent::browser_channel::BrowserAdmissions,
    /// Carried for the host a push builds, like the three above: a guest the
    /// push reaches may write a hand-over into Inbox, and that host tells the
    /// sync engine so. Not used here.
    pub hand_overs: kotton_sync::engine::HandOverSignal,
    /// One ceremony per user. A second `pair_start` replaces the first rather
    /// than racing it — two live ceremonies on one screen have no meaning, and a
    /// person pressing the button twice means *start over*.
    running: Arc<Mutex<HashMap<String, Running>>>,
    /// One *join* per user, in its own map beside the one above.
    ///
    /// Two maps and not one, because a join and a contact pairing are two
    /// ceremonies with two screens: sharing a slot would make opening
    /// Settings › Networking cancel the pairing somebody was halfway through,
    /// and `confirm` would answer whichever of the two wrote the slot last.
    /// See [`super::joining`].
    pub(super) joining: Arc<Mutex<HashMap<String, super::joining::RunningJoin>>>,
    /// The relay an admitted invite offered each user's device, by its line,
    /// awaiting their yes (`joining.take-relay`). Kept here and never handed
    /// to the guest as anything it could send back: the yes names nothing.
    /// See [`super::joining`].
    pub(super) offered: Arc<Mutex<HashMap<String, kotton_wire::line::InstanceLine>>>,
}

impl Ceremonies {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime: Arc<DeviceRuntime>,
        users: UserRegistry,
        sessions: crate::agent::sessions::SessionMap,
        base: PathBuf,
        db: Arc<SqlitePool>,
        record_stores: RecordStores,
        infer_proxy: Arc<crate::infer_proxy::InferProxy>,
        paired_keys: Arc<std::sync::RwLock<std::collections::HashSet<[u8; 32]>>>,
        pending_confirms: kotton_peer::daemon::nodes::PendingConfirms,
        live_instances: Arc<Mutex<HashMap<String, kotton_app::daemon::apps::LongLivedInstance>>>,
        events: Arc<kotton_diag::service::EventBus>,
        surface: Arc<SurfaceProxy>,
        runner: PathBuf,
        secrets: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync>,
        user_dbs: crate::db::user_db::UserDbMap,
        event_log_tasks: crate::event_log::EventLogTasks,
        device_db: Arc<SqlitePool>,
        connected_peers: Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
        browsers: crate::agent::browser_channel::BrowserAdmissions,
        hand_overs: kotton_sync::engine::HandOverSignal,
    ) -> Self {
        Self {
            runtime,
            users,
            sessions,
            base,
            db,
            record_stores,
            infer_proxy,
            paired_keys,
            pending_confirms,
            live_instances,
            events,
            surface,
            runner,
            secrets,
            user_dbs,
            event_log_tasks,
            device_db,
            connected_peers,
            browsers,
            hand_overs,
            running: Arc::new(Mutex::new(HashMap::new())),
            joining: Arc::new(Mutex::new(HashMap::new())),
            offered: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Begin a ceremony for `app_id` on `user_id`'s behalf, as either side.
    ///
    /// Returns as soon as the task is spawned. Everything the person sees after
    /// this arrives at `on-message`.
    pub async fn start(&self, user_id: String, side: Side) -> Result<(), String> {
        // A second ceremony replaces the first. Aborting before spawning means
        // there is never a window with two, which a person pressing the button
        // twice would otherwise open.
        self.cancel(&user_id).await;

        let this = self.clone();
        let uid = user_id.clone();
        let task = tokio::spawn(async move { this.drive(uid, side).await });
        self.running.lock().await.insert(
            user_id,
            Running {
                token: None,
                task: task.abort_handle(),
            },
        );
        Ok(())
    }

    /// Answer the digits for the ceremony `app_id` is running.
    pub async fn confirm(&self, user_id: &str, matched: bool) -> Result<(), String> {
        let token = self
            .running
            .lock()
            .await
            .get(user_id)
            .and_then(|r| r.token.clone())
            .ok_or_else(|| {
                "there are no digits to answer: no ceremony of this app's is waiting on a \
                 comparison"
                    .to_string()
            })?;
        // Infallible today (it fires a oneshot and acknowledges), but the
        // signature says otherwise and a swallowed error here would be a verdict
        // the ceremony never heard — the person would be left looking at digits
        // that never resolve.
        kotton_peer::daemon::nodes::confirm_code(&self.pending_confirms, token, matched)
            .await
            .map_err(|e| format!("answering the comparison: {e}"))?;
        Ok(())
    }

    /// Abandon whatever this user had running. Idempotent.
    pub async fn cancel(&self, user_id: &str) {
        if let Some(prev) = self.running.lock().await.remove(user_id) {
            prev.task.abort();
        }
    }

    /// Drive one ceremony's stream to its end, pushing every frame.
    async fn drive(self, user_id: String, side: Side) {
        let out = match side {
            Side::Start { label, ttl_seconds } => {
                kotton_device::users::contacts::handle_contact_pair_start(
                    Arc::clone(&self.runtime),
                    Arc::new(self.users.clone())
                        as Arc<dyn kotton_device::users::residency::Residency>,
                    self.pending_confirms.clone(),
                    user_id.clone(),
                    label,
                    ttl_seconds,
                )
                .await
            }
            Side::Join { code, label } => {
                kotton_device::users::contacts::handle_contact_pair_join(
                    Arc::clone(&self.runtime),
                    Arc::new(self.users.clone())
                        as Arc<dyn kotton_device::users::residency::Residency>,
                    self.pending_confirms.clone(),
                    user_id.clone(),
                    code,
                    label,
                )
                .await
            }
        };

        let mut rx = match out {
            Ok(rx) => rx,
            // A ceremony that refuses before it starts still owes the screen a
            // sentence — an unopenable ceremony that says nothing looks to a
            // person exactly like one that is still thinking. A refusal is an
            // `Err` or a frame on the stream: the handler's type is the
            // stream, so there is no one-frame answer to read here (#120).
            Err(e) => {
                self.push(
                    &user_id,
                    RunnerPairingState::Failed {
                        reason: e.to_string(),
                    },
                )
                .await;
                self.running.lock().await.remove(&user_id);
                return;
            }
        };

        while let Some(frame) = rx.recv().await {
            // The token is taken out of the frame and kept here rather than
            // pushed: see the module doc.
            if let UserResponse::PairShowCode { token, .. } = &frame {
                if let Some(r) = self.running.lock().await.get_mut(&user_id) {
                    r.token = Some(token.expose().to_owned());
                }
            }
            let Some(state) = as_state(frame) else {
                continue;
            };
            let last = matches!(
                state,
                RunnerPairingState::Paired { .. } | RunnerPairingState::Failed { .. }
            );
            self.push(&user_id, state).await;
            if last {
                break;
            }
        }
        self.running.lock().await.remove(&user_id);
    }

    /// The app the ceremony's frames go to, and the store to read it from.
    ///
    /// The `shell` designation in the user's own `app_roles` — the same reading
    /// that decides whether a host call is serviced at all. Not a value any
    /// caller supplies: a guest that could name the target could aim a push at
    /// another app.
    async fn shell_app(&self, user_id: &str) -> Option<(String, Arc<SqlitePool>)> {
        let user_db = super::dispatch::user_db_for(
            &self.runtime,
            &self.users,
            &self.user_dbs,
            &self.base,
            Some(user_id),
        )
        .await
        .ok()?;
        let app_id = kotton_app::daemon::db::role_db::get_role(&user_db, "shell")
            .await
            .ok()
            .flatten()?;
        Some((app_id, user_db))
    }

    /// Hand one pairing frame to the shell, as an `on-message` push.
    async fn push(&self, user_id: &str, state: RunnerPairingState) {
        self.push_frame(user_id, PAIRING_FRAME_KIND, &state).await;
    }

    /// Hand one frame of any sender to the shell.
    ///
    /// Named-frame rather than pairing-shaped, because there is a second
    /// sender: joining a network pushes its own states on the same channel
    /// under [`JOINING_FRAME_KIND`]. Everything below this line — resolving the
    /// shell designation, building the three hosts, handing the message over —
    /// is common to both and is not duplicated.
    pub(crate) async fn push_frame<T: serde::Serialize>(
        &self,
        user_id: &str,
        kind: &str,
        body: &T,
    ) {
        let msg = match serde_json::to_string(&HostFrame::new(kind, body)) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(kind, "could not encode a host frame: {e}");
                return;
            }
        };
        let Some((app_id, user_db)) = self.shell_app(user_id).await else {
            tracing::warn!(kind, "a host frame had nowhere to go: no app holds the shell designation");
            return;
        };
        let host = super::app_host::app_host(
            &self.events,
            &self.surface,
            self.runner.as_path(),
            &self.base,
            self.secrets.as_ref(),
            &self.users,
            self.hand_overs.clone(),
        );
        let occupant = super::occupant_host::occupant_host(
            &self.runtime,
            &self.users,
            &self.sessions,
            &self.base,
            &self.db,
            &self.record_stores,
            self,
            &self.user_dbs,
            &self.event_log_tasks,
            &self.device_db,
            &self.connected_peers,
            &self.surface,
            self.browsers.clone(),
        );
        let infer = super::infer_host::infer_host(
            &self.runtime,
            &self.record_stores,
            Some(user_id.to_string()),
            &self.infer_proxy,
        );
        // The person's kept records (`schema.kept`), for the same person infer
        // answers for: any app may hold `schema.read`, so this is not occupant-gated.
        let records = super::record_access::records_host(&self.runtime, &self.users, &self.base, &self.record_stores, Some(user_id.to_string()));
        if let Err(e) = kotton_app::daemon::apps::app_message(
            &host,
            &user_db,
            &self.base,
            Arc::clone(&self.live_instances),
            app_id.clone(),
            msg,
            Some(user_id.to_string()),
            Some(&occupant),
            Some(&infer),
            Some(&records),
        )
        .await
        {
            tracing::warn!(%app_id, kind, "could not hand a host frame to the shell: {e}");
        }
    }
}

/// Which side of the ceremony this node is on.
pub enum Side {
    Start {
        label: Option<String>,
        ttl_seconds: u64,
    },
    Join {
        code: String,
        label: Option<String>,
    },
}

/// The stream's frames, as the surface sees them.
///
/// Frames with no surface meaning map to `None` and are skipped rather than
/// shown as an error: the stream carries machinery the person has no use for.
fn as_state(resp: UserResponse) -> Option<RunnerPairingState> {
    match resp {
        UserResponse::PairAdvertising { code, .. } => {
            Some(RunnerPairingState::Advertising { code })
        }
        // Six digits, zero-padded, because the two people are reading them to
        // each other: `042 137` is a thing to say and `42137` is a different
        // number said the same way. The grouping the frame's own doc uses is the
        // surface's to apply.
        UserResponse::PairShowCode {
            sas, peer_label, ..
        } => Some(RunnerPairingState::Compare {
            digits: format!("{sas:06}"),
            peer_label,
        }),
        UserResponse::ContactPaired { did, label } => Some(RunnerPairingState::Paired {
            // An empty label is no label. The surface draws a name or a
            // fingerprint, and `Some("")` would have it draw neither.
            contact: RunnerContact {
                did,
                label: (!label.is_empty()).then_some(label),
            },
        }),
        UserResponse::PairFailed { reason } => Some(RunnerPairingState::Failed { reason }),
        UserResponse::Error { message } => Some(RunnerPairingState::Failed { reason: message }),
        _ => None,
    }
}
