// SPDX-License-Identifier: AGPL-3.0-or-later
//! Background sync engine: **a device replicates to its person's drives, and
//! to nothing else.**
//!
//! A drive is a tenancy on a vault: where a person's things live. A device
//! keeps the folders its person chose current with the drive — it sends its
//! changes there and takes the drive's changes from there — and no device is a
//! target of another. That is the storage model the protocol decided ("a
//! drive is where things live, and a device keeps what its person chose"), and
//! it is the one path this engine holds: one design to keep, and one place a
//! person's things are. Two of a person's devices reach each other's writes by
//! way of a drive.
//!
//! **What a pass can name.** [`targets`] is the whole of the engine's
//! targeting, and it takes the drives the drive record holds
//! (`kotton_peer::daemon::drives`) and this device's rules for them
//! (`kotton_peer::daemon::drive_rules`) — a rule names a drive and this
//! device's direction for it, never a node. So what the engine can reach is
//! exactly what the drive record holds, and the record is as good as its
//! writers: enrolment, the daemon's `Recover` after the proof (it takes the
//! vault's line), and the membership projection, each of which names a vault;
//! and the join, which records the drives the admitting device handed over,
//! resting on that device's word inside the SAS-confirmed, identity-attested
//! ceremony — the device that holds the identity, which could put a member in
//! the sealed set or introduce the joiner anywhere already
//! (`kotton_peer::daemon::drives`). No other caller's word makes a node a
//! drive: the `PeerAdd { drive: true }` that recorded any key it was given went
//! with #80, and the record refuses a node paired under another posture,
//! whichever writer hands it the row: the join writes no posture over a row
//! this device holds and replaces none under another key (#105), and a row is
//! the person's and the node's DID's, so no writer's label reaches another row,
//! another person's included (#99). So no
//! device of the person's is a target, and every peer a pass reaches holds no
//! data keys: a pass toward one sends packs and nothing loose
//! ([`ensure_packed_for_peer`]).
//!
//! **What left, with the mesh.** Rules that named a paired node (any node,
//! another of the person's devices among them) and a path nothing read; the
//! trigger that could name one node (`SyncTrigger { node_id }`, and the CLI's
//! `sync now --node`), which is now `SyncDrives` and names none; the bare
//! `sync` that pulled from every paired device in turn, which now syncs this
//! device's drives; and, inside a pass, telling the other end what was pushed
//! (`SyncAvailable`, `RecordSyncAvailable`) and pushing record changesets in
//! the clear to a node holding the data keys. A drive answers none of those;
//! records reach it as sealed segments in the packs, as before.
//!
//! ## Two execution paths
//!
//! 1. **Background loop** — started by [`SyncEngine::spawn_background`].
//!    Syncs the drives whose rule says `watch`, on a 5-minute timer or whenever
//!    [`SyncEngine::wake_background`] is called (e.g. from the VFS watcher).
//!    Passes are untracked (fire-and-forget).
//!
//! 2. **Asked for** — the `SyncDrives` / `SyncAwait` dispatch arms. Syncs
//!    every drive this device has, each in the direction its rule chooses and
//!    both ways where it has none. Creates a tracked `JobId`; callers block via
//!    `await_job` until the pass finishes, fails, or times out.
//!
//! In both paths a running-set prevents two concurrent passes for the same
//! drive (the vault's key and the tenancy).
//!
//! # Tier note
//! This module lives in `06_daemon` for the `device_sync` sprint. The sync
//! logic belongs in `05_runtime`; migration is tracked in
//! `IDEA-tier-discipline`.

use kotton_peer::daemon::drive_rules::DriveRule;
use kotton_peer::daemon::drives::Drive;
use kotton_wire::ipc::{SyncDirection, SyncOutcome, VfsChangeKind};
use kotton_wire::remote::{RemoteBackend, RemoteConfig};
use kotton_store::runtime::user::sync::Outbound;
use kotton_device::DeviceRuntime;
use notify::{EventKind, RecursiveMode, Watcher};
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::sync::{watch, Notify, Semaphore};
use tokio::time::{Duration, interval};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Public VFS change frame type (used by VfsWatch subscribers)
// ---------------------------------------------------------------------------

/// A single VFS change event broadcast from `spawn_fs_watcher` to active
/// `VfsWatch` IPC subscribers (RFC-0017).
///
/// Fields: `(path, kind, timestamp_secs)`
pub type VfsChangeFrame = (String, VfsChangeKind, u64);

// ---------------------------------------------------------------------------
// Polling interval
// ---------------------------------------------------------------------------

/// Polling interval for the background sync loop (5 minutes per RFC-0008).
const POLL_INTERVAL_SECS: u64 = 300;

/// A mount is maintained at least this often while the daemon runs. Time rather
/// than a segment count: RFC-0047 made the same call for object snapshots, and a
/// count heuristic drifts the moment two subsystems append at different rates.
pub const MAINTENANCE_INTERVAL_SECS: u64 = 3600;
/// No sync for this long means the machine is quiet enough for the expensive
/// half (compaction). The floor below keeps that from running constantly.
const IDLE_AFTER_SECS: u64 = 120;
/// Even when idle, do not maintain more often than this.
const MAINTENANCE_FLOOR_SECS: u64 = 300;
/// How soon the loop tries again while a hand-over is still waiting to enter the
/// log — because the mount was held by another writer, or because the wake that
/// announced it arrived while a pass was running and was not stored
/// (`wake_background` keeps no permit; RFC-0071's defect list names it).
const HAND_OVER_RETRY_MILLIS: u64 = 1_000;
/// Retention window handed to the snapshot: history newer than this survives
/// intact. Mirrors the store's own default (RFC-0047's 24h full-granularity
/// window) rather than reaching into that crate's provider module for it.
const MAINTENANCE_KEEP_FULL_SECS: u64 = 24 * 60 * 60;

/// Default semaphore size: at most 4 concurrent target pairs.
const DEFAULT_MAX_PARALLEL: usize = 4;

// ---------------------------------------------------------------------------
// Job state
// ---------------------------------------------------------------------------

type SyncTarget = (String, String); // (user_id, "<vault key hex>/<tenancy>")

/// Observed state of a tracked sync job.
#[derive(Debug, Clone)]
pub enum JobState {
    Queued,
    Running,
    Complete(SyncOutcome),
    Failed(String),
}

struct JobEntry {
    tx: watch::Sender<JobState>,
    created_at: Instant,
}

/// Result returned by [`SyncEngine::await_job`].
pub enum AwaitResult {
    Complete(SyncOutcome),
    Failed(String),
    /// The job id was not found (already evicted or never created).
    NotFound,
    /// The timeout elapsed before the job completed.
    Timeout,
}

/// `user_id`'s live store, or an error naming why not.
///
/// Was `handlers::active_user`, which took the daemon's `UserRegistry` directly.
/// Only this file ever called it, so it travels with the engine rather than
/// staying behind as the one daemon type the engine still had to name. The
/// resolution is the same; the parameter is the seam.
fn active_user(
    resources: &dyn crate::SyncHost,
    user_id: &str,
) -> anyhow::Result<Arc<kotton_store::runtime::user::UserStore>> {
    resources
        .user_store(user_id)
        .ok_or_else(|| anyhow::anyhow!("user '{user_id}' is not active"))
}

// ---------------------------------------------------------------------------
// SyncEngine
// ---------------------------------------------------------------------------

/// Central sync scheduler.  Wrap in `Arc` and share across the daemon.
pub struct SyncEngine {
    db: Arc<SqlitePool>,
    runtime: Arc<DeviceRuntime>,
    /// The host's live per-user resources. A field rather than a parameter on
    /// each method, for the same reason `runtime` is one: the engine outlives any
    /// single call and every pass needs it (RFC-0080 step 6).
    ///
    /// A trait rather than the daemon's three locator types, so nothing in this
    /// file names something that exists only in a binary crate.
    resources: Arc<dyn crate::SyncHost>,
    semaphore: Arc<Semaphore>,
    jobs: Arc<Mutex<HashMap<String, JobEntry>>>,
    /// Currently-running (user_id, node_id) pairs — prevents double-dispatch.
    running: Arc<Mutex<HashSet<SyncTarget>>>,
    /// Wakes the background loop (from non-async contexts such as the VFS watcher).
    notify: Arc<Notify>,
    /// Live mTLS allowlist — reprojected from membership after each sync pass, so a
    /// member admitted on another of the user's nodes (pulled in by the pass) is
    /// admitted here without a restart (RFC-0024 computed view).
    paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    /// When each user's mount was last maintained (monotonic, for the due test).
    last_maintenance: Arc<Mutex<HashMap<String, Instant>>>,
    /// The same event in wall-clock seconds, for reporting it to a human.
    last_maintenance_secs: Arc<Mutex<HashMap<String, i64>>>,
    /// When any sync last ran, for the idle signal.
    last_activity: Arc<Mutex<Instant>>,
    /// The people with a hand-over written into their tree and not yet in its
    /// log (RFC-0090, *A device of your own*): maintenance packs their mount on
    /// the next loop whatever its clock says, under the same lock as ever. Set by
    /// [`Self::hand_over_landed`], cleared when the pack starts — so a write that
    /// lands during that pack sets it again and is taken by the next one.
    hand_overs: Arc<Mutex<HashSet<String>>>,
    /// Unix seconds of the last pass that actually ran, per user.
    ///
    /// `SyncStatus` reported a hardcoded "never" before this, so the CLI said a
    /// sync had never happened no matter what the engine had been doing — the
    /// product misreporting itself, which RFC-0071's defect list names.
    last_sync_at: Arc<RwLock<HashMap<String, i64>>>,
}

impl SyncEngine {
    /// Create a new engine wrapping `db` and `runtime`.
    pub fn new(
        db: Arc<SqlitePool>,
        runtime: Arc<DeviceRuntime>,
        resources: Arc<dyn crate::SyncHost>,
        paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            db,
            runtime,
            resources,
            semaphore: Arc::new(Semaphore::new(DEFAULT_MAX_PARALLEL)),
            jobs: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(Mutex::new(HashSet::new())),
            notify: Arc::new(Notify::new()),
            paired_keys,
            last_sync_at: Arc::new(RwLock::new(HashMap::new())),
            last_maintenance: Arc::new(Mutex::new(HashMap::new())),
            last_maintenance_secs: Arc::new(Mutex::new(HashMap::new())),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            hand_overs: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    /// The per-user pool holding `user_id`'s sync rules; `None` (with a log)
    /// when the user's database cannot be opened — a rule that cannot be read
    /// is a pass that does not run, not a crash.
    async fn user_pool(&self, user_id: &str) -> Option<Arc<SqlitePool>> {
        self.resources.agent_db(user_id).await
    }

    /// When this user's last sync pass ran, in unix seconds.
    pub fn last_sync_at(&self, user_id: &str) -> Option<i64> {
        self.last_sync_at.read().unwrap().get(user_id).copied()
    }

    /// When this user's mount was last maintained, in unix seconds.
    ///
    /// Reported rather than acted on: maintenance that runs invisibly is
    /// indistinguishable from maintenance that never runs, and this session has
    /// found six mechanisms that were the second thing while looking like the
    /// first.
    pub fn last_maintenance_at(&self, user_id: &str) -> Option<i64> {
        self.last_maintenance_secs
            .lock()
            .unwrap()
            .get(user_id)
            .copied()
    }

    /// Record that a pass ran for `user_id`.
    fn mark_synced(&self, user_id: &str) {
        let now = kotton_common::time::now_secs();
        self.last_sync_at
            .write()
            .unwrap()
            .insert(user_id.to_string(), now);
    }

    /// Wake the background loop.  Cheap; safe to call from blocking threads.
    pub fn wake_background(&self) {
        self.notify.notify_waiters();
    }

    /// A hand-over to a device of `user_id`'s has been written into their tree,
    /// and somebody is waiting to see it in the log.
    ///
    /// The write lands loose; it enters the log only when a packing pass commits
    /// it, and the share sheet says *sent* only then
    /// (`TASK-a-hand-over-is-not-in-the-log-until-the-next-packing-pass`). So the
    /// mount is marked for the next loop and the loop is woken: maintenance then
    /// packs it whatever its clock and the idle floor say, under the mount's lock
    /// like every other writer, and nothing else changes — no pass of its own,
    /// and none outside that lock.
    pub fn hand_over_landed(&self, user_id: &str) {
        self.hand_overs.lock().unwrap().insert(user_id.to_string());
        self.wake_background();
    }

    /// Whether any hand-over is waiting to enter a log.
    fn any_hand_over_waiting(&self) -> bool {
        !self.hand_overs.lock().unwrap().is_empty()
    }

    /// Whether a hand-over of `user_id`'s is waiting to enter their log —
    /// marked by [`Self::hand_over_landed`] and not yet taken by a pack.
    pub fn hand_over_waiting(&self, user_id: &str) -> bool {
        self.hand_overs.lock().unwrap().contains(user_id)
    }

    /// The one thing the host's file verbs may tell this engine: that a
    /// hand-over landed. See [`HandOverSignal`].
    pub fn hand_over_signal(self: &Arc<Self>) -> HandOverSignal {
        HandOverSignal(Arc::clone(self))
    }

    /// The drives a pass for `user_id` syncs ([`targets`]): the drive record's,
    /// with this device's rules from the person's own database. A record or a
    /// rule that cannot be read is a pass that syncs nothing, not a crash.
    async fn drive_targets(&self, user_id: &str, background: bool) -> Vec<DriveTarget> {
        let drives = match kotton_peer::daemon::drives::list(&self.db, user_id).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(user_id, error = %e, "sync_engine: the drive record does not read");
                return Vec::new();
            }
        };
        let rules = match self.user_pool(user_id).await {
            Some(pool) => kotton_peer::daemon::drive_rules::rules(&pool, user_id).await.unwrap_or_else(|e| {
                tracing::warn!(user_id, error = %e, "sync_engine: failed to load sync rules");
                Vec::new()
            }),
            None => Vec::new(),
        };
        targets(&drives, &rules, background)
    }

    /// Sync `user_id`'s drives now — every drive this device has, each in the
    /// direction its rule chooses — and return a trackable `(job_id,
    /// drive_count)`. Non-blocking: returns as soon as the worker task is
    /// spawned. A drive already being synced is skipped (coalescing).
    pub async fn enqueue(self: &Arc<Self>, user_id: &str) -> (String, u32) {
        // 1. The drives, keyed for the running set.
        let targets: Vec<(SyncTarget, DriveTarget)> = self
            .drive_targets(user_id, false)
            .await
            .into_iter()
            .map(|t| (target_key(user_id, &t), t))
            .collect();
        let target_count = targets.len() as u32;
        let job_id = Uuid::new_v4().to_string();

        // 2. Create a job entry so callers can await it immediately.
        let (tx, _rx) = watch::channel(JobState::Queued);
        self.jobs.lock().unwrap().insert(
            job_id.clone(),
            JobEntry {
                tx: tx.clone(),
                created_at: Instant::now(),
            },
        );

        if targets.is_empty() {
            // No drives — complete immediately with zero counts.
            let _ = tx.send(JobState::Complete(SyncOutcome {
                files: 0,
                bytes: 0,
                conflicts_resolved: 0,
                duration_ms: 0,
            }));
            return (job_id, 0);
        }

        // 3. Filter out already-running targets (coalescing).
        let to_spawn: Vec<(SyncTarget, DriveTarget)> = {
            let mut running = self.running.lock().unwrap();
            targets
                .into_iter()
                .filter(|(key, _)| running.insert(key.clone()))
                .collect()
        };

        if to_spawn.is_empty() {
            // All targets already running — complete immediately.
            let _ = tx.send(JobState::Complete(SyncOutcome {
                files: 0,
                bytes: 0,
                conflicts_resolved: 0,
                duration_ms: 0,
            }));
            return (job_id, target_count);
        }

        // 4. Spawn aggregate worker task.
        let engine = Arc::clone(self);
        let job_id_task = job_id.clone();
        tokio::spawn(async move {
            let _ = tx.send(JobState::Running);
            let start = Instant::now();
            let mut agg = SyncOutcome {
                files: 0,
                bytes: 0,
                conflicts_resolved: 0,
                duration_ms: 0,
            };
            let mut first_error: Option<String> = None;

            for (key, target) in &to_spawn {
                let _permit = engine.semaphore.acquire().await.ok();
                match sync_drive_with_outcome(&engine.db, &engine.runtime, &*engine.resources, &engine.paired_keys, &key.0, target)
                    .await
                {
                    Ok(o) => {
                        engine.mark_synced(&key.0);
                        agg.files += o.files;
                        agg.bytes += o.bytes;
                        agg.conflicts_resolved += o.conflicts_resolved;
                    }
                    Err(e) => {
                        if first_error.is_none() {
                            first_error = Some(e);
                        }
                    }
                }
                engine.running.lock().unwrap().remove(key);
            }

            agg.duration_ms = start.elapsed().as_millis() as u64;

            let final_state = if let Some(err) = first_error {
                JobState::Failed(err)
            } else {
                JobState::Complete(agg)
            };

            if let Some(entry) = engine.jobs.lock().unwrap().get(&job_id_task) {
                let _ = entry.tx.send(final_state);
            }

            // Evict old completed jobs (simple TTL: 120 s, cap 256 entries).
            engine.evict_old_jobs();
        });

        (job_id, target_count)
    }

    /// Block until job `job_id` completes, fails, or `timeout` elapses.
    pub async fn await_job(&self, job_id: &str, timeout: Duration) -> AwaitResult {
        let rx = {
            let jobs = self.jobs.lock().unwrap();
            jobs.get(job_id).map(|e| e.tx.subscribe())
        };
        let Some(mut rx) = rx else {
            return AwaitResult::NotFound;
        };

        let result = tokio::time::timeout(timeout, async move {
            // Check the current value first (job may already be done).
            loop {
                {
                    let state = rx.borrow();
                    match &*state {
                        JobState::Complete(o) => return Ok(o.clone()),
                        JobState::Failed(msg) => return Err(msg.clone()),
                        _ => {}
                    }
                }
                if rx.changed().await.is_err() {
                    return Err("job dropped unexpectedly".to_string());
                }
            }
        })
        .await;

        match result {
            Ok(Ok(outcome)) => AwaitResult::Complete(outcome),
            Ok(Err(msg)) => AwaitResult::Failed(msg),
            Err(_) => AwaitResult::Timeout,
        }
    }

    /// Maintain every quiet user's mount: pack, snapshot, then compact.
    ///
    /// **The component that holds the mount maintains it.** This lives in the
    /// sync engine because the engine is what claims a mount today — not because
    /// maintenance is a sync concern. A device-scoped maintenance sidecar could
    /// not do this work at all: snapshotting reads the sealed log, which needs
    /// `K_log`, which a device-scoped process deliberately does not have. The
    /// keys are here, so the work is here.
    ///
    /// The order is fixed and not an implementation detail. Packing turns loose
    /// objects into segments, snapshotting collapses those segments, and only
    /// then can compaction see what is genuinely unreferenced. Run out of order
    /// — or concurrently — and the compactor reclaims packs a packing pass has
    /// written but not yet committed.
    async fn maintain_quiet_users(&self) {
        let idle = {
            let last = *self.last_activity.lock().unwrap();
            last.elapsed().as_secs() >= IDLE_AFTER_SECS
        };

        let users: Vec<String> = self.resources.user_ids();

        // **A mark for a person whose store is not resident is dropped.** One
        // who locks before the pack leaves `user_ids`, so nothing below would
        // ever clear their mark and the loop would retry each second until they
        // unlocked. The mark has nothing to say meanwhile: their loose writes
        // are packed once they unlock and the store is resident again.
        self.hand_overs
            .lock()
            .unwrap()
            .retain(|marked| users.iter().any(|u| u == marked));

        for user_id in users {
            // **A hand-over waiting makes the mount due**, whatever the clock
            // below says — first sight, the idle floor and the interval alike.
            // Those rules keep the expensive half off a busy machine; a person
            // who has just chosen a device is waiting on this mount's log, and
            // a pass run now packs exactly what a later one would.
            let handed_over = self.hand_overs.lock().unwrap().contains(&user_id);
            let due = {
                let mut last = self.last_maintenance.lock().unwrap();
                match last.get(&user_id) {
                    // First sight starts the clock; it does not fire.
                    //
                    // A mount seen a moment ago is not overdue, and daemon
                    // startup is the worst moment to take one: the user is
                    // enrolling, pairing and syncing, and maintenance would hold
                    // the mount through all of it. Measured, that is what it
                    // costs — the same pass that takes ~20 ms on a quiet machine
                    // took **25 s** competing with a starting daemon, not because
                    // it had more to do (it scanned 0 segments and exported 1
                    // row) but because it was starved while holding the lock.
                    //
                    // Nothing is skipped by waiting: the idle trigger below
                    // brings the first pass along within minutes of the machine
                    // going quiet, which is when it is cheap.
                    None => {
                        last.insert(user_id.clone(), Instant::now());
                        false
                    }
                    Some(t) => {
                        let secs = t.elapsed().as_secs();
                        secs >= MAINTENANCE_INTERVAL_SECS
                            || (idle && secs >= MAINTENANCE_FLOOR_SECS)
                    }
                }
            };
            if !due && !handed_over {
                continue;
            }

            // Claim the mount itself, and only if it is free.
            //
            // This is the whole correctness argument, and an earlier version of
            // this loop got it wrong: it consulted the engine's `running` set,
            // which is a coalescing set the manual `SyncMount` path never joins,
            // so maintenance ran on top of a user's own sync and lost a record.
            // The mount's lock has no such blind spot — every writer takes it.
            //
            // `try_lock` rather than `lock`: maintenance is never urgent, so it
            // yields to real work and comes back next tick instead of queueing
            // ahead of it.
            //
            // A hand-over yields too, and stays marked: the loop comes back for
            // it within `HAND_OVER_RETRY_MILLIS`, not at the next tick.
            let Some(_mount_lock) = self.runtime.try_lock_mount(&user_id, "local") else {
                tracing::debug!(user_id, "maintenance: mount busy, deferring");
                continue;
            };

            // Cleared before the pack, not after: the file verbs take no mount
            // lock, so a hand-over can land while this pass runs, and whether
            // the pass sees it is a race. Cleared first, that write marks the
            // mount again and the next loop — soon, because it is marked — packs
            // it.
            self.hand_overs.lock().unwrap().remove(&user_id);

            if !due {
                // Only the hand-over: pack, which is what puts it in the log,
                // and leave the snapshot and the compaction to their own clock.
                // A person handing a file over is the opposite of the quiet the
                // idle rule waits for, and the maintenance clock is not reset,
                // so the expensive half still comes when it would have.
                self.pack_handed_over(&user_id).await;
                continue;
            }

            self.maintain_one(&user_id).await;
            self.last_maintenance
                .lock()
                .unwrap()
                .insert(user_id.clone(), Instant::now());
            self.last_maintenance_secs
                .lock()
                .unwrap()
                .insert(user_id.clone(), kotton_common::time::now_secs());
        }
    }

    /// Pack `user_id`'s mount for a hand-over, and nothing else — the first step
    /// of [`Self::maintain_one`], run without the other two. The caller holds
    /// the mount's lock.
    async fn pack_handed_over(&self, user_id: &str) {
        let Some(store) = self
            .resources
            .user_store(user_id)
            .and_then(|user_rt| user_rt.get_remote("local"))
        else {
            return;
        };
        match kotton_store::runtime::pack_mount(&*store, "local").await {
            Ok(Some(s)) => tracing::info!(
                user_id,
                packed = s.files_packed,
                "maintenance: packed a hand-over into the log"
            ),
            Ok(None) => {}
            // Not marked again: a pack that keeps failing would then spin
            // the loop each second. So a failed hand-over waits for the
            // clock's own pass — a limit of this unit, filed as
            // `TASK-a-hand-over-whose-pack-failed-waits-for-the-clock`.
            Err(e) => tracing::warn!(user_id, error = %e, "maintenance: packing a hand-over failed"),
        }
    }

    /// One user's mount, in the one safe order. Every step is best-effort and
    /// logged: a store with no pack layer answers `None` to all three, which is
    /// a correct answer and not a failure.
    async fn maintain_one(&self, user_id: &str) {
        // The runtime handle is held for the whole pass. It used to be dropped
        // here, under a comment saying nothing below needed it — which was not
        // true: `snapshot_records` re-resolved the same user internally, so the
        // narrow borrow described the code rather than what it did. Now that the
        // resolution is the caller's (RFC-0080 step 6), the handle is visible and
        // the pass makes one lookup. Holding it is harmless: the remote set
        // carries its own lock, so a handle here does not block a `remote add`
        // the way it did when that path went through `Arc::get_mut`.
        let Some(user_rt) = self.resources.user_store(user_id) else {
            return;
        };
        let Some(store) = user_rt.get_remote("local") else {
            return;
        };

        match kotton_store::runtime::pack_mount(&*store, "local").await {
            Ok(Some(s)) if s.files_packed > 0 => {
                tracing::info!(user_id, packed = s.files_packed, "maintenance: packed loose objects")
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(user_id, error = %e, "maintenance: packing failed"),
        }

        // Record state rides the same snapshot segment as the objects (RFC-0046
        // slice 5), so this one call bounds both halves of the log. `keep_full_secs`
        // is the retention window, not a switch: segments newer than it survive.
        // This pass is best-effort and returns nothing, so a store that will not
        // open is logged and skipped rather than propagated.
        let record_store = match self.resources.record_store(user_id) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, user_id, "maintenance: record store unavailable");
                return;
            }
        };
        let Some(mount_store) = user_rt.get_remote("local") else {
            tracing::warn!(user_id, "maintenance: no local mount; nothing to snapshot");
            return;
        };
        match kotton_record::replication::snapshot_records(
            &self.runtime.schema_registry,
            &record_store,
            mount_store.as_ref(),
            MAINTENANCE_KEEP_FULL_SECS,
        )
        .await
        {
            Ok(Some(s)) if s.segments_subsumed > 0 => tracing::info!(
                user_id,
                subsumed = s.segments_subsumed,
                "maintenance: snapshotted the log"
            ),
            Ok(_) => {}
            Err(e) => tracing::warn!(user_id, error = %e, "maintenance: snapshot failed"),
        }

        match kotton_store::runtime::compact_mount(&*store, "local").await {
            Ok(Some(s)) if s.packs_rewritten > 0 => {
                tracing::info!(user_id, rewritten = s.packs_rewritten, "maintenance: compacted")
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(user_id, error = %e, "maintenance: compaction failed"),
        }
    }

    /// Start the background polling loop as a detached tokio task.
    pub fn spawn_background(self: Arc<Self>) {
        tokio::spawn(async move {
            // Initial reconciliation pass on startup.
            self.run_background_pass().await;

            let mut ticker = interval(Duration::from_secs(POLL_INTERVAL_SECS));
            ticker.tick().await; // discard the immediate first tick

            loop {
                // Registered before the hand-over check, so a hand-over that
                // lands between the two still wakes this wait.
                let woken = self.notify.notified();
                tokio::pin!(woken);
                woken.as_mut().enable();
                let waiting = self.any_hand_over_waiting();
                let retry = tokio::select! {
                    _ = ticker.tick() => false,
                    _ = &mut woken => {
                        tracing::debug!("sync_engine: triggered by background wake");
                        false
                    }
                    _ = tokio::time::sleep(Duration::from_millis(HAND_OVER_RETRY_MILLIS)), if waiting => true,
                };
                // A hand-over goes into the log before the pass dials anyone:
                // the pass in front of it can be a slow peer, and the person
                // is watching the sheet. The pass then carries the packed copy.
                if self.any_hand_over_waiting() {
                    self.maintain_quiet_users().await;
                }
                if retry {
                    continue;
                }
                self.run_background_pass().await;
                self.maintain_quiet_users().await;
            }
        });
    }

    /// Evict completed job entries older than 120 s, keeping at most 256 total.
    fn evict_old_jobs(&self) {
        const TTL_SECS: u64 = 120;
        const MAX_JOBS: usize = 256;

        let mut jobs = self.jobs.lock().unwrap();
        let now = Instant::now();

        // Remove entries that are done AND older than TTL.
        jobs.retain(|_, entry| {
            let done = matches!(
                *entry.tx.borrow(),
                JobState::Complete(_) | JobState::Failed(_)
            );
            if done && now.duration_since(entry.created_at).as_secs() > TTL_SECS {
                return false;
            }
            true
        });

        // If still over cap, evict oldest completed entries.
        if jobs.len() > MAX_JOBS {
            let mut completed_ages: Vec<(String, Instant)> = jobs
                .iter()
                .filter(|(_, e)| {
                    matches!(*e.tx.borrow(), JobState::Complete(_) | JobState::Failed(_))
                })
                .map(|(id, e)| (id.clone(), e.created_at))
                .collect();
            completed_ages.sort_by_key(|(_, t)| *t);
            let to_remove = jobs.len().saturating_sub(MAX_JOBS);
            for (id, _) in completed_ages.into_iter().take(to_remove) {
                jobs.remove(&id);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Background pass (untracked)
    // -----------------------------------------------------------------------

    async fn run_background_pass(&self) {
        // Each resident person's drives, from the drive record, that this
        // device's rules say the background pass syncs (`watch`). A rule with
        // it off says "sync only when asked", which `sync` still does.
        let mut work: Vec<(SyncTarget, DriveTarget)> = Vec::new();
        for user_id in self.resources.user_ids() {
            for target in self.drive_targets(&user_id, true).await {
                work.push((target_key(&user_id, &target), target));
            }
        }
        if work.is_empty() {
            return;
        }
        tracing::debug!(count = work.len(), "sync_engine: running background pass");

        let mut seen: HashSet<SyncTarget> = HashSet::new();
        for (key, target) in &work {
            if !seen.insert(key.clone()) {
                continue;
            }
            let (user_id, drive) = (key.0.as_str(), target.drive.node.id.as_str());
            // Skip a drive an asked-for pass is already syncing. Maintenance
            // needs no check of its own here: it holds the mount's lock, which
            // this pass takes before it writes anything.
            {
                let mut running = self.running.lock().unwrap();
                if running.contains(key) {
                    tracing::debug!(user_id, drive, "sync_engine: background pass: drive already syncing, skipping");
                    continue;
                }
                running.insert(key.clone());
            }
            match sync_drive_with_outcome(&self.db, &self.runtime, &*self.resources, &self.paired_keys, user_id, target).await {
                Ok(o) => {
                    self.mark_synced(user_id);
                    *self.last_activity.lock().unwrap() = Instant::now();
                    tracing::info!(user_id, drive, files = o.files, "sync_engine: background pass complete");
                }
                Err(e) => tracing::warn!(error = %e, user_id, drive, "sync_engine: background pass failed"),
            }
            self.running.lock().unwrap().remove(key);
        }
    }
}

/// What the host's `files` verbs hold of the sync engine: the one call that says
/// a hand-over landed ([`SyncEngine::hand_over_landed`]).
///
/// A handle rather than the engine, because a person's file tree has no
/// business enqueuing a sync, awaiting a job or reading a peer's status, and a
/// field of type `Arc<SyncEngine>` would let it.
#[derive(Clone)]
pub struct HandOverSignal(Arc<SyncEngine>);

impl HandOverSignal {
    /// A hand-over to a device of `user_id`'s has been written into their tree.
    pub fn landed(&self, user_id: &str) {
        self.0.hand_over_landed(user_id);
    }
}

// ---------------------------------------------------------------------------
// Core sync logic (used by both paths)
// ---------------------------------------------------------------------------

/// One drive a pass syncs, and the direction this device's rule chooses for
/// it (`None` both ways).
#[derive(Debug, Clone)]
pub struct DriveTarget {
    pub drive: Drive,
    pub direction: Option<SyncDirection>,
}

/// **Which drives a pass syncs** — the whole of the engine's targeting, and
/// what it can name: `drives`, the drives the drive record holds for the
/// person, and nothing else. A device is never in it, because nothing that is
/// not a drive is.
///
/// A pass the person asked for (`background == false`) syncs every one of
/// them, each in the direction its rule chooses and both ways where it has
/// none. The background pass syncs only the drives whose rule says `watch`. A
/// rule whose drive is no longer recorded syncs nothing.
pub fn targets(drives: &[Drive], rules: &[DriveRule], background: bool) -> Vec<DriveTarget> {
    drives
        .iter()
        .filter_map(|drive| {
            let rule = kotton_peer::daemon::drive_rules::rule_for(rules, drive);
            if background && !rule.is_some_and(|r| r.watch) {
                return None;
            }
            Some(DriveTarget { drive: drive.clone(), direction: rule.and_then(|r| r.direction.clone()) })
        })
        .collect()
}

/// The running-set key for a drive: the vault's key and the tenancy.
fn target_key(user_id: &str, target: &DriveTarget) -> SyncTarget {
    let key: String = target.drive.vault_key.iter().map(|b| format!("{b:02x}")).collect();
    (user_id.to_string(), format!("{key}/{}", target.drive.tenancy))
}

/// Sync one drive: reach the vault it is kept on through its node, and run the
/// object pass with the sealed record segments riding in its packs
/// ([`sync_mount_with_records`]). Returns a [`SyncOutcome`], or why not.
///
/// Nothing else crosses. Until the replication model changed, a pass toward a
/// paired node went on to tell it what had been pushed (`SyncAvailable`,
/// `RecordSyncAvailable`) and to push this device's record changesets in the
/// clear to a node holding the data keys — another of the person's devices.
/// A drive answers none of those, and no device is a target, so they are gone
/// from the pass: records reach a drive as sealed segments in the packs, and
/// reach another device from there.
async fn sync_drive_with_outcome(
    db: &Arc<SqlitePool>,
    runtime: &Arc<DeviceRuntime>,
    resources: &dyn crate::SyncHost,
    paired_keys: &Arc<RwLock<HashSet<[u8; 32]>>>,
    user_id: &str,
    target: &DriveTarget,
) -> Result<SyncOutcome, String> {
    let start = Instant::now();
    let node = target.drive.node.clone();
    let node_id = node.id.clone();

    // 1. Reach the vault through the node the drive is reached through.
    let prev_addr = node.addresses.first().copied();
    let prev_relay = node.relay_url.clone();
    let vault_did = node.device_did.to_string();
    let client = match resources.open_peer_client(node, user_id, resources.user_store(user_id).as_deref()).await {
        Ok(c) => {
            // Refresh the stored address from the live connection so the next
            // sync dials the current address first, and the relay the vault
            // said it reserves at.
            kotton_peer::daemon::nodes::refresh_observed_peer_address(
                db,
                user_id,
                &vault_did,
                prev_addr,
                c.observed_direct_addr(),
            )
            .await;
            kotton_peer::daemon::nodes::refresh_peer_relay(
                db,
                user_id,
                &vault_did,
                prev_relay.as_deref(),
                c.learned_relay(),
            )
            .await;
            c
        }
        Err(e) => return Err(format!("sync_engine: the drive at '{node_id}' did not answer (will retry): {e}")),
    };

    // 2. A transient (non-persisted) remote for the pass.
    // Named for the vault's key, not the node's label: a label keys no row
    // (`kotton_peer::daemon::db`), so two of the person's drives may be shown
    // under one, and two passes must not share a remote.
    let remote_name: String =
        std::iter::once("__sync_bg__".to_string()).chain(target.drive.vault_key.iter().map(|b| format!("{b:02x}"))).collect();
    let storage = Arc::new(client) as Arc<dyn kotton_sys::store::SyncableStore>;
    let config = RemoteConfig {
        // The vault's DID, not the node's name: the remote's configuration is
        // where every push through it learns who is on the other end
        // (`sync_mount_with_records`).
        backend: RemoteBackend::Kotton {
            peer_did: vault_did.clone(),
            label: node_id.clone(),
        },
        cache_dir: None,
        key_format: kotton_wire::remote::KeyFormat::default(),
    };
    if let Err(e) =
        active_user(resources, user_id).and_then(|user_rt| user_rt.add_remote(remote_name.clone(), storage, config))
    {
        return Err(format!("sync_engine: failed to register transient remote: {e}"));
    }

    // 3. The pass, in this device's direction for the drive. Packing toward a
    //    keyless vault is `sync_mount_with_records`'s, inside its mount lock.
    //    The transient remote is always cleaned up.
    let file_result =
        sync_mount_with_records(runtime, resources, user_id, "local", &remote_name, target.direction.clone()).await;
    let _ = active_user(resources, user_id).and_then(|user_rt| user_rt.remove_remote(&remote_name));
    let r = file_result.map_err(|e| format!("sync_engine: file sync pass failed: {e}"))?;
    tracing::info!(
        user_id,
        drive = %node_id,
        pushed = r.pushed,
        pulled = r.pulled,
        skipped = r.skipped,
        "sync_engine: drive pass complete",
    );
    let bytes: u64 = r.transfers.iter().map(|(_, _, b)| *b).sum();

    // The pass may have pulled new membership records; reproject them into the
    // live allowlist and the drive record, so a device or a drive admitted on
    // another of the person's devices is known here without a restart.
    // Additive and best-effort.
    if let Some(store) = resources.user_store(user_id) {
        kotton_peer::daemon::nodes::project_membership_into_allowlist(store.as_ref(), db, paired_keys, user_id).await;
    }

    Ok(SyncOutcome {
        files: r.pushed + r.pulled,
        bytes,
        conflicts_resolved: 0,
        duration_ms: start.elapsed().as_millis() as u64,
    })
}

/// Run one object sync pass with **record sync riding alongside it** (RFC-0046).
///
/// The single place records and objects sync together, called by both sync entry
/// points — the manual/SDK `SyncMount` handler and the background engine — so a
/// record reaches a peer whichever way a sync is triggered. Four steps:
///
/// 0. **Toward a peer, send only packs**
///    ([`ensure_packed_for_peer`]): pack the mount first, so nothing is left
///    behind, and have the transfer send packs and superblocks and nothing else
///    ([`Outbound::PacksOnly`]), so a loose object never crosses whatever
///    landed after the pack. It is here and not in either caller for the reason
///    the lock below is: until 2026-10-08 the background engine packed first and
///    the `SyncMount` request did not, so a manual push handed a blind vault
///    every loose object at its own sealed length (RFC-0070 M3).
/// 1. **`log_records`** — seal this device's record changes into the history log
///    *before* the pack push, so they replicate as sealed segments inside packs.
/// 2. **`sync_mount`** — the object sync, which moves the packs (segments
///    included, now over the RFC-0048 chunked transport) and reconciles.
/// 3. **`apply_record_segments`** — merge any record segments the peer's packs
///    just delivered into the record store.
///
/// Because records travel as sealed segments in packs, this is safe toward a
/// **blind** peer too — the very reason the old plaintext push had to refuse them
/// (RFC-0041 B3). The record steps are fail-soft: a record failure is logged but
/// does not sink the object sync, whose result is what callers report.
pub async fn sync_mount_with_records(
    runtime: &DeviceRuntime,
    resources: &dyn crate::SyncHost,
    user_id: &str,
    mount: &str,
    remote: &str,
    direction: Option<kotton_wire::ipc::SyncDirection>,
) -> anyhow::Result<kotton_wire::remote::SyncResult> {
    // Claim the mount for the whole pass — sealing records into the log, moving
    // the packs, and reconciling the manifest are one indivisible write.
    //
    // The lock is taken *here*, in the one function both sync entry points call,
    // rather than in each caller. A rule every caller must remember is a rule
    // that holds until someone adds a caller: the engine's `running` set was
    // exactly that, and the manual `SyncMount` handler never joined it.
    let _mount_lock = runtime.lock_mount(user_id, mount).await;

    // Resolve once, for the whole locked pass. This used to happen three times —
    // inside `log_records`, here, and inside `apply_record_segments` — which sat
    // badly with a lock whose whole purpose is to make the three steps one
    // indivisible write: an eviction landing mid-pass could have let the halves
    // run against different handles. One lookup, one handle, one pass.
    let user_rt = resources
        .user_store(user_id)
        .ok_or_else(|| anyhow::anyhow!("user '{user_id}' not found (session locked?)"))?;

    let store = resources.record_store(user_id)?;
    // Resolving which mount carries the record log is the daemon's: it is the
    // only side holding both the user's store and the record domain. The
    // wrappers that used to do it were forwarding and nothing else (RFC-0080
    // step 3).
    let mount_store = user_rt
        .get_remote(mount)
        .ok_or_else(|| anyhow::anyhow!("mount '{mount}' not found for user '{user_id}'"))?;

    // Who is on the other end is the remote's own configuration, so this asks
    // it rather than being told by each caller. Before any write, so a refusal
    // leaves the mount as it found it.
    let outbound = match user_rt.peer_of(remote) {
        Some(peer_did) => {
            let pushes = !matches!(direction, Some(kotton_wire::ipc::SyncDirection::Pull));
            ensure_packed_for_peer(user_id, &peer_did, mount, mount_store.as_ref(), pushes)
                .await
                .map_err(anyhow::Error::msg)?
        }
        // Not a peer: a directory in the person's own key domain.
        None => Outbound::Everything,
    };

    if let Err(e) =
        kotton_record::replication::log_records(&store, mount_store.as_ref()).await
    {
        tracing::warn!(error = %e, user_id, "sync: log_records before sync failed");
    }

    let result = user_rt.sync_mount(mount, remote, direction, outbound).await?;

    match kotton_record::replication::apply_record_segments(
        &runtime.schema_registry,
        &store,
        mount_store.as_ref(),
    )
    .await
    {
        Ok(n) if n > 0 => {
            tracing::info!(user_id, rows = n, "sync: applied record segments from the log")
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, user_id, "sync: apply_record_segments after sync failed"),
    }

    // Whatever the host caches out of the store is refreshed from what just
    // arrived — here, for the reason the lock above is taken here: both entry
    // points pass through this function, and a hook each caller had to
    // remember would be missed by the next one.
    resources.pass_landed(user_id).await;

    Ok(result)
}

/// What a pass may send toward `peer_did`, a drive, packing `mount` first
/// before a push (RFC-0070 M3, carried over from RFC-0045).
///
/// A keyless peer receives only sealed bytes — but object **sizes** are a
/// channel that packing exists to close, and loose objects on the wire reopen
/// it. So toward such a peer the answer is [`Outbound::PacksOnly`]: the
/// transfer sends packs and superblocks and withholds anything loose. That is
/// the property, and it holds at the transfer, not here — ordinary file writes
/// take no mount lock, so a write can land between this pack and the transfer
/// whatever lock the pass holds. The pack before a push is what keeps
/// everything written so far from being left behind; a mount with **no pack
/// layer at all** is refused rather than pushed nothing, since `pack_loose() ==
/// None` means it could never send its files. A pull sends the peer nothing, so
/// it packs nothing.
///
/// **Every peer is answered this way.** Until #80 a peer holding the data keys
/// (a `Full` member) was answered [`Outbound::Everything`], because one of the
/// person's own devices could be a sync target. Since #54 a peer remote is a
/// drive and nothing else, and since #80 no writer of the drive record can make
/// a device one, so that branch had no peer left to answer; it went with the
/// writer, and a pass toward any peer is held to packs. Were a device ever
/// reached again, it would be sent packs, which it can read, and never loose
/// objects.
///
/// Private, with one caller: [`sync_mount_with_records`], which both entry
/// points sync by. A guard each entry point had to remember was a guard the
/// `SyncMount` request forgot.
async fn ensure_packed_for_peer(
    user_id: &str,
    peer_did: &str,
    mount: &str,
    store: &dyn kotton_sys::store::SyncableStore,
    pushes: bool,
) -> Result<Outbound, String> {
    if !pushes {
        return Ok(Outbound::PacksOnly);
    }
    match kotton_store::runtime::pack_mount(store, mount).await {
        Ok(Some(summary)) => {
            tracing::debug!(
                user_id,
                peer_did,
                files = summary.files_packed,
                "sync: pre-push pack pass for a keyless peer"
            );
            Ok(Outbound::PacksOnly)
        }
        Ok(None) => Err(format!(
            "refusing to sync mount '{mount}' to {peer_did} — the peer holds no data keys \
             and this mount has no pack layer, so its files could only cross loose, \
             their sizes in the clear (RFC-0070 M3)"
        )),
        Err(e) => Err(format!(
            "pre-sync pack pass on '{mount}' failed, not syncing to a keyless peer: {e}"
        )),
    }
}


// ---------------------------------------------------------------------------
// VFS filesystem watcher (RFC-0017)
// ---------------------------------------------------------------------------

/// Spawn a filesystem watch task that calls [`SyncEngine::wake_background`]
/// whenever a file is created, modified, or deleted under `<base_dir>/users/`.
/// It also broadcasts a [`VfsChangeFrame`] to all active `VfsWatch` subscribers.
///
/// The watcher runs in a blocking thread (as required by the `notify` crate)
/// and only wakes the tokio runtime when events arrive.
/// Stops the watcher thread when dropped, releasing its inotify instance.
///
/// The thread used to have no way to end. Its loop was `for event in rx`, and the
/// sender lived inside the `Watcher` owned by that same thread's stack — so the
/// sender could not drop while the thread ran, the loop could not end, and the
/// thread held its kernel watch handle for the life of the process.
///
/// That is a leak in a long-running `kuserd` too, not only in tests: every sync
/// engine restart took another instance and never gave one back. `Linux
/// fs.inotify.max_user_instances` defaults to 128, so the 129th silently fails to
/// register.
///
/// Found on 2026-08-24 by consolidating the integration tests into one binary.
/// As 42 processes it was invisible — each exit reclaimed its instances. As one
/// process the 128 ran out partway through the suite and `vfs_watch` waited
/// forever for an event whose watcher had never registered.
#[must_use = "dropping this immediately stops the watcher; hold it for as long as \
              the watch should live"]
pub struct FsWatcherHandle {
    stop: Arc<std::sync::atomic::AtomicBool>,
    ready: watch::Receiver<FsWatchState>,
}

/// What the watcher thread has managed to do, as a subscriber can observe it.
///
/// It exists because *registered* was a fact only the log knew. `spawn_fs_watcher`
/// returns before its thread has created an inotify instance, so a caller that
/// subscribes and immediately writes a file can have the write land before there
/// is anything to catch it — no error, no frame, and nothing that says which of
/// the two happened. `VfsWatch`'s first frame is derived from this, so the answer
/// reaches the subscriber rather than only the operator reading logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsWatchState {
    /// The thread has not finished registering yet.
    Starting,
    /// The watch over `<base>/users/` is registered; changes under it are
    /// broadcast from here on.
    Watching,
    /// Registration failed. No change will ever be delivered.
    ///
    /// The reason travels with it for the same reason the state exists at all:
    /// each of the three failure sites already logs its `notify` error, and a
    /// log is not a place a subscriber can read. `Arc<str>` because every
    /// subscriber clones the state out of the `watch` channel.
    Failed(Arc<str>),
}

impl FsWatcherHandle {
    /// A receiver on the watcher's state, for handing to whoever needs to know
    /// whether the watch is up — `kuserd`'s `VfsWatch` handler, one per
    /// subscription. Read it with [`wait_until_watching`].
    pub fn state(&self) -> watch::Receiver<FsWatchState> {
        self.ready.clone()
    }
}

/// Resolve once the watch is registered, or report why it never will be.
///
/// `Ok(())` means a write under `<base>/users/` from this point on is observed.
/// It reads a *state*, not an event, so a caller that arrives after registration
/// gets the answer immediately rather than waiting for a transition that has
/// already happened.
///
/// `Err(reason)` is `Failed`, or a dropped sender — the watcher thread has ended,
/// so the watch is gone either way, and the caller's business is the same: say so
/// rather than wait. The reason is carried rather than reduced to a bool because
/// the one caller that matters, `kuserd`'s `VfsWatch` handler, puts it on the wire
/// for a client that cannot read this process's logs.
pub async fn wait_until_watching(
    rx: &mut watch::Receiver<FsWatchState>,
) -> Result<(), Arc<str>> {
    loop {
        match &*rx.borrow_and_update() {
            FsWatchState::Watching => return Ok(()),
            FsWatchState::Failed(reason) => return Err(Arc::clone(reason)),
            FsWatchState::Starting => {}
        }
        if rx.changed().await.is_err() {
            return Err(Arc::from(
                "the filesystem watcher stopped before the watch was registered",
            ));
        }
    }
}

impl Drop for FsWatcherHandle {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

pub fn spawn_fs_watcher(
    base_dir: std::path::PathBuf,
    engine: Arc<SyncEngine>,
    vfs_tx: tokio::sync::broadcast::Sender<VfsChangeFrame>,
) -> FsWatcherHandle {
    let watch_dir = base_dir.join("users");
    if !watch_dir.exists() {
        if let Err(e) = kotton_common::fs::create_dir_all_owner_only(&watch_dir) {
            tracing::warn!(
                error = %e,
                path = %watch_dir.display(),
                "fs_watcher: could not create users dir, skipping watch"
            );
            // A channel born in its final state, so a subscriber reads the
            // reason rather than a closed channel.
            let (_failed_tx, failed_rx) = watch::channel(FsWatchState::Failed(
                Arc::from(format!(
                    "could not create {}: {e}",
                    watch_dir.display()
                )),
            ));
            return FsWatcherHandle {
                stop: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                ready: failed_rx,
            };
        }
    }

    let (ready_tx, ready_rx) = watch::channel(FsWatchState::Starting);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);

    std::thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = match notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        }) {
            Ok(w) => w,
            Err(e) => {
                // `error`, not `warn`: nothing recovers from this and nothing else
                // reports it. A caller waiting on VfsChanged waits forever, which
                // is how the inotify exhaustion above presented — as a hang.
                tracing::error!(error = %e, "fs_watcher: failed to create watcher; no VFS change events will be delivered");
                let _ = ready_tx.send(FsWatchState::Failed(Arc::from(format!(
                    "could not create a filesystem watcher: {e}"
                ))));
                return;
            }
        };

        if let Err(e) = watcher.watch(&watch_dir, RecursiveMode::Recursive) {
            tracing::error!(error = %e, path = %watch_dir.display(), "fs_watcher: failed to watch path; no VFS change events will be delivered");
            let _ = ready_tx.send(FsWatchState::Failed(Arc::from(format!(
                "could not watch {}: {e}",
                watch_dir.display()
            ))));
            return;
        }

        tracing::info!(path = %watch_dir.display(), "fs_watcher: watching for changes");
        // The same fact the line above tells an operator, told to subscribers.
        let _ = ready_tx.send(FsWatchState::Watching);

        loop {
            // A timed receive rather than `for … in rx`, so the thread can notice
            // the handle was dropped. The blocking form could never return: the
            // sender is owned by `watcher`, which is owned by this stack.
            // The channel carries `Result<Event, notify::Error>`, so the outer
            // Result is the receive and the inner one is the watch.
            let event_result = match rx.recv_timeout(std::time::Duration::from_millis(250)) {
                Ok(inner) => inner,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if thread_stop.load(std::sync::atomic::Ordering::Relaxed) {
                        tracing::debug!("fs_watcher: handle dropped, releasing watch");
                        break;
                    }
                    continue;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            };
            match event_result {
                Ok(event) => {
                    if matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    ) {
                        tracing::debug!(?event.kind, "fs_watcher: change detected, waking sync engine");
                        engine.wake_background();

                        // Broadcast to VfsWatch subscribers (RFC-0017).
                        let kind = match event.kind {
                            EventKind::Create(_) => VfsChangeKind::Created,
                            EventKind::Remove(_) => VfsChangeKind::Deleted,
                            _ => VfsChangeKind::Modified,
                        };
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        for path in &event.paths {
                            let _ = vfs_tx.send((
                                path.to_string_lossy().into_owned(),
                                kind.clone(),
                                now,
                            ));
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "fs_watcher: watch error");
                }
            }
        }
        // `watcher` drops here, which is what returns the inotify instance.
    });

    FsWatcherHandle {
        stop,
        ready: ready_rx,
    }
}

#[cfg(test)]
mod maintenance_tests {
    use super::*;
    use kotton_store::runtime::user::UserStore;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A host for the scheduling tests.
    ///
    /// Not a stand-in for `kuserd`'s `DaemonUserResources` — these four tests are
    /// about *when* a maintenance pass is due, which is engine-internal clock logic
    /// the host plays no part in. The tests that do depend on real host behaviour
    /// (peer eligibility, packing) stayed in `kuserd` against the real one, because
    /// there a second implementation could drift and pass while the shipped one
    /// fails.
    struct TestHost {
        users: Mutex<HashMap<String, Arc<UserStore>>>,
        base: std::path::PathBuf,
        secrets: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync>,
    }

    #[async_trait::async_trait]
    impl crate::UserResources for TestHost {
        fn user_ids(&self) -> Vec<String> {
            self.users.lock().unwrap().keys().cloned().collect()
        }
        fn user_store(&self, user_id: &str) -> Option<Arc<UserStore>> {
            self.users.lock().unwrap().get(user_id).cloned()
        }
        fn record_store(&self, user_id: &str) -> anyhow::Result<Arc<kotton_record::SqliteRecordStore>> {
            Ok(Arc::new(kotton_record::open::user_record_store(
                &self.base, user_id, self.secrets.as_ref(),
            )?))
        }
        async fn agent_db(&self, _user_id: &str) -> Option<Arc<sqlx::SqlitePool>> {
            None
        }
    }

    #[async_trait::async_trait]
    impl crate::PeerLinks for TestHost {
        async fn open_peer_client(
            &self,
            _node: kotton_wire::peer::PairedNode,
            _user_id: &str,
            _loaded: Option<&UserStore>,
        ) -> anyhow::Result<kotton_peer::KottonPeerObjectStorage> {
            // These four tests never dial: maintenance packs a local mount. A panic
            // here is the assertion that that stays true.
            unreachable!("maintenance scheduling must not open a peer link")
        }
    }
    // `resources` is an `Arc<DaemonUserResources>`; the methods are the trait's.
    
    // Only the tests need this now: they build the daemon's host, so they name
    // daemon types on purpose. The engine's own body no longer names any.
    

    /// Returns the registry too — the engine holds a clone of the same one, so a
    /// test that needs alice's runtime must be handed the registry she was
    /// registered into rather than making an empty one of its own.
    pub(super) async fn engine() -> (
        tempfile::TempDir,
        Arc<DeviceRuntime>,
        Arc<SyncEngine>,
        Arc<dyn crate::SyncHost>,
    ) {
        let mut users: HashMap<String, Arc<UserStore>> = HashMap::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let secrets: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> =
            Arc::new(kotton_secret::MemorySecrets::new());
        let rt = DeviceRuntime::new_with_secrets(
            dir.path().to_owned(),
            kotton_device::config::RuntimeConfig::default(),
            secrets,
        )
        .await
        .expect("DeviceRuntime");
        // `UserStore::create`, not the daemon's `create_user`: that lives on
        // `kuserd`'s `DeviceUsers` extension trait, and this is a real store with
        // real keys built through `store`'s own public constructor.
        let alice_rt = Arc::new(
            UserStore::create(
                "alice",
                "did:key:zAlice",
                dir.path().join("users").join("alice"),
                // With a log key, as an unlocked person's store has: without one
                // a pass packs nothing into a log, and the hand-over tests would
                // be asking a store that cannot answer them.
                kotton_store::runtime::keys::UserKeys::new(Some([7u8; 32]))
                    .with_log("did:key:zAlice", &[3u8; 32]),
                &kotton_store::LocalShelves(kotton_fs::provider::os::OsFilesystem::new()),
            )
            .expect("create user store"),
        );
        users.insert("alice".to_string(), alice_rt);
        let rt = Arc::new(rt);

        let db = Arc::new(
            kotton_record::open_sqlite(&dir.path().join("agent.db"))
                .await
                .expect("db"),
        );
        let resources: Arc<dyn crate::SyncHost> = Arc::new(TestHost {
            users: Mutex::new(users),
            base: dir.path().to_owned(),
            secrets: rt.secrets_arc(),
        });
        let engine = SyncEngine::new(
            Arc::clone(&db),
            Arc::clone(&rt),
            Arc::clone(&resources) as Arc<dyn crate::SyncHost>,
            rt.paired_keys(),
        );
        (dir, rt, engine, resources)
    }

    /// Age `user_id`'s maintenance clock past the interval, so a pass is due.
    ///
    /// First sight deliberately starts the clock rather than firing (daemon
    /// startup is the worst moment to take a mount), so a test that wants the
    /// pass to run has to say the mount has been sitting there a while.
    fn make_due(engine: &Arc<SyncEngine>, user_id: &str) {
        let overdue = Instant::now()
            .checked_sub(Duration::from_secs(MAINTENANCE_INTERVAL_SECS + 1))
            .expect("clock far enough from process start to age");
        engine
            .last_maintenance
            .lock()
            .unwrap()
            .insert(user_id.to_string(), overdue);
    }

    /// Maintenance does not fire the moment it first sees a mount.
    ///
    /// Measured: the pass costs ~20 ms on a quiet machine and **25 s** when it
    /// runs against a starting daemon — starved while holding the mount lock,
    /// with nothing to do (0 segments scanned, 1 row exported). Firing at t=0
    /// put the most expensive possible moment first.
    #[tokio::test]
    async fn a_newly_seen_mount_is_not_maintained_immediately() {
        let (_dir, _rt, engine, _resources) = engine().await;

        engine.maintain_quiet_users().await;
        assert!(
            engine.last_maintenance_at("alice").is_none(),
            "a mount first seen this tick must not be maintained on that tick"
        );

        // Started, not skipped: once the clock says it is due, it runs.
        make_due(&engine, "alice");
        engine.maintain_quiet_users().await;
        assert!(
            engine.last_maintenance_at("alice").is_some(),
            "a mount that has gone an interval without maintenance must be maintained"
        );
    }

    /// The defect this exists for: loose objects were never packed, so the log
    /// was never built, never snapshotted and never compacted. Slice 5's
    /// mechanism shipped and nothing called it.
    ///
    /// A maintenance pass turns writes into a packed, committed store.
    #[tokio::test]
    async fn maintenance_packs_a_mount_that_nothing_else_would_have_packed() {
        let (_dir, _rt, engine, resources) = engine().await;
        let user_rt = resources.user_store("alice").expect("user runtime");

        for i in 0..3 {
            user_rt
                .write_file(&format!("/notes/{i}.md"), b"something worth keeping")
                .await
                .expect("write");
        }

        engine.maintain_one("alice").await;

        // The files survive the pass — the point is that they moved into packs,
        // not that maintenance is destructive.
        for i in 0..3 {
            assert_eq!(
                user_rt
                    .read_file(&format!("/notes/{i}.md"))
                    .await
                    .expect("read after maintenance"),
                b"something worth keeping",
                "maintenance must not lose a file it packed"
            );
        }
    }

    /// Maintenance and sync must never hold one mount at once: a packing pass
    /// writes packs before committing a manifest, and to the compactor those are
    /// indistinguishable from crash debris.
    ///
    /// The claim being tested is the *mount's* lock, not a set private to this
    /// engine. The earlier version of this test held a `maintaining` set that the
    /// manual `SyncMount` path never consulted, so it passed while maintenance
    /// ran on top of a user's sync and lost a record.
    #[tokio::test]
    async fn a_mount_held_by_anyone_is_not_maintained() {
        let (_dir, rt, engine, _users) = engine().await;
        make_due(&engine, "alice");

        // Whoever holds it — another maintenance pass, a background sync, or a
        // sync the user triggered over IPC — takes the same lock.
        let held = rt.lock_mount("alice", "local").await;

        engine.maintain_quiet_users().await;
        assert!(
            engine.last_maintenance_at("alice").is_none(),
            "a mount someone else holds must not be maintained underneath them"
        );

        // And it is deferred, not abandoned: the next tick picks it up.
        drop(held);
        engine.maintain_quiet_users().await;
        assert!(
            engine.last_maintenance_at("alice").is_some(),
            "maintenance must resume once the mount is free"
        );
    }

    /// **A hand-over is packed whatever the maintenance clock says**
    /// (`TASK-a-hand-over-is-not-in-the-log-until-the-next-packing-pass`).
    ///
    /// The mount was seen a moment ago and the machine is busy, so by the clock
    /// nothing is due — and the control shows that is so: the write stays loose.
    /// Once a hand-over is said to have landed, the same call packs it into the
    /// log, and only packs: the snapshot and the compaction keep their clock.
    #[tokio::test]
    async fn a_hand_over_is_packed_whatever_the_maintenance_clock_says() {
        let (_dir, _rt, engine, resources) = engine().await;
        let alice = resources.user_store("alice").expect("alice's store");

        // First sight starts the clock; the engine was made a moment ago, so the
        // machine is not idle either. Nothing is due by any rule but this one.
        engine.maintain_quiet_users().await;
        alice.write_file("/Inbox/beach.jpg", b"a photo of the beach").await.expect("write");
        engine.maintain_quiet_users().await;
        assert_eq!(
            alice.file_logged("/Inbox/beach.jpg").await.expect("logged"),
            None,
            "control: with nothing due and no hand-over, the write must still be loose"
        );

        engine.hand_over_landed("alice");
        engine.maintain_quiet_users().await;
        assert!(
            alice.file_logged("/Inbox/beach.jpg").await.expect("logged").is_some(),
            "a hand-over must be in the log after the next maintenance, whatever its clock"
        );
        assert!(!engine.hand_over_waiting("alice"), "a hand-over packed is no longer waiting");
        assert!(
            engine.last_maintenance_at("alice").is_none(),
            "a hand-over packs and nothing more: the snapshot and compaction keep their own clock"
        );
    }

    /// **A hand-over does not pack on top of another writer** — Done-when's
    /// *without a packing pass running on top of another writer of the mount*.
    /// It waits, still marked, and is packed once the mount is free.
    #[tokio::test]
    async fn a_hand_over_waits_for_a_mount_another_writer_holds() {
        let (_dir, rt, engine, resources) = engine().await;
        let alice = resources.user_store("alice").expect("alice's store");
        alice.write_file("/Inbox/beach.jpg", b"a photo of the beach").await.expect("write");
        engine.hand_over_landed("alice");

        let held = rt.lock_mount("alice", "local").await;
        engine.maintain_quiet_users().await;
        assert_eq!(
            alice.file_logged("/Inbox/beach.jpg").await.expect("logged"),
            None,
            "a mount another writer holds must not be packed underneath it"
        );
        assert!(engine.hand_over_waiting("alice"), "a deferred hand-over must stay marked");

        drop(held);
        engine.maintain_quiet_users().await;
        assert!(
            alice.file_logged("/Inbox/beach.jpg").await.expect("logged").is_some(),
            "the hand-over must be packed once the mount is free"
        );
    }

    /// **A mark for a person whose store is not resident does not outlive the
    /// next maintenance.** Someone who locks before their pack drops out of
    /// the resident users; were their mark kept, nothing would clear it and the
    /// loop would retry each second until they unlocked.
    #[tokio::test]
    async fn a_hand_over_mark_for_a_person_not_resident_is_dropped() {
        let (_dir, _rt, engine, _resources) = engine().await;
        engine.hand_over_landed("carol");
        assert!(engine.hand_over_waiting("carol"), "the mark is set before maintenance");

        engine.maintain_quiet_users().await;
        assert!(
            !engine.hand_over_waiting("carol"),
            "a mark for a person with no resident store must be dropped"
        );
        assert!(!engine.any_hand_over_waiting(), "and nothing is left to retry for");
    }

    /// **The bound**: on an engine whose loop runs, a hand-over is in the log
    /// within seconds — not at the five-minute tick, and not after the hour.
    ///
    /// The loop is given time to park on its wait first, so the wake is what
    /// moves it: without [`SyncEngine::hand_over_landed`]'s wake the loop
    /// sleeps to its tick and this fails at its deadline.
    ///
    /// The deadline is thirty seconds, not five, because what fills it is the
    /// pack, and a pack is slow in an unoptimised build: measured 2026-10-08,
    /// 4.8 s for two small files in `kuserd`'s test build. That is the pass's
    /// own cost, the same a later pass would pay; what this holds is that the
    /// pass starts now rather than at a tick 300 s off.
    #[tokio::test]
    async fn a_hand_over_is_in_the_log_within_seconds_on_a_running_engine() {
        let (_dir, _rt, engine, resources) = engine().await;
        let alice = resources.user_store("alice").expect("alice's store");
        Arc::clone(&engine).spawn_background();
        tokio::time::sleep(Duration::from_millis(300)).await;

        alice.write_file("/Inbox/beach.jpg", b"a photo of the beach").await.expect("write");
        engine.hand_over_signal().landed("alice");

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if alice.file_logged("/Inbox/beach.jpg").await.expect("logged").is_some() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "a hand-over was not in the log within thirty seconds of landing"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// And when nothing is in the way it does run — otherwise the tests above
    /// would pass on a pass that never fires at all.
    #[tokio::test]
    async fn a_quiet_user_is_maintained() {
        let (_dir, _rt, engine, _resources) = engine().await;
        make_due(&engine, "alice");
        engine.maintain_quiet_users().await;
        assert!(
            engine.last_maintenance_at("alice").is_some(),
            "a quiet mount must actually be maintained"
        );
    }
}

#[cfg(test)]
mod fs_watch_readiness_tests {
    use super::maintenance_tests::engine;
    use super::*;

    /// The watcher says when it is up.
    ///
    /// `spawn_fs_watcher` returns before its thread has created an inotify
    /// instance, and until 2026-09-19 *registered* was a fact only the log line
    /// `fs_watcher: watching for changes` knew. A subscriber could not tell "no
    /// file has changed" from "the watch is not up", so a write made straight
    /// after subscribing could vanish with no error
    /// (`TASK-a-watcher-test-times-out-under-a-loaded-suite`). This is the
    /// signal that replaced the log as the answer, and `VfsWatch`'s first frame
    /// is derived from it.
    ///
    /// The deadline is a hang guard. The assertion is on the state, not on time.
    #[tokio::test]
    async fn the_watcher_reports_when_its_watch_is_registered() {
        let (dir, _rt, engine, _resources) = engine().await;
        let (vfs_tx, _vfs_rx) = tokio::sync::broadcast::channel(16);
        let handle = spawn_fs_watcher(dir.path().to_owned(), Arc::clone(&engine), vfs_tx);

        let mut state = handle.state();
        let watching = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            wait_until_watching(&mut state),
        )
        .await
        .expect("the watcher reaches a terminal state rather than staying `Starting`");
        assert_eq!(
            watching,
            Ok(()),
            "the watch over <base>/users/ registers"
        );
        assert_eq!(*state.borrow(), FsWatchState::Watching);
    }

    /// A failure is not a bare "no": the reason the watcher thread had — the one
    /// it writes to the log — is carried in the state, because `kuserd` puts it on
    /// the wire in `VfsWatchFailed` for a client that cannot read this process's
    /// logs. A `Failed` with nothing in it would make that field a fixed sentence.
    #[tokio::test]
    async fn a_failed_watch_carries_the_reason_it_failed() {
        // A base whose `users` cannot be created: the parent is a file.
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("not-a-directory");
        std::fs::write(&base, b"").expect("write the blocking file");

        let (_dir2, _rt, engine, _resources) = engine().await;
        let (vfs_tx, _vfs_rx) = tokio::sync::broadcast::channel(16);
        let handle = spawn_fs_watcher(base.clone(), Arc::clone(&engine), vfs_tx);

        let mut state = handle.state();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            wait_until_watching(&mut state),
        )
        .await
        .expect("a watcher that cannot start says so rather than staying `Starting`");

        let reason = outcome.expect_err("the watch cannot be registered here");
        assert!(
            reason.contains("users"),
            "the reason names the path it could not watch, got {reason:?}"
        );
    }

    /// And the signal is not simply "yes" on a handle nobody is holding: dropping
    /// the handle stops the thread, and a caller arriving afterwards is told the
    /// watch is gone instead of waiting for a readiness that will never come.
    #[tokio::test]
    async fn a_dropped_handle_reports_no_watch_rather_than_waiting() {
        let (dir, _rt, engine, _resources) = engine().await;
        let (vfs_tx, _vfs_rx) = tokio::sync::broadcast::channel(16);
        let handle = spawn_fs_watcher(dir.path().to_owned(), Arc::clone(&engine), vfs_tx);
        let mut state = handle.state();
        // Take the state first, then stop the watcher: this is the ordering a
        // subscription has when a daemon shuts down underneath it.
        drop(handle);

        // `Watching` may already have been observed before the drop landed; what
        // must not happen is an await that never resolves.
        let settled = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            wait_until_watching(&mut state),
        )
        .await;
        assert!(
            settled.is_ok(),
            "a subscription must never wait forever on a watcher that has stopped"
        );
    }
}

#[cfg(test)]
mod drive_target_tests {
    //! The shape of what a pass syncs: drives, in this device's direction for
    //! each, and nothing that is not a drive.
    use super::{targets, DriveRule, SyncDirection};
    use kotton_peer::daemon::drives::Drive;
    use kotton_wire::peer::PairedNode;

    /// A drive under the vault key `[seed; 32]`, reached through the node
    /// `label`. Targeting reads the key, the tenancy and the node; the DID is
    /// only a well-formed one.
    fn a_drive(seed: u8, label: &str) -> Drive {
        Drive {
            vault_key: [seed; 32],
            tenancy: "alice".into(),
            node: PairedNode {
                id: label.into(),
                device_did: kotton_wire::did::Did::parse("did:key:z6MkqQEvkQX8axm6AzW37ZT5bSEJwFnRS7PgYhbrvzKVc4B2").unwrap(),
                public_key: [seed; 32],
                paired_at: 0,
                addresses: vec![],
                relay_url: None,
                posture: Some("blind-storage".into()),
            },
        }
    }

    fn a_rule(drive: &Drive, direction: Option<SyncDirection>, watch: bool) -> DriveRule {
        DriveRule { vault_key: drive.vault_key, tenancy: drive.tenancy.clone(), direction, watch, configured_at: 0 }
    }

    /// **A pass the person asks for syncs every drive**, each in the direction
    /// its rule chooses and both ways where it has none.
    #[test]
    fn an_asked_for_pass_syncs_every_drive_in_its_rules_direction() {
        let (home, attic) = (a_drive(1, "home"), a_drive(2, "attic"));
        let rules = [a_rule(&home, Some(SyncDirection::Pull), false)];
        let got = targets(&[home.clone(), attic.clone()], &rules, false);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].drive.node.id, "home");
        assert!(matches!(got[0].direction, Some(SyncDirection::Pull)));
        assert_eq!(got[1].drive.node.id, "attic");
        assert!(got[1].direction.is_none(), "a drive with no rule syncs both ways");
    }

    /// **The background pass syncs only the drives whose rule watches.**
    #[test]
    fn the_background_pass_syncs_only_watched_drives() {
        let (home, attic, shed) = (a_drive(1, "home"), a_drive(2, "attic"), a_drive(3, "shed"));
        let rules = [a_rule(&home, Some(SyncDirection::Push), true), a_rule(&attic, None, false)];
        let got = targets(&[home, attic, shed], &rules, true);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].drive.node.id, "home");
        assert!(matches!(got[0].direction, Some(SyncDirection::Push)));
    }

    /// **A rule is no target on its own.** A rule kept for a drive that is no
    /// longer recorded — the only thing a rule can name — syncs nothing, in
    /// either pass: what a pass can reach is the drive record and nothing else.
    #[test]
    fn a_rule_without_its_drive_syncs_nothing() {
        let gone = a_drive(4, "gone");
        let rules = [a_rule(&gone, None, true)];
        assert!(targets(&[], &rules, false).is_empty());
        assert!(targets(&[], &rules, true).is_empty());
        // And a rule for one drive does not stand for another tenancy on it.
        let mut other_tenancy = a_drive(4, "gone");
        other_tenancy.tenancy = "bob".into();
        let got = targets(&[other_tenancy], &rules, true);
        assert!(got.is_empty(), "a rule for alice's tenancy watched bob's");
    }
}
