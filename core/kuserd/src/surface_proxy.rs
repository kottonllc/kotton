// SPDX-License-Identifier: AGPL-3.0-or-later
//! kuserd's end of the surface channel to `kuid`.
//!
//! ## One connection, not one per message
//!
//! kuid has no socket to open: `kuserd` makes the pair before forking and
//! hands kuid the far end, so there is exactly one connection and it lasts as
//! long as the process does.
//!
//! Reconnect logic never appears. Connection
//! lifetime *is* process lifetime, and `supervise_kuid` already owns restart:
//! it makes a new pair, calls [`SurfaceProxy::attach`], and on exit calls
//! [`SurfaceProxy::detach`]. There is no state where a stale connection needs
//! re-establishing, because a broken pair means a dead child.
//!
//! ## Why a mutex rather than a channel
//!
//! Requests are request/response and the far end answers them in order, so
//! sends have to be serialised. A mutex says that directly. Contention is not
//! a concern at surface-patch rates, and the alternative — a writer task with a
//! queue — would add a place for patches to pile up unobserved.
//!
//! ## Both directions, one wire
//!
//! kuserd sends `KuidRequest` and reads the reply, and everything kuid has to
//! *say* — input events, a patch it could not apply, a window the user closed —
//! arrives here too, as [`CompositorEvent`], and not on kuserd's **named**
//! socket as a client with a bearer token (see [`kotton_wire::kuid_ipc`]).
//!
//! That makes this a two-direction channel on one descriptor, which is what the
//! reader task below is for. It cannot be avoided by adding a second
//! `socketpair`: the child rebuilds its end from the standard streams, because
//! doing it from a bare fd needs `unsafe` and the workspace denies it, so there
//! are exactly two std handles and a second pair would land on the same two.
//! The discriminator therefore lives in the frame — [`FromCompositor`] — and
//! the reader routes by it.
//!
//! Replies go to the one outstanding request (the mutex guarantees there is at
//! most one); events go to the sink kuserd drains. An event needs no reply, so
//! nothing flows back the other way for it.
//!
//! ## Who holds which surface
//!
//! `kuid` is told a minted [`SurfaceHandle`] for every surface, not an
//! `app_id`, and the association an app id would carry — *which app holds this
//! surface* — lives on this side of the wire, in [`SurfaceProxy::owners`].
//!
//! It is here rather than on the daemon because this is the one object that
//! spans both directions of the channel: the same type that sends `SurfaceOpen`
//! is the one that receives the keystroke that has to be routed back. A second
//! home would be a second answer.
//!
//! What this buys is not tidiness. Given an app id, `kuid` could decide which
//! surface is the desktop by comparing it against a hardcoded
//! `"sh.kotton.shell"` — the designation losing to a constant in the process
//! least entitled to hold it, which `launch_designated_shell` exists to end
//! (`agent/compositor.rs`). With no app id on this wire there is nothing to
//! compare.
//!
//! ## What is sent before a compositor attaches
//!
//! The daemon opens the shell's surface as part of booting, and `kuid` is a
//! child process that takes milliseconds to come up. On the owner's machine
//! the `SurfaceOpen` arrives here about 14 ms before [`SurfaceProxy::attach`]
//! does; dropped, `kuid` would buffer every commit for a surface nobody had
//! told it about, and no window would ever open.
//!
//! So a request sent with no writer attached is **held**, per surface, and
//! written in order when one attaches. Dropping still exists, behind a bound
//! that **frames cannot fill at structure's expense**.
//! [`Held`] carries the rules — an open is held once, a close cancels a held
//! open, geometry and stacking keep only their latest, and commits accumulate as
//! an ordered run because `0x02` mutation batches are incremental. The bounds
//! are [`BACKLOG_SURFACES`] and [`BACKLOG_BYTES`], and only the second one ever
//! drops anything an app sent.
//!
//! A queue that bounded *requests* and dropped the newest at the bound would
//! put frames and structure in one queue: one drawing app fills sixty-four
//! slots in a second or two, and then the `SurfaceOpen` of the next window is
//! what gives way — the same defect under a new name, on exactly the path
//! `detach` keeps open while `supervise_kuid` backs off for up to sixty
//! seconds.
//!
//! The backlog lives *inside* the same lock as the writer, which is what makes
//! "in order" true rather than hoped for: [`SurfaceProxy::send`] cannot take the
//! lock while a flush holds it, so a request racing the attach lands behind the
//! held ones instead of overtaking them.
//!
//! The other repair — have the daemon await the compositor before launching the
//! shell — is not taken: it couples the shell's launch to a process a headless
//! machine never spawns, and a headless machine is a real one.

use kotton_ipc::{read_frame, write_frame};
use kotton_wire::{CompositorEvent, FromCompositor, KuidRequest, KuidResponse};
use kotton_wire::SurfaceHandle;
use std::collections::{HashMap, VecDeque};
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::warn;

/// How many *surfaces* the backlog holds while no compositor is attached.
///
/// The bound is on surfaces rather than on requests, and that is the whole
/// repair over the first version of this queue. A bound on requests is a bound a
/// **drawing app fills**: one app committing frames pushes the queue to its
/// limit in a second or two, and then the next `SurfaceOpen` — a window the
/// person just asked for — is the thing that gives way. Frames are unbounded in
/// number and structure is not, so they cannot share a bound.
///
/// Only a surface nobody has held anything for yet can be refused here, and only
/// when sixty-four others are already held. No amount of drawing creates an
/// entry, so no amount of drawing can push out an open or a close.
const BACKLOG_SURFACES: usize = 64;

/// How many bytes of held commit payload the backlog holds, across all surfaces.
///
/// Commits are the only variable-size thing here and one frame may be up to
/// `kotton_ipc::MAX_FRAME_LEN` (32 MiB), so a count would not be a bound on
/// memory. **Structure is never dropped for this**: exceeding it evicts held
/// *frames*, starting with the run of whichever surface is holding the most —
/// the app that filled it loses its own frames rather than a quiet window losing
/// its two boot patches.
const BACKLOG_BYTES: usize = 4 * 1024 * 1024;

/// The bytes of `req` that are not a fixed-size field.
///
/// Only two variants carry any: a commit's patch, and the title on an open.
/// Every other variant is a handle and a couple of integers, so its contribution
/// to a memory bound is noise and is counted as nothing.
fn payload_bytes(req: &KuidRequest) -> usize {
    match req {
        KuidRequest::SurfaceCommit { patch, .. } => patch.len(),
        KuidRequest::SurfaceOpen { title, .. } => title.len(),
        _ => 0,
    }
}

/// Which surface `req` is about. Every *surface* variant on this wire addresses
/// one, which is what lets the backlog be keyed by surface at all.
///
/// `None` for the platform's prompts, which are the compositor's
/// own layer and no surface's — and which are never held: a question asked of a
/// desk that is not there is answered *no desk* now ([`SurfaceProxy::ask`]),
/// not asked later of whoever attaches.
fn handle_of(req: &KuidRequest) -> Option<SurfaceHandle> {
    match req {
        KuidRequest::SurfaceOpen { handle, .. }
        | KuidRequest::SurfaceCommit { handle, .. }
        | KuidRequest::SurfaceClose { handle }
        | KuidRequest::SurfaceResize { handle, .. }
        | KuidRequest::SurfaceSetTitle { handle, .. }
        | KuidRequest::SurfaceRaise { handle }
        | KuidRequest::SurfaceRestore { handle } => Some(*handle),
        KuidRequest::PromptRaise { .. } | KuidRequest::PromptWithdraw { .. } => None,
    }
}

/// The prompts the platform has asked and not yet heard back on, by id — each
/// a slot the reader fulfils when [`CompositorEvent::PromptAnswered`] arrives.
type Prompts = std::sync::Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<Option<String>>>>>;

/// Why a prompt could not be asked: there is no desk to ask it on.
///
/// A headless machine, a compositor between restarts, or one that refused the
/// frame. The verb that needed the answer is refused in these words rather than
/// taken without it — the prompt is the verb's guard, not a courtesy.
pub const NO_DESK: &str =
    "there is no desktop to ask on — this needs the person's answer on the platform's own prompt, \
     and no compositor is drawing one";

/// What is being held for one surface, and the one place the rules about
/// superseding live.
///
/// **Kept, because it is structure and there is at most one of each:**
///
/// - `open` — held once. A surface is opened once; the handle is minted per
///   surface and never reused, so there is no second open to reconcile.
/// - `close` — and it **cancels a held open**: if `kuid` was never told the
///   surface exists, the honest delivery is nothing at all. Without that rule a
///   window opens on the glass that nothing will ever close, and
///   [`SurfaceProxy::close`] has already dropped the owner, so it is not even in
///   [`SurfaceProxy::windows`] for the person to act on.
/// - `resize`, `title` and `front` (raise/restore) — **latest wins**. Each is a
///   single current wish — about geometry, about what the window is called,
///   about stacking — and an older one is not a step towards the newer one.
///
/// **Kept whole, and deliberately not coalesced:**
///
/// - `commits` — an ordered run. It is tempting to keep only the newest, and it
///   would be wrong: `0x02` mutation batches are *incremental* and are the
///   primary path (`guest/sdk/kotton-app/src/render.rs`). The
///   shell's own boot is `commit_css` (a `0x01` document establishing `<head>`
///   and an empty `<body>`) followed by `commit_component` (a `0x02` batch
///   against that body) — two patches, measured on the welcome screen's boot.
///   Keeping "the latest" there delivers the batch without the document it
///   mutates, which is the welcome screen not drawing. `kuid` says the same
///   thing from its side about its own buffer: *"a surface may send multiple
///   patches before Open fires … so we queue all of them and replay in order"*
///   (`core/kuid/src/main.rs`).
#[derive(Default)]
struct Held {
    open: Option<KuidRequest>,
    resize: Option<KuidRequest>,
    /// The latest title. One slot, because a title is a single current wish
    /// about what the frame says and an older one is not a step towards it.
    title: Option<KuidRequest>,
    /// The ordered run of commits, oldest first. Never partially dropped — a
    /// suffix of incremental batches applied to a document that never got its
    /// earlier ones is corruption wearing a frame's clothes.
    commits: VecDeque<KuidRequest>,
    /// [`payload_bytes`] summed over [`Self::commits`].
    commit_bytes: usize,
    /// This surface's run was evicted for the byte bound, so its held frames are
    /// no longer a run and further ones are refused rather than held as a
    /// fragment. The window still opens; what it shows is whatever the app draws
    /// next.
    run_evicted: bool,
    /// The latest raise/restore. One slot for both: each is the same ask — put
    /// this window in front of the person — and the newer one is the live wish.
    front: Option<KuidRequest>,
    close: Option<KuidRequest>,
}

impl Held {
    /// Everything held for this surface, in the order it must cross.
    ///
    /// Open, then geometry, then what the frame says, then the frames in the
    /// order they were drawn, then the stacking ask, then the close.
    fn into_requests(self) -> Vec<KuidRequest> {
        let mut out = Vec::with_capacity(3 + self.commits.len());
        out.extend(self.open);
        out.extend(self.resize);
        out.extend(self.title);
        out.extend(self.commits);
        out.extend(self.front);
        out.extend(self.close);
        out
    }
}

/// The half of a live pair that kuserd writes on, plus the slot the reader task
/// fulfils replies into.
struct Writer {
    /// The child's stdin.
    ///
    /// Boxed rather than typed as `ChildStdin` so the tests below can drive the
    /// real [`SurfaceProxy::send`] and [`SurfaceProxy::attach`] over a `duplex`
    /// without spawning a process — the same move [`crate::infer_proxy`] made,
    /// and for the same reason. The security property is untouched by it: it
    /// comes from the descriptors being *handed to the child at spawn*, not from
    /// their Rust type. What the spawn site passes is still a pipe pair, which
    /// exists on every platform this builds for where `tokio::net::unix` does
    /// not.
    half: Box<dyn AsyncWrite + Unpin + Send>,
    /// Set by [`SurfaceProxy::send`] before it writes, taken by the reader when
    /// a [`FromCompositor::Response`] arrives. At most one at a time — the
    /// mutex around the whole [`Channel`] is what makes that true.
    pending: std::sync::Arc<std::sync::Mutex<Option<oneshot::Sender<KuidResponse>>>>,
}

/// The writer, if one is attached, and what is waiting for one.
///
/// One lock over both, deliberately. Two would be two orders — the order things
/// were queued in and the order they are written in — and the whole point of the
/// backlog is that there is only one.
#[derive(Default)]
struct Channel {
    /// `None` before the first attach, and again once the child exits.
    writer: Option<Writer>,
    /// What is held for each surface, in the order the surfaces were first seen.
    ///
    /// A `Vec` rather than a map plus a separate order: the order *is* the
    /// structure, at most [`BACKLOG_SURFACES`] entries are ever in it, and a
    /// linear scan of sixty-four handles at surface-patch rates is nothing. Two
    /// structures would be two things that can disagree about which surfaces
    /// exist.
    ///
    /// **Not cleared by [`SurfaceProxy::detach`].** After a compositor exits the
    /// surfaces it drew are gone, so what is held across a restart is mostly
    /// frames a fresh `kuid` has no surface for — and `kuid` already buffers
    /// exactly those. Holding them is no worse than dropping them, and it keeps
    /// the case that matters, which
    /// `a_request_sent_after_a_detach_is_held_for_the_next_attach` and
    /// `a_flood_of_frames_cannot_evict_an_open_or_a_close` are the proof of: a
    /// surface opened while the compositor is down still opens when it returns.
    backlog: Vec<(SurfaceHandle, Held)>,
    /// [`Held::commit_bytes`] summed over [`Self::backlog`], kept as it changes
    /// so the bound is a comparison rather than a walk of every run per send.
    backlog_bytes: usize,
}

/// kuserd's handle on the surface channel.
pub struct SurfaceProxy {
    conn: Mutex<Channel>,
    /// Where [`CompositorEvent`]s go. Set once at startup by
    /// [`SurfaceProxy::on_event`]; the reader task clones it per attach.
    events: std::sync::Mutex<Option<mpsc::UnboundedSender<CompositorEvent>>>,
    /// Which app holds each open surface — the host's private map.
    ///
    /// **Not on the wire, and that is the point.** `kuid` is told a handle, a
    /// tier and a title; the association between a handle and an app is written
    /// here, by [`SurfaceProxy::open`], and read here, by
    /// [`SurfaceProxy::owner`], when an event comes back up. A compositor that
    /// could name the owner of the surface it is reporting would be asserting
    /// something only this daemon knows.
    ///
    /// A `std::sync::Mutex` rather than tokio's: every access is a map lookup
    /// with no await inside it, and `owner` is called from the event drain where
    /// an async lock would be a lock held across a routing decision for no
    /// reason.
    owners: std::sync::Mutex<HashMap<SurfaceHandle, SurfaceOwner>>,
    /// The app stack, as the compositor last reported it.
    ///
    /// Front-most last. Written by the event drain when
    /// [`CompositorEvent::WindowsChanged`] arrives and read when the designated app asks
    /// for the window list, which is why it is held rather than requested: a guest is
    /// blocked on that ask, and asking the display server inside it would put a process
    /// that is free to be slow in the path of a call it is not otherwise part of.
    ///
    /// Empty until the first report, which is the truth on a headless node — there is no
    /// compositor, so there are no windows, and the list says so rather than inventing the
    /// surfaces this daemon opened into nothing.
    windows: std::sync::Mutex<Vec<kotton_wire::kuid_ipc::CompositorWindow>>,
    /// **The platform's prompts, asked and not yet answered.**
    ///
    /// Shared with the reader task, which fulfils a slot the moment the answer
    /// arrives — **not** through the event sink. The sink is drained one event at
    /// a time by `handle_compositor_event`, and the verb waiting on this answer is
    /// usually being serviced *inside* one of those events: the shell's click is
    /// an input event, its handler calls `landlord.drop-pool`, and that call is
    /// what raised the prompt. An answer queued behind the event that is waiting
    /// for it would never be read.
    prompts: Prompts,
    /// The last prompt id handed out. Ids are this daemon's, per process, and
    /// mean nothing but *which question*.
    next_prompt: std::sync::atomic::AtomicU64,
}

/// What this daemon privately knows about a surface it opened.
///
/// **Never on any wire.** `kuid` is told a handle, a role and a title; the association
/// between a handle, an app and the name the person approved is written here and read here.
/// It is more than a bare `app_id` because a window list has to say what each window is
/// *called*, and the honest source for that is the name this
/// daemon sent to be drawn, not the copy the display server holds.
struct SurfaceOwner {
    app_id: String,
    /// `manifest.app.name`, as the install prompt showed it. The host's word,
    /// written here when the surface was opened and never by a guest.
    name: String,
    /// What the holder calls this surface — `surface.set-title`, bounded to
    /// [`kotton_wire::MAX_TITLE_CHARS`] before it reaches this daemon.
    ///
    /// **Kept here and not asked of the compositor.** `kuid` draws the title
    /// because it draws the frame, and its window reports deliberately carry no
    /// strings at all ([`kotton_wire::kuid_ipc::CompositorWindow`]) — a list
    /// assembled from what `kuid` was told would be this daemon quoting its own
    /// words back through a process that has no need to be trusted with them.
    /// So the copy every window list is built from is this one.
    title: Option<String>,
}

impl Default for SurfaceProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl SurfaceProxy {
    pub fn new() -> Self {
        Self {
            conn: Mutex::new(Channel::default()),
            events: std::sync::Mutex::new(None),
            owners: std::sync::Mutex::new(HashMap::new()),
            windows: std::sync::Mutex::new(Vec::new()),
            prompts: Prompts::default(),
            next_prompt: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Route [`CompositorEvent`]s to `sink` from here on.
    ///
    /// Called once during daemon startup, before any pair is attached. An event
    /// arriving with no sink installed is dropped with a warning rather than
    /// buffered: the alternative is a queue that fills during a startup failure
    /// and then replays a flood of stale keystrokes into whatever launched
    /// afterwards.
    pub fn on_event(&self, sink: mpsc::UnboundedSender<CompositorEvent>) {
        *self.events.lock().unwrap() = Some(sink);
    }

    /// Take ownership of kuserd's end of a freshly created pair.
    ///
    /// Called before the child is spawned, so a surface event racing the spawn
    /// finds a channel rather than a hole.
    ///
    /// # Unix only, and deliberately absent rather than emulated
    ///
    /// A `socketpair` handed to a child at spawn is what makes this channel
    /// unforgeable: there is no path, so there is no admission check to write.
    /// Windows has the analogue — an inheritable handle passed as a standard
    /// stream — and nobody has written it: a handed surface channel for
    /// Windows is not built.
    ///
    /// The gap is stated here, at the one method that cannot exist without it,
    /// rather than papered over with a connect-by-name fallback. A fallback
    /// would give kuid a socket to connect to, on one platform, silently — which is how a platform quietly
    /// becomes the one where the thesis does not hold.
    ///
    /// Not `#[cfg]`-guarded. It carried `#[cfg(unix)]` from when it took a
    /// `UnixStream`; the attribute outlived the signature by a few hours and
    /// broke the Windows build a third time. `ChildStdin` and `ChildStdout`
    /// exist on every platform tokio supports.
    pub async fn attach<W, R>(&self, write_half: W, read_half: R)
    where
        W: AsyncWrite + Unpin + Send + 'static,
        R: AsyncRead + Unpin + Send + 'static,
    {
        // Already two independent handles -- a pipe pair arrives split, where a
        // socket had to be halved.
        let pending: std::sync::Arc<std::sync::Mutex<Option<oneshot::Sender<KuidResponse>>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));

        let events = self.events.lock().unwrap().clone();
        tokio::spawn(read_from_compositor(
            Box::new(read_half),
            std::sync::Arc::clone(&pending),
            events,
            std::sync::Arc::clone(&self.prompts),
        ));

        let mut guard = self.conn.lock().await;
        guard.writer = Some(Writer {
            half: Box::new(write_half),
            pending,
        });

        // Everything sent before there was anywhere to send it, in the order it
        // must cross, before this lock is released to anyone else. A held
        // `SurfaceOpen` is the window opening at all; the run behind it is the
        // frames that were drawn into nothing.
        let queued = guard.drain();
        if !queued.is_empty() {
            tracing::info!(
                held = queued.len(),
                "SurfaceProxy: compositor attached; delivering what was held"
            );
        }
        let mut rest = queued.into_iter();
        for req in rest.by_ref() {
            // The pair broke mid-flush. What is left goes back on the backlog
            // for the next attach rather than into a dead pipe one frame at a
            // time.
            if !guard.write_one(req).await {
                break;
            }
        }
        for req in rest {
            guard.hold(req);
        }
    }

    /// Drop our end, because the child that held the other one is gone.
    pub async fn detach(&self) {
        let mut guard = self.conn.lock().await;
        guard.writer = None;
    }

    /// Record who holds `handle`, then tell `kuid` to open it.
    ///
    /// The recording happens first and unconditionally, including on a headless
    /// node where the send is dropped: the map is what routes a *future* event,
    /// and a surface whose owner was never written down is one whose keystrokes
    /// have nowhere to go.
    pub async fn open(
        &self,
        handle: SurfaceHandle,
        app_id: &str,
        spec: kotton_wire::SurfaceSpec,
    ) -> io::Result<()> {
        self.owners.lock().unwrap().insert(
            handle,
            SurfaceOwner {
                app_id: app_id.to_string(),
                name: spec.title.clone(),
                title: None,
            },
        );
        let kotton_wire::SurfaceSpec {
            role,
            edge,
            title,
            width,
            height,
        } = spec;
        self.send(KuidRequest::SurfaceOpen {
            handle,
            role,
            edge,
            title,
            width,
            height,
        })
        .await
    }

    pub async fn commit(&self, handle: SurfaceHandle, patch: Vec<u8>) -> io::Result<()> {
        self.send(KuidRequest::SurfaceCommit { handle, patch })
            .await
    }

    pub async fn close(&self, handle: SurfaceHandle) -> io::Result<()> {
        self.owners.lock().unwrap().remove(&handle);
        self.send(KuidRequest::SurfaceClose { handle }).await
    }

    pub async fn resize(&self, handle: SurfaceHandle, width: u32, height: u32) -> io::Result<()> {
        self.send(KuidRequest::SurfaceResize {
            handle,
            width,
            height,
        })
        .await
    }

    /// Record what the holder calls `handle`, and tell the compositor to draw it.
    ///
    /// **Both halves, and the order matters less than the fact that there are two.** The
    /// record here is what [`Self::windows`] answers from, so a dock sees the new title on
    /// its next paint whether or not a compositor is attached; the send is what puts it in
    /// the frame. A surface this daemon has no owner for is one that closed while the call
    /// was in flight — the record is simply not written, and nothing is forwarded either,
    /// because a title for a surface that is gone is a title `kuid` would hold forever.
    ///
    /// The string arrived already cut to [`kotton_wire::MAX_TITLE_CHARS`]: the bound is
    /// applied where the handle is resolved against the asking instance's own surfaces
    /// (`core/app`'s `bounded_title`), so no unbounded copy is ever stored here.
    pub async fn set_title(&self, handle: SurfaceHandle, title: String) -> io::Result<()> {
        {
            let mut owners = self.owners.lock().unwrap();
            let Some(owner) = owners.get_mut(&handle) else {
                return Ok(());
            };
            owner.title = Some(title.clone());
        }
        self.send(KuidRequest::SurfaceSetTitle { handle, title })
            .await
    }

    /// Forward a guest's ask that `handle` be brought to the front.
    ///
    /// Nothing is checked here. The handle came out of the asking guest's own
    /// resource table, so it is one that guest holds; what happens to it is
    /// `kuid`'s call.
    pub async fn raise(&self, handle: SurfaceHandle) -> io::Result<()> {
        self.send(KuidRequest::SurfaceRaise { handle }).await
    }

    /// Drop the record of a surface that is already gone.
    ///
    /// For the direction [`Self::close`] does not cover: the *person* dismissed
    /// the window, so `kuid` dropped the layer and told us about it rather than
    /// being told. Without this the map keeps an entry for a surface nothing can
    /// draw on, and a later event for that handle would be routed to an app
    /// that no longer holds it — the first bug a `handle -> app_id` map can
    /// have, and the reason it is written here beside the map rather than left
    /// to the caller.
    pub fn forget(&self, handle: SurfaceHandle) {
        self.owners.lock().unwrap().remove(&handle);
    }

    /// Which app holds `handle`, if this daemon opened it.
    ///
    /// `None` for a handle nobody opened — which is what a forged one would be,
    /// though nothing can forge one: the compositor only ever reports handles
    /// this daemon sent it.
    pub fn owner(&self, handle: SurfaceHandle) -> Option<String> {
        self.owners
            .lock()
            .unwrap()
            .get(&handle)
            .map(|o| o.app_id.clone())
    }

    /// Record the app stack the compositor just reported, and answer whether it moved.
    ///
    /// Last one wins, wholesale: the compositor sends what it has rather than a diff, so
    /// there is no order to reconcile and no state here that can drift from the glass.
    ///
    /// **The answer is what decides whether the designated app is nudged**, so the
    /// dock's window list is not as stale as its last repaint, which is why it is
    /// the compositor's report that is compared and not the joined list [`Self::windows`]
    /// builds. A window the person closed is taken out of `owners` by the close event,
    /// which can reach this daemon before the report that drops it from the stack; the
    /// joined list would already have lost it by then and would read the report as no
    /// change. The report cannot: it is what the glass says, before and after.
    ///
    /// And an unchanged report is not a nudge. That is what keeps the nudge from being a
    /// loop — the dock repaints, the pill resizes, and a panel is not in this list — and
    /// what keeps a compositor that reports on every repaint from making the dock repaint
    /// on every repaint.
    pub fn note_windows(&self, windows: Vec<kotton_wire::kuid_ipc::CompositorWindow>) -> bool {
        let mut held = self.windows.lock().unwrap();
        let moved = *held != windows;
        *held = windows;
        moved
    }

    /// Every open `Window` surface, in the host's words.
    ///
    /// **The join that makes the list the host's view.** The compositor says which windows
    /// are in the stack, in what order, and which are minimised — the half only it knows.
    /// This daemon says what each one is called, out of [`SurfaceOwner`] — the half only it
    /// knows.
    ///
    /// Two strings come out of the second half and they are not interchangeable: `name` is
    /// the host's attribution, which no guest writes, and `title` is what the holder called
    /// the window through `surface.set-title`. The guest's words travel — that is what a
    /// title is for — and they travel in a field that says *what this window is about* and
    /// can never be mistaken for the one that says whose it is.
    ///
    /// A handle the daemon has no owner for is **dropped**, not listed with a placeholder:
    /// it is a surface closed while the report was in flight, and a window in the list that
    /// nothing can be said about is a row the person cannot act on.
    pub fn windows(&self) -> Vec<kotton_wire::HostWindow> {
        let owners = self.owners.lock().unwrap();
        self.windows
            .lock()
            .unwrap()
            .iter()
            .filter_map(|w| {
                owners.get(&w.handle).map(|o| kotton_wire::HostWindow {
                    handle: w.handle,
                    name: o.name.clone(),
                    title: o.title.clone(),
                    minimised: w.minimised,
                })
            })
            .collect()
    }

    /// Forward the designated app's ask that a window be brought back to the person.
    ///
    /// The handle was resolved on the caller's side from the asking instance's own list of
    /// ids, so it is a window that instance was shown. What happens to it is `kuid`'s.
    pub async fn restore(&self, handle: SurfaceHandle) -> io::Result<()> {
        self.send(KuidRequest::SurfaceRestore { handle }).await
    }

    /// **Ask the person the platform's question, on the compositor's prompt
    /// layer, and wait at most `within` for what they type.**
    ///
    /// `Ok(Some(typed))` is what was typed; `Ok(None)` is no answer — declined,
    /// replaced by another prompt, the desk gone mid-question, or `within`
    /// running out, in which case the prompt is withdrawn so the desk does not
    /// go on asking a question nobody is waiting on. `Err` is [`NO_DESK`]: there
    /// is no compositor attached, so nothing is asked and nothing is held.
    ///
    /// **Whether the answer is right is the caller's.** This carries the typed
    /// words back and decides nothing about them; the door that raised the
    /// prompt is the one that knows what was asked.
    pub async fn ask(
        &self,
        prompt: kotton_wire::PlatformPrompt,
        within: std::time::Duration,
    ) -> Result<Option<String>, String> {
        let id = self
            .next_prompt
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        let (tx, rx) = oneshot::channel();
        // Registered before the frame is written, as `write_one` registers its
        // reply slot: a person quicker than this task must not find no slot.
        self.prompts.lock().unwrap().insert(id, tx);
        {
            let mut guard = self.conn.lock().await;
            if guard.writer.is_none() || !guard.write_one(KuidRequest::PromptRaise { id, prompt }).await {
                self.prompts.lock().unwrap().remove(&id);
                return Err(NO_DESK.to_string());
            }
        }
        match tokio::time::timeout(within, rx).await {
            Ok(Ok(typed)) => Ok(typed),
            // The reader dropped the slot: the pair closed with the question up.
            Ok(Err(_)) => Ok(None),
            Err(_) => {
                self.prompts.lock().unwrap().remove(&id);
                let _ = self.send(KuidRequest::PromptWithdraw { id }).await;
                Ok(None)
            }
        }
    }

    /// Send one request, or hold it until a compositor attaches.
    ///
    /// Always returns `Ok`. A compositor that is not running, or a channel that
    /// broke mid-frame, must not fail the app that was drawing — the reason the
    /// old name said "fire and forget". It never was: when there is a writer it
    /// awaits the response. Only the *errors* are forgotten.
    ///
    /// **Holding, not dropping, is what changed in 2026-09.** With no writer the
    /// request goes on the backlog and the caller is answered now; it
    /// is written when [`Self::attach`] runs. A caller cannot be told "later"
    /// any other way — `open` is awaited inside a launch, and blocking it on a
    /// process that a headless node never starts is a coupling refused.
    async fn send(&self, req: KuidRequest) -> io::Result<()> {
        let mut guard = self.conn.lock().await;
        if guard.writer.is_none() {
            guard.hold(req);
            return Ok(());
        }
        // The backlog is empty whenever a writer is attached: `attach` drains it
        // under this same lock before releasing it, and the only thing that
        // clears the writer also stops the drain. So writing straight through
        // here cannot overtake anything.
        guard.write_one(req).await;
        Ok(())
    }
}

impl Channel {
    /// Keep `req` for the compositor that has not attached yet.
    ///
    /// Held **per surface**, under the rules on [`Held`]: structure supersedes
    /// or cancels, frames accumulate as a run. Nothing a drawing app sends can
    /// displace an open or a close, because frames and structure do not share a
    /// bound: sharing one would let a drawing app's frames push out the open of
    /// the next window, and that window would never appear.
    fn hold(&mut self, req: KuidRequest) {
        // A prompt is never held — see [`handle_of`]. [`SurfaceProxy::ask`] does
        // not send one without a writer, so this is a withdraw for a desk that
        // has already gone, and a desk that has gone has taken the prompt with it.
        let Some(handle) = handle_of(&req) else {
            tracing::debug!(variant = req.variant_name(), "SurfaceProxy: no desk; a prompt request is not held");
            return;
        };
        let idx = match self.backlog.iter().position(|(h, _)| *h == handle) {
            Some(i) => i,
            None => {
                if self.backlog.len() >= BACKLOG_SURFACES {
                    warn!(
                        variant = req.variant_name(),
                        surface = %handle,
                        held_surfaces = self.backlog.len(),
                        "SurfaceProxy: no surface channel and the backlog is full of other surfaces (request dropped)"
                    );
                    return;
                }
                self.backlog.push((handle, Held::default()));
                self.backlog.len() - 1
            }
        };

        match req {
            KuidRequest::SurfaceOpen { .. } => self.backlog[idx].1.open = Some(req),
            KuidRequest::SurfaceResize { .. } => self.backlog[idx].1.resize = Some(req),
            KuidRequest::SurfaceSetTitle { .. } => self.backlog[idx].1.title = Some(req),
            KuidRequest::SurfaceRaise { .. } | KuidRequest::SurfaceRestore { .. } => {
                self.backlog[idx].1.front = Some(req)
            }
            KuidRequest::SurfaceClose { .. } => {
                let held = &mut self.backlog[idx].1;
                let freed = held.commit_bytes;
                // A close over a held open is the whole exchange cancelling.
                // `kuid` was never told this surface exists, so telling it now
                // and then telling it to forget is two frames of a window that
                // was never wanted — and the owner is already gone from
                // `owners`, so the person could not close it themselves.
                let never_opened = held.open.is_some();
                *held = Held::default();
                if !never_opened {
                    held.close = Some(req);
                }
                self.backlog_bytes -= freed;
                if never_opened {
                    self.backlog.remove(idx);
                }
            }
            KuidRequest::PromptRaise { .. } | KuidRequest::PromptWithdraw { .. } => {
                unreachable!("a prompt has no handle and returned above")
            }
            KuidRequest::SurfaceCommit { .. } => {
                let bytes = payload_bytes(&req);
                if self.backlog[idx].1.close.is_some() {
                    // A frame for a window that is on its way out.
                    return;
                }
                // Make room by evicting whole runs, biggest first, which is the
                // app that filled the budget rather than whoever committed next.
                while self.backlog_bytes + bytes > BACKLOG_BYTES && self.evict_largest_run() {}
                if self.backlog_bytes + bytes > BACKLOG_BYTES || self.backlog[idx].1.run_evicted {
                    let held = &mut self.backlog[idx].1;
                    if !held.run_evicted {
                        let freed = held.commit_bytes;
                        held.commits.clear();
                        held.commit_bytes = 0;
                        held.run_evicted = true;
                        self.backlog_bytes -= freed;
                    }
                    return;
                }
                let held = &mut self.backlog[idx].1;
                held.commit_bytes += bytes;
                held.commits.push_back(req);
                self.backlog_bytes += bytes;
            }
        }
    }

    /// Drop the held frames of whichever surface holds the most, keeping its
    /// structure. `false` when there were none to drop.
    ///
    /// **A run goes whole or not at all.** A `0x02` batch edits the document its
    /// predecessors built, so a surviving suffix would be applied to a document
    /// that never received the earlier ones — a corrupted window rather than a
    /// stale one. Dropping the run leaves the surface opening with whatever the
    /// app draws next, which is the honest outcome and the one stated in the
    /// record.
    fn evict_largest_run(&mut self) -> bool {
        let Some((idx, _)) = self
            .backlog
            .iter()
            .enumerate()
            .map(|(i, (_, h))| (i, h.commit_bytes))
            .filter(|(_, bytes)| *bytes > 0)
            .max_by_key(|(_, bytes)| *bytes)
        else {
            return false;
        };
        let handle = self.backlog[idx].0;
        let held = &mut self.backlog[idx].1;
        let freed = held.commit_bytes;
        let dropped = held.commits.len();
        held.commits.clear();
        held.commit_bytes = 0;
        held.run_evicted = true;
        self.backlog_bytes -= freed;
        warn!(
            surface = %handle,
            dropped,
            freed_bytes = freed,
            "SurfaceProxy: held frames exceed the backlog budget; dropping this surface's run (its window still opens)"
        );
        true
    }

    /// Everything held, in the order it must cross: surfaces in the order they
    /// were first seen, and within a surface the order on [`Held`].
    fn drain(&mut self) -> Vec<KuidRequest> {
        self.backlog_bytes = 0;
        std::mem::take(&mut self.backlog)
            .into_iter()
            .flat_map(|(_, held)| held.into_requests())
            .collect()
    }

    /// Write one request on the attached writer and await its reply.
    ///
    /// Returns `false` when the pair broke, having dropped the writer: nothing
    /// further will succeed on it, so the next caller gets the clear "no
    /// channel" path — now a hold — rather than another write into a dead pipe.
    async fn write_one(&mut self, req: KuidRequest) -> bool {
        let Some(writer) = self.writer.as_mut() else {
            return false;
        };

        // Register the reply slot *before* writing. The reader task is already
        // running, so a compositor that answers instantly would otherwise find
        // no slot and log a stray reply.
        let (tx, rx) = oneshot::channel();
        *writer.pending.lock().unwrap() = Some(tx);

        if let Err(e) = write_frame(&mut writer.half, &req).await {
            warn!(error = %e, variant = req.variant_name(), "SurfaceProxy: send to kuid failed (request dropped)");
            writer.pending.lock().unwrap().take();
            self.writer = None;
            return false;
        }

        match rx.await {
            Ok(KuidResponse::SurfaceOk) => true,
            Ok(other) => {
                warn!(?other, "SurfaceProxy: unexpected response from kuid");
                true
            }
            // The reader dropped the sender, which it does only when the pair
            // closed. Same terminal state as a failed write.
            Err(_) => {
                warn!("SurfaceProxy: surface channel closed awaiting reply (request dropped)");
                self.writer = None;
                false
            }
        }
    }
}

/// Read kuid's side of the pair until it closes, routing by frame kind.
///
/// This is the only reader of the descriptor. A second one would race for
/// buffered bytes and lose a frame silently, which is the same reason the guest
/// runner has exactly one owner of its stdio.
async fn read_from_compositor(
    mut half: Box<dyn AsyncRead + Unpin + Send>,
    pending: std::sync::Arc<std::sync::Mutex<Option<oneshot::Sender<KuidResponse>>>>,
    events: Option<mpsc::UnboundedSender<CompositorEvent>>,
    prompts: Prompts,
) {
    loop {
        let frame = match read_frame::<FromCompositor, _>(&mut half).await {
            kotton_ipc::FrameRead::Frame(frame) => frame,
            // The pair closed. For a channel handed over at spawn that is how
            // the conversation ends, and `supervise_kuid` is already watching
            // the child that held the other end.
            kotton_ipc::FrameRead::EndOfStream => break,
            // The compositor is still there and sent something this end will
            // not read. Said out loud rather than folded into the close above:
            // a stray line on kuid's stdout and a kuid that exited are
            // different events, and only one of them is anybody's fault.
            kotton_ipc::FrameRead::Refused(refusal) => {
                tracing::error!(
                    %refusal,
                    "SurfaceProxy: kuid sent a frame this end refuses; dropping the channel"
                );
                break;
            }
        };
        match frame {
            FromCompositor::Response(resp) => match pending.lock().unwrap().take() {
                Some(tx) => {
                    // The receiver is gone only if `send` was cancelled. Nothing
                    // to do about a reply nobody is waiting for.
                    let _ = tx.send(resp);
                }
                None => warn!(?resp, "SurfaceProxy: reply with no outstanding request"),
            },
            // **Straight to the one waiting, never through the sink** — see
            // [`SurfaceProxy::prompts`] for the deadlock that routing it through
            // the drain would be.
            FromCompositor::Event(CompositorEvent::PromptAnswered { id, typed }) => {
                match prompts.lock().unwrap().remove(&id) {
                    Some(slot) => {
                        let _ = slot.send(typed);
                    }
                    None => tracing::debug!(id, "SurfaceProxy: an answer to a prompt nobody is waiting on"),
                }
            }
            FromCompositor::Event(event) => match &events {
                Some(sink) => {
                    if sink.send(event).is_err() {
                        warn!("SurfaceProxy: event sink closed; compositor events are being lost");
                    }
                }
                None => warn!(
                    variant = event.variant_name(),
                    "SurfaceProxy: compositor event with no sink installed (dropped)"
                ),
            },
        }
    }
    // The pair closed. Wake anyone waiting rather than leaving them hung: the
    // oneshot sender dropping here is what `send`'s `Err(_)` arm reads.
    pending.lock().unwrap().take();
    // And every question the desk was asking: the desk is gone, so none of them
    // is answered, and each asker reads the dropped slot as *no answer*.
    prompts.lock().unwrap().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_wire::SurfaceRole;
    use tokio::io::{AsyncReadExt, DuplexStream};

    /// A compositor that answers without deserialising, deliberately.
    ///
    /// A test double that read `KuidRequest` frames would be a second acceptor
    /// of that type — the thing `channel-check` forbids, and one it could not
    /// tell apart from `kuid` itself. So this reads the length-prefixed frame as
    /// bytes, reports it verbatim, and answers `SurfaceOk`. What the test then
    /// asserts on is the wire, which is the only place the order is real.
    fn fake_compositor(
        mut read: DuplexStream,
        mut write: DuplexStream,
    ) -> mpsc::UnboundedReceiver<String> {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 4];
                if read.read_exact(&mut len).await.is_err() {
                    break;
                }
                let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
                if read.read_exact(&mut body).await.is_err() {
                    break;
                }
                if tx
                    .send(String::from_utf8_lossy(&body).into_owned())
                    .is_err()
                {
                    break;
                }
                if write_frame(
                    &mut write,
                    &FromCompositor::Response(KuidResponse::SurfaceOk),
                )
                .await
                .is_err()
                {
                    break;
                }
            }
        });
        rx
    }

    /// A handle with a value the test can look for in the frame the proxy
    /// wrote. `mint` would do for everything but that one assertion.
    fn handle() -> (uuid::Uuid, SurfaceHandle) {
        let id = uuid::Uuid::from_u128(0x5eed);
        (id, SurfaceHandle::from_uuid(id))
    }

    /// **A report that moved the stack says so, and one that did not says nothing.**
    /// The answer is
    /// whether the designated app is nudged, so a false `true` is a repaint loop and a
    /// false `false` is the stale dock this was built to end.
    ///
    /// The close case is the one that needs the compositor's report and not the joined
    /// list: the close event takes the window out of `owners` first, after which
    /// [`SurfaceProxy::windows`] has already lost it — and the report that drops it from
    /// the stack must still read as a move.
    #[tokio::test]
    async fn a_windows_report_answers_whether_the_stack_moved() {
        use kotton_wire::kuid_ipc::CompositorWindow;
        let proxy = SurfaceProxy::new();
        let (_, h) = handle();
        let spec = || kotton_wire::SurfaceSpec {
            role: SurfaceRole::Window,
            edge: None,
            title: "Files".into(),
            width: 400,
            height: 300,
        };
        proxy.open(h, "sh.kotton.shell", spec()).await.unwrap();
        let open = vec![CompositorWindow { handle: h, minimised: false }];

        assert!(proxy.note_windows(open.clone()), "a window appeared: that is a move");
        assert!(!proxy.note_windows(open.clone()), "the same stack again is not a move");
        assert!(
            proxy.note_windows(vec![CompositorWindow { handle: h, minimised: true }]),
            "a window put away is a move — the dock draws it differently"
        );
        assert!(proxy.note_windows(open.clone()));

        // The person closes it: the close lands first and the owner goes …
        proxy.forget(h);
        assert!(proxy.windows().is_empty(), "the joined list has already lost it");
        // … and the report that follows is still a move, because it is the glass that
        // is compared and not the join.
        assert!(proxy.note_windows(Vec::new()), "a window closed: that is a move");
        assert!(!proxy.note_windows(Vec::new()));
    }

    /// The measured failure, as a test: the shell's surface is opened and
    /// committed 14 ms before `kuid` gets its pipes, and both have to arrive —
    /// in that order — once it does.
    #[tokio::test]
    async fn a_surface_opened_before_the_compositor_attaches_is_delivered_on_attach() {
        let proxy = SurfaceProxy::new();
        let (id, h) = handle();

        proxy
            .open(
                h,
                "sh.kotton.shell",
                kotton_wire::SurfaceSpec {
                    role: SurfaceRole::Window,
                    edge: None,
                    title: "Kotton".into(),
                    width: 1024,
                    height: 768,
                },
            )
            .await
            .expect("an open with no compositor does not fail the launch");
        proxy
            .commit(h, b"\x01<h1>welcome</h1>".to_vec())
            .await
            .expect("a commit with no compositor does not fail the draw");

        // Nothing has been written anywhere yet — there was nowhere to write.
        // The owner was still recorded, which is what routes a later event.
        assert_eq!(proxy.owner(h).as_deref(), Some("sh.kotton.shell"));

        let (kuid_read, daemon_write) = tokio::io::duplex(64 * 1024);
        let (daemon_read, kuid_write) = tokio::io::duplex(64 * 1024);
        let mut seen = fake_compositor(kuid_read, kuid_write);

        proxy.attach(daemon_write, daemon_read).await;

        let first = seen.recv().await.expect("the open crossed");
        let second = seen.recv().await.expect("the commit crossed");
        assert!(first.contains("SurfaceOpen"), "first frame: {first}");
        assert!(
            !first.contains("welcome"),
            "the open carries no patch: {first}"
        );
        assert!(second.contains("SurfaceCommit"), "second frame: {second}");
        assert!(
            second.contains(&id.to_string()),
            "the commit addresses the surface that was opened: {second}"
        );
    }

    /// **The defect the first version of this queue had.** A drawing app floods
    /// the backlog while the compositor is down — `supervise_kuid` backs off for
    /// up to sixty seconds, so this is a second or two of frames — and then a
    /// second window opens and a third one closes. With one bound over frames
    /// and structure, the open and the close were what gave way. Here neither
    /// can be reached by drawing.
    #[tokio::test]
    async fn a_flood_of_frames_cannot_evict_an_open_or_a_close() {
        let proxy = SurfaceProxy::new();
        let (_, drawing) = handle();
        let opening_id = uuid::Uuid::from_u128(0xbee);
        let closing_id = uuid::Uuid::from_u128(0xcafe);
        let opening = SurfaceHandle::from_uuid(opening_id);
        let closing = SurfaceHandle::from_uuid(closing_id);

        // `closing` was opened before the compositor went away, so its open is
        // not held here — only its close is, and a close with no held open has
        // to cross.
        let megabyte = vec![0u8; 1024 * 1024];
        for _ in 0..16 {
            proxy
                .commit(drawing, megabyte.clone())
                .await
                .expect("held or dropped, never an error");
        }
        proxy
            .open(
                opening,
                "com.example.notes",
                kotton_wire::SurfaceSpec {
                    role: SurfaceRole::Window,
                    edge: None,
                    title: "Notes".into(),
                    width: 400,
                    height: 300,
                },
            )
            .await
            .expect("the open is held");
        proxy.close(closing).await.expect("the close is held");

        let (kuid_read, daemon_write) = tokio::io::duplex(64 * 1024);
        let (daemon_read, kuid_write) = tokio::io::duplex(64 * 1024);
        let mut seen = fake_compositor(kuid_read, kuid_write);
        proxy.attach(daemon_write, daemon_read).await;

        let mut frames = Vec::new();
        while let Ok(frame) = seen.try_recv() {
            frames.push(frame);
        }
        assert!(
            frames
                .iter()
                .any(|f| f.contains("SurfaceOpen") && f.contains(&opening_id.to_string())),
            "the open of a window asked for during the flood crossed: {frames:?}"
        );
        assert!(
            frames
                .iter()
                .any(|f| f.contains("SurfaceClose") && f.contains(&closing_id.to_string())),
            "the close crossed: {frames:?}"
        );
        // Sixteen megabytes were committed into a four-megabyte budget, so the
        // drawing surface's run was evicted whole rather than delivered as a
        // fragment.
        assert!(
            !frames.iter().any(|f| f.contains("SurfaceCommit")),
            "no fragment of the evicted run crossed: {frames:?}"
        );
    }

    /// An open held and then closed before anything attached: `kuid` is told
    /// **neither**.
    ///
    /// It was never told the surface exists, so opening it now and closing it in
    /// the next frame is a window flashing onto the glass that nobody asked to
    /// see — and `close` has already dropped the owner, so between those two
    /// frames it is not in `windows()` either and the person could not act on
    /// it.
    #[tokio::test]
    async fn an_open_closed_before_attach_reaches_kuid_as_nothing() {
        let proxy = SurfaceProxy::new();
        let (_, h) = handle();

        proxy
            .open(
                h,
                "com.example.notes",
                kotton_wire::SurfaceSpec {
                    role: SurfaceRole::Window,
                    edge: None,
                    title: "Notes".into(),
                    width: 400,
                    height: 300,
                },
            )
            .await
            .expect("the open is held");
        proxy
            .commit(h, b"\x01<p>gone</p>".to_vec())
            .await
            .expect("held");
        proxy.close(h).await.expect("the close cancels it");

        assert!(
            proxy.conn.lock().await.backlog.is_empty(),
            "nothing is left to send"
        );

        let (kuid_read, daemon_write) = tokio::io::duplex(64 * 1024);
        let (daemon_read, kuid_write) = tokio::io::duplex(64 * 1024);
        let mut seen = fake_compositor(kuid_read, kuid_write);
        proxy.attach(daemon_write, daemon_read).await;

        assert!(
            seen.try_recv().is_err(),
            "a surface kuid never heard of is not opened and then closed"
        );
    }

    /// A surface's frames are a **run**, not a latest: the shell's boot is a
    /// `0x01` document followed by a `0x02` batch against it, and keeping only
    /// the newest would deliver the batch without the document it mutates.
    #[tokio::test]
    async fn the_held_frames_of_a_surface_cross_as_a_run() {
        let proxy = SurfaceProxy::new();
        let (_, h) = handle();

        proxy
            .open(
                h,
                "sh.kotton.shell",
                kotton_wire::SurfaceSpec {
                    role: SurfaceRole::Window,
                    edge: None,
                    title: "Kotton".into(),
                    width: 1024,
                    height: 768,
                },
            )
            .await
            .expect("held");
        proxy
            .commit(
                h,
                b"\x01<html><head><style>body{}</style></head><body></body></html>".to_vec(),
            )
            .await
            .expect("held");
        proxy
            .commit(h, b"\x02{\"edits\":[]}".to_vec())
            .await
            .expect("held");

        let (kuid_read, daemon_write) = tokio::io::duplex(64 * 1024);
        let (daemon_read, kuid_write) = tokio::io::duplex(64 * 1024);
        let mut seen = fake_compositor(kuid_read, kuid_write);
        proxy.attach(daemon_write, daemon_read).await;

        let first = seen.recv().await.expect("the open crossed");
        let second = seen.recv().await.expect("the css document crossed");
        let third = seen.recv().await.expect("the mutation batch crossed");
        assert!(first.contains("SurfaceOpen"), "{first}");
        // The patch is a byte array on the wire, so the format byte is the
        // first element: `0x01` is the document, `0x02` the batch against it.
        assert!(
            second.contains(r#""patch":[1,"#),
            "the 0x01 document is not dropped for the newer batch: {second}"
        );
        assert!(
            third.contains(r#""patch":[2,"#),
            "the 0x02 batch follows it: {third}"
        );
    }

    /// The byte bound evicts whole runs rather than growing, and the structure
    /// of every surface survives it.
    #[tokio::test]
    async fn a_backlog_of_large_patches_is_bounded_by_bytes() {
        let proxy = SurfaceProxy::new();
        let (_, h) = handle();

        proxy
            .open(
                h,
                "sh.kotton.shell",
                kotton_wire::SurfaceSpec {
                    role: SurfaceRole::Window,
                    edge: None,
                    title: "Kotton".into(),
                    width: 1024,
                    height: 768,
                },
            )
            .await
            .expect("held");
        let megabyte = vec![0u8; 1024 * 1024];
        for _ in 0..8 {
            proxy
                .commit(h, megabyte.clone())
                .await
                .expect("held or dropped, never an error");
        }

        let guard = proxy.conn.lock().await;
        assert!(
            guard.backlog_bytes <= BACKLOG_BYTES,
            "held {} bytes",
            guard.backlog_bytes
        );
        assert_eq!(guard.backlog.len(), 1, "the surface is still held");
        assert!(
            guard.backlog[0].1.open.is_some(),
            "the open survives the eviction of the frames behind it"
        );
    }

    /// A surface nobody has held anything for can still be refused — but only by
    /// sixty-four *other surfaces*, never by frames.
    #[tokio::test]
    async fn the_backlog_is_bounded_by_surfaces() {
        let proxy = SurfaceProxy::new();
        for i in 0..(BACKLOG_SURFACES as u128 + 8) {
            let h = SurfaceHandle::from_uuid(uuid::Uuid::from_u128(0x1000 + i));
            proxy
                .open(
                    h,
                    "com.example.notes",
                    kotton_wire::SurfaceSpec {
                        role: SurfaceRole::Window,
                        edge: None,
                        title: "Notes".into(),
                        width: 10,
                        height: 10,
                    },
                )
                .await
                .expect("held or dropped, never an error");
        }
        let guard = proxy.conn.lock().await;
        assert_eq!(guard.backlog.len(), BACKLOG_SURFACES);
    }

    /// A compositor that exits does not take the daemon's next surface with it:
    /// what is sent while it is gone is held for the one that replaces it.
    #[tokio::test]
    async fn a_request_sent_after_a_detach_is_held_for_the_next_attach() {
        let proxy = SurfaceProxy::new();
        let (_, h) = handle();

        let (kuid_read, daemon_write) = tokio::io::duplex(64 * 1024);
        let (daemon_read, kuid_write) = tokio::io::duplex(64 * 1024);
        let mut seen = fake_compositor(kuid_read, kuid_write);
        proxy.attach(daemon_write, daemon_read).await;
        proxy.detach().await;

        proxy
            .open(
                h,
                "sh.kotton.shell",
                kotton_wire::SurfaceSpec {
                    role: SurfaceRole::Window,
                    edge: None,
                    title: "Kotton".into(),
                    width: 1024,
                    height: 768,
                },
            )
            .await
            .expect("the open survives the gap");
        assert!(
            seen.try_recv().is_err(),
            "nothing was written while the compositor was gone"
        );

        let (kuid_read, daemon_write) = tokio::io::duplex(64 * 1024);
        let (daemon_read, kuid_write) = tokio::io::duplex(64 * 1024);
        let mut seen = fake_compositor(kuid_read, kuid_write);
        proxy.attach(daemon_write, daemon_read).await;

        let first = seen
            .recv()
            .await
            .expect("the open reaches the new compositor");
        assert!(first.contains("SurfaceOpen"), "first frame: {first}");
    }

    /// **A desk that asks the person**: a fake compositor that answers each frame
    /// `SurfaceOk` and, when the frame is a prompt, answers it with `typed` — read
    /// as JSON rather than as a `KuidRequest`, for `fake_compositor`'s reason.
    /// `typed: None` stands for a person who declines; `hang` for one who never
    /// answers.
    fn asking_desk(
        mut read: DuplexStream,
        mut write: DuplexStream,
        typed: Option<&'static str>,
        hang: bool,
    ) -> mpsc::UnboundedReceiver<String> {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 4];
                if read.read_exact(&mut len).await.is_err() {
                    break;
                }
                let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
                if read.read_exact(&mut body).await.is_err() {
                    break;
                }
                let frame = String::from_utf8_lossy(&body).into_owned();
                let _ = tx.send(frame.clone());
                if write_frame(&mut write, &FromCompositor::Response(KuidResponse::SurfaceOk))
                    .await
                    .is_err()
                {
                    break;
                }
                let value: serde_json::Value = serde_json::from_str(&frame).unwrap();
                if let (Some(id), false) = (value["PromptRaise"]["id"].as_u64(), hang) {
                    let answer = CompositorEvent::PromptAnswered {
                        id,
                        typed: typed.map(str::to_owned),
                    };
                    if write_frame(&mut write, &FromCompositor::Event(answer)).await.is_err() {
                        break;
                    }
                }
            }
        });
        rx
    }

    fn drop_sam() -> kotton_wire::PlatformPrompt {
        kotton_wire::PlatformPrompt::DropTenant {
            vault: "kotton".into(),
            pool: "sam".into(),
        }
    }

    /// **No desk, no question — and nothing held for the next one.**
    ///
    /// A prompt asked with no compositor attached is refused now, in words, and
    /// is not put on the backlog: a question asked of whoever attaches next would
    /// be a question the person never saw asked, answered on a desk drawn later.
    #[tokio::test]
    async fn a_prompt_with_no_desk_is_refused_and_not_held() {
        let proxy = SurfaceProxy::new();
        let refused = proxy
            .ask(drop_sam(), std::time::Duration::from_secs(5))
            .await
            .expect_err("no desk is no answer");
        assert_eq!(refused, NO_DESK);
        assert!(proxy.conn.lock().await.backlog.is_empty(), "a prompt was held");
        assert!(proxy.prompts.lock().unwrap().is_empty(), "a slot was left waiting");
    }

    /// **The answer reaches the one asking, and never through the event drain.**
    ///
    /// The sink is installed and **never read** here — which is exactly the
    /// daemon's case, where the drain is blocked inside the input event whose
    /// handler raised the prompt. Routed through it, this would hang.
    #[tokio::test]
    async fn a_prompts_answer_reaches_the_asker_without_the_event_drain() {
        let proxy = SurfaceProxy::new();
        let (sink, _never_read) = mpsc::unbounded_channel();
        proxy.on_event(sink);
        let (kuid_read, daemon_write) = tokio::io::duplex(64 * 1024);
        let (daemon_read, kuid_write) = tokio::io::duplex(64 * 1024);
        let mut seen = asking_desk(kuid_read, kuid_write, Some("sam"), false);
        proxy.attach(daemon_write, daemon_read).await;

        let typed = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            proxy.ask(drop_sam(), std::time::Duration::from_secs(5)),
        )
        .await
        .expect("the answer went through the drain and was never read")
        .expect("a desk is attached");
        assert_eq!(typed.as_deref(), Some("sam"));
        let raised = tokio::time::timeout(std::time::Duration::from_secs(5), seen.recv())
            .await
            .expect("no prompt was raised")
            .unwrap();
        assert!(raised.contains("PromptRaise") && raised.contains("\"sam\""), "{raised}");
        assert!(!raised.contains("handle"), "a prompt addressed a surface: {raised}");
        assert!(proxy.prompts.lock().unwrap().is_empty());

        // A person who declines is `None`, not an error: the question was asked.
        let (kuid_read, daemon_write) = tokio::io::duplex(64 * 1024);
        let (daemon_read, kuid_write) = tokio::io::duplex(64 * 1024);
        let _seen = asking_desk(kuid_read, kuid_write, None, false);
        proxy.attach(daemon_write, daemon_read).await;
        let declined = proxy
            .ask(drop_sam(), std::time::Duration::from_secs(5))
            .await
            .expect("a desk is attached");
        assert_eq!(declined, None);
    }

    /// **A question nobody answers is taken down, and one whose desk goes is
    /// answered *no*.** Waiting past `within` withdraws the prompt so the desk
    /// stops asking it; a compositor that exits with the question up leaves the
    /// asker with no answer rather than hung.
    #[tokio::test]
    async fn an_unanswered_prompt_is_withdrawn_and_a_vanished_desk_answers_nothing() {
        let proxy = SurfaceProxy::new();
        let (kuid_read, daemon_write) = tokio::io::duplex(64 * 1024);
        let (daemon_read, kuid_write) = tokio::io::duplex(64 * 1024);
        let mut seen = asking_desk(kuid_read, kuid_write, None, true);
        proxy.attach(daemon_write, daemon_read).await;
        let answer = proxy
            .ask(drop_sam(), std::time::Duration::from_millis(50))
            .await
            .expect("a desk is attached");
        assert_eq!(answer, None);
        // Bounded: a proxy that never writes the raise, or never withdraws, fails
        // here rather than hanging the suite.
        let within = std::time::Duration::from_secs(5);
        let raised = tokio::time::timeout(within, seen.recv()).await.expect("no prompt was raised").unwrap();
        let withdrawn = tokio::time::timeout(within, seen.recv())
            .await
            .expect("the unanswered prompt was not withdrawn")
            .unwrap();
        let id = serde_json::from_str::<serde_json::Value>(&raised).unwrap()["PromptRaise"]["id"].clone();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&withdrawn).unwrap()["PromptWithdraw"]["id"],
            id,
            "{withdrawn}"
        );
        assert!(proxy.prompts.lock().unwrap().is_empty());

        // The desk goes with the question up.
        let (kuid_read, daemon_write) = tokio::io::duplex(64 * 1024);
        let (daemon_read, kuid_write) = tokio::io::duplex(64 * 1024);
        proxy.attach(daemon_write, daemon_read).await;
        let asking = proxy.ask(drop_sam(), std::time::Duration::from_secs(30));
        let closing = async move {
            // Answer the raise's reply, then leave: the pair closes.
            let mut kuid_read = kuid_read;
            let mut kuid_write = kuid_write;
            let mut len = [0u8; 4];
            kuid_read.read_exact(&mut len).await.unwrap();
            let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
            kuid_read.read_exact(&mut body).await.unwrap();
            write_frame(&mut kuid_write, &FromCompositor::Response(KuidResponse::SurfaceOk))
                .await
                .unwrap();
            drop(kuid_write);
            drop(kuid_read);
        };
        let (answer, ()) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async { tokio::join!(asking, closing) },
        )
        .await
        .expect("an asker was left hung by a desk that went away");
        assert_eq!(answer.expect("the question was asked"), None);
    }
}

