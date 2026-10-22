// SPDX-License-Identifier: AGPL-3.0-or-later
//! Wire protocol between `kotton-daemon` and the `kotton-runner` subprocess.
//!
//! ## Authentication — who may speak on this channel
//!
//! **The process boundary, and nothing else.** Stated here per RFC-0082 rule 6.
//! The runner does not listen anywhere: the daemon spawns it and holds the only
//! ends of its stdin and stdout, so "who may speak" is answered by who forked the
//! process rather than by any check in this file. There is no token, and none
//! would add anything — a party that could inject a frame here already controls
//! the pipe.
//!
//! That makes this the one channel whose authority is genuinely *possessed*
//! rather than asserted, which is why `IDEA-channel-handles-are-the-ladder-not-the-leap`
//! names it the highest-value place to adopt real capability handles: the
//! component model already supplies unforgeable ones and this boundary is
//! currently newline-delimited JSON.
//!
//! The daemon serializes a [`RunnerInput`] to a newline-terminated JSON line and
//! writes it to the runner's stdin. For long-lived apps the init frame is a full
//! `RunnerInput`; subsequent frames are [`RunnerMessage`] (op only, no manifest
//! payload). The runner writes a single [`RunnerOutput`] JSON line to stdout.
//!
//! ## Host calls (RFC-0049, extended by DEC-0045)
//!
//! An ordinary app only ever *answers* the daemon: one op in, one result out.
//! Two guests invert that mid-op, for the same underlying reason — they need a
//! capability the runner process deliberately does not hold, because a sandbox
//! escape must land somewhere with nothing worth stealing:
//!
//! - a **fetcher**, calling the network and writing quarantine while its
//!   `fetch` export runs (credentials and the object store are the daemon's);
//! - the **occupant**, creating or unlocking an identity while `on-input` runs
//!   (key material is the daemon's, and more so).
//!
//! So the runner asks the daemon and waits. During any op, the stdout stream
//! may carry zero or more [`RunnerOutput::HostCall`] frames, each answered by a
//! [`RunnerOp::HostReply`] frame on stdin, before the single terminating
//! result. All of these are additive variants on the existing tagged enums, so
//! every pre-existing app frame is unchanged on the wire.
//!
//! **The interleave is no longer scoped to `Fetch`.** It was, until an app-world
//! op needed it: the occupant's `create-identity` is called from `on-input`, and
//! it returns a recovery phrase, so it cannot be queued as an effect and drained
//! the way `surface::commit` is. Which *calls* a guest may make is still decided
//! by its world, not by which op is in flight.

use serde::{Deserialize, Serialize};

use crate::GrantEnvelope;

/// `impl $ty { pub fn name(&self) -> &'static str }`, naming each variant by
/// its identifier and nothing else.
///
/// The name is the one thing about a frame that can be said to whoever was not
/// its addressee: which kind of frame it was. Every arm matches `{ .. }` and
/// answers `stringify!` of the identifier, so no field can reach the string by
/// construction, and the list cannot drift from the enum because the match has
/// no wildcard: a variant added without its name here does not compile.
macro_rules! variant_names {
    ($ty:ident { $($variant:ident),+ $(,)? }) => {
        impl $ty {
            /// Which variant this is, by its identifier, and nothing of its
            /// fields: what a frame that arrived out of turn may be called in
            /// an error its reader shows to anyone.
            pub fn name(&self) -> &'static str {
                match self {
                    $(Self::$variant { .. } => stringify!($variant),)+
                }
            }
        }
    };
}

/// Input JSON sent to the `kotton-runner` subprocess via stdin on startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerInput {
    pub manifest_toml: String,
    pub wasm_path: String,
    pub app_data_path: String,
    pub envelopes: Vec<GrantEnvelope>,
    /// What the user approved at install, structured.
    ///
    /// **This, not `manifest_toml`, is what the guest may hold.** The manifest
    /// travels too — the sandbox needs the app's identity, kind and role — but
    /// until 2026-08-30 the sandbox also built its capability set *and its
    /// component linker* from `manifest.capabilities`, so an app approved for
    /// nothing still ran with everything it declared
    /// (`TASK-the-approval-is-signed-but-not-enforced`).
    ///
    /// Distinct from `envelopes`, which is the signed attestation and only
    /// exists where an identity key was available to sign one. This is the
    /// decision, which exists either way — bundled apps have it and have no
    /// envelope.
    ///
    /// `#[serde(default)]` so a runner binary from before this field existed
    /// still parses. The default is the empty set, which grants nothing: the
    /// safe direction, and the one that makes a version skew visible as an app
    /// that cannot reach its data rather than one that quietly can.
    #[serde(default)]
    pub approved: Vec<kotton_schemas::CapabilityGrant>,
    pub revoked_ids: Vec<String>,
    pub trusted_issuers: Vec<String>,
    /// Resolved `did:kel` issuer keys (AID → current authoritative key) for grant
    /// signature verification (RFC-0038 8c). The daemon replays the local KEL to
    /// populate own-identity; a `did:kel` issuer absent from this map fails closed.
    /// Empty for a legacy `did:key` user (whose key is carried in the DID itself).
    #[serde(default)]
    pub kel_keys: Vec<(String, [u8; 32])>,
    /// Root directory of the user's local VFS mount. `None` only if the user
    /// context is unavailable (should not occur in normal operation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_vfs_path: Option<String>,
    /// Instantiate into `world occupant` rather than `world app` — i.e. add the
    /// pre-auth `auth` interface to this guest's linker (DEC-0045).
    ///
    /// Set by the daemon for the one app the user designated `shell`, and by
    /// nothing else. It is not a claim the guest makes: the guest never sees
    /// this frame, and a component that imports `auth` while this is `false`
    /// fails to instantiate rather than running without it.
    ///
    /// `#[serde(default)]` so a runner from before this field existed still
    /// parses — false is the safe default in the direction that matters.
    #[serde(default)]
    pub occupant: bool,
    /// This person's roots, as the store knows them (RFC-0071 R11–R16) — or
    /// why they could not be read — and `None` for a guest that is not the
    /// occupant.
    ///
    /// **`None` and the absent interface are the same fact — and the occupant
    /// is never `None`.** `world occupant` is the only world with
    /// `kotton:app/roots` in it, and the host links the interface exactly when
    /// this is `Some`, the arrangement `devices` and `auth` already use. So a
    /// launch into the occupant world sends `Some` every time. A `None` for the
    /// occupant is not "no roots"; it is a component that fails to instantiate,
    /// which is what happened on 2026-09-21 the first time the shell imported
    /// the interface.
    ///
    /// **What it says is one of two things** ([`RunnerRoots`]): *these are the
    /// roots*, which may be none, or *the roots could not be read, and why*.
    /// Until 2026-09-24 every failure below this line — the shell launched for
    /// nobody, no chain to name the person by, a store not loaded or loaded
    /// without keys, an index that would not open — was sent as an **empty**
    /// list, and the file browser drew every one of them as a person with no
    /// places (`TASK-a-roots-failure-is-drawn-as-no-roots`). An empty list now
    /// means exactly that the index opened and holds no roots.
    ///
    /// A snapshot, like `revoked_ids` and `kel_keys` beside it, and for the same
    /// reason: nothing in this unit can create or retarget a root while a guest
    /// runs, so a live port would be marshalling for a value that cannot change.
    /// When creating a root becomes a thing a surface does, this field is the
    /// seam — it becomes a port, exactly as the device roster did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roots: Option<RunnerRoots>,
    pub op: RunnerOp,
}

/// What a launch hands the occupant as its roots: the roots, or why not.
///
/// Two arms rather than a `Vec` that is empty on failure, because those are
/// opposite facts and a surface must draw them differently — *you have no
/// places yet* and *your places could not be read* — and only the daemon, which
/// held the error, can tell them apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "kebab-case")]
pub enum RunnerRoots {
    /// The index opened. These are the roots, in the index's order; an empty
    /// list is a person with none.
    Read(Vec<RunnerRoot>),
    /// The index could not be read, and this is why.
    Unread(RootsUnread),
}

impl RunnerRoots {
    /// The roots, where they were read. `None` is *unread*, never *none*.
    pub fn read(&self) -> Option<&[RunnerRoot]> {
        match self {
            RunnerRoots::Read(roots) => Some(roots),
            RunnerRoots::Unread(_) => None,
        }
    }
}

/// Why a person's roots could not be read, named where the daemon found it.
///
/// **Typed, so the raw error never crosses.** The daemon logs the error chain
/// where the failure happens — that text is for an operator reading a log —
/// and hands the guest the *cause*, which [`Self::words`] turns into the one
/// sentence a person is shown (`TASK-a-roots-failure-is-drawn-as-no-roots`,
/// clause b). Networking's readout put the store's operator-facing chain in
/// front of the owner on 2026-09-24, doubled full stop and all; this enum is
/// the shape that makes that impossible here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RootsUnread {
    /// The shell was launched for nobody: the welcome or the lock screen.
    Nobody,
    /// No KEL chain names this person, so the index cannot be opened under
    /// the right member (RFC-0038 8c).
    NoIdentity,
    /// This person's store is not loaded in the daemon.
    StoreNotLoaded,
    /// This person's store is loaded without keys — locked. The meaning half
    /// is sealed under keys only an unlock brings.
    Locked,
    /// The store has keys and the sealed index still would not open.
    IndexUnopenable,
}

impl RootsUnread {
    /// One sentence in the person's words: what happened and what it means
    /// for them. Never the error chain, and one full stop.
    pub fn words(self) -> &'static str {
        match self {
            RootsUnread::Nobody => "No one is signed in, so there are no locations to list.",
            RootsUnread::NoIdentity => {
                "Kotton couldn't load your identity, so it can't list your locations."
            }
            RootsUnread::StoreNotLoaded => {
                "Your account isn't loaded on this device, so Kotton can't list your locations."
            }
            RootsUnread::Locked => {
                "Your files are locked on this device, so Kotton can't list your locations until you unlock."
            }
            RootsUnread::IndexUnopenable => {
                "Kotton couldn't open your list of locations on this device."
            }
        }
    }
}

/// A subsequent message frame sent to a long-lived runner after the init frame.
///
/// Only carries the `op` — the manifest and environment fields are already
/// held by the running process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerMessage {
    pub op: RunnerOp,
}

/// The operation the daemon wants the runner to perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RunnerOp {
    /// Start the app. `launch_args` is the key-value list passed to `on-launch`.
    Launch {
        launch_args: Vec<(String, String)>,
        /// The surface the daemon minted for this instance (RFC-0087).
        ///
        /// **This field is the only place the handle crosses into the runner
        /// process**, and `WasmSandbox::on_launch` is the only place it becomes
        /// a resource on the far side. The daemon mints it, opens it on `kuid`,
        /// and sends it here as data; the runner pushes it into the guest's
        /// table and passes the table entry. The value itself never reaches the
        /// guest, so the guest cannot name a surface — it holds one or it does
        /// not, which is the invariant that deletes the ownership check nobody
        /// has to write (RFC-0087, *Invariants*).
        ///
        /// No `#[serde(default)]`, unlike most fields added to this wire. The
        /// others have a safe meaning when absent — no grants, not the occupant
        /// — and a launch with no surface has none: it would be an app with
        /// nothing to draw on and no way to say so. A runner and a daemon from
        /// the same build are the supported pair; a mismatch fails at the
        /// decoder, loudly, rather than launching something blind.
        surface: crate::surface::SurfaceHandle,
    },
    /// Deliver a message to the running app. `msg` is the raw JSON string.
    Message { msg: String },
    /// Deliver a user input event (keyboard / pointer) to the running app,
    /// **on the surface it happened on**.
    Input {
        /// Which of the instance's surfaces the event is for.
        ///
        /// The compositor's own `SurfaceInputEvent` has carried this handle
        /// since RFC-0087 stage 1 and the daemon read it to find the owning
        /// app, then dropped it — so an instance with two surfaces was told
        /// that *something* was clicked and the SDK dispatched into whichever
        /// virtual DOM was first. It travels the last hop now.
        ///
        /// No `#[serde(default)]`, for the reason `Launch::surface` gives: a
        /// runner and a daemon from the same build are the supported pair, and
        /// an input with no surface has no safe meaning to invent.
        surface: crate::surface::SurfaceHandle,
        event: crate::ipc::types::InputEventPayload,
    },
    /// Request a clean shutdown. The runner calls `on-terminate` then exits 0.
    Terminate,
    /// Notify the guest that a surface patch was rejected after one retry.
    SurfaceError {
        /// Human-readable rejection reason from the compositor.
        reason: String,
    },
    /// Run one fetch cycle of an installed **fetcher** extension (RFC-0049).
    ///
    /// `config` is the user-supplied configuration for this instance (a feed
    /// URL, a calendar id) — user-authored values, so they may legitimately
    /// flow to the network side. Nothing derived from the user's *stored data*
    /// ever appears here. The daemon owns the schedule; a fetcher cannot invoke
    /// itself.
    Fetch { config: Vec<(String, String)> },
    /// The daemon's answer to a [`RunnerOutput::HostCall`] the runner is
    /// blocked on. Only valid while a `Fetch` op is in flight.
    HostReply { reply: RunnerHostReply },
}

variant_names!(RunnerOp { Launch, Message, Input, Terminate, SurfaceError, Fetch, HostReply });

/// A credential the host holds on a confined extension's behalf.
///
/// The extension names a slot and the header shape it needs; only the daemon
/// can resolve it, and only toward a destination the author declared. This is
/// the type that makes "the runner cannot leak what it was never given" true on
/// the wire: what crosses the process boundary is this reference, never the
/// material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostCredentialRef {
    pub slot: String,
    pub template: String,
}

/// A header value in a mediated request: literal bytes, or a credential
/// reference for the daemon to resolve.
///
/// A literal is [`SecretText`](crate::ipc::SecretText) because nothing on this
/// side can tell which literal is a credential. A slot the host holds is the
/// way a fetcher is meant to authenticate, but a literal is whatever the guest
/// wrote, and an `authorization` or `cookie` value it obtained itself (a token
/// from its own exchange, a key the person typed into its configuration) is as
/// much a bearer's words as a slot's material. So every literal prints
/// `<redacted>` in a `{:?}` and crosses the wire as the plain string it was.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostHeaderValue {
    Literal { value: crate::ipc::SecretText },
    Credential { credential: HostCredentialRef },
}

/// A mediated outbound request as it crosses the runner↔daemon boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, HostHeaderValue)>,
    pub body: Vec<u8>,
}

/// The daemon's response to a [`HostRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Something the runner needs the daemon to do on a confined extension's
/// behalf, mid-op (RFC-0049).
///
/// These mirror `kotton_wasm::extension::FetcherPort`. They exist as wire
/// frames rather than in-process calls because the capabilities behind them —
/// endpoint policy, host-held credentials, the object store — must stay on the
/// daemon side of the process boundary.
// `Eq` is absent because `RunnerInferVerb::Generate` carries `Options`, whose
// `temperature` is an `f32`, and a float has no total equality. `PartialEq` is
// what the tests and the dispatch actually use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "call", rename_all = "snake_case")]
pub enum RunnerHostCall {
    /// Perform a mediated outbound request. The daemon applies the extension's
    /// destination policy, injects any host-held credential, meters, and logs.
    /// Header values may carry credential *references*; the runner never sees
    /// resolved material.
    NetRequest { request: HostRequest },
    /// Write external content into this extension's quarantine namespace.
    QuarantineWrite { key: String, content: Vec<u8> },
    /// Read back something this extension itself wrote.
    QuarantineReadOwn { key: String },
    /// List this extension's own keys, relative to its namespace.
    QuarantineListOwn { prefix: String },
    /// A pre-auth verb from the **occupant** — create an identity, unlock one
    /// (DEC-0045).
    ///
    /// This rides the same blocked-call mechanism as the fetcher's calls above
    /// for the same reason: the answer is a value the guest needs, not an
    /// effect it can queue. It is not a fetcher capability and does not widen
    /// one — the two never appear in the same world, because a guest holds
    /// either `world occupant` or `world fetcher` and neither imports the
    /// other's interfaces.
    ///
    /// **The frame is not the authority.** A runner emits this only for a guest
    /// that resolved the `auth` import, which only an occupant can do, because
    /// the host adds that interface to the linker only for the app the user
    /// designated `shell`. The daemon still refuses the frame from a runner it
    /// did not spawn as the occupant — not as the security boundary, but
    /// because a runner emitting a call its world cannot make is a bug, and a
    /// bug in a confinement boundary must fail loudly rather than be serviced.
    Auth { verb: RunnerAuthVerb },
    /// A device-roster verb from the **occupant** (DEC-0045, DEC-0050).
    ///
    /// Rides the same blocked-call mechanism as `Auth` and for the same reason:
    /// a device list is a value the surface needs before it can draw, not an
    /// effect it can queue. Everything said about `Auth` above applies verbatim
    /// — the frame is not the authority, the daemon refuses it from a runner it
    /// did not spawn as the occupant, and a runner emitting a call its world
    /// cannot make is a bug that must fail loudly.
    Devices { verb: RunnerDeviceVerb },
    /// An inference verb from a guest that resolved the `infer` import
    /// (RFC-0085, `DEC-0073`).
    ///
    /// Rides the same blocked-call mechanism as `Devices` and for the same
    /// reason: a token is a value the guest needs, not an effect it can queue.
    ///
    /// **Unlike `Auth` and `Devices` this is not occupant-only.** Any app may
    /// declare `infer.run`; what it may *not* do is name a model `models()` did
    /// not show it, and that rule is enforced where the models are known rather
    /// than by which world the caller holds.
    Infer { verb: RunnerInferVerb },
    /// A guest asking the host for another surface (RFC-0087 stage 2).
    ///
    /// Rides the blocked-call mechanism rather than the effect queue that
    /// carries `launches` and `raises`, and the difference is the return value:
    /// `create-surface` hands the guest a `surface` **resource**, which the
    /// sandbox can only build once the daemon has minted a handle. A queued
    /// effect cannot answer a call whose result the guest is holding.
    ///
    /// **Not occupant-only, and the role is what decides that.** Any app may ask
    /// for a `Window`. `Background` and `Panel` arrive only from a guest that
    /// resolved the `layer-surface` import, which the host adds to the linker
    /// only for the designated app — so a frame naming either of those from an
    /// undesignated instance is a bug in the confinement boundary and the daemon
    /// fails loudly rather than servicing it, exactly as it does for `Auth`.
    Surface { verb: RunnerSurfaceVerb },
    /// A messaging verb from the **occupant** (`DEC-0055`, `DEC-0056`).
    ///
    /// The third frame that rides the blocked-call mechanism, and the one that
    /// carries plaintext in both directions: a body on the way out, an opened
    /// message on the way back. That is the point of routing it through the
    /// daemon rather than handing the guest a key — see [`RunnerMessageVerb::Open`].
    ///
    /// Everything said about `Auth` applies verbatim: the frame is not the
    /// authority, the daemon refuses it from a runner it did not spawn as the
    /// occupant, and a runner emitting a call its world cannot make is a bug
    /// that must fail loudly.
    Messages { verb: RunnerMessageVerb },
    /// A contacts verb from the **occupant**.
    ///
    /// The fourth blocked call, on the same terms as the three above: the list
    /// lives in the node's membership records and a process running untrusted
    /// WASM holds no store to read it from.
    Contacts { verb: RunnerContactVerb },
    /// A network readout from the **occupant** — the relay this device is
    /// paired with, the vaults enrolled through it, and this device's own name
    /// and local reach.
    ///
    /// The fifth blocked call, on the same terms as the four above, and the
    /// only one of them that can express nothing but a read: see
    /// [`RunnerNetworkVerb`].
    Network { verb: RunnerNetworkVerb },
    /// A joining verb from the **occupant** — pairing a relay, admitting an
    /// invite, and the six-digit ceremony that admitting one runs.
    ///
    /// The sixth blocked call, on the same terms as the five above, and the
    /// counterpart of [`RunnerHostCall::Network`]: that one can express
    /// nothing but a read, and this one is where the writes of the same pane
    /// live. See [`RunnerJoinVerb`].
    Joining { verb: RunnerJoinVerb },
    /// A records verb from the **occupant**, on one of the person's roots
    /// (RFC-0071 R17).
    ///
    /// The seventh blocked call, on the same terms as the six above: the
    /// records live in the person's own `records.db`, sealed under their key,
    /// and a process running untrusted WASM does not open it. The root is named
    /// by the id the daemon handed the occupant in its `RunnerRoot` list, and
    /// the daemon asks the person's membership again before it touches a row —
    /// the id is a name the guest holds, not the authority (R12).
    Records { verb: RunnerRecordVerb },
    /// A landlord's verb from the **occupant**, to a vault or a relay whose operator
    /// credential this person keeps (`interface landlord`).
    ///
    /// The eighth blocked call, on the same terms as the seven above: the
    /// credential is a key the daemon keeps sealed in the person's store, and
    /// a process running untrusted WASM holds none. See [`RunnerLandlordVerb`].
    Landlord { verb: RunnerLandlordVerb },
    /// This machine's operators, from the **occupant** — *This device ›
    /// Operators* (`interface operators`).
    ///
    /// The ninth blocked call, on the same terms as the eight above: each verb
    /// is spoken to `kdeviced` under the person's own operator key, which the
    /// daemon keeps sealed in their store, and a process running untrusted WASM
    /// holds none. See [`RunnerOperatorVerb`].
    Operators { verb: RunnerOperatorVerb },
    /// What **another app** was granted, asked by the **occupant**
    /// (`interface grants`).
    ///
    /// The tenth blocked call, on the same terms as the nine above: the grant
    /// envelopes are in the person's database, which a process running
    /// untrusted WASM does not open — and the answer is about a principal other
    /// than the one asking, which is why no other world can raise it. See
    /// [`RunnerGrantVerb`].
    Grants { verb: RunnerGrantVerb },
    /// One schema's records **kept in the person's roots**, from a guest that
    /// called `schema.kept` (RFC-0071 R17, RFC-0088 phase two).
    ///
    /// **Not occupant-only, and not a root verb.** R17's rule is that *an app
    /// holding `schema.read` on a schema sees that schema's records in every
    /// root the person is a member of, and no record from a root they are
    /// not*; this is that rule for an app that holds no root. The sandbox
    /// checks the schema grant before the frame is sent, exactly as it does for
    /// `schema.query` and `root.records`, and the daemon reads the person's
    /// membership before it reads a row. There is no root on this frame: the
    /// app names none, so it cannot name one it is not in.
    Kept { nsid: String },
    /// A `files` verb from any guest holding a file handle, on the person's own
    /// tree (`TASK-a-file-an-app-writes-rests-in-the-clear-in-the-sealed-stores-own-directory`).
    ///
    /// **The person's files rest in the sealed store (RFC-0070), and the store's
    /// keys are the daemon's.** A process running untrusted WASM holds none, so
    /// the runner cannot seal a write or open a read itself; it asks, the way
    /// every other blocked call here asks. Before this the runner wrote the
    /// guest's bytes straight into the store's own backing directory, in the
    /// clear and under the file's own name.
    ///
    /// **Not occupant-only.** Any app may hold a `files` handle; which paths it
    /// may name is its grant, and the daemon answers every frame against its
    /// own record of that grant rather than trusting the path on the frame.
    Files { verb: RunnerFileVerb },
}

/// The `files` verbs, mirroring `resource directory` in `interface files`.
///
/// Every `path` is an **absolute path in the person's tree** (`/notes/a.md`):
/// the sandbox has already resolved the guest's relative name under the handle
/// it holds, so the handle's root is inside the string. The daemon checks the
/// string against the instance's grant again before it touches the store — the
/// path on this wire is a name the runner computed, not the authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum RunnerFileVerb {
    /// A file's whole contents.
    Read { path: String },
    /// Create or overwrite a file. Sealed, blinded and packable exactly as a
    /// `kotton fs write` of the same path would be.
    Write {
        path: String,
        #[serde(with = "crate::base64_bytes")]
        data: Vec<u8>,
    },
    /// Delete a file. `not found` when there was none.
    Delete { path: String },
    /// Make an empty folder — an object in the store, not a placeholder file.
    /// `already exists` when anything is at the path. Write authority, as
    /// `Write` and `Delete` are.
    CreateDir { path: String },
    /// The immediate children of a directory.
    List { path: String },
    /// Whether a path names a file, a directory, or nothing — what the sandbox
    /// asks once per grant target, to shape the handle it mints (one file
    /// handed over, or a tree).
    Kind { path: String },
    /// Whether the current version of a file is in the history log of the
    /// tree that carries it, and at which generation — what the share sheet
    /// says *sent* on (RFC-0090, *A device of your own*). A readout: read
    /// authority, as `Read` is, and nothing is written.
    Logged { path: String },
}

/// One immediate child of a listed directory — `files.dir-entry` on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerDirEntry {
    /// The child's own name, one segment, no trailing slash.
    pub name: String,
    /// Whether the child is a directory — in the store, a prefix some file
    /// lies under.
    pub is_dir: bool,
    /// The file's length in bytes; `0` for a directory, which the store keeps
    /// no entry for.
    pub size: u64,
    /// When the file was last written, seconds since the Unix epoch, where the
    /// store records it; `None` for a directory.
    pub modified: Option<u64>,
}

/// What a path names in the person's tree.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunnerPathKind {
    /// A file: an object is stored at this path.
    File,
    /// A directory: at least one file lies beneath this path.
    Dir,
}

/// The landlord's verbs, mirroring `interface landlord` in `world occupant`.
///
/// A separate enum from [`RunnerJoinVerb`] for the reason the interfaces are
/// separate: those act on this device, these on a vault or a relay the person
/// runs, under a different credential. **Three of the vault's four, and each
/// narrower than its `vault` command** — a guest names a vault, a person's name
/// on it and a number of bytes. No key, no invite window, no posture: the
/// daemon fixes the window at a day, as `vault invite` does, and the vault
/// admits only blind. The relay's rule is named by the relay's own name
/// (DEC-0087), not a vault's.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum RunnerLandlordVerb {
    /// Who the vault keeps for. `OperatorVerb::Pools`.
    People { vault: String },
    /// Mint `name`'s invite, then set space aside for them; a refused mint sets
    /// no number. `OperatorVerb::Invite`.
    Invite {
        vault: String,
        name: String,
        space_bytes: u64,
    },
    /// Drop one person's pool. `OperatorVerb::Drop`.
    DropPool { vault: String, name: String },
    /// Who may use the relay, as the relay reports it. `OperatorVerb::ReadRule`.
    Rule { relay: String },
    /// Set who may use the relay. `OperatorVerb::SetRule`. The guest names
    /// one of the three rules and nothing else: the keys are minted, kept and
    /// handed on by the daemon, and never reach this wire.
    SetRule {
        relay: String,
        rule: crate::rendezvous::AdmissionRule,
    },
    /// Settings' one door: read a pasted code and say what it names —
    /// writing nothing (`TASK-settings-has-one-door-and-it-takes-a-code`). An
    /// invite's words are a bearer's, so the code crosses as
    /// [`crate::ipc::SecretText`] and prints `<redacted>`.
    Resolve { code: crate::ipc::SecretText },
    /// The door's second half for a vault's or a relay's line: the terminal's
    /// `enrol` of one line, completing the key this desktop minted for the instance
    /// (RFC-0084 V21). The guest names the pasted code and nothing else; the
    /// code crosses as [`crate::ipc::SecretText`], since what was pasted may be
    /// an invite.
    Enrol { code: crate::ipc::SecretText },
    /// Stand the vault `vault` at the relay this person runs as `relay`, and
    /// nowhere else. `OperatorVerb::Move` — the vault's *Move…*.
    MoveVault { vault: String, relay: String },
}

/// What a pasted code names, as the door shows it before anything is done.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerResolved {
    /// What it is.
    pub kind: RunnerCodeKind,
    /// The service's public key, 64 hex, where the code carries one.
    pub key: Option<String>,
    /// Where it is reached, as the code says.
    pub hint: String,
    /// Whether it answered from here — a relay proving the code's key, a
    /// vault's address taking a connection. Always false for an invite,
    /// which is not dialled here: its relay is dialled by `joining.admit`.
    pub reached: bool,
    /// For a vault's or a relay's line, the name of the key minted here that
    /// it completes. `None` for an invite.
    #[serde(default)]
    pub completes: Option<String>,
}

/// The kinds of code the door reads.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunnerCodeKind {
    /// An invite to keep your things at someone's vault
    /// (`kotton-invite:vault:…`).
    VaultInvite,
    /// A vault's line: pasting it completes the key minted here for it.
    VaultLine,
    /// A relay's line.
    RelayLine,
    /// An invite to stand at someone's relay (`kotton-invite:relay:…`).
    RelayInvite,
}

/// A line completed at the door: the credential is kept, and — for a vault
/// this desktop could not tell where to stand — why, and the acts that stand
/// it, each as `Unstood::acts` words it for the terminal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerEnrolled {
    /// `true` for a relay, `false` for a vault.
    pub relay: bool,
    /// The name the credential is kept under.
    pub name: String,
    /// Why the vault stands at no relay yet, in words; `None` when it was told.
    pub not_standing: Option<String>,
    /// The acts, each with the address it is about where there is one.
    pub acts: Vec<RunnerAct>,
    /// The relays to choose among when the desktop asks where the vault
    /// stands: each by its address and the name a move takes.
    pub choose: Vec<RunnerRelayChoice>,
}

/// One act that stands a vault, as `Unstood::acts` says it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerAct {
    pub at: Option<String>,
    pub act: String,
}

/// One relay this person runs, offered as where a vault stands.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerRelayChoice {
    pub name: String,
    pub address: String,
}

/// One relay this person runs, as its card reads it
/// (`TASK-settings-has-one-door-and-it-takes-a-code`, clause (3)).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerOperatedRelay {
    /// The name its credential is kept under — what the landlord's relay
    /// verbs are spoken to.
    pub name: String,
    /// Its key, 64 hex: what it is (RFC-0084 V9). `None` for a relay that
    /// showed none when it was enrolled.
    pub key: Option<String>,
    /// Where it was last found.
    pub address: String,
    /// The person's nodes this desktop told to stand there: each vault by its
    /// name, and this device when its own relay is this one, by key.
    pub standing: Vec<String>,
    /// Whether this device reserves here — its own relay proved this key.
    pub here: bool,
}

/// This machine's operators, mirroring `interface operators` in `world occupant`
/// (`TASK-this-devices-operators-box-speaks-to-kdeviced-under-the-persons-own-key`).
///
/// A guest names a **person** — the handle [`RunnerPerson::person`] gave it —
/// and nothing else: no key, no DID. Who is acting is the daemon's to know (the
/// person it serves), the key is the one it keeps sealed for them, and adding
/// binds the key the added person's own daemon proved.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum RunnerOperatorVerb {
    /// Who operates this machine, and who else has an account here.
    Read,
    /// Make `person` an operator.
    Add { person: String },
    /// Step `person` down — asked on the platform's own prompt first, by
    /// their name typed back (`DEC-0081`).
    Remove { person: String },
}

/// One of this machine's operators, as the occupant reads them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerOperator {
    /// The handle a verb names them by — their account's id on this machine,
    /// never drawn.
    pub person: String,
    /// What they are called.
    pub name: String,
    /// Whether this is the person asking.
    pub you: bool,
}

/// Someone with an account on this machine who is not one of its operators.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerPerson {
    /// The handle a verb names them by, never drawn.
    pub person: String,
    /// What they are called.
    pub name: String,
}

/// *Operators*, as the occupant reads it: whether the person asking is one,
/// and — only when they are — who is, and who else could be.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerOperatorBox {
    /// Whether the person asking operates this machine. When not, the two
    /// lists are empty: only an operator reads who operates it.
    pub operates: bool,
    /// The operators, oldest first, one row per person.
    pub operators: Vec<RunnerOperator>,
    /// Everyone else with an account here — who *Add an operator…* offers.
    pub others: Vec<RunnerPerson>,
}

/// The records verbs on a root, mirroring `records` and `add-record` on
/// `resource root` in `interface roots` (RFC-0071 R17).
///
/// **Read and add, and nothing else.** A record belongs to exactly one root,
/// so there is no verb here that could move one; and the schema grant is what
/// the app may see — checked by the sandbox against the approved capability set
/// before a frame is sent, as it is for `schema.query`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum RunnerRecordVerb {
    /// The live records of one schema in one root.
    List { root: String, nsid: String },
    /// Write one record into one root. `data` is the JSON body.
    Add { root: String, nsid: String, data: String },
}

/// One record, as a guest reads it: its id and its JSON body.
///
/// The shape of `schema.record-entry`, so a root's records and the app's own
/// read back through one type on the guest side.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerRecord {
    pub id: String,
    pub data: String,
}

/// One record kept in one of the person's roots, as an app reads it through
/// `schema.kept`: its id, its JSON body, and the root it is kept in.
///
/// **The root travels as the person's word for it, never its id.** An app holds
/// no root (`interface roots` is the occupant's), so an id would be a handle it
/// could do nothing with but join on. The name is what a surface draws — *which
/// root is this record in* — and it is the answer R17 makes the question have.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerKeptRecord {
    pub id: String,
    pub data: String,
    pub root: String,
}

/// The device-roster verbs, mirroring `interface devices` in `world occupant`.
///
/// Separate from [`RunnerAuthVerb`] on the same grounds that one is separate
/// from [`RunnerHostCall`]: the whole of what the occupant may ask about devices
/// should be one list a reader can finish, and adding an auth verb should not
/// read as widening this.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum RunnerDeviceVerb {
    /// Every device paired to this account.
    ListDevices,
    /// Revoke one device's pairing, by DID. Article IV's second half.
    RevokeDevice { did: String },
    /// Every browser admitted for this person (DEC-0053: a browser is paired
    /// *like a device*, so it is listed where devices are).
    ListBrowsers,
    /// Revoke one admitted browser, by the name it was admitted under. The
    /// daemon revokes it exactly as `BrowserDeviceRevoke` does: its row, the
    /// sessions its admission minted, and every channel it holds open.
    RevokeBrowser { name: String },
}

/// The network readouts, mirroring `interface network` in `world occupant`.
///
/// A separate enum from [`RunnerDeviceVerb`] for the reason that one is
/// separate from [`RunnerHostCall`], and for one more: **every variant here is
/// a read, and there is no variant that could be anything else.** The relay
/// address, the bind scope and this machine's name are `device_config` keys in
/// kdeviced's file, and a guest-facing host must not hold that pool
/// (`interface devices` says so where it explains why `set-device-name` is
/// absent). Read is not write — this enum is what makes that checkable by
/// reading three lines instead of auditing a verb list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum RunnerNetworkVerb {
    /// The relay this device is paired with, if one is named.
    PairedRelay,
    /// Every relay this person runs, as each card reads it.
    OperatedRelays,
    /// Every vault this device has enrolled.
    EnrolledVaults,
    /// This device's own name and local reachability.
    ThisDevice,
}

/// The joining verbs, mirroring `interface joining` in `world occupant`.
///
/// A separate enum from [`RunnerNetworkVerb`] for the reason the two
/// interfaces are separate: **every variant there is a read, and every variant
/// here is an act.** Keeping them in one list would make *read-only* a claim
/// about a subset of a list rather than a property of a type, and the point of
/// `RunnerNetworkVerb` is that it can be checked by reading three lines.
///
/// **One request behind three verbs, and it is the CLI's.** [`Self::Admit`] is
/// `UserRequest::DeviceAdmit` under the blind posture, which
/// `kotton device admit <invite> --blind` sends; [`Self::Confirm`] delivers the
/// ceremony's verdict the way `UserRequest::PairConfirmCode` does, and
/// [`Self::Cancel`] drops the stream. Nothing new crosses the IPC wire, which
/// is why `wire-surface.txt` is unchanged by this interface existing.
///
/// **What a guest may name is what a person typed.** No DID, no key, no
/// address, no user id, no posture — the posture is fixed blind on the daemon
/// side because a vault holds no key (`DEC-0068`). A verb list that could not
/// express those is a narrower surface than the terminal's, which is the rule
/// this interface was asked to hold.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum RunnerJoinVerb {
    /// Admit a vault's invite (`kotton-invite:vault:…`) under the blind
    /// posture, or stand at a relay by its invite (`kotton-invite:relay:…`).
    /// An invite's words are a bearer's, so it crosses as
    /// [`crate::ipc::SecretText`] and prints `<redacted>`.
    Admit { invite: crate::ipc::SecretText },
    /// The six digits the person typed off the other end's `sas=` line. No
    /// token: the host holds it, as for [`RunnerContactVerb::PairConfirm`].
    ///
    /// **The typed text, not a verdict.** This device is the issuer of a vault
    /// admit, and RFC-0076's asymmetric confirm has the issuer *type* the
    /// digits rather than say whether two screens agree — a yes/no is blindly
    /// approvable. The daemon compares them with the SAS it holds, so the
    /// guest never holds the digits and cannot answer *yes* without them
    /// (`TASK-the-desktop-asks-whether-the-six-digits-match-where-the-person-must-type-them`).
    Confirm { typed: String },
    /// Abandon whatever is in flight. Idempotent.
    Cancel,
    /// Stand this device at the relay the last admit offered, on the person's
    /// yes. Names nothing: the daemon kept the offer, by the relay's key
    /// (`TASK-an-invite-is-the-codes-other-clause-and-its-relay-is-offered`).
    TakeRelay,
}

/// The inference verbs, mirroring `interface infer` in `world app` (RFC-0085).
///
/// A separate enum for the same reason `RunnerDeviceVerb` is one: the whole of
/// what a guest may ask of a model should be a list a reader can finish.
///
/// **There is no template here, and that is the point.** `interface infer`'s
/// `context` record has no `template` field because the host fills it from the
/// manifest of the model the person installed; a guest that could supply the
/// prompt shape could put anything in front of the question. The daemon builds
/// `kotton_infer::Context` on the far side of this wire, and this is where that
/// invariant is enforced rather than merely intended.
///
/// **Generation is pulled, one round trip per token.** `interface infer`'s
/// `generation` resource is pulled — `next()` returns one token or `none` — and
/// this mirrors it rather than streaming, because the guest decides the pace and
/// dropping the resource is how a generation stops. [`Drop`] is what a dropped
/// resource sends, so a guest that stops reading stops the work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RunnerInferVerb {
    /// The models that answer on this machine — the active one of each kind.
    Models,
    /// Embed one text with a model the guest was shown.
    Embed { model: String, text: String },
    /// Begin one generation. Answered by [`RunnerHostReply::InferGeneration`]
    /// with a handle to pull.
    Generate {
        model: String,
        question: String,
        passages: Vec<RunnerPassage>,
        options: RunnerInferOptions,
    },
    /// Pull the next token of a generation this runner began.
    Next { generation: u64 },
    /// The guest dropped the resource. Everything for this generation goes.
    Drop { generation: u64 },
}

/// The shapes the inference verbs carry.
///
/// **Wire-local mirrors rather than `kotton_infer`'s own types, and that is the
/// boundary rather than a convenience.** `core/wasm` does not link
/// `kotton-infer` — the crate that owns a `Backend` is mechanism-tier and the
/// sandbox says in as many words that it does not name it, so the translation
/// between the guest's shapes and the backend's belongs to whoever implements
/// the port. Putting `kotton_infer` types on this wire would have forced that
/// crate into every process holding a frame, including the one that runs
/// untrusted WASM. `RunnerPairedDevice` is here for the same reason.
///
/// The daemon, which links both, is where these become `kotton_infer`'s.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RunnerModelKind {
    Chat,
    Embed,
    Vision,
}

/// Where a passage came from, as the *caller* knows it — never as its text
/// claims.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RunnerPassageOrigin {
    Import,
    Message,
    Calendar,
    File,
}

/// Who and when, beside the citation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerProvenance {
    pub origin: RunnerPassageOrigin,
    /// A `did:` the host resolves, never a display name.
    pub from: Option<String>,
    /// RFC-3339, as the record carries it.
    pub at: String,
}

/// One labelled span of the person's own data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerPassage {
    /// `kotton://records/<nsid>/<id>` (RFC-0003 addressing).
    pub reference: String,
    pub provenance: RunnerProvenance,
    pub text: String,
}

/// The knobs a caller sets per question.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunnerInferOptions {
    pub max_tokens: u32,
    pub temperature: f32,
    /// Fixed for a reproducible answer; `None` lets the backend choose.
    pub seed: Option<u64>,
}

/// Numbers about a generation, and only numbers (RFC-0085 IN9).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerMetering {
    pub tokens: u32,
    pub first_token_ms: u64,
    pub total_ms: u64,
}

/// A model as a guest may see it, mirroring `interface infer`'s `model-info`.
///
/// Deliberately not the whole manifest: a guest has no use for the weights'
/// format, its quantisation or its publisher's signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerModelInfo {
    /// The hex hash of the sealed weights — what RFC-0085 says a model *is*.
    pub id: String,
    pub name: String,
    pub version: String,
    pub kind: RunnerModelKind,
    pub context_window: u32,
}

/// What can go wrong, in the guest's taxonomy rather than the backend's.
///
/// `kotton_infer::InferError` is the *backend's* — unknown handle, unsupported
/// format, weights rejected. None of that is a guest's business or its
/// vocabulary. This mirrors `interface infer`'s `infer-error`, which is the
/// shape the port must produce, and the daemon is what translates one into the
/// other.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RunnerInferError {
    /// This machine runs no model — inference is off, or nothing is installed.
    /// Not a refusal: a device that cannot answer says so.
    NoRuntime,
    /// The id names no model the person has installed, or none this guest was
    /// shown.
    NoSuchModel(String),
    /// The context exceeds the model's window, which is carried so a caller can
    /// trim and ask again.
    ContextTooLarge(u32),
    /// The runtime failed. The reason names the stage, never the bytes and
    /// never the question.
    Runtime(String),
}

/// The messaging verbs, mirroring `interface messages` in `world occupant`.
///
/// A separate enum for the same reason `RunnerDeviceVerb` is one: the whole of
/// what the occupant may ask about messages should be a list a reader can
/// finish.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum RunnerMessageVerb {
    /// Seal `body` to `to_did` and hand it over. Answers with the record id and
    /// the one word the sender is owed (`DEC-0056`).
    Send { to_did: String, body: String },
    /// Share a file with `to_did`: a direct message whose `type` is `share`
    /// and whose body is the file's manifest (RFC-0090, *Delivery › To one
    /// person*). Answers as [`Self::Send`] does, with the record id and the
    /// one word. `origin` names the file on the sender's side and is kept on
    /// their own copy only; nothing of it is sealed to the recipient (SH5).
    Share {
        to_did: String,
        name: String,
        #[serde(with = "crate::base64_bytes")]
        data: Vec<u8>,
        origin: Option<String>,
    },
    /// Seal `body` to a channel's key and file it.
    ChannelSend { channel_did: String, body: String },
    /// Share a file with the group that holds `channel_did`'s key: a channel
    /// message whose `type` is `share` and whose body is the file's manifest,
    /// sealed under the newest epoch the person holds and handed once to each
    /// current member (RFC-0090, *Delivery › To a group*). Answers as
    /// [`Self::ChannelSend`] does, with the record id and no word: where each
    /// member's copy went is not a confined app's to hold. `origin` names the
    /// file on the sender's side and is not kept: every copy of a share to a
    /// group, the sender's own included, is sealed under the group's key, so
    /// none carries it (SH5).
    ChannelShare {
        channel_did: String,
        name: String,
        #[serde(with = "crate::base64_bytes")]
        data: Vec<u8>,
        origin: Option<String>,
    },
    /// The channels this person holds a key for, each with how many people
    /// hold its current epoch — read from their own grants and nothing else
    /// (RFC-0090 SH4, *The surface*).
    Groups,
    /// A channel's messages, newest first, still sealed.
    ChannelHistory {
        channel_did: String,
        before_id: Option<String>,
        limit: u32,
    },
    /// The messages addressed to this person, still sealed.
    PollInbox,
    /// **Open a sealed message, on the node.**
    ///
    /// This verb exists because the interface it serves said, until 2026-09-08,
    /// that the guest should decrypt *"using their own identity key"* — which a
    /// confined guest must never hold, and does not. The key stays on the node
    /// and the plaintext crosses, exactly as it does for a browser
    /// (`MessageDecryptDm`). Without this the other verbs hand a guest
    /// ciphertext it has no way to read.
    Open { message: RunnerSealedMessage },
    /// How many messages this person has not read (`DEC-0061`).
    UnreadCount,
    /// Advance one conversation's read mark to `(filed_at, message_id)`.
    ///
    /// The position comes from the messages that were drawn: `filed_at` is
    /// where this person's store filed the message, never the sender's claim
    /// (`TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`).
    MarkRead {
        peer_did: String,
        filed_at: u64,
        message_id: String,
    },
    /// Both directions of one conversation, from this person's own store,
    /// newest-filed first and still sealed: what `peer_did` sent them and what
    /// they sent `peer_did` (`TASK-messages-is-the-drawn-one`). What they sent
    /// opens on their own key since
    /// `TASK-a-sender-cannot-reopen-what-they-sent`, through [`Self::Open`].
    Conversation { peer_did: String },
    /// The one word each message this person sent `peer_did` reads as
    /// (`DEC-0056`): the same readings `MessageDeliveries` gives a browser.
    Deliveries { peer_did: String },
    /// How many of `peer_did`'s messages this person has not read — the
    /// conversation's own count, where [`Self::UnreadCount`] is every
    /// conversation's (`DEC-0061`).
    UnreadFrom { peer_did: String },
}

/// One message, as the occupant sees it: what came out of the store, unopened.
///
/// `RunnerSealedMessage` rather than `RunnerMessage`, which is already the name
/// of a frame the daemon sends a long-lived runner. Two things called a message
/// on one wire is how a reader loses the thread of which one a function takes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerSealedMessage {
    pub id: String,
    pub thread_id: String,
    pub from_did: String,
    pub to_did: Option<String>,
    pub channel_did: Option<String>,
    /// Base64 ciphertext.
    pub body: String,
    /// Base64 nonce.
    pub nonce: String,
    /// Base64 ephemeral X25519 public key. On a direct message, the key the
    /// body is sealed against. On a channel copy that came over a member's
    /// door, the key of the envelope it came in, kept to deduplicate a retried
    /// delivery — the body is sealed to the channel key, and this does not
    /// open it. `None` on the sender's own copy of a channel message. Which key
    /// opens a record is its `channel_did`, asked first
    /// (`kotton_msg::daemon::messages::message_open`).
    pub ephemeral_pub: Option<String>,
    /// When the sender says it was written: whole seconds on *their* clock. A
    /// claim, shown as one, and never what a conversation is ordered by.
    pub sent_at: u64,
    /// Where this person's own store filed it — milliseconds on the holder's
    /// clock, strictly increasing in the order one device files things; a row
    /// synced from another of the person's devices keeps its stamp from
    /// there, so it can sit below one filed here earlier. The key a conversation is
    /// ordered by and a read mark is written with
    /// (`TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`).
    #[serde(default)]
    pub filed_at: u64,
    /// `"text"` or `"attachment_ref"`.
    pub message_type: String,
}

/// The contacts verbs, mirroring `interface contacts` in `world occupant`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum RunnerContactVerb {
    /// Everyone this person has paired with. Reads; there is no write here,
    /// because a contact is made by a ceremony and not by an insert.
    List,
    /// Begin the RFC-0022 ceremony as the person who speaks the words.
    PairStart { label: Option<String>, ttl_seconds: u64 },
    /// Begin it as the person who heard them. The words are the PAKE's
    /// password, so they cross as [`crate::ipc::SecretText`].
    PairJoin {
        code: crate::ipc::SecretText,
        label: Option<String>,
    },
    /// Answer the six digits. No token: the host holds it (`DEC-0057`).
    PairConfirm { matched: bool },
    /// Abandon a ceremony in progress.
    PairCancel,
}

/// The grants verbs, mirroring `interface grants` in `world occupant`.
///
/// **Both carry the app they ask about, and neither can carry an answer.** The
/// frame names an app and, for `Covering`, a path the occupant is already
/// looking at; everything that comes back is a [`RunnerHolding`], which has no
/// field a path could travel in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum RunnerGrantVerb {
    /// Every resource `app_nsid` holds.
    HeldBy { app_nsid: String },
    /// Which of `app_nsid`'s holdings reaches `path` in the person's own tree.
    Covering { app_nsid: String, path: String },
    /// The installed apps a file can be opened in — the share sheet's *An
    /// app* (RFC-0090, unit 5). Carries nothing: the answer is the host's
    /// reading of what is installed and declared, never the asker's.
    OpensFiles,
}

/// An installed app a file can be handed to, as the occupant is told it: its
/// id and its name, and nothing about what it holds or where.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerOpener {
    /// What `apps.launch-with-args` is called with.
    pub app_nsid: String,
    /// The name the app was installed under.
    pub name: String,
}

/// One resource another app holds, as the occupant is told it: **a shape and
/// its words, never where it points** (RFC-0021).
///
/// There is deliberately no `target`. The folder a person chose for an app is
/// a durable identifier two apps could join on, and this record is the whole of
/// what crosses to the runner — so the absence of the field is the rule, not a
/// convention a serializer has to remember.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerHolding {
    /// The author's id for the shape, or `None` for a grant no declared shape
    /// answers to.
    pub shape: Option<String>,
    /// The words a person reads.
    pub label: String,
    /// Whether it carries write as well as read.
    pub writable: bool,
}

/// Where a pairing ceremony has got to, as the surface sees it.
///
/// **Pushed, not polled.** Each of these reaches the app at `on-message` the
/// moment the daemon learns it, wrapped in [`PAIRING_FRAME_KIND`]. The ceremony is
/// two people reading digits to each other; a surface that learned its state on a
/// timer would show a stale one for the length of that timer, in the one step
/// whose purpose is confirming nothing in between altered the meeting.
///
/// The token that answers the digits is **not** here. It stays in the host, so a
/// guest can only confirm the ceremony the host is running for it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum RunnerPairingState {
    /// The words are live. Say them to the other person. They are the PAKE's
    /// password, as `UserResponse::PairAdvertising`'s are, so they cross as
    /// [`crate::ipc::SecretText`].
    Advertising { code: crate::ipc::SecretText },
    /// Both sides met. Compare these digits aloud and answer.
    Compare {
        digits: String,
        /// What the other side calls itself, where it said.
        peer_label: Option<String>,
    },
    /// It held: this person is now a contact.
    Paired { contact: RunnerContact },
    /// It is over, and why. Includes a refusal on either screen — a ceremony
    /// somebody answered `no` to has failed, which is it working.
    Failed { reason: String },
}

/// The `on-message` envelope kind carrying a [`RunnerPairingState`].
///
/// `on-message` is one string channel shared by everything the host pushes, so
/// each sender names itself and an app matches on the name. Without it a second
/// pusher would silently break the first, and the failure would look like a
/// ceremony that stopped halfway.
pub const PAIRING_FRAME_KIND: &str = "kotton:contact-pairing";

/// Where joining a network has got to, as the surface sees it
/// (`TASK-the-desktop-pairs-a-relay-and-enrols-a-vault-from-settings-network`).
///
/// **Pushed, not polled**, for the reason [`RunnerPairingState`] is: admitting
/// an invite is the same six-digit ceremony, and a person is about to type the
/// digits the other end shows. A surface that learned its state on a timer
/// would be stale in the one step whose purpose is confirming that nothing in
/// between altered the meeting.
///
/// Neither the token that answers the digits **nor the digits themselves** are
/// here. Both stay in the host: the token so a guest can only confirm the
/// ceremony the host is running for it, the digits so the confirm is a
/// transcription and not a yes/no (RFC-0076).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum RunnerJoiningState {
    /// Reaching the relay — dialling it to pair, or meeting the invite at it.
    Reaching { relay: String },
    /// Both ends met at the relay. The other end printed six digits on its
    /// `sas=` line; type them, and answer with what was typed.
    ///
    /// **No digits here**, unlike [`RunnerPairingState::Compare`]. This device
    /// is the issuer, and RFC-0076's asymmetric confirm is that the issuer
    /// *does not display* the code: the digits must come from the other
    /// machine, or a person who never looks at it approves blind. The daemon
    /// keeps the SAS and compares what is typed against it.
    Compare,
    /// It held. The network is joined, named the way the readout names it.
    Joined {
        /// The relay, by the name the readout will show it under: the one the
        /// vault was met at, or the relay this device now stands at.
        relay: String,
        /// The vault admitted through it, where this flow admitted one —
        /// `None` for a relay alone, which joins no vault.
        vault: Option<String>,
        /// This device stands at no relay, and is offered `relay` as its own:
        /// said in words, and taken only on the person's yes
        /// (`RunnerJoinVerb::TakeRelay`). Admitting never takes it.
        #[serde(default)]
        offered: bool,
    },
    /// It is over, and why, in the person's words. A wrong name, a refused
    /// dial and a lapsed invite all arrive here.
    Failed { reason: String },
}

/// The `on-message` envelope kind carrying a [`RunnerJoiningState`].
///
/// A second name on the one string channel, which is what
/// [`PAIRING_FRAME_KIND`]'s own doc says the names are for: without it this
/// pusher would silently break the contact ceremony, and the failure would look
/// like a ceremony that stopped halfway.
pub const JOINING_FRAME_KIND: &str = "kotton:network-joining";

/// The `on-message` envelope kind that tells the designated app its window list
/// is out of date (`TASK-the-docks-window-list-is-as-stale-as-its-last-repaint`).
pub const WINDOWS_CHANGED_FRAME_KIND: &str = "kotton:windows-changed";

/// **The whole frame, as a constant — which is the argument.** `ask again`,
/// carrying nothing.
///
/// `layer-surface.list-windows` is a pull, and RFC-0087 stage 3b chose that for
/// the confinement argument: the designated app learns what the host tells it at
/// the moment it asks, and nothing it was not asking for. A push that carried a
/// window — a name, an id, a count — would be the push that stage rejected, in a
/// channel chosen because it was not one. So this is not a type with a body that
/// happens to be empty today; it is a string with no field to fill, and the guest
/// SDK matches it byte for byte (`a_windows_frame_is_the_same_bytes_on_both_sides`, in
/// the SDK's `host_wire_tests`).
/// A frame that grew a field would stop matching and the dock would go back to
/// being stale, which is the failure this shape makes loud rather than quiet.
///
/// The body is `null` rather than absent so the frame has the one shape every
/// [`HostFrame`] has; a reader that parses frames generically reads a kind and
/// nothing.
pub const WINDOWS_CHANGED_FRAME: &str = r#"{"kind":"kotton:windows-changed","body":null}"#;

#[cfg(test)]
mod pairing_frame_tests {
    use super::*;

    /// The guest SDK spells the frames out rather than importing them — it is
    /// compiled for wasm and does not depend on this crate — and its own tests
    /// hold its copies to these (`host_wire_tests` in `guest/sdk/kotton-app`):
    /// a release of this crate ships without the SDK, so they are held there.
    /// What this crate holds of them is that they are three: two pushers sharing
    /// one name is what the name exists to prevent.
    #[test]
    fn the_three_frames_have_three_names() {
        assert_ne!(JOINING_FRAME_KIND, PAIRING_FRAME_KIND);
        for other in [PAIRING_FRAME_KIND, JOINING_FRAME_KIND] {
            assert_ne!(WINDOWS_CHANGED_FRAME_KIND, other);
        }
    }

    /// And the shape the SDK parses is the shape this crate writes.
    #[test]
    fn a_frame_round_trips_through_the_shape_the_guest_reads() {
        let frame = HostFrame::new(
            PAIRING_FRAME_KIND,
            RunnerPairingState::Compare {
                digits: "042137".to_string(),
                peer_label: Some("alice".to_string()),
            },
        );
        let json = serde_json::to_string(&frame).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], PAIRING_FRAME_KIND);
        assert_eq!(v["body"]["state"], "compare");
        assert_eq!(v["body"]["digits"], "042137");
        assert_eq!(v["body"]["peer_label"], "alice");
    }

    /// **It carries no window data** — the one thing the record says to get right.
    ///
    /// Read as the generic frame shape: a kind, and a body that is `null`. Not an
    /// empty object, not an empty list — there is no field in it for a later
    /// change to fill without this test naming it.
    #[test]
    fn the_windows_frame_is_a_kind_and_nothing() {
        let v: serde_json::Value = serde_json::from_str(WINDOWS_CHANGED_FRAME).unwrap();
        assert_eq!(v["kind"], WINDOWS_CHANGED_FRAME_KIND);
        assert!(v["body"].is_null(), "the nudge carries a body: {v}");
        assert_eq!(
            v.as_object().map(|o| o.len()),
            Some(2),
            "the nudge carries a field beside kind and body: {v}"
        );
        // And it is exactly what the host's own frame type writes for no body, so
        // it is one of the family rather than a lookalike.
        assert_eq!(
            serde_json::to_string(&HostFrame::new(WINDOWS_CHANGED_FRAME_KIND, ())).unwrap(),
            WINDOWS_CHANGED_FRAME
        );
    }

    /// And every joining state the daemon writes is the shape the guest reads.
    ///
    /// All four, not one: the surface branches on the tag, and a variant whose
    /// tag or field names drifted would be dropped by `serde` at the guest and
    /// look exactly like a join that stopped.
    #[test]
    fn every_joining_state_round_trips_through_the_shape_the_guest_reads() {
        let cases = [
            (
                RunnerJoiningState::Reaching {
                    relay: "droplet.austin.dev:7700".to_string(),
                },
                "reaching",
            ),
            (RunnerJoiningState::Compare, "compare"),
            (
                RunnerJoiningState::Joined {
                    relay: "droplet.austin.dev:7700".to_string(),
                    vault: Some("Vault \u{00b7} droplet".to_string()),
                    offered: true,
                },
                "joined",
            ),
            (
                RunnerJoiningState::Failed {
                    reason: "that invite has lapsed".to_string(),
                },
                "failed",
            ),
        ];
        for (state, tag) in cases {
            let json = serde_json::to_string(&HostFrame::new(JOINING_FRAME_KIND, state)).unwrap();
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(v["kind"], JOINING_FRAME_KIND);
            assert_eq!(v["body"]["state"], tag, "in {json}");
        }
        // And the compare step carries nothing but its name: the issuer does
        // not display the code (RFC-0076), so no digits reach the guest.
        let json =
            serde_json::to_string(&HostFrame::new(JOINING_FRAME_KIND, RunnerJoiningState::Compare))
                .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["body"], serde_json::json!({ "state": "compare" }), "in {json}");
    }
}

/// One `on-message` push, named so an app can tell senders apart.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostFrame<T> {
    /// Which sender this is — [`PAIRING_FRAME_KIND`] and its siblings.
    pub kind: String,
    pub body: T,
}

impl<T> HostFrame<T> {
    pub fn new(kind: &str, body: T) -> Self {
        Self { kind: kind.to_string(), body }
    }
}

/// One contact, as the occupant sees it.
///
/// Deliberately narrower than `Member`, on the same grounds as
/// [`RunnerPairedDevice`]: a name and the DID a message is addressed to. The
/// relay a contact resolves through and the epoch of their handle are the
/// node's business and would be an account map the guest has no use for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerContact {
    pub did: String,
    pub label: Option<String>,
}

/// One channel this person holds a key for, as the share sheet offers it: its
/// DID and how many people hold its current epoch. A channel has no name yet
/// (`IDEA-a-channel-has-no-name-and-nothing-lists-the-channels-a-person-is-in`),
/// and who the members are is not here: a count is what the sheet draws.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerGroup {
    pub channel_did: String,
    pub members: u32,
}

// ---------------------------------------------------------------------------
// Roots (RFC-0071 R11–R16)
// ---------------------------------------------------------------------------

/// How much of a root this device holds (R15). Never topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunnerResidency {
    Full,
    OnDemand,
}

/// Where a root is kept, as the host can honestly state it.
///
/// [`RunnerKeeping::NotYetKeptAnywhereButHere`] is the one that earns this enum
/// its third arm: a recorded target is not a copy, and a surface that renders
/// the two the same tells somebody their only copy is backed up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunnerKeeping {
    ThisDeviceOnly,
    Replicated,
    NotYetKeptAnywhereButHere,
}

/// A vault a root is kept at, as the occupant sees it (R13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerRootTarget {
    /// The handle the device's own enrolment gave the vault (`DEC-0068`).
    /// Local — never the blinded per-target id R14 requires on the wire.
    pub handle: String,
    pub label: Option<String>,
}

/// One member of a root, by AID (RFC-0038).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerRootMember {
    pub aid: String,
    /// Whether this is the person whose device this is. The daemon decides,
    /// like `RunnerPairedDevice::is_this_device` — a guest cannot recognise an
    /// AID it has no other way to know.
    pub is_you: bool,
}

/// One root, as the occupant sees it.
///
/// Deliberately narrower than the store's own `Root`: no key material, and no
/// per-path anything, because a root has no per-path anything (R12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerRoot {
    /// The store's local id for this root. Not shown to a person and never
    /// presented to infrastructure.
    pub id: String,
    /// The person's own word for it.
    pub name: String,
    pub members: Vec<RunnerRootMember>,
    pub targets: Vec<RunnerRootTarget>,
    pub residency: RunnerResidency,
    pub kept: RunnerKeeping,
    /// Where this root's tree resolves on disk.
    ///
    /// **Host-side only.** There is no guest accessor for it, for the reason
    /// `DirHandle::abs_root` has none: a path the person chose is a durable
    /// identifier two guests could join on (RFC-0021, and
    /// `TASK-the-root-path-is-handed-to-the-guest`). It is here so the host can
    /// mint a `directory` on the tree, and it goes no further.
    pub tree_path: String,
    /// Whether this root's tree is the one the occupant was handed at launch
    /// through its `files` grant (`files.preopens`) — the person's files on
    /// this machine, adopted in place by the store's first run.
    ///
    /// The host's word, from the store's own marker (`Root::adopts_the_mount`),
    /// so a surface finds that root by this and never by its name: it is
    /// *This PC* on a device whose first run was on or after 2026-09-24,
    /// *Personal* on one whose first run was before, and whatever the person
    /// has renamed it since (`TASK-this-pc-is-the-one-root-everyone-starts-with`).
    /// It is also the root `tree_path` is empty for: one tree, one door.
    #[serde(default)]
    pub granted: bool,
    /// Whether the occupant may **write** this root's tree, as the host decides
    /// it — the one fact both `roots.tree`'s handle and the runner's kernel
    /// profile read, so the two layers cannot disagree.
    ///
    /// **`false` for every root today, pending a ruling.** A root's boundary is
    /// its sharing boundary (RFC-0071 R12), so a person writes a root they are
    /// a member of — but the occupant is software, any installed app can be
    /// designated it, and three written rules say designation carries no data
    /// reach: RFC-0087 (*"The tier grants drawing and nothing else. No
    /// capability, no data reach."*), RFC-0069 (*"No code path reaches user
    /// data without a grant."*) and R12's own last sentence (*"a grant to
    /// software is not membership"*). Whether the occupant writes a root on its
    /// designation alone is an open design question, and a default that crosses
    /// the design does not go through by silence. `runner_roots` in `kuserd` sets this.
    ///
    /// `#[serde(default)]`, so an input written before the field existed reads
    /// as read-only — the side that crosses nothing.
    #[serde(default)]
    pub writable: bool,
}

/// One paired device, as the occupant sees it.
///
/// Deliberately narrower than `PairedNode`: no raw public key, no socket
/// addresses. The surface renders a name, a fingerprint and a date; handing it
/// the key material and the last-known addresses would be handing the guest an
/// account map it has no use for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerPairedDevice {
    /// The name a person chose, from the member record. `None` for a device
    /// that was paired without one — most of them — because the alternative
    /// source, `paired_nodes.id`, is an internal identifier.
    pub name: Option<String>,
    pub did: String,
    pub paired_at: i64,
    /// Whether this is the device the surface is running on. The daemon decides.
    pub is_this_device: bool,
    /// Whether it opens the person's files: an own device holding the data
    /// keys (`Posture::Full`), read from its member record. A vault, a
    /// cosigner and the gateway are paired and answer `false` — they carry or
    /// sign and hold no root a person reads (RFC-0071 R13, R15) — and so does
    /// a row whose member record could not be read.
    ///
    /// `#[serde(default)]`, so a frame written before the field existed reads
    /// as `false` — the side that offers a hand-over to nothing.
    #[serde(default)]
    pub opens_your_files: bool,
}

/// One admitted browser, as the occupant sees it.
///
/// A name and two dates, and nothing else crosses: not the credential id the
/// daemon keys its sessions by, not the browser's public key, not a session
/// token. The surface draws a row and names the row back to revoke it; the
/// daemon resolves the name to the admission itself, so there is nothing here
/// a guest could hold on to or replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerAdmittedBrowser {
    /// The label given at admission, e.g. `"iphone"`. Unique per person: it is
    /// the handle a revoke names.
    pub name: String,
    /// Unix seconds when the browser was admitted.
    pub admitted_at: i64,
    /// Unix seconds of its most recent visit; `None` until it returns.
    pub last_visit: Option<i64>,
}

/// The relay this device is paired with, as the occupant sees it.
///
/// Three named facts with a state each, never a sentence: a relay carries and
/// keeps nothing past delivery, so its name, whether it answered, and how much
/// of the fleet it carries for is the whole of what a person needs off the row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerRelay {
    /// The address it is reached by, without the scheme.
    pub name: String,
    /// Whether a reservation is held there now (RFC-0083 R6).
    pub reachable: bool,
    /// How many of this person's devices it carries for, counting this one.
    /// Only devices that have said they reserve there are counted.
    pub relays_for: u32,
}

/// A vault this device has enrolled, as the occupant sees it.
///
/// Deliberately narrower than the enrolment record: no cache directory, no key
/// format, no mount name. What is here is what a person reads off a row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerVault {
    /// The word the person saw when they enrolled it, where there was one.
    pub label: Option<String>,
    /// The relay it reserves at, as this device last learned it (RFC-0083 R5).
    pub through: Option<String>,
    /// What it holds, in the person's words.
    pub holds: String,
    /// Bytes held and bytes bought, as the vault last told this device.
    ///
    /// `None` rather than `0`, for the reason [`crate::ipc::SyncStatusResult`]'s
    /// `pending_changes` is an option: the capacity of a vault nobody has asked
    /// is not zero, and a number that says otherwise is the product
    /// misreporting itself.
    pub held_bytes: Option<u64>,
    pub bought_bytes: Option<u64>,
    /// Whether this device has a live connection to it right now.
    pub answering: bool,
    /// Whether this person holds the vault's operator credential — the vault
    /// is their own, and Settings lists it as *yours*, enrolled or not
    /// (`TASK-the-landlords-verbs-reach-the-desktop-over-the-wire`). Read from
    /// the sealed object the credential is kept in; nothing is dialled.
    #[serde(default)]
    pub yours: bool,
    /// The vault's name when [`Self::yours`] — the name its operator
    /// credential was minted under, which the landlord's vault verbs are
    /// spoken to (`interface landlord`). `Some` exactly when `yours` is true.
    #[serde(default)]
    pub vault_name: Option<String>,
    /// The name of the relay this person operates that their desktop told this
    /// vault to stand at, matched by the relay's key and never its URL
    /// (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`) — what the
    /// relay's rule is read and set by. `None` when they operate no such relay.
    #[serde(default)]
    pub relay_name: Option<String>,
    /// Where this desktop told the vault to stand — the first relay of the set,
    /// at the address it was told — and when, in Unix seconds. `None` for a
    /// vault it told nothing, or one not its own
    /// (`TASK-settings-has-one-door-and-it-takes-a-code`, clause (3)).
    #[serde(default)]
    pub stands_at: Option<String>,
    #[serde(default)]
    pub told_at: Option<u64>,
}

/// One person a vault of the landlord's keeps for, as the occupant reads them
/// (`interface landlord`'s `tenant`).
///
/// The shape of [`crate::ipc::VaultTenant`] with the names a surface reads: a
/// name, two numbers and a count. Nothing here names a device or a key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerTenant {
    /// The name the landlord gave their pool at the invite.
    pub name: String,
    /// Sealed bytes held in their pool.
    pub held_bytes: u64,
    /// The space set aside for them, `None` when the vault's default holds them.
    pub space_bytes: Option<u64>,
    /// How many of their devices are paired with the vault.
    pub devices: u32,
}

/// What this device says about its own name and reach.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerThisDevice {
    /// The name this device answers to on the person's own network.
    pub name: String,
    /// Whether a peer on the same network can reach this one without the relay
    /// carrying anything — read from where the peer listener actually bound.
    pub local_reach: bool,
}

/// The pre-auth verbs, mirroring `interface auth` in `world occupant`.
///
/// A separate enum from [`RunnerHostCall`] so that adding a fetcher capability
/// cannot accidentally read as adding an auth one, and so the whole of what the
/// occupant may ask is one list a reader can finish.
///
/// **A passphrase and a PIN cross as [`crate::ipc::SecretText`]**, as they do
/// on the user channel: the plain string on the wire, `<redacted>` in a `{:?}`.
/// This enum derives `Debug`, and a mismatched reply is reported by formatting
/// it, so a plain `String` here is a passphrase in an error a guest is shown.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum RunnerAuthVerb {
    /// Unlock an existing identity with a passphrase.
    Unlock { passphrase: crate::ipc::SecretText },
    /// Create a new identity protected by a passphrase, called `display_name`
    /// on this device. The answer carries the DID, which is why this cannot be
    /// a queued effect.
    ///
    /// The name is what the person typed on the welcome and is stored beside an
    /// id the daemon mints; the guest never learns or chooses the id
    /// (`TASK-the-name-the-welcome-asks-for-goes-nowhere`). Empty means no
    /// name, and the shell draws its fallbacks until one is set.
    CreateIdentity {
        passphrase: crate::ipc::SecretText,
        display_name: String,
    },
    /// Change what this device calls the one identity it holds. Empty clears
    /// it. Refused unless that person is unlocked: the verb is reachable from
    /// the lock screen, and a name is changed by the person it names.
    SetDisplayName { name: String },
    /// Unlock using a device PIN shortcut.
    UnlockWithPin {
        user_id: String,
        pin: crate::ipc::SecretText,
    },
    /// Ask for a credential this device will accept. Reads nothing and stores
    /// nothing — it is a draw, so it needs no argument and grants no authority.
    SuggestCredential,
    /// Ask which identity this device holds. Takes no argument for the same
    /// reason `unlock` does not: there is one answer, or the device has several
    /// identities and naming one would be picking for the person.
    ReadIdentity,
}

/// The identity a device holds, as the occupant sees it.
///
/// Narrower than `UserRecord`, which is the file this is read from: a `did`,
/// the day it was registered and the name the person goes by, and nothing else
/// the record grows later. The surface renders the name, a fingerprint and a
/// date.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerIdentity {
    /// The local account id: the directory under `users/` and the value
    /// `unlock-with-pin` names. **Carried, never drawn.** `owner` on a device
    /// enrolled before 2026-09-24; a minted value the person has never seen on
    /// one enrolled since (`TASK-the-name-the-welcome-asks-for-goes-nowhere`).
    pub user_id: String,
    /// What the desktop calls the person, if they have said. `None` on an
    /// older device and on an identity the CLI made, for which the surface
    /// draws its no-name fallbacks and offers to set one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The canonical `did:kel` AID. Public by construction: it is the name
    /// other people's devices address this account by.
    pub did: String,
    /// Unix seconds when this identity was registered on this device.
    pub registered_at: i64,
}

/// Why an auth verb failed, as the daemon classified it.
///
/// Mirrors the WIT `auth-error` variant. It is spelled out on the wire rather
/// than flattened to a string — unlike the fetcher's errors above — because the
/// *guest* branches on it: "wrong passphrase" asks the person to retype,
/// "no identity" routes to the welcome screen. A string would make the shell
/// parse prose to decide which screen to show.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum RunnerAuthError {
    WrongPassphrase,
    WrongPin,
    NoIdentity,
    /// The credential was refused as too weak, carrying the reason.
    ///
    /// Distinct from `Daemon` for the reason this enum is typed at all: the
    /// guest branches on it. This one means *ask again, here is why*; `Daemon`
    /// means *stop*. Folded together — as they were until 2026-08-29 — first run
    /// showed a person a dead end for a credential they could simply retype.
    WeakCredential { message: String },
    /// The device holds several identities and the verb named none.
    ///
    /// Typed on the same argument as `WeakCredential` above: the guest branches
    /// on it. Before this existed the refusal arrived as `Daemon` carrying the
    /// sentence "this device has N identities…", so a surface wanting to route
    /// to a picker had to match on that prose — the exact failure this doc
    /// comment says the enum is spelled out to avoid.
    SeveralIdentities,
    Daemon { message: String },
}

/// What a guest may ask of the surface interfaces, marshalled to the daemon.
///
/// One verb. `commit`, `close` and `raise` are effects on a surface the guest
/// already holds and ride the drained queues instead; only *getting* one needs
/// an answer.
// `Copy` was dropped when `SetTitle` arrived: the verb carries a `String` now, and
// nothing moved — every call site already passes it by value or by reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RunnerSurfaceVerb {
    /// Open an additional surface for this instance.
    ///
    /// The size is a request, as it is at launch: the compositor owns geometry
    /// and treats it as a maximum.
    Create {
        role: crate::surface::SurfaceRole,
        /// Which screen edge a `Panel` hangs from; `None` for every other role.
        /// An anchor the host places from, never a position the app names —
        /// see [`crate::surface::PanelEdge`].
        edge: Option<crate::surface::PanelEdge>,
        width: u32,
        height: u32,
    },
    /// Give a surface back (RFC-0087 stage 3c).
    ///
    /// **A call, not a queued effect, because the daemon's list is what answers
    /// it.** The instance's surfaces are counted against
    /// [`crate::surface::MAX_SURFACES_PER_INSTANCE`] on the daemon's side, so a
    /// close that had not reached the daemon yet would leave an app that gave
    /// up a window still holding it as far as the cap is concerned — and a
    /// desktop that opens and closes windows all day would run out.
    ///
    /// It was a stub until stage 3c: `surface.close` logged and returned `ok`,
    /// so the WIT said an app could give a surface back and nothing did. That
    /// went unnoticed while every app had exactly one surface it never wanted
    /// to be rid of.
    Close { surface: crate::surface::SurfaceHandle },
    /// Ask again for a size on a surface this instance already holds — the
    /// guest's `surface.request-size`.
    ///
    /// **Real since `TASK-the-dock-is-its-pill-and-the-band-beside-it-is-nothing`;
    /// a stub before it.** The WIT has carried `request-size` since stage 1 and
    /// `KuidRequest::SurfaceResize` has existed the whole time with nothing
    /// sending it, so the promise that an app could ask again was a promise
    /// nothing kept. The dock is what needed it: a bottom panel's surface is now
    /// the width it asked for, and the width its items need is something the
    /// shell knows only after it has laid them out — so the size at creation
    /// cannot be the last word.
    ///
    /// **A call, not a queued effect, because the daemon's list is what answers
    /// it** — the same reason [`Self::Close`] is one. The surface is resolved
    /// against this instance's own surfaces before anything is forwarded, so a
    /// handle the runner got wrong is refused here rather than resized in the
    /// compositor. `raise` queues because it names nothing the daemon holds; this
    /// does.
    ///
    /// The size is a request, exactly as it is at `Create`. The compositor owns
    /// geometry, clamps it to the output, and may answer with nothing happening.
    Resize {
        surface: crate::surface::SurfaceHandle,
        width: u32,
        height: u32,
    },
    /// Say what one of this instance's surfaces is about — the guest's
    /// `surface.set-title`.
    ///
    /// **A call, not a queued effect, for the reason [`Self::Close`] and
    /// [`Self::Resize`] are**: the surface is resolved against this instance's
    /// own surfaces before anything is forwarded, so a handle the runner got
    /// wrong is refused here rather than retitling somebody else's window. It is
    /// also where the string is *cut* to
    /// [`crate::surface::MAX_TITLE_CHARS`] — the daemon holds the bound, because
    /// the daemon is the first process on this path a confined one cannot be.
    ///
    /// What happens to the text after that is the host's whole answer: it is
    /// drawn in the host's chrome, in the host's font and ink, in the position
    /// the host chose. The guest supplies characters and nothing else, which is
    /// what keeps a title from being a place to draw a second system.
    SetTitle {
        surface: crate::surface::SurfaceHandle,
        title: String,
    },
    /// Every open `Window` surface, as the designated app is told about them
    /// (RFC-0087 stage 3b).
    ///
    /// Answered rather than pushed, for the reason `Create` is: the guest is
    /// holding the call, and what it gets back has to be built on the daemon's
    /// side — the ids in it are minted for *this* instance out of a list only
    /// the daemon holds. A push would need an export the designated world alone
    /// carries, and the two worlds' exports are identical by construction (see
    /// `core/wasm`'s bindgen note).
    ///
    /// A frame naming this verb from an undesignated instance is a bug in the
    /// confinement boundary, exactly as a `Background` create is: the interface
    /// that can ask is not in an ordinary app's linker.
    ListWindows,
    /// The designated app asks that a window it was listed be brought to the
    /// front, restoring it first if the person had minimised it.
    ///
    /// The id is the one **this instance** was given in [`Self::ListWindows`].
    /// It is resolved against that instance's own list, so an id it was never
    /// given names nothing and the answer is an error rather than another app's
    /// window. What happens then is `kuid`'s: this is the same ask
    /// `surface.raise` makes, on behalf of a window the asker does not hold.
    RaiseWindow { window: u64 },
}

/// The daemon's answer to a [`RunnerHostCall`].
///
/// Errors are carried as strings rather than typed variants: the runner's only
/// job is to hand them back to the guest as its world's error type, and keeping
/// the wire shape flat avoids duplicating the error taxonomy in a third place.
// `Eq` is absent because `RunnerInferVerb::Generate` carries `Options`, whose
// `temperature` is an `f32`, and a float has no total equality. `PartialEq` is
// what the tests and the dispatch actually use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum RunnerHostReply {
    /// A mediated response.
    NetResponse { response: HostResponse },
    /// The request was refused or failed; the message is shown to the guest.
    NetError { message: String },
    /// A quarantine write succeeded.
    QuarantineWritten,
    /// A quarantine read succeeded.
    QuarantineContent { content: Vec<u8> },
    /// A quarantine listing succeeded.
    QuarantineKeys { keys: Vec<String> },
    /// A quarantine operation failed; the message is shown to the guest.
    QuarantineError { message: String },
    /// A new identity was minted.
    ///
    /// No mnemonic: creation does not produce one any more — an identity starts
    /// with a random key and no recovery authority, and setting recovery up is a
    /// later, separate act. This reply used to carry the phrase on the grounds that
    /// it was the only time it could ever cross the wire, which was true and is why
    /// it does not belong on the reply to a verb nobody asked a phrase of.
    AuthIdentity { did: String },
    /// An unlock succeeded; the token names the resulting session.
    AuthSession { token: crate::ipc::SecretText },
    /// A credential the device would accept, offered for the person to take —
    /// the passphrase they are about to hold, so it prints `<redacted>`.
    AuthCredentialSuggestion { credential: crate::ipc::SecretText },
    /// The identity this device holds.
    AuthIdentityRead { identity: RunnerIdentity },
    /// The display name was changed.
    AuthDisplayNameSet,
    /// An auth verb failed, classified.
    AuthFailed { error: RunnerAuthError },
    /// The device roster.
    Devices { devices: Vec<RunnerPairedDevice> },
    /// The browsers admitted for this person, oldest first.
    Browsers { browsers: Vec<RunnerAdmittedBrowser> },
    /// The relay this device is paired with, `None` when none is named.
    NetworkRelay { relay: Option<RunnerRelay> },
    /// Every vault this device has enrolled.
    NetworkVaults { vaults: Vec<RunnerVault> },
    /// This device's own name and local reachability.
    NetworkDevice { device: RunnerThisDevice },
    /// Every relay this person runs.
    NetworkOperatedRelays { relays: Vec<RunnerOperatedRelay> },
    /// A network readout failed; the message is shown to the guest.
    NetworkFailed { message: String },
    /// A joining verb was taken. It says nothing about how the attempt ends —
    /// that arrives at `on-message`, because pairing a relay is a dial and
    /// admitting an invite is a ceremony, and neither is a value a call can
    /// return.
    JoinOk,
    /// A joining verb was refused before anything started, in the words the
    /// surface shows.
    JoinFailed { message: String },
    /// Who a vault of the landlord's keeps for.
    LandlordPeople { tenants: Vec<RunnerTenant> },
    /// The invite a vault minted, to send to the person it names. A bearer's
    /// words, as `UserResponse::RelayInvite`'s are, so it prints `<redacted>`.
    LandlordInvite { invite: crate::ipc::SecretText },
    /// A landlord's verb was done — a pool dropped.
    LandlordOk,
    /// The rule the relay holds now.
    LandlordRule { rule: crate::rendezvous::AdmissionRule },
    /// What a pasted code names.
    LandlordResolved { resolved: RunnerResolved },
    /// A line completed at the door.
    LandlordEnrolled { enrolled: RunnerEnrolled },
    /// A landlord's verb was refused, or the service did not answer, in words.
    LandlordFailed { message: String },
    /// This machine's operators, as the occupant reads them.
    OperatorBox { operators: RunnerOperatorBox },
    /// An operator verb was done.
    OperatorsOk,
    /// An operator verb was refused, or `kdeviced` did not answer, in words.
    OperatorsFailed { message: String },
    /// A file's contents, answering [`RunnerFileVerb::Read`].
    FileContent {
        #[serde(with = "crate::base64_bytes")]
        data: Vec<u8>,
    },
    /// A write or a delete was done.
    FileDone,
    /// A directory's immediate children, answering [`RunnerFileVerb::List`].
    FileEntries { entries: Vec<RunnerDirEntry> },
    /// What a path names, answering [`RunnerFileVerb::Kind`]; `None` is nothing.
    FileKind { kind: Option<RunnerPathKind> },
    /// The generation at which a file's current version entered the log,
    /// answering [`RunnerFileVerb::Logged`]; `None` is *not yet*.
    FileLogged { generation: Option<u64> },
    /// A `files` verb was refused or failed; the message is shown to the guest.
    FileFailed { message: String },
    /// The models that answer on this machine.
    InferModels { models: Vec<RunnerModelInfo> },
    /// The answer to an embed.
    InferEmbedding { vector: Vec<f32> },
    /// A generation started; the handle is what [`RunnerInferVerb::Next`] pulls.
    InferGeneration { generation: u64 },
    /// One token, or `None` at the end of the answer. `metering` is present
    /// only on the terminating reply — numbers and only numbers (IN9).
    InferToken {
        text: Option<String>,
        metering: Option<RunnerMetering>,
    },
    /// An inference verb failed, in the guest's taxonomy.
    InferFailed { error: RunnerInferError },
    /// The daemon minted and opened a surface; this is its handle.
    ///
    /// The runner turns it into a `resource` in the asking guest's own table and
    /// the value never goes back the other way — the guest holds the resource,
    /// never the handle, so there is nothing for it to forge from.
    SurfaceCreated { handle: crate::surface::SurfaceHandle },
    /// The surface named by [`RunnerSurfaceVerb::Close`] is closed and is no
    /// longer counted against this instance.
    SurfaceReleased,
    /// The size asked for by [`RunnerSurfaceVerb::Resize`] was forwarded to the
    /// compositor.
    ///
    /// It says the ask reached the display server, not that a surface changed
    /// size: geometry is `kuid`'s and it may answer nothing, which is not an
    /// error. The same sentence [`Self::SurfaceRaised`] carries, for the same
    /// reason.
    SurfaceResized,
    /// The title asked for by [`RunnerSurfaceVerb::SetTitle`] was recorded and
    /// forwarded to the compositor.
    ///
    /// It says the daemon took the string, not that any pixels changed — the
    /// bar is redrawn by `kuid` when `kuid` gets to it, which is the same
    /// sentence [`Self::SurfaceResized`] carries. It also does not say the
    /// string arrived whole: a title past
    /// [`crate::surface::MAX_TITLE_CHARS`] is cut, and the guest is not told,
    /// because how long the host's bar can be is not the guest's business.
    SurfaceTitled,
    /// The surface was not created, and the message is shown to the guest.
    ///
    /// The one reachable reason is the per-instance cap
    /// ([`crate::surface::MAX_SURFACES_PER_INSTANCE`]), which is a resource
    /// bound rather than an authority check: a guest that may not create a
    /// `Background` has no interface to ask on, so it never arrives here.
    SurfaceFailed { message: String },
    /// The window list, in the host's words, with ids minted for the asking
    /// instance (RFC-0087 stage 3b).
    ///
    /// Front-most last, which is the order the compositor paints in, so a dock
    /// can show the stack without being told what the stack means.
    SurfaceWindows { windows: Vec<crate::surface::WindowView> },
    /// The raise was forwarded to the compositor.
    ///
    /// It says the ask reached the display server, not that a window moved:
    /// stacking is `kuid`'s and it may answer nothing, which is not an error
    /// (`surface.raise` says the same).
    SurfaceRaised,
    /// A device verb that returns nothing succeeded — a revoke, a rename.
    DeviceOk,
    /// A device verb failed; the message is shown to the guest.
    ///
    /// One error type, unlike auth's taxonomy, because the guest has nothing to
    /// branch on: there is no "ask again" arm for a revoke that did not happen.
    DeviceFailed { message: String },
    /// A message was sealed and filed; `delivery` is the one word the sender is
    /// owed, or `None` where the question does not arise (a channel message).
    MessageSent {
        id: String,
        delivery: Option<String>,
    },
    /// Sealed messages, newest first.
    MessageList { messages: Vec<RunnerSealedMessage> },
    /// The channels this person holds a key for ([`RunnerMessageVerb::Groups`]).
    MessageGroups { groups: Vec<RunnerGroup> },
    /// One message, opened on the node.
    MessageOpened { text: String },
    /// How many messages are unread (`DEC-0061`).
    MessageUnread { count: u64 },
    /// What each message the person sent one conversation reads as: the record
    /// id and the one word, and while it waits, when it is next tried.
    MessageDeliveries {
        readings: Vec<crate::ipc::DeliveryReading>,
    },
    /// A read mark was recorded. `moved` is false when the mark was already at
    /// or past the position given, which is the ordinary case for a surface
    /// re-marking a conversation nothing has arrived in.
    MessageRead { moved: bool },
    /// A messaging verb failed; the message is shown to the guest.
    MessageFailed { message: String },
    /// The people this person has paired with.
    ContactList { contacts: Vec<RunnerContact> },
    /// A contacts verb failed; the message is shown to the guest.
    /// A contacts verb that answers with nothing but success — the ceremony
    /// verbs, whose result arrives later at `on-message` rather than here.
    ContactOk,
    ContactFailed { message: String },
    /// What another app holds, in its manifest's order.
    GrantHoldings { holdings: Vec<RunnerHolding> },
    /// The holding that reaches the path asked about, or `None`.
    GrantCovering { holding: Option<RunnerHolding> },
    /// The installed apps a file can be opened in, by name.
    GrantOpeners { openers: Vec<RunnerOpener> },
    /// A grants verb failed; the message is shown to the guest.
    GrantFailed { message: String },
    /// A root's records of one schema.
    RecordList { records: Vec<RunnerRecord> },
    /// A record was written into a root; its id.
    RecordAdded { id: String },
    /// A records verb failed — including a root the person is not a member
    /// of, which is refused whether it exists or not.
    RecordFailed { message: String },
    /// The records of one schema kept in the person's roots, each with the
    /// person's word for the root it is kept in. See [`RunnerHostCall::Kept`].
    RecordsKept { records: Vec<RunnerKeptRecord> },
}

// A reply that answers a call it was not sent for is named to the guest, never
// printed: the runner's ports say which variant came and nothing of what it held.
variant_names!(RunnerHostReply {
    NetResponse, NetError, QuarantineWritten, QuarantineContent, QuarantineKeys, QuarantineError,
    AuthIdentity, AuthSession, AuthCredentialSuggestion, AuthIdentityRead, AuthDisplayNameSet,
    AuthFailed, Devices, Browsers, NetworkRelay, NetworkVaults, NetworkDevice,
    NetworkOperatedRelays, NetworkFailed, JoinOk, JoinFailed, LandlordPeople, LandlordInvite,
    LandlordOk, LandlordRule, LandlordResolved, LandlordEnrolled, LandlordFailed, OperatorBox,
    OperatorsOk, OperatorsFailed, FileContent, FileDone, FileEntries, FileKind, FileLogged,
    FileFailed, InferModels, InferEmbedding, InferGeneration, InferToken, InferFailed,
    SurfaceCreated, SurfaceReleased, SurfaceResized, SurfaceTitled, SurfaceFailed,
    SurfaceWindows, SurfaceRaised, DeviceOk, DeviceFailed, MessageSent, MessageList,
    MessageGroups, MessageOpened, MessageUnread, MessageDeliveries, MessageRead, MessageFailed,
    ContactList, ContactOk, ContactFailed, GrantHoldings, GrantCovering, GrantOpeners,
    GrantFailed, RecordList, RecordAdded, RecordFailed, RecordsKept,
});

/// One app a running guest asked the host to open, and what it asked for it to
/// be opened on.
///
/// A record rather than a tuple because it crosses the runner's stdio boundary:
/// `(String, Option<String>, Vec<(String, String)>)` in a JSON frame is three
/// positions a reader has to count, and the third one is the interesting one.
///
/// **`args` is what the caller *asked* for, not what the launched app receives.**
/// The host composes the real launch arguments and drops every key it authors
/// itself — who the app is running as, and which screen a shell opens on — in
/// `guest_launch_args` (`core/app/src/daemon/apps.rs`). The pen principle: the
/// confined thing names what it wants, the host writes what actually happens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchRequest {
    /// The app to open, by NSID.
    pub app_nsid: String,
    /// What to put in the title bar of a freshly opened window.
    #[serde(default)]
    pub name: Option<String>,
    /// Launch arguments the caller asked for. Empty for `apps::launch`, which
    /// carries none; the conventional key from `apps::launch-with-args` is
    /// `"path"`, relative to the *launched* app's own granted root.
    #[serde(default)]
    pub args: Vec<(String, String)>,
}

/// One rendered patch and the surface it is for (RFC-0087 stage 2).
///
/// **The handle is what makes a patch stream per-surface.** Until 2026-09-18
/// this wire carried a bare `Vec<u8>` and the daemon routed every patch to the
/// instance's one surface — `AppHost::surface_of`, the reverse lookup stage 1
/// left behind as *"the one assumption stage 2 has to revisit"*. The SDK's
/// render path already took its surface as an argument; this wire did not, so
/// an instance with two surfaces would have painted both of them onto the
/// first.
///
/// The guest cannot write a handle it was not given: `commit` is a method on a
/// `resource` it holds, and the host reads the handle off its own table entry
/// (`SurfaceEntry`). So the daemon forwards this without an ownership check,
/// for the same reason it forwards a raise without one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfacePatch {
    /// Which of the instance's surfaces this patch paints.
    pub surface: crate::surface::SurfaceHandle,
    /// Format: first byte is version (`0x01` = full HTML string, `0x02` =
    /// Dioxus mutation batch).
    pub patch: Vec<u8>,
}

/// Output JSON written by `kotton-runner` to stdout after handling an op.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum RunnerOutput {
    /// Successful launch. `patches` contains surface patches committed during `on-launch`.
    Launched {
        #[serde(default)]
        patches: Vec<SurfacePatch>,
        /// Apps the guest requested to launch via `apps::launch` or
        /// `apps::launch-with-args`.
        #[serde(default)]
        launches: Vec<LaunchRequest>,
        /// Surfaces the guest asked to be raised (RFC-0087).
        #[serde(default)]
        raises: Vec<crate::surface::SurfaceHandle>,
    },
    /// A message was delivered and the app optionally committed surface patches.
    MessageHandled {
        #[serde(default)]
        patches: Vec<SurfacePatch>,
        /// Apps the guest requested to launch via `apps::launch` or
        /// `apps::launch-with-args`.
        #[serde(default)]
        launches: Vec<LaunchRequest>,
        /// Surfaces the guest asked to be raised (RFC-0087).
        #[serde(default)]
        raises: Vec<crate::surface::SurfaceHandle>,
    },
    /// An input event was delivered and the app optionally re-rendered.
    InputHandled {
        #[serde(default)]
        patches: Vec<SurfacePatch>,
        /// Apps the guest requested to launch via `apps::launch` or
        /// `apps::launch-with-args`.
        #[serde(default)]
        launches: Vec<LaunchRequest>,
        /// Surfaces the guest asked to be raised (RFC-0087).
        ///
        /// A queued effect, like `launches` and for the same reason: `raise` is
        /// a request with no answer the guest waits for, so it rides out with
        /// the result rather than blocking the call. The handle is one the
        /// guest *holds* — it has no way to write a handle it was not given —
        /// so the daemon forwards it without an ownership check.
        #[serde(default)]
        raises: Vec<crate::surface::SurfaceHandle>,
    },
    /// `on-surface-error` completed (fire-and-forget; no patches expected).
    SurfaceErrorHandled,
    /// The runner is **blocked** on the daemon: a confined extension called a
    /// host capability the runner deliberately does not hold (RFC-0049).
    ///
    /// Not a terminal frame. The daemon must answer with a
    /// [`RunnerOp::HostReply`] on stdin; the runner then resumes the guest and
    /// eventually emits a terminating result.
    HostCall { call: RunnerHostCall },
    /// One fetch cycle completed. `wrote` is the quarantine keys the extension
    /// wrote during it, so the daemon can surface what arrived for promotion
    /// without reading quarantine content itself.
    Fetched {
        #[serde(default)]
        wrote: Vec<String>,
    },
    /// The op failed. `message` is a human-readable error string.
    Error { message: String },
}

#[cfg(test)]
mod file_frame_tests {
    use super::*;

    /// A file's bytes cross the runner wire as base64, both ways, and come back
    /// byte for byte — including bytes that are not text.
    ///
    /// A bare `Vec<u8>` in JSON is an array of numbers, about four times the
    /// size of the file; every save the editor makes and every read the file
    /// browser makes now crosses this pipe, so the encoding is not cosmetic.
    #[test]
    fn a_files_frame_carries_its_bytes_as_base64_and_round_trips() {
        let data: Vec<u8> = (0u8..=255).collect();
        let call = RunnerHostCall::Files {
            verb: RunnerFileVerb::Write {
                path: "/notes/a.md".to_string(),
                data: data.clone(),
            },
        };
        let json = serde_json::to_string(&call).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v["verb"]["data"].is_string(),
            "the bytes are not a base64 string on the wire: {json}"
        );
        assert_eq!(serde_json::from_str::<RunnerHostCall>(&json).unwrap(), call);

        let reply = RunnerHostReply::FileContent { data };
        let json = serde_json::to_string(&reply).unwrap();
        assert!(json.len() < 2 * 256 + 64, "a 256-byte read took {} bytes", json.len());
        match serde_json::from_str::<RunnerHostReply>(&json).unwrap() {
            RunnerHostReply::FileContent { data: back } => {
                assert_eq!(back, (0u8..=255).collect::<Vec<u8>>())
            }
            other => panic!("expected FileContent, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod secret_debug_tests {
    //! **No secret the runner wire carries prints through `Debug`.** Every
    //! enum here derives it, and the daemon formats a frame it could not
    //! service into the error that drops the instance, so every field that
    //! holds a passphrase, a PIN, a session token, a suggested credential, a
    //! code that admits or a header the guest wrote is [`SecretText`]: the
    //! plain string on the wire, `<redacted>` in a `{:?}`. What a guest is
    //! shown of a reply it was not owed is narrower still: its `name()`.

    use super::*;
    use crate::ipc::SecretText;

    const PASSPHRASE: &str = "velvet-orchard-passphrase-4417";
    const PIN: &str = "86420975";
    const TOKEN: &str = "session-7c1e9b0d4a62f835";
    const SUGGESTED: &str = "harbour-lantern-trellis-9052";
    const WORDS: &str = "ember-tundra-sapphire";
    const INVITE: &str = "kotton-invite:vault:ab12:fame-cheap-unfold:cd34@http://relay.example:7700";

    fn s(text: &str) -> SecretText {
        SecretText::new(text)
    }

    /// `value` prints `<redacted>` and not `secret`, and its JSON still
    /// carries `secret` as it was written.
    fn hides<T: std::fmt::Debug + Serialize>(value: &T, secret: &str) {
        let printed = format!("{value:?}");
        let wire = serde_json::to_string(value).unwrap();
        assert!(!printed.contains(secret), "{secret:?} prints in {printed}");
        let on_wire = serde_json::to_string(secret).unwrap();
        assert!(wire.contains(&on_wire), "{secret:?} is not on the wire as written: {wire}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }

    #[test]
    fn no_auth_verb_prints_the_passphrase_or_pin_it_carries() {
        hides(&RunnerAuthVerb::Unlock { passphrase: s(PASSPHRASE) }, PASSPHRASE);
        hides(
            &RunnerAuthVerb::CreateIdentity { passphrase: s(PASSPHRASE), display_name: "Austin".into() },
            PASSPHRASE,
        );
        hides(&RunnerAuthVerb::UnlockWithPin { user_id: "alice".into(), pin: s(PIN) }, PIN);
        // As the runner frames it: the verb inside the call on its stdout.
        hides(
            &RunnerOutput::HostCall {
                call: RunnerHostCall::Auth { verb: RunnerAuthVerb::Unlock { passphrase: s(PASSPHRASE) } },
            },
            PASSPHRASE,
        );
    }

    #[test]
    fn no_auth_reply_prints_the_token_or_credential_it_carries() {
        hides(&RunnerHostReply::AuthSession { token: s(TOKEN) }, TOKEN);
        hides(&RunnerHostReply::AuthCredentialSuggestion { credential: s(SUGGESTED) }, SUGGESTED);
        // As the daemon frames it: the reply inside the op on the runner's stdin.
        hides(&RunnerOp::HostReply { reply: RunnerHostReply::AuthSession { token: s(TOKEN) } }, TOKEN);
    }

    #[test]
    fn no_code_that_admits_prints_on_the_runner_wire() {
        hides(&RunnerJoinVerb::Admit { invite: s(INVITE) }, INVITE);
        hides(&RunnerContactVerb::PairJoin { code: s(WORDS), label: None }, WORDS);
        hides(&RunnerPairingState::Advertising { code: s(WORDS) }, WORDS);
        hides(&RunnerHostReply::LandlordInvite { invite: s(INVITE) }, INVITE);
        hides(&RunnerLandlordVerb::Resolve { code: s(INVITE) }, INVITE);
        hides(&RunnerLandlordVerb::Enrol { code: s(INVITE) }, INVITE);
    }

    /// A literal header is whatever the guest wrote, a bearer token among
    /// them, so it prints `<redacted>` wherever the request does.
    #[test]
    fn no_literal_header_prints_the_value_it_carries() {
        const BEARER: &str = "Bearer 3f9a1c7e-guest-held";
        hides(&HostHeaderValue::Literal { value: s(BEARER) }, BEARER);
        hides(
            &RunnerOutput::HostCall {
                call: RunnerHostCall::NetRequest {
                    request: HostRequest {
                        method: "GET".into(),
                        url: "https://api.example.com/".into(),
                        headers: vec![("authorization".into(), HostHeaderValue::Literal { value: s(BEARER) })],
                        body: vec![],
                    },
                },
            },
            BEARER,
        );
    }

    /// A variant's name is its identifier and carries nothing of its fields:
    /// the content, the secret and the handle a reply holds are all absent.
    #[test]
    fn a_reply_is_named_without_anything_it_holds() {
        let opened = RunnerHostReply::MessageOpened { text: "meet me at the harbour".into() };
        assert_eq!(opened.name(), "MessageOpened");
        assert_eq!(RunnerHostReply::AuthSession { token: s(TOKEN) }.name(), "AuthSession");
        assert_eq!(RunnerHostReply::QuarantineWritten.name(), "QuarantineWritten");
        assert_eq!(RunnerOp::Message { msg: "{\"secret\":1}".into() }.name(), "Message");
        assert_eq!(RunnerOp::Terminate.name(), "Terminate");
    }

    /// The JSON a guest and a runner from before this change read is the JSON
    /// they read now: `SecretText` is transparent, so the frame decodes from
    /// the plain string it always was.
    #[test]
    fn a_secret_decodes_from_the_plain_string_it_always_was() {
        let verb: RunnerAuthVerb =
            serde_json::from_str(&format!(r#"{{"verb":"unlock_with_pin","user_id":"alice","pin":"{PIN}"}}"#)).unwrap();
        assert_eq!(verb, RunnerAuthVerb::UnlockWithPin { user_id: "alice".into(), pin: s(PIN) });
        let state: RunnerPairingState =
            serde_json::from_str(&format!(r#"{{"state":"advertising","code":"{WORDS}"}}"#)).unwrap();
        assert_eq!(state, RunnerPairingState::Advertising { code: s(WORDS) });
    }

    /// The rule for a field not written yet: one named for a secret is
    /// `SecretText`, or this names it. Read from this file's own source,
    /// skipping its test modules (each a `#[cfg(test)]` through the `}` that
    /// closes it at the margin), because the runner wire has no recorded
    /// surface.
    ///
    /// `credential` is exempt in one place, by type: `HostHeaderValue`'s
    /// [`HostCredentialRef`] is the *reference* the daemon resolves, the type
    /// that keeps the material off this wire, and holds nothing to redact.
    ///
    /// `value` is here for `HostHeaderValue::Literal`, the one field on this
    /// wire a guest writes a header into, credentials included; a `value`
    /// added later is asked the same question rather than passed by default.
    #[test]
    fn every_runner_field_named_for_a_secret_is_secret_text() {
        const SECRET_NAMES: [&str; 10] = [
            "passphrase", "pin", "token", "credential", "code", "invite", "recovery_key", "share_hex", "secret",
            "value",
        ];
        const REFERENCES: [&str; 1] = ["HostCredentialRef"];
        let mut in_tests = false;
        let wire = include_str!("runner.rs").lines().filter(|line| {
            if *line == "#[cfg(test)]" {
                in_tests = true;
            } else if in_tests && *line == "}" {
                in_tests = false;
                return false;
            }
            !in_tests
        });
        let mut plain = Vec::new();
        let mut seen = 0;
        for line in wire.map(str::trim).filter(|l| !l.starts_with("//")) {
            for (at, _) in line.match_indices(": ") {
                let name = line[..at].rsplit(|c: char| !(c.is_alphanumeric() || c == '_')).next().unwrap_or("");
                if !SECRET_NAMES.contains(&name) {
                    continue;
                }
                let ty = line[at + 2..].split([',', '}']).next().unwrap_or("").trim();
                seen += 1;
                if !ty.contains("SecretText") && !REFERENCES.iter().any(|r| ty.ends_with(r)) {
                    plain.push(format!("{name}: {ty}"));
                }
            }
        }
        // The literal header value a fetcher writes is the thirteenth.
        assert_eq!(seen, 13, "the source names {seen} secret-named fields; a field added, renamed or removed changes this count, so change it here on purpose");
        assert!(plain.is_empty(), "runner fields that print a secret through Debug: {plain:?}");
    }
}
