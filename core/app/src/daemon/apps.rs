// SPDX-License-Identifier: AGPL-3.0-or-later
//! App lifecycle IPC handlers — M18b.
//!
//! These handlers cover installing, uninstalling, listing, and launching
//! WASM apps. State lives in the `app_registry` SQLite table (migration
//! `0006_v0_6_app_registry.sql`) and in `.wasm` files on disk under
//! `{base}/apps/{app_id}/app.wasm`.

use super::db::{app_registry_db as ardb, handler_registry_db as hrdb, role_db};
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{Signer as _, Verifier as _};
use hex;
use kotton_common::crypto::kdf_labels;
use kotton_crypto::DidKeyMethod;
use kotton_diag::service::{Event, EventBus, EventCategory, EventLevel, EventScope};
use kotton_grant::daemon::db::grant_db;
use kotton_schemas::{AppKind, AppManifest, ApprovedCapabilities, CapabilityGrant, CapabilityKind};
use kotton_sys::secret::SecretsStore;
use kotton_wire::did::Did;
use kotton_wire::ipc::{SecretText, UserResponse};
use kotton_wire::runner::{
    RunnerAdmittedBrowser, RunnerAuthError, RunnerAuthVerb, RunnerContact, RunnerContactVerb, RunnerDeviceVerb,
    RunnerDirEntry, RunnerFileVerb, RunnerHostCall, RunnerHostReply, RunnerPathKind, RunnerIdentity, RunnerInferError, RunnerInferOptions,
    RunnerInferVerb, RunnerJoinVerb, RunnerLandlordVerb, RunnerOperatorBox, RunnerOperatorVerb, RunnerMessageVerb, RunnerMetering,
    RunnerGrantVerb, RunnerGroup, RunnerHolding, RunnerModelInfo, RunnerOpener, RunnerNetworkVerb, RunnerTenant,
    RunnerKeptRecord, RunnerPairedDevice, RunnerPassage, RunnerRecord, RunnerRecordVerb,
    RunnerRelay, RunnerRoot,
    RunnerRoots, RunnerSealedMessage, RunnerSurfaceVerb, RunnerThisDevice, RunnerVault,
    RootsUnread,
};
use kotton_wire::{GrantEnvelope, GrantLifetime};
use kotton_wire::{RunnerInput, RunnerMessage, RunnerOp, RunnerOutput};
use kotton_wire::{SurfaceHandle, SurfaceRole, MAX_SURFACES_PER_INSTANCE};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use uuid::Uuid;

// ── What this domain needs from its host ──────────────────────────────────────

/// One entry of the device's users registry, as a launch needs it.
///
/// Two facts and a rule about them (`TASK-the-name-the-welcome-asks-for-goes-nowhere`):
/// the id is what the daemon routes on — the directory under `users/`, the
/// value `unlock-with-pin` names — and the display name is what a surface
/// draws. **The id is never drawn.** A launch hands the shell both, in
/// separate arguments, and the shell's documents read only the second; when
/// the second is absent the shell draws its no-name fallbacks rather than the
/// first. `owner` on a device enrolled before 2026-09-24 is an id like any
/// other under this rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredUser {
    /// The local account id. Carried, never drawn.
    pub user_id: String,
    /// What the desktop calls the person, if they have said.
    pub display_name: Option<String>,
}

/// The whole of what app lifecycle asks of the node it runs on.
///
/// Enumerated rather than assumed: an event bus, three compositor verbs, and
/// the list of users registered on this device.
///
/// **The compositor is named by its verbs, not by its client.** These handlers
/// used to take `&Arc<SurfaceProxy>` — `kuserd`'s IPC client for the `kuid`
/// display server — which tied app lifecycle to a transport it has no opinion
/// about. Opening, committing and closing a surface is what apps do; *how* the
/// bytes reach a compositor is the daemon's business, including its failure
/// model (RFC-0018: a missing `kuid` is best-effort, not an error).
///
/// `registered_users` is the narrow form of a wider reach. The shell needs to
/// route to a welcome, locked, or authenticated pane without a round-trip, and
/// that needs *which* ids exist and what to call each — so the host returns
/// exactly that, rather than this file reading `device/users.json` and deciding
/// what a user record is.
#[async_trait::async_trait]
pub trait AppHost: Send + Sync {
    /// Where app lifecycle events are published.
    fn events(&self) -> &Arc<EventBus>;

    /// Users registered on this device. Empty means an unclaimed node.
    fn registered_users(&self) -> Vec<RegisteredUser>;

    /// The keychain, for the one thing a launch needs a key for: re-minting a
    /// grant envelope that predates the signed `app_id` binding (`DEC-0052`).
    ///
    /// On the host trait rather than threaded through `app_launch` and the three
    /// frames that reach it. Every service this file needs from the machine
    /// arrives this way; a parameter passed through five frames to be used at the
    /// bottom is the same dependency, written where it is harder to find.
    fn secrets(&self) -> &dyn SecretsStore;

    /// Open a surface the daemon has just minted. Best-effort: a node with no
    /// compositor is a headless node, not a broken one.
    ///
    /// `app_id` is here and **not on the compositor wire** (RFC-0087). The host
    /// needs it to record who holds the handle, so that a keystroke coming back
    /// the other way can be routed to an instance; the compositor never learns
    /// it, and cannot, because what it is told is a handle, a tier and a title.
    /// That is the whole difference between "the host knows whose surface this
    /// is" and "the display server decides whose surface this is".
    ///
    /// `spec` is one named argument rather than five positional ones — see
    /// [`kotton_wire::SurfaceSpec`], which says why. The two facts about *who* stay
    /// separate from it, and from each other: `handle` is what the compositor is told,
    /// `app_id` is what only this side keeps.
    async fn surface_open(
        &self,
        handle: SurfaceHandle,
        app_id: &str,
        spec: kotton_wire::SurfaceSpec,
    );

    /// Push a rendered patch to a surface.
    async fn surface_commit(&self, handle: SurfaceHandle, patch: Vec<u8>);

    /// Close a surface.
    async fn surface_close(&self, handle: SurfaceHandle);

    /// Forward a guest's ask for a new size on a surface it holds.
    ///
    /// Forwarded, not decided, exactly as [`Self::surface_raise`] is: the compositor owns
    /// geometry and clamps, centres or ignores the number as it sees fit. The size is a
    /// request here for the same reason it is one at `surface_open` — an app that could
    /// name a rect would be an app placing itself.
    ///
    /// Ownership *is* checked before this is called, unlike `surface_raise`: the caller
    /// resolves the handle against the asking instance's own surface list, which is the
    /// same audit [`Self::surface_close`]'s call site performs.
    async fn surface_resize(&self, handle: SurfaceHandle, width: u32, height: u32);

    /// Record what the holder of `handle` calls this window, and pass it on to the
    /// compositor to draw.
    ///
    /// **Recorded as well as forwarded**, which is what separates this from
    /// [`Self::surface_resize`]: the window list this daemon answers
    /// ([`Self::surface_windows`]) carries the title beside the name, and it is assembled
    /// from this side's own record rather than from anything `kuid` sends back. The
    /// compositor draws the title because it draws the frame; it is not asked to remember
    /// it on the daemon's behalf.
    ///
    /// `title` arrives already cut to [`kotton_wire::MAX_TITLE_CHARS`] — the caller does
    /// it, at the same place it resolves the handle against the asking instance's own
    /// surfaces.
    async fn surface_set_title(&self, handle: SurfaceHandle, title: String);

    /// Forward a guest's request that one of its surfaces be raised.
    ///
    /// Forwarded, not decided: the compositor holds the stacking order and
    /// answers this how it likes. The daemon does not check ownership either —
    /// the handle came out of a guest's own resource table, so it is one the
    /// guest holds by construction.
    async fn surface_raise(&self, handle: SurfaceHandle);

    /// Every open `Window` surface, in the host's words (RFC-0087 stage 3b).
    ///
    /// The host's view and nobody else's: the compositor reports which windows are in the
    /// stack and which are minimised, the daemon says what each is called from the record
    /// it wrote when it opened them, and neither is asked to vouch for the other's half.
    /// Front-most last.
    ///
    /// Answered by the host rather than assembled here because the join needs the private
    /// `handle -> app` map, which is the daemon's and never crosses a wire.
    async fn surface_windows(&self) -> Vec<kotton_wire::HostWindow>;

    /// Forward the designated app's ask that a window be brought back to the person —
    /// restored if they minimised it, and raised.
    ///
    /// Distinct from [`Self::surface_raise`], which is a guest asking about a surface it
    /// holds and deliberately cannot un-minimise. This one is about a window the asker does
    /// not hold, and it is the only way back from minimise there is.
    async fn surface_restore(&self, handle: SurfaceHandle);

    /// The binary that runs an app — the sandbox, as a process.
    ///
    /// Stated once by the host rather than read from the environment at each
    /// spawn, which is what this file did until 2026-09-05: two sites each
    /// consulted `KOTTON_RUNNER`, so *which process is the sandbox* was a name
    /// any environment could set between one launch and the next. The daemon
    /// resolves it at start and this is the only place the answer comes from.
    fn runner(&self) -> &Path;

    /// This person's roots, as the occupant may read them (RFC-0071 R11–R16).
    ///
    /// **On the host because this domain may not reach the object store.**
    /// `kotton-store` is a dev-dependency of `core/app` on purpose, and roots
    /// are the store's — so the daemon that holds a user's store answers, and
    /// this file asks. `base` and `own_aid` are passed in rather than looked
    /// up: the AID is identity's (RFC-0038) and this file already replays the
    /// chain for grant verification, while a store that derived an identity
    /// would be a second identity authority.
    ///
    /// **`Err` says why, and an empty `Ok` is a person with no roots.** A host
    /// with no store to read — a headless node, a test double — answers
    /// [`RootsUnread::StoreNotLoaded`], and every other way the index cannot be
    /// read has its own arm, because the surface at the far end draws *could
    /// not read* and *nothing there* as opposite facts
    /// (`TASK-a-roots-failure-is-drawn-as-no-roots`). The host logs the error
    /// where it finds it; only the cause travels.
    fn user_roots(
        &self,
        base: &Path,
        user_id: &str,
        own_aid: &str,
    ) -> Result<Vec<RunnerRoot>, RootsUnread>;

    /// Whether this person's store is loaded **with keys** — unlocked, in the
    /// sense that matters to a launch: a store loaded without a CEK refuses
    /// every plaintext read, so a desk drawn over it shows a person their
    /// files gone (`TASK-a-roots-failure-is-drawn-as-no-roots`, clause a).
    ///
    /// Asked by [`app_launch`] before it believes a caller's `Some(user_id)`.
    /// What makes the question necessary is that the claim is a name any
    /// caller can pass, threaded from the exchange that opened a session
    /// rather than from the store it opened; the two doors that mint a session
    /// now rekey the resident store as part of the exchange, so this is the
    /// one case that survives them — a rekey that failed — and the seat RFC is
    /// what would delete the question by making the claim a keyed handle.
    fn keys_loaded(&self, user_id: &str) -> bool;

    /// This person's own files, as the sealed store keeps them (RFC-0070) —
    /// what every `files` handle a guest holds is answered from
    /// (`TASK-a-file-an-app-writes-rests-in-the-clear-in-the-sealed-stores-own-directory`).
    ///
    /// **On the host for the reason [`Self::user_roots`] is**: `core/app` may
    /// not reach the object store, and the store's keys are only in the daemon
    /// that unlocked it. `None` is a person whose store is not open on this
    /// device, or a host with no store at all — a guest asking then is told its
    /// files are not open here, never handed a directory to write around them.
    fn personal_tree(&self, user_id: &str) -> Option<Arc<dyn PersonalTree>>;
}

/// A person's own tree, as the sealed store answers it — the daemon's half of
/// the runner's `FilePort`.
///
/// The verbs of `resource directory` in `interface files`, `kind` that the
/// sandbox asks to shape a handle, and `logged` that the occupant's
/// `roots.logged` asks under read authority — and nothing wider: no mount, no
/// store name, no sealed blob. Every `path` is
/// absolute in the person's tree and was checked against the asking instance's
/// grant before it got here ([`service_files_call`]). A write is sealed,
/// blinded and packable exactly as a `kotton fs write` of the same path is,
/// because it is the same store call.
///
/// **The tree is the person's files and nothing else.** An implementation
/// answers from a namespace that holds no record of the host's own — in
/// `kuserd`, the store's `PERSON_TREE_ROOT`, beside which the membership set
/// and the read marks are kept — so that a grant on `/` is a grant on every
/// file of the person's and on no record of the daemon's. That is what lets
/// [`service_files_call`] check the grant and nothing more.
#[async_trait::async_trait]
pub trait PersonalTree: Send + Sync {
    /// A file's whole contents.
    async fn read(&self, path: &str) -> Result<Vec<u8>, String>;
    /// Create or overwrite a file.
    async fn write(&self, path: &str, data: &[u8]) -> Result<(), String>;
    /// Delete a file; `Err("not found")` when there was none.
    async fn delete(&self, path: &str) -> Result<(), String>;
    /// Make an empty folder; `Err("already exists")` when anything is there.
    async fn create_dir(&self, path: &str) -> Result<(), String>;
    /// A directory's immediate children.
    async fn list(&self, path: &str) -> Result<Vec<RunnerDirEntry>, String>;
    /// Whether `path` names a file, a directory, or nothing.
    async fn kind(&self, path: &str) -> Result<Option<RunnerPathKind>, String>;
    /// The generation at which `path`'s current version entered the tree's
    /// history log; `None` while it has not (a write still loose).
    async fn logged(&self, path: &str) -> Result<Option<u64>, String>;
}

/// What the daemon can answer about inference, for any guest that imported
/// `infer` (RFC-0085, `DEC-0073`).
///
/// **Separate from [`OccupantHost`] because inference is not occupant-only.**
/// Auth, devices, messages and contacts are the shell's — a guest holds them
/// only by being the app the person designated. Any app may declare `infer.run`;
/// what it may not do is name a model it was not shown, and that is a different
/// rule enforced in a different place.
///
/// Implemented by the daemon, which is the only process that can answer: which
/// models are active is a fact in the person's **sealed** store, and the weights
/// are a sealed object only an unlocked context opens.
#[async_trait::async_trait]
pub trait InferHost: Send + Sync {
    /// The active model of each kind, as `DEC-0073` defines active.
    ///
    /// **This is the join.** The store decides which model answers; this is
    /// where that decision reaches the guest, and every later check that a guest
    /// named a model it was shown is a check against this list.
    async fn models(&self) -> Result<Vec<RunnerModelInfo>, RunnerInferError>;

    /// Embed one text with a model the guest was shown.
    async fn embed(&self, model: &str, text: &str) -> Result<Vec<f32>, RunnerInferError>;

    /// Begin one generation, returning the handle the runner will pull.
    ///
    /// The template is **not** a parameter: the daemon fills it from the
    /// manifest of the model the person installed, which is why a guest cannot
    /// put anything in front of the question.
    async fn generate(
        &self,
        model: &str,
        question: &str,
        passages: Vec<RunnerPassage>,
        options: RunnerInferOptions,
    ) -> Result<u64, RunnerInferError>;

    /// The next token of a generation, or `None` at the end. The metering rides
    /// the terminating reply and is numbers only (IN9).
    async fn next_token(
        &self,
        generation: u64,
    ) -> Result<(Option<String>, Option<RunnerMetering>), RunnerInferError>;

    /// The guest dropped its resource. Everything for this generation goes.
    async fn drop_generation(&self, generation: u64);
}

/// What the daemon can answer about the records a person keeps, for any guest
/// that calls `schema.kept` (RFC-0071 R17; RFC-0088 phase two).
///
/// **Separate from [`OccupantHost`] for the reason [`InferHost`] is.** A root's
/// own verbs — `records` and `add-record` on a held `root` — are the occupant's,
/// because only the occupant is handed roots. `schema.kept` names no root: it
/// is R17's *an app holding `schema.read` on a schema sees that schema's
/// records in every root the person is a member of*, and any app may hold that
/// grant. The grant is checked by the sandbox before the frame is sent; what
/// this answers from is the person's membership, read before any row is.
///
/// Per person, like [`InferHost`]: built for the user a request's session names,
/// and on the compositor's paths — which carry no session — for the one person
/// loaded, or for nobody when there are two (`the_one_loaded` in `kuserd`).
#[async_trait::async_trait]
pub trait RecordsHost: Send + Sync {
    /// One schema's live records in every root this person is a member of,
    /// each with the person's word for its root.
    async fn kept_records(&self, nsid: &str) -> Result<Vec<RunnerKeptRecord>, String>;
}

/// The pre-auth verbs, as the daemon's side of the occupant channel (DEC-0045).
///
/// **A separate trait from [`AppHost`] on purpose.** `AppHost` is handed to
/// every app handler in this file; putting identity creation on it would make
/// "who can mint a user" a question about which call site remembered to check,
/// across a dozen of them. This one is handed only where an occupant's host
/// call is being serviced, so the answer is "whoever was given the host" — and
/// [`app_input_event`] and friends take it as `Option`, `None` for every
/// ordinary app.
///
/// Errors are [`RunnerAuthError`] rather than `io::Error` because the guest
/// branches on them: a wrong passphrase asks the person to retype, no identity
/// routes to the welcome screen. Classification is the daemon's job — it is the
/// only side that knows — and this is where it happens.
#[async_trait::async_trait]
pub trait OccupantHost: Send + Sync {
    /// Create an identity called `display_name` on this device and return its DID.
    ///
    /// The name is stored beside an id the daemon mints; the guest never
    /// learns or picks the id (`TASK-the-name-the-welcome-asks-for-goes-nowhere`).
    /// An empty name is no name.
    ///
    /// No phrase crosses this boundary any more, because creation mints none: an
    /// identity starts with a random key and no recovery authority.
    async fn create_identity(
        &self,
        passphrase: &str,
        display_name: &str,
    ) -> Result<String, RunnerAuthError>;

    /// Change what this device calls the one identity it holds. Empty clears
    /// it. The daemon refuses it unless that person is unlocked.
    async fn set_display_name(&self, name: &str) -> Result<(), RunnerAuthError>;

    /// Unlock an existing identity, returning a session token.
    async fn unlock(&self, passphrase: &str) -> Result<String, RunnerAuthError>;

    /// A credential this device will accept. Infallible: it is a draw from a
    /// fixed list, so there is nothing for it to fail at and nothing to refuse.
    async fn suggest_credential(&self) -> String;

    /// Which identity this device holds — readable before it is unlocked.
    ///
    /// Fallible where `suggest_credential` is not, because there is something to
    /// refuse: a device with no identity yet, and a device with several, where
    /// answering would mean picking one for the person.
    async fn read_identity(&self) -> Result<RunnerIdentity, RunnerAuthError>;

    /// Unlock a named identity with a device PIN, returning a session token.
    async fn unlock_with_pin(&self, user_id: &str, pin: &str) -> Result<String, RunnerAuthError>;

    /// Every device paired to this account.
    ///
    /// On this trait rather than `AppHost` for the same reason identity creation
    /// is: a device roster is the shape of the account — who may act as you —
    /// and "who can read or revoke that" should be answered by which host was
    /// handed over, not by which call site remembered to check.
    async fn list_devices(&self) -> Result<Vec<RunnerPairedDevice>, String>;

    /// Revoke a device's pairing. Article IV's "revocable" half.
    async fn revoke_device(&self, did: &str) -> Result<(), String>;

    /// Every browser admitted for this person, oldest first.
    ///
    /// On this trait for the reason `list_devices` is: a browser is paired
    /// *like a device* (DEC-0053), so it is part of who may act as you, and
    /// who may read that is answered by which host was handed over.
    async fn list_browsers(&self) -> Result<Vec<RunnerAdmittedBrowser>, String>;

    /// Revoke one admitted browser, by the name it was admitted under.
    ///
    /// The daemon's act and the same one `BrowserDeviceRevoke` performs — the
    /// row, the sessions its admission minted, and every channel it holds open.
    async fn revoke_browser(&self, name: &str) -> Result<(), String>;

    /// The relay this device is paired with, if one is named (`interface network`).
    ///
    /// On this trait for the same reason `list_devices` is, and with one more:
    /// the address it reports is a `device_config` key in kdeviced's file, and
    /// *who may read it* should be answered by which host was handed over. The
    /// three verbs below are reads and can express nothing else — see
    /// [`RunnerNetworkVerb`](kotton_wire::runner::RunnerNetworkVerb).
    async fn paired_relay(&self) -> Result<Option<RunnerRelay>, String>;

    /// Every vault this device has enrolled (`DEC-0068`).
    async fn enrolled_vaults(&self) -> Result<Vec<RunnerVault>, String>;

    /// This device's own name and local reachability.
    async fn this_device(&self) -> Result<RunnerThisDevice, String>;

    /// Every relay this person runs, as each card reads it — its key, its
    /// address, and who this desktop told to stand there. A read of the
    /// person's own sealed credentials and record; nothing is dialled.
    async fn operated_relays(&self) -> Result<Vec<kotton_wire::runner::RunnerOperatedRelay>, String>;

    /// Admit a vault's invite (`kotton-invite:vault:…`) under the blind
    /// posture, or stand at a relay by its invite (`kotton-invite:relay:…`).
    ///
    /// `UserRequest::DeviceAdmit`, which `kotton drive enrol <invite> --blind`
    /// already sends. The posture is not an argument: only the blind posture is
    /// admitted this way, because a vault holds no key and this door cannot
    /// make one that does (`DEC-0068`).
    async fn join_admit(&self, invite: String) -> Result<(), String>;

    /// Answer the join this occupant is running with the six digits the
    /// person typed off the other end's `sas=` line.
    ///
    /// No token crosses this boundary, for the reason [`Self::pair_confirm`]
    /// takes none — and no verdict either: the implementor holds the SAS and
    /// compares, so a yes/no the person never earned cannot be said here
    /// (RFC-0076's asymmetric confirm).
    async fn join_confirm(&self, typed: String) -> Result<(), String>;

    /// Abandon a join in progress. Idempotent.
    async fn join_cancel(&self) -> Result<(), String>;

    /// Stand this device at the relay the last admit offered, on the
    /// person's yes. The implementor kept the offer; nothing crosses here.
    async fn join_take_relay(&self) -> Result<(), String>;

    /// Who the vault `vault` keeps for (`interface landlord`).
    ///
    /// On this trait for the reason the joining verbs are, with a sharper form
    /// again: these speak under the operator credential of a vault or a relay
    /// the person runs, and *who may do that* should be answered by which host was handed
    /// over. Behind all three is `UserRequest::AsOperator`, the request the
    /// desktop's `vault` and `relay` commands already send; the credential stays where
    /// `enrol` kept it and never crosses to the guest.
    async fn landlord_people(&self, vault: String) -> Result<Vec<RunnerTenant>, String>;

    /// Mint `name`'s invite on the vault and, once it is minted, set
    /// `space_bytes` aside for them; answers with the invite
    /// (`OperatorVerb::Invite`). A refused mint sets no number.
    async fn landlord_invite(
        &self,
        vault: String,
        name: String,
        space_bytes: u64,
    ) -> Result<String, String>;

    /// Drop one person's pool on the vault (`OperatorVerb::Drop`).
    async fn landlord_drop(&self, vault: String, name: String) -> Result<(), String>;

    /// Who may use the relay `relay`, as the relay reports it
    /// (`OperatorVerb::ReadRule`).
    async fn landlord_rule(&self, relay: String) -> Result<kotton_wire::rendezvous::AdmissionRule, String>;

    /// Set who may use the relay (`OperatorVerb::SetRule`), answered with
    /// the rule the relay then reports. The guest names a rule and nothing
    /// else; every key behind it stays in the daemon.
    async fn landlord_set_rule(
        &self,
        relay: String,
        rule: kotton_wire::rendezvous::AdmissionRule,
    ) -> Result<kotton_wire::rendezvous::AdmissionRule, String>;

    /// Settings' one door: what a pasted code names, writing nothing
    /// (`TASK-settings-has-one-door-and-it-takes-a-code`). An invite's words
    /// are a bearer's; the implementor logs none of them.
    async fn landlord_resolve(&self, code: String) -> Result<kotton_wire::runner::RunnerResolved, String>;

    /// Paste a vault's or a relay's line: the terminal's `enrol` of one line,
    /// completing the key this desktop minted for the instance the line names
    /// (`operator::complete`, beside `UserRequest::OperatorEnrolLines`'s handler). The code may be anything
    /// pasted, an invite's words included; the implementor logs none of it.
    async fn landlord_enrol(&self, code: String) -> Result<kotton_wire::runner::RunnerEnrolled, String>;

    /// Stand the vault `vault` at the relay this person runs as `relay`
    /// (`OperatorVerb::Move`).
    async fn landlord_move_vault(&self, vault: String, relay: String) -> Result<(), String>;

    /// This machine's operators, as the person asking may read them
    /// (`interface operators`,
    /// `TASK-this-devices-operators-box-speaks-to-kdeviced-under-the-persons-own-key`).
    ///
    /// On this trait for the landlord's reason: each verb is spoken to
    /// `kdeviced` under the person's own operator key, which the host keeps
    /// sealed in their store and the guest never holds, and *who may* is
    /// answered by which host was handed over.
    async fn operators(&self) -> Result<RunnerOperatorBox, String>;

    /// Make `person` an operator — by the key their own daemon proved, never
    /// one this caller names (`OperatorAdd`).
    async fn operator_add(&self, person: String) -> Result<(), String>;

    /// Step `person` down, once the platform has asked on its own layer and
    /// heard their name typed back (`DEC-0081`).
    async fn operator_remove(&self, person: String) -> Result<(), String>;

    /// Seal a message to `to_did` and hand it over, answering with the record id
    /// and the one word the sender is owed (`DEC-0056`).
    async fn message_send(
        &self,
        to_did: &str,
        body: &str,
    ) -> Result<(String, Option<String>), String>;

    /// Share a file with `to_did` — a direct message whose `type` is `share`,
    /// on [`Self::message_send`]'s path (RFC-0090, *Delivery › To one person*) —
    /// answering as that does. `origin` stays on the sender's own copy.
    async fn message_share(
        &self,
        to_did: &str,
        name: &str,
        data: &[u8],
        origin: Option<&str>,
    ) -> Result<(String, Option<String>), String>;

    /// Seal a message to a channel's key and file it.
    async fn message_channel_send(&self, channel_did: &str, body: &str) -> Result<String, String>;

    /// Share a file with the group that holds `channel_did`'s key — a channel
    /// message whose `type` is `share`, on [`Self::message_channel_send`]'s
    /// path (RFC-0090, *Delivery › To a group*) — answering the record id as
    /// that does. `origin` is not kept: every copy of a share to a group, the
    /// sender's own included, is under the group's key, so none carries it.
    async fn message_channel_share(
        &self,
        channel_did: &str,
        name: &str,
        data: &[u8],
        origin: Option<&str>,
    ) -> Result<String, String>;

    /// The channels this person holds a key for, each with how many people
    /// hold its current epoch, from their own grants and nothing else.
    async fn message_groups(&self) -> Result<Vec<RunnerGroup>, String>;

    /// A channel's messages, newest first, still sealed.
    async fn message_channel_history(
        &self,
        channel_did: &str,
        before_id: Option<String>,
        limit: u32,
    ) -> Result<Vec<RunnerSealedMessage>, String>;

    /// The messages addressed to this person, still sealed.
    async fn message_poll_inbox(&self) -> Result<Vec<RunnerSealedMessage>, String>;

    /// Everyone this person has paired with.
    ///
    /// On this trait for the same reason `list_devices` is: *who a person knows*
    /// is the shape of their account, and who may read it should be answered by
    /// which host was handed over.
    async fn list_contacts(&self) -> Result<Vec<RunnerContact>, String>;

    /// Begin the RFC-0022 ceremony, as the side that speaks the words or the
    /// side that heard them.
    ///
    /// The answer does not come back through this call: the frames are pushed at
    /// `on-message` as they happen. **Which app they are pushed to is not a
    /// parameter** — the implementation resolves the `shell` designation from the
    /// user's own `app_roles`, the same reading that decides whether a host call
    /// is serviced at all. Only the occupant can reach these verbs, so there is
    /// exactly one right answer, and taking it as an argument would let a guest
    /// name where a push lands.
    async fn pair_start(&self, label: Option<String>, ttl_seconds: u64) -> Result<(), String>;

    async fn pair_join(&self, code: String, label: Option<String>) -> Result<(), String>;

    /// Answer the digits of the ceremony this occupant started. No token crosses
    /// this boundary — see `agent::ceremony`.
    async fn pair_confirm(&self, matched: bool) -> Result<(), String>;

    async fn pair_cancel(&self) -> Result<(), String>;

    /// Open one, on the node.
    ///
    /// On this trait for the same reason `list_devices` is: the key that opens
    /// it is the person's, it stays here, and *who may ask for plaintext* should
    /// be answered by which host was handed over rather than by which call site
    /// remembered to check.
    async fn message_open(&self, message: RunnerSealedMessage) -> Result<String, String>;

    /// How many messages this person has not read (`DEC-0061`).
    async fn message_unread_count(&self) -> Result<u64, String>;

    /// Both directions of one conversation, from this person's own store,
    /// still sealed (`TASK-messages-is-the-drawn-one`).
    async fn message_conversation(&self, peer_did: &str) -> Result<Vec<RunnerSealedMessage>, String>;

    /// The one word each message this person sent `peer_did` reads as
    /// (`DEC-0056`).
    async fn message_deliveries(
        &self,
        peer_did: &str,
    ) -> Result<Vec<kotton_wire::ipc::DeliveryReading>, String>;

    /// How many of `peer_did`'s messages this person has not read.
    async fn message_unread_from(&self, peer_did: &str) -> Result<u64, String>;

    /// Advance one conversation's read mark to `(filed_at, message_id)`.
    ///
    /// The only **write** the occupant makes to a person's own store through
    /// this trait, and it is deliberately the narrowest one available: it can
    /// move one conversation's watermark forwards and can express nothing else.
    /// Read state never leaves the person — a sender who learned it would know
    /// more than the four words `DEC-0056` allows them.
    /// Answers whether the mark actually moved, rather than `()`. The surface
    /// has nothing to do differently either way, but a frame field that is
    /// always `true` is a field that says nothing, and this one is read by the
    /// daemon's own tests.
    async fn message_mark_read(
        &self,
        peer_did: &str,
        filed_at: u64,
        message_id: &str,
    ) -> Result<bool, String>;

    /// One schema's live records in one of the person's roots (RFC-0071 R17).
    ///
    /// On this trait because roots are: the occupant is the one guest handed
    /// the person's roots, so it is the one that can name one. The root is an
    /// id the daemon itself handed over, and the implementation asks the
    /// person's membership before it reads a row (R12) — a name the guest
    /// holds is not the authority.
    async fn root_records(&self, root: &str, nsid: &str) -> Result<Vec<RunnerRecord>, String>;

    /// Write one record into one of the person's roots, answering its id.
    /// Refused for a root the person is not a member of.
    async fn root_add_record(&self, root: &str, nsid: &str, data: &str) -> Result<String, String>;

    /// What another installed app holds in the person's files, by shape
    /// (`interface grants`).
    ///
    /// On this trait because the answer is the person's grant tables, which the
    /// daemon holding their database reads — an implementation answers with
    /// [`app_holdings`] over that database, so there is one reading of what an
    /// app was granted. `covering` is answered from this list here, in
    /// [`service_host_call`], so the path predicate lives beside the rule that
    /// no target leaves.
    async fn app_holdings(&self, app_id: &str) -> Result<Vec<HeldShape>, String>;

    /// The installed apps a file can be opened in (`grants.opens-files`) —
    /// the share sheet's *An app* (RFC-0090, unit 5).
    ///
    /// On this trait for the reason [`app_holdings`](Self::app_holdings) is:
    /// the registry and the role table are the person's database. An
    /// implementation answers with [`app_file_openers`] over it, so there is
    /// one rule for which apps take a file.
    async fn file_openers(&self) -> Result<Vec<RunnerOpener>, String>;
}

/// Whether `app_id` is the app the user designated to fill the `shell` role.
///
/// One reading of `app_roles`, used both to set [`RunnerInput::occupant`] at
/// spawn and to decide whether a host call is serviced — so the two cannot
/// disagree about who the occupant is. The designation is the *user's*, in
/// their own database, changed with `app set-role`; nothing here is hardcoded
/// and nothing an app declares affects it.
async fn is_occupant(user_db: &Arc<SqlitePool>, app_id: &str) -> bool {
    matches!(role_db::get_role(user_db, "shell").await, Ok(Some(id)) if id == app_id)
}

/// Service one host call from a running guest, or refuse it.
///
/// The only call an app-world op can legitimately raise is an auth verb from
/// the occupant. Everything else — a fetcher's network or quarantine call, an
/// auth verb from a guest that is not the occupant — reaches here only if a
/// runner emitted a frame its guest's world cannot produce. That is a bug in
/// the confinement boundary, so it returns `Err`, which drops the instance,
/// rather than a reply that lets it continue.
/// Service one inference verb.
///
/// Every arm answers with a reply rather than an `Err`: a failure here is data
/// the guest receives, not a fault that drops its instance. That differs from
/// the occupant frames above on purpose — an occupant frame from a non-occupant
/// means the runner emitted something its world could not produce, which is a
/// bug in the boundary. An inference frame is one any app may send.
async fn service_infer(verb: RunnerInferVerb, host: &dyn InferHost) -> RunnerHostReply {
    match verb {
        RunnerInferVerb::Models => match host.models().await {
            Ok(models) => RunnerHostReply::InferModels { models },
            Err(error) => RunnerHostReply::InferFailed { error },
        },
        RunnerInferVerb::Embed { model, text } => match host.embed(&model, &text).await {
            Ok(vector) => RunnerHostReply::InferEmbedding { vector },
            Err(error) => RunnerHostReply::InferFailed { error },
        },
        RunnerInferVerb::Generate {
            model,
            question,
            passages,
            options,
        } => match host.generate(&model, &question, passages, options).await {
            Ok(generation) => RunnerHostReply::InferGeneration { generation },
            Err(error) => RunnerHostReply::InferFailed { error },
        },
        RunnerInferVerb::Next { generation } => match host.next_token(generation).await {
            Ok((text, metering)) => RunnerHostReply::InferToken { text, metering },
            Err(error) => RunnerHostReply::InferFailed { error },
        },
        RunnerInferVerb::Drop { generation } => {
            host.drop_generation(generation).await;
            // Nothing to report: the guest has already let go of the resource
            // and is not waiting on this. The reply exists because the channel
            // is request/reply, not because anyone reads it.
            RunnerHostReply::InferToken {
                text: None,
                metering: None,
            }
        }
    }
}

/// Which occupant interface a frame came from. A local shape, so the match
/// above reads as two interfaces rather than as a flat list of verbs.
enum OccupantCall {
    Auth(RunnerAuthVerb),
    Devices(RunnerDeviceVerb),
    Messages(RunnerMessageVerb),
    Contacts(RunnerContactVerb),
    Network(RunnerNetworkVerb),
    Joining(RunnerJoinVerb),
    Records(RunnerRecordVerb),
    Landlord(RunnerLandlordVerb),
    Operators(RunnerOperatorVerb),
    Grants(RunnerGrantVerb),
}

async fn service_host_call(
    call: RunnerHostCall,
    occupant: Option<&dyn OccupantHost>,
    infer: Option<&dyn InferHost>,
    records: Option<&dyn RecordsHost>,
) -> io::Result<RunnerHostReply> {
    // The person's kept records, outside the occupant gate for the reason
    // inference is: any app may hold `schema.read`, and the sandbox has checked
    // it before this frame was written. An instance launched for nobody has no
    // person whose records to read, and is told so rather than dropped.
    if let RunnerHostCall::Kept { nsid } = call {
        let Some(host) = records else {
            return Ok(RunnerHostReply::RecordFailed {
                message: "no person's records are open to this instance".to_string(),
            });
        };
        return Ok(match host.kept_records(&nsid).await {
            Ok(records) => RunnerHostReply::RecordsKept { records },
            Err(message) => RunnerHostReply::RecordFailed { message },
        });
    }
    // Inference first, and outside the occupant gate below: any app may declare
    // `infer.run`, so this frame is not evidence of a confinement bug the way an
    // `auth` frame from a non-occupant is. A guest whose machine has no runtime
    // is told so — `no-runtime` is an answer, not a refusal, and RFC-0085's
    // placement table has a whole column of devices that never will.
    if let RunnerHostCall::Infer { verb } = call {
        let Some(host) = infer else {
            return Ok(RunnerHostReply::InferFailed {
                error: RunnerInferError::NoRuntime,
            });
        };
        return Ok(service_infer(verb, host).await);
    }
    // Both occupant frames are serviced here; everything else is a bug in the
    // confinement boundary and drops the instance.
    let occupant_call = match call {
        RunnerHostCall::Auth { verb } => OccupantCall::Auth(verb),
        RunnerHostCall::Devices { verb } => OccupantCall::Devices(verb),
        RunnerHostCall::Messages { verb } => OccupantCall::Messages(verb),
        RunnerHostCall::Contacts { verb } => OccupantCall::Contacts(verb),
        RunnerHostCall::Network { verb } => OccupantCall::Network(verb),
        RunnerHostCall::Joining { verb } => OccupantCall::Joining(verb),
        RunnerHostCall::Records { verb } => OccupantCall::Records(verb),
        RunnerHostCall::Landlord { verb } => OccupantCall::Landlord(verb),
        RunnerHostCall::Operators { verb } => OccupantCall::Operators(verb),
        RunnerHostCall::Grants { verb } => OccupantCall::Grants(verb),
        other => {
            return Err(io::Error::other(format!(
                "a guest in the app world raised a host call it has no import for: {other:?}"
            )))
        }
    };
    let Some(host) = occupant else {
        return Err(io::Error::other(
            "a guest that is not the occupant raised an occupant call; its linker has no \
             such interface, so the runner emitted a frame it could not have been asked for",
        ));
    };
    let verb = match occupant_call {
        OccupantCall::Grants(verb) => {
            // What another app holds. Every failure is an answer — an app that
            // is not installed included — because the frame is one the
            // occupant's world can make. Only the holding crosses back; the
            // target it was matched against stays here.
            return Ok(match verb {
                RunnerGrantVerb::HeldBy { app_nsid } => match host.app_holdings(&app_nsid).await {
                    Ok(held) => RunnerHostReply::GrantHoldings {
                        holdings: held.into_iter().map(|h| h.holding).collect(),
                    },
                    Err(message) => RunnerHostReply::GrantFailed { message },
                },
                RunnerGrantVerb::Covering { app_nsid, path } => {
                    match host.app_holdings(&app_nsid).await {
                        Ok(held) => RunnerHostReply::GrantCovering {
                            holding: covering(&held, &path),
                        },
                        Err(message) => RunnerHostReply::GrantFailed { message },
                    }
                }
                RunnerGrantVerb::OpensFiles => match host.file_openers().await {
                    Ok(openers) => RunnerHostReply::GrantOpeners { openers },
                    Err(message) => RunnerHostReply::GrantFailed { message },
                },
            });
        }
        OccupantCall::Records(verb) => {
            // A root's records, read or added. Every failure is an answer the
            // guest receives — a root the person is not in included — and not
            // a fault that drops the instance: the frame is one its world can
            // make, and refusing it is the membership check doing its job.
            return Ok(match verb {
                RunnerRecordVerb::List { root, nsid } => {
                    match host.root_records(&root, &nsid).await {
                        Ok(records) => RunnerHostReply::RecordList { records },
                        Err(message) => RunnerHostReply::RecordFailed { message },
                    }
                }
                RunnerRecordVerb::Add { root, nsid, data } => {
                    match host.root_add_record(&root, &nsid, &data).await {
                        Ok(id) => RunnerHostReply::RecordAdded { id },
                        Err(message) => RunnerHostReply::RecordFailed { message },
                    }
                }
            });
        }
        OccupantCall::Network(verb) => {
            let reply = match verb {
                RunnerNetworkVerb::PairedRelay => match host.paired_relay().await {
                    Ok(relay) => RunnerHostReply::NetworkRelay { relay },
                    Err(message) => RunnerHostReply::NetworkFailed { message },
                },
                RunnerNetworkVerb::OperatedRelays => match host.operated_relays().await {
                    Ok(relays) => RunnerHostReply::NetworkOperatedRelays { relays },
                    Err(message) => RunnerHostReply::NetworkFailed { message },
                },
                RunnerNetworkVerb::EnrolledVaults => match host.enrolled_vaults().await {
                    Ok(vaults) => RunnerHostReply::NetworkVaults { vaults },
                    Err(message) => RunnerHostReply::NetworkFailed { message },
                },
                RunnerNetworkVerb::ThisDevice => match host.this_device().await {
                    Ok(device) => RunnerHostReply::NetworkDevice { device },
                    Err(message) => RunnerHostReply::NetworkFailed { message },
                },
            };
            return Ok(reply);
        }
        OccupantCall::Joining(verb) => {
            // Every arm answers `JoinOk` or `JoinFailed` and nothing else: a
            // joining verb is taken or refused before it starts, and what
            // happens after it is taken is pushed at `on-message` rather than
            // returned. One shape for three verbs is what makes that checkable.
            let taken = match verb {
                // The invite leaves `SecretText` here, handed to the one
                // reader that parses it.
                RunnerJoinVerb::Admit { invite } => host.join_admit(invite.expose().to_owned()).await,
                RunnerJoinVerb::Confirm { typed } => host.join_confirm(typed).await,
                RunnerJoinVerb::Cancel => host.join_cancel().await,
                RunnerJoinVerb::TakeRelay => host.join_take_relay().await,
            };
            return Ok(match taken {
                Ok(()) => RunnerHostReply::JoinOk,
                Err(message) => RunnerHostReply::JoinFailed { message },
            });
        }
        OccupantCall::Landlord(verb) => {
            // A refusal — no credential by that name, a service that did not
            // answer, a name the vault would not take — is an answer the
            // guest draws, not a fault: the frame is one its world can make.
            return Ok(match verb {
                RunnerLandlordVerb::People { vault } => {
                    match host.landlord_people(vault).await {
                        Ok(tenants) => RunnerHostReply::LandlordPeople { tenants },
                        Err(message) => RunnerHostReply::LandlordFailed { message },
                    }
                }
                RunnerLandlordVerb::Invite {
                    vault,
                    name,
                    space_bytes,
                } => match host.landlord_invite(vault, name, space_bytes).await {
                    Ok(invite) => RunnerHostReply::LandlordInvite { invite: SecretText::new(invite) },
                    Err(message) => RunnerHostReply::LandlordFailed { message },
                },
                RunnerLandlordVerb::DropPool { vault, name } => {
                    match host.landlord_drop(vault, name).await {
                        Ok(()) => RunnerHostReply::LandlordOk,
                        Err(message) => RunnerHostReply::LandlordFailed { message },
                    }
                }
                RunnerLandlordVerb::Rule { relay } => match host.landlord_rule(relay).await {
                    Ok(rule) => RunnerHostReply::LandlordRule { rule },
                    Err(message) => RunnerHostReply::LandlordFailed { message },
                },
                RunnerLandlordVerb::SetRule { relay, rule } => {
                    match host.landlord_set_rule(relay, rule).await {
                        Ok(rule) => RunnerHostReply::LandlordRule { rule },
                        Err(message) => RunnerHostReply::LandlordFailed { message },
                    }
                }
                // The code leaves `SecretText` here, handed to the one reader
                // that parses it, and is never logged on the way.
                RunnerLandlordVerb::Resolve { code } => match host.landlord_resolve(code.expose().to_owned()).await {
                    Ok(resolved) => RunnerHostReply::LandlordResolved { resolved },
                    Err(message) => RunnerHostReply::LandlordFailed { message },
                },
                RunnerLandlordVerb::Enrol { code } => match host.landlord_enrol(code.expose().to_owned()).await {
                    Ok(enrolled) => RunnerHostReply::LandlordEnrolled { enrolled },
                    Err(message) => RunnerHostReply::LandlordFailed { message },
                },
                RunnerLandlordVerb::MoveVault { vault, relay } => {
                    match host.landlord_move_vault(vault, relay).await {
                        Ok(()) => RunnerHostReply::LandlordOk,
                        Err(message) => RunnerHostReply::LandlordFailed { message },
                    }
                }
            });
        }
        OccupantCall::Operators(verb) => {
            // A refusal — not an operator, no kdeviced, the last operator, a
            // name not typed back — is an answer the guest draws, as the
            // landlord's are.
            return Ok(match verb {
                RunnerOperatorVerb::Read => match host.operators().await {
                    Ok(operators) => RunnerHostReply::OperatorBox { operators },
                    Err(message) => RunnerHostReply::OperatorsFailed { message },
                },
                RunnerOperatorVerb::Add { person } => match host.operator_add(person).await {
                    Ok(()) => RunnerHostReply::OperatorsOk,
                    Err(message) => RunnerHostReply::OperatorsFailed { message },
                },
                RunnerOperatorVerb::Remove { person } => match host.operator_remove(person).await {
                    Ok(()) => RunnerHostReply::OperatorsOk,
                    Err(message) => RunnerHostReply::OperatorsFailed { message },
                },
            });
        }
        OccupantCall::Devices(verb) => {
            let reply = match verb {
                RunnerDeviceVerb::ListDevices => match host.list_devices().await {
                    Ok(devices) => RunnerHostReply::Devices { devices },
                    Err(message) => RunnerHostReply::DeviceFailed { message },
                },
                RunnerDeviceVerb::RevokeDevice { did } => match host.revoke_device(&did).await {
                    Ok(()) => RunnerHostReply::DeviceOk,
                    Err(message) => RunnerHostReply::DeviceFailed { message },
                },
                RunnerDeviceVerb::ListBrowsers => match host.list_browsers().await {
                    Ok(browsers) => RunnerHostReply::Browsers { browsers },
                    Err(message) => RunnerHostReply::DeviceFailed { message },
                },
                RunnerDeviceVerb::RevokeBrowser { name } => match host.revoke_browser(&name).await {
                    Ok(()) => RunnerHostReply::DeviceOk,
                    Err(message) => RunnerHostReply::DeviceFailed { message },
                },
            };
            return Ok(reply);
        }
        OccupantCall::Messages(verb) => {
            let reply = match verb {
                RunnerMessageVerb::Send { to_did, body } => {
                    match host.message_send(&to_did, &body).await {
                        Ok((id, delivery)) => RunnerHostReply::MessageSent { id, delivery },
                        Err(message) => RunnerHostReply::MessageFailed { message },
                    }
                }
                RunnerMessageVerb::Share { to_did, name, data, origin } => {
                    match host.message_share(&to_did, &name, &data, origin.as_deref()).await {
                        Ok((id, delivery)) => RunnerHostReply::MessageSent { id, delivery },
                        Err(message) => RunnerHostReply::MessageFailed { message },
                    }
                }
                RunnerMessageVerb::ChannelSend { channel_did, body } => {
                    match host.message_channel_send(&channel_did, &body).await {
                        Ok(id) => RunnerHostReply::MessageSent { id, delivery: None },
                        Err(message) => RunnerHostReply::MessageFailed { message },
                    }
                }
                RunnerMessageVerb::ChannelShare { channel_did, name, data, origin } => {
                    match host.message_channel_share(&channel_did, &name, &data, origin.as_deref()).await {
                        Ok(id) => RunnerHostReply::MessageSent { id, delivery: None },
                        Err(message) => RunnerHostReply::MessageFailed { message },
                    }
                }
                RunnerMessageVerb::Groups => match host.message_groups().await {
                    Ok(groups) => RunnerHostReply::MessageGroups { groups },
                    Err(message) => RunnerHostReply::MessageFailed { message },
                },
                RunnerMessageVerb::ChannelHistory {
                    channel_did,
                    before_id,
                    limit,
                } => match host
                    .message_channel_history(&channel_did, before_id, limit)
                    .await
                {
                    Ok(messages) => RunnerHostReply::MessageList { messages },
                    Err(message) => RunnerHostReply::MessageFailed { message },
                },
                RunnerMessageVerb::PollInbox => match host.message_poll_inbox().await {
                    Ok(messages) => RunnerHostReply::MessageList { messages },
                    Err(message) => RunnerHostReply::MessageFailed { message },
                },
                RunnerMessageVerb::Open { message } => match host.message_open(message).await {
                    Ok(text) => RunnerHostReply::MessageOpened { text },
                    Err(message) => RunnerHostReply::MessageFailed { message },
                },
                RunnerMessageVerb::UnreadCount => match host.message_unread_count().await {
                    Ok(count) => RunnerHostReply::MessageUnread { count },
                    Err(message) => RunnerHostReply::MessageFailed { message },
                },
                RunnerMessageVerb::MarkRead {
                    peer_did,
                    filed_at,
                    message_id,
                } => {
                    match host
                        .message_mark_read(&peer_did, filed_at, &message_id)
                        .await
                    {
                        Ok(moved) => RunnerHostReply::MessageRead { moved },
                        Err(message) => RunnerHostReply::MessageFailed { message },
                    }
                }
                RunnerMessageVerb::Conversation { peer_did } => {
                    match host.message_conversation(&peer_did).await {
                        Ok(messages) => RunnerHostReply::MessageList { messages },
                        Err(message) => RunnerHostReply::MessageFailed { message },
                    }
                }
                RunnerMessageVerb::Deliveries { peer_did } => {
                    match host.message_deliveries(&peer_did).await {
                        Ok(readings) => RunnerHostReply::MessageDeliveries { readings },
                        Err(message) => RunnerHostReply::MessageFailed { message },
                    }
                }
                RunnerMessageVerb::UnreadFrom { peer_did } => {
                    match host.message_unread_from(&peer_did).await {
                        Ok(count) => RunnerHostReply::MessageUnread { count },
                        Err(message) => RunnerHostReply::MessageFailed { message },
                    }
                }
            };
            return Ok(reply);
        }
        OccupantCall::Contacts(verb) => {
            let reply = match verb {
                RunnerContactVerb::PairStart { label, ttl_seconds } => {
                    match host.pair_start(label, ttl_seconds).await {
                        Ok(()) => RunnerHostReply::ContactOk,
                        Err(message) => RunnerHostReply::ContactFailed { message },
                    }
                }
                RunnerContactVerb::PairJoin { code, label } => {
                    match host.pair_join(code.expose().to_owned(), label).await {
                        Ok(()) => RunnerHostReply::ContactOk,
                        Err(message) => RunnerHostReply::ContactFailed { message },
                    }
                }
                RunnerContactVerb::PairConfirm { matched } => {
                    match host.pair_confirm(matched).await {
                        Ok(()) => RunnerHostReply::ContactOk,
                        Err(message) => RunnerHostReply::ContactFailed { message },
                    }
                }
                RunnerContactVerb::PairCancel => match host.pair_cancel().await {
                    Ok(()) => RunnerHostReply::ContactOk,
                    Err(message) => RunnerHostReply::ContactFailed { message },
                },
                RunnerContactVerb::List => match host.list_contacts().await {
                    Ok(contacts) => RunnerHostReply::ContactList { contacts },
                    Err(message) => RunnerHostReply::ContactFailed { message },
                },
            };
            return Ok(reply);
        }
        OccupantCall::Auth(verb) => verb,
    };
    let reply = match verb {
        RunnerAuthVerb::SuggestCredential => RunnerHostReply::AuthCredentialSuggestion {
            credential: SecretText::new(host.suggest_credential().await),
        },
        RunnerAuthVerb::ReadIdentity => match host.read_identity().await {
            Ok(identity) => RunnerHostReply::AuthIdentityRead { identity },
            Err(error) => RunnerHostReply::AuthFailed { error },
        },
        RunnerAuthVerb::CreateIdentity {
            passphrase,
            display_name,
        } => match host.create_identity(passphrase.expose(), &display_name).await {
            Ok(did) => RunnerHostReply::AuthIdentity { did },
            Err(error) => RunnerHostReply::AuthFailed { error },
        },
        RunnerAuthVerb::SetDisplayName { name } => match host.set_display_name(&name).await {
            Ok(()) => RunnerHostReply::AuthDisplayNameSet,
            Err(error) => RunnerHostReply::AuthFailed { error },
        },
        // A passphrase and a PIN leave `SecretText` here, at the call that
        // checks them, and the token that answers goes back in one.
        RunnerAuthVerb::Unlock { passphrase } => match host.unlock(passphrase.expose()).await {
            Ok(token) => RunnerHostReply::AuthSession { token: SecretText::new(token) },
            Err(error) => RunnerHostReply::AuthFailed { error },
        },
        RunnerAuthVerb::UnlockWithPin { user_id, pin } => {
            match host.unlock_with_pin(&user_id, pin.expose()).await {
                Ok(token) => RunnerHostReply::AuthSession { token: SecretText::new(token) },
                Err(error) => RunnerHostReply::AuthFailed { error },
            }
        }
    };
    Ok(reply)
}

/// What a running instance may do in its person's tree, as the daemon recorded
/// it at spawn: whose tree, and the `files` grants the instance was launched
/// with.
///
/// **The daemon's own copy of the grant, not the runner's word.** A `files`
/// frame names an absolute path the sandbox resolved under a handle it minted
/// from a verified grant — but the frame comes from the process that runs
/// untrusted code, and a runner that sent a path outside its handles would be
/// a runner that had escaped its sandbox. Until this frame existed the kernel
/// profile was the backstop, and it granted the whole of the person's tree to
/// every runner that had one. The runner no longer reaches the tree at all, so
/// this is where the reach is bounded now, and it is bounded by the grant:
/// the same targets, from the same launch input, that the sandbox mints its
/// handles from (`granted_vfs_roots` in `kotton-wasm`).
pub(crate) struct PersonalReach {
    /// Whose tree.
    user_id: String,
    /// The `files` grants this instance holds: from its envelopes when it has
    /// any — the ones issued to this app, not revoked, not expired at launch —
    /// and from the recorded approval when it has none, which is the sandbox's
    /// precedence exactly. Checked with [`CapabilitySet::allows`], the same
    /// predicate the sandbox's check and every other VFS door here use.
    granted: kotton_schemas::CapabilitySet,
}

impl PersonalReach {
    /// The reach an instance of `app_id` launched with `input` holds, or `None`
    /// for an instance launched for nobody.
    pub(crate) fn of(app_id: &str, user_id: Option<&str>, input: &RunnerInput) -> Option<Self> {
        input.user_vfs_path.as_ref()?;
        let user_id = user_id?.to_string();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let grants: Vec<CapabilityGrant> = if input.envelopes.is_empty() {
            input.approved.clone()
        } else {
            input
                .envelopes
                .iter()
                .filter(|e| e.app_id.as_deref() == Some(app_id))
                .filter(|e| !input.revoked_ids.contains(&e.id))
                .filter(|e| e.expires_at.is_none_or(|t| t > now))
                .flat_map(|e| e.grants.iter().cloned())
                .collect()
        };
        let grants = grants
            .into_iter()
            .filter(|g| matches!(g.target, kotton_schemas::CapabilityTarget::Vfs { .. }))
            .collect();
        Some(Self {
            user_id,
            granted: kotton_schemas::CapabilitySet::new(grants),
        })
    }

    fn allows(&self, kind: &CapabilityKind, path: &str) -> bool {
        self.granted.allows(
            kind,
            &kotton_schemas::CapabilityTarget::Vfs {
                path: path.to_string(),
            },
        )
    }
}

/// Answer one `files` verb for a running instance, from its person's sealed
/// tree (`TASK-a-file-an-app-writes-rests-in-the-clear-in-the-sealed-stores-own-directory`).
///
/// **Serviced where the instance is**, like the surface verbs: whose tree and
/// which grant are facts about the instance ([`PersonalReach`]), not about the
/// frame.
///
/// Two ways to be stopped, and only one of them is an answer:
///
/// - **A path the grant does not cover** is answered, as `permission denied`.
///   The sandbox's handles cannot produce one, so it means either a runner
///   that escaped, or a grant that lapsed between the sandbox minting a handle
///   and this call — and the second is an ordinary refusal a guest can be
///   told.
/// - **A `files` frame from an instance launched for nobody** is not answered;
///   it returns `Err`, which drops the instance. The runner builds no file
///   port without a person's tree, so a frame from one is a runner emitting a
///   call it could not have been asked for — a bug in the confinement
///   boundary, which fails loudly rather than being serviced.
///
/// `tree` is how a person's tree is found — [`AppHost::personal_tree`] in the
/// daemon — passed as a lookup so a test can hand one in without a host.
pub(crate) async fn service_files_call(
    verb: RunnerFileVerb,
    reach: Option<&PersonalReach>,
    tree: &(dyn Fn(&str) -> Option<Arc<dyn PersonalTree>> + Sync),
) -> io::Result<RunnerHostReply> {
    let Some(reach) = reach else {
        return Err(io::Error::other(
            "an instance launched for nobody raised a files call; its runner holds no file \
             port, so it emitted a frame it could not have been asked for",
        ));
    };
    let (path, kinds): (&str, &[CapabilityKind]) = match &verb {
        RunnerFileVerb::Read { path }
        | RunnerFileVerb::List { path }
        | RunnerFileVerb::Logged { path } => (path, &[CapabilityKind::Read]),
        RunnerFileVerb::Write { path, .. }
        | RunnerFileVerb::Delete { path }
        | RunnerFileVerb::CreateDir { path } => (path, &[CapabilityKind::Write]),
        // Asked once per grant target to shape a handle, and a target granted
        // write alone is still a handle.
        RunnerFileVerb::Kind { path } => (path, &[CapabilityKind::Read, CapabilityKind::Write]),
    };
    // **The path checked is the path the store will resolve.** The store
    // canonicalises with `to_object_key`, which reads `\` as a separator
    // before it resolves `..`; the grant predicate normalises on `/` alone. So
    // the frame's string is canonicalised here by the store's own rule, and it
    // is that canonical string the grant is asked about and the store is
    // handed — `/documents/..\..\photos` is checked as `/photos`, which is
    // what it would have read.
    //
    // **No `.kotton` refusal, and no refusal of `/network` either.** The tree
    // is rooted in the store at `PERSON_TREE_ROOT` and the daemon's own
    // records lie outside it, so there is no path this could be handed that
    // reaches them; a check on a name would be a guard made necessary only by
    // the records being reachable, and they are not
    // (`TASK-a-file-an-app-writes-rests-in-the-clear-in-the-sealed-stores-own-directory`,
    // the assessor's forged member).
    let path = format!("/{}", kotton_schemas::to_object_key(path));
    let refused = |message: String| Ok(RunnerHostReply::FileFailed { message });
    if !kinds.iter().any(|k| reach.allows(k, &path)) {
        tracing::warn!(
            %path,
            "a files call named a path this instance's grant does not cover; refused"
        );
        return refused(format!("permission denied: {path} is outside this app's grant"));
    }
    let Some(tree) = tree(&reach.user_id) else {
        return refused("this person's files are not open on this device".to_string());
    };
    Ok(match verb {
        RunnerFileVerb::Read { .. } => match tree.read(&path).await {
            Ok(data) => RunnerHostReply::FileContent { data },
            Err(message) => RunnerHostReply::FileFailed { message },
        },
        RunnerFileVerb::Write { data, .. } => match tree.write(&path, &data).await {
            Ok(()) => RunnerHostReply::FileDone,
            Err(message) => RunnerHostReply::FileFailed { message },
        },
        RunnerFileVerb::Delete { .. } => match tree.delete(&path).await {
            Ok(()) => RunnerHostReply::FileDone,
            Err(message) => RunnerHostReply::FileFailed { message },
        },
        RunnerFileVerb::CreateDir { .. } => match tree.create_dir(&path).await {
            Ok(()) => RunnerHostReply::FileDone,
            Err(message) => RunnerHostReply::FileFailed { message },
        },
        RunnerFileVerb::List { .. } => match tree.list(&path).await {
            Ok(entries) => RunnerHostReply::FileEntries { entries },
            Err(message) => RunnerHostReply::FileFailed { message },
        },
        RunnerFileVerb::Kind { .. } => match tree.kind(&path).await {
            Ok(kind) => RunnerHostReply::FileKind { kind },
            Err(message) => RunnerHostReply::FileFailed { message },
        },
        RunnerFileVerb::Logged { .. } => match tree.logged(&path).await {
            Ok(generation) => RunnerHostReply::FileLogged { generation },
            Err(message) => RunnerHostReply::FileFailed { message },
        },
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the path where an app's compiled WASM is stored.
fn wasm_path_for(base: &Path, app_id: &str) -> PathBuf {
    base.join("apps").join(app_id).join("app.wasm")
}

/// Build the path where an app's manifest TOML is stored.
fn manifest_path_for(base: &Path, app_id: &str) -> PathBuf {
    base.join("apps").join(app_id).join("manifest.toml")
}

/// Current UTC timestamp as an ISO 8601 / RFC 3339 string.
fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

/// A persistent `kotton-runner` process used by `AppKind::LongLived` apps.
///
/// The process is started with `--long-lived`; initialization is sent as a
/// newline-terminated JSON line, then subsequent messages use `RunnerMessage`.
pub struct LongLivedInstance {
    pub stdin: tokio::io::BufWriter<tokio::process::ChildStdin>,
    pub stdout: BufReader<tokio::process::ChildStdout>,
    _child: tokio::process::Child,
    /// Every surface this instance holds, launch surface first (RFC-0087).
    ///
    /// Held so the daemon can close the *right* surfaces when the instance ends.
    /// Under `app_id` keying this was implicit — one app, one surface, closing
    /// by name — and that implicitness is exactly what stopped an app ever
    /// having two. Stage 1 made it one handle; stage 2 makes it the list,
    /// because `create-surface` appends to it.
    ///
    /// **This is also where the cap is counted**
    /// ([`kotton_wire::MAX_SURFACES_PER_INSTANCE`]). The instance is owned here,
    /// so this is the only place that can answer *how many does this one have*
    /// — the runner holds no count and must not be trusted with one.
    pub surfaces: Vec<kotton_wire::SurfaceHandle>,
    /// The app this instance is running, for `SurfaceOpen`'s private
    /// `handle -> app` record on `kuserd`'s side of the compositor wire.
    pub app_id: String,
    /// The name the host draws in the frame — `manifest.app.name`, as the
    /// install prompt showed it. Held rather than re-derived so that a surface
    /// created from an input handler is framed with the same words as the one
    /// created at launch, and so that an input path with no manifest in scope
    /// does not have to invent one.
    pub title: String,
    /// Whether the person designated this app (`input.occupant`).
    ///
    /// **Not the authority — the audit.** The authority is that an undesignated
    /// guest has no `layer-surface` import and therefore cannot ask for a
    /// `Background` or a `Panel` at all. This field is what lets the daemon
    /// notice a runner emitting a frame its world cannot make, which is a bug in
    /// the confinement boundary and must fail loudly rather than be serviced —
    /// the rule `RunnerHostCall::Auth` already states.
    pub designated: bool,
    /// The user's data mount this instance was launched with, or `None` for an
    /// instance launched for nobody (`RunnerInput::user_vfs_path`).
    ///
    /// **What it is for: telling the screen a person is looking at from the
    /// screen they should be.** A shell launched with `None` can open no file,
    /// was told no `did`, and draws the lock screen — so when the person
    /// unlocks at it, *this instance has no mount* is the fact that says the
    /// world they are in is the wrong one. Read by
    /// [`instance_world`]; see `DeviceDaemon::replace_the_screen`.
    ///
    /// Held rather than re-derived: the mount is a function of who the launch
    /// was for, and the instance is the only place that answer survives the
    /// launch — nothing else in the daemon records what an instance was handed.
    pub user_vfs_path: Option<String>,
    /// Whose tree this instance's `files` calls are answered from, and the
    /// grant they are checked against — `None` for an instance launched for
    /// nobody. Recorded at spawn from the same input the runner was sent; see
    /// [`PersonalReach`].
    pub(crate) personal: Option<PersonalReach>,
    /// The windows this instance has been **shown**, in the order it was shown them
    /// (RFC-0087 stage 3b).
    ///
    /// The designated app's names for other apps' windows: the id it is given is the
    /// position in this list plus one, and `raise-window` resolves an id back through it.
    /// So the id is scoped to this instance by construction — it means nothing to anybody
    /// else, it names nothing about the app or the person, and it dies when the instance
    /// does. A `HashMap<u64, SurfaceHandle>` would say the same thing with a second field
    /// for the counter; the vector *is* the counter.
    ///
    /// **Append-only, and never re-keyed.** A window that closes keeps its slot rather than
    /// freeing it, because a reused id would come back pointing at a different window —
    /// which is stage 3a's ordinal defect one level up, and the version of it that would
    /// send a person's click to somebody else's window. It grows by one per window this
    /// instance is ever shown; nothing in the tree opens windows in a loop, and the bound
    /// is a note in the RFC rather than a cap, because a cap here would mean a designated
    /// app that stops being able to name new windows while the person keeps opening them.
    pub windows_shown: Vec<kotton_wire::SurfaceHandle>,
}

/// **The parts of a running instance the surface verbs read — and the whole of them.**
///
/// [`service_surface_call`] answers five verbs and touches five fields. It does not touch
/// the child process, its pipes, the mount it was launched with, or anything else a
/// [`LongLivedInstance`] carries — so taking the whole instance was taking a **running
/// process** as an argument to a function about a list of handles.
///
/// That is why `surface.close`'s ownership audit was never tested: the audit is four lines
/// over `surfaces`, and reaching it meant spawning a runner. Borrowing the five fields
/// instead is what lets the audit be stated against a `Vec` and a recording host, in this
/// crate's own tests, with no process anywhere — see
/// `host_call_tests::a_surface_verb_is_refused_on_a_handle_the_instance_does_not_hold`.
///
/// A borrow rather than an owned copy, because `Create` and `Close` **change** the list and
/// the cap is counted on it: a copy would be a second answer to *how many does this one
/// hold*, which is the one thing [`LongLivedInstance::surfaces`] says must not exist.
pub(crate) struct InstanceSurfaces<'a> {
    /// Every surface this instance holds — appended to by `Create`, removed from by
    /// `Close`, and what every ownership audit here resolves against.
    pub(crate) surfaces: &'a mut Vec<kotton_wire::SurfaceHandle>,
    /// The windows this instance has been shown, which is what an id from `RaiseWindow`
    /// resolves through.
    pub(crate) windows_shown: &'a mut Vec<kotton_wire::SurfaceHandle>,
    /// Who is asking — for the private `handle -> app` record a new surface makes, and for
    /// the log. Never told to the compositor (RFC-0087).
    pub(crate) app_id: &'a str,
    /// The name the host draws in a new surface's frame: `manifest.app.name`, as the
    /// install prompt showed it.
    pub(crate) title: &'a str,
    /// Whether the person designated this app — the *audit*, not the authority. See
    /// [`LongLivedInstance::designated`].
    pub(crate) designated: bool,
}

impl LongLivedInstance {
    /// This instance, as the surface verbs see it.
    ///
    /// One function, so that *which fields a surface verb may read* is a list in one place
    /// rather than whatever the dispatch happens to reach for.
    pub(crate) fn surface_view(&mut self) -> InstanceSurfaces<'_> {
        InstanceSurfaces {
            surfaces: &mut self.surfaces,
            windows_shown: &mut self.windows_shown,
            app_id: &self.app_id,
            title: &self.title,
            designated: self.designated,
        }
    }
}

/// Hard wall-clock budget for a single `kotton-runner` invocation. A guest that
/// loops forever (or hangs) is killed rather than pinning a core and blocking the
/// key-holding daemon indefinitely (audit H7). Generous so legitimate handlers
/// are never cut off; overridable via `KOTTON_RUNNER_DEADLINE_MS` (ops tuning +
/// tests).
fn runner_deadline() -> Duration {
    std::env::var("KOTTON_RUNNER_DEADLINE_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_secs(30))
}
/// Cap on bytes buffered from the runner's stdout/stderr, so a runaway guest
/// cannot drive the daemon to buffer an unbounded (multi-GB) response.
const MAX_RUNNER_STDOUT: u64 = 64 * 1024 * 1024;
const MAX_RUNNER_STDERR: u64 = 1024 * 1024;

/// The operating-system confinement a `kotton-runner` is spawned under.
///
/// `DEC-0074` rules that a process running a stranger's code is a guest and is
/// confined like one, and
/// `TASK-the-wasm-runner-is-confined-only-by-wasmtime` is why this process is
/// the more exposed of the two callers: `kinferd` parses a file the person
/// chose to install, and this executes code a third party wrote, on every
/// launch of every app.
///
/// **The two sandboxes are different mechanisms, not one mechanism twice.**
/// WASM confines by construction — a guest cannot name a syscall because the
/// linker never provided one. This confines by interception — the runner is
/// native code asking the kernel, and the kernel refuses. They compose, and
/// before this the runner had only the first, so the whole confinement of a
/// guest app rested on one implementation having no escapes.
///
/// # What is granted, and what each line costs
///
/// - the runner's own program, or the `execve` is the first thing denied;
/// - the component, read-only — the guest's code, which the runner maps;
/// - the directory the app's SQLite database is in, because SQLite creates and
///   deletes `-wal` and `-journal` files beside it and a grant on the file
///   alone cannot cover a file that does not exist yet. It is created here
///   rather than granted loosely because a grant names an inode and one that
///   does not exist yet cannot be named without widening to whichever ancestor
///   does. **That directory is wider than its reason.** For a person's app it
///   is `app_data/`, where every app's database sits beside this one; for the
///   shell before an identity exists it is `system/shell/`, which also holds
///   the shell's own body and manifest. Placement, not this function, is what
///   makes it so, and the per-app directory that would narrow it is escalated on
///   `TASK-the-wasm-runner-is-confined-only-by-wasmtime`;
/// - **not** the person's own tree. It was granted here, whole and writable,
///   until 2026-09-24, because the runner answered `files` calls with
///   `tokio::fs` against it — which wrote a guest's bytes into the sealed
///   store's backing directory in the clear
///   (`TASK-a-file-an-app-writes-rests-in-the-clear-in-the-sealed-stores-own-directory`).
///   The runner now asks the daemon for every file, over the pipe it already
///   holds, and the daemon answers from the store after checking the path
///   against the instance's grant ([`service_files_call`]). So there is
///   nothing here for it to reach, and the grant is gone rather than narrowed:
///   an escaped runner reaches the person's files only through that check;
/// - for the occupant, each root tree it is handed — read, or write where the
///   host handed it writable, which today is nowhere — because a root other
///   than the personal one keeps its tree beside the mount rather than inside
///   it (the comment at the loop below).
///
/// No socket but a private pair — on Linux `socket(2)`, the calls that use a
/// socket, and `io_uring` are refused (`kotton_proc::Profile::nothing`) — and
/// no way for this function to ask for one:
/// `Article VIII` says no app reaches the network directly, and
/// `kotton_proc::Profile` cannot express it.
///
/// # Why this is public
///
/// So a test can prove the confinement by running **this** function, not a copy
/// of it: a profile exercised only by a re-implementation of itself proves the
/// re-implementation. No case in this repository's suite calls it from outside the
/// crate today (kottonllc/kotton#24).
pub async fn runner_profile(
    runner: &Path,
    input: &RunnerInput,
) -> io::Result<kotton_proc::Profile> {
    let mut profile = kotton_proc::Profile::nothing("kotton-runner")
        .executing(runner)
        .reading(&input.wasm_path);

    // The host owns placement (RFC-0058), so the host makes the directory. The
    // runner's own `create_dir_all` still runs and is a no-op.
    let app_data_dir = Path::new(&input.app_data_path)
        .parent()
        .ok_or_else(|| io::Error::other(format!("app data path has no parent: {}", input.app_data_path)))?
        .to_path_buf();
    kotton_common::fs::create_dir_all_owner_only(&app_data_dir)?;
    profile = profile.writing(app_data_dir);

    // `input.user_vfs_path` is deliberately not granted: see the list above.

    // Each root the occupant is handed, because `roots.tree` turns a
    // `RunnerRoot` into a directory handle on its `tree_path` and a root other
    // than the personal one keeps its tree at `roots/<id>` beside the mount
    // rather than inside it. **The reach is `RunnerRoot::writable`, the same
    // field the sandbox's handle reads**, so the kernel and the handle cannot
    // disagree: `Write` where the host handed a root writable, `Read` where it
    // did not. It hands none writable until the owner answers question 1 on
    // `TASK-a-member-writes-in-a-roots-tree` (RFC-0087, RFC-0069 and R12 say
    // designation alone reaches no data). *Personal* arrives with no tree — its
    // door is the `files` grant — and the core root not at all (`runner_roots`
    // in `kuserd`), so this cannot grant the mount twice or the index once.
    //
    // **This widens no guest's reach.** `input.roots` is `Some` for the
    // occupant alone — every launch path sets it through
    // `roots_for_the_occupant`, and only for the designated app or the shell
    // before an identity exists, each from one read of the designation — which
    // is the same fact that keeps `kotton:app/roots` out of every other linker,
    // so an ordinary app's profile names no root tree at all.
    //
    // A tree that is not on disk is left out rather than created or refused:
    // the store makes these directories and this function does not own them,
    // and a missing one already reads as an empty listing, which is what the
    // guest saw before a sandbox existed.
    for root in input.roots.as_ref().and_then(RunnerRoots::read).into_iter().flatten() {
        if root.tree_path.is_empty() {
            continue;
        }
        if fs::metadata(&root.tree_path).await.is_ok_and(|m| m.is_dir()) {
            profile = if root.writable {
                profile.writing(&root.tree_path)
            } else {
                profile.reading(&root.tree_path)
            };
        }
    }

    Ok(profile)
}

/// Confine `cmd` to what a runner carrying `input` may reach, or refuse.
///
/// Where `core/proc` has a provider — Linux today — there is no third answer:
/// a kernel that will not enforce the profile, a grant that names nothing, or
/// a refused rule is a refused launch, and the error says why.
///
/// **Where it has none, the answer depends on the operating system**
/// ([`on_unsupported`]). On Linux it is a refusal: a Linux build on an
/// architecture `core/proc` has no filter for (anything but x86-64 and
/// aarch64) gets `SandboxError::Unsupported` from the provider `cfg` selects,
/// and the escalation's default says every Linux spawn the kernel cannot
/// confine is refused. Everywhere else the runner is spawned with wasmtime as
/// its only layer, which is what every platform had before this function
/// existed. That is a concession and it is on the record rather than in this
/// comment alone: `DEC-0074` §1 rules that an *inference engine* Kotton cannot
/// confine does not run, and `supervise_kinferd` holds that line on every
/// platform. Whether the same refusal extends to every guest app — which on
/// macOS and Windows means the desktop itself, since the shell is a guest — is
/// a product decision nobody has made, escalated on
/// `TASK-windows-cannot-confine-a-guest-so-kotton-will-not-run-one-there`
/// with this as its default. It is not a setting: `Unsupported` is only ever
/// built by the provider for a platform with no sandbox.
///
/// Public for the reason [`runner_profile`] is: the test spawns a process
/// through this call rather than through a second copy of it.
pub async fn confine_runner(
    cmd: &mut tokio::process::Command,
    runner: &Path,
    input: &RunnerInput,
) -> io::Result<()> {
    let profile = runner_profile(runner, input).await?;
    match kotton_proc::confine(cmd, &profile) {
        Ok(()) => Ok(()),
        Err(e @ kotton_proc::SandboxError::Unsupported { os, .. }) => on_unsupported(os, &e),
        Err(e) => Err(io::Error::other(e.to_string())),
    }
}

/// What [`confine_runner`] does when `core/proc` has no sandbox for `os`.
///
/// On Linux, refuse: the escalation's default says every Linux spawn the
/// kernel cannot confine is refused, and a Linux build reaches this only on an
/// architecture the seccomp filter is not compiled for. Elsewhere, spawn with
/// wasmtime as the only layer and say so, which is that same default's other
/// half (`TASK-windows-cannot-confine-a-guest-so-kotton-will-not-run-one-there`).
/// Keyed on the error's `os` rather than on a `cfg`, so that both halves are
/// something a test on any one machine can call.
fn on_unsupported(os: &str, refusal: &kotton_proc::SandboxError) -> io::Result<()> {
    if os == "linux" {
        return Err(io::Error::other(refusal.to_string()));
    }
    tracing::warn!(
        "kotton-runner is not confined by the operating system on {os}: core/proc has \
         no sandbox for this platform, so this app runs with wasmtime as its only \
         layer (escalated on \
         TASK-windows-cannot-confine-a-guest-so-kotton-will-not-run-one-there)"
    );
    Ok(())
}

/// Spawn the runner at `runner`, write `input` to its stdin, and read the JSON
/// output.
///
/// `runner` is the host's answer to [`AppHost::runner`]; nothing here consults
/// the environment.
///
/// The invocation is bounded by [`RUNNER_DEADLINE`] and the child is killed on
/// timeout; stdout/stderr are capped ([`MAX_RUNNER_STDOUT`]/[`MAX_RUNNER_STDERR`]).
/// Together these stop a malicious or buggy guest from DoS-ing the daemon by
/// spinning, hanging, or emitting an unbounded response (audit H7).
async fn spawn_runner(runner: &Path, input: RunnerInput) -> io::Result<RunnerOutput> {
    let input_json = serde_json::to_vec(&input)
        .map_err(|e| io::Error::other(format!("serialize runner input: {e}")))?;

    let mut cmd = tokio::process::Command::new(runner);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // If the daemon task is dropped (e.g. connection closed), reap the child.
        .kill_on_drop(true);
    confine_runner(&mut cmd, runner, &input).await?;

    let mut child = cmd.spawn().map_err(|e| {
        io::Error::other(format!("spawn kotton-runner ({}): {e}", runner.display()))
    })?;

    // Write input JSON to stdin, then close to signal EOF.
    {
        let stdin = child.stdin.take().expect("stdin was piped");
        let mut writer = tokio::io::BufWriter::new(stdin);
        writer.write_all(&input_json).await?;
        writer.flush().await?;
    }

    // Read stdout/stderr concurrently (avoids a pipe-buffer deadlock), each
    // capped, then reap the child — all under a single wall-clock deadline.
    let mut stdout = child.stdout.take().expect("stdout was piped");
    let mut stderr = child.stderr.take().expect("stderr was piped");
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let run = async {
        let mut out_reader = (&mut stdout).take(MAX_RUNNER_STDOUT);
        let mut err_reader = (&mut stderr).take(MAX_RUNNER_STDERR);
        let (ro, re) = tokio::join!(
            out_reader.read_to_end(&mut stdout_bytes),
            err_reader.read_to_end(&mut stderr_bytes),
        );
        ro?;
        re?;
        child.wait().await
    };

    let deadline = runner_deadline();
    let status = match tokio::time::timeout(deadline, run).await {
        Ok(res) => res?,
        Err(_) => {
            // Deadline exceeded — kill and reap so no runaway process lingers.
            let _ = child.kill().await;
            return Err(io::Error::other(format!(
                "kotton-runner exceeded its {}ms time budget and was killed",
                deadline.as_millis()
            )));
        }
    };

    let stderr_str = String::from_utf8_lossy(&stderr_bytes);
    if !stderr_str.trim().is_empty() {
        tracing::warn!(runner = %runner.display(), stderr = %stderr_str.trim(), "runner stderr");
    }
    if !status.success() {
        // Try to surface a structured error from stdout.
        if let Ok(err_out) = serde_json::from_slice::<RunnerOutput>(&stdout_bytes) {
            return Ok(err_out);
        }
        let stdout_str = String::from_utf8_lossy(&stdout_bytes);
        return Err(io::Error::other(format!(
            "kotton-runner exited with status {} | stdout: {} | stderr: {}",
            status,
            stdout_str.trim(),
            stderr_str.trim()
        )));
    }

    serde_json::from_slice(&stdout_bytes).map_err(|e| {
        let stdout_str = String::from_utf8_lossy(&stdout_bytes);
        io::Error::other(format!(
            "deserialize runner output: {e} | raw: {}",
            stdout_str.trim()
        ))
    })
}

/// What the user approved for `app_id`, as grants for the runner.
///
/// An app with no recorded approval gets **nothing** — not its manifest. That is
/// the whole change: before 2026-08-30 the sandbox read `manifest.toml` back off
/// disk and treated the declaration as the grant, so an app approved for nothing
/// ran with everything it asked for.
///
/// Failing closed here is deliberate and it has a cost: an app installed before
/// the approval column existed reaches none of the user's data until it is
/// installed again. That is the correct direction for a security fix — the
/// failure is visible and recoverable, where the other direction is silent and
/// is the bug. Bundled apps repair themselves at boot; see
/// `auto_install_bundled_apps`.
async fn approved_for(user_db: &Arc<SqlitePool>, app_id: &str) -> Vec<CapabilityGrant> {
    match ardb::get_approved(user_db, app_id).await {
        Ok(Some(set)) => set.grants_slice().to_vec(),
        Ok(None) => {
            tracing::warn!(
                %app_id,
                "no recorded approval — launching with no capabilities. Reinstall the app to \
                 approve what it asks for."
            );
            Vec::new()
        }
        Err(e) => {
            tracing::error!(%app_id, "reading approval failed, launching with none: {e}");
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Report what an installed app asked for, and what it holds.
///
/// The read-only view of the consent decision. Reads the manifest from the app
/// store for `requested`, the registry for `approved`, and the grant tables for
/// the envelopes — three sources because they are three different facts, and
/// collapsing them is what let "the manifest" pass for "the grant" for as long
/// as it did.
///
/// Absent approval is reported as `None`, not as an empty list. An install that
/// predates the consent gate and an install where the user declined everything
/// both grant nothing, but only the first is a reason to ask again.
pub async fn app_grants(
    user_db: &Arc<SqlitePool>,
    base: &Path,
    app_id: String,
) -> io::Result<UserResponse> {
    let manifest_path = manifest_path_for(base, &app_id);
    let manifest_toml = fs::read_to_string(&manifest_path)
        .await
        .map_err(|e| io::Error::other(format!("no installed app '{app_id}': {e}")))?;
    let manifest = AppManifest::from_toml(&manifest_toml)
        .map_err(|e| io::Error::other(format!("manifest parse error: {e}")))?;

    let requested: Vec<CapabilityGrant> = manifest.capabilities.iter().cloned().collect();
    let requested_display = requested.iter().map(|g| g.display_string()).collect();

    let approved_set = ardb::get_approved(user_db, &app_id).await?;
    let approved: Option<Vec<CapabilityGrant>> =
        approved_set.as_ref().map(|s| s.grants_slice().to_vec());
    let approved_display: Vec<String> = approved
        .as_ref()
        .map(|g| g.iter().map(|x| x.display_string()).collect())
        .unwrap_or_default();

    let mut envelopes = Vec::new();
    for env in grant_db::get_envelopes_for_app(user_db, &app_id)
        .await
        .unwrap_or_default()
    {
        envelopes.push(kotton_wire::ipc::AppGrantEnvelope {
            revoked: grant_db::is_revoked(user_db, &env.id)
                .await
                .unwrap_or(false),
            grants_display: env.grants.iter().map(|g| g.display_string()).collect(),
            issuer_did: env.issuer_did.to_string(),
            expires_at: env.expires_at,
            id: env.id,
        });
    }

    Ok(UserResponse::AppGrants {
        app_id,
        name: manifest.app.name.clone(),
        requested,
        requested_display,
        approved,
        approved_display,
        envelopes,
    })
}

/// Report what an app package is asking for. Mints nothing, writes nothing.
///
/// The first half of the two-phase install ([`IDEA-install-consent-gate`],
/// Option B). A client calls this, shows a human what came back, and sends the
/// approved subset to [`app_install`]. Nothing reaches the app store here, so a
/// preview the user declines leaves no trace on disk.
///
/// The publisher signature is *checked* rather than enforced: a preview whose
/// signature fails still returns, with `publisher_verified: false`, because
/// refusing to describe a package is a worse answer than describing it
/// accurately. [`app_install`] still refuses to install it.
///
/// [`IDEA-install-consent-gate`]: https://kotton.sh/records/IDEA-install-consent-gate
pub fn app_install_preview(manifest_toml: &str, wasm_bytes: &[u8]) -> io::Result<UserResponse> {
    let manifest = AppManifest::from_toml(manifest_toml)
        .map_err(|e| io::Error::other(format!("manifest parse error: {e}")))?;

    let wasm_hash = hex::encode(blake3::hash(wasm_bytes).as_bytes());
    let publisher_verified = match (&manifest.publisher_did, &manifest.publisher_signature) {
        (Some(did), Some(sig)) => verify_publisher_signature(did, sig, &wasm_hash).is_ok(),
        _ => false,
    };

    let requested: Vec<CapabilityGrant> = manifest.capabilities.iter().cloned().collect();
    let requested_display = requested.iter().map(|g| g.display_string()).collect();

    Ok(UserResponse::AppInstallPreview {
        shapes: manifest.vfs_shapes(),
        app_id: manifest.app_id().to_owned(),
        name: manifest.app.name.clone(),
        version: manifest.app.version.clone(),
        wasm_hash,
        requested,
        requested_display,
        publisher_verified,
    })
}

/// Install a WASM app from manifest TOML + compiled bytes.
///
/// 1. Parse `manifest_toml` → `AppManifest`
/// 2. Compute BLAKE3 hash of `wasm_bytes`
/// 3. Verify publisher DID signature if `[publisher]` section present; warn if absent
/// 4. Write `manifest.toml` to `{base}/apps/{app_id}/manifest.toml`
/// 5. Write `.wasm` bytes to `{base}/apps/{app_id}/app.wasm`
/// 6. Insert row in `app_registry`
/// 7. Register each `handler_for` NSID in `handler_registry`
/// 8. Build + sign a `GrantEnvelope` over **`approved`** — never over what the
///    manifest declared
/// 9. Persist the envelope in `app_grant_envelopes`
///
/// `user_db` is the installing user's agent database (RFC-0063 stage 3b):
/// registry rows, handler rows, and the grant envelopes all live there.
///
/// # Consent
///
/// `approved` is what gets signed, and it is a parameter rather than something
/// read off the manifest. Until 2026-08-30 step 8 read `manifest.capabilities`
/// directly, so the user's identity key signed whatever the app asked for with
/// no approval step — security-audit finding **H2**, and after H1 that included
/// `media.camera`. See [`IDEA-install-consent-gate`] for why the fix is
/// structural rather than a prompt: a prompt in one client is bypassed by any
/// other caller, while a parameter has to be filled in by all of them.
///
/// The daemon still refuses to widen: `approved` must be a subset of what the
/// manifest requested, so the approval channel can only narrow.
///
/// [`IDEA-install-consent-gate`]: https://kotton.sh/records/IDEA-install-consent-gate
#[allow(clippy::too_many_arguments)]
pub async fn app_install(
    user_db: &Arc<SqlitePool>,
    base: &Path,
    user_id: &str,
    manifest_toml: String,
    wasm_bytes: Vec<u8>,
    event_bus: Option<&Arc<EventBus>>,
    secrets: &dyn SecretsStore,
    approved: ApprovedCapabilities,
) -> io::Result<UserResponse> {
    let manifest = AppManifest::from_toml(&manifest_toml)
        .map_err(|e| io::Error::other(format!("manifest parse error: {e}")))?;

    let app_id = manifest.app_id().to_owned();
    let name = manifest.app.name.clone();
    let version = manifest.app.version.clone();

    // The approval channel may narrow what the manifest asked for; it may never
    // widen it. Refused before anything is written, so a caller cannot use a
    // rejected install to leave a half-installed app behind.
    let requested: Vec<_> = manifest.capabilities.iter().cloned().collect();
    // Shape-aware since 2026-09-03. A VFS grant is judged against the shapes the
    // manifest declared, not the paths, because a user is invited to move where
    // one points; everything else is judged exactly against what was requested.
    // See `is_admissible_for` for what that gives up and what it keeps.
    if !approved.is_admissible_for(&requested, &manifest.vfs_shapes()) {
        return Err(io::Error::other(format!(
            "install refused: {app_id} was approved for a capability it never declared — \
             the daemon signs only shapes the manifest asked for, however they are bound"
        )));
    }

    // Compute BLAKE3 hash of the WASM binary — this is the content-addressed identity.
    let wasm_hash = hex::encode(blake3::hash(&wasm_bytes).as_bytes());

    // Verify or warn about publisher DID signature.
    match (&manifest.publisher_did, &manifest.publisher_signature) {
        (Some(did), Some(sig_b64)) => {
            verify_publisher_signature(did, sig_b64, &wasm_hash)
                .map_err(|e| io::Error::other(format!("publisher signature invalid: {e}")))?;
            tracing::info!(%app_id, %did, "publisher signature verified");
        }
        (None, None) => {
            tracing::warn!(
                %app_id,
                "installing unsigned binary — no [publisher] section in manifest"
            );
        }
        _ => {
            return Err(io::Error::other(
                "manifest [publisher] section must have both `did` and `signature`",
            ));
        }
    }

    // Create per-app directory and write files
    let wasm_path = wasm_path_for(base, &app_id);
    let manifest_path = manifest_path_for(base, &app_id);
    if let Some(parent) = wasm_path.parent() {
        kotton_common::fs::create_dir_all_owner_only(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;
        }
    }
    fs::write(&wasm_path, &wasm_bytes).await?;
    fs::write(&manifest_path, manifest_toml.as_bytes()).await?;

    // Capability strings for display. These describe what the app **holds** —
    // the approved set — not what it asked for. `manifest.toml` is written to
    // disk beside the binary and remains the record of the request.
    let caps: Vec<String> = approved
        .grants()
        .iter()
        .map(|g| g.display_string())
        .collect();
    let caps_json = serde_json::to_string(&caps)
        .map_err(|e| io::Error::other(format!("capability serialization: {e}")))?;

    // The decision itself, structured, for the sandbox to read back at launch.
    // Separate from the signed envelope on purpose: the envelope is the
    // *attestation* and only exists when an identity key was available, while
    // this is the *decision*, which exists either way. Bundled apps have the
    // second and not the first, and conflating them is what left the runtime
    // reading `manifest.toml` (TASK-the-approval-is-signed-but-not-enforced).
    let approved_json = serde_json::to_string(approved.grants())
        .map_err(|e| io::Error::other(format!("approved serialization: {e}")))?;

    let installed_at = now_rfc3339();
    ardb::insert_app(
        user_db,
        &app_id,
        &name,
        &version,
        &caps_json,
        wasm_path.to_str().unwrap_or_default(),
        &installed_at,
        &wasm_hash,
        &approved_json,
    )
    .await?;

    // Register handler_for entries in the handler registry
    for nsid in &manifest.app.handler_for {
        let existing = hrdb::count_for_nsid(user_db, nsid.as_str()).await?;
        let is_default: i32 = if existing == 0 { 1 } else { 0 };
        hrdb::upsert_handler(user_db, &app_id, nsid.as_str(), is_default).await?;
    }

    // Build and sign a GrantEnvelope over the *approved* capabilities. Note what
    // is not here: `manifest.capabilities`. The manifest says what the app wants;
    // only `approved` says what anyone agreed to, and only that is signed.
    // Best-effort: if the identity key isn't in the keychain (e.g. during
    // bundled-app boot before any user has logged in), skip gracefully.
    // Self-issued: the user granting capabilities to an app on their own device,
    // the case `GrantEnvelope::expires_at` documents `None` for; revocation is
    // the control, enforced on every access. When the consent prompt lets a
    // person choose *once* or *while open*, that choice replaces this default and
    // flows through `set_lifetime` below (TASK-a-grant-cannot-be-once-or-while-open).
    let install_lifetime = GrantLifetime::UntilRevoked;
    if let Some(envelope) = build_signed_envelope(
        base,
        user_id,
        &app_id,
        approved.grants().to_vec(),
        secrets,
        install_lifetime,
    ) {
        if let Err(e) = grant_db::store_envelope(user_db, &app_id, &envelope).await {
            tracing::warn!(%app_id, "failed to store grant envelope: {e}");
        }
        // Record the counted lifetime (Uses / WhileOpen); a no-op for the two a
        // clock or the revocation list already enforces. This is the seam the
        // consent prompt hangs *once* and *while open* from — the choice a
        // person makes flows in as `lifetime`
        // (TASK-a-grant-cannot-be-once-or-while-open).
        if let Err(e) =
            grant_db::set_lifetime(user_db, &app_id, &envelope.id, install_lifetime).await
        {
            tracing::warn!(%app_id, "failed to record grant lifetime: {e}");
        }
    } else {
        tracing::debug!(%app_id, %user_id, "identity key not available; skipping GrantEnvelope");
    }

    tracing::info!(%app_id, %version, "app installed");
    if let Some(bus) = event_bus {
        let wasm_size = wasm_bytes.len();
        let _ = bus.publish(Event::with_payload(
            EventCategory::WASM,
            EventLevel::Info,
            format!("App installed: {app_id}"),
            serde_json::json!({ "app_id": app_id, "version": version, "wasm_bytes": wasm_size }),
        )
        .in_scope(EventScope::User(user_id.to_string())));
    }
    Ok(UserResponse::AppInstalled {
        app_id,
        name,
        capabilities: caps,
    })
}

/// Verify that `sig_b64` is a valid Ed25519 signature over `BLAKE3(wasm_bytes)` by
/// the DID key embedded in `publisher_did`.
///
/// The signature bytes are standard base64-encoded (not URL-safe). The BLAKE3 hash
/// is represented as the 32-byte raw digest, not a hex string.
pub fn verify_publisher_signature(
    publisher_did: &str,
    sig_b64: &str,
    wasm_hash_hex: &str,
) -> Result<(), String> {
    // Decode the 32-byte BLAKE3 digest back from hex.
    let hash_bytes: [u8; 32] = hex::decode(wasm_hash_hex)
        .map_err(|e| format!("wasm_hash hex decode: {e}"))?
        .try_into()
        .map_err(|_| "wasm_hash is not 32 bytes".to_owned())?;

    // Decode the base64-encoded signature.
    let sig_bytes = BASE64_STD
        .decode(sig_b64)
        .map_err(|e| format!("signature base64 decode: {e}"))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature is not 64 bytes".to_owned())?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    // Parse the DID and extract the Ed25519 public key.
    let did = kotton_wire::did::Did::parse(publisher_did)
        .map_err(|e| format!("invalid publisher DID: {e}"))?;
    let verifying_key = DidKeyMethod::to_public_key(&did)
        .map_err(|e| format!("could not extract public key from DID: {e}"))?;

    verifying_key
        .verify(&hash_bytes, &signature)
        .map_err(|e| format!("signature verification failed: {e}"))
}

/// Re-hash the on-disk WASM binary for `app_id` and compare against the stored hash.
///
/// Returns `(stored_hash, computed_hash, matches)`.
pub async fn app_verify(
    user_db: &Arc<SqlitePool>,
    base: &Path,
    app_id: &str,
) -> io::Result<UserResponse> {
    let stored_hash = ardb::get_wasm_hash(user_db, app_id)
        .await?
        .ok_or_else(|| io::Error::other(format!("app '{app_id}' not found")))?;

    let wasm_path = wasm_path_for(base, app_id);
    let wasm_bytes = fs::read(&wasm_path).await.map_err(|e| {
        io::Error::other(format!(
            "could not read wasm for '{app_id}' at {}: {e}",
            wasm_path.display()
        ))
    })?;

    let computed_hash = hex::encode(blake3::hash(&wasm_bytes).as_bytes());
    let matches = stored_hash == computed_hash;

    Ok(UserResponse::AppVerifyResult {
        app_id: app_id.to_owned(),
        stored_hash,
        computed_hash,
        matches,
    })
}

/// The user's root DID: the `did:kel` AID from the local KEL (RFC-0038 8c). Every
/// identity `create_user` mints has an inception; `None` if the KEL is absent. The
/// KEL's seq-0 key-state is the identity key, so the AID resolves (via
/// `KelResolver`) to exactly the key that signs the envelope.
fn user_root_did(base: &Path, user_id: &str) -> Option<Did> {
    kotton_identity::kel_store::load_chain(base, user_id)
        .ok()
        .and_then(|chain| chain.into_iter().next())
        .and_then(|inception| Did::parse(&inception.aid.to_string()).ok())
}

/// What the occupant is handed as its roots: **always `Some`**, and it says
/// which of two things is true.
///
/// `kotton:app/roots` is `world occupant`'s, and the runner links the interface
/// exactly when this is `Some` (`RunnerInput::roots`). So for a launch into
/// that world the question is never *whether* the interface exists — the world
/// answered that — only what the list holds. `None` for an occupant is not "no
/// roots"; it is a component that fails to instantiate, which the drawn file
/// browser's first boot showed on 2026-09-21
/// (`TASK-the-lock-screen-fails-to-instantiate-because-the-shell-imports-roots`).
///
/// **This was `Some(from_store.unwrap_or_default())` until 2026-09-24**, and
/// that line is where every failure below it — nobody signed in, no chain, a
/// store not loaded or loaded without keys, an index that would not open —
/// became an empty list, so the file browser drew all of them as a person with
/// no places. The owner saw *"all of my roots disappeared"* over a store that
/// held no key (`TASK-a-roots-failure-is-drawn-as-no-roots`). Now the
/// occupant is handed [`RunnerRoots::Unread`] with the cause, and an empty
/// [`RunnerRoots::Read`] means exactly that the index opened and holds none.
///
/// A guest that is not the occupant is not this function's business: it gets
/// `None` and no interface, at the sites that decide occupancy.
fn roots_for_the_occupant(from_store: Result<Vec<RunnerRoot>, RootsUnread>) -> Option<RunnerRoots> {
    Some(match from_store {
        Ok(roots) => RunnerRoots::Read(roots),
        Err(why) => RunnerRoots::Unread(why),
    })
}

/// This person's roots, for the guest that may read them (RFC-0071 R11–R16).
///
/// The AID is replayed from the local KEL here — the same chain
/// [`own_kel_keys`] reads just below — and handed to the host, which reads the
/// store. `Err` where there is no user, or no chain to name them by: a root
/// index written under the wrong member is worse than none, because R16 makes
/// it the thing every later device learns the set from. Both are logged here,
/// where they happen; until 2026-09-24 neither was, and neither could be told
/// from a person with no roots.
fn user_roots(
    host: &dyn AppHost,
    base: &Path,
    user_id: Option<&str>,
) -> Result<Vec<RunnerRoot>, RootsUnread> {
    let Some(uid) = user_id else {
        tracing::info!(
            "roots: this launch is for nobody — the welcome or the lock screen — so \
             there is no index to read"
        );
        return Err(RootsUnread::Nobody);
    };
    let Some(own_aid) = user_root_did(base, uid) else {
        tracing::warn!(
            user = %uid,
            "roots: no KEL chain names this person, so their index cannot be opened \
             under the right member (RFC-0038 8c)"
        );
        return Err(RootsUnread::NoIdentity);
    };
    host.user_roots(base, uid, &own_aid.to_string())
}

/// The sentence the lock screen shows when a launch for a named person found
/// their keys not loaded (`TASK-a-roots-failure-is-drawn-as-no-roots`, clause a).
///
/// One sentence, one full stop, in the person's words: what is true and what
/// to do. The operator-facing reason is in the daemon's log beside it.
pub const KEYS_NOT_LOADED_NOTICE: &str =
    "Your files are locked on this device \u{2014} unlock to open them.";

/// **A launch for a person whose keys are not loaded is a launch for nobody,
/// and the shell is told why** (`TASK-a-roots-failure-is-drawn-as-no-roots`,
/// clause a).
///
/// `Some(user_id)` is a caller's claim that the person is in. The claim is
/// threaded from the exchange that opened a session, not read from the store
/// it opened, so it can be true of the session and false of the store: a
/// daemon that started before this identity was unlocked holds a keyless
/// store for them until something rebuilds it, and on 2026-09-24 the owner
/// was shown a desk over exactly that — an account row with a fingerprint,
/// an empty *Locations*, and a Networking notice saying the node held no key.
///
/// Demoting the launch to nobody is what makes every downstream fact agree:
/// no mount (so no app it raises is granted a file capability over a store
/// that refuses every read), no `did`, `mode=locked` from the same rule the
/// boot uses ([`push_shell_mode`]), and the roots saying *locked* rather than
/// *none*. The instance is then one the unlock door can replace
/// (`replace_the_screen` refuses an instance that already carries a mount),
/// so the person types their credential once and reaches a desk with keys.
///
/// Returns the person the launch is now for, and the cause where it was
/// demoted.
fn a_person_whose_keys_are_loaded(
    host: &dyn AppHost,
    user_id: Option<String>,
) -> (Option<String>, Option<RootsUnread>) {
    match user_id {
        Some(uid) if !host.keys_loaded(&uid) => {
            tracing::warn!(
                user = %uid,
                "launch: this person's store holds no keys, so the shell opens on the \
                 lock screen and not on a desk over files it cannot read"
            );
            (None, Some(RootsUnread::Locked))
        }
        other => (other, None),
    }
}

/// Resolve the own-identity `did:kel` issuer keys for grant verification
/// (RFC-0038 8c): the user's AID → its current authoritative key, replayed from the
/// local KEL. Other issuers' KELs (contacts/orgs) arrive via identity-core sync
/// (8e); until then a `did:kel` issuer we don't hold fails closed.
fn own_kel_keys(base: &Path, user_id: Option<&str>) -> Vec<(String, [u8; 32])> {
    let Some(uid) = user_id else {
        return Vec::new();
    };
    let aid = match kotton_identity::kel_store::load_chain(base, uid) {
        Ok(chain) => match chain.first() {
            Some(inception) => inception.aid.to_string(),
            None => return Vec::new(),
        },
        Err(_) => return Vec::new(),
    };
    match kotton_identity::kel_store::resolve_current_key_for(base, uid, false) {
        Ok(Some(key)) => vec![(aid, key)],
        _ => Vec::new(),
    }
}

/// Build and sign a self-issued `GrantEnvelope` for `app_id`.
///
/// Reads the user's identity signing key from the OS keychain, resolves the DID
/// (`user_root_did`), and produces a signed envelope with the given `lifetime`.
///
/// The lifetime is a parameter rather than a literal because an install
/// envelope is signed once and **never re-issued**. A TTL on a grant nothing
/// renews is not a security control, it is a fuse: when it burns, `grant_check`
/// returns `GrantDenied::Expired` and every capability the app declared stops
/// working, with an error indistinguishable to the app from one it never held.
///
/// The fourth call site is [`hand_over_picked_file`], which is not an install:
/// it mints one envelope per open, `WhileOpen`, from the person's own act of
/// picking a file. That one *is* re-issued — every open mints a fresh one — and
/// it is why the lifetime being a parameter earns its keep rather than merely
/// being tidy.
///
/// Returns `None` if the identity key is not available in the keychain.
pub fn build_signed_envelope(
    base: &Path,
    user_id: &str,
    app_id: &str,
    grants: Vec<CapabilityGrant>,
    secrets: &dyn SecretsStore,
    lifetime: GrantLifetime,
) -> Option<GrantEnvelope> {
    // Retrieve the identity signing key scalar from the keychain.
    let hex_key = secrets
        .get_secret(&kdf_labels::identity_signing_key(user_id))
        .ok()??;
    let key_bytes: [u8; 32] = hex::decode(&hex_key).ok()?.try_into().ok()?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);

    // The user's root DID is their did:kel AID.
    let user_did = user_root_did(base, user_id)?;

    // App's DID is the user's DID (self-issued grant) — which is exactly why the
    // app has to be named separately. Issuer and subject are both the user here,
    // so without `app_id` every app grant a user issues is byte-identical in its
    // signed body and distinguishable only by an unsigned column
    // (`DEC-0052`, Article IV).
    let subject_did = user_did.clone();

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let expires_at = lifetime.expires_at(now_secs);

    let mut envelope = GrantEnvelope {
        id: Uuid::new_v4().to_string(),
        issuer_did: user_did,
        subject_did,
        node_did: None,
        grants,
        issued_at: now_secs,
        expires_at,
        // The parameter this function used to take and discard as `_app_id`.
        app_id: Some(app_id.to_string()),
        issuer_signature: String::new(),
    };

    // Sign over the canonical JSON (issuer_signature excluded from digest).
    let canonical = envelope.canonical_json().ok()?;
    let sig = signing_key.sign(canonical.as_bytes());
    envelope.issuer_signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Some(envelope)
}

// ── The powerbox: the file the person picked ─────────────────────────────────

/// The launch argument that names the file the person opened.
///
/// One constant because every place that handles the key has to mean the same
/// one: the strip in [`guest_launch_args`], the mint in
/// [`hand_over_picked_file`] and the rewrite it does on its way out, and the
/// drops in [`prepare_launch`] where a launch has nothing to hand a file to.
const PICKED_FILE_ARG: &str = "path";
/// The launch argument carrying the one sentence a pre-auth screen shows
/// about why it is the screen being shown ([`KEYS_NOT_LOADED_NOTICE`]).
/// Host-authored, like `mode`.
pub const NOTICE_ARG: &str = "notice";

/// Mint the launching app a **while-open grant on the one file the person
/// picked**, and rewrite the launch argument into the app's own words.
///
/// This is the desktop's file-picker rule — macOS calls the mechanism the
/// powerbox — and it is the one place a confined app is handed a path it never
/// declared. The person choosing a file in the system's own surface *is* the
/// consent, so there is no prompt: a second dialog asking whether they meant
/// the file they just clicked teaches people to click through dialogs.
///
/// # What it grants, and what it cannot
///
/// Read and write on **that path and nothing beside it**. A
/// [`CapabilityTarget::Vfs`](kotton_schemas::CapabilityTarget::Vfs) grant
/// matches a path exactly or as a parent of it, so a grant naming a regular
/// file covers exactly that file: its neighbour is a different path and its
/// prefix-siblings (`trip-notes.md.bak`) fail the `/`-terminated descendant
/// test. Nothing here widens a target.
///
/// [`GrantLifetime::WhileOpen`], so the capability is bound to this instance
/// and is exhausted when the instance ends
/// (`TASK-a-grant-cannot-be-once-or-while-open`, [`app_closed`]). A later
/// launch inherits nothing.
///
/// # Only a file that is already there
///
/// The mint refuses anything that is not a regular file inside this user's own
/// VFS: a directory (a tree grant is what a manifest declares and the person
/// places, not something a launch invents) and a path that resolves to
/// nothing. The argument is then **dropped**, because an
/// app told to open a path it holds no grant on would either fail confusingly
/// or — worse — resolve the same string inside its *own* root and write there.
///
/// # The rewrite, and why the guest never sees the path
///
/// The person's path is in the *occupant's* frame of reference. What the
/// launched app gets back is the file's own name, which is what it must show
/// the person anyway and all it needs to address the handle the sandbox mints
/// for it (`DirHandle`, `granted_vfs_roots` in `kotton-wasm`). RFC-0021's rule
/// that an app never learns the path the person chose survives the hand-off
/// intact: the pen principle again — the confined thing named what it wanted,
/// the host wrote what actually happened.
///
/// # One file per launch
///
/// The hand-off answers for one `path`: the first in the list. Every `path`
/// after it is dropped before anything is asked of the tree, so the list that
/// leaves this function holds at most one `path`, and that one is the file's
/// name with a grant behind it. Dropped rather than refused, as
/// [`guest_launch_args`] drops a key it will not take: the launch is the
/// person's, and a list that asked wrongly does not cost them their editor.
///
/// Returns the VFS path that was handed over, for the log; `None` when nothing
/// was minted.
async fn hand_over_picked_file(
    user_db: &Arc<SqlitePool>,
    base: &Path,
    user_id: &str,
    app_id: &str,
    launch_args: &mut Vec<(String, String)>,
    secrets: &dyn SecretsStore,
    // The person's own tree, which is where their files are: the sealed store,
    // as the host answers it. `None` hands nothing over.
    tree: Option<&dyn PersonalTree>,
) -> Option<String> {
    // Every `path` but the first goes before the first is looked at: the rest
    // of this function rewrites or drops one pair, and a second left standing
    // would reach the app as the person's own path.
    let mut first = true;
    launch_args.retain(|(k, _)| k != PICKED_FILE_ARG || std::mem::take(&mut first));
    let index = launch_args.iter().position(|(k, _)| k == PICKED_FILE_ARG)?;
    let asked = launch_args[index].1.clone();

    // Everything below either mints and rewrites, or drops the argument. A
    // `path` that survives without a grant behind it is the failure this
    // function exists to prevent, so the drop is the default.
    let drop_it = |args: &mut Vec<(String, String)>| {
        args.remove(index);
    };

    let vfs_path = kotton_schemas::normalize_vfs_path(&asked);
    // No `.kotton` refusal: the person's tree is rooted in the store and no
    // path in it names anything of the daemon's (`PERSON_TREE_ROOT`), so the
    // tree's own answer below is the whole test of what the path names.
    if vfs_path == "/" {
        tracing::warn!(%app_id, "apps.launch: refusing to hand over `{asked}`");
        drop_it(launch_args);
        return None;
    }
    let Some(name) = vfs_path.rsplit('/').next().map(str::to_owned) else {
        drop_it(launch_args);
        return None;
    };

    // Asked of this person's own tree — the sealed store, which is where the
    // file is and the same place the sandbox asks when it shapes the handle
    // (`granted_vfs_roots` in `kotton-wasm`), so the two cannot disagree about
    // what the path names. `normalize_vfs_path` has already popped every `..`,
    // and it pops nothing at the root. It asked the disk under `data/` until
    // 2026-09-24, which could only see a file that rested there in the clear
    // (`TASK-a-file-an-app-writes-rests-in-the-clear-in-the-sealed-stores-own-directory`).
    let is_a_file = match tree {
        Some(tree) => matches!(tree.kind(&vfs_path).await, Ok(Some(RunnerPathKind::File))),
        None => false,
    };
    match is_a_file {
        true => {}
        false => {
            tracing::warn!(
                %app_id,
                "apps.launch: `{vfs_path}` is not a file of this person's, so nothing was handed over"
            );
            drop_it(launch_args);
            return None;
        }
    }

    let grants = vec![
        CapabilityGrant::vfs(CapabilityKind::Read, vfs_path.clone()),
        CapabilityGrant::vfs(CapabilityKind::Write, vfs_path.clone()),
    ];
    let Some(envelope) = build_signed_envelope(
        base,
        user_id,
        app_id,
        grants,
        secrets,
        GrantLifetime::WhileOpen,
    ) else {
        tracing::warn!(%app_id, "apps.launch: could not sign the hand-off grant; nothing handed over");
        drop_it(launch_args);
        return None;
    };
    if let Err(e) = grant_db::store_envelope(user_db, app_id, &envelope).await {
        tracing::warn!(%app_id, "apps.launch: could not store the hand-off grant: {e}");
        drop_it(launch_args);
        return None;
    }
    if let Err(e) =
        grant_db::set_lifetime(user_db, app_id, &envelope.id, GrantLifetime::WhileOpen).await
    {
        // A while-open grant with no lifetime row would never be exhausted —
        // it would outlive the instance it was minted for, which is the one
        // promise this grant makes. Take it back rather than issue it wrong.
        tracing::warn!(%app_id, "apps.launch: could not bind the hand-off grant to this instance: {e}");
        let _ = grant_db::delete_envelope(user_db, &envelope.id).await;
        drop_it(launch_args);
        return None;
    }

    launch_args[index].1 = name;
    tracing::info!(%app_id, envelope = %envelope.id, "apps.launch: handed over one file, while open");
    Some(vfs_path)
}

// ── What another app holds, by shape ─────────────────────────────────────────

/// One resource an app holds, as the daemon knows it: the words the occupant is
/// told, and the target it is not.
///
/// The target stays on this side. [`service_host_call`] answers `covering`
/// with it and sends only [`HeldShape::holding`] — a [`RunnerHolding`], which
/// has no field a path could travel in (RFC-0021: a guest never learns the
/// path a person chose, and that includes the path they chose for *another*
/// app).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldShape {
    /// What the occupant is told.
    pub holding: RunnerHolding,
    /// Where it points, normalized. Never sent.
    target: String,
}

/// What `app_id` holds in the person's files, **as the host granted it** —
/// the answer to `grants.held-by`
/// (`TASK-a-surface-cannot-ask-the-host-what-another-app-was-granted`).
///
/// # The grant, not the manifest
///
/// Read from the envelopes the host signed for this app, minus those revoked
/// or expired, and from the recorded approval only when there are no
/// envelopes — the precedence the sandbox itself mints handles by
/// ([`PersonalReach::of`], `granted_vfs_roots` in `kotton-wasm`). So a shape the
/// person bound somewhere other than the manifest's default is reported, and a
/// shape the person never approved is not. The manifest is read for its
/// *words* only — the id and label its author gave each shape — through
/// [`attribute_shapes`].
///
/// # What it leaves out
///
/// A while-open grant: a file the occupant itself handed over
/// ([`hand_over_picked_file`]). It is the asking surface's own act, it ends
/// with a window, and it is not what a person means by what an app *holds*.
///
/// # Named through the registry
///
/// The app is looked up in this person's registry before anything else, so a
/// name that is not an installed app is refused as one — and the only strings
/// that ever reach [`manifest_path_for`] from here are ids the registry already
/// holds, never one the asking guest made up.
pub async fn app_holdings(
    user_db: &Arc<SqlitePool>,
    base: &Path,
    app_id: &str,
) -> io::Result<Vec<HeldShape>> {
    if ardb::get_app(user_db, app_id).await?.is_none() {
        return Err(io::Error::other(format!("{app_id} is not installed")));
    }
    let manifest_toml = fs::read_to_string(manifest_path_for(base, app_id))
        .await
        .map_err(|e| io::Error::other(format!("reading {app_id}'s manifest: {e}")))?;
    let manifest = AppManifest::from_toml(&manifest_toml)
        .map_err(|e| io::Error::other(format!("{app_id}'s manifest: {e}")))?;

    let envelopes = grant_db::get_envelopes_for_app(user_db, app_id).await?;
    let grants: Vec<CapabilityGrant> = if envelopes.is_empty() {
        ardb::get_approved(user_db, app_id)
            .await?
            .map(|set| set.grants_slice().to_vec())
            .unwrap_or_default()
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let mut standing = Vec::new();
        for envelope in envelopes {
            if envelope.app_id.as_deref() != Some(app_id)
                || envelope.expires_at.is_some_and(|t| t <= now)
                || grant_db::is_revoked(user_db, &envelope.id).await?
                || grant_db::lifetime_kind(user_db, &envelope.id).await?.as_deref()
                    == Some("while_open")
            {
                continue;
            }
            standing.extend(envelope.grants);
        }
        standing
    };
    Ok(attribute_shapes(&manifest.vfs_shapes(), &grants))
}

/// The installed apps a file can be opened in — the answer to
/// `grants.opens-files`, which the share sheet's *An app* lists (RFC-0090,
/// *The three targets*: "a grant on the file, as today"; unit 5).
///
/// # The rule, and whose it is to state
///
/// **An app takes a file when its manifest declares a file shape it both
/// reads and writes** ([`AppManifest::vfs_shapes`], the declaration the
/// install prompt and [`app_holdings`] already read — the editor's
/// `documents` today). Read *and* write because that is what
/// [`hand_over_picked_file`] mints on the one file the person picked: an app
/// that declared it only reads files would be handed more than it asked for.
/// No manifest field says *this app opens a file it is handed*, or *which
/// kinds*; inventing one here would be a field nothing else reads. So the
/// rule is the nearest declaration there is, and stating it properly — a
/// declaration of the kinds an app opens — is the manifest's to do later.
///
/// The designated shell is not listed: it is the surface asking, and a file
/// is not handed from it to itself. An app whose manifest cannot be read
/// declares nothing the host can read, so it is left out and logged rather
/// than failing the whole answer.
///
/// **Ids and names, never a shape.** What an app holds is `held-by`'s answer,
/// asked separately; this one says only which apps a file can go to.
pub async fn app_file_openers(
    user_db: &Arc<SqlitePool>,
    base: &Path,
) -> io::Result<Vec<RunnerOpener>> {
    let shell = role_db::get_role(user_db, "shell").await?;
    let mut openers = Vec::new();
    for app in ardb::list_apps(user_db).await? {
        if shell.as_deref() == Some(app.app_id.as_str()) {
            continue;
        }
        let manifest = match fs::read_to_string(manifest_path_for(base, &app.app_id))
            .await
            .map_err(|e| e.to_string())
            .and_then(|toml| AppManifest::from_toml(&toml).map_err(|e| e.to_string()))
        {
            Ok(manifest) => manifest,
            Err(e) => {
                tracing::warn!(app_id = %app.app_id, "opens-files: its manifest could not be read, so it is not offered: {e}");
                continue;
            }
        };
        let takes_a_file = manifest.vfs_shapes().iter().any(|shape| {
            shape.access.contains(&CapabilityKind::Read) && shape.access.contains(&CapabilityKind::Write)
        });
        if takes_a_file {
            openers.push(RunnerOpener { app_nsid: app.app_id, name: app.name });
        }
    }
    openers.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.app_nsid.cmp(&b.app_nsid)));
    Ok(openers)
}

/// Name each file grant by the shape it answers to.
///
/// A grant is `(kind, path)` and carries no shape id, so the name has to be
/// recovered, and it is recovered two ways:
///
/// 1. **By the manifest's default**: a target equal to a shape's suggested
///    path is that shape. When that names every shape it is the answer, since
///    it assumes nothing about the order the grants came in — and a flat
///    approval comes in no particular order.
/// 2. **By position**, when it does not and the grants are exactly what
///    [`ApprovedCapabilities::from_bindings`] builds: one target per declared
///    shape, in declaration order, carrying that shape's access and no more.
///    That is every install made through RFC-0021's binding, and it is the only
///    way a rebound shape — `documents` bound to `/work` — can be named at all,
///    since its target no longer says anything about the manifest.
///
/// Anything left is reported with no shape and generic words, rather than
/// dropped: it is a real grant, and an answer that left it out would say the
/// app reaches less than it does.
fn attribute_shapes(
    shapes: &[kotton_schemas::CapabilityShape],
    grants: &[CapabilityGrant],
) -> Vec<HeldShape> {
    // One entry per target, in the order the grants name them, with every kind
    // held there.
    let mut targets: Vec<(String, Vec<CapabilityKind>)> = Vec::new();
    for grant in grants {
        let kotton_schemas::CapabilityTarget::Vfs { path } = &grant.target else {
            continue;
        };
        let path = kotton_schemas::normalize_vfs_path(path);
        match targets.iter_mut().find(|(t, _)| *t == path) {
            Some((_, kinds)) if !kinds.contains(&grant.kind) => kinds.push(grant.kind.clone()),
            Some(_) => {}
            None => targets.push((path, vec![grant.kind.clone()])),
        }
    }

    let same_kinds = |a: &[CapabilityKind], b: &[CapabilityKind]| {
        a.len() == b.len() && a.iter().all(|k| b.contains(k))
    };
    let bound_in_order = targets.len() >= shapes.len()
        && shapes
            .iter()
            .zip(&targets)
            .all(|(shape, (_, kinds))| same_kinds(&shape.access, kinds));

    // By default target first: it is the reading that needs no assumption
    // about order, and when it names every shape it is the whole answer — a
    // flat approval arrives in no particular order, and a position would
    // misname it.
    let mut by_default: Vec<Option<usize>> = vec![None; targets.len()];
    let mut taken = vec![false; shapes.len()];
    for (slot, (target, _)) in by_default.iter_mut().zip(&targets) {
        if let Some(i) = shapes.iter().enumerate().position(|(i, s)| {
            !taken[i] && kotton_schemas::normalize_vfs_path(&s.default_target) == *target
        }) {
            taken[i] = true;
            *slot = Some(i);
        }
    }
    let named: Vec<Option<usize>> = if taken.iter().all(|t| *t) || !bound_in_order {
        by_default
    } else {
        (0..targets.len()).map(|i| (i < shapes.len()).then_some(i)).collect()
    };

    // In the manifest's order, then whatever answers to no shape.
    let mut held: Vec<(usize, HeldShape)> = targets
        .into_iter()
        .zip(named)
        .map(|((target, kinds), shape)| {
            let writable = kinds.contains(&CapabilityKind::Write);
            let holding = match shape.map(|i| &shapes[i]) {
                Some(s) => RunnerHolding {
                    shape: Some(s.id.clone()),
                    label: s.label.clone().unwrap_or_else(|| s.id.clone()),
                    writable,
                },
                None => RunnerHolding {
                    shape: None,
                    label: OTHER_FILES.to_owned(),
                    writable,
                },
            };
            (shape.unwrap_or(usize::MAX), HeldShape { holding, target })
        })
        .collect();
    held.sort_by_key(|(order, _)| *order);
    held.into_iter().map(|(_, h)| h).collect()
}

/// The words for a file grant no declared shape answers to.
const OTHER_FILES: &str = "Other files you gave it";

/// Which holding reaches `path`, if any — the answer to `grants.covering`.
///
/// The predicate is [`CapabilitySet::allows`](kotton_schemas::CapabilitySet::allows)'s,
/// applied to one target at a time: a path covers itself and its descendants,
/// `/` covers everything, and `/documents` does not cover `/documentsother`.
/// Where two holdings nest, the nearer one answers, because that is the name
/// the person would give the place the file is in.
fn covering(held: &[HeldShape], path: &str) -> Option<RunnerHolding> {
    let path = kotton_schemas::normalize_vfs_path(path);
    held.iter()
        .filter(|h| {
            h.target == "/" || h.target == path || path.starts_with(&format!("{}/", h.target))
        })
        .max_by_key(|h| h.target.len())
        .map(|h| h.holding.clone())
}

/// Replace any grant envelope for `app_id` that predates the signed `app_id`
/// binding with one minted from `approved` (`DEC-0052`, Article IV).
///
/// A no-op once every stored envelope names its app, which is the steady state
/// after one launch. Best-effort: a failure here leaves the app with no usable
/// envelope, which denies rather than grants.
async fn rebind_legacy_envelopes(
    user_db: &Arc<SqlitePool>,
    base: &Path,
    user_id: &str,
    app_id: &str,
    approved: &[CapabilityGrant],
    secrets: &dyn SecretsStore,
) {
    let stored = match grant_db::get_envelopes_for_app(user_db, app_id).await {
        Ok(v) => v,
        Err(_) => return,
    };
    if stored.is_empty() || stored.iter().all(|e| e.app_id.is_some()) {
        return;
    }
    tracing::info!(
        %app_id,
        count = stored.iter().filter(|e| e.app_id.is_none()).count(),
        "re-minting grant envelopes that name no app, from the recorded approval"
    );

    // Drop the unbound ones. Their capabilities are re-derived from consent
    // below; keeping them would leave rows `check_grant` can only refuse.
    for env in stored.iter().filter(|e| e.app_id.is_none()) {
        if let Err(e) = grant_db::delete_envelope(user_db, &env.id).await {
            tracing::warn!(%app_id, envelope = %env.id, "could not drop an unbound envelope: {e}");
            return;
        }
    }

    if approved.is_empty() {
        return;
    }
    if let Some(envelope) = build_signed_envelope(
        base,
        user_id,
        app_id,
        approved.to_vec(),
        secrets,
        GrantLifetime::UntilRevoked,
    ) {
        if let Err(e) = grant_db::store_envelope(user_db, app_id, &envelope).await {
            tracing::warn!(%app_id, "could not store the re-minted envelope: {e}");
        }
    }
}

/// Uninstall a WASM app.
///
/// Removes the WASM file, the manifest, the `app_registry` row, and all
/// handler entries for this app.
pub async fn app_uninstall(
    user_db: &Arc<SqlitePool>,
    base: &Path,
    app_id: String,
) -> io::Result<UserResponse> {
    let deleted = ardb::delete_app(user_db, &app_id).await?;
    if !deleted {
        return Ok(UserResponse::AppNotFound { app_id });
    }

    // Remove files (best-effort — don't fail if already gone)
    let _ = fs::remove_file(wasm_path_for(base, &app_id)).await;
    let _ = fs::remove_file(manifest_path_for(base, &app_id)).await;
    let _ = fs::remove_dir(base.join("apps").join(&app_id)).await;

    // Remove all handler entries for this app
    hrdb::delete_all_for_app(user_db, &app_id).await?;

    // Remove all grant envelopes for this app (best-effort).
    let _ = grant_db::delete_envelopes_for_app(user_db, &app_id).await;

    tracing::info!(%app_id, "app uninstalled");
    Ok(UserResponse::AppUninstalled)
}

/// List all installed WASM apps.
pub async fn app_list(
    user_db: &Arc<SqlitePool>,
    live_ids: &std::collections::HashSet<String>,
) -> io::Result<UserResponse> {
    let mut apps = ardb::list_apps(user_db).await?;
    for app in &mut apps {
        app.running = live_ids.contains(&app.app_id);
    }
    Ok(UserResponse::AppList { apps })
}
/// Which screen the shell opens on: `authenticated`, `locked`, or `welcome`.
///
/// Three states and the order matters. A session decides it outright. With no session, the
/// question is whether this device has anybody registered at all — nobody means first run and
/// a welcome, somebody means a person who exists and is not currently in.
///
/// **`locked` is not "something went wrong".** It is the ordinary second run: a device that
/// knows who lives here and is waiting to be told the credential. Until 2026-09-17 the
/// compositor never reached this for a resident-but-locked user — it returned on the failure
/// to open their database — so a screen that was built, styled and specimened in the gallery
/// was unreachable in the state it exists for (`DEC-0077`).
fn shell_launch_mode(has_session: bool, users: &[RegisteredUser]) -> &'static str {
    if has_session {
        "authenticated"
    } else if users.is_empty() {
        "welcome"
    } else {
        "locked"
    }
}

/// Write the launch arguments that say **which screen the shell opens on**:
/// `mode`, and — when that mode is `locked` — the `users` the screen unlocks
/// and the `names` it calls them by.
///
/// **Into the shell's launch and no other.** Both callers launch the shell:
/// [`app_launch_system_shell`] runs nothing else, and [`prepare_launch`] calls
/// this only when the app is the one the person's `app_roles` designates. The
/// roster is who is registered on this device, and the shell is the one app
/// that draws a screen from it; an editor opened on the lock screen is handed
/// none of it.
///
/// # Why this is a function and not two copies
///
/// There are two launch paths and one rule. [`app_launch`] asked
/// [`shell_launch_mode`] for the answer; [`app_launch_system_shell`] wrote
/// `mode=welcome` as a literal, on the reasoning that *"this path only runs when
/// no user is resident"*. The premise was true and the conclusion was not:
/// **no user resident is not no user registered**, and nor is it the only way
/// here. A person's ordinary second boot arrives at that function by the *other*
/// door — their account is loaded and locked (`DEC-0049`), their database will
/// not open, and `launch_designated_shell` sends a locked account to the system
/// shell precisely because it needs no database. That door was opened on
/// 2026-09-17 to reach the unlock screen and delivered the welcome screen
/// instead, for four days, because the constant was two hundred lines below the
/// arm being added and nothing connected them. The one door on that screen then
/// refused, because `create_identity` reads the device registry and the registry
/// knew who lived here. Two readers, one question, and the screen was decided by
/// the one that had not been asked
/// (`TASK-a-second-boot-with-a-locked-identity-opens-the-welcome-and-not-the-lock-screen`).
///
/// So the rule lives in one place and both callers ask it. A path that resolves
/// *what to run* from a fixed directory still has to resolve *which screen* from
/// the registry, because those are different questions and only the first one
/// has a constant for an answer.
///
/// `has_session` is the caller's own claim that somebody is in at this screen —
/// `app_launch`'s `user_id`, and always `false` for the system shell, which has
/// no user to have a session for.
///
/// Absent-only, like the identity args above it: an operator typing
/// `kotton app launch <id> mode=…` is naming a screen deliberately, and a
/// *guest* never reaches here with one because [`guest_launch_args`] drops both
/// keys before they arrive.
///
/// The registry is read only when it is going to be used, because
/// [`AppHost::registered_users`] touches the disk at every call.
///
/// `users` and `names` are two lists of the same length in the same order —
/// ids joined by `,`, which an id cannot contain, and display names joined by
/// U+001F, which a display name cannot contain — and the shell reads the id at
/// position *n* to unlock and the name at position *n* to greet. An identity
/// with no name has an empty entry, and the shell draws its fallback for it;
/// it never reaches across to the id
/// (`TASK-the-name-the-welcome-asks-for-goes-nowhere`).
fn push_shell_mode(launch_args: &mut Vec<(String, String)>, has_session: bool, host: &dyn AppHost) {
    if launch_args.iter().any(|(k, _)| k == "mode") {
        return;
    }
    launch_args.extend(screen_args(has_session, &host.registered_users()));
}

/// The arguments [`push_shell_mode`] writes, as a function of the registry —
/// separate so the shape can be held by a test with no host behind it.
fn screen_args(has_session: bool, users: &[RegisteredUser]) -> Vec<(String, String)> {
    let mode = shell_launch_mode(has_session, users);
    let mut args = vec![("mode".to_owned(), mode.to_owned())];
    if mode == "locked" {
        let ids: Vec<&str> = users.iter().map(|u| u.user_id.as_str()).collect();
        // The daemon's writer refuses a control character in a name; a file
        // edited by hand is not that writer, so the separator is kept safe here
        // too rather than trusted to be.
        let names: Vec<String> = users
            .iter()
            .map(|u| {
                u.display_name
                    .as_deref()
                    .unwrap_or("")
                    .chars()
                    .filter(|c| !c.is_control())
                    .collect()
            })
            .collect();
        args.push(("users".to_owned(), ids.join(",")));
        args.push(("names".to_owned(), names.join(NAMES_SEPARATOR)));
    }
    args
}

/// What separates the entries of the `names` launch argument: the unit
/// separator, a control character, which `normalize_display_name` on the
/// daemon's side refuses in a name. The same shape as `users` and `,`.
pub const NAMES_SEPARATOR: &str = "\u{1f}";

/// Launch a WASM app.
///
/// Loads the WASM module from disk, rebuilds the sandbox with all host
/// bindings wired, and calls the `on_launch` export. An instance of `app_id`
/// that is already live is ended first ([`launch_instance`]).
#[allow(clippy::too_many_arguments)]
pub async fn app_launch(
    host: &dyn AppHost,
    user_db: &Arc<SqlitePool>,
    base: &Path,
    live_instances: Arc<tokio::sync::Mutex<HashMap<String, LongLivedInstance>>>,
    app_id: String,
    launch_args: Vec<(String, String)>,
    user_id: Option<String>,
    // The pre-auth verbs, for the one app the user designated `shell`; `None`
    // for every other app, and for a caller with no identity authority to lend.
    // Passing `Some` is what makes an auth call serviceable at all — see
    // `OccupantHost`.
    occupant: Option<&dyn OccupantHost>,
    infer: Option<&dyn InferHost>,
    records: Option<&dyn RecordsHost>,
) -> io::Result<UserResponse> {
    // Not awaited here: `launch_instance` awaits it after the prior instance is
    // gone, and nothing in it runs before then.
    let prepared = prepare_launch(host, user_db, base, app_id.clone(), launch_args, user_id);
    launch_instance(host, live_instances, app_id, prepared, occupant, infer, records).await
}

/// **Every launch's one path**: end the instance of `app_id` that is live, then
/// prepare the new one, then start it.
///
/// [`app_launch`] and [`app_launch_system_shell`] both come through here, and
/// nothing else reaches [`spawn_and_present`]. So a client's `AppLaunch`, the
/// daemon starting the shell the person designated (or the system shell), and
/// another app's `apps.launch` all replace a running instance the same way:
/// its `on-terminate` is called and every surface it held is closed, through
/// [`teardown_live_instance`]. `live_instances` holds one instance per app id,
/// so a launch that stored its instance without this would drop the old one
/// from the map unended: no `on-terminate`, and windows left open with nothing
/// behind them.
///
/// **Replace, not focus.** Focusing the window already open is a
/// window-manager act nothing in the daemon performs, so a second launch is a
/// fresh instance with its own surface, the arguments it was given and the
/// grants it was prepared with, and the first one ends.
///
/// **The teardown is first, and the order is the point.** `prepare` is a
/// future, so nothing it does has happened until it is awaited below:
///
/// - `on-terminate` is the app's moment to write what it holds (the export's
///   own doc says so), and the new instance reads the same app data when it
///   starts. Ending the old one after the new one had read would hand the new
///   one what the old one had not yet written.
/// - [`prepare_launch`] mints the grant on a file the person picked, a
///   `while_open` grant, and consumes one use of each `Uses` grant. Those
///   belong to the new instance, so the old one is gone before they exist, and
///   whatever ends with the old instance cannot take the new one's with it.
///
/// The cost is the one `replace_the_screen` already names: a launch that then
/// fails leaves nothing of `app_id` running, and between the two instances
/// there is a moment with neither on screen.
#[allow(clippy::too_many_arguments)]
async fn launch_instance(
    host: &dyn AppHost,
    live_instances: Arc<tokio::sync::Mutex<HashMap<String, LongLivedInstance>>>,
    app_id: String,
    prepare: impl std::future::Future<Output = io::Result<PreparedLaunch>>,
    occupant: Option<&dyn OccupantHost>,
    infer: Option<&dyn InferHost>,
    records: Option<&dyn RecordsHost>,
) -> io::Result<UserResponse> {
    if teardown_live_instance(host, &live_instances, &app_id).await {
        tracing::info!(%app_id, "ended the live instance before launching it again");
    }
    match prepare.await? {
        PreparedLaunch::Answered(response) => Ok(response),
        PreparedLaunch::Run {
            title,
            kind,
            input,
            user_id,
            launch_args,
        } => {
            spawn_and_present(
                host,
                live_instances,
                app_id,
                title,
                kind,
                *input,
                user_id,
                occupant,
                infer,
                records,
                launch_args,
            )
            .await
        }
    }
}

/// What a launch decided before it spawned anything: [`prepare_launch`]'s
/// answer for [`app_launch`], and [`app_launch_system_shell`]'s own.
///
/// It names no app: [`launch_instance`] holds the one `app_id`, the one its
/// teardown ended and its spawn starts.
///
/// Split from the spawn so that what the runner is handed can be read without
/// running one. The runner is spawned confined (`confine_runner`), and a test
/// double that is a shell script cannot start there — its interpreter is
/// outside the profile, as it should be — so the one test that read the init
/// frame back off a script's stdin reads this instead. Same value, one step
/// earlier: nothing between here and the pipe changes it.
enum PreparedLaunch {
    /// Answered without a runner — a bundle-only app, whose window the host
    /// opens from the launch event.
    Answered(UserResponse),
    /// The runner to spawn, and everything [`spawn_and_present`] needs for it.
    Run {
        title: String,
        kind: AppKind,
        // Boxed because it is most of the variant's size, and the other
        // variant is a small answer.
        input: Box<RunnerInput>,
        user_id: Option<String>,
        launch_args: Vec<(String, String)>,
    },
}

/// Everything [`app_launch`] does before the spawn: resolve the body, mint the
/// picked file's grant, consume `Uses` grants, and build the [`RunnerInput`].
async fn prepare_launch(
    host: &dyn AppHost,
    user_db: &Arc<SqlitePool>,
    base: &Path,
    app_id: String,
    launch_args: Vec<(String, String)>,
    user_id: Option<String>,
) -> io::Result<PreparedLaunch> {
    // Resolve the WASM path from the app registry.
    let registry_wasm_path = ardb::get_wasm_path(user_db, &app_id)
        .await?
        .ok_or_else(|| io::Error::other(format!("app not found: {app_id}")))?;

    // The person's own `app_roles` designation, read **once** and used twice: here,
    // to resolve the shell's body, and below to set `RunnerInput::occupant`. Two
    // readings of one row is how the welcome screen and the lock screen came to
    // disagree about which one they were (see `push_shell_mode`).
    let designated = is_occupant(user_db, &app_id).await;

    // Who this launch is for, as the host can vouch for it — before the mount,
    // the identity args and the roots are computed from the answer.
    let (user_id, keys_not_loaded) = a_person_whose_keys_are_loaded(host, user_id);

    // **The designated shell is one artifact.** Its body is the copy the system
    // staged, on this path as on the pre-identity one — not the second copy the
    // registry took at install and never rewrote. Everything else the registry row
    // holds for this app (the approval, the envelopes, the designation) is read
    // below exactly as before; what it no longer answers is *which program*.
    // See [`designated_shell_body`].
    let staged_shell = designated_shell_body(base, &app_id, designated).await;
    let wasm_path = match &staged_shell {
        Some((wasm, _)) => wasm.clone(),
        None => registry_wasm_path,
    };

    // Bundle-only apps (kind = "ui") have an empty wasm_path.  For these
    // the daemon has no WASM to run — it just emits the launch event so the
    // host can open the window reactively.
    //
    // **No `path` is announced.** The hand-off below mints a grant bound to a
    // running instance and names the file against the handle the sandbox makes
    // of it; a bundle has neither, so there is nothing to hand over and no
    // instance whose end would end the grant. A `path` left in the event would
    // be the person's path with no grant behind it, which is what the no-identity
    // branch below drops for the same reason.
    if wasm_path.is_empty() {
        let mut launch_args = launch_args;
        launch_args.retain(|(k, _)| k != PICKED_FILE_ARG);
        let _ = host.events().publish(
            Event::with_payload(
                EventCategory::WASM,
                EventLevel::Info,
                format!("App launched: {app_id}"),
                serde_json::json!({ "app_id": &app_id, "launch_args": launch_args }),
            )
            .in_scope(EventScope::of(user_id.as_deref())),
        );
        return Ok(PreparedLaunch::Answered(UserResponse::AppLaunched {
            app_id,
            patches: vec![],
        }));
    }

    // Read the manifest TOML from disk — from beside the body that is about to run,
    // which for the designated shell is the staged one. A manifest read from one copy
    // while the other runs would be the same two-bodies defect wearing a different
    // hat: the runner is told what the app declares, and it has to be what this
    // binary declares.
    let manifest_path = match staged_shell {
        Some((_, manifest)) => manifest,
        None => manifest_path_for(base, &app_id),
    };
    let manifest_toml = fs::read_to_string(&manifest_path).await?;
    let manifest = AppManifest::from_toml(&manifest_toml)
        .map_err(|e| io::Error::other(format!("parse manifest for {app_id}: {e}")))?;

    // Per-app data DB path (runner opens it).
    // Per-app record isolation is this line: the host derives the path from the
    // app id it resolved, and the guest never names it. Not encrypted at rest —
    // `open_app_data_pool` in `kotton-wasm` carries the full caveat.
    let app_data_path = base
        .join("app_data")
        .join(format!("{app_id}.db"))
        .to_string_lossy()
        .into_owned();

    // What the user approved at install. Not `manifest.capabilities` — that is
    // what the app asked for, and reading the request as the grant is the defect
    // TASK-the-approval-is-signed-but-not-enforced was filed for. A row with no
    // recorded approval yields nothing, which is the safe direction: the app
    // launches and can reach none of the user's data until it is approved.
    let approved = approved_for(user_db, &app_id).await;

    // Grants issued before `app_id` entered the signed body name no app, and
    // `check_grant` refuses them (`DEC-0052`, Article IV). Re-mint them here so
    // an existing install does not silently lose every capability it was granted.
    //
    // **From the approval, not from the old envelope.** The unsigned
    // `app_grant_envelopes.app_id` column is the thing being taken out of the
    // trust path; re-signing it would launder it into the signature and keep
    // exactly the property this change removes. `approved` above is the record of
    // what the person actually agreed to, which is what a grant is supposed to
    // say — so the unbound envelopes are dropped and one is minted afresh from
    // consent. An app with no recorded approval gets nothing, which is the safe
    // direction and the same one `approved_for` already takes.
    if let Some(uid) = user_id.as_deref() {
        rebind_legacy_envelopes(user_db, base, uid, &app_id, &approved, host.secrets()).await;
    }

    // **The file the person picked**, if this launch carries one. Before the
    // envelopes are read below, because the grant this mints has to be in the
    // set the instance is started with — the sandbox mints its handles from
    // that set once, at instantiation.
    //
    // A `path` only reaches here from the occupant or from an operator at the
    // terminal; [`guest_launch_args`] is where every other caller's is dropped.
    // `launch_args` is shadowed here rather than lower down so there is one
    // mutable list and not two.
    let mut launch_args = launch_args;
    if let Some(uid) = user_id.as_deref() {
        let tree = host.personal_tree(uid);
        hand_over_picked_file(
            user_db,
            base,
            uid,
            &app_id,
            &mut launch_args,
            host.secrets(),
            tree.as_deref(),
        )
        .await;
    } else {
        // No identity, no VFS, nothing to hand over — and a `path` left in the
        // list would be a name with no grant behind it.
        launch_args.retain(|(k, _)| k != PICKED_FILE_ARG);
    }

    // Load grant enforcement snapshots from the daemon DB.
    let envelopes = grant_db::get_envelopes_for_app(user_db, &app_id)
        .await
        .unwrap_or_default();
    let revoked_ids = {
        let mut set = std::collections::HashSet::new();
        for env in &envelopes {
            if grant_db::is_revoked(user_db, &env.id)
                .await
                .unwrap_or(false)
            {
                set.insert(env.id.clone());
            }
        }
        // A launch is an **activation**: consume one use of every `Uses` grant
        // now, atomically, and deny any already spent. `consume_use` revokes the
        // envelope as it takes the last use, so the *next* launch finds it in the
        // revocation check above — the "allow once" the consent standard asks for
        // (TASK-a-grant-cannot-be-once-or-while-open). `while_open` grants are not
        // consumed here; they end at teardown.
        for env in &envelopes {
            if matches!(grant_db::lifetime_kind(user_db, &env.id).await, Ok(Some(ref k)) if k == "uses")
                && !grant_db::consume_use(user_db, &env.id)
                    .await
                    .unwrap_or(false)
            {
                set.insert(env.id.clone());
            }
        }
        set
    };
    let trusted_issuers: std::collections::HashSet<String> =
        grant_db::list_trusted_issuers(user_db)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();

    // Whose tree this launch is for. It names the person; the runner opens
    // nothing there — its files are asked of the daemon, which answers from
    // the sealed store (`service_files_call`) — and its kernel profile does not
    // reach it (`runner_profile`).
    let user_vfs_path = user_id.as_deref().map(|uid| {
        base.join("users")
            .join(uid)
            .join("data")
            .to_string_lossy()
            .into_owned()
    });

    // Inject identity args — DID and display_name — so apps don't need to
    // call back into the daemon just to know who they're running as.
    //
    // `display_name` is the name the person goes by on this device, read from
    // the registry the host holds, and it is **absent when they have not said**:
    // until 2026-09-24 this line wrote the user id here, which is how the
    // desktop called the person `owner` after asking their name. The id is
    // never drawn; a shell handed no name draws its own fallback
    // (`TASK-the-name-the-welcome-asks-for-goes-nowhere`).
    if let Some(uid) = &user_id {
        if !launch_args.iter().any(|(k, _)| k == "display_name") {
            let name = host
                .registered_users()
                .into_iter()
                .find(|u| &u.user_id == uid)
                .and_then(|u| u.display_name);
            if let Some(name) = name {
                launch_args.push(("display_name".to_owned(), name));
            }
        }
        if !launch_args.iter().any(|(k, _)| k == "did") {
            // The app learns its identity as the user's root did:kel AID (RFC-0038 8c).
            if let Some(did) = user_root_did(base, uid) {
                launch_args.push(("did".to_owned(), did.to_string()));
            }
        }
    }

    // **The screen keys are the shell's.** `mode`, and on the lock screen the
    // `users` it unlocks and the `names` it greets them by, are written into
    // the launch of the app the person designated their shell and into no
    // other: that app draws the screen, and no other app reads the keys. The
    // same `designated` that chose the body above and the world below decides
    // it, so the app handed the roster is the app instantiated with the
    // `auth` interface that unlocks it. See [`push_shell_mode`].
    if designated {
        push_shell_mode(&mut launch_args, user_id.is_some(), host);
    }
    // And, where the launch was for a person whose keys are not loaded, the one
    // sentence the lock screen shows above the passphrase field. Absent-only
    // like `mode`: this key is host-authored and `guest_launch_args` drops a
    // guest's.
    if keys_not_loaded.is_some() && !launch_args.iter().any(|(k, _)| k == NOTICE_ARG) {
        launch_args.push((NOTICE_ARG.to_owned(), KEYS_NOT_LOADED_NOTICE.to_owned()));
    }

    let input = RunnerInput {
        manifest_toml,
        wasm_path,
        app_data_path,
        envelopes,
        approved: approved.clone(),
        revoked_ids: revoked_ids.into_iter().collect(),
        trusted_issuers: trusted_issuers.into_iter().collect(),
        kel_keys: own_kel_keys(base, user_id.as_deref()),
        user_vfs_path,
        // The person's roots (RFC-0071 R11–R16), for the occupant alone —
        // `kotton:app/roots` is in no other world, and the set of a person's
        // roots with their members and their vaults is the map R14 keeps from
        // every provider. Same `designated` that chose the world.
        // `Some` whenever the world is the occupant's, empty if the store could
        // not answer: the interface is the world's promise (see the locked
        // launch below), and a store that cannot list roots is an empty list
        // with a warning, not a component that fails to instantiate.
        roots: designated
            .then(|| match keys_not_loaded {
                // The launch was for a named person and their store is locked:
                // say so, rather than the *nobody* a demoted launch would read as.
                Some(why) => Some(RunnerRoots::Unread(why)),
                None => roots_for_the_occupant(user_roots(host, base, user_id.as_deref())),
            })
            .flatten(),
        // The user's own designation, read once at the top of this function and
        // used again to decide whether a host call from this instance is serviced.
        // An app the user has not designated is instantiated into `world app`,
        // where the `auth` interface does not exist. It is the same `designated`
        // that chose the body above, so the program that runs and the world it
        // runs in answer to one row.
        occupant: designated,
        op: RunnerOp::Launch {
            launch_args: launch_args.clone(),
            // **The daemon mints, and the guest is never asked** (RFC-0087).
            // One handle per launched instance, so a second launch of the same
            // app draws somewhere else — which under `app_id` keying was
            // impossible, because the key was the app's name and two launches
            // were the same string.
            surface: SurfaceHandle::mint(),
        },
    };

    Ok(PreparedLaunch::Run {
        title: manifest.app.name.clone(),
        kind: manifest.kind,
        input: Box::new(input),
        user_id,
        launch_args,
    })
}

/// Where the system shell lives: `system/shell/`, device-scoped.
///
/// Not `apps/<id>/`. That tree is the user's own app collection, indexed by a
/// per-user registry, and before an identity exists there is no user for it to
/// belong to. This is the other kind of thing — code that shipped with the
/// system, readable before anyone has logged in, and never listed as one of a
/// user's apps.
pub fn system_shell_dir(base: &Path) -> PathBuf {
    base.join("system").join("shell")
}

/// The body the **designated shell** runs from: the staged system copy, when the
/// app the person designated is the one the system staged there.
///
/// Returns `(wasm path, manifest path)` inside [`system_shell_dir`], or `None` to
/// leave the caller with whatever the user's app registry says.
///
/// # One artifact, and why this is not a refresh step
///
/// There were two bodies of one program. `system/shell/` is what `cargo xtask
/// build-apps` stages and what [`app_launch_system_shell`] runs for the welcome and
/// the lock screen; `apps/sh.kotton.shell/app.wasm` is what [`app_install`] wrote
/// into the user's collection when their identity was born, and the pass that would
/// rewrite it (`auto_install_bundled_apps`) ran at daemon start over *loaded* users
/// and at identity creation only — never on the unlock that relaunches the shell as
/// the person. So every build reached the welcome and the lock screen, and the desk
/// kept the body from the day the identity was made. Measured 2026-09-21: a desk
/// drawing the previous day's stylesheet, and every on-sight check of a shell-side
/// change since that identity was created looking at it
/// (`TASK-the-drawn-ground-shows-for-a-second-and-the-relaunched-desk-is-flat`).
///
/// **That third gap is narrower since.** `auto_install_bundled_apps` now also runs
/// on the unlock that rebuilds a *keyless* resident store — the shape a real
/// restart-then-unlock takes — so a shell rebuilt between restarts does reach an
/// identity that was locked at boot
/// (`custody_window::rekey_resident_store`,
/// `TASK-an-app-bundled-after-an-identity-was-made-never-reaches-it`). It still does
/// not run on a lock/unlock cycle over a store that stayed resident and keyed the
/// whole time, so a build landing mid-session is the case this section's argument
/// still covers.
///
/// A refresh step is what *two bodies* make necessary. One body, resolved on every
/// path, deletes the step and the class of bug with it. The registry row stays: it is
/// where the approval, the grant envelopes and the designation live, and none of those
/// are bytes. What it stops being is the answer to *which program is the shell*.
///
/// # The designation stays the person's
///
/// `sh.kotton.shell` is the staged shell because it ships as the default, not because
/// we wrote it — "point it at something else and that becomes the desktop"
/// (`RFC-0087`). So this matches the staged manifest's own `app.id` against the app
/// being launched and answers `None` when they differ: a person who designates their
/// own shell runs *their* body, out of *their* registry, and the system's copy is not
/// substituted for it. `designated` is the caller's single reading of `app_roles` —
/// the same one that sets [`RunnerInput::occupant`], so the two cannot disagree about
/// who the shell is.
///
/// # When it answers `None` for the shipped shell
///
/// Only when the system staged nothing: no manifest at that path, or no `app.wasm`
/// beside it. That is a machine that cannot draw a welcome screen either
/// ([`app_launch_system_shell`] refuses on the same two conditions), and the registry
/// copy is then the only body there is. It is not a fallback the stale case can reach —
/// the stale case is a staged copy that is *present and newer*.
async fn designated_shell_body(
    base: &Path,
    app_id: &str,
    designated: bool,
) -> Option<(String, PathBuf)> {
    if !designated {
        return None;
    }
    let dir = system_shell_dir(base);
    let manifest_path = dir.join("manifest.toml");
    let manifest_toml = fs::read_to_string(&manifest_path).await.ok()?;
    let staged_id = AppManifest::from_toml(&manifest_toml)
        .ok()?
        .app_id()
        .to_owned();
    if staged_id != app_id {
        return None;
    }
    let wasm_path = dir.join("app.wasm");
    if !wasm_path.exists() {
        return None;
    }
    Some((wasm_path.to_string_lossy().into_owned(), manifest_path))
}

/// Launch the system shell for a machine that has **no user loaded** — the
/// welcome screen before anybody exists, and the unlock screen every day after.
///
/// # Why this exists rather than a `None` on [`app_launch`]
///
/// `app_launch` resolves everything it needs from the **user's** database: the
/// wasm path from their app registry, grants from their envelope table, and the
/// occupant designation from their `app_roles`. A machine with no user loaded
/// can read none of those — a fresh one has no user, and a locked one has a
/// database that will not open (`DEC-0049`) — and threading `Option` through
/// each would leave one function whose meaning depends on which arguments
/// happen to be `Some`, including the one that decides whether a guest gets the
/// identity-minting interface.
///
/// So this is a separate, deliberately small path with fixed answers:
///
/// | | `app_launch` | here |
/// |---|---|---|
/// | what to run | user's app registry | `system/shell/`, a fixed path |
/// | grants | the user's envelopes | **none** |
/// | VFS root | the user's data mount | **none** |
/// | `world occupant` | the user's `app_roles` designation | **yes, unconditionally** |
///
/// **`mode` is not in that table, and used to be.** Which screen the shell opens
/// on is read from the device registry here exactly as it is in `app_launch` —
/// see [`push_shell_mode`], which holds the one copy of that rule and the record
/// of what writing it twice cost.
///
/// # The one that matters
///
/// This grants `world occupant` — the `auth` interface, `create-identity` and
/// `unlock` — with no designation behind it, because there is nobody *loaded*
/// whose designation could be consulted. That is only defensible for code the
/// system itself shipped, at a path a user's app can never be installed to, and
/// for exactly one app. All three hold here: the directory is fixed, nothing
/// writes it at runtime, and there is no `app_id` parameter to point somewhere
/// else.
///
/// **The seam, and where it is enforced.** The moment a user is loaded, their
/// `app_roles` designation is authoritative and this path must never be taken
/// again. `resident_user` is how that is checked *here*, in the function that
/// grants the authority, rather than only at the call site that happens to know
/// the answer: a caller passes what it knows about who is resident, and passing
/// `Some` is refused.
///
/// **Residency is the right test for that seam, and the registry is not.** A
/// designation lives in a user's own database; a user who is registered but not
/// loaded has one that cannot be read, so there is nothing for this path to
/// defer to and refusing would leave them with no window at all — which is what
/// happened for three weeks (`TASK-a-locked-identity-cannot-be-unlocked-from-the-window`).
/// The registry decides the *screen*, residency decides the *authority*, and the
/// one verb that could do damage with this authority guards itself against the
/// registry: `create_identity` refuses outright once anybody is registered.
///
/// The check could have lived in `launch_designated_shell` alone — it does read
/// the registry first — but then the one function in the system that hands out
/// `world occupant` with no designation behind it would be relying on every
/// future caller to remember why. A guard belongs with the power it guards.
pub async fn app_launch_system_shell(
    host: &dyn AppHost,
    base: &Path,
    live_instances: Arc<tokio::sync::Mutex<HashMap<String, LongLivedInstance>>>,
    occupant: Option<&dyn OccupantHost>,
    infer: Option<&dyn InferHost>,
    records: Option<&dyn RecordsHost>,
    // Whoever is resident, as the caller understands it. `Some` is a refusal:
    // a machine with a user has a designation to consult, and consulting it is
    // `app_launch`'s job.
    resident_user: Option<&str>,
) -> io::Result<UserResponse> {
    if let Some(uid) = resident_user {
        return Err(io::Error::other(format!(
            "refusing to launch the system shell: user `{uid}` is resident, so their \
             `app_roles` designation decides what the shell is. This path grants the \
             identity-minting interface with no designation behind it and exists only \
             for a machine that has none."
        )));
    }

    let dir = system_shell_dir(base);
    let manifest_toml = fs::read_to_string(dir.join("manifest.toml"))
        .await
        .map_err(|e| {
            io::Error::other(format!(
                "no system shell at {}: {e} — a fresh machine has nothing to draw. \
                 `cargo xtask build-apps` stages it; a packaged install ships it.",
                dir.display()
            ))
        })?;
    let manifest = AppManifest::from_toml(&manifest_toml)
        .map_err(|e| io::Error::other(format!("parse system shell manifest: {e}")))?;

    let wasm_path = dir.join("app.wasm");
    if !wasm_path.exists() {
        return Err(io::Error::other(format!(
            "system shell manifest at {} has no app.wasm beside it",
            dir.display()
        )));
    }
    let app_id = manifest.app.id.to_string();

    // The pre-auth system shell is launched from a directory on disk, before any
    // user exists to have approved anything — there is no registry row to read.
    // Its capabilities are the ones the system shipped it with, which is exactly
    // what `ConsentSource::SystemBundled` names: nobody was at the keyboard, and
    // the review happened when this shell was compiled in. Written out here
    // rather than falling back to the manifest silently, so that the one place
    // the declaration *is* the grant says so out loud.
    let approved: Vec<CapabilityGrant> = manifest.capabilities.iter().cloned().collect();

    // **Which screen this opens on is the registry's answer, not a constant.**
    //
    // *What to run* is fixed here — a directory the system shipped — and that is
    // the whole of what this path decides for itself. *Which screen it opens on*
    // is a different question with a different reader, and until 2026-09-21 this
    // function answered it with the literal `welcome`, twice, once in the frame
    // the runner receives and once in the record the daemon keeps.
    //
    // It is reached with a registered identity on this device every time a
    // person starts the daemon a second day: their account is loaded and locked,
    // their database will not open, and a locked account is sent here on purpose
    // because this path needs no database. So the second boot drew the first
    // boot's screen. See [`push_shell_mode`] for the whole of it.
    //
    // No session, always. Not because there is no user — there may well be one,
    // loaded and locked — but because a session is what an unlock produces, and
    // this path is only reached when no database opened.
    let mut launch_args: Vec<(String, String)> = Vec::new();
    push_shell_mode(&mut launch_args, false, host);

    let input = RunnerInput {
        approved,
        manifest_toml,
        wasm_path: wasm_path.to_string_lossy().into_owned(),
        // Device-scoped, like the shell itself. A per-user app_data path would
        // name a user who does not exist.
        app_data_path: dir.join("shell.db").to_string_lossy().into_owned(),
        // No grants, and none obtainable: a grant is a user's delegation and
        // there is no user *loaded*. Neither screen this path draws needs one —
        // both draw, read keystrokes, and call an `auth` verb (`create-identity`
        // on the welcome, `unlock` on the lock screen), which the occupant world
        // carries rather than a capability a grant confers.
        envelopes: vec![],
        revoked_ids: vec![],
        trusted_issuers: vec![],
        kel_keys: vec![],
        // No user, so no user data mount. The shell cannot read files here, and
        // there are none of anybody's to read.
        user_vfs_path: None,
        // **Unread, for nobody — not `None`, and not an empty set.** A root is
        // a person's and there is no person loaded, so there is no index to
        // read — but the *interface* is the occupant world's promise, and this
        // launch instantiates into that world. `None` here left
        // `kotton:app/roots` out of the linker, and the day the shell first
        // imported it (the drawn file browser, 2026-09-21) the lock screen
        // failed to instantiate on every boot: *component imports instance
        // `kotton:app/roots`, but a matching implementation was not found*.
        // The world decides which interfaces exist; a launch into it supplies
        // every one. It answered *nothing yet* with an empty set until
        // 2026-09-24, which is the same value as *a person with no roots*
        // (`TASK-a-roots-failure-is-drawn-as-no-roots`); it now says which.
        roots: roots_for_the_occupant(Err(RootsUnread::Nobody)),
        occupant: true,
        op: RunnerOp::Launch {
            launch_args: launch_args.clone(),
            // The pre-identity shell gets a minted surface like anything else.
            // It is the *first* screen anyone ever sees, and the one place the
            // whole handle path has to work before a user exists.
            surface: SurfaceHandle::mint(),
        },
    };

    // Named rather than "no identity yet", which was a guess this function is
    // not entitled to make: it knows no user is *loaded*, and the registry is
    // what knows whether one exists.
    let mode = launch_args
        .iter()
        .find(|(k, _)| k == "mode")
        .map(|(_, v)| v.as_str())
        .unwrap_or("welcome");
    tracing::info!(
        %app_id, %mode, dir = %dir.display(),
        "launching the system shell — no user is loaded"
    );

    // Built above rather than inside the future: nothing in it mints, consumes
    // or starts anything, so it is the same value before the teardown as after.
    let prepared = PreparedLaunch::Run {
        title: manifest.app.name.clone(),
        kind: manifest.kind,
        input: Box::new(input),
        user_id: None,
        launch_args,
    };
    launch_instance(
        host,
        live_instances,
        app_id,
        std::future::ready(Ok(prepared)),
        occupant,
        infer,
        records,
    )
    .await
}

/// Spawn a runner for `input`, then open and paint its surface.
///
/// Shared by [`app_launch`] and [`app_launch_system_shell`], and reached only
/// through [`launch_instance`], which has ended any instance of `app_id` that
/// was live before this stores the new one. The two differ
/// entirely in how they *resolve* what to run — a user's app registry versus a
/// device-scoped system directory — and not at all in what happens once a
/// `RunnerInput` exists. Extracted when the second caller appeared, rather than
/// copied, because the copy is where the pre-identity path would quietly stop
/// getting fixes the normal one got.
#[allow(clippy::too_many_arguments)]
async fn spawn_and_present(
    host: &dyn AppHost,
    live_instances: Arc<tokio::sync::Mutex<HashMap<String, LongLivedInstance>>>,
    app_id: String,
    // The name the host shows in the window frame: `manifest.app.name`.
    //
    // Passed rather than re-parsed from `input.manifest_toml`, and passed rather than
    // defaulted to `app_id`, because the frame is the one attribution a guest cannot write
    // and it should therefore read as a person would say it — "Editor", not
    // "sh.kotton.editor". Its provenance matters as much as its wording: the manifest is
    // what the install prompt showed and the person approved.
    title: String,
    kind: AppKind,
    input: RunnerInput,
    user_id: Option<String>,
    occupant: Option<&dyn OccupantHost>,
    infer: Option<&dyn InferHost>,
    records: Option<&dyn RecordsHost>,
    launch_args: Vec<(String, String)>,
) -> io::Result<UserResponse> {
    // ── The surface this instance draws on ────────────────────────────────────
    //
    // **The daemon minted it, once, for this instance** (RFC-0087) — in the
    // resolver that built `input`, beside the `RunnerOp::Launch` it belongs to.
    // Read back off the op here rather than passed a second time, so there is
    // one copy and nothing to disagree with: the frame that starts the runner
    // and the `SurfaceOpen` that tells `kuid` about it name the same value
    // because it is the same value. `spawn_long_lived_runner` reads it from the
    // same place for the same reason.
    //
    // The guest is not asked and cannot choose. `on-launch` receives what was
    // minted, as a resource, and the only thing it can do with it is hold it.
    let handle = match &input.op {
        RunnerOp::Launch { surface, .. } => *surface,
        other => {
            return Err(io::Error::other(format!(
                "spawn_and_present: expected a launch op, got {}",
                serde_json::to_string(other).unwrap_or_else(|_| "?".into())
            )))
        }
    };

    // What it opens as, from the one designation the launch already read.
    // `input.occupant` is the person's own `app_roles` row — the same row that
    // decides `world occupant` — so the desktop is the app they designated
    // rather than a constant compiled into the display server, which is where
    // that decision lived until RFC-0087 took the app id off the compositor
    // wire and left `kuid` nothing to compare.
    //
    // **The seam RFC-0087 leaves open**: it says a greeter and a desktop should
    // eventually be separate rows, because they are separable the way `gdm` and
    // `gnome-shell` are. Today there is one row and this reads it; when the row
    // splits, this is the line that chooses between them.
    //
    // **`Background`, not a fourth "system" role.** The designated app's launch
    // surface *is* the screen's base — the document `kuid` paints first, below
    // every composited layer — which is precisely what `Background` means. Stage
    // 1 called this `SurfaceTier::System` because stage 1 had no roles yet; the
    // behaviour is unchanged and only the word is.
    let role = if input.occupant {
        SurfaceRole::Background
    } else {
        SurfaceRole::Window
    };

    // **Opened before the runner starts, not after it answers.**
    //
    // It was after, and that was right while the only thing a launch produced
    // was patches. It stopped being right when a guest could ask for a *second*
    // surface during `on-launch`: that ask is serviced inside the init exchange,
    // so the surface the guest asked for was opened on the compositor before the
    // one it was launched with — a window arriving before the screen it sits on.
    //
    // The handle has been known since the resolver minted it, so there was never
    // anything to wait for. The cost is that a launch which then fails has a
    // surface to take back down, and **who takes it down depends on how far the
    // launch got**:
    //
    // - `spawn_long_lived_runner` returning `Err` has already closed this handle
    //   *and* every surface the guest asked for while its init frame was being
    //   serviced. It is the only party that knows the second list, so it owns
    //   both; closing here as well would be a second close of a handle that is
    //   already gone.
    // - Everything else on this path — the one-shot spawn, and a launch that
    //   answered with something other than `Launched` — is closed below, where
    //   this handle is the only one open.
    // No edge: a launch surface is either the screen's base or an ordinary window, and
    // neither hangs from a side. A `Panel` is only ever asked for, never launched into.
    host.surface_open(
        handle,
        &app_id,
        kotton_wire::SurfaceSpec {
            role,
            edge: None,
            title: title.clone(),
            width: 1200,
            height: 800,
        },
    )
    .await;

    // Long-lived apps keep a persistent runner process alive so subsequent
    // input events and messages can be delivered to the same instance.  The
    // launch op is the init frame, so its `Launched` patches come back directly.
    let runner_out = if kind == AppKind::LongLived {
        let spawned = spawn_long_lived_runner(
            host,
            &app_id,
            &title,
            input,
            user_id.as_deref(),
            occupant,
            infer,
            records,
        )
        .await
        .inspect_err(|e| {
            let _ = host.events().publish(
                Event::with_payload(
                    EventCategory::WASM,
                    EventLevel::Error,
                    format!("App launch error: {app_id}"),
                    serde_json::json!({ "app_id": &app_id, "error": e.to_string() }),
                )
                .in_scope(EventScope::of(user_id.as_deref())),
            );
        });
        let (instance, init_output) = match spawned {
            Ok(v) => v,
            // Nothing to close: see the note at `surface_open` above. The callee
            // hands back an error only after closing everything the instance
            // held, which is more than this function can name.
            Err(e) => return Err(e),
        };
        // `launch_instance` ended whatever of `app_id` was live when this launch
        // began. Two launches of one app in flight at once can still meet here,
        // the later storing over the earlier: the map is keyed by app id, not by
        // instance.
        live_instances.lock().await.insert(app_id.clone(), instance);
        init_output
    } else {
        match spawn_runner(host.runner(), input).await.inspect_err(|e| {
            let _ = host.events().publish(
                Event::with_payload(
                    EventCategory::WASM,
                    EventLevel::Error,
                    format!("App launch error: {app_id}"),
                    serde_json::json!({ "app_id": &app_id, "error": e.to_string() }),
                )
                .in_scope(EventScope::of(user_id.as_deref())),
            );
        }) {
            Ok(v) => v,
            Err(e) => {
                host.surface_close(handle).await;
                return Err(e);
            }
        }
    };

    match runner_out {
        // `launches` from a guest's own `on-launch` are intentionally ignored
        // here: relaunching at startup risks a self-relaunch loop while surfaces
        // are still keyed by app_id (no instance id yet). Guest-initiated launch
        // is driven from interactive handlers (input/message) instead.
        RunnerOutput::Launched {
            patches, raises, ..
        } => {
            let _ = host.events().publish(
                Event::with_payload(
                    EventCategory::WASM,
                    EventLevel::Info,
                    format!("App launched: {app_id}"),
                    serde_json::json!({ "app_id": &app_id, "launch_args": launch_args }),
                )
                .in_scope(EventScope::of(user_id.as_deref())),
            );
            tracing::info!(%app_id, surface = %handle, patch_count = patches.len(), "app launched");
            // **Each patch goes to the surface it names**, not to "the
            // instance's surface". At launch there is one and they are the same
            // value; writing it this way is what makes a second surface an
            // addition rather than a rewrite (RFC-0087, stage 2).
            for p in &patches {
                host.surface_commit(p.surface, p.patch.clone()).await;
            }
            for raised in raises {
                host.surface_raise(raised).await;
            }
            Ok(UserResponse::AppLaunched {
                app_id,
                patches: bare_patches(&patches),
            })
        }
        RunnerOutput::Error { message } => {
            let _ = host.events().publish(
                Event::with_payload(
                    EventCategory::WASM,
                    EventLevel::Error,
                    format!("App launch error: {app_id}"),
                    serde_json::json!({ "app_id": &app_id, "error": &message }),
                )
                .in_scope(EventScope::of(user_id.as_deref())),
            );
            // Reachable from the **one-shot** spawn only: the long-lived path
            // turns an `Error` init frame into an `Err` return, which the callee
            // has already cleaned up after. A one-shot runner opened no surfaces
            // of its own — it holds no `surface` resource to ask with — so this
            // handle is the whole of what is open.
            abandon_launch(host, &live_instances, &app_id, handle).await;
            Err(io::Error::other(format!("runner: {message}")))
        }
        _ => {
            // A launch op answered with something that is not a launch. Reachable
            // from either path, so this goes through the same teardown: on the
            // long-lived path the instance is already in the map and has to come
            // back out with its surfaces, or the person is left with windows for
            // an app that never reported itself launched.
            abandon_launch(host, &live_instances, &app_id, handle).await;
            Err(io::Error::other("unexpected runner output for launch op"))
        }
    }
}

/// Take back a launch that got as far as answering, and could not be used.
///
/// Drops the instance if one was stored — terminating its process — and closes
/// every surface it held, falling back to the launch handle when there is no
/// instance to read a list off (the one-shot path, where there never is one).
async fn abandon_launch(
    host: &dyn AppHost,
    live_instances: &Arc<tokio::sync::Mutex<HashMap<String, LongLivedInstance>>>,
    app_id: &str,
    launch_surface: SurfaceHandle,
) {
    if !teardown_live_instance(host, live_instances, app_id).await {
        host.surface_close(launch_surface).await;
    }
}

/// What the host instantiated a live instance into — the two facts a caller
/// needs before it replaces the screen somebody is looking at.
///
/// Read together rather than as two queries, because they are one reading of
/// one instance and a caller that asked twice could be told about two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceWorld {
    /// `world occupant`: the app the person designated `shell`, the only one
    /// whose linker carries the `auth` interface. [`LongLivedInstance::designated`].
    pub occupant: bool,
    /// Whether the launch handed it the person's data mount.
    pub mounted: bool,
}

/// What the live instance of `app_id` was launched into, or `None` if nothing
/// of `app_id` is live.
///
/// **The question is about the instance, never about the app id.** An app id is
/// a name; two launches of it are two worlds, and the one that matters is the
/// one the event in hand was delivered to. `None` is not `false`: it says there
/// is no instance to have an opinion about, which is what a caller sees when an
/// exchange dropped the instance it was talking to.
pub async fn instance_world(
    live_instances: &Arc<tokio::sync::Mutex<HashMap<String, LongLivedInstance>>>,
    app_id: &str,
) -> Option<InstanceWorld> {
    live_instances
        .lock()
        .await
        .get(app_id)
        .map(|instance| InstanceWorld {
            occupant: instance.designated,
            mounted: instance.user_vfs_path.is_some(),
        })
}

/// End the live instance of `app_id`: kill its process and close every surface
/// it held. `true` if there was one.
///
/// **The one teardown, so a relaunch cannot diverge from an abandonment.** Every
/// launch ends the instance it replaces here ([`launch_instance`]), a launch that
/// had to be taken back ends here ([`abandon_launch`]), and so does the occupant
/// world when the resident shell replaces it. Three copies of *what it means for
/// an instance to stop* is how one of them comes to close the first surface
/// instead of all of them.
///
/// Its own surfaces, not "the app's": a relaunch mints a new handle, and closing
/// by app id would have been ambiguous the moment an app could hold two — which
/// it now can (RFC-0087), so this closes every one the instance held rather than
/// the first. A surface left open for a process that is gone is a window nothing
/// can draw in and nothing can close.
///
/// The map lock is released before the teardown is awaited, so a caller that
/// relaunches on the same id does not hold it across a process kill.
pub async fn teardown_live_instance(
    host: &dyn AppHost,
    live_instances: &Arc<tokio::sync::Mutex<HashMap<String, LongLivedInstance>>>,
    app_id: &str,
) -> bool {
    let prior = live_instances.lock().await.remove(app_id);
    let Some(mut instance) = prior else {
        return false;
    };
    let surfaces = std::mem::take(&mut instance.surfaces);
    terminate_long_lived_instance(&mut instance).await;
    for handle in surfaces {
        host.surface_close(handle).await;
    }
    true
}

/// The launch arguments a *guest-requested* launch may carry.
///
/// **The confined thing names what it wants; the host writes what actually
/// happens** (`CLAUDE.md`, the pen principle). A guest asking for another app
/// to be opened may say what to open it *on* — a `path`, a file in the
/// person's own tree, which the launched app is handed as the file's name —
/// and may not say anything about who that app is running as or which screen
/// it opens on. Those keys are the host's, written
/// in [`app_launch`] from the daemon's own knowledge of the session.
///
/// It matters because [`app_launch`] writes `did`, `display_name` and `notice`,
/// and into the designated shell's launch `mode`, only when they are *absent*
/// (`if !launch_args.iter().any(|(k, _)| k == "mode")`), and the shell's `users`
/// and `names` beside whatever is there, which is right for the
/// operator typing `kotton app launch` and wrong for a confined caller: a guest
/// that could pass `mode=welcome` would put the first-run screen in front of a
/// person who already has an identity, and one that could pass `did=` would
/// tell another app it is somebody else. This is the one place a guest's words
/// enter that list, so it is the one place that has to refuse them.
///
/// Dropped rather than rejected: the launch is the person's, the extra key is
/// the caller's, and refusing the whole launch would let a guest deny a person
/// their own editor by asking wrongly.
///
/// # `path` is the occupant's word, and nobody else's
///
/// Since `TASK-a-file-the-person-opens-is-handed-to-the-app-that-opens-it`, a
/// `path` that survives this function is not a hint — it is a **grant**:
/// [`hand_over_picked_file`] mints the launched app a while-open capability on
/// that one file. So the key is taken only from the app the person designated
/// their shell, whose surface is where the person picked the file. From any
/// other guest it is dropped here.
///
/// **Stripped here rather than refused at the mint**, and the choice matters
/// enough to state. Both would stop a confined app minting itself a
/// capability. Stripping is the one that also stops the *other* thing a
/// surviving `path` does: telling another app to open a named file. A mint
/// that refused would still hand the launched app the string, so a confined
/// caller could aim someone else's editor at a file it cannot itself reach and
/// watch what came back on screen — a channel with no grant behind it. It is
/// also the rule that leaves nothing for the mint to re-decide: wherever a
/// `path` reaches [`app_launch`], it was the person's, so the mint has one
/// condition instead of two that can drift apart. And it matches what this
/// function already does with every other key it refuses — drop, so a bad ask
/// cannot deny the person their launch.
fn guest_launch_args(
    name: Option<String>,
    asked: Vec<(String, String)>,
    from_occupant: bool,
) -> Vec<(String, String)> {
    /// Keys `app_launch` authors from the session. Never taken from a guest.
    const HOST_AUTHORED: [&str; 7] =
        ["name", "mode", "users", "names", "did", "display_name", NOTICE_ARG];

    let mut args: Vec<(String, String)> = Vec::new();
    if let Some(n) = name {
        args.push(("name".to_owned(), n));
    }
    for (k, v) in asked {
        if HOST_AUTHORED.contains(&k.as_str()) {
            tracing::warn!(key = %k, "apps.launch: dropping a host-authored launch argument");
            continue;
        }
        if k == PICKED_FILE_ARG && !from_occupant {
            tracing::warn!(
                "apps.launch: dropping a `path` from a guest that is not the occupant; \
                 only the surface the person picks a file in may hand one over"
            );
            continue;
        }
        args.push((k, v));
    }
    args
}

/// Perform the app launches a guest requested via `apps::launch` during a
/// host→guest call. Called *after* the originating call returns and after the
/// caller has released the `live_instances` lock — [`app_launch`] re-acquires it.
///
/// This is the kuserd half of the guest-launch boundary (compositor/04 Phase 1):
/// a launched app is a *separate* confined guest with *its own* grants, not the
/// caller's. The `apps.launch` capability was already enforced in the runner
/// sandbox before these reached us.
///
/// A target that already has a live instance is replaced, not focused: the
/// launch ends it first, as every launch does ([`launch_instance`]). A
/// self-relaunch therefore ends the caller, after the call that asked has
/// returned.
///
/// `caller_app_id` is **who asked**, and it is read for one thing: whether this
/// caller is the app the person designated their shell. Only that app's launch
/// may carry the file the person picked ([`guest_launch_args`]), because only
/// its surface is the one the person picked it in.
#[allow(clippy::too_many_arguments)]
async fn process_pending_launches(
    host: &dyn AppHost,
    user_db: &Arc<SqlitePool>,
    base: &Path,
    live_instances: &Arc<tokio::sync::Mutex<HashMap<String, LongLivedInstance>>>,
    launches: Vec<kotton_wire::runner::LaunchRequest>,
    caller_app_id: &str,
    user_id: Option<String>,
    // Threaded rather than dropped: `app_launch` sets `RunnerInput::occupant`
    // from the user's `app_roles` designation whatever the caller is, so
    // passing `None` here would instantiate the designated shell into
    // `world occupant` and then refuse the first call it made — a torn state
    // worse than either consistent answer.
    //
    // That a confined app can make the login surface appear at a time of its
    // choosing is a trusted-path question, not an authority one, and it is
    // `IDEA-replaceable-system-ui-needs-two-integrities`'s to answer.
    occupant: Option<&dyn OccupantHost>,
    infer: Option<&dyn InferHost>,
    records: Option<&dyn RecordsHost>,
) {
    let from_occupant = is_occupant(user_db, caller_app_id).await;
    for launch in launches {
        let app_nsid = launch.app_nsid;
        let launch_args = guest_launch_args(launch.name, launch.args, from_occupant);
        tracing::info!(%app_nsid, "apps.launch: launching separate confined guest");
        if let Err(e) = app_launch(
            host,
            user_db,
            base,
            Arc::clone(live_instances),
            app_nsid.clone(),
            launch_args,
            user_id.clone(),
            occupant,
            infer,
            records,
        )
        .await
        {
            tracing::warn!(%app_nsid, error = %e, "apps.launch failed");
        }
    }
}

/// Deliver one string to an app's `on-message` export, unchanged.
///
/// Two callers: the daemon's own ceremony pushes (`push_frame` in
/// `kuserd`'s `agent::ceremony`, for contact pairing and network joining, to
/// the app holding the `shell` role), and a client's `AppMessage`. The
/// window-list nudge does not come through here; see [`app_windows_changed`].
///
/// If the app manifest declares `kind = "long-lived"`, the runner subprocess
/// is kept alive between calls via `live_instances`, and spawned by the first
/// message if it is not running.  Otherwise a fresh subprocess is spawned for
/// each message (one-shot model), whose patch list is always empty.
#[allow(clippy::too_many_arguments)]
pub async fn app_message(
    host: &dyn AppHost,
    user_db: &Arc<SqlitePool>,
    base: &Path,
    live_instances: Arc<tokio::sync::Mutex<HashMap<String, LongLivedInstance>>>,
    app_id: String,
    msg: String,
    user_id: Option<String>,
    // The pre-auth verbs, for the one app the user designated `shell`; `None`
    // for every other app, and for a caller with no identity authority to lend.
    // Passing `Some` is what makes an auth call serviceable at all — see
    // `OccupantHost`.
    occupant: Option<&dyn OccupantHost>,
    infer: Option<&dyn InferHost>,
    records: Option<&dyn RecordsHost>,
) -> io::Result<UserResponse> {
    let wasm_path = ardb::get_wasm_path(user_db, &app_id)
        .await?
        .ok_or_else(|| io::Error::other(format!("app not found: {app_id}")))?;

    let manifest_path = manifest_path_for(base, &app_id);
    let manifest_toml = fs::read_to_string(&manifest_path).await?;

    let manifest = AppManifest::from_toml(&manifest_toml)
        .map_err(|e| io::Error::other(format!("manifest parse: {e}")))?;

    // Per-app record isolation is this line: the host derives the path from the
    // app id it resolved, and the guest never names it. Not encrypted at rest —
    // `open_app_data_pool` in `kotton-wasm` carries the full caveat.
    let app_data_path = base
        .join("app_data")
        .join(format!("{app_id}.db"))
        .to_string_lossy()
        .into_owned();

    let approved = approved_for(user_db, &app_id).await;
    let envelopes = grant_db::get_envelopes_for_app(user_db, &app_id)
        .await
        .unwrap_or_default();
    let revoked_ids = {
        let mut set = std::collections::HashSet::new();
        for env in &envelopes {
            if grant_db::is_revoked(user_db, &env.id)
                .await
                .unwrap_or(false)
            {
                set.insert(env.id.clone());
            }
        }
        set
    };
    let trusted_issuers: std::collections::HashSet<String> =
        grant_db::list_trusted_issuers(user_db)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();

    let user_vfs_path = user_id.as_deref().map(|uid| {
        base.join("users")
            .join(uid)
            .join("data")
            .to_string_lossy()
            .into_owned()
    });

    // ── Long-lived mode ───────────────────────────────────────────────────────
    if manifest.kind == AppKind::LongLived {
        // The name the host draws in the frame of every surface this instance
        // opens — `manifest.app.name`, as the install prompt showed it and the
        // person approved it. Read once here and carried on the instance, so an
        // input handler that asks for a second window does not have to find a
        // manifest to name it with.
        let title = manifest.app.name.clone();
        let mut instances = live_instances.lock().await;

        // Spawn a new long-lived runner if one isn't already running for this app.
        // The init op delivers this same message, so its patches are returned
        // directly and we skip the redundant second send below.
        if !instances.contains_key(&app_id) {
            // **One read of the designation**, for both fields below. They were
            // two reads of the role table, and `runner_profile` grants root
            // trees on `roots` while the world is chosen on `occupant`: a
            // re-designation landing between the reads could send an input whose
            // roots and world disagree. One read makes them one fact
            // (`TASK-a-member-writes-in-a-roots-tree`).
            let designated = is_occupant(user_db, &app_id).await;
            let init_input = RunnerInput {
                approved: approved.clone(),
                manifest_toml: manifest_toml.clone(),
                wasm_path: wasm_path.clone(),
                app_data_path: app_data_path.clone(),
                envelopes: envelopes.clone(),
                revoked_ids: revoked_ids.clone().into_iter().collect(),
                trusted_issuers: trusted_issuers.clone().into_iter().collect(),
                kel_keys: own_kel_keys(base, user_id.as_deref()),
                user_vfs_path: user_vfs_path.clone(),
                roots: if designated {
                    // `Some` for the occupant, always: the interface is the
                    // world's promise, an empty set is the answer when the
                    // store has none (see the launch paths above).
                    roots_for_the_occupant(user_roots(host, base, user_id.as_deref()))
                } else {
                    None
                },
                occupant: designated,
                op: RunnerOp::Message { msg: msg.clone() },
            };
            // `?` and nothing else: an init that failed here has already had its
            // surfaces closed by the callee. This path opens no launch surface of
            // its own — the op is a message, so the handle is minted and never
            // sent to `kuid` — but the guest can still ask for one while its init
            // frame is serviced, and that one is real. Which is why the closing
            // lives with the instance rather than at each call site.
            let (instance, init_output) = spawn_long_lived_runner(
                host,
                &app_id,
                &title,
                init_input,
                user_id.as_deref(),
                occupant,
                infer,
                records,
            )
            .await?;
            instances.insert(app_id.clone(), instance);
            if let RunnerOutput::MessageHandled {
                patches,
                launches,
                raises,
            } = init_output
            {
                for p in &patches {
                    host.surface_commit(p.surface, p.patch.clone()).await;
                }
                for raised in raises {
                    host.surface_raise(raised).await;
                }
                drop(instances);
                if !launches.is_empty() {
                    process_pending_launches(
                        host,
                        user_db,
                        base,
                        &live_instances,
                        launches,
                        &app_id,
                        user_id,
                        occupant,
                        infer,
                        records,
                    )
                    .await;
                }
                return Ok(UserResponse::AppMessageDelivered {
                    patches: bare_patches(&patches),
                });
            }
            return Ok(UserResponse::AppMessageDelivered { patches: vec![] });
        }

        // Take ownership of the instance.  On any I/O error it is dropped
        // without being re-inserted, so the next call triggers a fresh spawn
        // (crash recovery).  On success we re-insert after reading the response.
        let mut instance = instances.remove(&app_id).unwrap();

        let runner_out = exchange(
            &mut instance,
            RunnerOp::Message { msg: msg.clone() },
            host,
            occupant,
            infer,
            records,
        )
        .await?;

        return match runner_out {
            RunnerOutput::MessageHandled {
                patches,
                launches,
                raises,
            } => {
                instances.insert(app_id.clone(), instance);
                for p in &patches {
                    host.surface_commit(p.surface, p.patch.clone()).await;
                }
                for raised in raises {
                    host.surface_raise(raised).await;
                }
                drop(instances);
                if !launches.is_empty() {
                    process_pending_launches(
                        host,
                        user_db,
                        base,
                        &live_instances,
                        launches,
                        &app_id,
                        user_id,
                        occupant,
                        infer,
                        records,
                    )
                    .await;
                }
                Ok(UserResponse::AppMessageDelivered {
                    patches: bare_patches(&patches),
                })
            }
            RunnerOutput::Error { message } => {
                // Not re-inserted; next call will respawn.
                Err(io::Error::other(format!("runner: {message}")))
            }
            _ => Err(io::Error::other("unexpected runner output for message op")),
        };
    }

    // ── One-shot mode (default) ───────────────────────────────────────────────
    let input = RunnerInput {
        manifest_toml,
        wasm_path,
        app_data_path,
        envelopes,
        approved: approved.clone(),
        revoked_ids: revoked_ids.into_iter().collect(),
        trusted_issuers: trusted_issuers.into_iter().collect(),
        kel_keys: own_kel_keys(base, user_id.as_deref()),
        user_vfs_path,
        // One-shot refuses the occupant below, and `kotton:app/roots` is the
        // occupant's alone, so there is nothing to send.
        roots: None,
        // One-shot: the runner reads stdin to EOF before running, so no host
        // call could be answered. The occupant is long-lived by manifest, and
        // the runner refuses this combination explicitly rather than hanging.
        occupant: false,
        op: RunnerOp::Message { msg: msg.clone() },
    };

    let runner_out = spawn_runner(host.runner(), input).await.inspect_err(|e| {
        let _ = host.events().publish(
            Event::with_payload(
                EventCategory::WASM,
                EventLevel::Error,
                format!("App message error: {app_id}"),
                serde_json::json!({ "app_id": &app_id, "error": e.to_string() }),
            )
            .in_scope(EventScope::of(user_id.as_deref())),
        );
    })?;

    match runner_out {
        RunnerOutput::MessageHandled {
            patches,
            launches,
            raises,
        } => {
            let msg_len = msg.len();
            let patch_count = patches.len();
            let _ = host.events().publish(Event::with_payload(
                EventCategory::WASM,
                EventLevel::Debug,
                format!("App message: {app_id}"),
                serde_json::json!({ "app_id": &app_id, "msg_len": msg_len, "patch_count": patch_count }),
            )
            .in_scope(EventScope::of(user_id.as_deref())));
            // **`surface_of` is gone, and the answer to the question it stood
            // in for is that this list is empty** (RFC-0087, stage 2).
            //
            // Stage 1 left a reverse lookup here — *which surface does this app
            // have open?* — because a one-shot app has no live instance to read
            // a handle off and its patches had to reach something. Asked
            // properly, the answer is that a one-shot message op cannot produce
            // a patch at all: `on-launch` is the only thing that hands a guest a
            // `surface` resource, a one-shot spawn runs `on-message` in a fresh
            // process with an empty resource table, and `commit` is a method on
            // a resource. So the loop below is over a list that is empty by
            // construction, and it routes by handle like every other one rather
            // than guessing on the app's behalf.
            for p in &patches {
                host.surface_commit(p.surface, p.patch.clone()).await;
            }
            if !patches.is_empty() {
                tracing::debug!(
                    %app_id,
                    patch_count,
                    "a one-shot message painted; the patches name their own surfaces"
                );
            }
            for raised in raises {
                host.surface_raise(raised).await;
            }
            if !launches.is_empty() {
                process_pending_launches(
                    host,
                    user_db,
                    base,
                    &live_instances,
                    launches,
                    &app_id,
                    user_id,
                    occupant,
                    infer,
                    records,
                )
                .await;
            }
            Ok(UserResponse::AppMessageDelivered {
                patches: bare_patches(&patches),
            })
        }
        RunnerOutput::Error { message } => {
            let _ = host.events().publish(
                Event::with_payload(
                    EventCategory::WASM,
                    EventLevel::Error,
                    format!("App message error: {app_id}"),
                    serde_json::json!({ "app_id": &app_id, "error": &message }),
                )
                .in_scope(EventScope::of(user_id.as_deref())),
            );
            Err(io::Error::other(format!("runner: {message}")))
        }
        _ => Err(io::Error::other("unexpected runner output for message op")),
    }
}

/// Deliver a user input event (keyboard / pointer) to a running app.
///
/// Input is only meaningful for an app that already has a live runner process
/// (long-lived apps launched via [`app_launch`]).  If no live instance exists
/// for `app_id` the event is dropped silently — there is no persistent state to
/// route it to.  Any element patches the app produces in its `on-input` handler
/// are committed back to the compositor.
#[allow(clippy::too_many_arguments)]
pub async fn app_input_event(
    host: &dyn AppHost,
    // `None` before anybody has enrolled. Input delivery does not read the user's
    // database — only a launch the guest *raises* does, and a machine with no
    // user has no app registry to launch out of. Demanding it up front is what
    // deadlocked first run: the pre-identity shell is handed `world occupant` and
    // `create-identity` precisely so a person can enrol by clicking, and every
    // click was dropped because the routing asked for the user that clicking was
    // going to create (`TASK-first-run-input-needs-the-user-it-creates`).
    user_db: Option<&Arc<SqlitePool>>,
    base: &Path,
    live_instances: Arc<tokio::sync::Mutex<HashMap<String, LongLivedInstance>>>,
    app_id: String,
    // Which of the app's surfaces the event happened on. The compositor knows
    // — it hit-tested a window — and the daemon has used this handle to find
    // `app_id` since stage 1. It is passed on rather than dropped here, because
    // *which window was clicked* is not a question the guest can answer for
    // itself (`TASK-on-input-does-not-say-which-surface`). A handle this
    // instance does not hold is dropped by the runner, which is the side that
    // knows what the guest was given.
    surface: kotton_wire::SurfaceHandle,
    event: kotton_wire::ipc::types::InputEventPayload,
    user_id: Option<String>,
    // The pre-auth verbs, for the one app the user designated `shell`; `None`
    // for every other app, and for a caller with no identity authority to lend.
    // Passing `Some` is what makes an auth call serviceable at all — see
    // `OccupantHost`.
    occupant: Option<&dyn OccupantHost>,
    infer: Option<&dyn InferHost>,
    records: Option<&dyn RecordsHost>,
) -> io::Result<UserResponse> {
    let mut instances = live_instances.lock().await;

    // No running instance → nothing to deliver input to.
    if !instances.contains_key(&app_id) {
        return Ok(UserResponse::AppMessageDelivered { patches: vec![] });
    }

    // Take ownership; on any I/O error the instance is dropped (not re-inserted)
    // so a future launch respawns it.
    let mut instance = instances.remove(&app_id).unwrap();

    // Input is the occupant's primary path: a person typing a passphrase and
    // pressing a button arrives here, and the auth call it raises is serviced
    // inside this exchange.
    let runner_out = exchange(
        &mut instance,
        RunnerOp::Input { surface, event },
        host,
        occupant,
        infer,
        records,
    )
    .await?;

    match runner_out {
        RunnerOutput::InputHandled {
            patches,
            launches,
            raises,
        } => {
            instances.insert(app_id.clone(), instance);
            for p in &patches {
                host.surface_commit(p.surface, p.patch.clone()).await;
            }
            for raised in raises {
                host.surface_raise(raised).await;
            }
            // Release the lock before any guest-initiated launch (app_launch
            // re-acquires it). This is the primary desktop path: a dock/launcher
            // click is an input event whose handler calls `apps::launch`.
            drop(instances);
            if !launches.is_empty() {
                match user_db {
                    Some(db) => {
                        process_pending_launches(
                            host,
                            db,
                            base,
                            &live_instances,
                            launches,
                            &app_id,
                            user_id,
                            occupant,
                            infer,
                            records,
                        )
                        .await;
                    }
                    // A guest asking to launch another app before any user
                    // exists. There is no registry to resolve the request
                    // against, so this is not a case to serve quietly — the
                    // pre-identity shell should be enrolling, not launching.
                    None => tracing::warn!(
                        %app_id,
                        count = launches.len(),
                        "launch requested before any user exists; ignored"
                    ),
                }
            }
            Ok(UserResponse::AppMessageDelivered {
                patches: bare_patches(&patches),
            })
        }
        RunnerOutput::Error { message } => Err(io::Error::other(format!("runner: {message}"))),
        _ => Err(io::Error::other("unexpected runner output for input op")),
    }
}

/// Tell the designated app its window list is out of date
/// (`TASK-the-docks-window-list-is-as-stale-as-its-last-repaint`).
///
/// **What is sent is [`kotton_wire::runner::WINDOWS_CHANGED_FRAME`], a constant.** No
/// window, no id, no count: the frame is the same bytes whatever changed, so the one
/// thing it can tell its recipient is *now*. The list is still `list-windows`, answered
/// at the moment it is asked from what the compositor last reported — the pull RFC-0087
/// stage 3b chose, with a moment to pull at.
///
/// **Who it goes to is [`nudged`]'s answer**, and it is addressing rather than a guard:
/// the instance the person designated, which is the only one whose linker has
/// `layer-surface` and therefore the only one with a list to ask for. *Now* is the one
/// thing the frame carries, and delivered to anybody else it would be the one thing a
/// guest should not have — when some other app's window opened or closed, as a clock
/// it could read. That is why the recipient is chosen and not merely allowed.
///
/// **Only a live instance is nudged.** Nothing is launched for it: a designated app
/// that is not running has no dock to be stale, and `app_message`'s spawn-on-demand is
/// the wrong verb for a notice that means nothing to an instance that has not yet
/// asked.
///
/// A launch or a raise the guest asks for while answering is **dropped with a line**, not
/// served. The person did nothing; the host did, and an app that answers the host's *ask
/// again* by opening a window, or by bringing one to the front, is acting on a gesture
/// nobody made. Its patches are served — repainting is what the nudge is for.
pub async fn app_windows_changed(
    host: &dyn AppHost,
    live_instances: Arc<tokio::sync::Mutex<HashMap<String, LongLivedInstance>>>,
    occupant: Option<&dyn OccupantHost>,
    infer: Option<&dyn InferHost>,
    records: Option<&dyn RecordsHost>,
) -> io::Result<()> {
    let mut instances = live_instances.lock().await;
    let app_id = match nudged(instances.iter().map(|(id, i)| (id.as_str(), i.designated))) {
        Ok(Some(id)) => id.to_owned(),
        Ok(None) => return Ok(()),
        Err(claimants) => {
            tracing::error!(
                claimants,
                "more than one live instance is marked designated; the window-list nudge goes to none of them"
            );
            return Ok(());
        }
    };
    // Take ownership, as every exchange does: on an I/O error the instance is not
    // put back, so the next launch respawns it.
    let mut instance = instances.remove(&app_id).unwrap();
    let runner_out = exchange(
        &mut instance,
        RunnerOp::Message {
            msg: kotton_wire::runner::WINDOWS_CHANGED_FRAME.to_string(),
        },
        host,
        occupant,
        infer,
        records,
    )
    .await?;
    match runner_out {
        RunnerOutput::MessageHandled {
            patches,
            launches,
            raises,
        } => {
            instances.insert(app_id.clone(), instance);
            for p in &patches {
                host.surface_commit(p.surface, p.patch.clone()).await;
            }
            if !launches.is_empty() || !raises.is_empty() {
                tracing::warn!(
                    %app_id,
                    launches = launches.len(),
                    raises = raises.len(),
                    "a launch or raise asked for in answer to the window-list nudge; nobody made the gesture, ignored"
                );
            }
            Ok(())
        }
        RunnerOutput::Error { message } => Err(io::Error::other(format!("runner: {message}"))),
        _ => Err(io::Error::other("unexpected runner output for the window-list nudge")),
    }
}

/// Which live instance the window-list nudge is addressed to: the designated one, or
/// nobody — and `Err` with the count when more than one claims the designation.
///
/// A free function over `(app_id, designated)` so the addressing can be read and tested
/// without a running process — the same reason [`needs_the_designation`] is one.
///
/// **Two claimants is a bug elsewhere, and it is refused rather than resolved.** It cannot
/// happen today — the designation is one row, and a re-designation tears the old occupant
/// down. Picking one of two would hide that bug, and fanning out to both would turn it
/// into a clock handed to a second app. Nudging neither keeps the failure a stale dock and
/// a line in the log saying why.
fn nudged<'a>(instances: impl Iterator<Item = (&'a str, bool)>) -> Result<Option<&'a str>, usize> {
    let claimants: Vec<&str> = instances
        .filter(|(_, designated)| *designated)
        .map(|(id, _)| id)
        .collect();
    match claimants.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(one)),
        many => Err(many.len()),
    }
}

/// Forward a compositor patch-rejection to the running WASM guest via
/// `on-surface-error`.  Fire-and-forget from the compositor's perspective;
/// this function returns `UserResponse::SurfaceOk` in all non-fatal cases.
pub async fn app_surface_error(
    live_instances: Arc<tokio::sync::Mutex<HashMap<String, LongLivedInstance>>>,
    app_id: String,
    reason: String,
) -> io::Result<UserResponse> {
    let mut instances = live_instances.lock().await;

    // No running instance → nothing to notify.
    if !instances.contains_key(&app_id) {
        return Ok(UserResponse::SurfaceOk);
    }

    let mut instance = instances.remove(&app_id).unwrap();

    let frame = serde_json::to_string(&RunnerMessage {
        op: RunnerOp::SurfaceError { reason },
    })
    .map_err(|e| io::Error::other(format!("serialize runner surface_error: {e}")))?;
    instance.stdin.write_all(frame.as_bytes()).await?;
    instance.stdin.write_all(b"\n").await?;
    instance.stdin.flush().await?;

    let mut resp_line = String::new();
    let n = instance.stdout.read_line(&mut resp_line).await?;
    if n == 0 {
        return Err(io::Error::other("runner exited (EOF)"));
    }
    let runner_out: RunnerOutput = serde_json::from_str(resp_line.trim())
        .map_err(|e| io::Error::other(format!("deserialize runner output: {e}")))?;

    match runner_out {
        RunnerOutput::SurfaceErrorHandled => {
            instances.insert(app_id, instance);
            Ok(UserResponse::SurfaceOk)
        }
        RunnerOutput::Error { message } => Err(io::Error::other(format!("runner: {message}"))),
        _ => Err(io::Error::other(
            "unexpected runner output for surface_error op",
        )),
    }
}

/// Spawn a `kotton-runner --long-lived` process and send the initial frame.
///
/// The first line sent is the full `RunnerInput` JSON; subsequent calls send
/// `RunnerMessage` frames. Responses are read one line at a time.
///
/// Returns the live instance together with the parsed [`RunnerOutput`] of the
/// initial op so callers can collect launch/message patches.
#[allow(clippy::too_many_arguments)]
async fn spawn_long_lived_runner(
    host: &dyn AppHost,
    app_id: &str,
    // `manifest.app.name` — what the host draws in the frame of every surface
    // this instance opens, at launch and afterwards.
    title: &str,
    init_input: RunnerInput,
    user_id: Option<&str>,
    occupant: Option<&dyn OccupantHost>,
    infer: Option<&dyn InferHost>,
    records: Option<&dyn RecordsHost>,
) -> io::Result<(LongLivedInstance, RunnerOutput)> {
    match open_long_lived_runner(host, app_id, title, init_input, user_id, occupant, infer, records).await {
        Ok(ok) => Ok(ok),
        Err((error, surfaces)) => {
            // **The one place a failed launch's surfaces are closed.**
            //
            // The obligation is carried by the error type rather than by a rule
            // callers are asked to remember: `open_long_lived_runner` hands back
            // what it left open, and this closes it. Four call sites each
            // closing what they thought the instance held is how one of them
            // ends up closing the launch handle and not the two the guest asked
            // for during `on-launch` — which is exactly what the first version
            // of this stage did.
            for handle in surfaces {
                host.surface_close(handle).await;
            }
            Err(error)
        }
    }
}

/// The fallible half of [`spawn_long_lived_runner`].
///
/// **On `Err` it returns every surface still open**, so the caller above can
/// close them and nothing else has to know. The list is the launch surface the
/// resolver minted — already opened on the compositor by `spawn_and_present`
/// before this was called — plus every surface the guest asked for while its
/// init frame was being serviced (`service_surface_call`), which is why a bare
/// "close the launch handle" is not enough and never was.
///
/// On `Ok` the surfaces belong to the returned instance, and closing them is
/// teardown's job rather than this path's.
#[allow(clippy::too_many_arguments)]
async fn open_long_lived_runner(
    host: &dyn AppHost,
    app_id: &str,
    title: &str,
    init_input: RunnerInput,
    user_id: Option<&str>,
    occupant: Option<&dyn OccupantHost>,
    infer: Option<&dyn InferHost>,
    records: Option<&dyn RecordsHost>,
) -> Result<(LongLivedInstance, RunnerOutput), (io::Error, Vec<SurfaceHandle>)> {
    // The surface this instance was launched with, read off the init frame
    // rather than passed a second time: the op is where the handle already is,
    // and two sources for one fact is how they drift.
    //
    // Read **before** the spawn, because a spawn that fails still has to hand
    // the handle back: `spawn_and_present` opened it on the compositor before
    // calling this.
    let surface = match &init_input.op {
        RunnerOp::Launch { surface, .. } => *surface,
        // A long-lived instance spawned by a *message* rather than a launch
        // (`app_message`, when nothing is running yet). It gets a handle so its
        // patches have somewhere to go, and that surface is never opened on
        // `kuid` — which is exactly what happened before handles existed: the
        // commits arrived for a surface no `SurfaceOpen` had created and the
        // compositor buffered them, undrawn, in `deferred_patches`. Minting
        // here reproduces that rather than quietly making a window appear.
        //
        // Closing one nobody opened is a no-op on both sides of the wire, so it
        // rides the same list rather than needing a case.
        _ => kotton_wire::SurfaceHandle::mint(),
    };

    let runner = host.runner();
    let mut cmd = tokio::process::Command::new(runner);
    cmd.arg("--long-lived")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Expose the user identity to the runner so its `files`/`schema` host functions
    // resolve against the right user's VFS without an explicit --user flag.
    if let Some(uid) = user_id {
        cmd.env("KOTTON_USER", uid);
    }
    // Confined before it is spawned, and a refusal is a failed spawn: the
    // launch surface goes back to the caller exactly as it would for a runner
    // binary that is not there (DEC-0074 §1, `confine_runner`).
    if let Err(e) = confine_runner(&mut cmd, runner, &init_input).await {
        return Err((e, vec![surface]));
    }
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Err((
                io::Error::other(format!("spawn kotton-runner ({}): {e}", runner.display())),
                vec![surface],
            ))
        }
    };

    let stdin = child.stdin.take().expect("stdin was piped");
    let stdout = child.stdout.take().expect("stdout was piped");

    // Drain the runner's stderr asynchronously, logging each line.
    let stderr = child.stderr.take().expect("stderr was piped");
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt as _, BufReader};
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::warn!(runner = "kotton-runner", stderr = %line, "runner stderr");
        }
    });

    let mut instance = LongLivedInstance {
        stdin: tokio::io::BufWriter::new(stdin),
        stdout: BufReader::new(stdout),
        _child: child,
        surfaces: vec![surface],
        app_id: app_id.to_string(),
        title: title.to_string(),
        // The person's own `app_roles` row, as the launch already read it. Not a
        // second source: `input.occupant` is the same value the runner was told,
        // so the daemon and the guest's world cannot disagree about it.
        designated: init_input.occupant,
        // The mount this instance was launched with, as the launch computed it.
        // Not a second source either: it is the same string the runner was told,
        // so *does this screen have the person's files* is answered from what
        // the guest actually holds rather than from a guess about who it is.
        user_vfs_path: init_input.user_vfs_path.clone(),
        // The grant this instance's file calls are checked against, from the
        // input the runner was just sent — so the daemon and the sandbox mint
        // from one snapshot.
        personal: PersonalReach::of(app_id, user_id, &init_input),
        windows_shown: Vec::new(),
    };

    // From here on the instance owns the list, and `service_surface_call`
    // appends to it as the guest asks. Every failure below therefore reports
    // `instance.surfaces` rather than the one handle this started with.
    match init_long_lived_runner(&mut instance, init_input, host, occupant, infer, records).await {
        Ok(init_output) => Ok((instance, init_output)),
        Err(e) => Err((e, std::mem::take(&mut instance.surfaces))),
    }
}

/// Send the init frame and read its answer, servicing anything the guest asks
/// for along the way.
///
/// Split out so that every `?` in it is covered by one `match` above: the
/// instance is about to be dropped and its process killed, and the surfaces it
/// acquired while running have to go with it.
async fn init_long_lived_runner(
    instance: &mut LongLivedInstance,
    init_input: RunnerInput,
    host: &dyn AppHost,
    occupant: Option<&dyn OccupantHost>,
    infer: Option<&dyn InferHost>,
    records: Option<&dyn RecordsHost>,
) -> io::Result<RunnerOutput> {
    // Send the initialization frame.
    let init_json = serde_json::to_string(&init_input)
        .map_err(|e| io::Error::other(format!("serialize runner init: {e}")))?;
    instance.stdin.write_all(init_json.as_bytes()).await?;
    instance.stdin.write_all(b"\n").await?;
    instance.stdin.flush().await?;

    // Read the response to the init op. `on-launch` may itself raise a host
    // call — the occupant's welcome screen asks nothing on launch today, but a
    // single-read here would desync the stream the first time one did.
    //
    // A runner that exits without writing anything (e.g. MOCK_RUNNER_MODE=exit)
    // surfaces as EOF, so the caller never stores a dead instance.
    let init_output = drain_until_result(instance, host, occupant, infer, records).await?;
    if let RunnerOutput::Error { message } = &init_output {
        return Err(io::Error::other(format!("runner init: {message}")));
    }

    Ok(init_output)
}

/// Read frames from a running instance until a terminal result, servicing any
/// host call raised along the way.
///
/// **Why the read is a loop now.** It was a single `read_line` at four call
/// sites, each of which treated anything but its own terminal frame as
/// "unexpected runner output". That was true while an app could only answer,
/// and stopped being true when the occupant gained a verb that needs a value
/// back mid-op: `create-identity` is called from `on-input` and returns a
/// recovery phrase, so it cannot be queued as an effect and drained afterwards
/// the way `surface::commit` is (DEC-0045).
///
/// A host call that cannot be serviced returns `Err`, which drops the instance
/// rather than re-inserting it — the stream is in an unknown state after a
/// frame nobody could answer, and a dropped instance respawns clean on the
/// next call.
async fn drain_until_result(
    instance: &mut LongLivedInstance,
    host: &dyn AppHost,
    occupant: Option<&dyn OccupantHost>,
    infer: Option<&dyn InferHost>,
    records: Option<&dyn RecordsHost>,
) -> io::Result<RunnerOutput> {
    loop {
        let mut line = String::new();
        let n = instance.stdout.read_line(&mut line).await?;
        if n == 0 {
            return Err(io::Error::other("runner exited (EOF)"));
        }
        let frame: RunnerOutput = serde_json::from_str(line.trim())
            .map_err(|e| io::Error::other(format!("deserialize runner output: {e}")))?;

        let RunnerOutput::HostCall { call } = frame else {
            return Ok(frame);
        };
        // **Serviced here rather than in `service_host_call`, because this is
        // where the instance is.** A surface belongs to an instance: the cap is
        // per-instance, the new handle is recorded on the instance, and the
        // designation that says whether a `Background` frame is legitimate is
        // the instance's. `service_host_call` is handed verbs and no instance,
        // by design — every other frame it answers is about the *user*.
        let reply = match call {
            RunnerHostCall::Surface { verb } => {
                service_surface_call(verb, &mut instance.surface_view(), host).await?
            }
            // The person's files: whose they are and what the grant covers are
            // the instance's, so they are answered here for the reason the
            // surface verbs are.
            RunnerHostCall::Files { verb } => {
                service_files_call(verb, instance.personal.as_ref(), &|uid| host.personal_tree(uid))
                    .await?
            }
            call => service_host_call(call, occupant, infer, records).await?,
        };
        send_op(instance, RunnerOp::HostReply { reply }).await?;
    }
}

/// Answer one surface verb for a running instance (RFC-0087).
///
/// Three verbs: open another surface, list the windows there are, ask for one
/// of them back. They are serviced together because they are the three things
/// that need *this instance* — the cap counts its surfaces, the new handle is
/// recorded on it, the window ids are its own, and the designation that says
/// which of them are legitimate is its.
///
/// **The daemon mints**, as it does at launch, and for the same reason: the
/// handle is what `kuid` draws by and what `kuserd` keys its private
/// `handle -> app` map on, so a value a confined process chose would be a
/// surface the host never agreed to open. The same rule is why a window list
/// carries an id and not a handle.
///
/// Three things can stop a call here and only the last is about authority:
///
/// - **The cap.** [`MAX_SURFACES_PER_INSTANCE`] is unbounded reach otherwise —
///   a guest in a loop making the host open documents until the machine stops.
///   It is answered to the guest, because a resource bound is something an app
///   can sensibly be told.
/// - **An id naming no window this instance was shown.** Also answered to the
///   guest: it is an ordinary mistake, and the list it should have asked for is
///   one call away. Nothing is revealed by the refusal, because there was
///   nothing behind the id.
/// - **A verb the instance's world cannot make.** That is not answered to the
///   guest; it returns `Err`, which drops the instance. An undesignated guest
///   has no `layer-surface` import, so a `Background` frame — or a window list
///   ask — from one means the runner emitted a call it could not have been
///   asked for: a bug in the confinement boundary, which must fail loudly
///   rather than be serviced.
async fn service_surface_call(
    verb: RunnerSurfaceVerb,
    instance: &mut InstanceSurfaces<'_>,
    host: &dyn AppHost,
) -> io::Result<RunnerHostReply> {
    // **The audit, at the process boundary the linker is inside of.** Every verb below the
    // first is reachable only through `layer-surface`, which is added to a runner's linker
    // only for the app the person designated — so an undesignated instance emitting one is
    // a runner making a call its world cannot make. That is a bug in the confinement
    // boundary and it fails loudly rather than being serviced, exactly as `RunnerHostCall::
    // Auth` does. See the note on `LongLivedInstance::designated` for why this is not the
    // second guard it looks like: the absence is enforced *inside* the runner process, and
    // this is the daemon declining to take that process's word for it.
    if needs_the_designation(&verb) && !instance.designated {
        return Err(io::Error::other(format!(
            "an undesignated guest emitted {verb:?}; its linker has no layer-surface \
             interface, so the runner emitted a frame it could not have been asked for"
        )));
    }

    match verb {
        RunnerSurfaceVerb::Create {
            role,
            edge,
            width,
            height,
        } => service_surface_create(role, edge, width, height, instance, host).await,
        RunnerSurfaceVerb::Close { surface } => {
            // **Resolved against this instance's own list**, which is the whole of the
            // confinement: a handle is not something a guest can write — it holds a
            // `resource` and the runner turns that into the handle it was minted — but the
            // runner is a separate process, and the daemon declining to close a surface the
            // instance does not hold is the same audit the designation check is.
            if !instance.surfaces.contains(&surface) {
                return Ok(RunnerHostReply::SurfaceFailed {
                    message: "surface.close: this instance does not hold that surface".into(),
                });
            }
            instance.surfaces.retain(|h| *h != surface);
            host.surface_close(surface).await;
            tracing::info!(
                app_id = %instance.app_id,
                surface = %surface,
                held = instance.surfaces.len(),
                "app gave a surface back"
            );
            Ok(RunnerHostReply::SurfaceReleased)
        }
        RunnerSurfaceVerb::Resize {
            surface,
            width,
            height,
        } => {
            // **Resolved against this instance's own list**, the same audit `Close` above
            // performs and for the same reason: the guest holds a `resource` and cannot
            // write a handle, but the runner is a separate process, and the daemon
            // declining to resize a surface the instance does not hold is where that stops
            // mattering. Without it a runner bug would be a guest resizing somebody else's
            // dock.
            if !instance.surfaces.contains(&surface) {
                return Ok(RunnerHostReply::SurfaceFailed {
                    message: "surface.request-size: this instance does not hold that surface"
                        .into(),
                });
            }
            host.surface_resize(surface, width, height).await;
            Ok(RunnerHostReply::SurfaceResized)
        }
        RunnerSurfaceVerb::SetTitle { surface, title } => {
            // **Resolved against this instance's own list**, the same audit `Close` and
            // `Resize` perform and for the same reason. Without it a runner bug would be a
            // guest writing words into somebody else's title bar, which is the one thing a
            // title must never be able to do.
            if !instance.surfaces.contains(&surface) {
                return Ok(RunnerHostReply::SurfaceFailed {
                    message: "surface.set-title: this instance does not hold that surface".into(),
                });
            }
            host.surface_set_title(surface, bounded_title(&title)).await;
            Ok(RunnerHostReply::SurfaceTitled)
        }
        RunnerSurfaceVerb::ListWindows => Ok(list_windows_for(instance, host).await),
        RunnerSurfaceVerb::RaiseWindow { window } => {
            // Resolved against **this instance's** list, so an id it was never given names
            // nothing. That is the whole of the confinement on this verb: there is no
            // handle on this wire for a guest to guess at, and no window outside the list
            // it was shown that an id can reach.
            let Some(handle) = window_handle(instance.windows_shown, window) else {
                return Ok(RunnerHostReply::SurfaceFailed {
                    message: format!("no window {window} — this app was never shown one"),
                });
            };
            host.surface_restore(handle).await;
            Ok(RunnerHostReply::SurfaceRaised)
        }
    }
}

/// The window list, with an id minted for this instance for each window in it.
///
/// **Ids are handed out here and remembered on the instance**, because an id the daemon
/// forgot is an id `raise-window` cannot resolve. A window this instance has seen before
/// keeps the id it had, so a dock does not renumber itself every time it repaints.
async fn list_windows_for(
    instance: &mut InstanceSurfaces<'_>,
    host: &dyn AppHost,
) -> RunnerHostReply {
    let windows = host.surface_windows().await;
    RunnerHostReply::SurfaceWindows {
        windows: window_views(instance.windows_shown, windows),
    }
}

/// A guest's title, cut to what the host will hold.
///
/// **Here rather than at the compositor**, because this is the first process on the path
/// that a confined one is not: a bound enforced where the string is drawn would be a bound
/// `kuserd` had already stored an unbounded copy of, and `kuserd`'s copy is the one every
/// window list is built from.
///
/// Cut on a `char` boundary and counted in characters, so the bound means the same in every
/// script and what comes out is still a string. Nothing is appended: an ellipsis would be
/// the host writing a character the guest did not, into a field whose whole rule is that
/// the guest supplies the characters — and the bar already truncates visually, in CSS, at
/// whatever width the window actually is.
fn bounded_title(title: &str) -> String {
    title.chars().take(kotton_wire::MAX_TITLE_CHARS).collect()
}

/// Whether a verb is one only the **designated** app's world can make.
///
/// The list of what `layer-surface` carries, which is the interface the host adds to a
/// runner's linker only for the app the person designated. A free function so the rule can
/// be read, and tested, without a running instance — and so that adding a verb to that
/// interface without adding it here is a visible omission rather than a silent one.
fn needs_the_designation(verb: &RunnerSurfaceVerb) -> bool {
    match verb {
        // `create-surface` is in every app's world; the *role* is what is not. `Window` is
        // the only member of the enum `world app` carries.
        RunnerSurfaceVerb::Create { role, .. } => role.is_system(),
        // Giving a surface back is `surface.close`, which is in every app's world — the
        // designation decides what may be *created*, not what may be released. Asking
        // again for a size is `surface.request-size`, on the same interface and for the
        // same reason: an app that may hold a surface may say how big it would like it.
        // Saying what a surface is about is `surface.set-title`, the same again — the
        // designation is about which *layers* may exist, and a title is about a surface
        // its holder already has.
        RunnerSurfaceVerb::Close { .. }
        | RunnerSurfaceVerb::Resize { .. }
        | RunnerSurfaceVerb::SetTitle { .. } => false,
        RunnerSurfaceVerb::ListWindows | RunnerSurfaceVerb::RaiseWindow { .. } => true,
    }
}

/// Translate the host's window list into the asking instance's own view of it.
///
/// **The trap this unit exists to avoid, in one function.** What goes out is an id minted
/// for this instance, the host's attribution, the holder's own title for the window, and
/// one bit. What does not go out is the handle — which is minted per machine, is what every
/// surface wire is addressed by, and would tell one app how many surfaces every other app
/// has opened.
///
/// `shown` is the instance's own list, appended to here and never re-keyed: a window keeps
/// the id it was first given, so a dock does not renumber itself between repaints, and an
/// id is never handed to a second window — which is stage 3a's ordinal defect one level up,
/// and the version of it that would send a person's click to somebody else's window.
fn window_views(
    shown: &mut Vec<SurfaceHandle>,
    windows: Vec<kotton_wire::HostWindow>,
) -> Vec<kotton_wire::WindowView> {
    windows
        .into_iter()
        .map(|w| {
            let id = match shown.iter().position(|h| *h == w.handle) {
                Some(i) => i as u64 + 1,
                None => {
                    shown.push(w.handle);
                    shown.len() as u64
                }
            };
            kotton_wire::WindowView {
                id,
                name: w.name,
                title: w.title,
                minimised: w.minimised,
            }
        })
        .collect()
}

/// Which window an instance's id names, or `None` for one it was never given.
///
/// Ids count from 1 so that `0` — the value a guest gets from an uninitialised variable, and
/// the one stage 3a's assessment found `ordinal` answering on a failed lookup — names
/// nothing rather than the first window.
fn window_handle(shown: &[SurfaceHandle], window: u64) -> Option<SurfaceHandle> {
    window
        .checked_sub(1)
        .and_then(|i| shown.get(i as usize))
        .copied()
}

/// Mint, open and record one more surface for a running instance.
async fn service_surface_create(
    role: kotton_wire::SurfaceRole,
    edge: Option<kotton_wire::PanelEdge>,
    width: u32,
    height: u32,
    instance: &mut InstanceSurfaces<'_>,
    host: &dyn AppHost,
) -> io::Result<RunnerHostReply> {
    if instance.surfaces.len() >= MAX_SURFACES_PER_INSTANCE {
        return Ok(RunnerHostReply::SurfaceFailed {
            message: format!(
                "this app already holds {MAX_SURFACES_PER_INSTANCE} surfaces, which is the \
                 most one instance may hold"
            ),
        });
    }

    let handle = SurfaceHandle::mint();
    host.surface_open(
        handle,
        instance.app_id,
        kotton_wire::SurfaceSpec {
            role,
            edge,
            title: instance.title.to_string(),
            width,
            height,
        },
    )
    .await;
    instance.surfaces.push(handle);
    tracing::info!(
        app_id = %instance.app_id,
        surface = %handle,
        ?role,
        ?edge,
        held = instance.surfaces.len(),
        "app created an additional surface"
    );
    Ok(RunnerHostReply::SurfaceCreated { handle })
}

/// Drop the handles and keep the bytes, for the client-facing wire.
///
/// [`UserResponse::AppLaunched`] and [`UserResponse::AppMessageDelivered`]
/// answer a *client* asking what a call drew — the CLI, or any other caller of
/// `AppLaunch` or `AppMessage` — and a client has one view. Which surface a
/// patch was for is the compositor's routing question, answered above by
/// sending each patch to its own handle, and nothing on this wire reads it.
/// Stated here rather than widening a second wire that nobody asked to widen.
fn bare_patches(patches: &[kotton_wire::runner::SurfacePatch]) -> Vec<Vec<u8>> {
    patches.iter().map(|p| p.patch.clone()).collect()
}

/// Write one op frame to a running instance.
async fn send_op(instance: &mut LongLivedInstance, op: RunnerOp) -> io::Result<()> {
    let frame = serde_json::to_string(&RunnerMessage { op })
        .map_err(|e| io::Error::other(format!("serialize runner message: {e}")))?;
    instance.stdin.write_all(frame.as_bytes()).await?;
    instance.stdin.write_all(b"\n").await?;
    instance.stdin.flush().await
}

/// Send one op and read the result it produces.
async fn exchange(
    instance: &mut LongLivedInstance,
    op: RunnerOp,
    host: &dyn AppHost,
    occupant: Option<&dyn OccupantHost>,
    infer: Option<&dyn InferHost>,
    records: Option<&dyn RecordsHost>,
) -> io::Result<RunnerOutput> {
    send_op(instance, op).await?;
    drain_until_result(instance, host, occupant, infer, records).await
}

/// Exhaust an app's `while_open` grants because its instance has exited.
///
/// The window-close and terminate paths call this after tearing the instance
/// down: a `while_open` grant is bound to the running process, so when the
/// process is gone the grant is too, and a later launch does not inherit it
/// (TASK-a-grant-cannot-be-once-or-while-open). Idempotent and best-effort — an
/// app with no such grant has nothing to revoke.
pub async fn app_closed(user_db: &SqlitePool, app_id: &str) {
    if let Err(e) = grant_db::exhaust_while_open_for_app(user_db, app_id).await {
        tracing::warn!(%app_id, "failed to exhaust while-open grants on close: {e}");
    }
}

/// Send a `Terminate` op to a long-lived runner and wait for it to exit.
///
/// Best-effort: if the runner is already dead or the send fails, we still
/// drop the instance so the process is cleaned up via its `_child` field.
pub async fn terminate_long_lived_instance(instance: &mut LongLivedInstance) {
    let frame = match serde_json::to_string(&RunnerMessage {
        op: RunnerOp::Terminate,
    }) {
        Ok(f) => f,
        Err(_) => return,
    };
    let _ = instance.stdin.write_all(frame.as_bytes()).await;
    let _ = instance.stdin.write_all(b"\n").await;
    let _ = instance.stdin.flush().await;

    // Read one response line (the `on-terminate` result). We give it a short
    // window; if the runner hangs it will be killed when `_child` is dropped.
    let mut resp = String::new();
    let timeout = tokio::time::Duration::from_secs(2);
    let _ = tokio::time::timeout(timeout, instance.stdout.read_line(&mut resp)).await;
}

/// Register a pre-built web bundle as an installed app (no WASM).
///
/// This is the handler for `AppRegisterBundle`. The bundle directory must
/// exist on disk — the daemon stores the path, not the files.
pub async fn app_register_bundle(
    user_db: &Arc<SqlitePool>,
    app_id: String,
    name: String,
    version: String,
    capabilities_json: String,
    bundle_path: String,
    dev: bool,
) -> io::Result<UserResponse> {
    // Validate that bundle_path exists and is a directory.
    let path = std::path::Path::new(&bundle_path);
    if !path.is_dir() {
        return Err(io::Error::other(format!(
            "bundle_path does not exist or is not a directory: {bundle_path}"
        )));
    }

    let installed_at = now_rfc3339();
    ardb::insert_bundle_app(
        user_db,
        &app_id,
        &name,
        &version,
        &capabilities_json,
        &bundle_path,
        &installed_at,
        dev,
    )
    .await?;

    let kind = if dev { "dev" } else { "production" };
    tracing::info!(%app_id, %version, %kind, "bundle app registered");
    Ok(UserResponse::AppBundleRegistered { app_id })
}

/// Return the bundle path for an installed app.
///
/// Used by the Tauri host at startup to resolve bundle locations from the
/// registry instead of reading env vars.
pub async fn app_get_bundle_path(
    user_db: &Arc<SqlitePool>,
    app_id: String,
) -> io::Result<UserResponse> {
    let bundle_path = ardb::get_bundle_path(user_db, &app_id).await?;
    Ok(UserResponse::AppBundlePath {
        app_id,
        bundle_path,
    })
}

// ── Role registry ─────────────────────────────────────────────────────────────

/// Required capability strings for each named system role.
/// The target app must declare all of these in its manifest.
fn role_required_caps(role: &str) -> &'static [&'static str] {
    match role {
        // The `shell` role denotes **surface ownership** only (which app draws the screen)
        // — not a data-access privilege (RFC-0028). A shell is an ordinary confined app; its
        // power is the user-approved breadth of its `files`/`schema` grants, identical to what
        // any app could request, never a role-gated bypass. So the role has no required
        // capability. Seam: when the role system can express path-grant contracts, this could
        // require e.g. `files.read` over the user's namespace.
        "shell" => &[],
        "dock" => &["events.subscribe"],
        _ => &[],
    }
}

pub async fn app_get_role(user_db: &Arc<SqlitePool>, role: String) -> io::Result<UserResponse> {
    match role_db::get_role(user_db, &role).await? {
        Some(app_id) => Ok(UserResponse::AppRole { role, app_id }),
        None => Ok(UserResponse::AppNotFound { app_id: role }),
    }
}

pub async fn app_set_role(
    user_db: &Arc<SqlitePool>,
    role: String,
    app_id: String,
) -> io::Result<UserResponse> {
    // Verify the target app is installed and fetch its capabilities.
    let app = ardb::get_app(user_db, &app_id)
        .await?
        .ok_or_else(|| io::Error::other(format!("app not found: {app_id}")))?;
    let caps = app.capabilities;

    // Validate capability contract for the role.
    let required = role_required_caps(&role);
    for req in required {
        if !caps.iter().any(|c| c == req) {
            return Ok(UserResponse::Error {
                message: format!(
                    "app '{app_id}' does not satisfy role '{role}': missing capability '{req}'"
                ),
            });
        }
    }

    role_db::set_role(user_db, &role, &app_id).await?;
    Ok(UserResponse::AppRoleSet { role, app_id })
}

#[cfg(test)]
mod host_call_tests {
    use super::roots_for_the_occupant;

    /// **The occupant is never handed `None` for its roots.** The interface is
    /// the world's promise; the list is what varies. A store with nothing (or
    /// no store, before an identity exists) is an empty `Some`, and a store's
    /// answer passes through untouched. Pinned because the first shell that
    /// imported `kotton:app/roots` failed to instantiate on every locked boot
    /// while the pre-identity launch sent `None`.
    #[test]
    fn the_occupant_is_handed_an_empty_root_set_and_never_none() {
        assert_eq!(
            roots_for_the_occupant(Ok(Vec::new())),
            Some(RunnerRoots::Read(Vec::new())),
            "an empty list is a person with no roots, and it is still Some"
        );
        let one = vec![kotton_wire::runner::RunnerRoot {
            id: "r1".into(),
            name: "This PC".into(),
            members: Vec::new(),
            targets: Vec::new(),
            residency: kotton_wire::runner::RunnerResidency::Full,
            kept: kotton_wire::runner::RunnerKeeping::ThisDeviceOnly,
            tree_path: String::new(),
            granted: true,
            writable: false,
        }];
        assert_eq!(
            roots_for_the_occupant(Ok(one.clone())),
            Some(RunnerRoots::Read(one))
        );
        // **A failure is never an empty list.** This is the line the owner's
        // "all of my roots disappeared" came through.
        for why in [
            RootsUnread::Nobody,
            RootsUnread::NoIdentity,
            RootsUnread::StoreNotLoaded,
            RootsUnread::Locked,
            RootsUnread::IndexUnopenable,
        ] {
            assert_eq!(
                roots_for_the_occupant(Err(why)),
                Some(RunnerRoots::Unread(why)),
                "{why:?} was handed to the occupant as something other than unread"
            );
        }
    }

    /// **The two failures that logged nothing and read as no roots**
    /// (`TASK-a-roots-failure-is-drawn-as-no-roots`): a launch for nobody,
    /// and a person no KEL chain names. Each is its own cause, and each cause
    /// is one sentence with one full stop.
    #[test]
    fn a_launch_for_nobody_and_a_person_with_no_chain_each_say_why_the_roots_are_unread() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let host = RootsHost;

        let nobody = user_roots(&host, tmp.path(), None);
        assert_eq!(nobody, Err(RootsUnread::Nobody));
        assert_eq!(
            RootsUnread::Nobody.words(),
            "No one is signed in, so there are no locations to list."
        );

        // A named person with no KEL under `base`: nothing names them.
        let unnamed = user_roots(&host, tmp.path(), Some("owner"));
        assert_eq!(unnamed, Err(RootsUnread::NoIdentity));
        assert_eq!(
            RootsUnread::NoIdentity.words(),
            "Kotton couldn't load your identity, so it can't list your locations."
        );

        for why in [
            RootsUnread::Nobody,
            RootsUnread::NoIdentity,
            RootsUnread::StoreNotLoaded,
            RootsUnread::Locked,
            RootsUnread::IndexUnopenable,
        ] {
            let words = why.words();
            assert_eq!(words.matches('.').count(), 1, "{why:?}: {words}");
            assert!(words.ends_with('.'), "{why:?}: {words}");
        }
    }

    /// A host that would answer roots if it were ever asked. The two tests
    /// above stop before the host, which is the point.
    struct RootsHost;

    #[async_trait::async_trait]
    impl AppHost for RootsHost {
        fn events(&self) -> &Arc<EventBus> {
            unreachable!("not exercised by these tests")
        }
        fn registered_users(&self) -> Vec<RegisteredUser> {
            Vec::new()
        }
        fn secrets(&self) -> &dyn SecretsStore {
            unreachable!("not exercised by these tests")
        }
        fn runner(&self) -> &Path {
            unreachable!("not exercised by these tests")
        }
        fn user_roots(&self, _: &Path, _: &str, _: &str) -> Result<Vec<RunnerRoot>, RootsUnread> {
            unreachable!("the launch stops before the host is asked")
        }
        fn keys_loaded(&self, _: &str) -> bool {
            true
        }
        /// No store behind this double, so no person's tree either.
        fn personal_tree(&self, _: &str) -> Option<Arc<dyn PersonalTree>> {
            None
        }
        async fn surface_open(&self, _: SurfaceHandle, _: &str, _: kotton_wire::SurfaceSpec) {}
        async fn surface_commit(&self, _: SurfaceHandle, _: Vec<u8>) {}
        async fn surface_close(&self, _: SurfaceHandle) {}
        async fn surface_resize(&self, _: SurfaceHandle, _: u32, _: u32) {}
        async fn surface_set_title(&self, _: SurfaceHandle, _: String) {}
        async fn surface_raise(&self, _: SurfaceHandle) {}
        async fn surface_windows(&self) -> Vec<kotton_wire::HostWindow> {
            Vec::new()
        }
        async fn surface_restore(&self, _: SurfaceHandle) {}
    }

    use super::*;

    /// The second run is `locked`, and it is an ordinary state rather than a failure.
    ///
    /// Pinned because the screen it selects was unreachable for three weeks while being
    /// fully built: `components/lock.rs` was written, styled and given a gallery specimen on
    /// 2026-08-29, and the compositor returned before any launch whenever a resident user's
    /// database would not open — which is exactly what a locked account does (`DEC-0049`:
    /// loaded and locked are not exclusive). Nothing failed; a person just got no window.
    #[test]
    fn a_device_that_knows_who_lives_here_opens_locked_not_welcome() {
        let nobody: Vec<RegisteredUser> = vec![];
        let somebody = vec![RegisteredUser {
            user_id: "austin".to_owned(),
            display_name: None,
        }];

        // No session and nobody registered: first run.
        assert_eq!(super::shell_launch_mode(false, &nobody), "welcome");
        // No session but somebody lives here: the unlock screen, not the welcome flow.
        assert_eq!(super::shell_launch_mode(false, &somebody), "locked");
        // A session decides it outright, whoever else is registered.
        assert_eq!(super::shell_launch_mode(true, &somebody), "authenticated");
        assert_eq!(super::shell_launch_mode(true, &nobody), "authenticated");
    }

    /// The lock screen is told whom to unlock and what to call them, in two
    /// lists that line up — and the id is in the first alone.
    ///
    /// The case that matters is the middle one: an identity with no display
    /// name (an `owner` device, or one the CLI made) gets an **empty** entry in
    /// `names`, never its id copied across, because the shell draws a fallback
    /// for an empty name and would draw an id it was handed
    /// (`TASK-the-name-the-welcome-asks-for-goes-nowhere`).
    #[test]
    fn the_lock_screen_is_told_ids_to_unlock_and_names_to_draw_and_never_an_id_to_draw() {
        let users = vec![
            RegisteredUser {
                user_id: "u3f9c0a1b2c3d4e5f60718293a4b5c6d7".to_owned(),
                display_name: Some("Austin".to_owned()),
            },
            RegisteredUser {
                user_id: "owner".to_owned(),
                display_name: None,
            },
            RegisteredUser {
                user_id: "sam".to_owned(),
                // A separator smuggled into a name by a hand-edited file does
                // not become a fourth slot.
                display_name: Some("Sam \u{2014} \u{1f}work".to_owned()),
            },
        ];
        let args = super::screen_args(false, &users);
        let arg = |k: &str| args.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str());
        assert_eq!(arg("mode"), Some("locked"));
        assert_eq!(
            arg("users"),
            Some("u3f9c0a1b2c3d4e5f60718293a4b5c6d7,owner,sam")
        );
        assert_eq!(arg("names"), Some("Austin\u{1f}\u{1f}Sam \u{2014} work"));
        let names: Vec<&str> = arg("names").unwrap().split(super::NAMES_SEPARATOR).collect();
        assert_eq!(names.len(), users.len(), "one name slot per id, empty or not");
        for u in &users {
            assert!(
                !names.contains(&u.user_id.as_str()),
                "an id must never stand in for a missing name: {args:?}"
            );
        }

        // A session, or nobody registered, writes neither list.
        for (session, users) in [(true, users.clone()), (false, vec![])] {
            let args = super::screen_args(session, &users);
            assert!(!args.iter().any(|(k, _)| k == "users" || k == "names"), "{args:?}");
        }
    }

    /// An occupant host that records what it was asked and answers predictably.
    ///
    /// The point of the tests below is the **routing**, not the daemon's
    /// messaging — which is `kotton_msg`'s, tested there, and reached by the
    /// real implementation through the same `msg_host` the IPC arms use. What
    /// is new here, and therefore what is tested here, is that each verb lands
    /// on its own method and that each answer becomes the right reply.
    struct Spy {
        asked: std::sync::Mutex<Vec<String>>,
    }

    impl Spy {
        fn new() -> Self {
            Self {
                asked: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn note(&self, what: &str) {
            self.asked.lock().unwrap().push(what.to_string());
        }
        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }
    }

    fn sealed(id: &str) -> RunnerSealedMessage {
        RunnerSealedMessage {
            id: id.to_string(),
            thread_id: "t".into(),
            from_did: "did:key:zFrom".into(),
            to_did: Some("did:key:zTo".into()),
            channel_did: None,
            body: "Y2lwaGVy".into(),
            nonce: "bm9uY2U=".into(),
            ephemeral_pub: Some("ZXBo".into()),
            sent_at: 1,
            filed_at: 1_000,
            message_type: "text".into(),
        }
    }

    #[async_trait::async_trait]
    impl OccupantHost for Spy {
        async fn create_identity(&self, _p: &str, _n: &str) -> Result<String, RunnerAuthError> {
            unreachable!("not exercised by these tests")
        }
        async fn set_display_name(&self, _n: &str) -> Result<(), RunnerAuthError> {
            unreachable!("not exercised by these tests")
        }
        async fn unlock(&self, _p: &str) -> Result<String, RunnerAuthError> {
            unreachable!("not exercised by these tests")
        }
        async fn suggest_credential(&self) -> String {
            unreachable!("not exercised by these tests")
        }
        async fn read_identity(&self) -> Result<RunnerIdentity, RunnerAuthError> {
            unreachable!("not exercised by these tests")
        }
        async fn unlock_with_pin(&self, _u: &str, _p: &str) -> Result<String, RunnerAuthError> {
            unreachable!("not exercised by these tests")
        }
        async fn pair_start(&self, _l: Option<String>, _t: u64) -> Result<(), String> {
            unreachable!("not exercised by these tests")
        }
        async fn pair_join(&self, _c: String, _l: Option<String>) -> Result<(), String> {
            unreachable!("not exercised by these tests")
        }
        async fn pair_confirm(&self, _m: bool) -> Result<(), String> {
            unreachable!("not exercised by these tests")
        }
        async fn pair_cancel(&self) -> Result<(), String> {
            unreachable!("not exercised by these tests")
        }
        async fn list_devices(&self) -> Result<Vec<RunnerPairedDevice>, String> {
            unreachable!("not exercised by these tests")
        }
        async fn revoke_device(&self, _did: &str) -> Result<(), String> {
            unreachable!("not exercised by these tests")
        }
        async fn list_browsers(&self) -> Result<Vec<RunnerAdmittedBrowser>, String> {
            self.note("list-browsers");
            Ok(vec![RunnerAdmittedBrowser {
                name: "Austin's phone".into(),
                admitted_at: 1_790_337_600,
                last_visit: None,
            }])
        }
        async fn revoke_browser(&self, name: &str) -> Result<(), String> {
            self.note(&format!("revoke-browser {name}"));
            if name == "Austin's phone" {
                Ok(())
            } else {
                Err(format!("no browser named '{name}' is admitted"))
            }
        }

        async fn paired_relay(&self) -> Result<Option<RunnerRelay>, String> {
            self.note("paired-relay");
            Ok(Some(RunnerRelay {
                name: "droplet.austin.dev:7700".into(),
                reachable: true,
                relays_for: 2,
            }))
        }
        async fn enrolled_vaults(&self) -> Result<Vec<RunnerVault>, String> {
            self.note("enrolled-vaults");
            Ok(vec![RunnerVault {
                label: Some("Vault \u{00b7} droplet".into()),
                through: Some("droplet.austin.dev:7700".into()),
                holds: "everything".into(),
                // The two numbers a device has not been told. See
                // `TASK-a-device-never-records-what-its-vault-said-about-capacity`.
                held_bytes: None,
                bought_bytes: None,
                answering: true,
                yours: true,
                vault_name: Some("droplet".into()),
                relay_name: Some("droplet".into()),
                stands_at: Some("http://droplet.austin.dev:7700".into()),
                told_at: Some(1_790_000_000),
            }])
        }
        async fn operated_relays(&self) -> Result<Vec<kotton_wire::runner::RunnerOperatedRelay>, String> {
            self.note("operated-relays");
            Ok(vec![kotton_wire::runner::RunnerOperatedRelay {
                name: "droplet".into(),
                key: Some("ab".repeat(32)),
                address: "http://droplet.austin.dev:7700".into(),
                standing: vec!["droplet".into()],
                here: false,
            }])
        }
        async fn join_admit(&self, invite: String) -> Result<(), String> {
            self.note(&format!("admit:{invite}"));
            // An empty invite is what the daemon refuses before anything
            // starts, and the spy refuses it here so the door's *taken or
            // refused* shape is exercised in both directions.
            if invite.trim().is_empty() {
                return Err("That is empty. An invite is one line, and it begins `kotton-invite:`.".into());
            }
            Ok(())
        }
        async fn join_confirm(&self, typed: String) -> Result<(), String> {
            self.note(&format!("confirm:{typed}"));
            Ok(())
        }
        async fn join_cancel(&self) -> Result<(), String> {
            self.note("cancel");
            Ok(())
        }
        async fn join_take_relay(&self) -> Result<(), String> {
            self.note("take-relay");
            Ok(())
        }
        async fn landlord_people(&self, vault: String) -> Result<Vec<RunnerTenant>, String> {
            self.note(&format!("people:{vault}"));
            if vault != "droplet" {
                return Err(format!("this desktop holds no operator credential for '{vault}'"));
            }
            Ok(vec![RunnerTenant {
                name: "sam".into(),
                held_bytes: 12_000_000_000,
                space_bytes: Some(50_000_000_000),
                devices: 2,
            }])
        }
        async fn landlord_invite(
            &self,
            vault: String,
            name: String,
            space_bytes: u64,
        ) -> Result<String, String> {
            self.note(&format!("invite:{vault}:{name}:{space_bytes}"));
            Ok("droplet.austin.dev:7700#fame-cheap-unfold".into())
        }
        async fn landlord_drop(&self, vault: String, name: String) -> Result<(), String> {
            self.note(&format!("drop:{vault}:{name}"));
            Ok(())
        }
        async fn landlord_rule(&self, relay: String) -> Result<kotton_wire::rendezvous::AdmissionRule, String> {
            self.note(&format!("rule:{relay}"));
            Ok(kotton_wire::rendezvous::AdmissionRule::OnlyMyDevices)
        }
        async fn landlord_set_rule(
            &self,
            relay: String,
            rule: kotton_wire::rendezvous::AdmissionRule,
        ) -> Result<kotton_wire::rendezvous::AdmissionRule, String> {
            self.note(&format!("set-rule:{relay}:{rule:?}"));
            Ok(rule)
        }
        async fn landlord_resolve(&self, code: String) -> Result<kotton_wire::runner::RunnerResolved, String> {
            // What the spy notes is that a resolve came, never the code.
            self.note(&format!("resolve:{}", code.len()));
            Ok(kotton_wire::runner::RunnerResolved {
                kind: kotton_wire::runner::RunnerCodeKind::VaultInvite,
                key: None,
                hint: "relay.example:7700".into(),
                reached: false,
                completes: None,
            })
        }
        async fn landlord_enrol(&self, code: String) -> Result<kotton_wire::runner::RunnerEnrolled, String> {
            self.note(&format!("enrol:{}", code.len()));
            Ok(kotton_wire::runner::RunnerEnrolled {
                relay: true,
                name: "droplet".into(),
                not_standing: None,
                acts: Vec::new(),
                choose: Vec::new(),
            })
        }
        async fn landlord_move_vault(&self, vault: String, relay: String) -> Result<(), String> {
            self.note(&format!("move:{vault}:{relay}"));
            Ok(())
        }
        async fn operators(&self) -> Result<RunnerOperatorBox, String> {
            self.note("operators");
            Ok(RunnerOperatorBox {
                operates: true,
                operators: vec![kotton_wire::runner::RunnerOperator {
                    person: "u-austin".into(),
                    name: "Austin".into(),
                    you: true,
                }],
                others: vec![kotton_wire::runner::RunnerPerson { person: "u-ana".into(), name: "Ana".into() }],
            })
        }
        async fn operator_add(&self, person: String) -> Result<(), String> {
            self.note(&format!("operator-add:{person}"));
            Ok(())
        }
        async fn operator_remove(&self, person: String) -> Result<(), String> {
            self.note(&format!("operator-remove:{person}"));
            if person == "u-austin" {
                return Err("Austin is this device's last operator".into());
            }
            Ok(())
        }

        async fn this_device(&self) -> Result<RunnerThisDevice, String> {
            self.note("this-device");
            Ok(RunnerThisDevice {
                name: "Austin's PC".into(),
                local_reach: true,
            })
        }

        async fn message_send(
            &self,
            to_did: &str,
            body: &str,
        ) -> Result<(String, Option<String>), String> {
            self.note(&format!("send {to_did} {body}"));
            Ok(("m1".into(), Some("delivered".into())))
        }
        async fn message_share(
            &self,
            to_did: &str,
            name: &str,
            data: &[u8],
            origin: Option<&str>,
        ) -> Result<(String, Option<String>), String> {
            self.note(&format!("share {to_did} {name} {} {origin:?}", data.len()));
            Ok(("m3".into(), Some("sent".into())))
        }
        async fn message_channel_send(
            &self,
            channel_did: &str,
            _b: &str,
        ) -> Result<String, String> {
            self.note(&format!("channel-send {channel_did}"));
            Ok("m2".into())
        }
        async fn message_channel_share(
            &self,
            channel_did: &str,
            name: &str,
            data: &[u8],
            origin: Option<&str>,
        ) -> Result<String, String> {
            self.note(&format!("channel-share {channel_did} {name} {} {origin:?}", data.len()));
            Ok("m4".into())
        }
        async fn message_groups(&self) -> Result<Vec<RunnerGroup>, String> {
            self.note("groups");
            Ok(vec![RunnerGroup { channel_did: "did:key:zCh".into(), members: 3 }])
        }
        async fn message_channel_history(
            &self,
            channel_did: &str,
            _before: Option<String>,
            limit: u32,
        ) -> Result<Vec<RunnerSealedMessage>, String> {
            self.note(&format!("channel-history {channel_did} {limit}"));
            Ok(vec![sealed("h1")])
        }
        async fn message_poll_inbox(&self) -> Result<Vec<RunnerSealedMessage>, String> {
            self.note("poll-inbox");
            Ok(vec![sealed("i1")])
        }
        async fn list_contacts(&self) -> Result<Vec<RunnerContact>, String> {
            self.note("list-contacts");
            Ok(vec![RunnerContact {
                did: "did:key:zBob".into(),
                label: Some("Bob from the bakery".into()),
            }])
        }
        async fn message_open(&self, message: RunnerSealedMessage) -> Result<String, String> {
            self.note(&format!("open {}", message.id));
            Ok("the ferry leaves at 6:40".into())
        }
        async fn message_unread_count(&self) -> Result<u64, String> {
            self.note("unread-count");
            Ok(3)
        }
        async fn message_mark_read(
            &self,
            peer_did: &str,
            filed_at: u64,
            message_id: &str,
        ) -> Result<bool, String> {
            self.note(&format!("mark-read {peer_did} {filed_at} {message_id}"));
            Ok(true)
        }
        async fn message_conversation(
            &self,
            peer_did: &str,
        ) -> Result<Vec<RunnerSealedMessage>, String> {
            self.note(&format!("conversation {peer_did}"));
            Ok(vec![sealed("c2"), sealed("c1")])
        }
        async fn message_deliveries(
            &self,
            peer_did: &str,
        ) -> Result<Vec<kotton_wire::ipc::DeliveryReading>, String> {
            self.note(&format!("deliveries {peer_did}"));
            Ok(vec![kotton_wire::ipc::DeliveryReading {
                message_id: "c2".into(),
                word: "waiting at home".into(),
                retry_at: Some(1_757_000_720),
            }])
        }
        async fn message_unread_from(&self, peer_did: &str) -> Result<u64, String> {
            self.note(&format!("unread-from {peer_did}"));
            Ok(2)
        }
        async fn root_records(&self, root: &str, nsid: &str) -> Result<Vec<RunnerRecord>, String> {
            self.note(&format!("root-records {root} {nsid}"));
            if root == "not-a-member" {
                return Err("no root this person is a member of has that id".into());
            }
            Ok(vec![RunnerRecord { id: "r1".into(), data: "{}".into() }])
        }
        async fn root_add_record(&self, root: &str, nsid: &str, data: &str) -> Result<String, String> {
            self.note(&format!("root-add {root} {nsid} {data}"));
            Ok("r2".into())
        }
        async fn app_holdings(&self, app_id: &str) -> Result<Vec<HeldShape>, String> {
            self.note(&format!("app-holdings {app_id}"));
            if app_id != "sh.kotton.editor" {
                return Err(format!("{app_id} is not installed"));
            }
            // The editor's `documents`, bound by the person to `/work` rather
            // than the manifest's `/documents`.
            Ok(vec![HeldShape {
                holding: RunnerHolding {
                    shape: Some("documents".into()),
                    label: "Your documents".into(),
                    writable: true,
                },
                target: "/work".into(),
            }])
        }
        async fn file_openers(&self) -> Result<Vec<RunnerOpener>, String> {
            self.note("file-openers");
            Ok(vec![RunnerOpener { app_nsid: "sh.kotton.editor".into(), name: "Editor".into() }])
        }
    }

    /// **The occupant asks what another app holds, and is told the shape and
    /// never the place.** `held-by` lands on the host with the app named;
    /// `covering` answers *yes, through Your documents* for a file under the
    /// bound folder and for the folder itself, and *no* for a file beside it,
    /// for a name that merely starts the same, and for the manifest's own
    /// default, which the person moved it away from. No reply carries the
    /// folder the person chose, and an app that is not installed is an answer
    /// rather than a dropped instance.
    #[tokio::test]
    async fn the_occupant_is_told_what_another_app_holds_by_shape_and_never_by_path() {
        let spy = Spy::new();
        let ask = |verb| service_host_call(RunnerHostCall::Grants { verb }, Some(&spy), None, None);

        let documents = RunnerHolding {
            shape: Some("documents".into()),
            label: "Your documents".into(),
            writable: true,
        };
        let held = ask(RunnerGrantVerb::HeldBy { app_nsid: "sh.kotton.editor".into() })
            .await
            .expect("serviced");
        assert!(
            matches!(&held, RunnerHostReply::GrantHoldings { holdings } if holdings == &vec![documents.clone()]),
            "{held:?}"
        );
        let wire = serde_json::to_string(&held).expect("the reply serializes");
        assert!(!wire.contains("/work"), "the folder the person chose crossed to the guest: {wire}");

        for (path, expected) in [
            ("/work/trip.md", Some(documents.clone())),
            ("/work", Some(documents.clone())),
            ("/work/../work/deep/notes.md", Some(documents.clone())),
            ("/workshop/trip.md", None),
            ("/photos/trip.md", None),
            ("/documents/trip.md", None),
            ("/work/../photos/trip.md", None),
        ] {
            let reply = ask(RunnerGrantVerb::Covering {
                app_nsid: "sh.kotton.editor".into(),
                path: path.into(),
            })
            .await
            .expect("serviced");
            assert!(
                matches!(&reply, RunnerHostReply::GrantCovering { holding } if *holding == expected),
                "{path}: {reply:?}"
            );
            let wire = serde_json::to_string(&reply).expect("the reply serializes");
            assert!(!wire.contains("/work"), "{path}: the bound folder crossed: {wire}");
        }

        let unknown = ask(RunnerGrantVerb::HeldBy { app_nsid: "sh.kotton.nothing".into() })
            .await
            .expect("an unknown app is an answer, not a fault");
        assert!(
            matches!(&unknown, RunnerHostReply::GrantFailed { message } if message.contains("not installed")),
            "{unknown:?}"
        );
    }

    /// **The occupant asks which apps a file can be opened in, and is told
    /// ids and names.** `opens-files` lands on the host's one rule
    /// ([`app_file_openers`] in the daemon) and the reply carries nothing a
    /// shape, a label or a folder could ride in.
    #[tokio::test]
    async fn the_occupant_is_told_which_apps_open_a_file_by_id_and_name() {
        let spy = Spy::new();
        let reply = service_host_call(
            RunnerHostCall::Grants { verb: RunnerGrantVerb::OpensFiles },
            Some(&spy),
            None,
            None,
        )
        .await
        .expect("serviced");
        assert_eq!(
            reply,
            RunnerHostReply::GrantOpeners {
                openers: vec![RunnerOpener { app_nsid: "sh.kotton.editor".into(), name: "Editor".into() }],
            }
        );
        assert_eq!(spy.asked(), vec!["file-openers".to_owned()]);
    }

    /// **An app that is not the occupant cannot ask what another app holds.**
    /// Its linker has no `kotton:app/grants` (the sandbox's half, held in
    /// `kotton-wasm`), and this is the daemon's half: a grants frame from a
    /// runner not spawned as the occupant is a bug in the boundary, so it
    /// drops the instance and reaches no host at all.
    #[tokio::test]
    async fn a_grants_frame_from_a_non_occupant_drops_the_instance() {
        for verb in [
            RunnerGrantVerb::HeldBy { app_nsid: "sh.kotton.editor".into() },
            RunnerGrantVerb::Covering {
                app_nsid: "sh.kotton.editor".into(),
                path: "/work/trip.md".into(),
            },
            RunnerGrantVerb::OpensFiles,
        ] {
            let err = service_host_call(RunnerHostCall::Grants { verb: verb.clone() }, None, None, None)
                .await
                .expect_err("a non-occupant grants frame must not be serviced");
            assert!(err.to_string().contains("not the occupant"), "{verb:?}: {err}");
        }
    }

    /// **A root's records reach the occupant host, and a refusal is an answer.**
    /// Both records verbs land on their own methods with the root and schema
    /// the guest named; a root the person is not in comes back as
    /// `RecordFailed` rather than dropping the instance, because the frame is
    /// one the occupant's world can make; and the same frame from a guest that
    /// is not the occupant is the confinement bug every occupant frame is.
    #[tokio::test]
    async fn a_roots_records_reach_the_occupant_host_and_nothing_else() {
        let spy = Spy::new();
        let ask = |verb| service_host_call(RunnerHostCall::Records { verb }, Some(&spy), None, None);

        match ask(RunnerRecordVerb::List { root: "fam".into(), nsid: "sh.kotton.calendar".into() })
            .await
            .unwrap()
        {
            RunnerHostReply::RecordList { records } => assert_eq!(records[0].id, "r1"),
            other => panic!("unexpected: {other:?}"),
        }
        match ask(RunnerRecordVerb::Add {
            root: "fam".into(),
            nsid: "sh.kotton.calendar".into(),
            data: "{\"title\":\"x\"}".into(),
        })
        .await
        .unwrap()
        {
            RunnerHostReply::RecordAdded { id } => assert_eq!(id, "r2"),
            other => panic!("unexpected: {other:?}"),
        }
        match ask(RunnerRecordVerb::List {
            root: "not-a-member".into(),
            nsid: "sh.kotton.calendar".into(),
        })
        .await
        .unwrap()
        {
            RunnerHostReply::RecordFailed { .. } => {}
            other => panic!("a non-member root was answered: {other:?}"),
        }
        assert_eq!(
            spy.asked(),
            vec![
                "root-records fam sh.kotton.calendar",
                "root-add fam sh.kotton.calendar {\"title\":\"x\"}",
                "root-records not-a-member sh.kotton.calendar",
            ]
        );

        let err = service_host_call(
            RunnerHostCall::Records {
                verb: RunnerRecordVerb::List { root: "fam".into(), nsid: "sh.kotton.calendar".into() },
            },
            None,
            None,
            None,
        )
        .await;
        assert!(err.is_err(), "a records frame from a non-occupant was serviced");
    }

    /// **The Devices screen's browser verbs reach the occupant host and nothing
    /// else** (`TASK-the-devices-screen-does-not-list-admitted-browsers`).
    ///
    /// Both frames are answered by the host the designated shell is handed —
    /// the list as a name and two dates, a revoke as done or refused with the
    /// daemon's reason — and the same frame from an instance handed no occupant
    /// host is not serviced at all: an ordinary app cannot read the list or
    /// revoke from it, whatever frame it writes.
    #[tokio::test]
    async fn the_browser_verbs_reach_the_occupant_host_and_nothing_else() {
        let spy = Spy::new();
        let ask = |verb| service_host_call(RunnerHostCall::Devices { verb }, Some(&spy), None, None);

        match ask(RunnerDeviceVerb::ListBrowsers).await.unwrap() {
            RunnerHostReply::Browsers { browsers } => {
                assert_eq!(browsers.len(), 1);
                assert_eq!(browsers[0].name, "Austin's phone");
            }
            other => panic!("unexpected: {other:?}"),
        }
        match ask(RunnerDeviceVerb::RevokeBrowser { name: "Austin's phone".into() }).await.unwrap() {
            RunnerHostReply::DeviceOk => {}
            other => panic!("unexpected: {other:?}"),
        }
        match ask(RunnerDeviceVerb::RevokeBrowser { name: "a stranger".into() }).await.unwrap() {
            RunnerHostReply::DeviceFailed { message } => assert!(message.contains("a stranger"), "{message}"),
            other => panic!("a refused revoke was answered as done: {other:?}"),
        }
        assert_eq!(
            spy.asked(),
            vec!["list-browsers", "revoke-browser Austin's phone", "revoke-browser a stranger"]
        );

        for verb in [
            RunnerDeviceVerb::ListBrowsers,
            RunnerDeviceVerb::RevokeBrowser { name: "Austin's phone".into() },
        ] {
            let err = service_host_call(RunnerHostCall::Devices { verb }, None, None, None).await;
            assert!(err.is_err(), "a browser frame from a non-occupant was serviced: {err:?}");
        }
    }

    /// **A person's kept records reach any instance through the records host,
    /// and the occupant is not asked** (`schema.kept`, RFC-0071 R17; RFC-0088
    /// phase two).
    ///
    /// The frame is answered with no occupant at all — the records app is an
    /// ordinary app — and never reaches the occupant host even where there is
    /// one, because it is not a root verb. A refusal from the store is an
    /// answer the guest draws, not a dropped instance; and an instance
    /// launched for nobody, which has no records host, is told so rather than
    /// dropped.
    #[tokio::test]
    async fn kept_records_are_answered_for_any_instance_and_never_by_the_occupant() {
        struct Kept(std::sync::Mutex<Vec<String>>);
        #[async_trait::async_trait]
        impl RecordsHost for Kept {
            async fn kept_records(&self, nsid: &str) -> Result<Vec<RunnerKeptRecord>, String> {
                self.0.lock().unwrap().push(nsid.to_owned());
                if nsid == "sh.kotton.refused" {
                    return Err("the store would not open".into());
                }
                Ok(vec![RunnerKeptRecord {
                    id: "RFC-0088".into(),
                    data: "{}".into(),
                    root: "Kotton".into(),
                }])
            }
        }
        let kept = Kept(std::sync::Mutex::new(Vec::new()));
        let spy = Spy::new();
        let nsid = "sh.kotton.governance.record";

        // No occupant: an ordinary app.
        match service_host_call(RunnerHostCall::Kept { nsid: nsid.into() }, None, None, Some(&kept))
            .await
            .expect("a kept-records frame from an ordinary app is serviced")
        {
            RunnerHostReply::RecordsKept { records } => {
                assert_eq!(records[0].root, "Kotton");
            }
            other => panic!("unexpected: {other:?}"),
        }
        // With an occupant present, it is still the records host that answers.
        service_host_call(RunnerHostCall::Kept { nsid: nsid.into() }, Some(&spy), None, Some(&kept))
            .await
            .expect("serviced");
        assert!(spy.asked().is_empty(), "the occupant host was asked for kept records");
        match service_host_call(
            RunnerHostCall::Kept { nsid: "sh.kotton.refused".into() },
            None,
            None,
            Some(&kept),
        )
        .await
        .expect("a refusal is an answer")
        {
            RunnerHostReply::RecordFailed { message } => assert!(message.contains("would not open")),
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(*kept.0.lock().unwrap(), vec![nsid, nsid, "sh.kotton.refused"]);

        // Nobody's instance: no host, and an answer rather than a dropped instance.
        match service_host_call(RunnerHostCall::Kept { nsid: nsid.into() }, None, None, None)
            .await
            .expect("an instance with no person is answered, not dropped")
        {
            RunnerHostReply::RecordFailed { .. } => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    async fn call(spy: &Spy, verb: RunnerMessageVerb) -> RunnerHostReply {
        service_host_call(RunnerHostCall::Messages { verb }, Some(spy), None, None)
            .await
            .expect("an occupant's messaging frame is serviced")
    }

    /// Each verb reaches its own method, and each answer becomes its own reply.
    #[tokio::test]
    async fn every_messaging_verb_lands_on_its_own_method() {
        let spy = Spy::new();

        match call(
            &spy,
            RunnerMessageVerb::Send {
                to_did: "did:key:zTo".into(),
                body: "hello".into(),
            },
        )
        .await
        {
            RunnerHostReply::MessageSent { id, delivery } => {
                assert_eq!(id, "m1");
                assert_eq!(delivery.as_deref(), Some("delivered"));
            }
            other => panic!("send: {other:?}"),
        }

        match call(
            &spy,
            RunnerMessageVerb::Share {
                to_did: "did:key:zTo".into(),
                name: "beach.jpg".into(),
                data: vec![1, 2, 3],
                origin: Some("Photos/beach.jpg".into()),
            },
        )
        .await
        {
            RunnerHostReply::MessageSent { id, delivery } => {
                assert_eq!(id, "m3");
                assert_eq!(delivery.as_deref(), Some("sent"));
            }
            other => panic!("share: {other:?}"),
        }

        match call(
            &spy,
            RunnerMessageVerb::ChannelSend {
                channel_did: "did:key:zCh".into(),
                body: "hi".into(),
            },
        )
        .await
        {
            RunnerHostReply::MessageSent { id, delivery } => {
                assert_eq!(id, "m2");
                assert_eq!(
                    delivery, None,
                    "a channel message is not delivered to one person, so there is no \
                     word to give the sender"
                );
            }
            other => panic!("channel-send: {other:?}"),
        }

        match call(
            &spy,
            RunnerMessageVerb::ChannelShare {
                channel_did: "did:key:zCh".into(),
                name: "beach.jpg".into(),
                data: vec![1, 2, 3],
                origin: Some("Photos/beach.jpg".into()),
            },
        )
        .await
        {
            RunnerHostReply::MessageSent { id, delivery } => {
                assert_eq!(id, "m4");
                assert_eq!(delivery, None, "a share to a group has no one word, as a channel message has none");
            }
            other => panic!("channel-share: {other:?}"),
        }
        assert!(
            spy.asked().iter().any(|c| c == "channel-share did:key:zCh beach.jpg 3 Some(\"Photos/beach.jpg\")"),
            "{:?}",
            spy.asked()
        );

        match call(&spy, RunnerMessageVerb::Groups).await {
            RunnerHostReply::MessageGroups { groups } => {
                assert_eq!(groups, vec![RunnerGroup { channel_did: "did:key:zCh".into(), members: 3 }]);
            }
            other => panic!("groups: {other:?}"),
        }

        match call(
            &spy,
            RunnerMessageVerb::ChannelHistory {
                channel_did: "did:key:zCh".into(),
                before_id: None,
                limit: 20,
            },
        )
        .await
        {
            RunnerHostReply::MessageList { messages } => assert_eq!(messages[0].id, "h1"),
            other => panic!("channel-history: {other:?}"),
        }

        match call(&spy, RunnerMessageVerb::PollInbox).await {
            RunnerHostReply::MessageList { messages } => assert_eq!(messages[0].id, "i1"),
            other => panic!("poll-inbox: {other:?}"),
        }

        match call(
            &spy,
            RunnerMessageVerb::Open {
                message: sealed("i1"),
            },
        )
        .await
        {
            RunnerHostReply::MessageOpened { text } => {
                assert_eq!(text, "the ferry leaves at 6:40")
            }
            other => panic!("open: {other:?}"),
        }

        match call(&spy, RunnerMessageVerb::UnreadCount).await {
            RunnerHostReply::MessageUnread { count } => assert_eq!(count, 3),
            other => panic!("unread-count: {other:?}"),
        }

        // The whole position crosses — both halves: the filing stamp that
        // orders, and the id that names which message the mark is at.
        match call(
            &spy,
            RunnerMessageVerb::MarkRead {
                peer_did: "did:key:zFrom".into(),
                filed_at: 1_757_000_000_123,
                message_id: "i1".into(),
            },
        )
        .await
        {
            RunnerHostReply::MessageRead { moved } => assert!(moved),
            other => panic!("mark-read: {other:?}"),
        }

        // The conversation window's three reads cross whole: both directions of
        // one conversation, the one word per sent message with its retry, and
        // that conversation's own unread count (`TASK-messages-is-the-drawn-one`).
        match call(&spy, RunnerMessageVerb::Conversation { peer_did: "did:key:zSam".into() }).await {
            RunnerHostReply::MessageList { messages } => {
                assert_eq!(messages.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), vec!["c2", "c1"])
            }
            other => panic!("conversation: {other:?}"),
        }
        match call(&spy, RunnerMessageVerb::Deliveries { peer_did: "did:key:zSam".into() }).await {
            RunnerHostReply::MessageDeliveries { readings } => {
                assert_eq!(readings.len(), 1);
                assert_eq!(readings[0].message_id, "c2");
                assert_eq!(readings[0].word, "waiting at home");
                assert_eq!(readings[0].retry_at, Some(1_757_000_720));
            }
            other => panic!("deliveries: {other:?}"),
        }
        match call(&spy, RunnerMessageVerb::UnreadFrom { peer_did: "did:key:zSam".into() }).await {
            RunnerHostReply::MessageUnread { count } => assert_eq!(count, 2),
            other => panic!("unread-from: {other:?}"),
        }

        assert_eq!(
            spy.asked(),
            vec![
                "send did:key:zTo hello",
                "share did:key:zTo beach.jpg 3 Some(\"Photos/beach.jpg\")",
                "channel-send did:key:zCh",
                "channel-share did:key:zCh beach.jpg 3 Some(\"Photos/beach.jpg\")",
                "groups",
                "channel-history did:key:zCh 20",
                "poll-inbox",
                "open i1",
                "unread-count",
                "mark-read did:key:zFrom 1757000000123 i1",
                "conversation did:key:zSam",
                "deliveries did:key:zSam",
                "unread-from did:key:zSam",
            ],
            "each verb reached its own method, in order, with its own arguments"
        );
    }

    /// Contacts is read-only across the boundary, and this pins that there is
    /// nothing else to reach: one verb, one method, and no write.
    #[tokio::test]
    async fn contacts_is_one_read_and_nothing_else() {
        let spy = Spy::new();
        match service_host_call(
            RunnerHostCall::Contacts {
                verb: RunnerContactVerb::List,
            },
            Some(&spy),
            None,
            None,
        )
        .await
        .expect("an occupant's contacts frame is serviced")
        {
            RunnerHostReply::ContactList { contacts } => {
                assert_eq!(contacts.len(), 1);
                assert_eq!(contacts[0].did, "did:key:zBob");
                assert_eq!(contacts[0].label.as_deref(), Some("Bob from the bakery"));
            }
            other => panic!("list-contacts: {other:?}"),
        }
        assert_eq!(spy.asked(), vec!["list-contacts"]);
    }

    /// **The occupant reads its relay, its vaults and this device, each on its
    /// own verb.**
    ///
    /// Three verbs and not one record, because the three fail apart: a relay
    /// that will not answer says nothing about whether a vault is enrolled.
    /// This is the door itself — the same function every occupant frame is
    /// serviced through — so what it proves is that the readout is reachable
    /// from `world occupant` and that each answer becomes its own reply.
    #[tokio::test]
    async fn the_occupant_reads_its_relay_its_vaults_and_this_device() {
        let spy = Spy::new();
        let ask = |verb| service_host_call(RunnerHostCall::Network { verb }, Some(&spy), None, None);

        match ask(RunnerNetworkVerb::PairedRelay).await.expect("serviced") {
            RunnerHostReply::NetworkRelay { relay } => {
                let relay = relay.expect("a relay is paired");
                assert_eq!(relay.name, "droplet.austin.dev:7700");
                assert!(relay.reachable);
                assert_eq!(relay.relays_for, 2);
            }
            other => panic!("paired-relay: {other:?}"),
        }
        match ask(RunnerNetworkVerb::EnrolledVaults)
            .await
            .expect("serviced")
        {
            RunnerHostReply::NetworkVaults { vaults } => {
                assert_eq!(vaults.len(), 1);
                assert_eq!(
                    vaults[0].through.as_deref(),
                    Some("droplet.austin.dev:7700")
                );
                assert_eq!(vaults[0].holds, "everything");
                assert!(vaults[0].answering);
                // Not zero. A capacity nobody has asked for is unknown, and the
                // wire says so rather than reporting a number it never read.
                assert_eq!(vaults[0].held_bytes, None);
                assert_eq!(vaults[0].bought_bytes, None);
            }
            other => panic!("enrolled-vaults: {other:?}"),
        }
        match ask(RunnerNetworkVerb::ThisDevice).await.expect("serviced") {
            RunnerHostReply::NetworkDevice { device } => {
                assert_eq!(device.name, "Austin's PC");
                assert!(device.local_reach);
            }
            other => panic!("this-device: {other:?}"),
        }
        assert_eq!(
            spy.asked(),
            vec!["paired-relay", "enrolled-vaults", "this-device"]
        );
    }

    /// **The occupant joins a network, pairs a relay and enrols a vault.**
    ///
    /// The three doors of Settings › Networking, driven through the same
    /// function every occupant frame is serviced through — so what this proves
    /// is that each one is reachable from `world occupant` and that the thing
    /// the person typed arrives at the host unchanged.
    ///
    /// **One verb behind one door.** An invite pasted at *Paste a code* sends
    /// `Admit`; the six digits and a cancel follow it.
    #[tokio::test]
    async fn the_occupant_joins_a_network_pairs_a_relay_and_enrols_a_vault() {
        let spy = Spy::new();
        let ask = |verb| service_host_call(RunnerHostCall::Joining { verb }, Some(&spy), None, None);
        let invite = "kotton-invite:vault:<key>:fame-cheap-unfold:<relay key>@http://droplet.austin.dev:7700";

        // An invite pasted at the door — a vault, met at its relay.
        match ask(RunnerJoinVerb::Admit { invite: SecretText::new(invite) })
            .await
            .expect("serviced")
        {
            RunnerHostReply::JoinOk => {}
            other => panic!("admit: {other:?}"),
        }
        // The six digits, typed — and carried to the host as typed, since the
        // host is what compares them.
        match ask(RunnerJoinVerb::Confirm { typed: "042 137".to_owned() })
            .await
            .expect("serviced")
        {
            RunnerHostReply::JoinOk => {}
            other => panic!("confirm: {other:?}"),
        }
        // The yes to the relay the admit offered, which names nothing.
        match ask(RunnerJoinVerb::TakeRelay).await.expect("serviced") {
            RunnerHostReply::JoinOk => {}
            other => panic!("take-relay: {other:?}"),
        }
        match ask(RunnerJoinVerb::Cancel).await.expect("serviced") {
            RunnerHostReply::JoinOk => {}
            other => panic!("cancel: {other:?}"),
        }
        assert_eq!(
            spy.asked(),
            vec![
                format!("admit:{invite}"),
                "confirm:042 137".to_owned(),
                "take-relay".to_owned(),
                "cancel".to_owned(),
            ]
        );
    }

    /// **A verb refused before it starts comes back as a refusal, not a fault.**
    ///
    /// The distinction the whole family is shaped around: `JoinFailed` is data
    /// the guest receives and draws as a Notice, and an `Err` out of
    /// `service_host_call` drops the instance. A wrong name is the person's,
    /// not the boundary's, so it must be the first of the two.
    #[tokio::test]
    async fn an_invite_that_is_not_one_is_refused_rather_than_dropping_the_instance() {
        let spy = Spy::new();
        match service_host_call(
            RunnerHostCall::Joining {
                verb: RunnerJoinVerb::Admit { invite: SecretText::new("   ") },
            },
            Some(&spy),
            None,
            None,
        )
        .await
        .expect("a refused verb is still serviced")
        {
            RunnerHostReply::JoinFailed { message } => {
                assert!(message.contains("empty"), "{message}");
            }
            other => panic!("admit with nothing in it: {other:?}"),
        }
    }

    /// **A joining frame from a guest that is not the occupant drops it.**
    ///
    /// The second half of *possession of the world is the enforcement*, held to
    /// the same rule as a network frame and for a sharper reason: these three
    /// verbs act. A frame arriving from a runner that was not spawned as the
    /// occupant is a bug in the confinement boundary, and a reply that let it
    /// continue would be the boundary's failure servicing its own consequence.
    #[tokio::test]
    async fn a_joining_frame_from_a_non_occupant_drops_the_instance() {
        for verb in [
            RunnerJoinVerb::Admit {
                invite: SecretText::new("droplet.austin.dev:7700#fame-cheap-unfold"),
            },
            RunnerJoinVerb::Confirm { typed: "042137".to_owned() },
            RunnerJoinVerb::Cancel,
            RunnerJoinVerb::TakeRelay,
        ] {
            let err = service_host_call(RunnerHostCall::Joining { verb: verb.clone() }, None, None, None)
                .await
                .expect_err("an occupant frame from a non-occupant is a boundary bug");
            assert!(
                err.to_string().contains("not the occupant"),
                "the refusal should name what went wrong, got: {err}"
            );
        }
    }

    /// **The landlord's three verbs reach the host as the person asked them.**
    ///
    /// *People on this network*, *Invite…* and a drop, driven through the one
    /// function every occupant frame is serviced through: each arrives with
    /// the vault, the name and the number the pane sent, unchanged, and each
    /// answer comes back in its own reply. A vault this person holds no
    /// credential for is a refusal the guest draws, not a dropped instance.
    #[tokio::test]
    async fn the_occupant_asks_its_box_who_it_keeps_for_invites_one_and_drops_one() {
        let spy = Spy::new();
        let ask = |verb| service_host_call(RunnerHostCall::Landlord { verb }, Some(&spy), None, None);

        match ask(RunnerLandlordVerb::People { vault: "droplet".into() })
            .await
            .expect("serviced")
        {
            RunnerHostReply::LandlordPeople { tenants } => {
                assert_eq!(tenants.len(), 1);
                assert_eq!(tenants[0].name, "sam");
                assert_eq!(tenants[0].space_bytes, Some(50_000_000_000));
            }
            other => panic!("people: {other:?}"),
        }
        match ask(RunnerLandlordVerb::Invite {
            vault: "droplet".into(),
            name: "priya".into(),
            space_bytes: 25_000_000_000,
        })
        .await
        .expect("serviced")
        {
            RunnerHostReply::LandlordInvite { invite } => {
                assert_eq!(invite.expose(), "droplet.austin.dev:7700#fame-cheap-unfold");
            }
            other => panic!("invite: {other:?}"),
        }
        match ask(RunnerLandlordVerb::DropPool {
            vault: "droplet".into(),
            name: "sam".into(),
        })
        .await
        .expect("serviced")
        {
            RunnerHostReply::LandlordOk => {}
            other => panic!("drop: {other:?}"),
        }
        match ask(RunnerLandlordVerb::People { vault: "attic".into() })
            .await
            .expect("a refused verb is still serviced")
        {
            RunnerHostReply::LandlordFailed { message } => {
                assert!(message.contains("no operator credential"), "{message}");
            }
            other => panic!("people at a host with no credential: {other:?}"),
        }
        assert_eq!(
            spy.asked(),
            vec![
                "people:droplet".to_owned(),
                "invite:droplet:priya:25000000000".to_owned(),
                "drop:droplet:sam".to_owned(),
                "people:attic".to_owned(),
            ]
        );
    }

    /// **A landlord's frame from a guest that is not the occupant drops it.**
    ///
    /// The same rule as a joining frame, for the sharpest reason on this
    /// channel: these change who a vault keeps for. A runner that was not spawned
    /// as the occupant has no `kotton:app/landlord` in its linker, so a frame
    /// from it is a boundary bug and is not serviced.
    #[tokio::test]
    async fn a_landlord_frame_from_a_non_occupant_drops_the_instance() {
        for verb in [
            RunnerLandlordVerb::People { vault: "droplet".into() },
            RunnerLandlordVerb::Invite {
                vault: "droplet".into(),
                name: "priya".into(),
                space_bytes: 1,
            },
            RunnerLandlordVerb::DropPool {
                vault: "droplet".into(),
                name: "sam".into(),
            },
        ] {
            let err = service_host_call(RunnerHostCall::Landlord { verb }, None, None, None)
                .await
                .expect_err("an occupant frame from a non-occupant is a boundary bug");
            assert!(err.to_string().contains("not the occupant"), "{err}");
        }
    }

    /// **The door's verbs reach the occupant's host and no one else's, and the
    /// pasted code is never printed** (`TASK-settings-has-one-door-and-it-takes-a-code`).
    /// A resolve, an enrol and a move from the occupant are serviced, each in its
    /// own reply; from a runner that was not spawned as the occupant they drop
    /// the instance, as every landlord frame does — there is no door to guard
    /// there, because there is no function. And the frame that carries a code,
    /// printed as a log or an error would print it, shows `<redacted>`.
    #[tokio::test]
    async fn the_door_is_the_occupants_alone_and_never_prints_the_code() {
        const CODE: &str = "relay.example:7700#fame-cheap-unfold";
        let spy = Spy::new();
        let ask = |verb| service_host_call(RunnerHostCall::Landlord { verb }, Some(&spy), None, None);
        let secret = || kotton_wire::ipc::SecretText::new(CODE);
        match ask(RunnerLandlordVerb::Resolve { code: secret() }).await.expect("serviced") {
            RunnerHostReply::LandlordResolved { resolved } => {
                assert_eq!(resolved.kind, kotton_wire::runner::RunnerCodeKind::VaultInvite)
            }
            other => panic!("resolve: {other:?}"),
        }
        match ask(RunnerLandlordVerb::Enrol { code: secret() }).await.expect("serviced") {
            RunnerHostReply::LandlordEnrolled { enrolled } => assert_eq!(enrolled.name, "droplet"),
            other => panic!("enrol: {other:?}"),
        }
        match ask(RunnerLandlordVerb::MoveVault { vault: "droplet".into(), relay: "attic".into() }).await.expect("serviced") {
            RunnerHostReply::LandlordOk => {}
            other => panic!("move: {other:?}"),
        }
        assert_eq!(
            spy.asked(),
            vec![format!("resolve:{}", CODE.len()), format!("enrol:{}", CODE.len()), "move:droplet:attic".to_owned()]
        );
        for verb in [
            RunnerLandlordVerb::Resolve { code: secret() },
            RunnerLandlordVerb::Enrol { code: secret() },
            RunnerLandlordVerb::MoveVault { vault: "droplet".into(), relay: "attic".into() },
        ] {
            let printed = format!("{:?}", RunnerHostCall::Landlord { verb: verb.clone() });
            assert!(!printed.contains("fame-cheap-unfold"), "{printed}");
            let err = service_host_call(RunnerHostCall::Landlord { verb }, None, None, None)
                .await
                .expect_err("an occupant frame from a non-occupant is a boundary bug");
            assert!(err.to_string().contains("not the occupant"), "{err}");
        }
    }

    /// **This machine's operators reach the host as the person asked them**
    /// (`TASK-this-devices-operators-box-speaks-to-kdeviced-under-the-persons-own-key`):
    /// read, add and remove each reach the occupant host with the person the
    /// guest named and nothing else, and a refusal — the last operator — is an
    /// answer the guest draws, not a dropped instance.
    #[tokio::test]
    async fn the_occupant_reads_adds_and_removes_this_machines_operators() {
        let spy = Spy::new();
        let ask = |verb| service_host_call(RunnerHostCall::Operators { verb }, Some(&spy), None, None);
        match ask(RunnerOperatorVerb::Read).await.expect("serviced") {
            RunnerHostReply::OperatorBox { operators } => {
                assert!(operators.operates);
                assert_eq!(operators.others[0].name, "Ana");
            }
            other => panic!("read: {other:?}"),
        }
        assert!(matches!(
            ask(RunnerOperatorVerb::Add { person: "u-ana".into() }).await.expect("serviced"),
            RunnerHostReply::OperatorsOk
        ));
        assert!(matches!(
            ask(RunnerOperatorVerb::Remove { person: "u-ana".into() }).await.expect("serviced"),
            RunnerHostReply::OperatorsOk
        ));
        match ask(RunnerOperatorVerb::Remove { person: "u-austin".into() }).await.expect("a refusal is serviced") {
            RunnerHostReply::OperatorsFailed { message } => assert!(message.contains("last"), "{message}"),
            other => panic!("the last: {other:?}"),
        }
        assert_eq!(
            spy.asked(),
            vec![
                "operators".to_owned(),
                "operator-add:u-ana".to_owned(),
                "operator-remove:u-ana".to_owned(),
                "operator-remove:u-austin".to_owned(),
            ]
        );
    }

    /// **An operators frame from a guest that is not the occupant drops it** —
    /// the landlord's rule, for the same reason: these change who may run this
    /// machine, and a runner that was not spawned as the occupant has no
    /// `kotton:app/operators` in its linker to have asked with.
    #[tokio::test]
    async fn an_operators_frame_from_a_non_occupant_drops_the_instance() {
        for verb in [
            RunnerOperatorVerb::Read,
            RunnerOperatorVerb::Add { person: "u-ana".into() },
            RunnerOperatorVerb::Remove { person: "u-ana".into() },
        ] {
            let err = service_host_call(RunnerHostCall::Operators { verb }, None, None, None)
                .await
                .expect_err("an occupant frame from a non-occupant is a boundary bug");
            assert!(err.to_string().contains("not the occupant"), "{err}");
        }
    }

    /// **A guest that is not the occupant cannot reach the readout.**
    ///
    /// The enforcement is possession of the world — an ordinary app's linker
    /// has no `kotton:app/network` in it, so it does not instantiate — and this
    /// is the second half of that: a frame arriving from a runner that was not
    /// spawned as the occupant is a bug in the confinement boundary, so it
    /// drops the instance rather than being serviced. Held to the same rule as
    /// a contacts frame, and for the same reason.
    #[tokio::test]
    async fn a_network_frame_from_a_non_occupant_drops_the_instance() {
        for verb in [
            RunnerNetworkVerb::PairedRelay,
            RunnerNetworkVerb::EnrolledVaults,
            RunnerNetworkVerb::ThisDevice,
        ] {
            let err = service_host_call(RunnerHostCall::Network { verb: verb.clone() }, None, None, None)
                .await
                .expect_err("a non-occupant network frame must not be serviced");
            assert!(
                err.to_string().contains("not the occupant"),
                "{verb:?}: {err}"
            );
        }
    }

    /// A contacts frame is held to the same rule as a messaging one.
    #[tokio::test]
    async fn a_contacts_frame_from_a_non_occupant_drops_the_instance() {
        let err = service_host_call(
            RunnerHostCall::Contacts {
                verb: RunnerContactVerb::List,
            },
            None,
            None,
            None,
        )
        .await
        .expect_err("a non-occupant contacts frame must not be serviced");
        assert!(err.to_string().contains("not the occupant"), "{err}");
    }

    /// A guest may say what to open, and may not say who the app is.
    ///
    /// The keys `app_launch` fills in from the session — `mode`, `users`,
    /// `did`, `display_name`, and the window `name` the caller passes
    /// separately — are dropped from what a confined guest asked for. It fills
    /// them in only when absent, so a guest that could name one would be
    /// writing a fact about the *person's* session: `mode=welcome` puts first
    /// run in front of someone who already has an identity, and `did=` tells
    /// the launched app it is running as somebody else.
    #[test]
    fn a_guest_cannot_author_the_launch_arguments_the_host_owns() {
        let args = super::guest_launch_args(
            Some("Editor".to_owned()),
            vec![
                ("path".to_owned(), "notes/trip.md".to_owned()),
                ("mode".to_owned(), "welcome".to_owned()),
                ("did".to_owned(), "did:key:zSomeoneElse".to_owned()),
                ("display_name".to_owned(), "someone-else".to_owned()),
                ("users".to_owned(), "a,b".to_owned()),
                ("names".to_owned(), "Someone\u{1f}Else".to_owned()),
                ("name".to_owned(), "Not the editor".to_owned()),
            ],
            true,
        );

        assert_eq!(
            args,
            vec![
                ("name".to_owned(), "Editor".to_owned()),
                ("path".to_owned(), "notes/trip.md".to_owned()),
            ],
            "a host-authored key survived a guest-requested launch: {args:?}"
        );
    }

    /// And the ordinary case still carries what it is for.
    #[test]
    fn a_guest_launch_carries_the_path_it_asked_for() {
        let args = super::guest_launch_args(
            None,
            vec![("path".to_owned(), "trip-2026.md".to_owned())],
            true,
        );
        assert_eq!(args, vec![("path".to_owned(), "trip-2026.md".to_owned())]);
    }

    /// **The powerbox rule: a path is the occupant's word, and nobody else's.**
    ///
    /// A `path` that survives `guest_launch_args` becomes a grant —
    /// `hand_over_picked_file` mints the launched app a while-open capability
    /// on that file — so an ordinary confined app asking for one would be
    /// minting itself a capability on a file it never declared and the person
    /// never picked. It is stripped here rather than refused at the mint,
    /// because stripping also stops the launched app being *told* a path it
    /// holds no grant on. The rest of the launch survives: refusing it outright
    /// would let a guest deny a person their own editor by asking wrongly.
    #[test]
    fn a_path_from_a_guest_that_is_not_the_occupant_is_stripped() {
        let args = super::guest_launch_args(
            Some("Editor".to_owned()),
            vec![
                ("path".to_owned(), "photos/receipts.md".to_owned()),
                ("theme".to_owned(), "light".to_owned()),
            ],
            false,
        );
        assert_eq!(
            args,
            vec![
                ("name".to_owned(), "Editor".to_owned()),
                ("theme".to_owned(), "light".to_owned()),
            ],
            "a non-occupant guest handed another app a file: {args:?}"
        );
    }

    /// **The confinement rule, and the reason this test exists.**
    ///
    /// A messaging frame from a guest that is not the occupant is not answered
    /// with a refusal — it is an `Err`, which drops the instance. A runner that
    /// emits a call its guest's world cannot make is a bug in the boundary, and
    /// a bug in a confinement boundary must fail loudly rather than be
    /// serviced. Same rule `Auth` and `Devices` are held to.
    #[tokio::test]
    async fn a_messaging_frame_from_a_non_occupant_drops_the_instance() {
        // The conversation window's three reads are held to the same rule by
        // the same line — no verb of their own is checked, because none needs
        // to be (`TASK-messages-is-the-drawn-one`): no guest reads a list of
        // who this person talks to.
        let peer = || "did:key:zSam".to_string();
        for verb in [
            RunnerMessageVerb::PollInbox,
            RunnerMessageVerb::Conversation { peer_did: peer() },
            RunnerMessageVerb::Deliveries { peer_did: peer() },
            RunnerMessageVerb::UnreadFrom { peer_did: peer() },
        ] {
            let err = service_host_call(RunnerHostCall::Messages { verb: verb.clone() }, None, None, None)
                .await
                .expect_err("a non-occupant messaging frame must not be serviced");
            assert!(
                err.to_string().contains("not the occupant"),
                "the error must say what happened for {verb:?}: {err}"
            );
        }
    }

    /// **The window list is the host's view, and the id is this instance's name for it.**
    ///
    /// RFC-0087 stage 3b's trap, as an assertion: nothing a guest supplied is in the list,
    /// and the handle — the value every surface wire is addressed by — does not leave the
    /// daemon. A designated app learns three things about a window and no fourth.
    #[test]
    fn a_window_list_carries_the_hosts_words_and_never_a_handle() {
        let a = SurfaceHandle::mint();
        let b = SurfaceHandle::mint();
        let mut shown = Vec::new();

        let views = window_views(
            &mut shown,
            vec![
                kotton_wire::HostWindow {
                    handle: a,
                    name: "Notes".into(),
                    title: Some("Shopping".into()),
                    minimised: false,
                },
                kotton_wire::HostWindow {
                    handle: b,
                    name: "Messages".into(),
                    title: None,
                    minimised: true,
                },
            ],
        );

        assert_eq!(views.len(), 2);
        assert_eq!(views[0].id, 1, "ids count from 1, so 0 names nothing");
        assert_eq!(views[0].name, "Notes");
        // The holder's own title travels beside the host's name, and neither stands in for
        // the other: a window that has said nothing carries `None` rather than its name.
        assert_eq!(views[0].title.as_deref(), Some("Shopping"));
        assert_eq!(views[1].name, "Messages");
        assert_eq!(views[1].title, None);
        assert!(!views[0].minimised);
        assert_eq!(views[1].id, 2);
        assert!(views[1].minimised);

        // Nothing in what crosses to the guest spells a handle.
        let json = serde_json::to_string(&views).unwrap();
        for handle in [a, b] {
            assert!(
                !json.contains(&handle.to_string()),
                "a window list that carries a handle hands one app a name for another \
                 app's surface: {json}"
            );
        }
    }

    /// An id is stable across asks and is never handed to a second window.
    ///
    /// Both halves matter, and the second is the sharp one: a list that renumbered from the
    /// current stack would give a closed window's id to whatever took its place, and the
    /// next `raise-window` would bring back somebody else's window. That is stage 3a's
    /// ordinal defect — *a freed slot given to the next push* — one level up.
    #[test]
    fn an_id_is_stable_across_asks_and_is_never_reused() {
        let a = SurfaceHandle::mint();
        let b = SurfaceHandle::mint();
        let c = SurfaceHandle::mint();
        let win = |h: SurfaceHandle, name: &str| kotton_wire::HostWindow {
            handle: h,
            name: name.into(),
            title: None,
            minimised: false,
        };
        let mut shown = Vec::new();

        let first = window_views(&mut shown, vec![win(a, "a"), win(b, "b")]);
        assert_eq!(first.iter().map(|w| w.id).collect::<Vec<_>>(), vec![1, 2]);

        // `a` closes and `c` opens. `b` keeps the id it had; `c` gets a new one.
        let second = window_views(&mut shown, vec![win(b, "b"), win(c, "c")]);
        assert_eq!(second[0].id, 2, "b keeps the id it was given");
        assert_eq!(second[1].id, 3, "c is a new window and gets a new id");
        assert_eq!(
            window_handle(&shown, 1),
            Some(a),
            "the id of the window that closed still names it, and nothing else"
        );
    }

    /// An id this instance was never given names nothing.
    ///
    /// The whole of the confinement on `raise-window`: there is no handle on that wire to
    /// guess at, and an id is resolved against the asking instance's own list — so there is
    /// no window outside the list it was shown that an id can reach.
    #[test]
    fn an_id_the_instance_was_never_given_names_nothing() {
        let a = SurfaceHandle::mint();
        let shown = vec![a];

        assert_eq!(window_handle(&shown, 1), Some(a));
        assert_eq!(window_handle(&shown, 0), None, "0 is not the first window");
        assert_eq!(window_handle(&shown, 2), None);
        assert_eq!(window_handle(&shown, u64::MAX), None);
        assert_eq!(window_handle(&[], 1), None);
    }

    /// The window-list nudge goes to the designated instance and to nobody else
    /// (`TASK-the-docks-window-list-is-as-stale-as-its-last-repaint`).
    ///
    /// The frame is empty, so *when* is all it says — and when some other app's window
    /// opened is a clock an ordinary guest must not be handed. An undesignated instance
    /// is never addressed, however many are live; with no designated one, nobody is; with
    /// two, nobody is either, and the count comes back to be logged.
    #[test]
    fn the_window_nudge_is_addressed_to_the_designated_instance_alone() {
        use super::nudged;
        assert_eq!(
            nudged([("app.editor", false), ("sh.kotton.shell", true), ("app.notes", false)].into_iter()),
            Ok(Some("sh.kotton.shell"))
        );
        assert_eq!(
            nudged([("app.editor", false), ("app.notes", false)].into_iter()),
            Ok(None),
            "no designated instance, no nudge — not the first live one"
        );
        assert_eq!(nudged(std::iter::empty()), Ok(None));
        // Never more than one, whatever the map holds: a bug elsewhere that marked two
        // instances designated is refused and counted, not resolved by picking one.
        assert_eq!(nudged([("b.second", true), ("a.first", true)].into_iter()), Err(2));
    }

    /// Every verb `layer-surface` carries needs the designation, and the one `world app`
    /// carries does not.
    ///
    /// The audit arm's rule, read as a list. A verb added to that interface without being
    /// added here would be serviced for any app whose runner emitted it — which is the one
    /// thing this arm exists to stop.
    #[test]
    fn only_the_designated_worlds_verbs_need_the_designation() {
        assert!(!needs_the_designation(&RunnerSurfaceVerb::Create {
            role: kotton_wire::SurfaceRole::Window,
            edge: None,
            width: 1,
            height: 1,
        }));
        for role in [
            kotton_wire::SurfaceRole::Background,
            kotton_wire::SurfaceRole::Panel,
        ] {
            assert!(needs_the_designation(&RunnerSurfaceVerb::Create {
                role,
                edge: None,
                width: 1,
                height: 1,
            }));
        }
        assert!(needs_the_designation(&RunnerSurfaceVerb::ListWindows));
        assert!(needs_the_designation(&RunnerSurfaceVerb::RaiseWindow {
            window: 1
        }));
        // Giving a surface back and asking again for a size are both `surface`'s, which
        // every app's world carries: the designation decides what may be *created*, not
        // what may be said about a surface an app already holds.
        assert!(!needs_the_designation(&RunnerSurfaceVerb::Close {
            surface: SurfaceHandle::mint()
        }));
        assert!(!needs_the_designation(&RunnerSurfaceVerb::Resize {
            surface: SurfaceHandle::mint(),
            width: 1,
            height: 1,
        }));
    }

    /// A host that records the surface calls it is handed, and refuses everything else.
    ///
    /// Everything the surface verbs do not touch is `unreachable!`, which is this module's
    /// own idiom (see [`Spy`]): a double that answered a question the code under test never
    /// asks is a double that can make the test pass for the wrong reason.
    #[derive(Default)]
    struct SurfaceSpy {
        opened: std::sync::Mutex<Vec<kotton_wire::SurfaceHandle>>,
        closed: std::sync::Mutex<Vec<kotton_wire::SurfaceHandle>>,
        resized: std::sync::Mutex<Vec<(kotton_wire::SurfaceHandle, u32, u32)>>,
        titled: std::sync::Mutex<Vec<(kotton_wire::SurfaceHandle, String)>>,
    }

    impl SurfaceSpy {
        fn closed(&self) -> Vec<kotton_wire::SurfaceHandle> {
            self.closed.lock().unwrap().clone()
        }
        fn resized(&self) -> Vec<(kotton_wire::SurfaceHandle, u32, u32)> {
            self.resized.lock().unwrap().clone()
        }
        fn titled(&self) -> Vec<(kotton_wire::SurfaceHandle, String)> {
            self.titled.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl AppHost for SurfaceSpy {
        fn events(&self) -> &Arc<EventBus> {
            unreachable!("not exercised by these tests")
        }
        fn registered_users(&self) -> Vec<RegisteredUser> {
            unreachable!("not exercised by these tests")
        }
        fn secrets(&self) -> &dyn SecretsStore {
            unreachable!("not exercised by these tests")
        }
        fn runner(&self) -> &Path {
            unreachable!("not exercised by these tests")
        }
        /// No store behind this double, so no roots — which is a fact about
        /// this host and not an empty set (RFC-0071 R11).
        fn user_roots(&self, _: &Path, _: &str, _: &str) -> Result<Vec<RunnerRoot>, RootsUnread> {
            Err(RootsUnread::StoreNotLoaded)
        }
        /// This double stands for a host whose person is in with keys; the
        /// launch tests here are about grants, bodies and surfaces.
        fn keys_loaded(&self, _: &str) -> bool {
            true
        }
        /// No store behind this double, so no person's tree either.
        fn personal_tree(&self, _: &str) -> Option<Arc<dyn PersonalTree>> {
            None
        }
        async fn surface_open(
            &self,
            handle: SurfaceHandle,
            _app_id: &str,
            _spec: kotton_wire::SurfaceSpec,
        ) {
            self.opened.lock().unwrap().push(handle);
        }
        async fn surface_commit(&self, _handle: SurfaceHandle, _patch: Vec<u8>) {
            unreachable!("not exercised by these tests")
        }
        async fn surface_close(&self, handle: SurfaceHandle) {
            self.closed.lock().unwrap().push(handle);
        }
        async fn surface_resize(&self, handle: SurfaceHandle, width: u32, height: u32) {
            self.resized.lock().unwrap().push((handle, width, height));
        }
        async fn surface_set_title(&self, handle: SurfaceHandle, title: String) {
            self.titled.lock().unwrap().push((handle, title));
        }
        async fn surface_raise(&self, _handle: SurfaceHandle) {
            unreachable!("not exercised by these tests")
        }
        async fn surface_windows(&self) -> Vec<kotton_wire::HostWindow> {
            unreachable!("not exercised by these tests")
        }
        async fn surface_restore(&self, _handle: SurfaceHandle) {
            unreachable!("not exercised by these tests")
        }
    }

    /// An instance that holds `surfaces` and has been shown no windows.
    ///
    /// The whole of what a surface verb is entitled to see ([`InstanceSurfaces`]) — which is
    /// the point: before that type existed this took a `LongLivedInstance`, and a
    /// `LongLivedInstance` owns a child process, so none of the audits below could be
    /// reached without spawning a runner.
    fn asking<'a>(
        surfaces: &'a mut Vec<SurfaceHandle>,
        shown: &'a mut Vec<SurfaceHandle>,
        designated: bool,
    ) -> InstanceSurfaces<'a> {
        InstanceSurfaces {
            surfaces,
            windows_shown: shown,
            app_id: "sh.kotton.shell",
            title: "Kotton",
            designated,
        }
    }

    /// **A size is asked for on a surface this instance holds, or the host never hears it.**
    ///
    /// `surface.request-size` was a stub on the host's side until
    /// `TASK-the-dock-is-its-pill-and-the-band-beside-it-is-nothing` made the dock's width
    /// real, and the audit it gained is the one `Close` has: the guest holds a `resource`
    /// and cannot write a handle, but the runner is a separate process, so the daemon
    /// declines to take that process's word for which surface is being named. Without it a
    /// runner bug would be one app resizing another app's dock.
    ///
    /// The refusal is answered to the guest rather than dropping the instance, because a
    /// handle is not an authority claim — it is a mistake, and nothing is revealed by
    /// saying so.
    #[tokio::test]
    async fn a_resize_reaches_the_host_only_for_a_surface_this_instance_holds() {
        let host = SurfaceSpy::default();
        let mine = SurfaceHandle::mint();
        let somebody_elses = SurfaceHandle::mint();
        let mut surfaces = vec![mine];
        let mut shown = Vec::new();

        let reply = service_surface_call(
            RunnerSurfaceVerb::Resize {
                surface: mine,
                width: 620,
                height: 64,
            },
            &mut asking(&mut surfaces, &mut shown, true),
            &host,
        )
        .await
        .expect("a held surface is not a confinement-boundary bug");
        assert!(
            matches!(reply, RunnerHostReply::SurfaceResized),
            "a held surface's ask is forwarded: {reply:?}"
        );
        assert_eq!(
            host.resized(),
            vec![(mine, 620, 64)],
            "the numbers the guest named, unchanged — the compositor does the clamping"
        );

        let reply = service_surface_call(
            RunnerSurfaceVerb::Resize {
                surface: somebody_elses,
                width: 4096,
                height: 64,
            },
            &mut asking(&mut surfaces, &mut shown, true),
            &host,
        )
        .await
        .expect("naming a surface you do not hold is a mistake, not a boundary bug");
        match reply {
            RunnerHostReply::SurfaceFailed { message } => assert!(
                message.contains("does not hold that surface"),
                "the refusal says what was wrong: {message}"
            ),
            other => panic!("a surface this instance does not hold was resized: {other:?}"),
        }
        assert_eq!(
            host.resized(),
            vec![(mine, 620, 64)],
            "**the host never saw it** — the audit is before the forward, not after"
        );
        assert_eq!(
            surfaces,
            vec![mine],
            "a resize is not a close: the list is the same either way"
        );

        // And it is not the designation doing the work. An ordinary app holds `surface`,
        // so an undesignated instance may ask for a size on a surface it holds — the audit
        // above is about *which* surface, which is the only question here.
        let reply = service_surface_call(
            RunnerSurfaceVerb::Resize {
                surface: mine,
                width: 700,
                height: 64,
            },
            &mut asking(&mut surfaces, &mut shown, false),
            &host,
        )
        .await
        .expect("`surface` is in every app's world");
        assert!(matches!(reply, RunnerHostReply::SurfaceResized));
        assert_eq!(host.resized().len(), 2);
    }

    /// **A title is set on a surface this instance holds, or the host never hears it.**
    ///
    /// The same audit `Resize` and `Close` carry, on the verb where it is sharpest: a
    /// title is *text the person reads in a title bar*, so a runner bug that let one app
    /// name another app's surface would be one app writing words into somebody else's
    /// window — which is the one thing a title must never be able to do, and the reason
    /// `set-title` is a verb on the resource rather than a function taking a handle.
    #[tokio::test]
    async fn a_title_reaches_the_host_only_for_a_surface_this_instance_holds() {
        let host = SurfaceSpy::default();
        let mine = SurfaceHandle::mint();
        let somebody_elses = SurfaceHandle::mint();
        let mut surfaces = vec![mine];
        let mut shown = Vec::new();

        let reply = service_surface_call(
            RunnerSurfaceVerb::SetTitle {
                surface: mine,
                title: "Files \u{2014} Documents".into(),
            },
            &mut asking(&mut surfaces, &mut shown, true),
            &host,
        )
        .await
        .expect("a held surface is not a confinement-boundary bug");
        assert!(
            matches!(reply, RunnerHostReply::SurfaceTitled),
            "a held surface's title is forwarded: {reply:?}"
        );
        assert_eq!(
            host.titled(),
            vec![(mine, "Files \u{2014} Documents".to_owned())],
            "the characters the guest wrote, unchanged — the host decides how they are drawn"
        );

        let reply = service_surface_call(
            RunnerSurfaceVerb::SetTitle {
                surface: somebody_elses,
                title: "Settings".into(),
            },
            &mut asking(&mut surfaces, &mut shown, true),
            &host,
        )
        .await
        .expect("naming a surface you do not hold is a mistake, not a boundary bug");
        match reply {
            RunnerHostReply::SurfaceFailed { message } => assert!(
                message.contains("does not hold that surface"),
                "the refusal says what was wrong: {message}"
            ),
            other => panic!("a surface this instance does not hold was titled: {other:?}"),
        }
        assert_eq!(
            host.titled().len(),
            1,
            "**the host never saw it** — the audit is before the forward, not after"
        );

        // And it is not the designation doing the work. `surface.set-title` is in every
        // app's world, so an undesignated instance may title a surface it holds: the
        // designation decides which *layers* may exist, not what an app may say about a
        // window it already has.
        let reply = service_surface_call(
            RunnerSurfaceVerb::SetTitle {
                surface: mine,
                title: "Terminal".into(),
            },
            &mut asking(&mut surfaces, &mut shown, false),
            &host,
        )
        .await
        .expect("`surface` is in every app's world");
        assert!(matches!(reply, RunnerHostReply::SurfaceTitled));
        assert_eq!(host.titled().len(), 2);
        assert!(!needs_the_designation(&RunnerSurfaceVerb::SetTitle {
            surface: mine,
            title: String::new(),
        }));
    }

    /// **A title is cut to the host's bound before anything holds it.**
    ///
    /// The bound is the host's business and not the guest's, so the string is cut where the
    /// handle is resolved — the first process on this path that a confined one is not —
    /// rather than where it is drawn. Without that, `kuserd` would store whatever length a
    /// guest chose, in a map every window list is built from, and a loop calling
    /// `set-title` would be a confined app deciding how much of the daemon's memory a
    /// window costs.
    ///
    /// **Characters, not bytes, and nothing appended.** A bound counted in bytes would mean
    /// a different number of letters in every script, and cutting mid-character would hand
    /// the compositor something that is not a string. An ellipsis would be the host writing
    /// a character the guest did not, into the one field whose rule is that the guest
    /// supplies the characters — and the bar already truncates visually, in CSS, at
    /// whatever width the window actually is.
    #[tokio::test]
    async fn a_title_is_cut_to_the_hosts_bound_and_never_mid_character() {
        let host = SurfaceSpy::default();
        let mine = SurfaceHandle::mint();
        let mut surfaces = vec![mine];
        let mut shown = Vec::new();

        // Four bytes per character, so a byte-counted bound would cut inside one.
        let long: String = "\u{1f5c2}".repeat(kotton_wire::MAX_TITLE_CHARS + 40);
        let reply = service_surface_call(
            RunnerSurfaceVerb::SetTitle {
                surface: mine,
                title: long.clone(),
            },
            &mut asking(&mut surfaces, &mut shown, true),
            &host,
        )
        .await
        .expect("a long title is not a boundary bug");
        assert!(matches!(reply, RunnerHostReply::SurfaceTitled), "{reply:?}");

        let (_, kept) = host.titled().pop().expect("the host was told");
        assert_eq!(
            kept.chars().count(),
            kotton_wire::MAX_TITLE_CHARS,
            "the bound is counted in characters"
        );
        assert!(
            kept.starts_with('\u{1f5c2}'),
            "it is still a string: {kept:?}"
        );
        assert!(long.starts_with(&kept), "nothing was added, only cut");

        // A title already inside the bound crosses untouched — the cut is a bound, not a
        // format.
        let short = "Files \u{2014} Documents";
        service_surface_call(
            RunnerSurfaceVerb::SetTitle {
                surface: mine,
                title: short.into(),
            },
            &mut asking(&mut surfaces, &mut shown, true),
            &host,
        )
        .await
        .expect("a short title is not a boundary bug");
        assert_eq!(host.titled().pop().expect("told").1, short);
    }

    /// **The same audit on `Close`, which is where it was written first and has never been
    /// tested.**
    ///
    /// It could not be: the dispatch took a `LongLivedInstance`, which owns a running
    /// child, so reaching four lines about a `Vec` meant spawning a runner. It is here now
    /// because [`InstanceSurfaces`] exists, and it is here rather than only on `Resize`
    /// because the two are one rule and a rule tested on one of its two sites is a rule
    /// half held.
    #[tokio::test]
    async fn a_close_reaches_the_host_only_for_a_surface_this_instance_holds() {
        let host = SurfaceSpy::default();
        let mine = SurfaceHandle::mint();
        let somebody_elses = SurfaceHandle::mint();
        let mut surfaces = vec![mine];
        let mut shown = Vec::new();

        let reply = service_surface_call(
            RunnerSurfaceVerb::Close {
                surface: somebody_elses,
            },
            &mut asking(&mut surfaces, &mut shown, true),
            &host,
        )
        .await
        .expect("naming a surface you do not hold is a mistake, not a boundary bug");
        assert!(matches!(reply, RunnerHostReply::SurfaceFailed { .. }));
        assert!(host.closed().is_empty(), "the host never saw it");
        assert_eq!(
            surfaces,
            vec![mine],
            "and nothing was taken off this instance's list"
        );

        let reply = service_surface_call(
            RunnerSurfaceVerb::Close { surface: mine },
            &mut asking(&mut surfaces, &mut shown, true),
            &host,
        )
        .await
        .expect("a held surface is not a confinement-boundary bug");
        assert!(matches!(reply, RunnerHostReply::SurfaceReleased));
        assert_eq!(host.closed(), vec![mine]);
        assert!(
            surfaces.is_empty(),
            "the cap is counted on this list, so a close that did not shorten it would be              an app charged for a surface it gave back"
        );
    }
}

// ---------------------------------------------------------------------------
// One shell, one body
// ---------------------------------------------------------------------------

/// The designated shell runs from the copy the system staged, and from nothing else.
///
/// The defect these pin
/// (`TASK-the-drawn-ground-shows-for-a-second-and-the-relaunched-desk-is-flat`) was two
/// bodies of one program: `system/shell/`, rebuilt by every `cargo xtask build-apps`, and
/// `apps/sh.kotton.shell/app.wasm`, written into the user's collection the day their
/// identity was born and never rewritten. The welcome and the lock screen ran the first;
/// the relaunch as the person ran the second. What the owner saw was a desk painting the
/// previous day's stylesheet, and what the tests saw was a rule that drew correctly in a
/// document nobody's desk was made of.
#[cfg(test)]
mod one_shell_tests {
    use super::*;
    use kotton_sys::secret::SecretsResult;

    const SHELL: &str = "sh.kotton.shell";

    /// A manifest for `id`, distinguishable by `version`.
    fn manifest(id: &str, version: &str) -> String {
        format!(
            "[app]\n\
             id      = \"{id}\"\n\
             name    = \"Kotton\"\n\
             version = \"{version}\"\n\
             kind    = \"long-lived\"\n\
             role    = \"shell\"\n\
             \n\
             [capabilities]\n\
             \"events.subscribe\" = [\"*\"]\n"
        )
    }

    /// A base directory with a **stale** registry body and a **fresh** staged one —
    /// the machine the owner was looking at.
    fn two_bodies(app_id: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path();

        let staged = base.join("system").join("shell");
        std::fs::create_dir_all(&staged).expect("staged dir");
        std::fs::write(staged.join("app.wasm"), b"the shell that was just built")
            .expect("staged wasm");
        std::fs::write(staged.join("manifest.toml"), manifest(app_id, "0.2.0"))
            .expect("staged manifest");

        let installed = base.join("apps").join(app_id);
        std::fs::create_dir_all(&installed).expect("registry dir");
        std::fs::write(
            installed.join("app.wasm"),
            b"the shell from the day the identity was born",
        )
        .expect("registry wasm");
        std::fs::write(installed.join("manifest.toml"), manifest(app_id, "0.1.0"))
            .expect("registry manifest");

        tmp
    }

    #[tokio::test]
    async fn the_designated_shell_resolves_to_the_body_the_system_staged() {
        let tmp = two_bodies(SHELL);
        let (wasm, manifest_path) = designated_shell_body(tmp.path(), SHELL, true)
            .await
            .expect("the staged shell is the designated app, so it is the body");

        assert_eq!(
            PathBuf::from(&wasm),
            system_shell_dir(tmp.path()).join("app.wasm"),
            "the body is the staged copy `cargo xtask build-apps` writes"
        );
        assert_eq!(
            manifest_path,
            system_shell_dir(tmp.path()).join("manifest.toml"),
            "and the manifest is the one beside it — a manifest read from the other copy \
             would tell the runner what a different binary declared"
        );
        assert_ne!(
            PathBuf::from(&wasm),
            wasm_path_for(tmp.path(), SHELL),
            "which is not the second body in the user's app collection"
        );
    }

    /// The designation is the person's, and a shell they chose is not swapped for ours.
    ///
    /// `RFC-0087`: `sh.kotton.shell` holds the role because it ships as the default,
    /// "point it at something else and that becomes the desktop". Matching the staged
    /// manifest's own `app.id` is what keeps *one artifact* from quietly meaning *our
    /// artifact*.
    #[tokio::test]
    async fn a_shell_the_person_chose_themselves_keeps_its_own_body() {
        let tmp = two_bodies("com.acme.desktop");
        // The staged copy is ours; the designated app is theirs.
        std::fs::write(
            system_shell_dir(tmp.path()).join("manifest.toml"),
            manifest(SHELL, "0.2.0"),
        )
        .expect("staged manifest");

        assert!(
            designated_shell_body(tmp.path(), "com.acme.desktop", true)
                .await
                .is_none(),
            "the app the person designated is not the app the system staged, so the \
             system's body must not be substituted for theirs"
        );
    }

    #[tokio::test]
    async fn an_app_that_holds_no_designation_is_never_redirected() {
        let tmp = two_bodies(SHELL);
        assert!(
            designated_shell_body(tmp.path(), SHELL, false)
                .await
                .is_none(),
            "the redirect is the shell's, and `designated` is the one reading of \
             `app_roles` that says whether this launch is the shell's"
        );
        assert!(
            designated_shell_body(tmp.path(), "sh.kotton.editor", true)
                .await
                .is_none(),
            "and a different app id finds no staged copy of itself"
        );
    }

    /// A machine that staged nothing keeps the only body it has.
    ///
    /// Not a fallback the stale case can reach: the stale case is a staged copy that is
    /// present and *newer*. This is a machine with no welcome screen either —
    /// [`app_launch_system_shell`] refuses on the same two conditions.
    #[tokio::test]
    async fn nothing_staged_leaves_the_registrys_body_alone() {
        let tmp = two_bodies(SHELL);
        std::fs::remove_file(system_shell_dir(tmp.path()).join("app.wasm")).expect("rm wasm");
        assert!(
            designated_shell_body(tmp.path(), SHELL, true)
                .await
                .is_none(),
            "a manifest with no binary beside it is a half-staged install, not a body"
        );

        std::fs::remove_dir_all(system_shell_dir(tmp.path())).expect("rm staged");
        assert!(
            designated_shell_body(tmp.path(), SHELL, true)
                .await
                .is_none(),
            "and a machine that staged nothing has one body, which is the registry's"
        );
    }

    // ── The launch itself ────────────────────────────────────────────────────

    struct NoSecrets;

    impl SecretsStore for NoSecrets {
        fn get_secret(&self, _k: &str) -> SecretsResult<Option<String>> {
            Ok(None)
        }
        fn set_secret(&self, _k: &str, _v: &str) -> SecretsResult<()> {
            Ok(())
        }
        fn delete_secret(&self, _k: &str) -> SecretsResult<()> {
            Ok(())
        }
    }

    /// A host that answers the four questions `app_launch` asks before it spawns, and
    /// hands it a runner that writes down what it was told.
    ///
    /// `secrets` and `tree` are the two answers a hand-off needs: a key to sign the
    /// grant with, and the person's tree to say what a path names. A launch with
    /// neither hands nothing over.
    ///
    /// `keys_loaded` is whether the person's store holds their keys; `false`
    /// stands for a session whose store was opened without them, the launch
    /// that is demoted to the lock screen with a `notice`.
    ///
    /// `surfaces` is every surface it was asked to open or close, in order.
    struct LaunchHost {
        events: Arc<EventBus>,
        secrets: Box<dyn SecretsStore>,
        runner: PathBuf,
        tree: Option<Arc<dyn PersonalTree>>,
        keys_loaded: bool,
        surfaces: std::sync::Mutex<Vec<SurfaceCall>>,
    }

    /// One surface call a [`LaunchHost`] was handed.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SurfaceCall {
        Opened(SurfaceHandle),
        Closed(SurfaceHandle),
    }

    // Read only by the unix-only test of a second launch, which stands a shell in for the
    // first instance.
    #[cfg(unix)]
    impl LaunchHost {
        fn surface_calls(&self) -> Vec<SurfaceCall> {
            self.surfaces.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl AppHost for LaunchHost {
        fn events(&self) -> &Arc<EventBus> {
            &self.events
        }
        fn registered_users(&self) -> Vec<RegisteredUser> {
            vec![RegisteredUser {
                user_id: "owner".to_owned(),
                display_name: None,
            }]
        }
        fn secrets(&self) -> &dyn SecretsStore {
            self.secrets.as_ref()
        }
        fn runner(&self) -> &Path {
            &self.runner
        }
        /// No store behind this double, so no roots — which is a fact about
        /// this host and not an empty set (RFC-0071 R11).
        fn user_roots(&self, _: &Path, _: &str, _: &str) -> Result<Vec<RunnerRoot>, RootsUnread> {
            Err(RootsUnread::StoreNotLoaded)
        }
        fn keys_loaded(&self, _: &str) -> bool {
            self.keys_loaded
        }
        /// The person's tree when the test seeded one, and none otherwise.
        fn personal_tree(&self, _: &str) -> Option<Arc<dyn PersonalTree>> {
            self.tree.clone()
        }
        async fn surface_open(
            &self,
            handle: SurfaceHandle,
            _app_id: &str,
            _spec: kotton_wire::SurfaceSpec,
        ) {
            self.surfaces.lock().unwrap().push(SurfaceCall::Opened(handle));
        }
        async fn surface_commit(&self, _handle: SurfaceHandle, _patch: Vec<u8>) {}
        async fn surface_close(&self, handle: SurfaceHandle) {
            self.surfaces.lock().unwrap().push(SurfaceCall::Closed(handle));
        }
        async fn surface_resize(&self, _handle: SurfaceHandle, _width: u32, _height: u32) {}
        async fn surface_set_title(&self, _handle: SurfaceHandle, _title: String) {}
        async fn surface_raise(&self, _handle: SurfaceHandle) {}
        async fn surface_windows(&self) -> Vec<kotton_wire::HostWindow> {
            vec![]
        }
        async fn surface_restore(&self, _handle: SurfaceHandle) {}
    }

    /// A user database holding what the relaunch reads: the shell installed, and the
    /// person's own `app_roles` row designating it.
    async fn registry_with_stale_shell(stale_wasm: &Path) -> Arc<SqlitePool> {
        let pool = SqlitePool::connect(":memory:").await.expect("in-memory db");
        sqlx::query(
            "CREATE TABLE app_registry (
                app_id        TEXT PRIMARY KEY,
                name          TEXT NOT NULL,
                version       TEXT NOT NULL,
                capabilities  TEXT NOT NULL,
                wasm_path     TEXT NOT NULL,
                installed_at  TEXT NOT NULL,
                wasm_hash     TEXT NOT NULL,
                approved_json TEXT
             )",
        )
        .execute(&pool)
        .await
        .expect("create app_registry");
        sqlx::query("CREATE TABLE app_roles (role TEXT PRIMARY KEY, app_id TEXT NOT NULL)")
            .execute(&pool)
            .await
            .expect("create app_roles");

        let db = Arc::new(pool);
        ardb::insert_app(
            &db,
            SHELL,
            "Kotton",
            "0.1.0",
            "[]",
            &stale_wasm.to_string_lossy(),
            "2026-09-01T00:00:00Z",
            "deadbeef",
            "[]",
        )
        .await
        .expect("install the shell the way an identity's birth did");
        role_db::set_role(&db, "shell", SHELL)
            .await
            .expect("the person designates their shell");
        db
    }

    /// **The relaunch as the person runs the staged body, not the registry's.**
    ///
    /// The whole record in one assertion: a base with a stale registry body and a fresh
    /// staged one, `app_launch` driven for the app the person designated `shell`, and the
    /// `wasm_path` the runner is handed read back. Before this change it was
    /// `apps/sh.kotton.shell/app.wasm` — the copy no rebuild reaches — and the launch
    /// succeeded, which is why no test caught it.
    ///
    /// Read off [`prepare_launch`], the value `app_launch` hands `spawn_and_present`,
    /// rather than off a runner double's stdin. It was a `/bin/sh` script until
    /// 2026-09-23, when the runner came to be spawned under the operating system's
    /// confinement (`confine_runner`, `DEC-0074`): a script's interpreter is outside the
    /// runner's profile, so the double could no longer start, and on a platform with a
    /// sandbox the double is not the thing to widen.
    #[tokio::test]
    async fn app_launch_hands_the_runner_the_staged_shell() {
        let tmp = two_bodies(SHELL);
        let base = tmp.path();

        let db = registry_with_stale_shell(&wasm_path_for(base, SHELL)).await;
        let host = LaunchHost {
            events: Arc::new(EventBus::with_default_capacity()),
            secrets: Box::new(NoSecrets),
            runner: base.join("no-runner-is-spawned"),
            tree: None,
            keys_loaded: true,
            surfaces: Default::default(),
        };

        // The relaunch after the unlock: the person is in, and the app is theirs.
        let prepared = prepare_launch(
            &host,
            &db,
            base,
            SHELL.to_owned(),
            vec![],
            Some("owner".to_owned()),
        )
        .await
        .expect("the launch is prepared");
        let PreparedLaunch::Run { input, .. } = prepared else {
            panic!("the shell has a body, so its launch is a runner and not a bare event");
        };

        assert_eq!(
            PathBuf::from(&input.wasm_path),
            system_shell_dir(base).join("app.wasm"),
            "the designated shell runs the staged body — the one a rebuild reaches"
        );
        assert_ne!(
            PathBuf::from(&input.wasm_path),
            wasm_path_for(base, SHELL),
            "and never the registry's second copy, which is where the desk's stylesheet \
             came from for as long as the identity had existed"
        );
        assert!(
            input.manifest_toml.contains("0.2.0"),
            "the manifest is the staged one too: the runner is told what the binary it \
             is about to run declares, not what the other copy declared"
        );
        assert!(
            input.occupant,
            "and it is instantiated as the occupant, from the same `app_roles` reading \
             that chose the body"
        );
    }

    // ── The screen keys are the shell's ──────────────────────────────────────

    /// A machine whose shell is staged and designated, with the editor installed
    /// beside it and one person registered (`LaunchHost`'s `owner`).
    async fn the_shell_and_the_editor_installed() -> (tempfile::TempDir, Arc<SqlitePool>) {
        let tmp = two_bodies(SHELL);
        let base = tmp.path();
        let db = registry_with_stale_shell(&wasm_path_for(base, SHELL)).await;
        let dir = base.join("apps").join(EDITOR);
        std::fs::create_dir_all(&dir).expect("the editor's directory");
        std::fs::write(dir.join("app.wasm"), b"the editor").expect("its body");
        std::fs::write(dir.join("manifest.toml"), EDITOR_MANIFEST).expect("its manifest");
        ardb::insert_app(
            &db,
            EDITOR,
            "Editor",
            "0.1.0",
            "[]",
            &wasm_path_for(base, EDITOR).to_string_lossy(),
            "2026-09-25T00:00:00Z",
            "",
            "[]",
        )
        .await
        .expect("the editor is installed");
        (tmp, db)
    }

    /// The arguments the runner is told to call `app_id`'s `on-launch` with,
    /// for a launch for `user_id` on a host whose person's keys are or are not
    /// loaded.
    async fn told_on_launch(
        base: &Path,
        db: &Arc<SqlitePool>,
        app_id: &str,
        user_id: Option<&str>,
        keys_loaded: bool,
    ) -> Vec<(String, String)> {
        let host = LaunchHost {
            events: Arc::new(EventBus::with_default_capacity()),
            secrets: Box::new(NoSecrets),
            runner: base.join("no-runner-is-spawned"),
            tree: None,
            keys_loaded,
            surfaces: Default::default(),
        };
        let prepared = prepare_launch(
            &host,
            db,
            base,
            app_id.to_owned(),
            vec![],
            user_id.map(str::to_owned),
        )
        .await
        .expect("the launch is prepared");
        let PreparedLaunch::Run { input, launch_args, .. } = prepared else {
            panic!("{app_id} has a body, so its launch is a runner and not a bare event");
        };
        let RunnerOp::Launch { launch_args: told, .. } = input.op else {
            panic!("a launch is a launch op");
        };
        assert_eq!(told, launch_args, "the runner and the presenter are told the same list");
        told
    }

    fn value<'a>(args: &'a [(String, String)], key: &str) -> Option<&'a str> {
        args.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// **The lock screen's roster is handed to the shell and to no other app.**
    ///
    /// Nobody holds a session and somebody is registered: the screen is the lock
    /// screen. The designated shell's launch carries `mode=locked`, the `users`
    /// it unlocks and the `names` it greets them by. The editor, launched on the
    /// same screen, is told none of the three: who is registered on this device
    /// is not an argument to an app that does not draw the screen. With a
    /// session, the shell is told `authenticated` and the editor still no
    /// `mode`.
    #[tokio::test]
    async fn the_lock_screens_roster_is_handed_to_the_shell_and_to_no_other_app() {
        let (tmp, db) = the_shell_and_the_editor_installed().await;
        let base = tmp.path();

        let shell = told_on_launch(base, &db, SHELL, None, true).await;
        assert_eq!(value(&shell, "mode"), Some("locked"), "{shell:?}");
        assert_eq!(value(&shell, "users"), Some("owner"), "{shell:?}");
        assert_eq!(
            value(&shell, "names"),
            Some(""),
            "one empty name for the one person with none: {shell:?}"
        );

        let editor = told_on_launch(base, &db, EDITOR, None, true).await;
        for key in ["mode", "users", "names"] {
            assert_eq!(
                value(&editor, key),
                None,
                "an app that is not the shell was handed `{key}`: {editor:?}"
            );
        }

        let shell = told_on_launch(base, &db, SHELL, Some(OWNER), true).await;
        assert_eq!(value(&shell, "mode"), Some("authenticated"), "{shell:?}");
        let editor = told_on_launch(base, &db, EDITOR, Some(OWNER), true).await;
        assert_eq!(value(&editor, "mode"), None, "{editor:?}");
    }

    /// **The `notice` is written as it was, into any launch for a person whose
    /// keys are not loaded.** The launch is demoted to the lock screen: the
    /// shell is told `locked`, the roster and the sentence; the editor is told
    /// the sentence and still none of the screen keys.
    #[tokio::test]
    async fn a_launch_whose_keys_are_not_loaded_carries_the_notice_and_only_the_shell_the_roster() {
        let (tmp, db) = the_shell_and_the_editor_installed().await;
        let base = tmp.path();

        let shell = told_on_launch(base, &db, SHELL, Some(OWNER), false).await;
        assert_eq!(value(&shell, NOTICE_ARG), Some(KEYS_NOT_LOADED_NOTICE), "{shell:?}");
        assert_eq!(value(&shell, "mode"), Some("locked"), "{shell:?}");
        assert_eq!(value(&shell, "users"), Some("owner"), "{shell:?}");
        assert_eq!(value(&shell, "names"), Some(""), "{shell:?}");

        let editor = told_on_launch(base, &db, EDITOR, Some(OWNER), false).await;
        assert_eq!(value(&editor, NOTICE_ARG), Some(KEYS_NOT_LOADED_NOTICE), "{editor:?}");
        for key in ["mode", "users", "names"] {
            assert_eq!(
                value(&editor, key),
                None,
                "an app that is not the shell was handed `{key}`: {editor:?}"
            );
        }
    }

    // ── The powerbox: the file the person picked ─────────────────────────────

    /// The app the hand-off is for, in these tests.
    const EDITOR: &str = "sh.kotton.editor";
    /// The person.
    const OWNER: &str = "owner";

    /// A keychain holding one identity signing key, so a grant can be signed.
    ///
    /// [`NoSecrets`] answers `None`, which makes `build_signed_envelope` return
    /// `None` and the mint decline — the right behaviour, and useless for
    /// testing that the mint happens.
    struct OneKey;

    impl SecretsStore for OneKey {
        fn get_secret(&self, k: &str) -> SecretsResult<Option<String>> {
            if k == kdf_labels::identity_signing_key(OWNER) {
                Ok(Some(hex::encode([7u8; 32])))
            } else {
                Ok(None)
            }
        }
        fn set_secret(&self, _k: &str, _v: &str) -> SecretsResult<()> {
            Ok(())
        }
        fn delete_secret(&self, _k: &str) -> SecretsResult<()> {
            Ok(())
        }
    }

    /// A base directory with this person's VFS in it, holding `at` and a
    /// neighbour beside it, and a KEL the mint can read a DID out of.
    fn a_person_with_files(at: &str) -> tempfile::TempDir {
        use kotton_wire::kel::{Aid, Authorization, EventKind, KelEvent, KeyState};

        let tmp = tempfile::tempdir().expect("tempdir");
        let data = tmp.path().join("users").join(OWNER).join("data");
        let folder = data.join("photos");
        std::fs::create_dir_all(&folder).expect("the person's files");
        std::fs::write(folder.join(at), b"the file they picked").expect("the file");
        std::fs::write(folder.join("receipts.md"), b"not this one").expect("its neighbour");

        kotton_identity::kel_store::save_chain(
            tmp.path(),
            OWNER,
            &[KelEvent {
                aid: Aid("did:kel:EOwnerInception".to_owned()),
                seq: 0,
                prev_event_digest: None,
                kind: EventKind::Inception,
                key_state: KeyState {
                    group_key: [7u8; 32],
                    threshold: 1,
                    participants: 1,
                },
                recovery_commitment: [0u8; 32],
                recovery_set: Vec::new(),
                authorization: Authorization::Quorum { sig: vec![0u8; 64] },
                contest_window: None,
            }],
        )
        .expect("the person has an identity");
        tmp
    }

    /// The person's tree as the hand-off asks it: what a path names, answered
    /// from the scratch tree [`a_person_with_files`] seeds. The daemon's own
    /// answers come from the sealed store (`DaemonPersonalTree` in `kuserd`);
    /// what these tests hold is what the mint does with the answer.
    struct SeededTree(std::path::PathBuf);

    #[async_trait::async_trait]
    impl PersonalTree for SeededTree {
        async fn read(&self, _: &str) -> Result<Vec<u8>, String> {
            unreachable!("the hand-off only asks what a path names")
        }
        async fn write(&self, _: &str, _: &[u8]) -> Result<(), String> {
            unreachable!("the hand-off only asks what a path names")
        }
        async fn delete(&self, _: &str) -> Result<(), String> {
            unreachable!("the hand-off only asks what a path names")
        }
        async fn create_dir(&self, _: &str) -> Result<(), String> {
            unreachable!("the hand-off only asks what a path names")
        }
        async fn list(&self, _: &str) -> Result<Vec<RunnerDirEntry>, String> {
            unreachable!("the hand-off only asks what a path names")
        }
        async fn logged(&self, _: &str) -> Result<Option<u64>, String> {
            unreachable!("the hand-off only asks what a path names")
        }
        async fn kind(&self, path: &str) -> Result<Option<RunnerPathKind>, String> {
            let at = self
                .0
                .join("users")
                .join(OWNER)
                .join("data")
                .join(path.trim_start_matches('/'));
            Ok(match std::fs::metadata(at) {
                Ok(m) if m.is_file() => Some(RunnerPathKind::File),
                Ok(_) => Some(RunnerPathKind::Dir),
                Err(_) => None,
            })
        }
    }

    /// **No tree, no hand-off.** A person whose store is not open on this
    /// device has nothing the daemon can say is a file of theirs, so nothing
    /// is minted — the answer the mint gave when it read the disk and found
    /// nothing, now given without reading the disk.
    #[tokio::test]
    async fn with_no_tree_open_nothing_is_handed_over() {
        let tmp = a_person_with_files("trip-notes.md");
        let db = grant_tables().await;
        let mut args = vec![("path".to_owned(), "/photos/trip-notes.md".to_owned())];
        assert!(
            hand_over_picked_file(&db, tmp.path(), OWNER, EDITOR, &mut args, &OneKey, None)
                .await
                .is_none()
        );
        assert!(args.is_empty(), "the path stayed with no grant behind it: {args:?}");
    }

    /// The grant tables the mint and the teardown write.
    async fn grant_tables() -> Arc<SqlitePool> {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("in-memory db");
        for ddl in [
            "CREATE TABLE app_grant_envelopes (id TEXT PRIMARY KEY, app_id TEXT NOT NULL, \
             envelope_json TEXT NOT NULL, stored_at INTEGER NOT NULL)",
            "CREATE TABLE grant_lifetime (envelope_id TEXT PRIMARY KEY, app_id TEXT NOT NULL, \
             kind TEXT NOT NULL, uses_remaining INTEGER, bound_instance TEXT, \
             set_at INTEGER NOT NULL)",
            "CREATE TABLE revocation_list (envelope_id TEXT PRIMARY KEY, revoked_at INTEGER NOT NULL)",
        ] {
            sqlx::query(ddl).execute(&pool).await.expect("create the grant tables");
        }
        Arc::new(pool)
    }

    // ── What another app holds ───────────────────────────────────────────────

    /// The editor's shipped manifest, as far as this test needs it: one shape,
    /// `documents`, read and write, suggested at `/documents`.
    const EDITOR_MANIFEST: &str = r#"[app]
id      = "sh.kotton.editor"
name    = "Editor"
version = "0.1.0"
kind    = "long-lived"

[[capabilities]]
id      = "documents"
type    = "vfs-tree"
access  = ["read", "write"]
default = "/documents"
label   = "Your documents"
desc    = "The folder this editor reads and saves files in."
"#;

    /// A person with files, the grant tables, and the editor installed: in the
    /// registry, with its manifest on disk where the daemon keeps it.
    async fn the_editor_installed() -> (tempfile::TempDir, Arc<SqlitePool>) {
        let tmp = a_person_with_files("trip-notes.md");
        let db = grant_tables().await;
        sqlx::query(
            "CREATE TABLE app_registry (app_id TEXT PRIMARY KEY, name TEXT NOT NULL, \
             version TEXT NOT NULL, capabilities TEXT NOT NULL DEFAULT '[]', \
             wasm_path TEXT NOT NULL, installed_at TEXT NOT NULL, \
             wasm_hash TEXT NOT NULL DEFAULT '', bundle_path TEXT, \
             dev INTEGER NOT NULL DEFAULT 0, approved_json TEXT)",
        )
        .execute(db.as_ref())
        .await
        .expect("create app_registry");
        ardb::insert_app(&db, EDITOR, "Editor", "0.1.0", "[]", "/x.wasm", "2026-09-25T00:00:00Z", "", "[]")
            .await
            .expect("the editor is installed");
        let dir = tmp.path().join("apps").join(EDITOR);
        std::fs::create_dir_all(&dir).expect("the app's directory");
        std::fs::write(dir.join("manifest.toml"), EDITOR_MANIFEST).expect("its manifest");
        (tmp, db)
    }

    /// Store an install envelope for the editor, the way `app_install` does:
    /// the approved grants, signed, until revoked. Its id.
    async fn install_envelope(tmp: &Path, db: &Arc<SqlitePool>, grants: Vec<CapabilityGrant>) -> String {
        let envelope =
            build_signed_envelope(tmp, OWNER, EDITOR, grants, &OneKey, GrantLifetime::UntilRevoked)
                .expect("signed");
        grant_db::store_envelope(db, EDITOR, &envelope).await.expect("stored");
        envelope.id
    }

    fn read_write(at: &str) -> Vec<CapabilityGrant> {
        vec![
            CapabilityGrant::vfs(CapabilityKind::Read, at),
            CapabilityGrant::vfs(CapabilityKind::Write, at),
        ]
    }

    /// **The host's grant, not the manifest's default.** The person bound the
    /// editor's `documents` to `/work` at install (RFC-0021). Asked what the
    /// editor holds, the daemon names `documents` — *Your documents* — and
    /// answers `covering` against `/work`, where the grant is: a file there is
    /// reached, and a file in `/documents`, the manifest's suggestion, is not.
    /// The file the occupant handed over while its window is open is the
    /// occupant's own act and is not listed as a holding.
    #[tokio::test]
    async fn a_shape_bound_elsewhere_is_named_by_its_shape_and_answered_where_it_was_bound() {
        let (tmp, db) = the_editor_installed().await;
        install_envelope(tmp.path(), &db, read_write("/work")).await;
        // And a hand-off, while open, of a file outside it.
        let mut args = vec![("path".to_owned(), "/photos/trip-notes.md".to_owned())];
        hand_over_picked_file(&db, tmp.path(), OWNER, EDITOR, &mut args, &OneKey, Some(&SeededTree(tmp.path().to_path_buf())))
            .await
            .expect("handed over");

        let held = app_holdings(&db, tmp.path(), EDITOR).await.expect("read");
        assert_eq!(
            held.iter().map(|h| h.holding.clone()).collect::<Vec<_>>(),
            vec![RunnerHolding {
                shape: Some("documents".into()),
                label: "Your documents".into(),
                writable: true,
            }],
            "{held:?}"
        );
        assert_eq!(held[0].target, "/work", "matched against the bound folder");

        assert!(covering(&held, "/work/plan.md").is_some());
        assert!(covering(&held, "/documents/plan.md").is_none(), "the manifest's default is not the grant");
        assert!(
            covering(&held, "/photos/trip-notes.md").is_none(),
            "a file handed over while open is not something the editor holds"
        );
    }

    /// **A revoked grant is not held, whatever the manifest declares.** The
    /// manifest still says `documents` at `/documents`; the person revoked the
    /// grant; the editor holds nothing, and nothing is reached.
    #[tokio::test]
    async fn a_revoked_grant_is_not_held_though_the_manifest_still_declares_it() {
        let (tmp, db) = the_editor_installed().await;
        let id = install_envelope(tmp.path(), &db, read_write("/documents")).await;
        assert_eq!(app_holdings(&db, tmp.path(), EDITOR).await.expect("read").len(), 1);

        grant_db::revoke_envelope(&db, &id).await.expect("revoked");
        let held = app_holdings(&db, tmp.path(), EDITOR).await.expect("read");
        assert!(held.is_empty(), "a revoked grant was reported: {held:?}");
        assert!(covering(&held, "/documents/plan.md").is_none());
    }

    /// **A name that is not an installed app is refused as one**, before any
    /// file is read — including a name shaped to climb out of the apps folder,
    /// which never becomes a path because only registry ids do.
    #[tokio::test]
    async fn an_app_not_in_the_registry_is_not_installed_and_names_no_file() {
        let (tmp, db) = the_editor_installed().await;
        for name in ["sh.kotton.nothing", "../apps/sh.kotton.editor", "sh.kotton.editor/../sh.kotton.editor"] {
            let err = app_holdings(&db, tmp.path(), name).await.expect_err(name);
            assert!(err.to_string().contains("not installed"), "{name}: {err}");
        }
    }

    /// Install `app_id` under `name` with `manifest` on disk where the daemon
    /// keeps it, beside the editor [`the_editor_installed`] put there.
    async fn install(tmp: &Path, db: &Arc<SqlitePool>, app_id: &str, name: &str, at: &str, manifest: &str) {
        ardb::insert_app(db, app_id, name, "0.1.0", "[]", "/x.wasm", at, "", "[]")
            .await
            .expect("installed");
        let dir = tmp.join("apps").join(app_id);
        std::fs::create_dir_all(&dir).expect("the app's directory");
        std::fs::write(dir.join("manifest.toml"), manifest).expect("its manifest");
    }

    /// **The apps a file can be opened in are the installed apps that declare
    /// a file shape they read and write — and nothing the asker says.**
    ///
    /// Six apps installed: the editor (`documents`, read and write); a notes
    /// app declaring the same in the flat form; a viewer whose one shape only
    /// reads; the records app, which declares no file at all; the shell,
    /// which declares `/` read and write but is the designated occupant — the
    /// one asking; and `sh.example.broken`, whose manifest is not on disk. The answer is the editor and the notes app, by name, and
    /// no other: the viewer would be handed write it never declared, the
    /// records app takes no file, and a file is not handed from the shell to
    /// itself. An app whose manifest cannot be read declares nothing.
    #[tokio::test]
    async fn the_apps_a_file_opens_in_are_those_declaring_a_file_they_read_and_write() {
        let (tmp, db) = the_editor_installed().await;
        sqlx::query("CREATE TABLE app_roles (role TEXT PRIMARY KEY, app_id TEXT NOT NULL)")
            .execute(db.as_ref())
            .await
            .expect("create app_roles");
        install(
            tmp.path(),
            &db,
            "sh.example.notes",
            "Notes",
            "2026-10-01T00:00:00Z",
            "[app]\nid = \"sh.example.notes\"\nname = \"Notes\"\nversion = \"0.1.0\"\n\n\
             [capabilities]\n\"files.read\" = [\"/notes\"]\n\"files.write\" = [\"/notes\"]\n",
        )
        .await;
        install(
            tmp.path(),
            &db,
            "sh.example.viewer",
            "Viewer",
            "2026-10-02T00:00:00Z",
            "[app]\nid = \"sh.example.viewer\"\nname = \"Viewer\"\nversion = \"0.1.0\"\n\n\
             [[capabilities]]\nid = \"photos\"\ntype = \"vfs-tree\"\naccess = [\"read\"]\ndefault = \"/photos\"\n",
        )
        .await;
        install(
            tmp.path(),
            &db,
            "sh.kotton.records",
            "Records",
            "2026-10-03T00:00:00Z",
            "[app]\nid = \"sh.kotton.records\"\nname = \"Records\"\nversion = \"0.1.0\"\n\n\
             [capabilities]\n\"schema.read\" = [\"sh.kotton.governance.record\"]\n",
        )
        .await;
        install(
            tmp.path(),
            &db,
            "sh.kotton.shell",
            "Kotton",
            "2026-10-04T00:00:00Z",
            "[app]\nid = \"sh.kotton.shell\"\nname = \"Kotton\"\nversion = \"0.1.0\"\nrole = \"shell\"\n\n\
             [capabilities]\n\"files.read\" = [\"/\"]\n\"files.write\" = [\"/\"]\n",
        )
        .await;
        ardb::insert_app(&db, "sh.example.broken", "Broken", "0.1.0", "[]", "/x.wasm", "2026-10-05T00:00:00Z", "", "[]")
            .await
            .expect("installed with no manifest on disk");
        role_db::set_role(&db, "shell", "sh.kotton.shell").await.expect("the shell is designated");

        let openers = app_file_openers(&db, tmp.path()).await.expect("read");
        assert_eq!(
            openers,
            vec![
                RunnerOpener { app_nsid: EDITOR.into(), name: "Editor".into() },
                RunnerOpener { app_nsid: "sh.example.notes".into(), name: "Notes".into() },
            ],
        );

        // With no shell designated, the shell is an app like any other that
        // declares `/` read and write — the exclusion is the designation, not
        // its id.
        sqlx::query("DELETE FROM app_roles").execute(db.as_ref()).await.expect("undesignated");
        let names: Vec<String> =
            app_file_openers(&db, tmp.path()).await.expect("read").into_iter().map(|o| o.name).collect();
        assert_eq!(names, vec!["Editor", "Kotton", "Notes"]);
    }

    fn shape(id: &str, default: &str, access: &[CapabilityKind], label: Option<&str>) -> kotton_schemas::CapabilityShape {
        kotton_schemas::CapabilityShape {
            id: id.into(),
            access: access.to_vec(),
            default_target: default.into(),
            label: label.map(Into::into),
            desc: None,
        }
    }

    /// **Naming a grant by its shape, both ways, and leaving nothing out.**
    ///
    /// Positional when the grants are what a binding builds — so two shapes,
    /// both rebound, keep their own names; by default target when they are
    /// not; and a grant no shape answers to is reported under generic words
    /// rather than dropped, because it is still something the app can reach.
    #[test]
    fn grants_are_named_by_the_shape_they_answer_to() {
        use CapabilityKind::{Read, Write};
        let shapes = vec![
            shape("notes", "/notes", &[Read, Write], Some("Your notes")),
            shape("photos", "/photos", &[Read], None),
        ];

        // Both rebound, in binding order.
        let mut bound = read_write("/journal");
        bound.push(CapabilityGrant::vfs(Read, "/pictures"));
        let held = attribute_shapes(&shapes, &bound);
        let words: Vec<_> = held.iter().map(|h| (h.holding.shape.clone(), h.holding.label.clone(), h.holding.writable, h.target.clone())).collect();
        assert_eq!(
            words,
            vec![
                (Some("notes".into()), "Your notes".into(), true, "/journal".into()),
                (Some("photos".into()), "photos".into(), false, "/pictures".into()),
            ]
        );

        // Not in binding order — a flat approval — so by default target, and
        // reported in the manifest's order whatever order the grants came in.
        let mut flat = vec![CapabilityGrant::vfs(Read, "/photos")];
        flat.extend(read_write("/notes"));
        let held = attribute_shapes(&shapes, &flat);
        assert_eq!(
            held.iter().map(|h| h.holding.shape.clone()).collect::<Vec<_>>(),
            vec![Some("notes".into()), Some("photos".into())]
        );

        // A grant nothing declared: still held, under no shape.
        let mut extra = read_write("/notes");
        extra.push(CapabilityGrant::vfs(Read, "/photos"));
        extra.push(CapabilityGrant::vfs(Read, "/imported"));
        let held = attribute_shapes(&shapes, &extra);
        let last = held.last().expect("three");
        assert_eq!(held.len(), 3);
        assert_eq!(last.holding.shape, None);
        assert_eq!(last.holding.label, OTHER_FILES);
        assert!(!last.holding.writable);
    }

    /// **`covering` is the grant predicate, one target at a time.** A folder
    /// covers itself and what is under it, not a name that starts the same;
    /// `/` covers everything; a `..` cannot walk out of a folder and back into
    /// the answer; and where two holdings nest, the nearer one names the place.
    #[test]
    fn covering_is_the_grant_predicate_and_the_nearer_holding_answers() {
        let held = |shape: &str, target: &str| HeldShape {
            holding: RunnerHolding { shape: Some(shape.into()), label: shape.into(), writable: false },
            target: target.into(),
        };
        let two = vec![held("all", "/"), held("work", "/work")];
        let name = |p: &str| covering(&two, p).and_then(|h| h.shape);
        assert_eq!(name("/work/a.md").as_deref(), Some("work"));
        assert_eq!(name("/workshop/a.md").as_deref(), Some("all"));
        assert_eq!(name("/photos").as_deref(), Some("all"));

        let one = vec![held("work", "/work")];
        assert!(covering(&one, "/work").is_some());
        assert!(covering(&one, "/workshop/a.md").is_none());
        assert!(covering(&one, "/work/../photos/a.md").is_none());
        assert!(covering(&[], "/work/a.md").is_none());
    }

    /// **The file the person picked, and nothing beside it.**
    ///
    /// The record's own condition, as one test: the occupant launches the
    /// editor on a path *outside* the `/documents` tree the editor's manifest
    /// declares, and the editor comes away holding read and write on that one
    /// file — not on its neighbour, not on the folder the two sit in — for as
    /// long as the instance runs.
    ///
    /// `CapabilitySet::allows` is the same predicate `check_grant` step 1 uses
    /// and the same one `granted_vfs_roots` mints a handle from, so asserting
    /// against it is asserting what the sandbox will do rather than a second
    /// reading of the grant.
    #[tokio::test]
    async fn the_occupants_launch_hands_over_one_file_outside_the_apps_own_tree() {
        use kotton_schemas::{CapabilitySet, CapabilityTarget};

        let tmp = a_person_with_files("trip-notes.md");
        let db = grant_tables().await;
        let mut args = vec![
            ("path".to_owned(), "/photos/trip-notes.md".to_owned()),
            ("theme".to_owned(), "light".to_owned()),
        ];

        let handed = hand_over_picked_file(&db, tmp.path(), OWNER, EDITOR, &mut args, &OneKey, Some(&SeededTree(tmp.path().to_path_buf())))
            .await
            .expect("the person picked a file of theirs, so it is handed over");
        assert_eq!(handed, "/photos/trip-notes.md");

        let envelopes = grant_db::get_envelopes_for_app(&db, EDITOR)
            .await
            .expect("read the editor's grants");
        assert_eq!(envelopes.len(), 1, "one grant per open, and one only");
        let caps = CapabilitySet::new(envelopes[0].grants.clone());

        let it = CapabilityTarget::Vfs {
            path: "/photos/trip-notes.md".to_owned(),
        };
        assert!(
            caps.allows(&CapabilityKind::Read, &it),
            "the editor can read the file"
        );
        assert!(caps.allows(&CapabilityKind::Write, &it), "and write it");

        for beside in ["/photos/receipts.md", "/photos", "/documents", "/"] {
            let other = CapabilityTarget::Vfs {
                path: beside.to_owned(),
            };
            assert!(
                !caps.allows(&CapabilityKind::Read, &other),
                "the hand-off reached {beside}, which the person did not pick"
            );
            assert!(
                !caps.allows(&CapabilityKind::Write, &other),
                "the hand-off could write {beside}, which the person did not pick"
            );
        }

        // Bound to the instance, not to a clock: `WhileOpen` carries no expiry,
        // and the daemon's lifetime row is what ends it.
        assert_eq!(envelopes[0].expires_at, None);
        assert_eq!(
            grant_db::lifetime_kind(&db, &envelopes[0].id)
                .await
                .unwrap()
                .as_deref(),
            Some("while_open"),
            "a hand-off that outlived its instance would be a standing grant nobody asked for"
        );
        assert_eq!(
            envelopes[0].app_id.as_deref(),
            Some(EDITOR),
            "and it names the app it is for"
        );
        // **An app the person did not pick is granted nothing** (RFC-0090
        // unit 5: the share sheet's *An app* hands over through this mint, as
        // *Edit* does). Read across the whole table rather than per app, so a
        // grant filed under any other app — the occupant that asked, or
        // another app that also takes a file — is counted.
        let everyone: Vec<(String, String)> =
            sqlx::query_as("SELECT id, app_id FROM app_grant_envelopes")
                .fetch_all(db.as_ref())
                .await
                .expect("read every grant");
        assert_eq!(
            everyone,
            vec![(envelopes[0].id.clone(), EDITOR.to_owned())],
            "the hand-off granted something to an app the person did not pick"
        );

        // What the launched app is told: the file's own name, against the
        // handle the sandbox mints for it. Never the person's path (RFC-0021).
        assert_eq!(
            args,
            vec![
                ("path".to_owned(), "trip-notes.md".to_owned()),
                ("theme".to_owned(), "light".to_owned()),
            ],
            "the launched app was told where the person keeps their files: {args:?}"
        );

        // And the grant is gone when the instance ends.
        app_closed(&db, EDITOR).await;
        let after = grant_db::get_envelopes_for_app(&db, EDITOR).await.unwrap();
        assert!(
            after.is_empty(),
            "the hand-off outlived the window it was for: {after:?}"
        );
    }

    /// A path that is not a file of this person's hands nothing over — **and
    /// the argument goes with it**.
    ///
    /// Leaving the key in place is the failure worth naming: the launched app
    /// would resolve the same string inside its *own* granted root and write
    /// there, so a launch on `/photos/trip-notes.md` that minted nothing would
    /// have the editor quietly creating `photos/trip-notes.md` under
    /// `/documents`. A directory is refused for a second reason — a tree grant
    /// is what a manifest declares and the person places, not something a
    /// launch invents.
    #[tokio::test]
    async fn nothing_is_handed_over_for_a_folder_or_a_path_that_is_not_there() {
        let tmp = a_person_with_files("trip-notes.md");
        let db = grant_tables().await;

        for asked in [
            "/photos",
            "/photos/nothing-here.md",
            "/",
        ] {
            let mut args = vec![("path".to_owned(), asked.to_owned())];
            let handed =
                hand_over_picked_file(&db, tmp.path(), OWNER, EDITOR, &mut args, &OneKey, Some(&SeededTree(tmp.path().to_path_buf()))).await;
            assert!(handed.is_none(), "`{asked}` was handed over");
            assert!(
                args.is_empty(),
                "`{asked}` stayed in the launch arguments with no grant behind it: {args:?}"
            );
        }
        assert!(
            grant_db::get_envelopes_for_app(&db, EDITOR)
                .await
                .unwrap()
                .is_empty(),
            "a refused hand-off still minted something"
        );
    }

    /// A launch carrying no `path` mints nothing and changes nothing.
    ///
    /// The ordinary case, and the one that says the mint is driven by the
    /// argument rather than by the launch: a guest whose `path` was stripped by
    /// [`guest_launch_args`] arrives here exactly like an app opened from the
    /// dock, so this is the other half of
    /// `a_path_from_a_guest_that_is_not_the_occupant_is_stripped`.
    #[tokio::test]
    async fn a_launch_with_no_path_mints_nothing() {
        let tmp = a_person_with_files("trip-notes.md");
        let db = grant_tables().await;
        let mut args = vec![("theme".to_owned(), "light".to_owned())];

        assert!(
            hand_over_picked_file(&db, tmp.path(), OWNER, EDITOR, &mut args, &OneKey, Some(&SeededTree(tmp.path().to_path_buf())))
                .await
                .is_none()
        );
        assert_eq!(args, vec![("theme".to_owned(), "light".to_owned())]);
        assert!(grant_db::get_envelopes_for_app(&db, EDITOR)
            .await
            .unwrap()
            .is_empty());
    }

    /// The launch of `app_id`, prepared for the person with a key to sign
    /// with and their tree to ask, carrying `args`.
    async fn launch_for_the_person(
        tmp: &Path,
        db: &Arc<SqlitePool>,
        app_id: &str,
        args: Vec<(String, String)>,
        events: Arc<EventBus>,
    ) -> PreparedLaunch {
        let host = LaunchHost {
            events,
            secrets: Box::new(OneKey),
            runner: tmp.join("no-runner-is-spawned"),
            tree: Some(Arc::new(SeededTree(tmp.to_path_buf()))),
            keys_loaded: true,
            surfaces: Default::default(),
        };
        prepare_launch(&host, db, tmp, app_id.to_owned(), args, Some(OWNER.to_owned()))
            .await
            .expect("the launch is prepared")
    }

    fn pair(k: &str, v: &str) -> (String, String) {
        (k.to_owned(), v.to_owned())
    }

    /// **Two `path` pairs, one file handed over, and the person's path in
    /// neither.**
    ///
    /// The launch carries the file the person picked and, after it, a second
    /// `path` naming a real file of theirs beside it. What the runner is told
    /// to call `on-launch` with holds one `path`, the picked file's name, and
    /// no value that is a path in the person's tree; the one grant minted is on
    /// the first file, and the second is reached by nothing.
    #[tokio::test]
    async fn a_launch_with_two_paths_hands_the_app_one_name_and_no_path() {
        use kotton_schemas::{CapabilitySet, CapabilityTarget};

        let (tmp, db) = the_editor_installed().await;
        let prepared = launch_for_the_person(
            tmp.path(),
            &db,
            EDITOR,
            vec![
                pair("path", "/photos/trip-notes.md"),
                pair("theme", "light"),
                pair("path", "/photos/receipts.md"),
            ],
            Arc::new(EventBus::with_default_capacity()),
        )
        .await;
        let PreparedLaunch::Run { input, launch_args, .. } = prepared else {
            panic!("the editor has a body, so its launch is a runner");
        };
        let RunnerOp::Launch { launch_args: told, .. } = &input.op else {
            panic!("a launch is a launch op");
        };
        assert_eq!(told, &launch_args, "the runner and the presenter are told the same list");

        let paths: Vec<&str> = told
            .iter()
            .filter(|(k, _)| k == PICKED_FILE_ARG)
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(paths, vec!["trip-notes.md"], "the app was handed {told:?}");
        assert!(
            told.iter().all(|(_, v)| !v.contains("/photos")),
            "the launched app was told where the person keeps their files: {told:?}"
        );
        assert!(told.contains(&pair("theme", "light")), "a key that is not `path` is kept");

        let envelopes = grant_db::get_envelopes_for_app(&db, EDITOR).await.expect("read");
        assert_eq!(envelopes.len(), 1, "one file, one grant");
        let caps = CapabilitySet::new(envelopes[0].grants.clone());
        let at = |path: &str| CapabilityTarget::Vfs { path: path.to_owned() };
        assert!(caps.allows(&CapabilityKind::Read, &at("/photos/trip-notes.md")));
        assert!(
            !caps.allows(&CapabilityKind::Read, &at("/photos/receipts.md")),
            "the second `path` was granted"
        );
    }

    /// **A refused first `path` does not promote the second.** The first names
    /// nothing of the person's, so nothing is handed over; the second names a
    /// real file, and it goes too, because only the first is ever asked about.
    #[tokio::test]
    async fn a_second_path_is_dropped_when_the_first_is_refused() {
        let tmp = a_person_with_files("trip-notes.md");
        let db = grant_tables().await;
        let mut args = vec![
            pair("path", "/photos/nothing-here.md"),
            pair("path", "/photos/receipts.md"),
            pair("theme", "light"),
        ];
        let handed = hand_over_picked_file(&db, tmp.path(), OWNER, EDITOR, &mut args, &OneKey, Some(&SeededTree(tmp.path().to_path_buf())))
            .await;
        assert!(handed.is_none(), "{handed:?} was handed over");
        assert_eq!(args, vec![pair("theme", "light")], "a `path` stayed with no grant behind it");
        assert!(grant_db::get_envelopes_for_app(&db, EDITOR).await.unwrap().is_empty());
    }

    /// **A bundle's launch announces no `path`.** An app with no WASM is
    /// answered with the launch event alone, and the event carries the launch
    /// arguments; a `path` in them would be the person's own path, with no
    /// grant behind it and no instance to hold one. Every `path` is gone from
    /// what is published, every other key is there, and nothing is minted.
    #[tokio::test]
    async fn a_bundle_launch_announces_no_path() {
        const BUNDLE: &str = "sh.example.bundle";
        let (tmp, db) = the_editor_installed().await;
        ardb::insert_app(&db, BUNDLE, "Bundle", "0.1.0", "[]", "", "2026-10-01T00:00:00Z", "", "[]")
            .await
            .expect("a bundle is installed with no body");

        let events = Arc::new(EventBus::with_default_capacity());
        let mut heard = events.subscribe();
        let prepared = launch_for_the_person(
            tmp.path(),
            &db,
            BUNDLE,
            vec![
                pair("path", "/photos/trip-notes.md"),
                pair("theme", "light"),
                pair("path", "/photos/receipts.md"),
            ],
            events,
        )
        .await;
        assert!(
            matches!(prepared, PreparedLaunch::Answered(_)),
            "a bundle is answered with the event, not run"
        );

        let event = heard.try_recv().expect("the launch is announced");
        let payload = event.payload.clone().expect("with its arguments");
        assert_eq!(payload["app_id"], BUNDLE);
        let announced: Vec<(String, String)> =
            serde_json::from_value(payload["launch_args"].clone()).expect("a list of pairs");
        assert_eq!(
            announced,
            vec![pair("theme", "light")],
            "the bundle's launch announced the person's path"
        );
        assert!(
            grant_db::get_envelopes_for_app(&db, BUNDLE).await.unwrap().is_empty(),
            "a grant was minted for an app with no instance to end it"
        );
    }

    /// A live instance of `app_id` whose process writes the first frame it is
    /// sent to `heard` and answers it, holding `surfaces`.
    ///
    /// Not a runner: a runner is spawned confined, and the frame is what this is
    /// for. A runner answers `Terminate` by calling `on-terminate`, so the frame
    /// written down is what says whether `on-terminate` was asked for.
    #[cfg(unix)]
    fn an_instance_that_writes_down_what_it_hears(
        app_id: &str,
        heard: &Path,
        surfaces: Vec<SurfaceHandle>,
    ) -> LongLivedInstance {
        let mut child = tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(r#"IFS= read -r frame; printf '%s\n' "$frame" > "$0"; echo '{}'"#)
            .arg(heard)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("a shell to stand for the first instance");
        LongLivedInstance {
            stdin: tokio::io::BufWriter::new(child.stdin.take().expect("piped")),
            stdout: BufReader::new(child.stdout.take().expect("piped")),
            _child: child,
            surfaces,
            app_id: app_id.to_owned(),
            title: "Editor".to_owned(),
            designated: false,
            user_vfs_path: None,
            personal: None,
            windows_shown: Vec::new(),
        }
    }

    /// **A client's second launch of a running app ends the first, through the
    /// host, before the second starts.**
    ///
    /// The editor is running with two surfaces open, and `app_launch` is called
    /// for it again, the call a client's `AppLaunch` reaches. The first instance
    /// is sent `Terminate`, the op its runner answers by calling `on-terminate`;
    /// both of its surfaces are closed through the host; and both happen before
    /// the second instance's surface is opened. No runner is there to start, so
    /// the second launch then fails and closes its own surface, which is far
    /// enough: everything held here has happened by the time it opens.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_second_launch_of_a_running_app_ends_the_first_before_it_starts() {
        let (tmp, db) = the_editor_installed().await;
        let heard = tmp.path().join("what-the-first-instance-heard");
        let (first, second) = (SurfaceHandle::mint(), SurfaceHandle::mint());
        let live = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        live.lock().await.insert(
            EDITOR.to_owned(),
            an_instance_that_writes_down_what_it_hears(EDITOR, &heard, vec![first, second]),
        );
        let host = LaunchHost {
            events: Arc::new(EventBus::with_default_capacity()),
            secrets: Box::new(NoSecrets),
            runner: tmp.path().join("no-runner-is-spawned"),
            tree: None,
            keys_loaded: true,
            surfaces: Default::default(),
        };

        let relaunched = app_launch(
            &host,
            &db,
            tmp.path(),
            Arc::clone(&live),
            EDITOR.to_owned(),
            vec![],
            Some(OWNER.to_owned()),
            None,
            None,
            None,
        )
        .await;
        assert!(
            relaunched.is_err(),
            "there is no runner, so the second launch fails once it has opened: {relaunched:?}"
        );

        let frame = std::fs::read_to_string(&heard).expect("the first instance was sent a frame");
        let frame: RunnerMessage = serde_json::from_str(frame.trim()).expect("a runner frame");
        assert!(
            matches!(frame.op, RunnerOp::Terminate),
            "the first instance was asked to end, which is what calls its `on-terminate`: {}",
            frame.op.name()
        );

        let calls = host.surface_calls();
        assert_eq!(
            calls.get(..2),
            Some(&[SurfaceCall::Closed(first), SurfaceCall::Closed(second)][..]),
            "the first instance's surfaces, both of them, are closed through the host \
             before anything of the second launch: {calls:?}"
        );
        let Some(SurfaceCall::Opened(launched)) = calls.get(2).copied() else {
            panic!("the second launch opened its surface after the first's were closed: {calls:?}");
        };
        assert!(
            ![first, second].contains(&launched),
            "the second instance draws on a surface of its own"
        );
        assert_eq!(
            calls.get(3),
            Some(&SurfaceCall::Closed(launched)),
            "and the launch that failed took its own surface back: {calls:?}"
        );
        assert!(
            live.lock().await.get(EDITOR).is_none(),
            "the first instance is gone from the map, not left behind the failed launch"
        );
    }
}

#[cfg(test)]
mod unconfinable_runner_tests {
    use super::on_unsupported;
    use kotton_proc::SandboxError;

    fn refusal(os: &'static str) -> SandboxError {
        SandboxError::Unsupported {
            purpose: "kotton-runner".into(),
            os,
        }
    }

    /// A Linux build with no filter for its architecture is refused, as the
    /// escalation's default says of every Linux spawn the kernel cannot
    /// confine. Before, this arm spawned on every platform and its comment
    /// said no Linux build could reach it, which was false off x86-64 and
    /// aarch64.
    #[test]
    fn a_linux_runner_that_cannot_be_confined_is_refused() {
        let err = on_unsupported("linux", &refusal("linux")).expect_err("refused on Linux");
        assert!(err.to_string().contains("cannot be confined on linux"), "{err}");
    }

    /// Everywhere else the concession stands: wasmtime is the only layer, and
    /// the launch goes ahead.
    #[test]
    fn elsewhere_an_unconfinable_runner_still_launches() {
        for os in ["windows", "macos"] {
            assert!(on_unsupported(os, &refusal(os)).is_ok(), "{os}");
        }
    }
}

#[cfg(test)]
mod files_call_tests {
    //! The daemon's half of `files`
    //! (`TASK-a-file-an-app-writes-rests-in-the-clear-in-the-sealed-stores-own-directory`):
    //! a frame is answered from the person's tree only for a path the
    //! instance's own grant covers, and the grant is the daemon's record of it.

    use super::{service_files_call, PersonalReach, PersonalTree};
    use kotton_schemas::{CapabilityGrant, CapabilityKind};
    use kotton_wire::runner::{
        RunnerDirEntry, RunnerFileVerb, RunnerHostReply, RunnerInput, RunnerOp, RunnerPathKind,
    };
    use kotton_wire::GrantEnvelope;
    use std::sync::{Arc, Mutex};

    const APP: &str = "sh.kotton.editor";

    /// A tree that records what it was asked, and holds files in memory.
    #[derive(Default)]
    struct Spy {
        asked: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl PersonalTree for Spy {
        async fn read(&self, path: &str) -> Result<Vec<u8>, String> {
            self.asked.lock().unwrap().push(format!("read {path}"));
            Ok(b"sealed bytes".to_vec())
        }
        async fn write(&self, path: &str, _: &[u8]) -> Result<(), String> {
            self.asked.lock().unwrap().push(format!("write {path}"));
            Ok(())
        }
        async fn delete(&self, path: &str) -> Result<(), String> {
            self.asked.lock().unwrap().push(format!("delete {path}"));
            Ok(())
        }
        async fn create_dir(&self, path: &str) -> Result<(), String> {
            self.asked.lock().unwrap().push(format!("create-dir {path}"));
            Ok(())
        }
        async fn list(&self, path: &str) -> Result<Vec<RunnerDirEntry>, String> {
            self.asked.lock().unwrap().push(format!("list {path}"));
            Ok(vec![])
        }
        async fn kind(&self, path: &str) -> Result<Option<RunnerPathKind>, String> {
            self.asked.lock().unwrap().push(format!("kind {path}"));
            Ok(Some(RunnerPathKind::Dir))
        }
        async fn logged(&self, path: &str) -> Result<Option<u64>, String> {
            self.asked.lock().unwrap().push(format!("logged {path}"));
            Ok(Some(7))
        }
    }

    fn input(approved: Vec<CapabilityGrant>, envelopes: Vec<GrantEnvelope>) -> RunnerInput {
        RunnerInput {
            manifest_toml: String::new(),
            wasm_path: String::new(),
            app_data_path: String::new(),
            envelopes,
            approved,
            revoked_ids: vec![],
            trusted_issuers: vec![],
            kel_keys: vec![],
            user_vfs_path: Some("/base/users/owner/data".to_string()),
            occupant: false,
            roots: None,
            op: RunnerOp::Message { msg: String::new() },
        }
    }

    fn envelope(id: &str, app: Option<&str>, grants: Vec<CapabilityGrant>) -> GrantEnvelope {
        GrantEnvelope {
            id: id.to_string(),
            issuer_did: kotton_wire::did::Did::parse("did:key:z6MkIssuer").unwrap(),
            subject_did: kotton_wire::did::Did::parse("did:key:z6MkIssuer").unwrap(),
            node_did: None,
            grants,
            issued_at: 0,
            expires_at: None,
            app_id: app.map(str::to_string),
            issuer_signature: String::new(),
        }
    }

    async fn ask(
        verb: RunnerFileVerb,
        reach: Option<&PersonalReach>,
        spy: &Arc<Spy>,
    ) -> std::io::Result<RunnerHostReply> {
        let tree = Arc::clone(spy) as Arc<dyn PersonalTree>;
        service_files_call(verb, reach, &move |_| Some(Arc::clone(&tree))).await
    }

    /// **Inside the grant, the tree is asked at the normalised path; outside
    /// it, the tree is never asked.** An editor approved `/documents` writes
    /// and reads there, and a path that climbs out — which no handle the
    /// sandbox mints can produce, so only an escaped runner could send it — is
    /// answered `permission denied` without the store hearing of it.
    #[tokio::test]
    async fn a_files_call_reaches_the_tree_only_inside_the_instances_grant() {
        let reach = PersonalReach::of(
            APP,
            Some("owner"),
            &input(
                vec![
                    CapabilityGrant::vfs(CapabilityKind::Read, "/documents"),
                    CapabilityGrant::vfs(CapabilityKind::Write, "/documents"),
                ],
                vec![],
            ),
        )
        .expect("an instance launched for a person has a reach");
        let spy = Arc::new(Spy::default());

        let wrote = ask(
            RunnerFileVerb::Write {
                path: "/documents/./a.md".into(),
                data: b"x".to_vec(),
            },
            Some(&reach),
            &spy,
        )
        .await
        .unwrap();
        assert_eq!(wrote, RunnerHostReply::FileDone);
        let read = ask(RunnerFileVerb::Read { path: "/documents/a.md".into() }, Some(&reach), &spy)
            .await
            .unwrap();
        assert_eq!(read, RunnerHostReply::FileContent { data: b"sealed bytes".to_vec() });

        for outside in [
            "/documents/../photos/a.jpg",
            "/documents/..\\photos\\a.jpg",
            "/documents/sub\\..\\..\\photos\\a.jpg",
            "/photos",
            "/documents-private/x",
            "/",
        ] {
            let answer = ask(RunnerFileVerb::Read { path: outside.into() }, Some(&reach), &spy)
                .await
                .unwrap();
            assert!(
                matches!(&answer, RunnerHostReply::FileFailed { message } if message.starts_with("permission denied")),
                "{outside} was not refused: {answer:?}"
            );
        }
        assert_eq!(
            spy.asked.lock().unwrap().clone(),
            vec!["write /documents/a.md".to_string(), "read /documents/a.md".to_string()],
            "the tree was asked for something the grant does not cover"
        );
    }

    /// **The log readout reaches no further than a read** (RFC-0090, *A device
    /// of your own*): a read grant on `/Inbox` is asked at the canonical path
    /// and answered with the tree's generation, a path outside it is refused
    /// before the tree hears of it, and a write grant alone — which may not
    /// read the file — may not ask whether it is in the log either.
    #[tokio::test]
    async fn the_log_readout_is_answered_only_inside_the_instances_read_grant() {
        let reach = PersonalReach::of(
            APP,
            Some("owner"),
            &input(vec![CapabilityGrant::vfs(CapabilityKind::Read, "/Inbox")], vec![]),
        )
        .unwrap();
        let spy = Arc::new(Spy::default());
        let answer = ask(
            RunnerFileVerb::Logged { path: "/Inbox/./photo.jpg".into() },
            Some(&reach),
            &spy,
        )
        .await
        .unwrap();
        assert_eq!(answer, RunnerHostReply::FileLogged { generation: Some(7) });
        let outside = ask(
            RunnerFileVerb::Logged { path: "/Inbox/../photos/a.jpg".into() },
            Some(&reach),
            &spy,
        )
        .await
        .unwrap();
        assert!(
            matches!(&outside, RunnerHostReply::FileFailed { message } if message.starts_with("permission denied")),
            "a path outside the grant was answered: {outside:?}"
        );

        let write_only = PersonalReach::of(
            APP,
            Some("owner"),
            &input(vec![CapabilityGrant::vfs(CapabilityKind::Write, "/Inbox")], vec![]),
        )
        .unwrap();
        let refused = ask(
            RunnerFileVerb::Logged { path: "/Inbox/photo.jpg".into() },
            Some(&write_only),
            &spy,
        )
        .await
        .unwrap();
        assert!(
            matches!(&refused, RunnerHostReply::FileFailed { message } if message.starts_with("permission denied")),
            "a write grant alone was answered a read: {refused:?}"
        );
        assert_eq!(
            spy.asked.lock().unwrap().clone(),
            vec!["logged /Inbox/photo.jpg".to_string()],
            "the tree was asked for something the grant does not cover"
        );
    }

    /// **A folder is made only inside the grant, at the path the store will
    /// resolve** (`TASK-the-files-world-cannot-make-a-folder`). The daemon's
    /// check is the same one `write` passes — write authority over the
    /// canonical path — so a `create-dir` reaches nothing a `write` cannot:
    /// every climbing spelling is refused before the tree hears of it, and one
    /// that stays inside is handed on canonicalised.
    #[tokio::test]
    async fn a_folder_is_made_only_inside_the_instances_grant() {
        let reach = PersonalReach::of(
            APP,
            Some("owner"),
            &input(vec![CapabilityGrant::vfs(CapabilityKind::Write, "/documents")], vec![]),
        )
        .unwrap();
        let spy = Arc::new(Spy::default());
        let made = ask(
            RunnerFileVerb::CreateDir { path: "/documents/./trip/../trip".into() },
            Some(&reach),
            &spy,
        )
        .await
        .unwrap();
        assert_eq!(made, RunnerHostReply::FileDone);
        for outside in [
            "/documents/../photos/trip",
            "/documents/..\\photos",
            "/photos/trip",
            "/documents-private/trip",
            "/",
        ] {
            let answer = ask(RunnerFileVerb::CreateDir { path: outside.into() }, Some(&reach), &spy)
                .await
                .unwrap();
            assert!(
                matches!(&answer, RunnerHostReply::FileFailed { message } if message.starts_with("permission denied")),
                "{outside} was not refused: {answer:?}"
            );
        }
        assert_eq!(
            spy.asked.lock().unwrap().clone(),
            vec!["create-dir /documents/trip".to_string()],
            "the tree was asked to make a folder the grant does not cover"
        );
    }

    /// **Read and write are separate.** A read-only grant lists and reads, and
    /// a write or delete through it is refused before the tree hears of it.
    #[tokio::test]
    async fn a_read_grant_does_not_write() {
        let reach = PersonalReach::of(
            APP,
            Some("owner"),
            &input(vec![CapabilityGrant::vfs(CapabilityKind::Read, "/")], vec![]),
        )
        .unwrap();
        let spy = Arc::new(Spy::default());
        let listed = ask(RunnerFileVerb::List { path: "/".into() }, Some(&reach), &spy).await.unwrap();
        assert_eq!(listed, RunnerHostReply::FileEntries { entries: vec![] });
        for verb in [
            RunnerFileVerb::Write { path: "/mine.md".into(), data: b"x".to_vec() },
            RunnerFileVerb::Delete { path: "/mine.md".into() },
            RunnerFileVerb::CreateDir { path: "/trip".into() },
        ] {
            let answer = ask(verb, Some(&reach), &spy).await.unwrap();
            assert!(
                matches!(&answer, RunnerHostReply::FileFailed { message } if message.starts_with("permission denied")),
                "{answer:?}"
            );
        }
        assert_eq!(spy.asked.lock().unwrap().clone(), vec!["list /".to_string()]);
    }

    /// **The envelopes decide when there are any**, as they do in the sandbox:
    /// one issued to another app, one revoked, and one expired all grant
    /// nothing, and the approval is not consulted beside them.
    #[tokio::test]
    async fn the_reach_is_the_envelopes_this_app_holds_and_not_the_approval() {
        let mut expired = envelope(
            "expired",
            Some(APP),
            vec![CapabilityGrant::vfs(CapabilityKind::Read, "/old")],
        );
        expired.expires_at = Some(1);
        let mut run = input(
            vec![CapabilityGrant::vfs(CapabilityKind::Read, "/approved-only")],
            vec![
                envelope("mine", Some(APP), vec![CapabilityGrant::vfs(CapabilityKind::Read, "/notes")]),
                envelope("theirs", Some("sh.kotton.other"), vec![CapabilityGrant::vfs(CapabilityKind::Read, "/photos")]),
                envelope("unbound", None, vec![CapabilityGrant::vfs(CapabilityKind::Read, "/legacy")]),
                envelope("revoked", Some(APP), vec![CapabilityGrant::vfs(CapabilityKind::Read, "/gone")]),
                expired,
            ],
        );
        run.revoked_ids = vec!["revoked".to_string()];
        let reach = PersonalReach::of(APP, Some("owner"), &run).unwrap();
        assert!(reach.allows(&CapabilityKind::Read, "/notes/a.md"));
        for denied in ["/photos/a", "/legacy/a", "/gone/a", "/old/a", "/approved-only/a"] {
            assert!(!reach.allows(&CapabilityKind::Read, denied), "{denied} was reachable");
        }
    }

    /// **An app whose only grant is `schema.read` reaches no file of the
    /// person's** — the records app's case (`sh.kotton.records`, whose
    /// manifest declares a schema and nothing under `files`;
    /// `TASK-the-records-app-browses-the-project-root-in-kuid`). It is launched
    /// for a person, so it has a reach, and the reach is empty: every verb on
    /// every path is refused before the tree hears of it.
    ///
    /// **This is the daemon's guard, not the reason the app cannot reach a
    /// file.** The reason is upstream: `kotton:app/files` is linked only for a
    /// `Vfs` grant (`DeclaredInterfaces::from` in `kotton-wasm`), so the app has
    /// no import to make a call through, and `granted_vfs_roots` would mint it
    /// no handle if it had. This pins the last layer — that a frame nothing in
    /// the app could produce is still refused by the daemon's own record of
    /// the grant, on the launch path the sealed-store merge rebuilt.
    #[tokio::test]
    async fn a_schema_grant_alone_reaches_no_file() {
        let nsid = kotton_schemas::Nsid::new("sh.kotton.governance.record").unwrap();
        let reach = PersonalReach::of(
            "sh.kotton.records",
            Some("owner"),
            &input(vec![CapabilityGrant::schema(CapabilityKind::Read, nsid)], vec![]),
        )
        .expect("an instance launched for a person has a reach");
        let spy = Arc::new(Spy::default());
        for verb in [
            RunnerFileVerb::List { path: "/".into() },
            RunnerFileVerb::Kind { path: "/".into() },
            RunnerFileVerb::Read { path: "/records/RFC-0088.md".into() },
            RunnerFileVerb::Write { path: "/a.md".into(), data: b"x".to_vec() },
            RunnerFileVerb::Delete { path: "/a.md".into() },
            RunnerFileVerb::CreateDir { path: "/trip".into() },
        ] {
            let answer = ask(verb.clone(), Some(&reach), &spy).await.unwrap();
            assert!(
                matches!(&answer, RunnerHostReply::FileFailed { message } if message.starts_with("permission denied")),
                "{verb:?} was not refused: {answer:?}"
            );
        }
        assert!(spy.asked.lock().unwrap().is_empty(), "the tree was asked for a schema-only app");
    }

    /// **A frame from an instance launched for nobody drops the instance.** Its
    /// runner builds no file port, so the frame is a call it could not have
    /// been asked for — and there is no person's tree to answer it from.
    #[tokio::test]
    async fn a_files_call_from_an_instance_for_nobody_is_a_fault() {
        let mut nobody = input(vec![CapabilityGrant::vfs(CapabilityKind::Read, "/")], vec![]);
        nobody.user_vfs_path = None;
        assert!(PersonalReach::of(APP, None, &nobody).is_none());
        let spy = Arc::new(Spy::default());
        assert!(ask(RunnerFileVerb::Read { path: "/a".into() }, None, &spy).await.is_err());
        assert!(spy.asked.lock().unwrap().is_empty());
    }

    /// **A person whose store is not open is told so**, not handed anything.
    #[tokio::test]
    async fn a_files_call_with_no_tree_open_is_answered_not_serviced() {
        let reach = PersonalReach::of(
            APP,
            Some("owner"),
            &input(vec![CapabilityGrant::vfs(CapabilityKind::Read, "/")], vec![]),
        )
        .unwrap();
        let answer = service_files_call(RunnerFileVerb::Read { path: "/a".into() }, Some(&reach), &|_| None)
            .await
            .unwrap();
        assert!(matches!(answer, RunnerHostReply::FileFailed { .. }), "{answer:?}");
    }
}
