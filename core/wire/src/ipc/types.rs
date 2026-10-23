// SPDX-License-Identifier: AGPL-3.0-or-later
use serde::{Deserialize, Serialize};

// -- Import (TASK-a-person-brings-their-history-with-them) -------------------

/// Which reader an [`crate::ipc::UserRequest::Import`] wants.
///
/// The caller names the format; the daemon never sniffs it. A reader chosen by
/// guessing decides what the bytes *mean* — which record shape they become —
/// and a wrong guess writes a person's history under the wrong shape silently.
///
/// One variant today. The rest of
/// `TASK-a-person-brings-their-history-with-them` — `.vcf`, a message export, a
/// folder of photos — arrives as variants here, so each widening is one line in
/// `wire-surface.txt` and visible in a diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFormat {
    /// An iCalendar export (RFC 5545) — `.ics`.
    Ics,
}

// -- Sync engine outcome (RFC-0019) -----------------------------------------

/// Transfer summary returned when a tracked sync pass completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncOutcome {
    /// Number of files pushed or pulled.
    pub files: u32,
    /// Total bytes transferred (pushed + pulled).
    pub bytes: u64,
    /// Number of record NSIDs synced.
    pub records: u32,
    /// Number of LWW conflicts resolved (always 0 in the current engine).
    pub conflicts_resolved: u32,
    /// Wall-clock duration of the sync pass in milliseconds.
    pub duration_ms: u64,
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Record sync wire types Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Unix timestamp (seconds) used as a sync watermark.
///
/// `export_changeset(since)` returns rows with `updated_at > since`.
pub type SyncWatermark = i64;

/// Wire representation of a single record snapshot transmitted during record sync.
///
/// Mirrors `kotton_record::ChangesetRow`; defined here so
/// `wire` stays free of `03_providers` dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncChangesetRow {
    /// Stable record identifier (UUID v4 string).
    pub id: String,
    /// NSID of the schema this record belongs to.
    pub schema_nsid: String,
    /// JSON body of the record fields at the time of export.
    pub body: serde_json::Value,
    /// Unix timestamp (seconds) of the last write.
    pub updated_at: SyncWatermark,
    /// Unix timestamp when the record was deleted, or `None` if alive.
    pub deleted_at: Option<SyncWatermark>,
    /// The root the record belongs to (RFC-0071 R17), `None` for Personal.
    /// Records travel with their root; a Personal row travels unmarked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// When the device that first held the record filed it, in milliseconds on
    /// that device's clock (`kotton_record::ChangesetRow::filed_at`). Travels so
    /// a read mark written on one of the person's devices names the same place
    /// on the next; `None` for a row filed before the stamp existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filed_at: Option<i64>,
}

/// Serializable snapshot of a single open WASM app window.
///
/// Mirror of `kotton_surface::WindowState`; duplicated here so that
/// `wire` stays free of `sys` dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowStateDto {
    /// Reverse-domain app identifier.
    pub app_id: String,
    /// UUID of this open instance (string form for JSON compatibility).
    pub instance_id: String,
    /// Window title.
    pub title: String,
    /// Optional numeric badge count.
    pub badge: Option<u32>,
    /// Optional progress fraction in `[0.0, 1.0]`.
    pub progress: Option<f32>,
    /// Whether the app is requesting user attention.
    pub attention: bool,
}

/// Lock mode for a user's device session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum LockMode {
    /// No lock screen Ã¢â‚¬â€ session persists until explicit lock (trusted hardware).
    #[default]
    None,
    /// A short digits-only PIN.
    ///
    /// **Legacy, and no longer settable** where nothing outside Kotton limits
    /// the guess rate — which is everywhere, until RFC-0053 step 8 seals
    /// secrets to platform hardware. Existing PINs keep unlocking: the identity
    /// continuity invariant means an upgrade never locks anyone out of their
    /// own device. The variant stays so that `auth.json` files written before
    /// RFC-0053 step 3 still deserialize, and still say what they are.
    Pin,
    /// The daily credential of RFC-0053: a passphrase carrying enough entropy
    /// to stand up to offline guessing on its own, since nothing else does.
    Passphrase,
}


/// Whether an identity's operational roots are in this daemon's custody, as
/// `GetUnlockState` reports it — the third of the three things a person means
/// by "logged in", and until 2026-09-12 the one no verb could answer
/// (`TASK-unlock-never-ends-and-nothing-reports-it`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CustodyState {
    /// The vault is sealed and nothing is held: reads of this identity's data
    /// refuse until a credential opens it.
    Locked,
    /// The roots are held in memory, and drop at `until` (unix seconds) unless
    /// a credential re-arms the window before then.
    Open { until: i64 },
    /// The roots sit in the platform keychain because no daily credential has
    /// ever sealed them (an install that predates RFC-0053 step 4, or an
    /// identity whose passphrase was never set). Readable, and with no end:
    /// the weakest of the three states, reported rather than passed off as
    /// `Open`.
    InPlatformStore,
}

/// Direction for a sync operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncDirection {
    /// Transfer files from local mount to remote.
    Push,
    /// Transfer files from remote to local mount.
    Pull,
}

/// A single entry in the handler registry.
///
/// Maps an app identifier to a schema NSID it can render.  At most one entry
/// per NSID may have `is_default = true`; the GUI uses this to choose which
/// app to open when the user navigates to a record URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerEntry {
    /// Reverse-domain app identifier, e.g. `"com.acme.notes-pro"`.
    pub app_id: String,
    /// Schema NSID this app can render, e.g. `"sh.kotton.notes"`.
    pub nsid: String,
    /// Whether this is the user's preferred handler for the NSID.
    pub is_default: bool,
}

/// One schema access grant row for a given `(app_id, nsid)` pair.
///
/// Returned by [`UserResponse::SchemaGrantListResult`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaGrantEntry {
    /// Reverse-domain app identifier.
    pub app_id: String,
    /// Schema NSID this grant covers.
    pub nsid: String,
    /// App may query records from this schema.
    pub can_read: bool,
    /// App may insert / delete records in this schema.
    pub can_write: bool,
    /// App may register / update the schema definition.
    pub can_register: bool,
    /// Maximum live records (0 = unlimited).
    pub record_quota: i64,
    /// Maximum total body bytes (0 = unlimited).
    pub byte_quota: i64,
    /// Current live record count.
    pub record_count: i64,
    /// Current total body bytes.
    pub byte_count: i64,
}

/// An app installed on this device (WASM, web bundle, or both).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApp {
    /// Reverse-domain app identifier, e.g. `"com.acme.notes-pro"`.
    pub app_id: String,
    /// Human-readable display name.
    pub name: String,
    /// App version string.
    pub version: String,
    /// Capability grants in display form, e.g. `"schema.read:sh.kotton.notes"`.
    pub capabilities: Vec<String>,
    /// ISO 8601 installation timestamp.
    pub installed_at: String,
    /// Absolute path to the pre-built web bundle directory (`dist/`), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_path: Option<String>,
    /// `true` if registered with `app dev` Ã¢â‚¬â€ points at a live build output
    /// and is not eligible for export or network distribution.
    pub dev: bool,
    /// `true` if the app has a live `LongLived` runner instance currently active.
    /// Always `false` for one-shot apps.
    #[serde(default)]
    pub running: bool,
}

/// A confined extension installed on this device (RFC-0049 / RFC-0050).
///
/// Separate from [`InstalledApp`] because the two answer different questions: an
/// app lists which of the user's data it may touch, an extension lists which
/// *class* it is and where it may connect. Sharing a type would force one
/// listing to render both consent stories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledExtension {
    /// Reverse-domain identifier; also names the extension's quarantine
    /// namespace, which is why it is validated at install.
    pub extension_id: String,
    pub name: String,
    pub version: String,
    /// `"fetcher"` | `"storage-backend"` — selects the WIT world, and therefore
    /// what the extension can reach at all.
    pub class: String,
    pub description: String,
    /// BLAKE3 hex of the component, re-checked on load.
    pub content_hash: String,
    /// `None` when the package was unsigned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_did: Option<String>,
    /// The hosts this extension may reach, as consented. Empty means none —
    /// absence is refusal, never permission.
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// Names of the credential slots the host holds for it. The secrets live in
    /// the OS keychain and never appear here.
    #[serde(default)]
    pub credential_slots: Vec<String>,
    /// Unix seconds.
    pub installed_at: i64,
}

/// The largest object a `WriteFile` may declare.
///
/// **This bounds disk, not memory.** A large file is streamed into the store as
/// its chunks arrive and its hash is verified at the end, so a transfer that will
/// be refused has already written its declared size. Nothing can read those bytes
/// — no name resolves to them, the commit never happens, and compaction reclaims
/// them — but the disk was spent, and this is what bounds how much.
///
/// ~2.5x the largest model RFC-0085 names (0.7–3 GiB quantised, 1–4B parameters).
///
/// **It lives on the wire because it is a property of the channel rather than of
/// either end.** It was previously written down twice — once in the store and
/// once in the CLI, which cannot name the store — with a test grepping one
/// source file from the other crate to keep the copies honest. That test went
/// green while the constant it guarded stopped being the relevant one, which is
/// the failure a duplicated number produces and a grep cannot catch. Two copies
/// cannot disagree when there is one.
pub const MAX_STREAMED_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// A model the person has installed (RFC-0085, `DEC-0073`).
///
/// The manifest itself, unchanged — it is the thing that was stored, and this
/// carries it rather than restating its fields — plus the two facts a manifest
/// cannot hold, because they are about *this person's installation* and not
/// about the model: whether it is the one of its kind that answers, and when
/// they installed it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledModel {
    pub manifest: kotton_schemas::ModelManifest,
    /// One per kind answers, and the person chooses which (`DEC-0073`).
    pub active: bool,
    /// RFC-3339, as the record carries it.
    pub installed_at: String,
}

/// An org identity owned by this user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgEntry {
    /// Fully-qualified `did:key:Ã¢â‚¬Â¦` of the org.
    pub org_did: String,
    /// Human-readable org name.
    pub name: String,
    /// Unix seconds when the org was created.
    pub created_at: i64,
}

/// A grant issued by an org to a member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgGrantEntry {
    /// The `did:key:Ã¢â‚¬Â¦` of the member who received this grant.
    pub member_did: String,
    /// The `GrantEnvelope.id` Ã¢â‚¬â€ used to revoke or track the grant.
    pub envelope_id: String,
    /// Unix seconds when the grant was issued.
    pub issued_at: i64,
}

/// How `org.invite` on a new org-owned root reached the person who created it.
///
/// A plain org signs at once, and the envelope is held; a FROST org signs by quorum, so the
/// person is handed the ceremony to run (`kotton org frost sign-contribute` on a co-signer,
/// `sign-finalize` here) and holds the result with `kotton grant import`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OrgRootDelegation {
    /// Signed by the org and held by the person. The envelope's id.
    Held { envelope_id: String },
    /// A FROST signing session the person completes with a co-signer.
    Ceremony {
        session_id: String,
        message_hex: String,
        coordinator_id_hex: String,
        coordinator_commitment_hex: String,
    },
}

/// The status of a single recovery layer for a user's cryptographic identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryLayerStatus {
    /// Layer identifier: `"mnemonic"` | `"pin_wrap"` | `"escrow"` | `"guardian"`.
    pub layer: String,
    /// Whether this recovery path is currently configured and usable.
    pub active: bool,
    /// Unix seconds of the most recent successful test of this layer.
    /// `None` if it has never been explicitly tested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_tested_at: Option<u64>,
}

/// Cryptographic health summary for a user.
///
/// Returned by the `GetKeyHealth` IPC command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHealth {
    /// Active signing algorithm identifier, e.g. `"ed25519-v1"`.
    pub root_algorithm: String,
    /// Monotonically increasing key version (1 = original, increments on `RotateDbKeys`).
    pub key_version: u32,
    /// Unix seconds of the most recent explicit key rotation.
    /// `None` until the first deliberately-triggered rotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_rotated_at: Option<u64>,
    /// Advisory rotation interval in days set by the user's lock policy.
    /// `None` if no rotation policy is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_policy_days: Option<u32>,
    /// `true` when a rotation is overdue according to `rotation_policy_days`.
    pub rotation_due: bool,
    /// Status of every configured recovery layer.
    pub recovery_layers: Vec<RecoveryLayerStatus>,
}

/// A single entry from the daemon event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEntry {
    pub id: String,
    /// Unix seconds timestamp.
    pub timestamp: i64,
    /// ISO 8601 timestamp (e.g. `"2026-03-12T14:03:44Z"`). Added in M22a.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iso_timestamp: Option<String>,
    pub level: String,
    pub category: String,
    pub message: String,
    /// JSON payload blob, if present.
    pub payload: Option<String>,
}


/// One row in the `kotton config status` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigItem {
    /// Short config key, e.g. `"relay_url"`.
    pub key: String,
    /// Current value, or `None` if not configured.
    pub value: Option<String>,
    /// Whether the item has a value (convenience flag for display logic).
    pub configured: bool,
    /// Human-readable description of what capability this enables.
    pub capability: String,
    /// The `kotton` command to configure this item.
    pub command: String,
}

// -- Runtime inspection (runtime_inspection sprint) -------------------------

/// Snapshot of a kuserd-managed sidecar process.
///
/// Returned by [`crate::UserRequest::DaemonSidecars`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarInfo {
    /// Process name, e.g. `"kuserd"`, `"ksyncd"`, `"kquicd"`, `"khttpd"`.
    pub name: String,
    /// Human-readable role description.
    pub role: String,
    /// Whether this sidecar is configured to run.
    pub enabled: bool,
    /// Whether the process is currently running.
    pub running: bool,
    /// OS process ID, if running.
    pub pid: Option<u32>,
    /// Listening port, if applicable.
    pub port: Option<u16>,
    /// Number of times the supervisor has restarted this process.
    pub restart_count: u32,
    /// Unix timestamp (seconds) when the process last started.
    pub started_at: Option<i64>,
    /// Why the supervisor stopped, if it did: a sidecar that exited within
    /// moments of every start and never ran is reported here rather than
    /// restarted forever. `None` while supervised.
    #[serde(default)]
    pub failed: Option<String>,
}

/// Snapshot of a single authenticated IPC connection.
///
/// Returned by [`crate::UserRequest::IpcSessions`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcSessionInfo {
    /// First 8 characters of the session token (for display only).
    pub token_prefix: String,
    /// The `user_id` this session is authenticated as.
    pub user_id: String,
    /// Optional scope allow-list; `None` means full access.
    pub scope: Option<Vec<String>>,
    /// Unix timestamp (seconds) when `Authenticate` succeeded.
    pub authenticated_at: i64,
    /// Number of requests dispatched on this connection since authentication.
    pub request_count: u64,
}

// -- Network status (net_status sprint) ----------------------------------------

/// Sync state summary returned by [`crate::UserRequest::SyncStatus`] and
/// embedded in [`crate::UserResponse::NetworkStatusResult`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatusResult {
    /// Unix timestamp of the last completed sync pass, or `None` if no pass
    /// has completed since the daemon started.
    pub last_sync_at: Option<i64>,
    /// Number of items in the outbound sync queue, or `None` when the daemon
    /// does not track it.
    ///
    /// `None` rather than `0`, deliberately: this was hardcoded to zero, so the
    /// CLI reported "0 changes" whatever was queued. Zero is a claim — "nothing
    /// is waiting" — and making an untracked value say it is the product
    /// misreporting itself. Unknown is the true answer until something counts.
    pub pending_changes: Option<u32>,
    /// Unix timestamp of the last maintenance pass (pack, snapshot, compact), or
    /// `None` if none has run since the daemon started.
    ///
    /// Maintenance is what keeps the history log bounded. Without a way to see
    /// it, a log growing without limit looks exactly like one being maintained.
    pub last_maintenance_at: Option<i64>,
    /// Number of live QUIC connections reported by ksyncd.
    pub connected_peer_count: u32,
    /// Whether `ksyncd` is currently running.
    pub ksyncd_running: bool,
}

/// Per-peer status entry in a [`crate::UserResponse::NetworkStatusResult`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    /// Human-readable label (the `id` field from `paired_nodes`).
    pub label: String,
    /// DID string of the paired device.
    pub did: String,
    /// Whether there is an active QUIC connection to this peer (from ksyncd report).
    pub connected: bool,
    /// Unix timestamp of the last observed connection to this peer, or `None`.
    pub last_seen_at: Option<i64>,
}

/// Whether this node can be reached through its relay right now (RFC-0083 R6).
///
/// Reachability is a *readout* — a named thing with a state — never a sentence
/// (the design skill's rule). The state is what the relay listener knows: a
/// reservation is a live control socket on the relay, so "held" is "reachable".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayState {
    /// No relay is named. Nothing answers for this node while its devices sleep,
    /// and the readout says so rather than staying blank.
    None,
    /// At least one reservation is held on the relay: a paired device dialing
    /// this node by its handle lands.
    Up,
    /// A relay is named and no reservation is held there — the relay is down,
    /// unreachable from here, or (with nothing paired) there is nothing to hold.
    Down,
}

/// The relay readout: [`RelayState`] and the counts it was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayReadout {
    pub state: RelayState,
    /// Reservations this node should be holding — two per paired peer, one per
    /// epoch in the window (`core/peer`'s reachability).
    pub reservations_wanted: u32,
    /// Of those, the ones whose control socket is open on the relay now.
    pub reservations_live: u32,
}

impl RelayReadout {
    /// The readout of a node with no relay named.
    pub const NONE: Self = Self {
        state: RelayState::None,
        reservations_wanted: 0,
        reservations_live: 0,
    };
}

/// What a gateway elsewhere knows about the node it serves (RFC-0078): written
/// by `khttpd enroll` when the ceremony completes, beside the key the gateway
/// generated for itself and never gives up. Nothing in it is secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayBundle {
    /// The user this gateway serves.
    pub user_id: String,
    /// The paired-node label the node knows the gateway by.
    pub label: String,
    /// The gateway's `did:key`.
    pub gateway_did: String,
    /// The node's device public key, hex — what the gateway dials and verifies.
    pub node_pubkey_hex: String,
    /// The node's name, shown to no one by the gateway; here so a person can
    /// tell two bundles apart.
    pub node_label: String,
    /// The relay the node holds reservations at.
    pub relay_url: String,
}

/// A browser a user admitted by the six-digit ceremony (DEC-0053), as listed
/// to a person: its label, when it was admitted, when it last came back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserDevice {
    /// The label given at admission, e.g. `"iphone"`.
    pub name: String,
    /// Unix seconds when the browser was admitted.
    pub created_at: i64,
    /// Unix seconds of its most recent visit; `None` until it returns.
    pub last_used_at: Option<i64>,
}

/// Sidecar gateway status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewaySummary {
    /// Whether this gateway is configured to run.
    pub enabled: bool,
    /// Whether the sidecar is currently running.
    pub running: bool,
    /// Configured listening port, if any.
    pub port: Option<u16>,
    /// Configured bind address, if any.
    pub bind: Option<String>,
}

// -- Display server / kuid sidecar (RFC-0018) ----------------------------------

/// Input event payload delivered by `kuid` to `kuserd` when the user interacts
/// with an app surface.  Serialised as a tagged JSON object over the IPC wire.
///
/// Mirrors the `input-event` variant from RFC-0011's WIT definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InputEventPayload {
    /// A keyboard key was pressed or released.
    Key {
        /// The logical key string (e.g. `"a"`, `"Enter"`, `"ArrowUp"`).
        key: String,
        /// `true` if the key was pressed, `false` if released.
        pressed: bool,
        /// Whether the Shift modifier was active.
        shift: bool,
        /// Whether the Ctrl/Cmd modifier was active.
        ctrl: bool,
        /// Whether the Alt/Option modifier was active.
        alt: bool,
    },
    /// The pointer (mouse/touch) was moved or clicked.
    Pointer {
        /// X coordinate in logical pixels, relative to the surface origin.
        x: f32,
        /// Y coordinate in logical pixels, relative to the surface origin.
        y: f32,
        /// Whether the primary button was pressed when this event fired.
        button_pressed: bool,
        /// The kind of pointer event.
        action: PointerAction,
    },
    /// A DOM-level event resolved by the compositor's hit-test pass.
    ///
    /// kuid performs layout-aware hit-testing on the blitz document and walks
    /// ancestors to find the nearest element with a registered listener for
    /// `event_type`.  The resolved `element_id` is the Dioxus `ElementId` that
    /// the WASM app uses to dispatch the event through its virtual DOM.
    Dom {
        /// Dioxus `ElementId` (the `usize` component, cast to `u64`).
        element_id: u64,
        /// DOM event type name (e.g. `"click"`, `"mousedown"`, `"input"`).
        event_type: String,
        /// X coordinate in logical pixels at the time of the event.
        x: f32,
        /// Y coordinate in logical pixels at the time of the event.
        y: f32,
        /// For `"input"` events on a natively-edited `<textarea>`/`<input>`: the
        /// element's current text value after the edit (the compositor owns the
        /// editing buffer; the guest observes the value here). `None` for other
        /// event types. (Native text input — TEXT-INPUT-PRIMITIVE.)
        #[serde(default)]
        value: Option<String>,
    },
    /// A clipboard paste, delivered as **data** by the compositor (RFC-0032).
    ///
    /// kuid owns the OS clipboard; on a real paste gesture it reads the clipboard
    /// and delivers the text here. This is never synthetic key input, so pasted
    /// newlines are characters, not Enter presses — paste cannot execute.
    Paste {
        /// The pasted text.
        text: String,
        /// Where the content came from.
        origin: PasteOrigin,
    },
    /// The host gave this surface a new size (RFC-0087, *movable and resizable windows*).
    ///
    /// **Not a request, and not a negotiation.** The host has already laid the surface
    /// out at this size by the time the message is sent — a window whose guest could
    /// refuse a resize would be an app placing itself, which the RFC's invariants forbid.
    /// What this carries is the *news*, so a guest that keeps its own idea of its extent
    /// (a canvas, a layout that reflows in code rather than in CSS) can catch up.
    ///
    /// The numbers are **logical pixels of the guest's own content area** — the frame
    /// minus the host's title bar, and minus the attribution slot on a top panel. They
    /// are the same units the surface's pointer coordinates are in, which is the only
    /// pair of facts a guest can compare.
    ///
    /// It rides `on-input` because `resize(size)` has been a member of `world app`'s
    /// `input-event` since RFC-0011 and nothing ever produced it: the variant is the
    /// guest's half of this message and it was already there.
    Resize {
        /// Content width in logical pixels.
        width: u32,
        /// Content height in logical pixels.
        height: u32,
    },
    /// The person closed this surface (RFC-0087 stage 3c).
    ///
    /// **Not a request the app may decline.** The host has already taken the
    /// surface off the screen by the time this arrives: a close a hung guest
    /// could veto is a window the person cannot get rid of, which is the whole
    /// reason the frame's controls are the host's. What this carries is the
    /// *news*, so an app holding several surfaces can forget the one that is
    /// gone — drop its view, drop its renderer, and stop drawing into nothing.
    ///
    /// It rides `on-input` because it is a thing the person did to a named
    /// surface, which is what that export is for, and because `close-request`
    /// has been a member of `world app`'s `input-event` since before this: the
    /// variant existed and nothing ever produced it. An app that ignores it
    /// loses nothing it still has.
    CloseRequest,
}

/// The source of a [`InputEventPayload::Paste`] (RFC-0032). Lets a
/// security-sensitive app treat host-originated content with more suspicion.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasteOrigin {
    /// The host OS clipboard (external, untrusted).
    HostClipboard,
    /// The Kotton-internal off-host slot (Phase 2; not yet produced).
    KottonSlot,
}

/// The kind of pointer action in an [`InputEventPayload::Pointer`] event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerAction {
    /// Pointer moved (no button state change).
    Move,
    /// Primary button pressed.
    Down,
    /// Primary button released.
    Up,
    /// Pointer left the surface bounds.
    Leave,
}


/// One signed grant envelope backing an installed app, as reported by
/// [`UserResponse::AppGrants`].
///
/// Carries the facts a person or a test needs to judge whether the attestation
/// is still good — not the signature itself, which nothing outside the daemon
/// can check anyway.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub struct AppGrantEnvelope {
    /// Envelope id, as it appears in the revocation list.
    pub id: String,
    /// DID that signed it.
    pub issuer_did: String,
    /// Unix seconds after which it is no longer valid; `None` means until revoked.
    #[cfg_attr(feature = "ts-types", ts(type = "number | null"))]
    pub expires_at: Option<i64>,
    /// Whether this envelope has been revoked.
    pub revoked: bool,
    /// The grants it carries, rendered.
    pub grants_display: Vec<String>,
}

// -- A drive accepts the person's other devices ------------------------------

/// What a tenant's change to the devices its drive admits does: admit a key, or
/// withdraw one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantDeviceAct {
    /// The drive admits this key for the tenant from now on, as it admits the
    /// device that enrolled it.
    Admit,
    /// The drive admits this key no longer.
    Withdraw,
}

/// One device of a person, introduced to or withdrawn from a drive that keeps
/// for them, as the identity signs it ([`crate::ipc::UserRequest::TenantDevice`]).
///
/// A vault holds no data keys, so it cannot read the person's member list to
/// learn their devices; it admits the device that enrolled it and, before this,
/// nobody else. The device that admitted a new device of the person's says
/// this to each drive the person has, signed under the identity, and the drive
/// checks the signature against the identity's current key in the key log it
/// keeps: pairing introduces a device's key to the set a drive admits.
///
/// `said_at_ms` orders a tenant's changes to one key: a drive refuses an admit
/// no later than the last change it took for that key, so an admit replayed
/// after a withdrawal does not put a revoked device back; and it takes a
/// withdrawal whatever its time, so a revoke in the same millisecond as the
/// admit, or under a clock that stepped back, still takes the device out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantDeviceChange {
    pub act: TenantDeviceAct,
    /// The device's `did:key`, which names [`Self::public_key`].
    pub device_did: String,
    /// The device's operational key, the one its TLS handshake presents.
    pub public_key: [u8; 32],
    /// Unix milliseconds when the identity said it.
    pub said_at_ms: u64,
}

impl TenantDeviceChange {
    /// The domain the identity's signature is made in, so a signature over these
    /// bytes is never one over anything else the identity signs.
    pub const DOMAIN: &'static [u8] = b"kotton/tenant-device/v1\0";

    /// The bytes the identity signs for this change to `user_id`'s devices at a
    /// drive: the domain, then each field length-prefixed, so no two changes
    /// share an encoding.
    pub fn signed_bytes(&self, user_id: &str) -> Vec<u8> {
        fn field(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        let mut out = Self::DOMAIN.to_vec();
        field(&mut out, user_id.as_bytes());
        field(
            &mut out,
            match self.act {
                TenantDeviceAct::Admit => b"admit",
                TenantDeviceAct::Withdraw => b"withdraw",
            },
        );
        field(&mut out, self.device_did.as_bytes());
        field(&mut out, &self.public_key);
        field(&mut out, &self.said_at_ms.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tenant_device_tests {
    use super::*;

    fn a_change(act: TenantDeviceAct) -> TenantDeviceChange {
        TenantDeviceChange { act, device_did: "did:key:zB".into(), public_key: [7; 32], said_at_ms: 42 }
    }

    /// Every field the identity signs changes the bytes, the tenant included,
    /// so a signature for one change, one key or one person is no other's.
    #[test]
    fn every_field_of_a_tenant_device_change_is_signed() {
        let base = a_change(TenantDeviceAct::Admit);
        let bytes = base.signed_bytes("alice");
        assert!(bytes.starts_with(TenantDeviceChange::DOMAIN));
        assert_ne!(bytes, base.signed_bytes("bob"), "the tenant");
        assert_ne!(bytes, a_change(TenantDeviceAct::Withdraw).signed_bytes("alice"), "the act");
        let mut other = base.clone();
        other.public_key = [8; 32];
        assert_ne!(bytes, other.signed_bytes("alice"), "the key");
        let mut other = base.clone();
        other.device_did = "did:key:zC".into();
        assert_ne!(bytes, other.signed_bytes("alice"), "the did");
        let mut other = base.clone();
        other.said_at_ms = 43;
        assert_ne!(bytes, other.signed_bytes("alice"), "the time");
    }
}
