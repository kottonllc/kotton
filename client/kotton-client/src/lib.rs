// SPDX-License-Identifier: AGPL-3.0-or-later
use kotton_ipc::IpcClient;

mod app;
mod connect;
mod crypto;
mod diag;
mod extensions;
mod filesystem;
mod frost_orgs;
mod grant;
mod identity;
mod model;
mod msg;
mod net;
mod peer;
mod org;
mod protocol;
mod record;
mod records;
mod schema;
mod session;
mod store;
mod sync;
pub mod active_identity;
pub mod session_cache;
mod surface;

pub use app::{App, AppLaunchOutput};
pub use diag::{DaemonHealthInfo, Diag};
pub use filesystem::Fs;
pub use crypto::Crypto;
pub use grant::Grant;
pub use identity::{Identity, Recovery};
pub use peer::Peer;
pub use model::{hash_file, Model};
pub use msg::Msg;
pub use record::{ImportFormat, Record};
pub use records::{records_export, records_import, ImportReport, OrgRoot, OrgRootDelegation};
pub use surface::Surface;
pub use store::Store;
pub use sync::Sync;
pub use net::{ForgottenCredential, InvitedMe, KeptCredential, LocalDoor, Net, NetworkStatusSummary};
pub use org::Org;
pub use frost_orgs::{org_grant_issue_full, OrgGrantIssueResult};
pub use kotton_wire::ipc::{
    ConfigItem, CustodyState, EventEntry, HandlerEntry, InstalledApp,
    InstalledModel, KeyHealth, LockMode, OrgEntry, OrgGrantEntry,
    RecoveryLayerStatus, SchemaGrantEntry, SyncDirection, WindowStateDto,
};
/// The manifest a model is installed with, carried unchanged from the person's
/// file to the record in their store (RFC-0085).
pub use kotton_schemas::{Licence, ModelFormat, ModelKind, ModelManifest};
pub use kotton_wire::peer::{
    EphemeralSession, MountConfig, PairedNode, SessionPermissions, SyncRule,
};
pub use kotton_wire::rendezvous::RendezvousStatusInfo;
pub use kotton_wire::GrantEnvelope;
pub use kotton_wire::{RemoteBackend, RemoteConfig, SyncResult};
pub use kotton_schemas::{CapabilityGrant, CapabilityKind, CapabilityTarget};
pub use protocol::{UserRequest, UserResponse};
pub use session::{format_wait, PinUnlock, Session, UnlockState};

/// SDK client for interacting with the system daemon
pub struct KottonClient {
    pub(crate) client: IpcClient<UserRequest, UserResponse>,
    /// The endpoint this client connected to. Retained so streaming calls
    /// (e.g. the RFC-0040 ceremony) can open additional connections to the
    /// **same** daemon — including a test/dev daemon on a non-default socket.
    pub(crate) endpoint: kotton_sys::ipc::IpcEndpoint,
    /// Session token issued by the daemon upon successful login or account
    /// creation.  Sent via `Authenticate` at the start of each new connection.
    pub session_token: Option<String>,
    /// Whether tokens from this connection belong in the on-disk session cache.
    ///
    /// True only for [`KottonClient::connect`] — the default daemon. The cache
    /// lives at an **ambient per-machine path and is keyed by `user_id` alone**,
    /// so it cannot distinguish which daemon minted a token. Caching one from a
    /// test or dev daemon on a non-default socket therefore hands the *real*
    /// daemon a token it never issued, and `connect_as` presents it before
    /// falling back — a stale-credential path nobody would look for.
    ///
    /// It also stopped the suite writing `sessions/*.session` into a
    /// developer's actual Kotton directory on every run, which is how this was
    /// noticed: a reconnect in an integration test picked up a token another
    /// test's daemon had minted.
    pub(crate) caches_sessions: bool,
}
