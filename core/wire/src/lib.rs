// SPDX-License-Identifier: AGPL-3.0-or-later
//! Kotton domain schemas
//!
//! Pure data structure definitions for wire formats and persisted data.
//! Only includes types that are actively used in current features.
//!
//! ## Layer rule
//!
//! This crate must never depend on `05_runtime` or higher. It sits below the
//! runtime in the dependency graph and is imported by everything above it.

pub mod base64_bytes;
pub mod did;
pub mod grant;
pub mod ipc;
pub mod kel;
pub mod kuid_ipc;
pub mod line;
pub mod peer;
/// The one reader of the recorded wire surfaces, for the tests that read them; xtask
/// compiles the same file by `#[path]` (see its module doc).
#[cfg(test)]
mod recorded_surface;
pub mod remote;
pub mod rendezvous;
pub mod runner;
pub mod surface;
pub mod sys_ipc;

// Convenience re-exports for the most commonly used schema types
pub use grant::{GrantEnvelope, GrantLifetime, MembershipGrant};
pub use ipc::{SyncDirection, UserRequest, UserResponse};
pub use ipc::remote_request::RemoteRequest;
pub use ipc::request::{ConnTrustOrigin, REMOTE_ELIGIBLE};
pub use peer::{
    EphemeralSession, FrostSharePayload, GuestAccess, GuestAccessToken, MountConfig, PairedNode,
    DriveHandout, PairingPayload, SessionPermissions, SyncRule, WarmKeyDelegation,
};
pub use remote::{RemoteBackend, RemoteConfig, SyncResult};
pub use rendezvous::{
    RendezvousLookupResponse,
    RendezvousPushPayload, RendezvousStatusInfo,
};
pub use runner::{RunnerInput, RunnerMessage, RunnerOp, RunnerOutput};
pub use kuid_ipc::{CompositorEvent, FromCompositor, KuidRequest, KuidResponse, PlatformPrompt};
pub use surface::{
    HostWindow, PanelEdge, SurfaceHandle, SurfaceRole, SurfaceSpec, WindowView,
    MAX_SURFACES_PER_INSTANCE, MAX_TITLE_CHARS,
};
pub use sys_ipc::{DeviceIpcSessionInfo, DeviceInfo, DeviceOperator, DeviceRequest, DeviceResponse, SysDaemonStatus, UserSessionInfo};
