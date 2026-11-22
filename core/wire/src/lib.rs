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

/// A frame or an answer that can be said by its variant's name and nothing of
/// its fields: what a reader says of one it did not ask for (an answer not
/// asked for is said by its name and no field; [`ipc::unasked`]). Implemented
/// by `variant_names!`, the one way this crate gives a type a name.
pub trait Named {
    /// Which variant this is, by its identifier, and nothing of its fields.
    fn name(&self) -> &'static str;
}

/// `impl $ty { pub fn name(&self) -> &'static str }` and [`Named`] for `$ty`,
/// naming each variant by its identifier and nothing else.
///
/// The name is the one thing about a frame that can be said to whoever was not
/// its addressee: which kind of frame it was. Every arm matches `{ .. }` and
/// answers `stringify!` of the identifier, so no field can reach the string by
/// construction, and nothing of the value is formatted to find it. The list
/// cannot drift from the enum because the match has no wildcard: a variant
/// added without its name here does not compile, and a name listed for no
/// variant does not compile either.
macro_rules! variant_names {
    ($ty:ident { $($variant:ident),+ $(,)? }) => {
        impl $ty {
            /// Which variant this is, by its identifier, and nothing of its
            /// fields: what a frame or an answer that arrived out of turn may
            /// be called in an error or a log its reader writes.
            pub fn name(&self) -> &'static str {
                match self {
                    $(Self::$variant { .. } => stringify!($variant),)+
                }
            }
        }

        impl $crate::Named for $ty {
            fn name(&self) -> &'static str {
                <$ty>::name(self)
            }
        }
    };
}

pub mod base64_bytes;
pub mod did;
pub mod grant;
pub mod handshake;
pub mod ipc;
pub mod kel;
pub mod kuid_ipc;
pub mod line;
pub mod note;
pub mod peer;
/// The one reader of the recorded wire surfaces, for the tests that read them; xtask
/// compiles the same file by `#[path]` (see its module doc).
#[cfg(test)]
mod recorded_surface;
/// The one twin comparison of the peer wires' recordings against the door's, beside the
/// reader; kotton-wire's tests only (xtask's `wire-check` has its own twin rule).
#[cfg(test)]
mod recorded_twin;
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
