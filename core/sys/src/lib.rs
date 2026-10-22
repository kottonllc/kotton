// SPDX-License-Identifier: AGPL-3.0-or-later
//! Platform Abstraction Layer (PAL)
//!
//! This crate provides trait-based abstractions for platform-specific functionality,
//! enabling Kotton to run on different platforms:
//! - Standard OS (Windows, Linux, macOS) via tokio/std
//! - WASM runtime
//! - Future bare-metal / Kotton OS
//!
//! # Architecture
//!
//! All platform features are organized as modules:
//! - `secrets` - Secure credential storage (keychain integration)
//! - `filesystem` - File system operations
//! - `crypto` - Cryptographic operations
//! - `network` - Network I/O (TCP/UDP, discovery, HTTP)
//! - `process` - Process/task execution
//! - `service` - Service lifecycle management
//! - `time` - Clock and timing operations
//! - `ipc` - Inter-process communication
//! - `auth` - Authentication providers
//! - `object_storage` - Object storage abstraction
//!
//! Each module provides:
//! - Traits defining the platform abstraction
//! - Error types and result aliases
//! - Documentation and examples

// Platform modules (alphabetically ordered)
pub mod session;
pub mod crypto;
pub mod fs;
pub mod ipc;
pub mod net;
/// Egress to the public internet — the seam confined code reaches through.
///
/// A sibling of [`net`] rather than a child of it. RFC-0054 split `outbound`
/// from `net` as domains because the authority differs: egress is granted
/// per-extension, while the peer mesh runs on peer authority. This file had
/// stayed nested under `net` by naming convention, importing nothing from its
/// former siblings.
pub mod outbound;
pub mod store;
pub mod proc;
pub mod secret;
pub mod svc;
pub mod time;
// `surface` moved to core/surface on 2026-08-15. A window belongs to a principal
// (`WindowOwner`), and `sys` is defined as having no opinion about who is asking.
// See RFC-0062, migration step 4.

// Re-export main traits for convenience
pub use session::{
    AuthError, AuthRequest, AuthResult, AuthenticationProvider, AuthenticationResult, Credentials,
    RequestAuthError, RequestAuthProvider, RequestAuthResult,
};
pub use crypto::{
    Decryptor, Encryptor, Hasher, KeyDeriver, KeypairGenerator, RandomSource, Signer, Verifier,
};
pub use crypto::suite::CryptoSuite;
pub use fs::{FileMetadata, Filesystem, FilesystemError, FilesystemResult};
// `Connection` and `Listener` are deliberately **not** re-exported here.
//
// `net` does not re-export its `Connection` and `Listener` either, and for the
// same reason: this crate spans a dozen domains and both names mean something
// different in two of them. Reached through the module — `ipc::Connection`,
// `net::Connection` — the path says which, the way `io::Result` and
// `fmt::Result` do. Root-exported, one of them would have to carry a prefix
// forever to stay unambiguous, which is what `IpcConnection` was.
//
// The error types stay: `IpcError` and `IpcResult` sit beside `DiscoveryError`
// and `ObjectStorageError`, which are prefixed for the same reason.
pub use ipc::{IpcError, IpcResult};
pub use net::{
    Discovery, DiscoveryError, DiscoveryResult, NetworkMonitor, NetworkTopology, NetworkType, Peer,
};
pub use store::{ObjectMetadata, ObjectStorage, ObjectStorageError, ObjectStorageResult};
pub use proc::{ExitStatus, Process, ProcessConfig, ProcessOutput};
pub use secret::{SecretsError, SecretsResult, SecretsStore};
pub use svc::{Service, ServiceStatus};
pub use time::{Clock, Instant};
