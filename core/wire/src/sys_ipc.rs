// SPDX-License-Identifier: AGPL-3.0-or-later
//! IPC contract between `kdeviced` (the device daemon) and its clients.
//!
//! `DeviceRequest` / `DeviceResponse` are the wire types for the **`kdeviced` socket**
//! (`\\.\pipe\kdeviced` on Windows, `/run/kdeviced.sock` on Unix, or the value
//! of `KDEVICED_IPC_NAME` for dev overrides).
//!
//! This socket is distinct from the per-user `kuserd-{did_short}` socket:
//!
//! - `kdeviced` handles **device-level** operations: starting/stopping user
//!   daemon instances, reporting device status, and `kctl` challenge-response auth.
//! - Per-user `kuserd` handles **user-level** operations (apps, data, grants).
//!
//! ## Authentication protocol
//!
//! All requests except `Ping`, `Challenge`, and `Authenticate` require the
//! caller to first prove DID ownership.  The flow is:
//!
//! 1. Caller sends `Challenge`.  kdeviced returns `ChallengeIssued { nonce }`.
//! 2. Caller signs the raw nonce bytes with their Ed25519 private key and
//!    base64url-encodes the 64-byte signature.
//! 3. Caller sends `Authenticate { did, nonce, signature }`.
//!    kdeviced: extracts the public key from the `did:key:` DID, verifies
//!    the signature, checks the DID against the sudoers set.
//! 4. On success, `Authenticated { did }` is returned and subsequent requests
//!    on **this connection** are unlocked — while the key stays in the set:
//!    standing is read again on every request, so a key removed from the set
//!    is refused its next act on a connection it already holds.
//! 5. If the set is empty (first setup), the first successfully verified proof
//!    auto-enrolls the DID as the first operator.
//!
//! ## Operators are a set (`TASK-a-device-has-operators-not-an-operator`)
//!
//! A device has operators, each holding a credential of their own: a
//! `did:key` whose row names the one person, an account on this device, it
//! answers for. A key is never two people's. Any operator may add one — from
//! the people with an account here — and remove one, except that the last is
//! never removed, so handing the device on is add-then-step-down. Every act
//! an operator takes is kept under the key that authenticated it. The verbs
//! keep their `Sudoers` names until the rename the idea's fifth question
//! leaves for later.

use serde::{Deserialize, Serialize};

/// Requests sent to the `kdeviced` device daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceRequest {
    /// No-op connectivity check. Returns [`SysResponse::Pong`].
    /// Allowed without authentication.
    Ping,

    /// Request a random challenge nonce — the first step of authentication.
    /// Allowed without authentication.
    Challenge,

    /// Complete authentication by proving DID ownership.
    ///
    /// `nonce` must be the base64url string returned by a preceding `Challenge`
    /// call on this connection.
    ///
    /// `signature` must be a base64url-encoded Ed25519 signature over the raw
    /// decoded nonce bytes, produced by the private key of `did`.
    Authenticate {
        /// `did:key:…` of the caller.
        did: String,
        /// The nonce string from `ChallengeIssued`, as-is (base64url).
        nonce: String,
        /// base64url-encoded 64-byte Ed25519 signature over the raw nonce bytes.
        signature: String,
        /// **The person whose own key this is**, when the caller is that
        /// person's daemon speaking with the key it keeps in their sealed store
        /// (`TASK-this-devices-operators-box-speaks-to-kdeviced-under-the-persons-own-key`).
        ///
        /// It admits nothing. A key that is already an operator's authenticates
        /// as it always did; the first key on an empty device is enrolled and
        /// bound to `person` at once; and a key that is neither is **kept** as
        /// `person`'s — [`DeviceResponse::OperatorKeyKept`], no standing — so
        /// that an operator can later make that person an operator
        /// ([`DeviceRequest::OperatorAdd`]) without ever naming a key they do
        /// not hold. `None` (the default, and what `kctl` sends) is the old
        /// behaviour exactly.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        person: Option<String>,
    },

    /// Return this machine's **device operational key** — the Ed25519 seed that
    /// signs presence and builds the peer mTLS identity, and whose public half
    /// `paired_nodes.public_key` records.
    ///
    /// Authorized for **supervised children only**, never for operators: an
    /// operator has no use for it, and the fewer principals that can name a
    /// durable machine identity, the better. `kdeviced` remains the only process
    /// that reads the keychain; a child receives exactly this one secret and
    /// holds no other.
    ///
    /// RFC-0063 stage 4 item 1, under Article II as amended — device principals
    /// split into operators (sudoers DID set) and supervised children (per-spawn
    /// ephemeral key, verbs named at spawn). Reasoning in
    /// `DEC-0019`.
    GetDeviceOperationalKey,

    /// Return a live snapshot of `kdeviced` state.
    /// Requires authentication.
    DaemonStatus,

    /// Start a per-user `kuserd` instance for `user_did`.
    ///
    /// If an instance is already running for this DID the daemon returns
    /// `UserAlreadyRunning` without spawning a second process.
    /// Requires authentication.
    StartUser { user_did: String },

    /// Gracefully stop the `kuserd` instance for `user_did`.
    ///
    /// If no instance is running, returns `UserNotRunning`.
    /// Requires authentication.
    StopUser { user_did: String },

    /// List all currently active per-user `kuserd` processes.
    /// Requires authentication.
    ListSessions,

    /// List this device's operators: each key and whose it is.
    /// Requires authentication.
    SudoersList,

    /// Make `person` — an account on this device — an operator, holding the
    /// key `did`. Caller must be an operator. Refused when `person` has no
    /// account here, or when `did` is already another person's key: a key is
    /// never shared. Naming a key already this person's changes nothing; naming
    /// the first-run key, which answers for nobody yet, binds it to `person`.
    SudoersAdd { did: String, person: String },

    /// Make `person` — an account on this device — an operator, **holding the
    /// key their own daemon proved and kept for them** (`Authenticate` with
    /// `person`). The caller names a person and never a key: the key is shown
    /// to be theirs by the only party that holds it
    /// (`TASK-this-devices-operators-box-speaks-to-kdeviced-under-the-persons-own-key`).
    /// Refused when `person` has no account here or no key of their own has
    /// been kept for them yet. Caller must be an operator; kept as an act
    /// under the caller's key.
    OperatorAdd { person: String },

    /// Step an operator down: `did` names one key, or a person, which removes
    /// every key of theirs. Refused when it would leave the device with no
    /// operator — the last is never removed, by anyone.
    SudoersRemove { did: String },

    /// Return device identity and name.
    /// Requires authentication.
    DeviceShow,

    /// Set a human-readable name for this device.
    /// Requires authentication.
    DeviceRename { name: String },

    /// Stop the `kuserd` instance for `user_did`, wipe local session key
    /// material and VFS cache, then remove the user from the session registry.
    /// The user's DID and remote data are not affected.
    /// Requires authentication.
    UserRemove { user_did: String },

    /// Gracefully shut down the `kdeviced` process so a supervisor (or the
    /// user) can restart it fresh.  Responds `Ok` before exiting.
    /// Requires authentication.
    DaemonRestart,

    /// Return a snapshot of all currently-authenticated kctl IPC sessions.
    ///
    /// Each entry corresponds to a kctl operator connection that has completed
    /// DID challenge-response authentication.  Short-lived connections may have
    /// already closed by the time the response is read.
    /// Requires authentication.
    IpcSessions,
}

/// Summary of a single active per-user daemon instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSessionInfo {
    /// The user's DID.
    pub user_did: String,
    /// The IPC socket name this instance is listening on (`kuserd-{last8}`).
    pub socket_name: String,
    /// OS process ID of the `kuserd` child process.
    pub pid: u32,
}

/// Live snapshot of system daemon state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysDaemonStatus {
    /// Daemon uptime in whole seconds.
    pub uptime_secs: u64,
    /// Number of active per-user daemon instances.
    pub active_user_count: usize,
    /// The version the system daemon reports: `kotton_version::VERSION`, the form
    /// kotton-protocol's `VERSIONING.md` describes (a tag's version, or one derived from the
    /// nearest tag, with the commit after `+`).
    pub version: String,
}

/// Device identity and metadata, returned by `DeviceShow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device DID.  `None` until the device DID key is generated (post-bootstrap).
    pub did: Option<String>,
    /// Human-readable device name set by `kctl device rename`.
    pub name: Option<String>,
}

/// One of a device's operators: a key, and the person it answers for
/// (`TASK-a-device-has-operators-not-an-operator`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceOperator {
    /// The credential: the `did:key` that authenticates.
    pub did: String,
    /// The account on this device the key answers for. `None` only for the
    /// key that enrolled itself on first run, until an operator binds it.
    pub person: Option<String>,
    /// Unix seconds when the key was enrolled.
    pub added_at: i64,
    /// The key that enrolled it, or `bootstrap` for the first.
    pub added_by: String,
}

/// A single authenticated kctl operator session, returned by `IpcSessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIpcSessionInfo {
    /// DID of the authenticated operator.
    pub did: String,
    /// Unix timestamp (seconds) when authentication completed.
    pub authenticated_at: i64,
    /// Number of requests dispatched on this session.
    pub request_count: u64,
}

/// Responses from the `kdeviced` device daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceResponse {
    /// Response to [`SysRequest::Ping`].
    Pong,

    /// A random nonce for the caller to sign.  Valid only for this connection
    /// and only until a subsequent `Challenge` or `Authenticate` replaces it.
    ChallengeIssued {
        /// base64url-encoded random 32-byte nonce.
        nonce: String,
    },

    /// The device operational key, as a 32-byte Ed25519 seed.
    ///
    /// Carried over the authenticated IPC channel and never written to an
    /// environment block, a command line, or disk.
    DeviceOperationalKey {
        /// Raw 32-byte Ed25519 seed: `<redacted>` in a `{:?}`.
        signing_key_bytes: crate::ipc::SecretBytes,
    },

    /// Authentication succeeded.  All subsequent requests on this connection
    /// are now authorized as `did`.
    Authenticated { did: String },

    /// Authentication failed.
    AuthFailed { reason: String },

    /// The key proved itself and is not an operator's; it is kept as
    /// `person`'s own, standing for nothing until an operator makes `person`
    /// an operator ([`DeviceRequest::OperatorAdd`]). The connection is not
    /// authenticated.
    OperatorKeyKept { person: String },

    /// The request requires successful `Authenticate` first.
    Unauthenticated,

    /// Live snapshot of system daemon state.
    DaemonStatus(SysDaemonStatus),

    /// The `kuserd` instance for `user_did` was started.
    UserStarted {
        user_did: String,
        /// IPC socket name the instance is listening on.
        socket_name: String,
        /// OS PID of the child process.
        pid: u32,
    },

    /// There is already an active instance for this user DID.
    UserAlreadyRunning { socket_name: String, pid: u32 },

    /// The `kuserd` instance was stopped.
    UserStopped { user_did: String },

    /// No `kuserd` instance is currently running for the given DID.
    UserNotRunning,

    /// List of currently active per-user daemon sessions.
    SessionList { sessions: Vec<UserSessionInfo> },

    /// This device's operators, oldest first.
    SudoersList { operators: Vec<DeviceOperator> },

    /// A sudoers mutation completed successfully.
    SudoersModified,

    /// Device identity and name, returned by `DeviceShow`.
    DeviceInfo(DeviceInfo),

    /// The user daemon was stopped and local state was wiped.
    UserRemovedAndWiped { user_did: String },

    /// List of authenticated kctl operator sessions.
    IpcSessionsResult { sessions: Vec<DeviceIpcSessionInfo> },

    /// Generic success acknowledgement.
    Ok,

    /// An error occurred; `message` is a human-readable description.
    Error { message: String },
}

/// A handler's error, as the frame kdeviced's door answers it with
/// (`kotton_ipc::ChannelAcceptor` requires this of every `Resp` it serves).
impl From<std::io::Error> for DeviceResponse {
    fn from(e: std::io::Error) -> Self {
        DeviceResponse::Error {
            message: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DeviceResponse;
    use crate::ipc::SecretBytes;

    /// **The device's operational seed never prints**: `DeviceResponse`
    /// derives `Debug`, so the seed it hands `kuserd` is `SecretBytes` —
    /// `<redacted>` in a `{:?}`, the JSON array of bytes it was on the wire.
    #[test]
    fn the_operational_seed_is_redacted_in_debug_and_plain_on_the_wire() {
        let seed: Vec<u8> = (0xa0..0xc0).collect();
        let answer = DeviceResponse::DeviceOperationalKey { signing_key_bytes: SecretBytes::new(seed.clone()) };
        let printed = format!("{answer:?}");
        assert!(!printed.contains("160") && printed.contains("<redacted>"), "{printed}");
        let wire = serde_json::to_value(&answer).unwrap();
        assert_eq!(wire["DeviceOperationalKey"]["signing_key_bytes"], serde_json::json!(seed));
    }
}
