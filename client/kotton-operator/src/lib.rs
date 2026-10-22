// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton-operator` — the device operator's facade.
//!
//! The **D column** of RFC-0054's
//! domain × principal matrix, published as its own crate per
//! RFC-0055.
//!
//! ```no_run
//! # async fn example(mut dev: kotton_operator::DeviceClient) -> std::io::Result<()> {
//! let info = dev.device().show().await?;
//! # let _ = info;
//! # Ok(())
//! # }
//! ```
//!
//! ## Why a separate crate rather than a prefix
//!
//! A device operator and a user are different principals. `kotton` (the user
//! facade) reaches a user's files, records and keys; this crate reaches none of
//! them, and that is structural rather than advisory — `DeviceRequest` has no
//! verb that returns user data, and nothing here re-exports `UserRequest`.
//!
//! A `kotton::device::` module inside the user facade would have linked both
//! surfaces into every binary and left "do not call this one" to a developer
//! noticing. For a project whose thesis is structural enforcement over
//! convention, the crate boundary is the honest form: the item is absent, so
//! there is nothing to notice.
//!
//! ## What an operator can and cannot do
//!
//! An operator starts and stops user instances, renames the device, manages the
//! sudoers set and removes a user's data from this machine. None of that opens
//! any of it — `UserRemove` wipes, it does not read. The operator holds no
//! content key, and the only way into user data is a session belonging to that
//! user.
//!
//! That is the same claim the storage layer makes one tier down, where
//! `cargo xtask blindness-check` asserts terminal backends hold no key material.
//! Here it holds because the vocabulary the operator can speak does not contain
//! a verb for it.

use std::io;

use kotton_ipc::IpcClient;
use kotton_wire::{DeviceOperator, DeviceRequest, DeviceResponse};

pub use kotton_wire::sys_ipc::{
    DeviceInfo, DeviceIpcSessionInfo, SysDaemonStatus, UserSessionInfo,
};

/// A connection to `kdeviced`, the device daemon.
pub struct DeviceClient {
    client: IpcClient<DeviceRequest, DeviceResponse>,
}

impl DeviceClient {
    /// Wrap an already-connected IPC client.
    pub fn new(client: IpcClient<DeviceRequest, DeviceResponse>) -> Self {
        Self { client }
    }

    /// The underlying connection, for the challenge/response handshake, which is
    /// a protocol ceremony rather than a domain verb.
    pub fn inner(&mut self) -> &mut IpcClient<DeviceRequest, DeviceResponse> {
        &mut self.client
    }

    /// Enter the `device` domain — the machine and who may administer it.
    pub fn device(&mut self) -> Device<'_> {
        Device { client: self }
    }

    /// Enter the `session` domain — which users are running here.
    pub fn session(&mut self) -> Session<'_> {
        Session { client: self }
    }

    /// Enter the `diag` domain — what the daemon is doing.
    pub fn diag(&mut self) -> Diag<'_> {
        Diag { client: self }
    }

    async fn send(&mut self, req: DeviceRequest) -> io::Result<DeviceResponse> {
        self.client.send(&req).await
    }
}

/// Map the two responses every verb can answer with into an error, so each
/// method matches only the shapes it actually expects.
fn unexpected(resp: DeviceResponse) -> io::Error {
    match resp {
        DeviceResponse::Error { message } => io::Error::other(message),
        DeviceResponse::Unauthenticated => {
            io::Error::other("not authenticated to kdeviced — run the challenge handshake first")
        }
        other => io::Error::other(format!("unexpected response: {other:?}")),
    }
}

/// The `device` domain: the machine, and who may administer it.
pub struct Device<'a> {
    client: &'a mut DeviceClient,
}

impl Device<'_> {
    /// This device's identity and metadata.
    pub async fn show(&mut self) -> io::Result<DeviceInfo> {
        match self.client.send(DeviceRequest::DeviceShow).await? {
            DeviceResponse::DeviceInfo(info) => Ok(info),
            other => Err(unexpected(other)),
        }
    }

    /// Rename this device. The name is what peers see when pairing.
    pub async fn rename(&mut self, name: &str) -> io::Result<()> {
        match self
            .client
            .send(DeviceRequest::DeviceRename {
                name: name.to_string(),
            })
            .await?
        {
            DeviceResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    /// Start a user's instance, returning its socket name and PID.
    ///
    /// `Ok((socket, pid, already_running))` — starting a running user is not an
    /// error, and the caller usually wants to say which happened.
    pub async fn start_user(&mut self, user_did: &str) -> io::Result<(String, u32, bool)> {
        match self
            .client
            .send(DeviceRequest::StartUser {
                user_did: user_did.to_string(),
            })
            .await?
        {
            DeviceResponse::UserStarted {
                socket_name, pid, ..
            } => Ok((socket_name, pid, false)),
            DeviceResponse::UserAlreadyRunning { socket_name, pid } => {
                Ok((socket_name, pid, true))
            }
            other => Err(unexpected(other)),
        }
    }

    /// Stop a user's instance. `Ok(false)` if it was not running.
    pub async fn stop_user(&mut self, user_did: &str) -> io::Result<bool> {
        match self
            .client
            .send(DeviceRequest::StopUser {
                user_did: user_did.to_string(),
            })
            .await?
        {
            DeviceResponse::UserStopped { .. } => Ok(true),
            DeviceResponse::UserNotRunning => Ok(false),
            other => Err(unexpected(other)),
        }
    }

    /// Remove a user from this device and wipe their data here.
    ///
    /// Wipes; does not read. An operator running this never sees what it erases,
    /// which is the distinction the whole crate rests on.
    pub async fn remove_user(&mut self, user_did: &str) -> io::Result<String> {
        match self
            .client
            .send(DeviceRequest::UserRemove {
                user_did: user_did.to_string(),
            })
            .await?
        {
            DeviceResponse::UserRemovedAndWiped { user_did } => Ok(user_did),
            other => Err(unexpected(other)),
        }
    }

    /// This device's operators: each key, and the person it answers for.
    pub async fn sudoers(&mut self) -> io::Result<Vec<DeviceOperator>> {
        match self.client.send(DeviceRequest::SudoersList).await? {
            DeviceResponse::SudoersList { operators } => Ok(operators),
            other => Err(unexpected(other)),
        }
    }

    /// Make `person` — an account on this device — an operator holding the
    /// key `did` (`TASK-a-device-has-operators-not-an-operator`).
    pub async fn sudoers_add(&mut self, did: &str, person: &str) -> io::Result<()> {
        match self
            .client
            .send(DeviceRequest::SudoersAdd {
                did: did.to_string(),
                person: person.to_string(),
            })
            .await?
        {
            DeviceResponse::SudoersModified => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    /// Step an operator down: one key, or a person and every key of theirs.
    /// The device refuses to step down its last.
    pub async fn sudoers_remove(&mut self, did: &str) -> io::Result<()> {
        match self
            .client
            .send(DeviceRequest::SudoersRemove {
                did: did.to_string(),
            })
            .await?
        {
            DeviceResponse::SudoersModified => Ok(()),
            other => Err(unexpected(other)),
        }
    }
}

/// The `session` domain: which users are running on this device.
pub struct Session<'a> {
    client: &'a mut DeviceClient,
}

impl Session<'_> {
    /// Every running user instance.
    pub async fn list(&mut self) -> io::Result<Vec<UserSessionInfo>> {
        match self.client.send(DeviceRequest::ListSessions).await? {
            DeviceResponse::SessionList { sessions } => Ok(sessions),
            other => Err(unexpected(other)),
        }
    }

    /// Ask for a challenge nonce, the first half of the operator handshake.
    pub async fn challenge(&mut self) -> io::Result<String> {
        match self.client.send(DeviceRequest::Challenge).await? {
            DeviceResponse::ChallengeIssued { nonce } => Ok(nonce),
            other => Err(unexpected(other)),
        }
    }

    /// Answer a challenge, the second half. Returns the authenticated DID.
    ///
    /// `signature` is base64url over the raw nonce bytes. Signing happens in the
    /// caller: this crate never holds a key, which is why it takes a signature
    /// rather than something to sign with.
    pub async fn authenticate(
        &mut self,
        did: &str,
        nonce: &str,
        signature: &str,
    ) -> io::Result<String> {
        match self
            .client
            .send(DeviceRequest::Authenticate {
                did: did.to_string(),
                nonce: nonce.to_string(),
                signature: signature.to_string(),
                person: None,
            })
            .await?
        {
            DeviceResponse::Authenticated { did } => Ok(did),
            DeviceResponse::AuthFailed { reason } => Err(io::Error::other(reason)),
            other => Err(unexpected(other)),
        }
    }
}

/// The `diag` domain: what the daemon is doing.
pub struct Diag<'a> {
    client: &'a mut DeviceClient,
}

impl Diag<'_> {
    /// Liveness check. Needs no authentication.
    pub async fn ping(&mut self) -> io::Result<()> {
        match self.client.send(DeviceRequest::Ping).await? {
            DeviceResponse::Pong => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    /// Daemon status.
    pub async fn status(&mut self) -> io::Result<SysDaemonStatus> {
        match self.client.send(DeviceRequest::DaemonStatus).await? {
            DeviceResponse::DaemonStatus(s) => Ok(s),
            other => Err(unexpected(other)),
        }
    }

    /// Restart the daemon.
    pub async fn restart(&mut self) -> io::Result<()> {
        match self.client.send(DeviceRequest::DaemonRestart).await? {
            DeviceResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    /// Live IPC connections to this daemon.
    pub async fn ipc_sessions(&mut self) -> io::Result<Vec<DeviceIpcSessionInfo>> {
        match self.client.send(DeviceRequest::IpcSessions).await? {
            DeviceResponse::IpcSessionsResult { sessions } => Ok(sessions),
            other => Err(unexpected(other)),
        }
    }
}
